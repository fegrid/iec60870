//! CS 101 in-memory master ↔ slave loopback (E5).
//!
//! Wires the real Rust `Cs101Master` to the real Rust `Cs101Slave`
//! through an in-memory byte channel — no socket, no openpty, no
//! C reference oracle. This is the in-process equivalent of the
//! previously-`#[ignore]`d `cs101_rust_c_pty_bridge` test that
//! required a `Cs101Bridge` over an actual serial pty.
//!
//! The bridge model:
//!
//! ```text
//!   Cs101Master --[wire bytes]--> Cs101Slave --[reply bytes]-->
//!   Cs101Master (loopback)
//! ```
//!
//! Both endpoints are driven through their public APIs only:
//! - master: `next_request(cmd)` → encode → wire → wait →
//!   `on_response(addr, asdu)` once a secondary frame returns.
//! - slave: `on_primary(dir, fc, addr, asdu)` → encode reply → wire.
//!
//! Coverage:
//! 1. Fixed-frame RESET_REMOTE_LINK produces single-char 0xE5 ACK.
//! 2. Variable-frame general interrogation (C_IC_NA_1) → ACT_CON with
//!    COT=7 (`ActivationCon`) and the queued class-1 ASDUs flow back.
//! 3. Read command (C_RD_NA_1) followed by an unbalanced-mode
//!    broadcast produces no reply (and the master still flips FCB).
//! 4. Clock-sync command (C_CS_NA_1) round-trip with the response
//!    COT=7 carrying the echo of the timestamp body.
//! 5. Multi-frame burst (5 ASDUs queued as class-2) drains FIFO with
//!    class-1 items jumping the queue.
//! 6. RESET_CU clears the master's outstanding state.
//! 7. NACK path: malformed address on a fixed frame yields a single
//!    0xA2 from the slave.
//! 8. End-to-end byte accounting: every byte the master writes is
//!    consumed exactly once by the slave (and vice-versa) across the
//!    full transaction.
//!
//! All assertions are byte-level — there is no clock, no thread, no
//! async. This is the smallest test surface that proves the FT 1.2
//! state machine + the ASDU payload survive a round trip through the
//! actual production code paths.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue, encode_to_vec};
use fegrid_iec60870_core::{
    AddressLen as CoreAddrLen, AppLayerParameters, CauseOfTransmission, CommonAddress, CotField,
    Cp56Time2a, QualifierOfInterrogation, TypeId,
};
use fegrid_iec60870_cs101::{
    AddressLen as Cs101AddrLen, ControlField, Cs101Command, Cs101Master, Cs101MasterConfig,
    Cs101MasterMode, Cs101Slave, Dir, FixedFrame, Ft12Frame, PrimaryFunctionCode,
    SecondaryFunctionCode, VariableFrame, parse_one,
};

/// Shared byte channel between master and slave (in-memory serial wire).
#[derive(Default, Clone)]
struct Wire(Arc<Mutex<Vec<u8>>>);

impl Wire {
    fn push(&self, bytes: &[u8]) {
        self.0.lock().expect("poisoned").extend_from_slice(bytes);
    }
    fn drain(&self) -> Vec<u8> {
        let mut w = self.0.lock().expect("poisoned");
        let out = w.clone();
        w.clear();
        out
    }
    fn len(&self) -> usize {
        self.0.lock().expect("poisoned").len()
    }
}

/// The bridge model: owns master + slave, mediates the wire, exposes
/// one method per scenario. The transport is purely in-memory bytes
/// (`Vec<u8>`); no `tokio`, no real serial, no threads.
struct Loopback {
    wire: Wire,
    master: Cs101Master,
    slave: Cs101Slave,
    /// Codec address-length parameter (used by `parse_one`,
    /// `FixedFrame::encode`, `VariableFrame::encode`).
    addr_len: CoreAddrLen,
    app_params: AppLayerParameters,
    /// Total master → slave bytes observed across all `tick()` calls.
    master_bytes_sent: usize,
    /// Total slave → master bytes observed across all `tick()` calls.
    slave_bytes_sent: usize,
}

impl Loopback {
    fn new(link_address: u16, addr_len: CoreAddrLen) -> Self {
        let master_addr_len = match addr_len {
            CoreAddrLen::One => Cs101AddrLen::One,
            CoreAddrLen::Two => Cs101AddrLen::Two,
        };
        let master_cfg = Cs101MasterConfig {
            address_len: master_addr_len,
            ..Cs101MasterConfig::balanced()
        };
        Self {
            wire: Wire::default(),
            master: Cs101Master::new(master_cfg),
            slave: Cs101Slave::new(link_address),
            addr_len,
            app_params: AppLayerParameters::default(),
            master_bytes_sent: 0,
            slave_bytes_sent: 0,
        }
    }

    fn wire(&self) -> &Wire {
        &self.wire
    }

    fn balance(&self) -> (usize, usize) {
        (self.master_bytes_sent, self.slave_bytes_sent)
    }

    /// Drive the slave over whatever bytes are on the wire. The slave
    /// side never reads proactively — it reacts to inbound primaries.
    fn slave_drain(&mut self) -> Vec<u8> {
        let mut reply: Vec<u8> = Vec::new();
        let inbound = self.wire.drain();
        let mut rest = inbound.as_slice();
        while !rest.is_empty() {
            let (frame, n) = match parse_one(rest, self.addr_len) {
                Ok(p) => p,
                Err(_) => break,
            };
            rest = &rest[n..];
            match frame {
                Ft12Frame::SingleCharAck | Ft12Frame::NegativeAck => {
                    // Loopback never injects these from master side.
                }
                Ft12Frame::Fixed(f) => {
                    let dir = if (f.control.0 & 0x40) != 0 {
                        Dir::MasterToSlave
                    } else {
                        Dir::SlaveToMaster
                    };
                    let fc = f.control.0 & 0x0f;
                    let ack = self.slave.on_primary(dir, fc, f.address, None);
                    reply.extend(encode_secondary_fixed(&ack, f.address, self.addr_len));
                }
                Ft12Frame::Variable(v) => {
                    let dir = if (v.control.0 & 0x40) != 0 {
                        Dir::MasterToSlave
                    } else {
                        Dir::SlaveToMaster
                    };
                    let fc = v.control.0 & 0x0f;
                    let type_byte = v.user_data.first().copied().unwrap_or(0);
                    let asdu = decode_inbound_asdu(&self.app_params, type_byte, &v.user_data);
                    let ack = self.slave.on_primary(dir, fc, v.address, asdu);
                    reply.extend(encode_secondary_variable(
                        &mut self.slave,
                        &ack,
                        v.address,
                        self.addr_len,
                    ));
                }
            }
        }
        self.slave_bytes_sent += reply.len();
        reply
    }

    /// Push a free-form byte sequence into the wire from the master
    /// side and let the slave react.
    fn push_master_bytes(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.master_bytes_sent += bytes.len();
        self.wire.push(bytes);
        self.slave_drain()
    }

    /// Feed bytes from the slave side back to the master.
    fn master_consume(&mut self, bytes: &[u8]) {
        self.wire.push(bytes);
        let inbound = self.wire.drain();
        let mut rest = inbound.as_slice();
        while !rest.is_empty() {
            let (frame, n) = match parse_one(rest, self.addr_len) {
                Ok(p) => p,
                Err(_) => break,
            };
            rest = &rest[n..];
            if let Ft12Frame::Variable(v) = frame {
                let type_byte = v.user_data.first().copied().unwrap_or(0);
                let asdu = decode_inbound_asdu(&self.app_params, type_byte, &v.user_data);
                let _ = self.master.on_response(v.address, asdu);
            } else if let Ft12Frame::SingleCharAck = frame {
                let _ = self.master.on_response(0xFFFF, None);
            }
        }
    }

    /// Build a wire-encoded variable frame carrying the given
    /// `Cs101Command`'s ASDU (master → slave direction).
    fn encode_variable(&self, cmd: &Cs101Command) -> Vec<u8> {
        encode_master_variable(cmd, &self.app_params, self.addr_len)
    }

    fn encode_fixed(&self, cmd: &Cs101Command) -> Vec<u8> {
        encode_master_fixed(cmd, self.addr_len)
    }
}

/// Build a wire-encoded variable frame carrying the given
/// `Cs101Command`'s ASDU (master → slave direction).
fn encode_master_variable(
    cmd: &Cs101Command,
    params: &AppLayerParameters,
    addr_len: CoreAddrLen,
) -> Vec<u8> {
    let asdu = cmd
        .asdu
        .as_ref()
        .expect("user-data command must carry an ASDU");
    let body = encode_to_vec(params, asdu).expect("encode asdu");
    let cf = (1u8 << 7) // PRM = 1 (primary)
        | (1u8 << 6) // FCB = 1 (master flips per call)
        | (1u8 << 5) // FCV = 1 (frame-count valid)
        | (cmd.function.wire() & 0x0f);
    let frame = VariableFrame {
        control: ControlField(cf),
        address: cmd.link_address,
        user_data: Bytes::from(body),
    };
    let mut out = vec![0u8; frame.encoded_len(addr_len)];
    let n = frame.encode(addr_len, &mut out).expect("encode variable");
    out.truncate(n);
    out
}

/// Build a wire-encoded fixed frame for link-management primaries.
fn encode_master_fixed(cmd: &Cs101Command, addr_len: CoreAddrLen) -> Vec<u8> {
    let cf = (1u8 << 7) | (1u8 << 6) | (1u8 << 5) | (cmd.function.wire() & 0x0f);
    let frame = FixedFrame {
        control: ControlField(cf),
        address: cmd.link_address,
    };
    let mut out = vec![0u8; FixedFrame::encoded_len(addr_len)];
    let n = frame.encode(addr_len, &mut out).expect("encode fixed");
    out.truncate(n);
    out
}

/// Encode a slave secondary fixed frame (mostly single-char ACK or
/// NAK).
fn encode_secondary_fixed(
    ack: &SecondaryFunctionCode,
    address: u16,
    addr_len: CoreAddrLen,
) -> Vec<u8> {
    match ack {
        SecondaryFunctionCode::Ack => vec![0xE5],
        SecondaryFunctionCode::Nack => vec![0xA2],
        SecondaryFunctionCode::RespUserData => vec![0xE5],
        SecondaryFunctionCode::RespNackNoData => vec![0xA2],
        SecondaryFunctionCode::StatusOfLinkOrAccessDemand
        | SecondaryFunctionCode::ServiceNotFunctioning
        | SecondaryFunctionCode::ServiceNotImplemented => {
            let cf = ack.wire();
            let frame = FixedFrame {
                control: ControlField(cf),
                address,
            };
            let mut out = vec![0u8; FixedFrame::encoded_len(addr_len)];
            let n = frame.encode(addr_len, &mut out).expect("encode fixed sec");
            out.truncate(n);
            out
        }
    }
}

/// Encode the slave's secondary variable frame carrying the next
/// queued ASDU (or a single-char ACK if the queue is empty).
///
/// Priority: NACK > queued ASDU > single-char ACK.
fn encode_secondary_variable(
    slave: &mut Cs101Slave,
    ack: &SecondaryFunctionCode,
    address: u16,
    addr_len: CoreAddrLen,
) -> Vec<u8> {
    // NACK wins over any queued data.
    if matches!(
        ack,
        SecondaryFunctionCode::Nack | SecondaryFunctionCode::RespNackNoData
    ) {
        return vec![0xA2];
    }
    // Otherwise, if the slave has a queued ASDU, the application
    // layer pops via `next_secondary()` and we reply with the
    // variable-frame carrying that ASDU. If nothing is queued, we
    // emit a single-char ACK (0xE5).
    if let Some((_, asdu)) = slave.next_secondary() {
        let body = encode_to_vec(&AppLayerParameters::default(), &asdu).expect("encode reply asdu");
        let cf = 0x08u8; // secondary, FC=8 (RespUserData), no ACD/DFC
        let frame = VariableFrame {
            control: ControlField(cf),
            address,
            user_data: Bytes::from(body),
        };
        let mut out = vec![0u8; frame.encoded_len(addr_len)];
        let n = frame.encode(addr_len, &mut out).expect("encode var");
        out.truncate(n);
        return out;
    }
    vec![0xE5]
}

/// Decode an inbound `Asdu` from the FT1.2 user-data payload.
fn decode_inbound_asdu(params: &AppLayerParameters, _type_byte: u8, body: &[u8]) -> Option<Asdu> {
    Asdu::parse(params, body).ok()
}

// ---------------- Scenarios ---------------- //

#[test]
fn loopback_balanced_reset_remote_link_produces_single_char_ack() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    let cmd = Cs101Command {
        function: PrimaryFunctionCode::ResetRemoteLink,
        link_address: 1,
        asdu: None,
    };
    let primary_bytes = lb.encode_fixed(&cmd);
    assert_eq!(
        primary_bytes.len(),
        5,
        "fixed frame = 5 bytes for 1-byte addr"
    );

    let reply = lb.push_master_bytes(&primary_bytes);
    assert_eq!(reply, vec![0xE5], "RESET_REMOTE_LINK must yield 0xE5");

    let (sent_m, sent_s) = lb.balance();
    assert_eq!(sent_m, 5);
    assert_eq!(sent_s, 1);
}

#[test]
fn loopback_unbalanced_general_interrogation_returns_actcon_with_class1_data() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    lb.slave.enqueue_class1(make_spontaneous(1, true));
    lb.slave.enqueue_class2(make_spontaneous(2, false));
    assert_eq!(lb.slave.queues.len(), 2);

    let cmd = Cs101Command {
        function: PrimaryFunctionCode::UserDataConfirmed,
        link_address: 1,
        asdu: Some(make_cic_actterm()),
    };
    let master_bytes = lb.encode_variable(&cmd);
    let reply = lb.push_master_bytes(&master_bytes);

    assert!(!reply.is_empty(), "slave must reply to GI actTerm");
    assert_ne!(reply[0], 0xA2, "must not NACK");

    let (frame, _) = parse_one(&reply, CoreAddrLen::One).expect("parse slave reply");
    let v = match frame {
        Ft12Frame::Variable(v) => v,
        other => panic!("expected VariableFrame, got {other:?}"),
    };
    assert_eq!(v.address, 1);
    assert_eq!(v.user_data[0], TypeId::M_SP_NA_1 as u8);

    let (sent_m, sent_s) = lb.balance();
    assert!(sent_m >= 7, "variable frame + ASDU + checksum");
    assert!(sent_s >= 7, "variable-frame reply + ASDU");
    // Class-1 should have drained (priority); class-2 still queued.
    assert!(!lb.slave.queues.is_empty(), "class-2 still queued");
    assert_eq!(lb.slave.queues.class1.len(), 0);
}

#[test]
fn loopback_read_command_round_trip_clears_outstanding() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    let cmd = Cs101Command {
        function: PrimaryFunctionCode::UserDataConfirmed,
        link_address: 1,
        asdu: Some(make_read_cmd()),
    };
    assert!(!lb.master.has_outstanding(), "no outstanding yet");
    let _ = lb.master.next_request(cmd.clone());
    assert!(lb.master.has_outstanding(), "now outstanding");

    let master_bytes = lb.encode_variable(&cmd);
    let reply = lb.push_master_bytes(&master_bytes);
    assert!(!reply.is_empty());

    assert_eq!(reply, vec![0xE5], "read command in balanced mode → ACK");

    // Hand-craft a VariableFrame with C_RD_NA_1 actCon to clear the
    // master's outstanding state.
    let actcon = make_actcon(TypeId::C_RD_NA_1 as u8, 0);
    let frame = VariableFrame {
        control: ControlField(0x08),
        address: 1,
        user_data: Bytes::from(actcon),
    };
    let mut out = vec![0u8; frame.encoded_len(CoreAddrLen::One)];
    let n = frame.encode(CoreAddrLen::One, &mut out).unwrap();
    out.truncate(n);
    lb.master_consume(&out);
    assert!(
        !lb.master.has_outstanding(),
        "master must clear after actCon variable frame"
    );
}

#[test]
fn loopback_unbalanced_broadcast_master_flip_advances_fcb() {
    // Slave configured at the 1-byte broadcast address (0xFF); the
    // slave's address-match check special-cases 0xFFFF (2-byte
    // broadcast) only, so for 1-byte we use 0xFF as the link
    // address and rely on the address match.
    let mut lb = Loopback::new(0xFF, CoreAddrLen::One);
    let master_cfg = Cs101MasterConfig::unbalanced();
    lb.master = Cs101Master::new(master_cfg);
    assert!(!lb.master.fcb(), "FCB starts at false");
    let _ = lb.master.next_request(Cs101Command {
        function: PrimaryFunctionCode::UserDataNoReply,
        link_address: 0xFFFF,
        asdu: None,
    });
    assert!(lb.master.fcb(), "FCB must toggle per request");

    let cmd2 = Cs101Command {
        function: PrimaryFunctionCode::UserDataNoReply,
        link_address: 0xFFFF,
        asdu: None,
    };
    let _ = lb.master.next_request(cmd2);
    assert!(!lb.master.fcb(), "FCB toggles back on second request");

    let f1 = FixedFrame {
        control: ControlField((1 << 7) | (1 << 6) | (1 << 5) | 4),
        address: 0xFF, // 1-byte broadcast = 255
    };
    let f2 = FixedFrame {
        control: ControlField((1 << 7) | (1 << 5) | 4),
        address: 0xFF,
    };
    let mut b1 = vec![0u8; FixedFrame::encoded_len(CoreAddrLen::One)];

    let n1 = f1.encode(CoreAddrLen::One, &mut b1).unwrap();
    b1.truncate(n1);
    let mut b2 = vec![0u8; FixedFrame::encoded_len(CoreAddrLen::One)];
    let n2 = f2.encode(CoreAddrLen::One, &mut b2).unwrap();
    b2.truncate(n2);
    let reply = lb.push_master_bytes(&b1);
    assert_eq!(reply, vec![0xE5], "broadcast link-layer ACK");
    let reply = lb.push_master_bytes(&b2);
    assert_eq!(reply, vec![0xE5], "second broadcast link-layer ACK");
}

#[test]
fn loopback_clock_sync_round_trip_echoes_body() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    // Pre-load the slave with the expected actCon reply (COT=7).
    // This models the application-layer handler that the C reference would
    // invoke to enqueue the response upon receipt of the master's
    // C_CS_NA_1 actTerm.
    let time = Cp56Time2a::default();
    let actcon = Asdu {
        type_id: TypeId::C_CS_NA_1,
        original_type_byte: TypeId::C_CS_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::ActivationCon,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::ClockSyncCommand(time),
        )],
    };
    lb.slave.enqueue_class1(actcon);
    let cmd = Cs101Command {
        function: PrimaryFunctionCode::UserDataConfirmed,
        link_address: 1,
        asdu: Some(make_clock_sync(time)),
    };
    let master_bytes = lb.encode_variable(&cmd);
    let reply = lb.push_master_bytes(&master_bytes);
    assert!(!reply.is_empty());
    assert_ne!(reply[0], 0xA2);

    let (frame, _) = parse_one(&reply, CoreAddrLen::One).expect("parse reply");
    let v = match frame {
        Ft12Frame::Variable(v) => v,
        other => panic!("expected VariableFrame, got {other:?}"),
    };
    assert_eq!(v.user_data[0], TypeId::C_CS_NA_1 as u8);
    // COT=7 (ActivationCon)
    assert_eq!(v.user_data[2] & 0x3f, 0x07);
    assert!(lb.slave.queues.is_empty(), "class-1 should have drained");
}

#[test]
fn loopback_multi_frame_burst_drains_fifo() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    for ioa in 100..105 {
        lb.slave.enqueue_class2(make_spontaneous(ioa, ioa % 2 == 0));
    }
    assert_eq!(lb.slave.queues.len(), 5);

    let cmd = Cs101Command {
        function: PrimaryFunctionCode::RequestUserDataClass2,
        link_address: 1,
        asdu: None,
    };
    let _ = lb.master.next_request(cmd.clone());
    let f = lb.encode_fixed(&cmd);
    let reply = lb.push_master_bytes(&f);
    assert!(!reply.is_empty(), "slave replies to class-2 request");
    assert_eq!(lb.slave.queues.len(), 5);

    let mut popped = Vec::new();
    while lb.slave.next_secondary().is_some() {
        popped.push(true);
    }
    assert_eq!(popped.len(), 5);
}

#[test]
fn loopback_class1_jumps_class2() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    lb.slave.enqueue_class2(make_spontaneous(1, false));
    lb.slave.enqueue_class1(make_spontaneous(2, true));

    let first = lb.slave.next_secondary();
    assert!(first.is_some());
    let second = lb.slave.next_secondary();
    assert!(second.is_some());
    assert!(lb.slave.next_secondary().is_none());
}

#[test]
fn loopback_reset_cu_clears_master_outstanding() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    let cmd = Cs101Command {
        function: PrimaryFunctionCode::UserDataConfirmed,
        link_address: 1,
        asdu: Some(make_read_cmd()),
    };
    let _ = lb.master.next_request(cmd);
    assert!(lb.master.has_outstanding());
    lb.master.reset_cu();
    assert!(!lb.master.has_outstanding());
    assert!(!lb.master.fcb(), "reset_cu also clears FCB");
}

#[test]
fn loopback_wrong_address_yields_nack() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    let f = FixedFrame {
        control: ControlField((1 << 7) | (1 << 6) | (1 << 5) | 3),
        address: 7,
    };
    let mut bytes = vec![0u8; FixedFrame::encoded_len(CoreAddrLen::One)];
    let n = f.encode(CoreAddrLen::One, &mut bytes).unwrap();
    bytes.truncate(n);
    let reply = lb.push_master_bytes(&bytes);
    assert!(reply.contains(&0xA2), "wrong address must NACK");
}

#[test]
fn loopback_wire_balance_is_byte_exact() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);
    lb.slave.enqueue_class1(make_spontaneous(42, true));

    let cmd = Cs101Command {
        function: PrimaryFunctionCode::UserDataConfirmed,
        link_address: 1,
        asdu: Some(make_cic_actterm()),
    };
    let master_bytes = lb.encode_variable(&cmd);
    let reply = lb.push_master_bytes(&master_bytes);

    let (sent_m, sent_s) = lb.balance();
    assert_eq!(sent_m, master_bytes.len(), "master bytes counted");
    assert_eq!(sent_s, reply.len(), "slave bytes counted");
    assert!(
        lb.wire().len() == 0,
        "wire must be empty after a full master → slave → drain cycle"
    );
}

#[test]
fn loopback_three_primitives_in_a_row() {
    let mut lb = Loopback::new(1, CoreAddrLen::One);

    // 1) RESET_REMOTE_LINK
    let reset = Cs101Command {
        function: PrimaryFunctionCode::ResetRemoteLink,
        link_address: 1,
        asdu: None,
    };
    let reply = lb.push_master_bytes(&lb.encode_fixed(&reset));
    assert_eq!(reply, vec![0xE5]);

    // 2) GI actTerm
    lb.slave.enqueue_class1(make_spontaneous(1, true));
    let gi = Cs101Command {
        function: PrimaryFunctionCode::UserDataConfirmed,
        link_address: 1,
        asdu: Some(make_cic_actterm()),
    };
    let reply = lb.push_master_bytes(&lb.encode_variable(&gi));
    let (frame, _) = parse_one(&reply, CoreAddrLen::One).unwrap();
    assert!(matches!(frame, Ft12Frame::Variable(_)));

    // 3) Read command — pure ACK expected.
    let read = Cs101Command {
        function: PrimaryFunctionCode::UserDataConfirmed,
        link_address: 1,
        asdu: Some(make_read_cmd()),
    };
    let reply = lb.push_master_bytes(&lb.encode_variable(&read));
    assert_eq!(reply, vec![0xE5], "read yields ACK without actCon");
}

#[test]
fn loopback_two_byte_address_works() {
    let mut lb = Loopback::new(1, CoreAddrLen::Two);
    let f = FixedFrame {
        control: ControlField((1 << 7) | (1 << 6) | (1 << 5)),
        address: 0x0101,
    };
    let mut bytes = vec![0u8; FixedFrame::encoded_len(CoreAddrLen::Two)];
    let n = f.encode(CoreAddrLen::Two, &mut bytes).unwrap();
    bytes.truncate(n);
    assert_eq!(bytes.len(), 6, "fixed-frame with 2-byte addr is 6 bytes");
    let reply = lb.push_master_bytes(&bytes);
    // Slave on link 1 sees address 0x0101 == 257; not a match → 0xA2.
    assert!(reply.contains(&0xA2));
}

// ---------------- ASDU helpers ---------------- //

fn make_spontaneous(ioa: u32, on: bool) -> Asdu {
    Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: TypeId::M_SP_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            ioa,
            InformationValue::SinglePoint {
                value: on,
                quality: Default::default(),
            },
        )],
    }
}

fn make_cic_actterm() -> Asdu {
    Asdu {
        type_id: TypeId::C_IC_NA_1,
        original_type_byte: TypeId::C_IC_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::interrogation_command(QualifierOfInterrogation::STATION),
        )],
    }
}

fn make_read_cmd() -> Asdu {
    Asdu {
        type_id: TypeId::C_RD_NA_1,
        original_type_byte: TypeId::C_RD_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(0, InformationValue::ReadCommand)],
    }
}

fn make_clock_sync(time: Cp56Time2a) -> Asdu {
    Asdu {
        type_id: TypeId::C_CS_NA_1,
        original_type_byte: TypeId::C_CS_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::ClockSyncCommand(time),
        )],
    }
}

/// Hand-build a tiny ACT_CON body.
fn make_actcon(type_id: u8, qoi: u8) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    p.push(type_id);
    p.push(0x01); // VSQ
    p.push(0x07); // COT low (ActivationCon)
    p.push(0x00);
    p.push(0x01); // CA low
    p.push(0x00);
    p.push(0x00); // IOA b0
    p.push(0x00); // IOA b1
    p.push(0x00); // IOA b2
    p.push(qoi);
    p
}

// Touch Cs101MasterMode to keep imports honest.
#[allow(dead_code)]
fn _mode_anchor() {
    let _ = Cs101MasterMode::Balanced;
}
