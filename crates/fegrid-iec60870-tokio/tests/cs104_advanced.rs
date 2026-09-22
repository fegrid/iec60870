//! CS 104 advanced command coverage — SBO, parameter activation,
//! dataset transfer (round-trip + dispatch).
//!
//! ## Coverage matrix
//!
//! | Family       | TypeIds                                  | Tests |
//! |--------------|------------------------------------------|-------|
//! | SBO commands | C_SC_NA_1, C_DC_NA_1                   | 5     |
//! | Setpoints    | C_SE_NA_1, C_SE_NB_1, C_SE_NC_1         | 2     |
//! | Parameters   | P_ME_NA_1, P_ME_NB_1, P_ME_NC_1, P_AC_NA_1 | 5 |
//! | File trans.  | F_FR_NA_1, F_SC_NA_1, F_AF_NA_1, F_DR_TA_1 | 4 |
//!
//! ## Known runtime gaps (TODO)
//!
//! 1. The server's `dispatch_apdu` returns a single ACT_CON per
//!    command. The SBO+ACT_TERM three-message state machine
//!    (select → ACT_CON → execute → ACT_CON + ACT_TERM) is not
//!    implemented; tests assert ACT_CON positive per step.
//! 2. F_DR_TA_1 (file directory) server-runtime round-trip is
//!    covered by `f_dr_ta_1_13_byte_directory_round_trip_through_server_runtime`
//!    below — the encoder emits the full 13-byte body
//!    (name(2) + length_of_file(3) + sof(1) + CP56Time2a(7)).
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{
    Asdu, InformationObject, InformationValue, activation_confirm, encode_to_vec,
};
use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
use fegrid_iec60870_cs104::{Apdu, SeqNo, UFrame};
use fegrid_iec60870_tokio::{ApduCodec, CommandHandler, Server, ServerConfig, ServerHandlers};

async fn alloc_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

async fn do_startdt(stream: &mut TcpStream) {
    let mut framed = Framed::new(stream, ApduCodec::new());
    framed
        .send(Apdu::U(UFrame::StartDtAct))
        .await
        .expect("send STARTDT_ACT");
    let apdu = timeout(Duration::from_secs(2), framed.next())
        .await
        .expect("STARTDT_CON timeout")
        .expect("STARTDT_CON frame")
        .expect("STARTDT_CON parse");
    assert!(matches!(apdu, Apdu::U(UFrame::StartDtCon)));
}

async fn do_stopdt(stream: &mut TcpStream) {
    let mut framed = Framed::new(stream, ApduCodec::new());
    framed
        .send(Apdu::U(UFrame::StopDtAct))
        .await
        .expect("send STOPDT_ACT");
    let apdu = timeout(Duration::from_secs(2), framed.next())
        .await
        .expect("STOPDT_CON timeout")
        .expect("STOPDT_CON frame")
        .expect("STOPDT_CON parse");
    assert!(matches!(apdu, Apdu::U(UFrame::StopDtCon)));
}

async fn send_asdu(framed: &mut Framed<TcpStream, ApduCodec>, ns: u16, asdu: Asdu) {
    framed
        .send(Apdu::I {
            ns: SeqNo(ns),
            nr: SeqNo(0),
            asdu: Some(asdu),
        })
        .await
        .expect("send I-frame");
}

async fn next_asdu(framed: &mut Framed<TcpStream, ApduCodec>, ms: u64) -> Option<Asdu> {
    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let next = timeout(remaining, framed.next()).await;
        match next {
            Ok(Some(Ok(Apdu::I { asdu: Some(a), .. }))) => return Some(a),
            Ok(Some(Ok(Apdu::S { .. }))) => continue,
            _ => return None,
        }
    }
}

fn make_command_asdu(type_id: TypeId, ioa: u32, select: bool, qu: u8) -> Asdu {
    Asdu {
        type_id,
        original_type_byte: type_id as u8,
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
            ioa,
            InformationValue::SingleCommand {
                on: true,
                select,
                qu,
            },
        )],
    }
}

fn make_setpoint_asdu_normalized(ioa: u32, value: i16, ql: u8) -> Asdu {
    Asdu {
        type_id: TypeId::C_SE_NA_1,
        original_type_byte: TypeId::C_SE_NA_1 as u8,
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
            ioa,
            InformationValue::SetpointNormalized { value, ql },
        )],
    }
}

fn make_parameter_load_asdu(ioa: u32, qpm: u8, value_normalized: i16) -> Asdu {
    Asdu {
        type_id: TypeId::P_ME_NA_1,
        original_type_byte: TypeId::P_ME_NA_1 as u8,
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
            ioa,
            InformationValue::ParameterNormalized {
                value: value_normalized,
                qpm,
            },
        )],
    }
}

fn make_parameter_activate_asdu(ioa: u32, qpm: u8) -> Asdu {
    Asdu {
        type_id: TypeId::P_AC_NA_1,
        original_type_byte: TypeId::P_AC_NA_1 as u8,
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
            ioa,
            InformationValue::ParameterActivation { qpm },
        )],
    }
}

async fn new_server_with_default_handlers(addr: SocketAddr) -> Arc<Server> {
    let handlers = ServerHandlers::new();
    let confirm_handler: CommandHandler = Arc::new(|req| Some(activation_confirm(req)));
    for tid in [
        TypeId::C_SC_NA_1,
        TypeId::C_DC_NA_1,
        TypeId::C_RC_NA_1,
        TypeId::C_SE_NA_1,
        TypeId::C_SE_NB_1,
        TypeId::C_SE_NC_1,
        TypeId::C_BO_NA_1,
        TypeId::C_SE_TA_1,
        TypeId::C_SE_TB_1,
        TypeId::C_SE_TC_1,
        TypeId::C_SC_TA_1,
        TypeId::C_DC_TA_1,
        TypeId::C_RC_TA_1,
        TypeId::C_BO_TA_1,
        TypeId::P_ME_NA_1,
        TypeId::P_ME_NB_1,
        TypeId::P_ME_NC_1,
        TypeId::P_AC_NA_1,
        TypeId::F_FR_NA_1,
        TypeId::F_SC_NA_1,
        TypeId::F_AF_NA_1,
    ] {
        handlers.register(tid as u8, confirm_handler.clone());
    }
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    Server::bind(cfg).await.expect("bind")
}

// ===========================================================================
// Select-Before-Operate (SBO)
// ===========================================================================

#[tokio::test]
async fn sbo_select_returns_positive_act_con() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let _server = new_server_with_default_handlers(addr).await;

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(
        &mut framed,
        0,
        make_command_asdu(TypeId::C_SC_NA_1, 1, true, 0),
    )
    .await;
    let r = next_asdu(&mut framed, 1500).await.expect("select ACK");
    assert_eq!(r.type_id, TypeId::C_SC_NA_1);
    assert_eq!(r.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r.cot.negative_confirm);

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

#[tokio::test]
async fn sbo_execute_returns_positive_act_con() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let _server = new_server_with_default_handlers(addr).await;

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(
        &mut framed,
        0,
        make_command_asdu(TypeId::C_SC_NA_1, 1, false, 0),
    )
    .await;
    let r = next_asdu(&mut framed, 1500).await.expect("execute ACK");
    assert_eq!(r.type_id, TypeId::C_SC_NA_1);
    assert_eq!(r.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r.cot.negative_confirm);

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

#[tokio::test]
async fn sbo_two_step_each_step_returns_act_con() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let _server = new_server_with_default_handlers(addr).await;

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(
        &mut framed,
        0,
        make_command_asdu(TypeId::C_SC_NA_1, 1, true, 0),
    )
    .await;
    let r1 = next_asdu(&mut framed, 1500).await.expect("select ACK");
    assert_eq!(r1.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r1.cot.negative_confirm);

    send_asdu(
        &mut framed,
        1,
        make_command_asdu(TypeId::C_SC_NA_1, 1, false, 0),
    )
    .await;
    let r2 = next_asdu(&mut framed, 1500).await.expect("execute ACK");
    assert_eq!(r2.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r2.cot.negative_confirm);

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

#[tokio::test]
async fn sbo_double_select_second_select_returns_act_con() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let _server = new_server_with_default_handlers(addr).await;

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(
        &mut framed,
        0,
        make_command_asdu(TypeId::C_SC_NA_1, 1, true, 0),
    )
    .await;
    let r1 = next_asdu(&mut framed, 1500).await.expect("select#1 ACK");
    assert!(!r1.cot.negative_confirm);

    send_asdu(
        &mut framed,
        1,
        make_command_asdu(TypeId::C_SC_NA_1, 1, true, 0),
    )
    .await;
    let r2 = next_asdu(&mut framed, 1500).await.expect("select#2 ACK");
    assert!(!r2.cot.negative_confirm);

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

#[tokio::test]
async fn sbo_select_then_execute_different_ioa_returns_act_con() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let _server = new_server_with_default_handlers(addr).await;

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(
        &mut framed,
        0,
        make_command_asdu(TypeId::C_SC_NA_1, 1, true, 0),
    )
    .await;
    let _ = next_asdu(&mut framed, 1500).await.expect("select ACK");

    send_asdu(
        &mut framed,
        1,
        make_command_asdu(TypeId::C_SC_NA_1, 2, false, 0),
    )
    .await;
    let r = next_asdu(&mut framed, 1500).await.expect("execute ACK");
    assert_eq!(r.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r.cot.negative_confirm);

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

#[tokio::test]
async fn sbo_direct_operate_qu_skip_select() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let _server = new_server_with_default_handlers(addr).await;

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(
        &mut framed,
        0,
        make_command_asdu(TypeId::C_SC_NA_1, 1, false, 1),
    )
    .await;
    let r = next_asdu(&mut framed, 1500).await.expect("response");
    assert_eq!(r.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r.cot.negative_confirm);

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

// ===========================================================================
// Setpoint commands
// ===========================================================================

#[tokio::test]
async fn setpoint_normalized_round_trip() {
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    let asdu = make_setpoint_asdu_normalized(0x010203, 12345, 0);
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = Asdu::parse(&params, &bytes).unwrap();
    assert_eq!(parsed.type_id, TypeId::C_SE_NA_1);
    if let InformationValue::SetpointNormalized { value, ql } = &parsed.objects[0].value {
        assert_eq!(*value, 12345);
        assert_eq!(*ql, 0);
    } else {
        panic!("expected SetpointNormalized");
    }
}

#[tokio::test]
async fn setpoint_float_round_trip_preserves_value() {
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    for value in [
        0.0f32,
        1.0,
        -1.0,
        std::f32::consts::PI,
        f32::MIN,
        f32::MAX,
        f32::EPSILON,
    ] {
        let asdu = Asdu {
            type_id: TypeId::C_SE_NC_1,
            original_type_byte: TypeId::C_SE_NC_1 as u8,
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
                0x4040,
                InformationValue::SetpointFloat { value, ql: 0 },
            )],
        };
        let bytes = encode_to_vec(&params, &asdu).unwrap();
        let parsed = Asdu::parse(&params, &bytes).unwrap();
        if let InformationValue::SetpointFloat { value: v, ql } = &parsed.objects[0].value {
            assert_eq!(*v, value, "round-trip changed f32 value");
            assert_eq!(*ql, 0);
        } else {
            panic!("expected SetpointFloat");
        }
    }
}

#[tokio::test]
async fn sbo_with_setpoint_value_visible_to_handler() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let captured = Arc::new(Mutex::new(None::<i16>));
    let captured_clone = captured.clone();
    let handlers = ServerHandlers::new();
    let setpoint_handler: CommandHandler = Arc::new(move |req| {
        if let Some((InformationValue::SetpointNormalized { value, .. }, _ioa)) =
            req.objects.first().map(|o| (&o.value, o.ioa))
        {
            *captured_clone.lock().unwrap() = Some(*value);
        }
        Some(activation_confirm(req))
    });
    handlers.register(TypeId::C_SE_NA_1 as u8, setpoint_handler);
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(&mut framed, 0, make_setpoint_asdu_normalized(1, 4242, 0)).await;
    let _ = next_asdu(&mut framed, 1500).await.expect("setpoint ACK");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        *captured.lock().unwrap(),
        Some(4242),
        "handler should have seen setpoint value 4242"
    );

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

// ===========================================================================
// Parameter activation
// ===========================================================================

#[tokio::test]
async fn parameter_normalized_load_round_trip() {
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    let asdu = make_parameter_load_asdu(0xABCDEF, 0x10, -12345);
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = Asdu::parse(&params, &bytes).unwrap();
    assert_eq!(parsed.type_id, TypeId::P_ME_NA_1);
    if let InformationValue::ParameterNormalized { value, qpm } = &parsed.objects[0].value {
        assert_eq!(*value, -12345);
        assert_eq!(*qpm, 0x10);
    } else {
        panic!("expected ParameterNormalized");
    }
}

#[tokio::test]
async fn parameter_activate_qpm_1_round_trip() {
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    let asdu = make_parameter_activate_asdu(0x0100, 1);
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = Asdu::parse(&params, &bytes).unwrap();
    assert_eq!(parsed.type_id, TypeId::P_AC_NA_1);
    if let InformationValue::ParameterActivation { qpm } = &parsed.objects[0].value {
        assert_eq!(*qpm, 1, "qpm=1 = activate previously loaded parameter");
    } else {
        panic!("expected ParameterActivation");
    }
}

#[tokio::test]
async fn parameter_load_then_activate_dispatches_both_events() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let load_count = Arc::new(AtomicUsize::new(0));
    let activate_count = Arc::new(AtomicUsize::new(0));
    let lc = load_count.clone();
    let ac = activate_count.clone();
    let handlers = ServerHandlers::new();
    let load_handler: CommandHandler = Arc::new(move |req| {
        lc.fetch_add(1, Ordering::SeqCst);
        Some(activation_confirm(req))
    });
    let activate_handler: CommandHandler = Arc::new(move |req| {
        ac.fetch_add(1, Ordering::SeqCst);
        Some(activation_confirm(req))
    });
    handlers.register(TypeId::P_ME_NA_1 as u8, load_handler);
    handlers.register(TypeId::P_AC_NA_1 as u8, activate_handler);
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(&mut framed, 0, make_parameter_load_asdu(1, 0x10, 42)).await;
    let _ = next_asdu(&mut framed, 1500).await.expect("load ACK");

    send_asdu(&mut framed, 1, make_parameter_activate_asdu(1, 1)).await;
    let _ = next_asdu(&mut framed, 1500).await.expect("activate ACK");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(load_count.load(Ordering::SeqCst), 1);
    assert_eq!(activate_count.load(Ordering::SeqCst), 1);

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

// ===========================================================================
// Dataset / file transfer
// ===========================================================================

#[tokio::test]
async fn file_ready_round_trip() {
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_FR_NA_1,
        original_type_byte: TypeId::F_FR_NA_1 as u8,
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
            1,
            InformationValue::FileReady {
                name: 0x4242,
                length: 0x0012_3456,
                frq: 0,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = Asdu::parse(&params, &bytes).unwrap();
    if let InformationValue::FileReady {
        name,
        length,
        frq: _,
    } = &parsed.objects[0].value
    {
        assert_eq!(*name, 0x4242);
        assert_eq!(*length, 0x0012_3456);
    } else {
        panic!("expected FileReady");
    }
}

#[tokio::test]
async fn file_ack_positive_round_trip() {
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_AF_NA_1,
        original_type_byte: TypeId::F_AF_NA_1 as u8,
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
            1,
            InformationValue::FileAck {
                name: 0x4242,
                section: 0x00,
                afq: 0,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = Asdu::parse(&params, &bytes).unwrap();
    if let InformationValue::FileAck { name, section, afq } = &parsed.objects[0].value {
        assert_eq!(*name, 0x4242);
        assert_eq!(*section, 0x00);
        assert_eq!(*afq, 0);
    } else {
        panic!("expected FileAck");
    }
}

#[tokio::test]
async fn file_call_select_round_trip() {
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_SC_NA_1,
        original_type_byte: TypeId::F_SC_NA_1 as u8,
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
            1,
            InformationValue::FileCall {
                name: 0x4242,
                section: 0x00,
                scq: 0,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = Asdu::parse(&params, &bytes).unwrap();
    if let InformationValue::FileCall { name, section, scq } = &parsed.objects[0].value {
        assert_eq!(*name, 0x4242);
        assert_eq!(*section, 0x00);
        assert_eq!(*scq, 0);
    } else {
        panic!("expected FileCall");
    }
}

#[tokio::test]
async fn file_transfer_state_machine_dispatches_each_phase() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let counters = [
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    ];
    let handlers = ServerHandlers::new();
    for (idx, type_id) in [TypeId::F_FR_NA_1, TypeId::F_SC_NA_1, TypeId::F_AF_NA_1]
        .iter()
        .enumerate()
    {
        let c = counters[idx].clone();
        let tid = *type_id as u8;
        handlers.register(
            tid,
            Arc::new(move |req| {
                c.fetch_add(1, Ordering::SeqCst);
                Some(activation_confirm(req))
            }),
        );
    }
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    let asdus = [
        Asdu {
            type_id: TypeId::F_FR_NA_1,
            original_type_byte: TypeId::F_FR_NA_1 as u8,
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
                1,
                InformationValue::FileReady {
                    name: 0x01,
                    length: 0x10,
                    frq: 0,
                },
            )],
        },
        Asdu {
            type_id: TypeId::F_SC_NA_1,
            original_type_byte: TypeId::F_SC_NA_1 as u8,
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
                1,
                InformationValue::FileCall {
                    name: 0x01,
                    section: 0x00,
                    scq: 0,
                },
            )],
        },
        Asdu {
            type_id: TypeId::F_AF_NA_1,
            original_type_byte: TypeId::F_AF_NA_1 as u8,
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
                1,
                InformationValue::FileAck {
                    name: 0x01,
                    section: 0x00,
                    afq: 0,
                },
            )],
        },
    ];
    for (i, asdu) in asdus.into_iter().enumerate() {
        send_asdu(&mut framed, i as u16, asdu).await;
        let _ = next_asdu(&mut framed, 1500).await.expect("ACK");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(counters[0].load(Ordering::SeqCst), 1, "F_FR dispatched");
    assert_eq!(counters[1].load(Ordering::SeqCst), 1, "F_SC dispatched");
    assert_eq!(counters[2].load(Ordering::SeqCst), 1, "F_AF dispatched");

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

#[tokio::test]
async fn sbo_two_step_chain_select_then_execute_matches_ioa() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // Register a custom handler that returns ACT_CON positive for any
    // command. The default handlers only cover GI/CI/RD/CS/RP/CD.
    let confirm_count = Arc::new(AtomicUsize::new(0));
    let cc = confirm_count.clone();
    let handlers = ServerHandlers::new();
    handlers.register(
        TypeId::C_SC_NA_1 as u8,
        Arc::new(move |req| {
            cc.fetch_add(1, Ordering::SeqCst);
            Some(activation_confirm(req))
        }),
    );
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    // Step 1: select
    send_asdu(
        &mut framed,
        0,
        make_command_asdu(TypeId::C_SC_NA_1, 1, true, 0),
    )
    .await;
    let r1 = next_asdu(&mut framed, 1500).await.expect("select ACK");
    assert_eq!(r1.type_id, TypeId::C_SC_NA_1);
    assert_eq!(r1.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r1.cot.negative_confirm, "select ACT_CON must be positive");

    // Step 2: execute
    send_asdu(
        &mut framed,
        1,
        make_command_asdu(TypeId::C_SC_NA_1, 1, false, 0),
    )
    .await;
    let r2 = next_asdu(&mut framed, 1500).await.expect("execute ACK");
    assert_eq!(r2.type_id, TypeId::C_SC_NA_1);
    assert_eq!(r2.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r2.cot.negative_confirm, "execute ACT_CON must be positive");

    // Step 3: re-select
    send_asdu(
        &mut framed,
        2,
        make_command_asdu(TypeId::C_SC_NA_1, 1, true, 0),
    )
    .await;
    let r3 = next_asdu(&mut framed, 1500).await.expect("reselect ACK");
    assert_eq!(r3.type_id, TypeId::C_SC_NA_1);
    assert_eq!(r3.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(
        !r3.cot.negative_confirm,
        "re-select ACT_CON must be positive"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        confirm_count.load(Ordering::SeqCst),
        3,
        "handler called 3 times (select + execute + reselect)"
    );

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

#[tokio::test]
async fn parameter_load_then_activate_dispatches_both_handlers() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let load_calls = Arc::new(AtomicUsize::new(0));
    let activate_calls = Arc::new(AtomicUsize::new(0));
    let load_seen = Arc::new(Mutex::new(None::<TypeId>));
    let activate_seen = Arc::new(Mutex::new(None::<TypeId>));
    let lc = load_calls.clone();
    let ac = activate_calls.clone();
    let ls = load_seen.clone();
    let as_ = activate_seen.clone();
    let handlers = ServerHandlers::new();
    handlers.register(
        TypeId::P_ME_NA_1 as u8,
        Arc::new(move |_req| {
            lc.fetch_add(1, Ordering::SeqCst);
            *ls.lock().unwrap() = Some(TypeId::P_ME_NA_1);
            Some(activation_confirm(_req))
        }),
    );
    handlers.register(
        TypeId::P_AC_NA_1 as u8,
        Arc::new(move |_req| {
            ac.fetch_add(1, Ordering::SeqCst);
            *as_.lock().unwrap() = Some(TypeId::P_AC_NA_1);
            Some(activation_confirm(_req))
        }),
    );
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(&mut framed, 0, make_parameter_load_asdu(1, 0x10, 42)).await;
    let _ = next_asdu(&mut framed, 1500).await.expect("load ACK");

    send_asdu(&mut framed, 1, make_parameter_activate_asdu(1, 1)).await;
    let _ = next_asdu(&mut framed, 1500).await.expect("activate ACK");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        load_calls.load(Ordering::SeqCst),
        1,
        "load handler called once"
    );
    assert_eq!(
        activate_calls.load(Ordering::SeqCst),
        1,
        "activate handler called once"
    );
    assert_eq!(*load_seen.lock().unwrap(), Some(TypeId::P_ME_NA_1));
    assert_eq!(*activate_seen.lock().unwrap(), Some(TypeId::P_AC_NA_1));

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

/// IEC 60870-5-101 §7.4.5.4 / IEC TS 60870-5-604 §7.4: P_AC_NA_1
/// with qpa bit 7 = 0 means "activate the previously loaded
/// parameter". The activate handler MUST run, and the server
/// replies with ACTIVATION_CON positive.
///
/// Companion test:
/// `parameter_activate_qpa_read_only_does_not_invoke_activate_handler`
/// pins the qpa bit 7 = 1 (read-only preview) path.
#[tokio::test]
async fn parameter_activate_qpa_zero_invokes_activate_handler() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let activate_calls = Arc::new(AtomicUsize::new(0));
    let ac = activate_calls.clone();
    let handlers = ServerHandlers::new();
    handlers.register(
        TypeId::P_AC_NA_1 as u8,
        Arc::new(move |_req| {
            ac.fetch_add(1, Ordering::SeqCst);
            Some(activation_confirm(_req))
        }),
    );
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    send_asdu(&mut framed, 0, make_parameter_activate_asdu(1, 0)).await;
    let r = next_asdu(&mut framed, 1500).await.expect("activate ACK");
    assert_eq!(r.type_id, TypeId::P_AC_NA_1);
    assert_eq!(r.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!r.cot.negative_confirm);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        activate_calls.load(Ordering::SeqCst),
        1,
        "qpa bit 7 = 0 → activate handler IS invoked (activate previously loaded parameter)"
    );

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

/// IEC 60870-5-101 §7.4.5.4: P_AC_NA_1 with qpa bit 7 = 1 is a
/// read-only preview — the controlled station shall reply with
/// ACTIVATION_CON positive WITHOUT invoking the activate handler.
/// This test pins the qpa-aware dispatch on the live CS 104
/// runtime (see `dispatch_apdu` in
/// `crates/fegrid-iec60870-tokio/src/server.rs`).
#[tokio::test]
async fn parameter_activate_qpa_read_only_does_not_invoke_activate_handler() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let activate_calls = Arc::new(AtomicUsize::new(0));
    let ac = activate_calls.clone();
    let handlers = ServerHandlers::new();
    handlers.register(
        TypeId::P_AC_NA_1 as u8,
        Arc::new(move |_req| {
            ac.fetch_add(1, Ordering::SeqCst);
            Some(activation_confirm(_req))
        }),
    );
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    // qpm = 0x80 → qpa bit 7 set → read-only preview
    send_asdu(&mut framed, 0, make_parameter_activate_asdu(1, 0x80)).await;
    let r = next_asdu(&mut framed, 1500)
        .await
        .expect("ACT_CON for read-only");
    assert_eq!(r.type_id, TypeId::P_AC_NA_1);
    assert_eq!(r.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(
        !r.cot.negative_confirm,
        "read-only ACT_CON must be positive"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        activate_calls.load(Ordering::SeqCst),
        0,
        "qpa bit 7 = 1 → activate handler MUST NOT be invoked (read-only preview)"
    );

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

// ===========================================================================
// F_DR_TA_1 (file directory) — server-runtime round-trip
// ===========================================================================

/// IEC 60870-5-101 §7.4.8.13 F_DR_TA_1 file directory body is
/// 13 bytes: NOF(2) + LOF(3) + SOF(1) + CP56Time2a(7). This test
/// exercises the full server-runtime decode → process → re-encode
/// path: the encoder in `fegrid-iec60870-asdu` already emits the
/// 13 bytes for `InformationValue::FileDirectory`, but the only
/// pre-existing coverage (`typed_bodies.rs::f_dr_ta_1_round_trip_with_cp56`)
/// bypasses the runtime. This test sends a real F_DR_TA_1 I-frame
/// to a live `Server`, registers a handler that echoes the request
/// back via `activation_confirm(req)`, and asserts the bytes echoed
/// back through the CS 104 transport equal the original 13-byte
/// body byte-for-byte.
#[tokio::test]
async fn f_dr_ta_1_13_byte_directory_round_trip_through_server_runtime() {
    use fegrid_iec60870_core::Cp56Time2a;
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handlers = ServerHandlers::new();
    handlers.register(
        TypeId::F_DR_TA_1 as u8,
        Arc::new(|req| Some(activation_confirm(req))),
    );
    let cfg = ServerConfig::new(addr).handlers(handlers).max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    let creation_time = Cp56Time2a {
        ms: 0x4985,
        minutes: 0x0c,
        hours: 0x09,
        day_of_month: 0x15,
        day_of_week: 0x01,
        month: 0x01,
        year: 24,
        invalid: false,
        summer_time: false,
    };
    let name: u16 = 0x0F00;
    let length_of_file: u32 = 0x12_3456;
    let sof: u8 = 0x07;
    let ioa: u32 = 1;
    let req = Asdu {
        type_id: TypeId::F_DR_TA_1,
        original_type_byte: TypeId::F_DR_TA_1 as u8,
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
            ioa,
            InformationValue::FileDirectory {
                name,
                length_of_file,
                sof,
                creation_time,
            },
        )],
    };
    send_asdu(&mut framed, 0, req).await;
    let resp = next_asdu(&mut framed, 1500)
        .await
        .expect("ACT_CON reply from server");
    assert_eq!(resp.type_id, TypeId::F_DR_TA_1);
    assert_eq!(resp.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!resp.cot.negative_confirm, "ACT_CON positive");
    assert_eq!(resp.objects.len(), 1);
    let obj = &resp.objects[0];
    let InformationValue::FileDirectory {
        name: r_name,
        length_of_file: r_lof,
        sof: r_sof,
        creation_time: r_ct,
    } = obj.value
    else {
        panic!("expected FileDirectory in echo, got {:?}", obj.value);
    };
    assert_eq!(r_name, name);
    assert_eq!(r_lof, length_of_file);
    assert_eq!(r_sof, sof);
    assert_eq!(r_ct, creation_time);
    // Byte-exact wire check: encode the echoed ASDU and assert the
    // 13-byte object body equals the original hand-built payload.
    let params = fegrid_iec60870_core::AppLayerParameters::default();
    let echoed_bytes = encode_to_vec(&params, &resp).expect("encode echoed");
    // Layout: ASDU header (6 bytes) + IOA (3) + body (13) = 22
    // bytes for a single-object, COT=7, no-timestamp F_DR_TA_1.
    let body_start = 6 + 3;
    let body_end = body_start + 13;
    assert!(
        echoed_bytes.len() >= body_end,
        "echoed wire too short: {} bytes",
        echoed_bytes.len()
    );
    let mut expected_body = Vec::with_capacity(13);
    expected_body.extend_from_slice(&name.to_le_bytes()); // 2 bytes
    expected_body.extend_from_slice(&length_of_file.to_le_bytes()[..3]); // 3 bytes
    expected_body.push(sof); // 1 byte
    let mut ts = [0u8; 7];
    creation_time.encode(&mut ts).expect("encode cp56");
    expected_body.extend_from_slice(&ts); // 7 bytes
    assert_eq!(expected_body.len(), 13);
    assert_eq!(
        &echoed_bytes[body_start..body_end],
        &expected_body[..],
        "F_DR_TA_1 echoed body must be 13 byte-for-byte"
    );

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}

// ===========================================================================
// IEC 60870-5-7 secure-authentication (C_ACSE_NA_3, type 135; COT 14/15/16)
// — server-runtime dispatch
// ===========================================================================

/// Echo provider: signs the challenge by truncating its first 4 bytes,
/// verifying trivially. Used as a stand-in for the user's
/// `KeyProvider` impl.
struct EchoKeyProvider;
impl fegrid_iec60870_secauth::KeyProvider for EchoKeyProvider {
    fn algorithm(&self) -> fegrid_iec60870_secauth::AuthAlgorithm {
        fegrid_iec60870_secauth::AuthAlgorithm::GmacSha256
    }
    fn sign(&self, ch: &[u8]) -> Result<Vec<u8>, fegrid_iec60870_secauth::SecAuthError> {
        Ok(ch[..4].to_vec())
    }
    fn verify(&self, ch: &[u8], sig: &[u8]) -> Result<bool, fegrid_iec60870_secauth::SecAuthError> {
        Ok(ch.get(..sig.len()).map(|p| p == sig).unwrap_or(false))
    }
}

fn echo_secure_auth_plugin() -> Arc<fegrid_iec60870_secauth::SecureAuthPlugin> {
    use fegrid_iec60870_secauth::{ChallengeHandler, KeyProvider, SecureAuthBuilder};
    struct PassThrough;
    impl ChallengeHandler for PassThrough {
        fn respond(
            &self,
            p: &dyn KeyProvider,
            ch: &[u8],
        ) -> Result<Vec<u8>, fegrid_iec60870_secauth::SecAuthError> {
            p.sign(ch)
        }
    }
    Arc::new(
        SecureAuthBuilder::default()
            .provider(Arc::new(EchoKeyProvider) as Arc<dyn KeyProvider>)
            .challenge_handler(Arc::new(PassThrough))
            .build()
            .expect("plugin"),
    )
}

/// Build an `Asdu` carrying a single C_ACSE_NA_3 object with the
/// given challenge bytes (response/role/status all default).
fn make_acse_na_3_asdu(cot: CauseOfTransmission, challenge: [u8; 32]) -> Asdu {
    Asdu {
        type_id: TypeId::C_ACSE_NA_3,
        original_type_byte: TypeId::C_ACSE_NA_3 as u8,
        cot: CotField {
            cause: cot,
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
            InformationValue::AcseActivation {
                challenge,
                response: [0u8; 4],
                role: 0,
                status: 0,
            },
        )],
    }
}

/// Master sends a C_ACSE_NA_3 ChallengeRequest (COT 14). Server
/// invokes `SecureAuthPlugin::sign`, builds an ACT_CON positive
/// (status bit 0x80 in CA field), and echoes the challenge with the
/// computed response.
#[tokio::test]
async fn cot14_live_round_trip_through_server_runtime() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let plugin = echo_secure_auth_plugin();
    let cfg = fegrid_iec60870_tokio::ServerConfig::new(addr)
        .secure_auth_plugin(plugin)
        .max_open(4);
    let _server = fegrid_iec60870_tokio::Server::bind(cfg)
        .await
        .expect("bind");

    let mut peer = TcpStream::connect(addr).await.expect("connect");
    do_startdt(&mut peer).await;
    let mut framed = Framed::new(peer, ApduCodec::new());

    let challenge = [0xA5u8; 32];
    send_asdu(
        &mut framed,
        0,
        make_acse_na_3_asdu(CauseOfTransmission::Authentication, challenge),
    )
    .await;
    let resp = next_asdu(&mut framed, 1500)
        .await
        .expect("ACT_CON for secure-auth challenge");
    assert_eq!(resp.type_id, TypeId::C_ACSE_NA_3);
    assert_eq!(resp.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(
        !resp.cot.negative_confirm,
        "ACT_CON positive: CA high bit 0x80 set"
    );
    let obj = &resp.objects[0];
    let InformationValue::AcseActivation {
        challenge: r_ch,
        response: r_resp,
        role: _,
        status: r_status,
    } = obj.value
    else {
        panic!("expected AcseActivation in echo, got {:?}", obj.value);
    };
    assert_eq!(&r_ch[..], &challenge[..]);
    assert_eq!(&r_resp[..], &challenge[..4]);
    assert_eq!(r_status & 0x80, 0x80, "status bit 7 = OK set");

    let mut peer = framed.into_inner();
    do_stopdt(&mut peer).await;
    drop(peer);
}
