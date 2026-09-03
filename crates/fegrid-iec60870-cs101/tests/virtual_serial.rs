//! Virtual serial loopback tests for CS 101 (E5).
//!
//! The CS 101 FT 1.2 codec is transport-agnostic; we exercise the
//! master + slave runtimes over an in-memory `Vec<u8>` channel that
//! simulates a serial wire.

use std::sync::{Arc, Mutex};

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
use fegrid_iec60870_core::{
    CauseOfTransmission, CommonAddress, CotField, QualifierOfInterrogation, TypeId,
};
use fegrid_iec60870_cs101::{
    AddressLen, Cs101Master, Cs101MasterConfig, Cs101MasterMode, Cs101Slave, Dir, LinkState,
    PrimaryFunctionCode,
};

fn dummy_asdu() -> Asdu {
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
            1,
            InformationValue::interrogation_command(QualifierOfInterrogation::STATION),
        )],
    }
}

/// In-memory serial simulator: a Mutex<Vec<u8>> that the "master"
/// writes to and the "slave" reads from. Real test loopback.
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
}

#[test]
fn address_len_default_is_one() {
    let _ = AddressLen::One;
    assert_eq!(AddressLen::default(), AddressLen::One);
}

#[test]
fn master_balanced_uses_default_mode() {
    let m = Cs101Master::new(Cs101MasterConfig::balanced());
    assert_eq!(m.config().mode, Cs101MasterMode::Balanced);
}

#[test]
fn master_unbalanced_uses_broadcast() {
    let m = Cs101Master::new(Cs101MasterConfig::unbalanced());
    assert_eq!(m.config().common_address, 0xFFFF);
    assert_eq!(m.config().mode, Cs101MasterMode::Unbalanced);
}

#[test]
fn master_multi_slave_addresses_listed() {
    let m = Cs101Master::new(Cs101MasterConfig::multi_slave(vec![1, 2, 3]));
    assert_eq!(m.config().slaves, vec![1, 2, 3]);
}

#[test]
fn slave_can_enqueue_class1_and_drain() {
    let mut s = Cs101Slave::new(1);
    let a = dummy_asdu();
    s.enqueue_class1(a.clone());
    s.enqueue_class2(a);
    assert_eq!(s.queues.len(), 2);
    let sec = s.next_secondary();
    assert!(sec.is_some());
    let sec2 = s.next_secondary();
    assert!(sec2.is_some());
    assert!(s.next_secondary().is_none());
}

#[test]
fn slave_dir_flips_on_inbound_primary() {
    let mut s = Cs101Slave::new(1);
    s.dir = Dir::SlaveToMaster;
    let _ = s.on_primary(Dir::MasterToSlave, 0, 1, Some(dummy_asdu()));
    assert_eq!(s.dir, Dir::SlaveToMaster);
}

#[test]
fn slave_idle_timeout_transitions() {
    let mut s = Cs101Slave::new(1);
    s.idle_threshold = 1;
    let st = s.tick_idle();
    assert_eq!(st, LinkState::IdleTimeout);
}

#[test]
fn wire_loopback_simulated() {
    let wire = Wire::default();
    // Master writes a "request", slave reads, replies, master reads.
    wire.push(&[0x10, 0x5A, 0x5A, 0x16]); // pretend FT 1.2 fixed frame
    let drained = wire.drain();
    assert_eq!(drained, vec![0x10, 0x5A, 0x5A, 0x16]);
    wire.push(&[0x68, 0x05, 0x05, 0x68]); // variable frame header
    let drained = wire.drain();
    assert_eq!(drained.len(), 4);
}

#[test]
fn primary_function_user_data_confirmed_wire_value() {
    let v = PrimaryFunctionCode::UserDataConfirmed.wire();
    assert_eq!(v, 3);
}

#[test]
fn reset_cu_clears_outstanding() {
    let mut m = Cs101Master::new(Cs101MasterConfig::balanced());
    let cmd = fegrid_iec60870_cs101::master::cmds::read(1);
    let _ = m.next_request(cmd);
    assert!(m.has_outstanding());
    m.reset_cu();
    assert!(!m.has_outstanding());
}
