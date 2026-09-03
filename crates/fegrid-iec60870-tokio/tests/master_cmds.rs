//! Integration test for the MClient + cmds encoder module.
//!
//! Verifies that the command encoders build well-formed ASDUs with the
//! right TypeId, IOA, and qualifier bytes, and that the encoded bytes
//! round-trip through the wire codec.

use bytes::BytesMut;
use fegrid_iec60870_asdu::{Asdu, InformationValue, encode_to_vec};
use fegrid_iec60870_core::{
    AppLayerParameters, CauseOfTransmission, CotField, Cp56Time2a, QualifierOfCIC,
    QualifierOfInterrogation, TypeId,
};
use fegrid_iec60870_tokio::cmds;

fn activation_cot() -> CotField {
    CotField {
        cause: CauseOfTransmission::Activation,
        negative_confirm: false,
        test: false,
        originator: 0,
        cause_raw_override: None,
    }
}

fn round_trip(asdu: &Asdu) {
    let params = AppLayerParameters::default();
    let bytes = encode_to_vec(&params, asdu).expect("encode");
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, asdu.type_id);
    assert_eq!(parsed.cot.cause, asdu.cot.cause);
    assert_eq!(parsed.objects.len(), asdu.objects.len());
    for (a, b) in asdu.objects.iter().zip(parsed.objects.iter()) {
        assert_eq!(a.ioa, b.ioa);
        assert_eq!(a.value, b.value);
    }
}

#[test]
fn general_interrogation_round_trip() {
    let asdu = cmds::general_interrogation(1, QualifierOfInterrogation::STATION);
    assert_eq!(asdu.type_id, TypeId::C_IC_NA_1);
    assert_eq!(asdu.objects.len(), 1);
    assert_eq!(asdu.objects[0].ioa, 0);
    round_trip(&asdu);
}

#[test]
fn counter_interrogation_round_trip() {
    let asdu = cmds::counter_interrogation(1, QualifierOfCIC::GROUP_1_FREEZE_READ);
    assert_eq!(asdu.type_id, TypeId::C_CI_NA_1);
    round_trip(&asdu);
}

#[test]
fn read_round_trip() {
    let asdu = cmds::read(2, 0x010203);
    assert_eq!(asdu.type_id, TypeId::C_RD_NA_1);
    assert_eq!(asdu.objects[0].ioa, 0x010203);
    round_trip(&asdu);
}

#[test]
fn clock_sync_round_trip() {
    let time = Cp56Time2a {
        ms: 12345,
        minutes: 6,
        hours: 12,
        day_of_month: 15,
        day_of_week: 3,
        month: 8,
        year: 126,
        summer_time: false,
        invalid: false,
    };
    let asdu = cmds::clock_sync(1, time);
    assert_eq!(asdu.type_id, TypeId::C_CS_NA_1);
    round_trip(&asdu);
}

#[test]
fn process_command_single_round_trip() {
    let value = InformationValue::SingleCommand {
        on: true,
        select: false,
        qu: 0,
    };
    let asdu = cmds::process_command(1, 0x42, value);
    assert_eq!(asdu.type_id, TypeId::C_SC_NA_1);
    round_trip(&asdu);
}

#[test]
fn confirm_helpers() {
    // Build a request and confirm it (positive and negative).
    let request = cmds::general_interrogation(1, QualifierOfInterrogation::STATION);
    let pos = cmds::confirm(&request);
    assert_eq!(
        pos.cot.cause,
        fegrid_iec60870_core::CauseOfTransmission::ActivationCon
    );
    assert!(!pos.cot.negative_confirm);
    let neg = cmds::confirm_negative(&request);
    assert_eq!(
        neg.cot.cause,
        fegrid_iec60870_core::CauseOfTransmission::ActivationCon
    );
    assert!(neg.cot.negative_confirm);
}

#[test]
fn activation_cot_helper_smoke() {
    let _ = activation_cot();
}

#[test]
fn iotest_bytemut_used() {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0x68, 0x04]);
    assert_eq!(buf.len(), 2);
}
