//! Tests for FT 1.2 control-field bit accessors, single-character NAK, and
//! fixed-frame length validation.

use fegrid_iec60870_core::AddressLen;
use fegrid_iec60870_cs101::ft12::{
    ControlField, FixedFrame, SINGLE_CHAR_ACK, SINGLE_CHAR_NAK, START_FIXED, START_VARIABLE,
};

#[test]
fn control_field_dir_bit() {
    // PRM=1 → bit 7 set.
    let cf = ControlField(0x80);
    assert!(cf.dir());
    // PRM=0 → bit 7 clear.
    let cf = ControlField(0x7F);
    assert!(!cf.dir());
}

#[test]
fn control_field_fcb_fcv_bits() {
    // FCB = bit 6; FCV = bit 5.
    let cf = ControlField(0x40);
    assert!(cf.fcb());
    assert!(!cf.fcv());
    let cf = ControlField(0x20);
    assert!(!cf.fcb());
    assert!(cf.fcv());
    let cf = ControlField(0x60);
    assert!(cf.fcb());
    assert!(cf.fcv());
}

#[test]
fn control_field_acd_dfc_bits() {
    // ACD = bit 5; DFC = bit 4.
    let cf = ControlField(0x20);
    assert!(cf.acd());
    assert!(!cf.dfc());
    let cf = ControlField(0x10);
    assert!(!cf.acd());
    assert!(cf.dfc());
}

#[test]
fn control_field_function_code() {
    let cf = ControlField(0x0A);
    assert_eq!(cf.fc(), 0x0A);
}

#[test]
fn primary_function_codes_round_trip() {
    use fegrid_iec60870_cs101::function_codes::PrimaryFunctionCode;
    let codes = [
        PrimaryFunctionCode::ResetRemoteLink,
        PrimaryFunctionCode::ResetUserProcess,
        PrimaryFunctionCode::TestFunctionForLink,
        PrimaryFunctionCode::UserDataConfirmed,
        PrimaryFunctionCode::ResetFcb,
        PrimaryFunctionCode::RequestLinkStatus,
    ];
    for code in codes {
        let wire = code.wire();
        let decoded = PrimaryFunctionCode::try_from_wire(wire).unwrap();
        assert_eq!(decoded, code);
    }
}
#[test]
fn single_char_ack_and_nak() {
    assert_eq!(SINGLE_CHAR_ACK, 0xE5);
    assert_eq!(SINGLE_CHAR_NAK, 0xA2);
}

#[test]
fn fixed_frame_length_is_five_or_six() {
    let len_one = FixedFrame::encoded_len(AddressLen::One);
    let len_two = FixedFrame::encoded_len(AddressLen::Two);
    assert_eq!(len_one, 5);
    assert_eq!(len_two, 6);
    assert_ne!(len_one, len_two);
}

#[test]
fn start_bytes_are_known() {
    assert_eq!(START_FIXED, 0x10);
    assert_eq!(START_VARIABLE, 0x68);
}
