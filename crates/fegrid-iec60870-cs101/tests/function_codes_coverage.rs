//! Coverage tests for function_codes.rs (cs101).

use fegrid_iec60870_cs101::{PrimaryFunctionCode, SecondaryFunctionCode};

#[test]
fn primary_function_code_wire_values() {
    assert_eq!(PrimaryFunctionCode::ResetRemoteLink.wire(), 0);
    assert_eq!(PrimaryFunctionCode::ResetUserProcess.wire(), 1);
    assert_eq!(PrimaryFunctionCode::TestFunctionForLink.wire(), 2);
    assert_eq!(PrimaryFunctionCode::UserDataConfirmed.wire(), 3);
    assert_eq!(PrimaryFunctionCode::UserDataNoReply.wire(), 4);
    assert_eq!(PrimaryFunctionCode::Reserved56.wire(), 5);
    assert_eq!(PrimaryFunctionCode::Reserved57.wire(), 6);
    assert_eq!(PrimaryFunctionCode::ResetFcb.wire(), 7);
    assert_eq!(PrimaryFunctionCode::RequestForAccessDemand.wire(), 8);
    assert_eq!(PrimaryFunctionCode::RequestLinkStatus.wire(), 9);
    assert_eq!(PrimaryFunctionCode::RequestUserDataClass1.wire(), 10);
    assert_eq!(PrimaryFunctionCode::RequestUserDataClass2.wire(), 11);
}

#[test]
fn primary_function_code_round_trip() {
    for variant in [
        PrimaryFunctionCode::ResetRemoteLink,
        PrimaryFunctionCode::ResetUserProcess,
        PrimaryFunctionCode::TestFunctionForLink,
        PrimaryFunctionCode::UserDataConfirmed,
        PrimaryFunctionCode::UserDataNoReply,
        PrimaryFunctionCode::ResetFcb,
        PrimaryFunctionCode::RequestForAccessDemand,
        PrimaryFunctionCode::RequestLinkStatus,
        PrimaryFunctionCode::RequestUserDataClass1,
        PrimaryFunctionCode::RequestUserDataClass2,
    ] {
        assert_eq!(
            PrimaryFunctionCode::try_from_wire(variant.wire()).unwrap(),
            variant
        );
    }
}

#[test]
fn primary_function_code_reserved_rejected() {
    // Reserved values 5 and 6 should fail.
    assert!(PrimaryFunctionCode::try_from_wire(5).is_err());
    assert!(PrimaryFunctionCode::try_from_wire(6).is_err());
    assert!(PrimaryFunctionCode::try_from_wire(12).is_err());
    assert!(PrimaryFunctionCode::try_from_wire(15).is_err());
}

#[test]
fn primary_function_code_no_high_nibble_mask() {
    // The current implementation does NOT mask the high nibble;
    // callers are expected to mask before passing the low 4 bits.
    assert_eq!(
        PrimaryFunctionCode::try_from_wire(3).unwrap(),
        PrimaryFunctionCode::UserDataConfirmed
    );
}
#[test]
fn secondary_function_code_wire_values() {
    assert_eq!(SecondaryFunctionCode::Ack.wire(), 0);
    assert_eq!(SecondaryFunctionCode::Nack.wire(), 1);
    assert_eq!(SecondaryFunctionCode::RespUserData.wire(), 8);
    assert_eq!(SecondaryFunctionCode::RespNackNoData.wire(), 9);
    assert_eq!(SecondaryFunctionCode::StatusOfLinkOrAccessDemand.wire(), 11);
    assert_eq!(SecondaryFunctionCode::ServiceNotFunctioning.wire(), 14);
    assert_eq!(SecondaryFunctionCode::ServiceNotImplemented.wire(), 15);
}

#[test]
fn secondary_function_code_round_trip() {
    for variant in [
        SecondaryFunctionCode::Ack,
        SecondaryFunctionCode::Nack,
        SecondaryFunctionCode::RespUserData,
        SecondaryFunctionCode::RespNackNoData,
        SecondaryFunctionCode::StatusOfLinkOrAccessDemand,
        SecondaryFunctionCode::ServiceNotFunctioning,
        SecondaryFunctionCode::ServiceNotImplemented,
    ] {
        assert_eq!(
            SecondaryFunctionCode::try_from_wire(variant.wire()).unwrap(),
            variant
        );
    }
}

#[test]
fn secondary_function_code_reserved_rejected() {
    // 2..=7 and 10, 12, 13 are reserved.
    for bits in [2u8, 3, 4, 5, 6, 7, 10, 12, 13] {
        assert!(
            SecondaryFunctionCode::try_from_wire(bits).is_err(),
            "bits {bits} should be rejected"
        );
    }
}
