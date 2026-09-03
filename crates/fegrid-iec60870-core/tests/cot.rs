//! Integration tests for [`CotField`], [`CauseOfTransmission`].

use fegrid_iec60870_core::error::AsduError;
use fegrid_iec60870_core::params::CotSize;
use fegrid_iec60870_core::{CauseOfTransmission, CotField};

#[test]
fn default_cot_field_is_unknown_zero_originator() {
    let f = CotField::default();
    assert_eq!(f.cause, CauseOfTransmission::UnknownCot);
    assert!(!f.negative_confirm);
    assert!(!f.test);
    assert_eq!(f.originator, 0);
    assert!(f.cause_raw_override.is_none());
}

#[test]
fn from_wire_rejects_out_of_set() {
    let err = CauseOfTransmission::from_wire(0).unwrap_err();
    assert!(matches!(err, AsduError::InvalidCause(0)));
    let err = CauseOfTransmission::from_wire(0xFF).unwrap_err();
    assert!(matches!(err, AsduError::InvalidCause(0xFF)));
    // Gaps inside the IEC-defined set.
    let err = CauseOfTransmission::from_wire(17).unwrap_err();
    assert!(matches!(err, AsduError::InvalidCause(17)));
}

#[test]
fn from_wire_accepts_every_defined_value() {
    use CauseOfTransmission::*;
    let cases = [
        (1, Periodic),
        (2, Background),
        (3, Spontaneous),
        (4, Initialized),
        (5, Request),
        (6, Activation),
        (7, ActivationCon),
        (8, Deactivation),
        (9, DeactivationCon),
        (10, ActivationTermination),
        (11, ReturnInfoRemote),
        (12, ReturnInfoLocal),
        (13, FileTransfer),
        (14, Authentication),
        (15, MaintenanceOfAuthSessionKey),
        (16, MaintenanceOfUserRoleAndUpdateKey),
        (20, StationInterrogation),
        (21, Group1Interrogation),
        (36, Group16Interrogation),
        (37, RequestedByGeneralCounter),
        (38, RequestedByGroup1Counter),
        (41, RequestedByGroup4Counter),
        (44, UnknownTypeId),
        (45, UnknownCot),
        (46, UnknownCa),
        (47, UnknownIoa),
    ];
    for (byte, expected) in cases {
        let got = CauseOfTransmission::from_wire(byte).expect("legal cause");
        assert_eq!(got, expected, "byte={byte}");
        assert_eq!(got.to_wire(), byte);
    }
}

#[test]
fn encode_decode_round_trip_one_byte_cot() {
    let f = CotField {
        cause: CauseOfTransmission::Spontaneous,
        negative_confirm: false,
        test: false,
        originator: 0,
        cause_raw_override: None,
    };
    let mut buf = [0u8; 1];
    let n = f.encode(CotSize::One, &mut buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(buf[0], 0x03);
    let back = CotField::decode(CotSize::One, &buf).unwrap();
    assert_eq!(back, f);
}

#[test]
fn encode_decode_round_trip_two_byte_cot() {
    let f = CotField {
        cause: CauseOfTransmission::StationInterrogation,
        negative_confirm: true,
        test: false,
        originator: 7,
        cause_raw_override: None,
    };
    let mut buf = [0u8; 2];
    let n = f.encode(CotSize::Two, &mut buf).unwrap();
    assert_eq!(n, 2);
    // 0x14 (StationInterrogation = 20) | 0x40 (P/N) = 0x54.
    assert_eq!(buf[0], 0x54);
    assert_eq!(buf[1], 7);
    let back = CotField::decode(CotSize::Two, &buf).unwrap();
    assert_eq!(back, f);
}

#[test]
fn decode_undefined_cause_sets_raw_override() {
    // Use byte 42 which is in the defined gaps (not a real cause).
    let buf = [42u8, 9];
    let f = CotField::decode(CotSize::Two, &buf).unwrap();
    assert_eq!(f.cause, CauseOfTransmission::UnknownCot);
    assert_eq!(f.cause_raw_override, Some(42));
    assert_eq!(f.originator, 9);
}

#[test]
fn encode_uses_raw_override_when_set() {
    let f = CotField {
        cause: CauseOfTransmission::UnknownCot,
        negative_confirm: false,
        test: false,
        originator: 0,
        cause_raw_override: Some(42),
    };
    let mut buf = [0u8; 1];
    f.encode(CotSize::One, &mut buf).unwrap();
    assert_eq!(buf[0], 42);
}

#[test]
fn encode_decode_buffer_too_short() {
    let f = CotField::default();
    let mut buf: [u8; 0] = [];
    assert!(matches!(
        f.encode(CotSize::One, &mut buf),
        Err(AsduError::BufferTooShort { need: 1, have: 0 })
    ));
    assert!(matches!(
        CotField::decode(CotSize::One, &[]),
        Err(AsduError::BufferTooShort { need: 1, have: 0 })
    ));
    let mut one = [0u8; 1];
    assert!(matches!(
        f.encode(CotSize::Two, &mut one),
        Err(AsduError::BufferTooShort { need: 2, have: 1 })
    ));
    assert!(matches!(
        CotField::decode(CotSize::Two, &[1]),
        Err(AsduError::BufferTooShort { need: 2, have: 1 })
    ));
}

#[test]
fn test_flag_is_top_bit() {
    let f = CotField {
        cause: CauseOfTransmission::Spontaneous,
        negative_confirm: false,
        test: true,
        originator: 0,
        cause_raw_override: None,
    };
    let mut buf = [0u8; 1];
    f.encode(CotSize::One, &mut buf).unwrap();
    assert_eq!(buf[0], 0x03 | 0x80);
    let back = CotField::decode(CotSize::One, &buf).unwrap();
    assert!(back.test);
    assert_eq!(back.cause, CauseOfTransmission::Spontaneous);
}

#[test]
fn conversion_traits_round_trip() {
    use core::convert::TryFrom;
    let c = CauseOfTransmission::Spontaneous;
    let byte: u8 = c.into();
    assert_eq!(byte, 3);
    assert_eq!(CauseOfTransmission::try_from(3).unwrap(), c);
    assert!(CauseOfTransmission::try_from(99).is_err());
}
