//! Integration tests for [`Ioa`] and [`CommonAddress`] covering every
//! encode/decode branch + validation error.

use fegrid_iec60870_core::error::AsduError;
use fegrid_iec60870_core::params::{CaSize, IoaSize};
use fegrid_iec60870_core::{CommonAddress, Ioa};

#[test]
fn ioa_encoded_size_matches_size_enum() {
    assert_eq!(Ioa::encoded_size(IoaSize::One), 1);
    assert_eq!(Ioa::encoded_size(IoaSize::Two), 2);
    assert_eq!(Ioa::encoded_size(IoaSize::Three), 3);
}

#[test]
fn ioa_round_trip_one_byte() {
    let ioa = Ioa::new(0x42);
    let mut buf = [0u8; 1];
    ioa.encode(IoaSize::One, &mut buf).unwrap();
    assert_eq!(buf, [0x42]);
    let back = Ioa::decode(IoaSize::One, &buf).unwrap();
    assert_eq!(back, ioa);
}

#[test]
fn ioa_round_trip_two_bytes() {
    let ioa = Ioa::new(0xCAFE);
    let mut buf = [0u8; 2];
    ioa.encode(IoaSize::Two, &mut buf).unwrap();
    assert_eq!(buf, [0xFE, 0xCA]);
    let back = Ioa::decode(IoaSize::Two, &buf).unwrap();
    assert_eq!(back, ioa);
}

#[test]
fn ioa_round_trip_three_bytes() {
    let ioa = Ioa::new(0x12_3456);
    let mut buf = [0u8; 3];
    ioa.encode(IoaSize::Three, &mut buf).unwrap();
    assert_eq!(buf, [0x56, 0x34, 0x12]);
    let back = Ioa::decode(IoaSize::Three, &buf).unwrap();
    assert_eq!(back, ioa);
}

#[test]
fn ioa_encode_buffer_too_short() {
    let ioa = Ioa::new(1);
    let mut buf = [];
    let err = ioa.encode(IoaSize::One, &mut buf).unwrap_err();
    assert!(matches!(
        err,
        AsduError::BufferTooShort { need: 1, have: 0 }
    ));

    let mut two = [0u8; 1];
    let err = Ioa::new(1).encode(IoaSize::Two, &mut two).unwrap_err();
    assert!(matches!(
        err,
        AsduError::BufferTooShort { need: 2, have: 1 }
    ));

    let mut three = [0u8; 2];
    let err = Ioa::new(1).encode(IoaSize::Three, &mut three).unwrap_err();
    assert!(matches!(
        err,
        AsduError::BufferTooShort { need: 3, have: 2 }
    ));
}

#[test]
fn ioa_overflow_errors() {
    let mut buf = [0u8; 1];
    assert!(matches!(
        Ioa::new(0x100).encode(IoaSize::One, &mut buf),
        Err(AsduError::InvalidNumericField(_))
    ));

    let mut buf2 = [0u8; 2];
    assert!(matches!(
        Ioa::new(0x10000).encode(IoaSize::Two, &mut buf2),
        Err(AsduError::InvalidNumericField(_))
    ));

    let mut buf3 = [0u8; 3];
    assert!(matches!(
        Ioa::new(0x100_0000).encode(IoaSize::Three, &mut buf3),
        Err(AsduError::InvalidNumericField(_))
    ));
}

#[test]
fn ioa_decode_buffer_too_short() {
    let err = Ioa::decode(IoaSize::Two, &[0x01]).unwrap_err();
    assert!(matches!(
        err,
        AsduError::BufferTooShort { need: 2, have: 1 }
    ));
}

#[test]
fn common_address_new_accepts_valid_values() {
    assert_eq!(CommonAddress::new(CaSize::One, 0xFF).unwrap().0, 0xFF);
    assert_eq!(CommonAddress::new(CaSize::Two, 0xFFFF).unwrap().0, 0xFFFF);
    // CaSize::Two has no upper-bound check beyond what fits in u16.
    assert_eq!(CommonAddress::new(CaSize::Two, 0xCAFE).unwrap().0, 0xCAFE);
}

#[test]
fn common_address_new_rejects_one_byte_overflow() {
    let err = CommonAddress::new(CaSize::One, 0x100).unwrap_err();
    assert!(matches!(err, AsduError::InvalidNumericField(_)));
}

#[test]
fn common_address_encode_decode_round_trip() {
    let ca = CommonAddress(0xABCD);
    let mut buf = [0u8; 2];
    ca.encode(CaSize::Two, &mut buf).unwrap();
    assert_eq!(buf, [0xCD, 0xAB]);
    assert_eq!(CommonAddress::decode(CaSize::Two, &buf).unwrap(), ca);

    let small = CommonAddress(0x7F);
    let mut buf = [0u8; 1];
    small.encode(CaSize::One, &mut buf).unwrap();
    assert_eq!(buf, [0x7F]);
    assert_eq!(CommonAddress::decode(CaSize::One, &buf).unwrap(), small);
}

#[test]
fn common_address_encode_buffer_too_short() {
    let ca = CommonAddress(1);
    let mut buf: [u8; 0] = [];
    assert!(matches!(
        ca.encode(CaSize::One, &mut buf),
        Err(AsduError::BufferTooShort { need: 1, have: 0 })
    ));
    let mut one = [0u8; 1];
    assert!(matches!(
        ca.encode(CaSize::Two, &mut one),
        Err(AsduError::BufferTooShort { need: 2, have: 1 })
    ));
}

#[test]
fn common_address_decode_buffer_too_short() {
    assert!(matches!(
        CommonAddress::decode(CaSize::Two, &[0x01]),
        Err(AsduError::BufferTooShort { need: 2, have: 1 })
    ));
}
