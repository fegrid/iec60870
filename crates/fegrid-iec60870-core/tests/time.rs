//! Integration tests for CP32/CP56 encode/decode (CP16/CP24 covered in
//! src/time.rs and tests/timestamp.rs already).

use fegrid_iec60870_core::error::AsduError;
use fegrid_iec60870_core::time::{Cp32Time2a, Cp56Time2a};

#[test]
fn cp32_round_trip() {
    let t = Cp32Time2a {
        ms: 12_345,
        minutes: 30,
        hours: 23,
        invalid: true,
        summer_time: true,
    };
    let mut buf = [0u8; 4];
    t.encode(&mut buf).unwrap();
    // ms=12345 → LE [0x39, 0x30].
    assert_eq!(buf[0], 0x39);
    assert_eq!(buf[1], 0x30);
    // minutes=30 | invalid(0x80) | summer(0x40) = 30 + 0xC0 = 0xDE.
    assert_eq!(buf[2], 0xDE);
    // hours=23 | summer(0x80) = 0x97.
    assert_eq!(buf[3], 0x97);
    let back = Cp32Time2a::decode(&buf).unwrap();
    assert_eq!(back, t);
}

#[test]
fn cp32_decode_short_buffer() {
    assert!(matches!(
        Cp32Time2a::decode(&[0x01, 0x02, 0x03]),
        Err(AsduError::BufferTooShort { need: 4, have: 3 })
    ));
}

#[test]
fn cp32_encode_short_buffer() {
    let mut buf = [0u8; 3];
    assert!(matches!(
        Cp32Time2a::default().encode(&mut buf),
        Err(AsduError::BufferTooShort { need: 4, have: 3 })
    ));
}

#[test]
fn cp56_round_trip_with_all_flags() {
    let t = Cp56Time2a {
        ms: 59_999,
        minutes: 59,
        hours: 23,
        day_of_month: 31,
        day_of_week: 7,
        month: 12,
        year: 99,
        invalid: true,
        summer_time: true,
    };
    let mut buf = [0u8; 7];
    t.encode(&mut buf).unwrap();
    let back = Cp56Time2a::decode(&buf).unwrap();
    assert_eq!(back, t);
}

#[test]
fn cp56_handles_flags_independently() {
    // SU + IV off
    let t = Cp56Time2a {
        ms: 1,
        minutes: 1,
        hours: 1,
        day_of_month: 1,
        day_of_week: 0,
        month: 1,
        year: 0,
        invalid: false,
        summer_time: false,
    };
    let mut buf = [0u8; 7];
    t.encode(&mut buf).unwrap();
    assert_eq!(buf[2], 0x01); // minutes
    assert_eq!(buf[3], 0x01); // hours
    assert_eq!(buf[4], 0x01); // day
    let back = Cp56Time2a::decode(&buf).unwrap();
    assert_eq!(back, t);

    // SU on only (minutes byte sets bit 6)
    let t = Cp56Time2a {
        ms: 0,
        minutes: 5,
        hours: 0,
        day_of_month: 1,
        day_of_week: 0,
        month: 1,
        year: 0,
        invalid: false,
        summer_time: true,
    };
    t.encode(&mut buf).unwrap();
    assert_eq!(buf[2], 0x40 | 0x05);
    let back = Cp56Time2a::decode(&buf).unwrap();
    assert!(back.summer_time);
    assert!(!back.invalid);

    // IV on only (minutes byte sets bit 7)
    let t = Cp56Time2a {
        ms: 0,
        minutes: 5,
        hours: 0,
        day_of_month: 1,
        day_of_week: 0,
        month: 1,
        year: 0,
        invalid: true,
        summer_time: false,
    };
    t.encode(&mut buf).unwrap();
    assert_eq!(buf[2], 0x80 | 0x05);
    let back = Cp56Time2a::decode(&buf).unwrap();
    assert!(back.invalid);
    assert!(!back.summer_time);

    // Day-of-week packing at bits 5..7 of byte 4.
    let t = Cp56Time2a {
        ms: 0,
        minutes: 0,
        hours: 0,
        day_of_month: 1,
        day_of_week: 5,
        month: 1,
        year: 0,
        invalid: false,
        summer_time: false,
    };
    t.encode(&mut buf).unwrap();
    assert_eq!(buf[4] & 0x1F, 1);
    assert_eq!((buf[4] >> 5) & 0x07, 5);
}

#[test]
fn cp56_decode_short_buffer() {
    assert!(matches!(
        Cp56Time2a::decode(&[0; 6]),
        Err(AsduError::BufferTooShort { need: 7, have: 6 })
    ));
}

#[test]
fn cp56_encode_short_buffer() {
    let mut buf = [0u8; 6];
    assert!(matches!(
        Cp56Time2a::default().encode(&mut buf),
        Err(AsduError::BufferTooShort { need: 7, have: 6 })
    ));
}
