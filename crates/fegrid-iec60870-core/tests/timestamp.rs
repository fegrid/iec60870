//! Integration tests for [`Timestamp`], [`TimestampKind`], and the
//! per-`TypeId` mapping.

use fegrid_iec60870_core::TypeId;
use fegrid_iec60870_core::error::AsduError;
use fegrid_iec60870_core::time::{Cp16Time2a, Cp24Time2a, Cp56Time2a};
use fegrid_iec60870_core::timestamp::{
    Timestamp, TimestampKind, timestamp_kind_for, timestamp_len,
};

#[test]
fn timestamp_len_matches_kind() {
    assert_eq!(timestamp_len(TimestampKind::Cp16), 2);
    assert_eq!(timestamp_len(TimestampKind::Cp24), 3);
    assert_eq!(timestamp_len(TimestampKind::Cp56), 7);
}

#[test]
fn timestamp_kind_len_and_is_empty() {
    assert_eq!(TimestampKind::Cp16.len(), 2);
    assert_eq!(TimestampKind::Cp24.len(), 3);
    assert_eq!(TimestampKind::Cp56.len(), 7);
    assert!(!TimestampKind::Cp16.is_empty());
    assert!(!TimestampKind::Cp24.is_empty());
    assert!(!TimestampKind::Cp56.is_empty());
}

#[test]
fn timestamp_len_and_is_empty() {
    let t16 = Timestamp::Cp16(Cp16Time2a { ms: 1 });
    assert_eq!(t16.len(), 2);
    assert!(!t16.is_empty());
    let t24 = Timestamp::Cp24(Cp24Time2a::default());
    assert_eq!(t24.len(), 3);
    assert!(!t24.is_empty());
    let t56 = Timestamp::Cp56(Cp56Time2a::default());
    assert_eq!(t56.len(), 7);
    assert!(!t56.is_empty());
}

#[test]
fn timestamp_encode_decode_each_variant() {
    let mut buf = [0u8; 7];

    let cp16 = Timestamp::Cp16(Cp16Time2a { ms: 59_999 });
    let n = cp16.encode(&mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], &[0x5F, 0xEA]);
    let back = Timestamp::decode(TimestampKind::Cp16, &buf[..2]).unwrap();
    assert_eq!(back, cp16);

    let cp24 = Timestamp::Cp24(Cp24Time2a {
        ms: 1234,
        minutes: 5,
        invalid: true,
        summer_time: false,
    });
    let n = cp24.encode(&mut buf).unwrap();
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], &[0xD2, 0x04, 0x85]);
    let back = Timestamp::decode(TimestampKind::Cp24, &buf[..3]).unwrap();
    assert_eq!(back, cp24);

    let cp56 = Timestamp::Cp56(Cp56Time2a {
        ms: 1000,
        minutes: 30,
        hours: 12,
        day_of_month: 15,
        day_of_week: 3,
        month: 6,
        year: 26,
        invalid: false,
        summer_time: true,
    });
    let n = cp56.encode(&mut buf).unwrap();
    assert_eq!(n, 7);
    let back = Timestamp::decode(TimestampKind::Cp56, &buf[..7]).unwrap();
    assert_eq!(back, cp56);
}

#[test]
fn timestamp_decode_buffer_too_short() {
    let err = Timestamp::decode(TimestampKind::Cp16, &[0x01]).unwrap_err();
    assert!(matches!(
        err,
        AsduError::BufferTooShort { need: 2, have: 1 }
    ));
    let err = Timestamp::decode(TimestampKind::Cp24, &[0x01, 0x02]).unwrap_err();
    assert!(matches!(
        err,
        AsduError::BufferTooShort { need: 3, have: 2 }
    ));
    let err = Timestamp::decode(TimestampKind::Cp56, &[0; 6]).unwrap_err();
    assert!(matches!(
        err,
        AsduError::BufferTooShort { need: 7, have: 6 }
    ));
}

#[test]
fn timestamp_kind_for_cp24_family() {
    for t in [
        TypeId::M_SP_TA_1,
        TypeId::M_DP_TA_1,
        TypeId::M_ST_TA_1,
        TypeId::M_BO_TA_1,
        TypeId::M_ME_TA_1,
        TypeId::M_ME_TB_1,
        TypeId::M_ME_TC_1,
        TypeId::M_IT_TA_1,
        // Type ids 18/19 (M_EP_TB_1 / M_EP_TC_1) carry a CP24 suffix.
        TypeId::M_EP_TB_1,
        TypeId::M_EP_TC_1,
    ] {
        assert_eq!(timestamp_kind_for(t), Some(TimestampKind::Cp24), "{t:?}");
    }
}

#[test]
fn timestamp_kind_for_cp56_family() {
    for t in [
        TypeId::M_SP_TB_1,
        TypeId::M_DP_TB_1,
        TypeId::M_ST_TB_1,
        TypeId::M_BO_TB_1,
        TypeId::M_ME_TD_1,
        TypeId::M_ME_TE_1,
        TypeId::M_ME_TF_1,
        TypeId::M_IT_TB_1,
        TypeId::M_EP_TD_1,
        TypeId::M_EP_TE_1,
        TypeId::M_EP_TF_1,
        TypeId::C_SC_TA_1,
        TypeId::C_DC_TA_1,
        TypeId::C_RC_TA_1,
        TypeId::C_SE_TA_1,
        TypeId::C_SE_TB_1,
        TypeId::C_SE_TC_1,
        TypeId::C_BO_TA_1,
        TypeId::C_TS_TA_1,
    ] {
        assert_eq!(timestamp_kind_for(t), Some(TimestampKind::Cp56), "{t:?}");
    }
}

#[test]
fn timestamp_kind_for_returns_none_for_non_timestamp_types() {
    // C_CS_NA_1 must NOT be counted: its body IS the CP56.
    assert_eq!(timestamp_kind_for(TypeId::C_CS_NA_1), None);
    assert_eq!(timestamp_kind_for(TypeId::M_SP_NA_1), None);
    assert_eq!(timestamp_kind_for(TypeId::C_IC_NA_1), None);
}

#[test]
fn timestamp_kind_for_undefined_returns_none() {
    assert_eq!(timestamp_kind_for(TypeId::Undefined), None);
}
