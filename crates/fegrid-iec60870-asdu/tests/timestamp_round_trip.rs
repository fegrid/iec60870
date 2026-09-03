//! Round-trip tests for the `Timestamp` enum on `InformationObject`.
//!
//! Covers all three CP variants:
//!
//! - CP56 (`M_SP_TB_1`): the 7-byte full timestamp used by `_TB_1` /
//!   `_TC_1` / `M_EP_T*` / `C_TS_TA_1`.
//! - CP24 (`M_SP_TA_1`): the 3-byte ms + minutes tag used by `_TA_1`.
//! - CP16: reserved by IEC 60870-5-103 (not present in our TypeId set);
//!   we still verify the wire-level `Timestamp::Cp16` round-trip against a
//!   2-byte buffer.

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue, encode_to_vec};
use fegrid_iec60870_core::{
    AppLayerParameters, CauseOfTransmission, CommonAddress, CotField, Cp16Time2a, Cp24Time2a,
    Cp56Time2a, Timestamp, TimestampKind, TypeId,
};

fn default_params() -> AppLayerParameters {
    AppLayerParameters::default()
}

fn single_obj(type_id: TypeId, ts: Option<Timestamp>) -> Asdu {
    Asdu {
        type_id,
        original_type_byte: type_id.to_wire(),
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
        objects: vec![InformationObject::with_timestamp(
            0x000100,
            single_point_for(type_id),
            ts,
        )],
    }
}

fn single_point_for(t: TypeId) -> InformationValue {
    // For TA / TB family types we use SinglePoint; the body is 1 byte and
    // the trailing timestamp is what we're testing.
    let _ = t;
    InformationValue::SinglePoint {
        value: true,
        quality: Default::default(),
    }
}

#[test]
fn cp56_round_trip_m_sp_tb_1() {
    // ms=821, minute=12, hour=4, day=29, dow=6, month=1, year=24 (the year
    // corresponding to 2024-01-29 04:12:00.821).
    let cp = Cp56Time2a {
        invalid: false,
        summer_time: true,
        year: 24,
        month: 1,
        day_of_month: 29,
        day_of_week: 6,
        hours: 4,
        minutes: 12,
        ms: 821,
    };
    let asdu = single_obj(TypeId::M_SP_TB_1, Some(Timestamp::Cp56(cp)));
    let params = default_params();
    let bytes = encode_to_vec(&params, &asdu).expect("encode");
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, TypeId::M_SP_TB_1);
    assert_eq!(parsed.objects.len(), 1);
    let obj = &parsed.objects[0];
    assert_eq!(obj.ioa, 0x000100);
    match obj.timestamp {
        Some(Timestamp::Cp56(t)) => assert_eq!(t, cp),
        other => panic!("expected Cp56 timestamp, got {other:?}"),
    }
}

#[test]
fn cp24_round_trip_m_sp_ta_1() {
    let cp = Cp24Time2a {
        ms: 1234,
        minutes: 42,
        invalid: false,
        summer_time: false,
    };
    let asdu = single_obj(TypeId::M_SP_TA_1, Some(Timestamp::Cp24(cp)));
    let params = default_params();
    let bytes = encode_to_vec(&params, &asdu).expect("encode");
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, TypeId::M_SP_TA_1);
    assert_eq!(parsed.objects.len(), 1);
    let obj = &parsed.objects[0];
    match obj.timestamp {
        Some(Timestamp::Cp24(t)) => assert_eq!(t, cp),
        other => panic!("expected Cp24 timestamp, got {other:?}"),
    }
}

#[test]
fn cp16_decode_encode_loop() {
    // CP16 has no live TypeId carrier in our set; exercise the codec
    // directly.
    let mut buf = [0u8; 2];
    let cp = Cp16Time2a { ms: 59999 };
    cp.encode(&mut buf).expect("encode cp16");
    let parsed = Cp16Time2a::decode(&buf).expect("decode cp16");
    assert_eq!(parsed, cp);
    assert_eq!(TimestampKind::Cp16.len(), 2);
}

#[test]
fn timestamp_kind_for_lookup() {
    use fegrid_iec60870_core::timestamp_kind_for;
    assert_eq!(timestamp_kind_for(TypeId::M_SP_NA_1), None);
    assert_eq!(
        timestamp_kind_for(TypeId::M_SP_TA_1),
        Some(TimestampKind::Cp24)
    );
    assert_eq!(
        timestamp_kind_for(TypeId::M_SP_TB_1),
        Some(TimestampKind::Cp56)
    );
    // C_TS_TA_1 (107) carries a CP56 inside its body alongside FBP.
    assert_eq!(
        timestamp_kind_for(TypeId::C_TS_TA_1),
        Some(TimestampKind::Cp56)
    );
    // Type ids 18/19 (M_EP_TB_1 / M_EP_TC_1) carry a CP24 suffix.
    assert_eq!(
        timestamp_kind_for(TypeId::M_EP_TB_1),
        Some(TimestampKind::Cp24)
    );
    assert_eq!(
        timestamp_kind_for(TypeId::M_EP_TC_1),
        Some(TimestampKind::Cp24)
    );
    assert_eq!(timestamp_kind_for(TypeId::C_SC_NA_1), None);
}
