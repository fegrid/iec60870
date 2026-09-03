//! Round-trip tests for the typed InformationValue variants added in
//! steps 1-3 of the feature completion plan. Each scenario:
//! 1. Builds an `Asdu` carrying a typed InformationValue (and timestamp
//!    when applicable).
//! 2. Encodes the ASDU strictly (`Asdu::parse` is strict-by-default).
//! 3. Parses the resulting bytes via the strict path.
//! 4. Asserts the parsed variant equals the original AND that re-encoding
//!    yields a byte-identical buffer.

use std::vec::Vec;

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue, encode_to_vec};
use fegrid_iec60870_core::{
    AppLayerParameters, CauseOfTransmission, CommonAddress, CotField, Cp24Time2a, Cp56Time2a,
    QualityDescriptor, Timestamp, TypeId,
};

fn build_asdu(t: TypeId, ca: u16, items: Vec<(u32, InformationValue, Option<Timestamp>)>) -> Asdu {
    Asdu {
        type_id: t,
        original_type_byte: t as u8,
        cot: CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(ca),
        is_sequence: false,
        is_test: false,
        objects: items
            .into_iter()
            .map(|(ioa, value, ts)| InformationObject::with_timestamp(ioa, value, ts))
            .collect(),
    }
}

fn strict_round_trip(
    t: TypeId,
    ca: u16,
    items: Vec<(u32, InformationValue, Option<Timestamp>)>,
) -> Vec<u8> {
    let params = AppLayerParameters::default();
    let asdu = build_asdu(t, ca, items);
    let bytes = encode_to_vec(&params, &asdu).expect("encode");
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    assert_eq!(
        parsed.objects.len(),
        asdu.objects.len(),
        "object count mismatch"
    );
    assert_eq!(parsed.type_id, asdu.type_id);
    for (a, b) in asdu.objects.iter().zip(parsed.objects.iter()) {
        assert_eq!(a.ioa, b.ioa, "ioa");
        assert_eq!(a.value, b.value, "value");
        assert_eq!(a.timestamp, b.timestamp, "timestamp");
    }
    let re = encode_to_vec(&params, &parsed).expect("re-encode");
    assert_eq!(
        re, bytes,
        "byte mismatch after round-trip for type={}",
        t as u8
    );
    bytes
}

// --- Step 1: types 17/18/19/20/31..=40 ---

#[test]
fn m_ep_ta_1_round_trip() {
    let ts = Timestamp::Cp24(Cp24Time2a {
        ms: 1234,
        minutes: 30,
        invalid: false,
        summer_time: true,
    });
    let val = InformationValue::ProtectionEvent {
        event: 0x12,
        elapsed_ms: 0x3456,
    };
    strict_round_trip(TypeId::M_EP_TA_1, 1, vec![(0x010000, val, Some(ts))]);
}

#[test]
fn m_ep_tb_1_round_trip() {
    let ts = Timestamp::Cp24(Cp24Time2a {
        ms: 500,
        minutes: 12,
        invalid: false,
        summer_time: false,
    });
    strict_round_trip(
        TypeId::M_EP_TB_1,
        1,
        vec![(
            0x020000,
            InformationValue::PackedStartEvent {
                event: 0x34,
                qdp: 0x56,
                elapsed_ms: 0x7890,
            },
            Some(ts),
        )],
    );
}

#[test]
fn m_ep_tc_1_round_trip() {
    let ts = Timestamp::Cp24(Cp24Time2a::default());
    strict_round_trip(
        TypeId::M_EP_TC_1,
        1,
        vec![(
            0x030000,
            InformationValue::PackedOutputEvent {
                oci: 0x34,
                qdp: 0x56,
                elapsed_ms: 0x7890,
            },
            Some(ts),
        )],
    );
}

#[test]
fn m_ep_td_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::ProtectionEvent {
        event: 0xfe,
        elapsed_ms: 0xed42,
    };
    strict_round_trip(TypeId::M_EP_TD_1, 1, vec![(0x040000, val, Some(ts))]);
}

#[test]
fn m_ep_te_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::PackedStartEvent {
        event: 0x11,
        qdp: 0x22,
        elapsed_ms: 0x3344,
    };
    strict_round_trip(TypeId::M_EP_TE_1, 1, vec![(0x050000, val, Some(ts))]);
}

#[test]
fn m_ep_tf_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::PackedOutputEvent {
        oci: 0xaa,
        qdp: 0xbb,
        elapsed_ms: 0xccdd,
    };
    strict_round_trip(TypeId::M_EP_TF_1, 1, vec![(0x060000, val, Some(ts))]);
}

#[test]
fn m_ps_na_1_round_trip() {
    let val = InformationValue::PackedStartEvents {
        scd: 0xdead_beef,
        quality: QualityDescriptor::from_bits_truncate(0x12),
    };
    strict_round_trip(TypeId::M_PS_NA_1, 1, vec![(0x070000, val, None)]);
}

#[test]
fn m_dp_tb_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::DoublePoint {
        state: 2,
        quality: QualityDescriptor::from_bits_truncate(0x1c),
    };
    strict_round_trip(TypeId::M_DP_TB_1, 1, vec![(0x080000, val, Some(ts))]);
}

#[test]
fn m_st_tb_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::StepPosition {
        value: -7,
        transient: true,
        quality: QualityDescriptor::from_bits_truncate(0x05),
    };
    strict_round_trip(TypeId::M_ST_TB_1, 1, vec![(0x090000, val, Some(ts))]);
}

#[test]
fn m_bo_tb_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::BitString32 {
        value: 0xfeed_face,
        quality: QualityDescriptor::from_bits_truncate(0x05),
    };
    let _ = strict_round_trip(TypeId::M_BO_TB_1, 1, vec![(0x0a0000, val, Some(ts))]);
}

#[test]
fn m_me_td_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::MeasuredNormalized {
        value: 12345,
        quality: fegrid_iec60870_core::QualityDescriptorP::from_bits_truncate(0x05),
    };
    strict_round_trip(TypeId::M_ME_TD_1, 1, vec![(0x0b0000, val, Some(ts))]);
}

#[test]
fn m_me_te_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::MeasuredScaled {
        value: -42,
        quality: fegrid_iec60870_core::QualityDescriptorP::from_bits_truncate(0x05),
    };
    strict_round_trip(TypeId::M_ME_TE_1, 1, vec![(0x0c0000, val, Some(ts))]);
}

#[test]
fn m_me_tf_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::MeasuredFloat {
        value: 1.234,
        quality: fegrid_iec60870_core::QualityDescriptorP::from_bits_truncate(0x05),
    };
    strict_round_trip(TypeId::M_ME_TF_1, 1, vec![(0x0d0000, val, Some(ts))]);
}

#[test]
fn m_it_tb_1_round_trip() {
    let ts = Timestamp::Cp56(Cp56Time2a::default());
    let val = InformationValue::IntegratedTotals(fegrid_iec60870_asdu::BinaryCounterReading {
        counter: 0x123456,
        sequence: 3,
        quality: fegrid_iec60870_core::BinaryCounterQuality::from_bits_truncate(0xa0),
    });
    strict_round_trip(TypeId::M_IT_TB_1, 1, vec![(0x0e0000, val, Some(ts))]);
}

#[test]
fn c_ts_ta_1_raw_round_trip() {
    // 107 still round-trips as Raw (its body IS the FBP+CP56, no split).
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::C_TS_TA_1,
        original_type_byte: TypeId::C_TS_TA_1 as u8,
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
            0x010000,
            InformationValue::Raw {
                type_id: 107,
                bytes: vec![0x34, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).expect("encode");
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    let re = encode_to_vec(&params, &parsed).expect("re-encode");
    assert_eq!(re, bytes);
}

// --- Step 2: types 110-113 (no timestamps) ---

#[test]
fn p_me_na_1_round_trip() {
    let val = InformationValue::ParameterNormalized {
        value: 2000,
        qpm: 0x10,
    };
    strict_round_trip(TypeId::P_ME_NA_1, 1, vec![(0x010000, val, None)]);
}

#[test]
fn p_me_nb_1_round_trip() {
    let val = InformationValue::ParameterScaled {
        value: -1234,
        qpm: 0x08,
    };
    strict_round_trip(TypeId::P_ME_NB_1, 1, vec![(0x020000, val, None)]);
}

#[test]
fn p_me_nc_1_round_trip() {
    let val = InformationValue::ParameterFloat {
        value: core::f32::consts::PI,
        qpm: 0x05,
    };
    strict_round_trip(TypeId::P_ME_NC_1, 1, vec![(0x030000, val, None)]);
}

#[test]
fn p_ac_na_1_round_trip() {
    let val = InformationValue::ParameterActivation { qpm: 0x07 };
    strict_round_trip(TypeId::P_AC_NA_1, 1, vec![(0x040000, val, None)]);
}

#[test]
fn f_fr_na_1_round_trip() {
    let val = InformationValue::FileReady {
        name: 0x0007,
        length: 0x012345,
        frq: 0x01,
    };
    strict_round_trip(TypeId::F_FR_NA_1, 1, vec![(0x050000, val, None)]);
}

#[test]
fn f_sr_na_1_round_trip() {
    let val = InformationValue::SectionReady {
        name: 0x0007,
        section: 0x01,
        length: 0x654321,
        srq: 0x01,
    };
    strict_round_trip(TypeId::F_SR_NA_1, 1, vec![(0x060000, val, None)]);
}

#[test]
fn f_sc_na_1_round_trip() {
    let val = InformationValue::FileCall {
        name: 0x0007,
        section: 1,
        scq: 0x02,
    };
    strict_round_trip(TypeId::F_SC_NA_1, 1, vec![(0x070000, val, None)]);
}

#[test]
fn f_ls_na_1_round_trip() {
    let val = InformationValue::FileLastSection {
        name: 0x0007,
        section: 9,
        lsq: 0x01,
        checksum: 0xa5,
    };
    strict_round_trip(TypeId::F_LS_NA_1, 1, vec![(0x080000, val, None)]);
}

#[test]
fn f_af_na_1_round_trip() {
    let val = InformationValue::FileAck {
        name: 0x0007,
        section: 9,
        afq: 0x01,
    };
    strict_round_trip(TypeId::F_AF_NA_1, 1, vec![(0x090000, val, None)]);
}

// --- Step 4: F_SG_NA_1 (125, variable) and F_DR_TA_1 (126, fixed) ---

#[test]
fn f_sg_na_1_round_trip_variable_length() {
    // F_SG_NA_1 body: NOF(2) + NOS(1) + LOS(1) + data[LOS]. LOS = 5.
    let val = InformationValue::FileSegment {
        name: 0x0007,
        section: 3,
        los: 5,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42],
    };
    strict_round_trip(TypeId::F_SG_NA_1, 1, vec![(0x030000, val, None)]);
}

#[test]
fn f_dr_ta_1_round_trip_with_cp56() {
    // F_DR_TA_1 body: NOF(2) + LOF(3) + SOF(1) + CP56Time2a(7). Total 13 bytes.
    let creation = Cp56Time2a {
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
    let val = InformationValue::FileDirectory {
        name: 0x00FF,
        length_of_file: 0x012345,
        sof: 0x10, // LFD bit
        creation_time: creation,
    };
    strict_round_trip(TypeId::F_DR_TA_1, 1, vec![(0x0F0000, val, None)]);
}
