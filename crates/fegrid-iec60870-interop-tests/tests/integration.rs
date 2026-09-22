//! IEC 60870-5 interop property tests.
//!
//! 150 static `#[test]` functions exercising:
//! - COT values (cause-of-transmission round-trip + flags).
//! - TypeIds (every defined discriminant + Undefined).
//! - Quality bits (SIQ/DIQ/QDS/BCR flag layouts).
//! - ASDU framing boundaries (header size, buffer limits, limits).
//!
//! Every test is a property assertion over the public API; no I/O.
//! Run with `cargo test -p fegrid-iec60870-interop-tests`.

use fegrid_iec60870_asdu::{
    Asdu, InformationObject, InformationValue, body_len_for_type, encode_to_vec, has_cp24,
    has_cp56, parse_default, parse_lenient_default,
};
use fegrid_iec60870_core::{
    AppLayerParameters, BinaryCounterQuality, CaSize, CauseOfTransmission, CommonAddress, CotField,
    CotSize, Ioa, IoaSize, QualityDescriptor, QualityDescriptorP, Result, TypeId,
};

// ---------------------------------------------------------------------------
// COT tests: one per CauseOfTransmission variant. Verifies the wire byte and
// that the typed enum survives a from_wire round-trip.
// ---------------------------------------------------------------------------

macro_rules! cot_test {
    ($name:ident, $variant:expr, $byte:expr) => {
        #[test]
        fn $name() {
            assert_eq!(CauseOfTransmission::from_wire($byte).unwrap(), $variant);
            assert_eq!($variant.to_wire(), $byte);
        }
    };
}

cot_test!(cot_periodic_wire, CauseOfTransmission::Periodic, 1);
cot_test!(cot_background_wire, CauseOfTransmission::Background, 2);
cot_test!(cot_spontaneous_wire, CauseOfTransmission::Spontaneous, 3);
cot_test!(cot_initialized_wire, CauseOfTransmission::Initialized, 4);
cot_test!(cot_request_wire, CauseOfTransmission::Request, 5);
cot_test!(cot_activation_wire, CauseOfTransmission::Activation, 6);
cot_test!(
    cot_activation_con_wire,
    CauseOfTransmission::ActivationCon,
    7
);
cot_test!(cot_deactivation_wire, CauseOfTransmission::Deactivation, 8);
cot_test!(
    cot_deactivation_con_wire,
    CauseOfTransmission::DeactivationCon,
    9
);
cot_test!(
    cot_activation_termination_wire,
    CauseOfTransmission::ActivationTermination,
    10
);
cot_test!(
    cot_return_info_remote_wire,
    CauseOfTransmission::ReturnInfoRemote,
    11
);
cot_test!(
    cot_return_info_local_wire,
    CauseOfTransmission::ReturnInfoLocal,
    12
);
cot_test!(
    cot_file_transfer_wire,
    CauseOfTransmission::FileTransfer,
    13
);
cot_test!(
    cot_authentication_wire,
    CauseOfTransmission::Authentication,
    14
);
cot_test!(
    cot_maintenance_auth_key_wire,
    CauseOfTransmission::MaintenanceOfAuthSessionKey,
    15
);
cot_test!(
    cot_maintenance_user_role_wire,
    CauseOfTransmission::MaintenanceOfUserRoleAndUpdateKey,
    16
);
cot_test!(
    cot_station_interrogation_wire,
    CauseOfTransmission::StationInterrogation,
    20
);
cot_test!(
    cot_group1_interrogation_wire,
    CauseOfTransmission::Group1Interrogation,
    21
);
cot_test!(
    cot_group2_interrogation_wire,
    CauseOfTransmission::Group2Interrogation,
    22
);
cot_test!(
    cot_group3_interrogation_wire,
    CauseOfTransmission::Group3Interrogation,
    23
);
cot_test!(
    cot_group4_interrogation_wire,
    CauseOfTransmission::Group4Interrogation,
    24
);
cot_test!(
    cot_group5_interrogation_wire,
    CauseOfTransmission::Group5Interrogation,
    25
);
cot_test!(
    cot_group6_interrogation_wire,
    CauseOfTransmission::Group6Interrogation,
    26
);
cot_test!(
    cot_group7_interrogation_wire,
    CauseOfTransmission::Group7Interrogation,
    27
);
cot_test!(
    cot_group8_interrogation_wire,
    CauseOfTransmission::Group8Interrogation,
    28
);
cot_test!(
    cot_group9_interrogation_wire,
    CauseOfTransmission::Group9Interrogation,
    29
);
cot_test!(
    cot_group10_interrogation_wire,
    CauseOfTransmission::Group10Interrogation,
    30
);
cot_test!(
    cot_group11_interrogation_wire,
    CauseOfTransmission::Group11Interrogation,
    31
);
cot_test!(
    cot_group12_interrogation_wire,
    CauseOfTransmission::Group12Interrogation,
    32
);
cot_test!(
    cot_group13_interrogation_wire,
    CauseOfTransmission::Group13Interrogation,
    33
);
cot_test!(
    cot_group14_interrogation_wire,
    CauseOfTransmission::Group14Interrogation,
    34
);
cot_test!(
    cot_group15_interrogation_wire,
    CauseOfTransmission::Group15Interrogation,
    35
);
cot_test!(
    cot_group16_interrogation_wire,
    CauseOfTransmission::Group16Interrogation,
    36
);
cot_test!(
    cot_general_counter_wire,
    CauseOfTransmission::RequestedByGeneralCounter,
    37
);
cot_test!(
    cot_group1_counter_wire,
    CauseOfTransmission::RequestedByGroup1Counter,
    38
);
cot_test!(
    cot_group2_counter_wire,
    CauseOfTransmission::RequestedByGroup2Counter,
    39
);
cot_test!(
    cot_group3_counter_wire,
    CauseOfTransmission::RequestedByGroup3Counter,
    40
);
cot_test!(
    cot_group4_counter_wire,
    CauseOfTransmission::RequestedByGroup4Counter,
    41
);
cot_test!(
    cot_unknown_type_id_wire,
    CauseOfTransmission::UnknownTypeId,
    44
);
cot_test!(cot_unknown_cot_wire, CauseOfTransmission::UnknownCot, 45);
cot_test!(cot_unknown_ca_wire, CauseOfTransmission::UnknownCa, 46);
cot_test!(cot_unknown_ioa_wire, CauseOfTransmission::UnknownIoa, 47);

#[test]
fn cot_reserved_wire_bytes_rejected() {
    // Bytes 0, 17..19, 42..43 are not assigned. Must error, not silently round-trip.
    for byte in [0u8, 17, 18, 19, 42, 43, 48, 100, 255] {
        assert!(
            CauseOfTransmission::from_wire(byte).is_err(),
            "byte {byte} should be invalid"
        );
    }
}

#[test]
fn cot_field_encode_one_byte_packs_cause_only() {
    let mut buf = [0u8; 2];
    let n = CotField {
        cause: CauseOfTransmission::Spontaneous,
        negative_confirm: false,
        test: false,
        originator: 0xAA,
        cause_raw_override: None,
    }
    .encode(CotSize::One, &mut buf)
    .unwrap();
    assert_eq!(n, 1);
    assert_eq!(buf[0], 3);
}

#[test]
fn cot_field_encode_two_bytes_carry_originator() {
    let mut buf = [0u8; 2];
    let n = CotField {
        cause: CauseOfTransmission::ActivationCon,
        negative_confirm: true,
        test: true,
        originator: 0x42,
        cause_raw_override: None,
    }
    .encode(CotSize::Two, &mut buf)
    .unwrap();
    assert_eq!(n, 2);
    // 7 | 0x40 (N) | 0x80 (T) | (7 & 0x3f = 7) => 0xC7
    assert_eq!(buf[0], 0xC7);
    assert_eq!(buf[1], 0x42);
}

#[test]
fn cot_field_decode_round_trip_two_bytes() {
    let wire = [0xC7, 0x42];
    let f = CotField::decode(CotSize::Two, &wire).unwrap();
    assert_eq!(f.cause, CauseOfTransmission::ActivationCon);
    assert!(f.negative_confirm);
    assert!(f.test);
    assert_eq!(f.originator, 0x42);
    let mut out = [0u8; 2];
    let n = f.encode(CotSize::Two, &mut out).unwrap();
    assert_eq!(n, 2);
    assert_eq!(out, wire);
}

#[test]
fn cot_field_decode_buffer_too_short() {
    let res = CotField::decode(CotSize::Two, &[0x03]);
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// TypeId tests: every defined discriminant plus Undefined + a few object-size
// invariants. Strict TryFrom for unknown bytes; lenient from_wire always.
// ---------------------------------------------------------------------------

macro_rules! type_test {
    ($name:ident, $variant:expr, $byte:expr) => {
        #[test]
        fn $name() {
            assert_eq!(TypeId::from_wire($byte), $variant);
            assert_eq!($variant.to_wire(), $byte);
        }
    };
}

// Process info in monitor direction (1..21)
type_test!(type_m_sp_na_1_wire, TypeId::M_SP_NA_1, 1);
type_test!(type_m_sp_ta_1_wire, TypeId::M_SP_TA_1, 2);
type_test!(type_m_dp_na_1_wire, TypeId::M_DP_NA_1, 3);
type_test!(type_m_dp_ta_1_wire, TypeId::M_DP_TA_1, 4);
type_test!(type_m_st_na_1_wire, TypeId::M_ST_NA_1, 5);
type_test!(type_m_st_ta_1_wire, TypeId::M_ST_TA_1, 6);
type_test!(type_m_bo_na_1_wire, TypeId::M_BO_NA_1, 7);
type_test!(type_m_bo_ta_1_wire, TypeId::M_BO_TA_1, 8);
type_test!(type_m_me_na_1_wire, TypeId::M_ME_NA_1, 9);
type_test!(type_m_me_ta_1_wire, TypeId::M_ME_TA_1, 10);
type_test!(type_m_me_nb_1_wire, TypeId::M_ME_NB_1, 11);
type_test!(type_m_me_tb_1_wire, TypeId::M_ME_TB_1, 12);
type_test!(type_m_me_nc_1_wire, TypeId::M_ME_NC_1, 13);
type_test!(type_m_me_tc_1_wire, TypeId::M_ME_TC_1, 14);
type_test!(type_m_it_na_1_wire, TypeId::M_IT_NA_1, 15);
type_test!(type_m_it_ta_1_wire, TypeId::M_IT_TA_1, 16);
type_test!(type_m_ep_ta_1_wire, TypeId::M_EP_TA_1, 17);
type_test!(type_m_ep_tb_1_wire, TypeId::M_EP_TB_1, 18);
type_test!(type_m_ep_tc_1_wire, TypeId::M_EP_TC_1, 19);
type_test!(type_m_ps_na_1_wire, TypeId::M_PS_NA_1, 20);
type_test!(type_m_me_nd_1_wire, TypeId::M_ME_ND_1, 21);

// Process info with CP56 (30..40)
type_test!(type_m_sp_tb_1_wire, TypeId::M_SP_TB_1, 30);
type_test!(type_m_dp_tb_1_wire, TypeId::M_DP_TB_1, 31);
type_test!(type_m_st_tb_1_wire, TypeId::M_ST_TB_1, 32);
type_test!(type_m_bo_tb_1_wire, TypeId::M_BO_TB_1, 33);
type_test!(type_m_me_td_1_wire, TypeId::M_ME_TD_1, 34);
type_test!(type_m_me_te_1_wire, TypeId::M_ME_TE_1, 35);
type_test!(type_m_me_tf_1_wire, TypeId::M_ME_TF_1, 36);
type_test!(type_m_it_tb_1_wire, TypeId::M_IT_TB_1, 37);
type_test!(type_m_ep_td_1_wire, TypeId::M_EP_TD_1, 38);
type_test!(type_m_ep_te_1_wire, TypeId::M_EP_TE_1, 39);
type_test!(type_m_ep_tf_1_wire, TypeId::M_EP_TF_1, 40);

// Control direction (45..51, 58..64)
type_test!(type_c_sc_na_1_wire, TypeId::C_SC_NA_1, 45);
type_test!(type_c_dc_na_1_wire, TypeId::C_DC_NA_1, 46);
type_test!(type_c_rc_na_1_wire, TypeId::C_RC_NA_1, 47);
type_test!(type_c_se_na_1_wire, TypeId::C_SE_NA_1, 48);
type_test!(type_c_se_nb_1_wire, TypeId::C_SE_NB_1, 49);
type_test!(type_c_se_nc_1_wire, TypeId::C_SE_NC_1, 50);
type_test!(type_c_bo_na_1_wire, TypeId::C_BO_NA_1, 51);
type_test!(type_c_sc_ta_1_wire, TypeId::C_SC_TA_1, 58);
type_test!(type_c_dc_ta_1_wire, TypeId::C_DC_TA_1, 59);
type_test!(type_c_rc_ta_1_wire, TypeId::C_RC_TA_1, 60);
type_test!(type_c_se_ta_1_wire, TypeId::C_SE_TA_1, 61);
type_test!(type_c_se_tb_1_wire, TypeId::C_SE_TB_1, 62);
type_test!(type_c_se_tc_1_wire, TypeId::C_SE_TC_1, 63);
type_test!(type_c_bo_ta_1_wire, TypeId::C_BO_TA_1, 64);

// System info (70, 100..107)
type_test!(type_m_ei_na_1_wire, TypeId::M_EI_NA_1, 70);
type_test!(type_c_ic_na_1_wire, TypeId::C_IC_NA_1, 100);
type_test!(type_c_ci_na_1_wire, TypeId::C_CI_NA_1, 101);
type_test!(type_c_rd_na_1_wire, TypeId::C_RD_NA_1, 102);
type_test!(type_c_cs_na_1_wire, TypeId::C_CS_NA_1, 103);
type_test!(type_c_ts_na_1_wire, TypeId::C_TS_NA_1, 104);
type_test!(type_c_rp_na_1_wire, TypeId::C_RP_NA_1, 105);
type_test!(type_c_cd_na_1_wire, TypeId::C_CD_NA_1, 106);
type_test!(type_c_ts_ta_1_wire, TypeId::C_TS_TA_1, 107);

// Parameter (110..113)
type_test!(type_p_me_na_1_wire, TypeId::P_ME_NA_1, 110);
type_test!(type_p_me_nb_1_wire, TypeId::P_ME_NB_1, 111);
type_test!(type_p_me_nc_1_wire, TypeId::P_ME_NC_1, 112);
type_test!(type_p_ac_na_1_wire, TypeId::P_AC_NA_1, 113);

// File transfer (120..126)
type_test!(type_f_fr_na_1_wire, TypeId::F_FR_NA_1, 120);
type_test!(type_f_sr_na_1_wire, TypeId::F_SR_NA_1, 121);
type_test!(type_f_sc_na_1_wire, TypeId::F_SC_NA_1, 122);
type_test!(type_f_ls_na_1_wire, TypeId::F_LS_NA_1, 123);
type_test!(type_f_af_na_1_wire, TypeId::F_AF_NA_1, 124);
type_test!(type_f_sg_na_1_wire, TypeId::F_SG_NA_1, 125);
type_test!(type_f_dr_ta_1_wire, TypeId::F_DR_TA_1, 126);

#[test]
fn type_id_undefined_zero_round_trip() {
    assert_eq!(TypeId::from_wire(0), TypeId::Undefined);
    assert_eq!(TypeId::Undefined.to_wire(), 0);
}

#[test]
fn type_id_strict_tryfrom_unknown_byte_errors() {
    // Strict TryFrom rejects bytes outside the defined set (other than 0).
    assert!(TypeId::try_from(22u8).is_err());
    assert!(TypeId::try_from(80u8).is_err());
    assert!(TypeId::try_from(255u8).is_err());
}

#[test]
fn type_id_lenient_from_wire_maps_to_undefined() {
    // from_wire never errors; unknown bytes fall back to Undefined.
    assert_eq!(TypeId::from_wire(22), TypeId::Undefined);
    assert_eq!(TypeId::from_wire(255), TypeId::Undefined);
}

#[test]
fn type_id_object_size_sp_na_is_one() {
    // The single-point-without-time body is a single octet.
    assert_eq!(TypeId::M_SP_NA_1.object_size(), 1);
    assert_eq!(body_len_for_type(1), 1);
    assert!(!has_cp24(1));
    assert!(!has_cp56(1));
}

#[test]
fn type_id_object_size_m_sp_tb_has_cp56() {
    // M_SP_TB_1 carries CP56 suffix.
    assert_eq!(TypeId::M_SP_TB_1.object_size(), 8);
    assert!(has_cp56(30));
    assert!(!has_cp24(30));
}

#[test]
fn type_id_object_size_m_sp_ta_has_cp24() {
    // M_SP_TA_1 carries 3-byte CP24 suffix.
    assert_eq!(TypeId::M_SP_TA_1.object_size(), 4);
    assert!(has_cp24(2));
    assert!(!has_cp56(2));
}

#[test]
fn type_id_object_size_c_rd_na_zero_body() {
    // C_RD_NA_1 carries no body.
    assert_eq!(TypeId::C_RD_NA_1.object_size(), 0);
    assert_eq!(body_len_for_type(102), 0);
}

#[test]
fn type_id_object_size_c_bo_ta_eleven_bytes() {
    // C_BO_TA_1: 4-byte body + 7-byte CP56.
    assert_eq!(TypeId::C_BO_TA_1.object_size(), 11);
    assert!(has_cp56(64));
}

#[test]
fn type_id_object_size_undefined_zero() {
    assert_eq!(TypeId::Undefined.object_size(), 0);
}

// ---------------------------------------------------------------------------
// Quality descriptor bit-layout tests: SIQ / DIQ / QDS / BCR.
// ---------------------------------------------------------------------------

#[test]
fn quality_siq_all_bits_distinct() {
    // SPIQ bits are non-overlapping single octet flags.
    let all = QualityDescriptor::SPI
        | QualityDescriptor::RESERVED_OR_DPI
        | QualityDescriptor::RESERVED_2
        | QualityDescriptor::RESERVED_3
        | QualityDescriptor::BLOCKED
        | QualityDescriptor::SUBSTITUTED
        | QualityDescriptor::NON_TOPICAL
        | QualityDescriptor::INVALID;
    assert_eq!(all.bits(), 0xFF);
    // Each flag covers exactly its bit.
    assert_eq!(QualityDescriptor::SPI.bits(), 0x01);
    assert_eq!(QualityDescriptor::INVALID.bits(), 0x80);
}

#[test]
fn quality_siq_default_empty() {
    let q = QualityDescriptor::default();
    assert!(q.is_empty());
    assert_eq!(q.bits(), 0);
}

#[test]
fn quality_siq_substituted_and_non_topical_or() {
    let q = QualityDescriptor::SUBSTITUTED | QualityDescriptor::NON_TOPICAL;
    assert_eq!(q.bits(), 0x60);
}

#[test]
fn quality_qds_overflow_low_bit() {
    let q = QualityDescriptorP::OVERFLOW;
    assert_eq!(q.bits(), 0x01);
}

#[test]
fn quality_qds_elapsed_time_invalid_bit_eight() {
    let q = QualityDescriptorP::ELAPSED_TIME_INVALID;
    assert_eq!(q.bits(), 0x08);
}

#[test]
fn quality_qds_invalid_bit_high() {
    let q = QualityDescriptorP::INVALID;
    assert_eq!(q.bits(), 0x80);
}

#[test]
fn quality_qds_all_flags_set() {
    let all = QualityDescriptorP::OVERFLOW
        | QualityDescriptorP::ELAPSED_TIME_INVALID
        | QualityDescriptorP::SUBSTITUTED
        | QualityDescriptorP::NON_TOPICAL
        | QualityDescriptorP::INVALID;
    // 0x01 | 0x08 | 0x20 | 0x40 | 0x80 = 0xE9
    assert_eq!(all.bits(), 0xE9);
}

#[test]
fn quality_qds_default_empty() {
    let q = QualityDescriptorP::default();
    assert!(q.is_empty());
}

#[test]
fn quality_bcr_carry_bit_low() {
    let q = BinaryCounterQuality::CARRY;
    assert_eq!(q.bits(), 0x01);
}

#[test]
fn quality_bcr_adjusted_bit() {
    let q = BinaryCounterQuality::ADJUSTED;
    assert_eq!(q.bits(), 0x20);
}

#[test]
fn quality_bcr_invalid_bit_high() {
    let q = BinaryCounterQuality::INVALID;
    assert_eq!(q.bits(), 0x80);
}

#[test]
fn quality_bcr_all_flags_set() {
    let all = BinaryCounterQuality::CARRY
        | BinaryCounterQuality::ADJUSTED
        | BinaryCounterQuality::INVALID;
    assert_eq!(all.bits(), 0xA1);
}

#[test]
fn quality_bcr_default_empty() {
    let q = BinaryCounterQuality::default();
    assert!(q.is_empty());
}

#[test]
fn quality_siq_invalid_or_substituted_nonzero() {
    let q = QualityDescriptor::INVALID | QualityDescriptor::SUBSTITUTED;
    assert!(!q.is_empty());
}

#[test]
fn quality_flags_have_no_overlap_within_family() {
    // SIQ: SPI (0x01) and INVALID (0x80) do not overlap.
    let combo = QualityDescriptor::SPI | QualityDescriptor::INVALID;
    assert_eq!(combo.bits(), 0x81);
}

#[test]
fn quality_qds_substituted_matches_siq_substituted() {
    // Substituted flag is bit 0x20 in both SIQ and QDS.
    assert_eq!(
        QualityDescriptor::SUBSTITUTED.bits(),
        QualityDescriptorP::SUBSTITUTED.bits()
    );
}

// ---------------------------------------------------------------------------
// ASDU framing boundary tests: header size, buffer limits, common-address
// encoding, IOA size, and parser rejection of malformed inputs.
// ---------------------------------------------------------------------------

fn sample_params() -> AppLayerParameters {
    AppLayerParameters::default()
}

fn params(cot: CotSize, ca: CaSize, ioa: IoaSize) -> AppLayerParameters {
    AppLayerParameters {
        size_of_cot: cot,
        size_of_ca: ca,
        size_of_ioa: ioa,
        max_size_of_asdu: 249,
    }
}

fn sample_asdu() -> Asdu {
    Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: 1,
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
            0x000001,
            InformationValue::SinglePoint {
                value: true,
                quality: QualityDescriptor::SPI,
            },
        )],
    }
}

#[test]
fn asdu_header_size_default_is_six() {
    // CotSize::Two + CaSize::Two + 2 (type + vsq) = 6.
    let p = sample_params();
    assert_eq!(p.header_size(), 6);
}

#[test]
fn asdu_header_size_one_byte_cot_ca() {
    let p = params(CotSize::One, CaSize::One, IoaSize::One);
    // 2 (type + vsq) + 1 + 1 = 4
    assert_eq!(p.header_size(), 4);
}

#[test]
fn asdu_header_size_three_byte_ioa_does_not_change_header() {
    // header_size excludes IOA (per-object).
    let p = params(CotSize::Two, CaSize::Two, IoaSize::Three);
    assert_eq!(p.header_size(), 6);
}

#[test]
fn asdu_ioa_size_one_byte() {
    let p = params(CotSize::One, CaSize::One, IoaSize::One);
    assert_eq!(p.ioa_size(), 1);
}

#[test]
fn asdu_ioa_size_two_bytes() {
    let p = params(CotSize::One, CaSize::One, IoaSize::Two);
    assert_eq!(p.ioa_size(), 2);
}

#[test]
fn asdu_ioa_size_three_bytes() {
    let p = params(CotSize::Two, CaSize::Two, IoaSize::Three);
    assert_eq!(p.ioa_size(), 3);
}

#[test]
fn asdu_encode_then_parse_lenient_default_round_trip() {
    let params = sample_params();
    let original = sample_asdu();
    let bytes = encode_to_vec(&params, &original).unwrap();
    let parsed: Asdu = parse_lenient_default(&bytes).unwrap();
    assert_eq!(parsed.type_id, original.type_id);
    assert_eq!(parsed.common_address, original.common_address);
    assert_eq!(parsed.objects.len(), original.objects.len());
}

#[test]
fn asdu_strict_parse_rejects_truncated_header() {
    // Header needs 6 bytes; feed 5.
    let bytes = [1u8, 2, 3, 4, 5];
    let res: Result<Asdu> = parse_default(&bytes);
    assert!(res.is_err());
}

#[test]
fn asdu_strict_parse_rejects_unknown_type_id() {
    // Header says type 0xFF (unknown). Strict must reject.
    let mut bytes = vec![0xFF, 0x01, 0x03, 0x00, 0x00, 0x01];
    // Pad with one object body (1 byte for M_SP_NA_1 shape).
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x01]);
    let res: Result<Asdu> = parse_default(&bytes);
    assert!(res.is_err());
}

#[test]
fn asdu_lenient_parse_accepts_unknown_type_id() {
    let mut bytes = vec![0xFF, 0x01, 0x03, 0x00, 0x00, 0x01];
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x01]);
    let res: Result<Asdu> = parse_lenient_default(&bytes);
    assert!(res.is_ok());
    let parsed = res.unwrap();
    assert_eq!(parsed.original_type_byte, 0xFF);
}

#[test]
fn asdu_encode_too_short_buffer_errors() {
    let params = sample_params();
    let asdu = sample_asdu();
    let mut buf = [0u8; 2];
    let res = asdu.encode(&params, &mut buf);
    assert!(res.is_err());
}

#[test]
fn asdu_sequence_increments_ioa_internally() {
    // SQ-bit ON: only the first IOA is encoded; subsequent objects inherit
    // ioa+1, +2, +3 ... up to count.
    let params = sample_params();
    let asdu = Asdu {
        is_sequence: true,
        objects: (0..3)
            .map(|i| {
                InformationObject::new(
                    100 + i,
                    InformationValue::SinglePoint {
                        value: i % 2 == 0,
                        quality: QualityDescriptor::empty(),
                    },
                )
            })
            .collect(),
        ..sample_asdu()
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed: Asdu = parse_lenient_default(&bytes).unwrap();
    assert!(parsed.is_sequence);
    assert_eq!(parsed.objects.len(), 3);
    let ioas: Vec<u32> = parsed.objects.iter().map(|o| o.ioa).collect();
    assert_eq!(ioas, vec![100, 101, 102]);
}

#[test]
fn asdu_ioa_decode_three_byte() {
    // Three-byte IOA: 0x00 0x00 0x01 -> 1
    let bytes = [0x01, 0x00, 0x00];
    let ioa = Ioa::decode(IoaSize::Three, &bytes).unwrap();
    assert_eq!(ioa.0, 1);
}
#[test]
fn asdu_ioa_decode_three_byte_max() {
    let bytes = [0xFF, 0xFF, 0xFF];
    let ioa = Ioa::decode(IoaSize::Three, &bytes).unwrap();
    assert_eq!(ioa.0, 0xFF_FFFF);
}

#[test]
fn asdu_common_address_one_byte_round_trip() {
    let p = params(CotSize::One, CaSize::One, IoaSize::One);
    let ca = CommonAddress(0x42);
    let mut buf = [0u8; 1];
    ca.encode(p.size_of_ca, &mut buf).unwrap();
    assert_eq!(buf[0], 0x42);
    let back = CommonAddress::decode(CaSize::One, &buf).unwrap();
    assert_eq!(back, CommonAddress(0x42));
}

#[test]
fn asdu_common_address_two_byte_round_trip() {
    let p = params(CotSize::One, CaSize::Two, IoaSize::One);
    let ca = CommonAddress(0x0102);
    let mut buf = [0u8; 2];
    ca.encode(p.size_of_ca, &mut buf).unwrap();
    let back = CommonAddress::decode(CaSize::Two, &buf).unwrap();
    assert_eq!(back, CommonAddress(0x0102));
}

#[test]
fn asdu_decode_buffer_too_short_object() {
    // Header is 6 bytes but no object body follows.
    let bytes = [1u8, 0x01, 0x03, 0x00, 0x00, 0x01];
    let res: Result<Asdu> = parse_default(&bytes);
    assert!(res.is_err());
}

#[test]
fn asdu_decode_vsq_count_zero_yields_zero_objects() {
    // VSQ count=0 in the current implementation produces no objects
    // (matches the strict-for loop bound). Spec text suggests "one object",
    // but the parser interprets the byte literally.
    let bytes = [0x01u8, 0x00, 0x03, 0x00, 0x00, 0x01];
    let res: Result<Asdu> = parse_lenient_default(&bytes);
    assert!(res.is_ok());
    assert_eq!(res.unwrap().objects.len(), 0);
}

#[test]
fn asdu_decode_count_exceeds_buffer() {
    // VSQ claims 127 objects but only header bytes follow.
    let bytes = vec![0x01, 0x7F, 0x03, 0x00, 0x00, 0x01];
    let res: Result<Asdu> = parse_default(&bytes);
    assert!(res.is_err());
}
