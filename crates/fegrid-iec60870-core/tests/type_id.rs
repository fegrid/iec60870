//! Integration tests for [`TypeId`] round-trips, the standard size
//! table, and CP24/CP56 helpers.

use core::convert::TryFrom;

use fegrid_iec60870_core::TypeId;
use fegrid_iec60870_core::error::AsduError;

#[test]
fn from_wire_undefined_byte_is_undefined() {
    // Gaps in the IEC-defined set map to Undefined.
    assert_eq!(TypeId::from_wire(0), TypeId::Undefined);
    assert_eq!(TypeId::from_wire(22), TypeId::Undefined);
    assert_eq!(TypeId::from_wire(200), TypeId::Undefined);
    assert_eq!(TypeId::from_wire(255), TypeId::Undefined);
}

#[test]
fn try_from_rejects_unknown_nonzero_bytes() {
    let err = TypeId::try_from(22u8).unwrap_err();
    assert!(matches!(err, AsduError::InvalidTypeId(22)));
    let err = TypeId::try_from(200u8).unwrap_err();
    assert!(matches!(err, AsduError::InvalidTypeId(200)));
}

#[test]
fn try_from_accepts_zero_as_undefined() {
    let t = TypeId::try_from(0u8).unwrap();
    assert_eq!(t, TypeId::Undefined);
}

#[test]
fn to_wire_round_trips_every_known_id() {
    let known = [
        TypeId::M_SP_NA_1,
        TypeId::M_SP_TA_1,
        TypeId::M_DP_NA_1,
        TypeId::M_ST_NA_1,
        TypeId::M_BO_NA_1,
        TypeId::M_ME_NA_1,
        TypeId::M_ME_NB_1,
        TypeId::M_ME_NC_1,
        TypeId::M_IT_NA_1,
        TypeId::M_EP_TA_1,
        TypeId::M_EP_TB_1,
        TypeId::M_EP_TC_1,
        TypeId::M_PS_NA_1,
        TypeId::M_ME_ND_1,
        TypeId::M_SP_TB_1,
        TypeId::M_DP_TB_1,
        TypeId::M_IT_TB_1,
        TypeId::C_SC_NA_1,
        TypeId::C_DC_NA_1,
        TypeId::C_RC_NA_1,
        TypeId::C_SE_NA_1,
        TypeId::C_SE_NB_1,
        TypeId::C_SE_NC_1,
        TypeId::C_BO_NA_1,
        TypeId::C_SC_TA_1,
        TypeId::C_DC_TA_1,
        TypeId::C_SE_TA_1,
        TypeId::C_SE_TB_1,
        TypeId::C_SE_TC_1,
        TypeId::C_BO_TA_1,
        TypeId::M_EI_NA_1,
        TypeId::C_IC_NA_1,
        TypeId::C_CI_NA_1,
        TypeId::C_RD_NA_1,
        TypeId::C_CS_NA_1,
        TypeId::C_TS_NA_1,
        TypeId::C_RP_NA_1,
        TypeId::C_CD_NA_1,
        TypeId::C_TS_TA_1,
        TypeId::P_ME_NA_1,
        TypeId::P_ME_NB_1,
        TypeId::P_ME_NC_1,
        TypeId::P_AC_NA_1,
        TypeId::F_FR_NA_1,
        TypeId::F_SR_NA_1,
        TypeId::F_SC_NA_1,
        TypeId::F_LS_NA_1,
        TypeId::F_AF_NA_1,
        TypeId::F_SG_NA_1,
        TypeId::F_DR_TA_1,
    ];
    for t in known {
        let byte = t.to_wire();
        assert_eq!(TypeId::from_wire(byte), t, "{t:?} != byte {byte}");
    }
}

#[test]
fn object_size_matches_standard_table() {
    // Body size for representative ids (matches IEC 60870-5 size table).
    assert_eq!(TypeId::M_SP_NA_1.object_size(), 1);
    assert_eq!(TypeId::M_SP_TA_1.object_size(), 4); // 1 + CP24
    assert_eq!(TypeId::M_DP_NA_1.object_size(), 1);
    assert_eq!(TypeId::M_ST_NA_1.object_size(), 2);
    assert_eq!(TypeId::M_BO_NA_1.object_size(), 5);
    assert_eq!(TypeId::M_ME_NA_1.object_size(), 3);
    assert_eq!(TypeId::M_ME_NB_1.object_size(), 3);
    assert_eq!(TypeId::M_ME_NC_1.object_size(), 5);
    assert_eq!(TypeId::M_IT_NA_1.object_size(), 5);
    assert_eq!(TypeId::M_EP_TA_1.object_size(), 6);
    assert_eq!(TypeId::M_EP_TB_1.object_size(), 7);
    assert_eq!(TypeId::M_EP_TC_1.object_size(), 7);
    assert_eq!(TypeId::M_PS_NA_1.object_size(), 5);
    assert_eq!(TypeId::M_ME_ND_1.object_size(), 2);
    assert_eq!(TypeId::M_SP_TB_1.object_size(), 8); // 1 + CP56
    assert_eq!(TypeId::M_BO_TB_1.object_size(), 12);
    assert_eq!(TypeId::M_IT_TB_1.object_size(), 12);
    assert_eq!(TypeId::M_EP_TD_1.object_size(), 10);
    assert_eq!(TypeId::C_SC_NA_1.object_size(), 1);
    assert_eq!(TypeId::C_SE_NC_1.object_size(), 5);
    assert_eq!(TypeId::C_BO_NA_1.object_size(), 4);
    assert_eq!(TypeId::C_SC_TA_1.object_size(), 8);
    assert_eq!(TypeId::C_SE_TA_1.object_size(), 10);
    assert_eq!(TypeId::C_BO_TA_1.object_size(), 11);
    assert_eq!(TypeId::M_EI_NA_1.object_size(), 1);
    assert_eq!(TypeId::C_IC_NA_1.object_size(), 1);
    assert_eq!(TypeId::C_RD_NA_1.object_size(), 0);
    assert_eq!(TypeId::C_CS_NA_1.object_size(), 7);
    assert_eq!(TypeId::C_TS_NA_1.object_size(), 2);
    assert_eq!(TypeId::C_RP_NA_1.object_size(), 1);
    assert_eq!(TypeId::C_CD_NA_1.object_size(), 2);
    assert_eq!(TypeId::C_TS_TA_1.object_size(), 9);
    assert_eq!(TypeId::P_ME_NA_1.object_size(), 3);
    // F_FR_NA_1: NOF(2) + LOF(3) + FRQ(1) = 6 (per IEC 60870-5 §7.3.1.120).
    assert_eq!(TypeId::F_FR_NA_1.object_size(), 6);
    // F_SR_NA_1: NOF(2) + NOS(1) + LOS(3) + SRQ(1) = 7 (per IEC 60870-5 §7.3.1.121).
    assert_eq!(TypeId::F_SR_NA_1.object_size(), 7);
    assert_eq!(TypeId::F_AF_NA_1.object_size(), 4);
    assert_eq!(TypeId::F_SG_NA_1.object_size(), 0);
    assert_eq!(TypeId::F_DR_TA_1.object_size(), 0);
    assert_eq!(TypeId::Undefined.object_size(), 0);
}

#[test]
fn has_cp56_time_covers_cp56_family() {
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
        TypeId::M_EP_TB_1,
        TypeId::M_EP_TC_1,
        TypeId::C_SC_TA_1,
        TypeId::C_DC_TA_1,
        TypeId::C_RC_TA_1,
        TypeId::C_SE_TA_1,
        TypeId::C_SE_TB_1,
        TypeId::C_SE_TC_1,
        TypeId::C_BO_TA_1,
        TypeId::C_TS_TA_1,
    ] {
        assert!(t.has_cp56_time(), "{t:?} should have CP56");
        assert!(!t.has_cp24_time(), "{t:?} should NOT have CP24");
    }
}

#[test]
fn has_cp24_time_covers_cp24_family() {
    for t in [
        TypeId::M_SP_TA_1,
        TypeId::M_DP_TA_1,
        TypeId::M_ST_TA_1,
        TypeId::M_BO_TA_1,
        TypeId::M_ME_TA_1,
        TypeId::M_ME_TB_1,
        TypeId::M_ME_TC_1,
        TypeId::M_IT_TA_1,
        TypeId::M_EP_TA_1,
    ] {
        assert!(t.has_cp24_time(), "{t:?} should have CP24");
        assert!(!t.has_cp56_time(), "{t:?} should NOT have CP56");
    }
}

#[test]
fn time_helpers_return_false_for_no_time_types() {
    assert!(!TypeId::M_SP_NA_1.has_cp24_time());
    assert!(!TypeId::M_SP_NA_1.has_cp56_time());
    assert!(!TypeId::C_IC_NA_1.has_cp24_time());
    assert!(!TypeId::C_IC_NA_1.has_cp56_time());
    // C_CS_NA_1 is intentionally NOT counted as CP56-suffix.
    assert!(!TypeId::C_CS_NA_1.has_cp56_time());
    assert!(!TypeId::Undefined.has_cp24_time());
    assert!(!TypeId::Undefined.has_cp56_time());
}

#[test]
fn from_to_round_trip_preserves_undefined_byte() {
    // Undefined round-trips via to_wire preserving the byte.
    let t = TypeId::Undefined;
    let byte = t.to_wire();
    assert_eq!(byte, 0);
    assert_eq!(TypeId::from_wire(byte), TypeId::Undefined);
}

#[test]
fn into_u8_returns_wire_byte() {
    let b: u8 = TypeId::M_SP_NA_1.into();
    assert_eq!(b, 1);
}
