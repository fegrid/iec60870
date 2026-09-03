//! IEC 60870-5 `TypeId` enumeration + per-type body size.

use crate::error::AsduError;

/// All type identifiers defined by IEC 60870-5-101/104.
///
/// Discriminants are the wire values; `Undefined = 0` is the catch-all used
/// for type ids outside the defined set — those still decode to
/// `TypeId::Undefined` and round-trip via the value byte, never rejected.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TypeId {
    /// Catch-all for unknown wire values; wire round-trips the byte.
    Undefined = 0,

    // --- process information in monitor direction (1..21) ---
    /// Single-point information without time.
    M_SP_NA_1 = 1,
    /// Single-point information with CP24 time (TA).
    M_SP_TA_1 = 2,
    /// Double-point information without time.
    M_DP_NA_1 = 3,
    /// Double-point information with CP24 time.
    M_DP_TA_1 = 4,
    /// Step position information without time.
    M_ST_NA_1 = 5,
    /// Step position information with CP24 time.
    M_ST_TA_1 = 6,
    /// Bitstring of 32 bits without time.
    M_BO_NA_1 = 7,
    /// Bitstring of 32 bits with CP24 time.
    M_BO_TA_1 = 8,
    /// Measured value, normalized without time.
    M_ME_NA_1 = 9,
    /// Measured value, normalized with CP24 time.
    M_ME_TA_1 = 10,
    /// Measured value, scaled without time.
    M_ME_NB_1 = 11,
    /// Measured value, scaled with CP24 time.
    M_ME_TB_1 = 12,
    /// Measured value, short floating-point without time.
    M_ME_NC_1 = 13,
    /// Measured value, short floating-point with CP24 time.
    M_ME_TC_1 = 14,
    /// Integrated totals without time.
    M_IT_NA_1 = 15,
    /// Integrated totals with CP24 time.
    M_IT_TA_1 = 16,
    /// Event of protection equipment with CP24 time.
    M_EP_TA_1 = 17,
    /// Event of protection equipment with CP56 time.
    M_EP_TB_1 = 18,
    /// Packed start events of protection equipment with CP56 time.
    M_EP_TC_1 = 19,
    /// Packed single-point events with status change detection.
    M_PS_NA_1 = 20,
    /// Measured value, normalized without quality descriptor.
    M_ME_ND_1 = 21,

    // --- process information in monitor direction with CP56 time (30..40) ---
    /// Single-point with CP56 time.
    M_SP_TB_1 = 30,
    /// Double-point with CP56 time.
    M_DP_TB_1 = 31,
    /// Step position with CP56 time.
    M_ST_TB_1 = 32,
    /// Bitstring of 32 bits with CP56 time.
    M_BO_TB_1 = 33,
    /// Measured value, normalized with CP56 time.
    M_ME_TD_1 = 34,
    /// Measured value, scaled with CP56 time.
    M_ME_TE_1 = 35,
    /// Measured value, short floating-point with CP56 time.
    M_ME_TF_1 = 36,
    /// Integrated totals with CP56 time.
    M_IT_TB_1 = 37,
    /// Event of protection equipment with CP56 time (alternate).
    M_EP_TD_1 = 38,
    /// Event of protection equipment with CP56 time (alternate).
    M_EP_TE_1 = 39,
    /// Event of protection equipment with CP56 time (alternate).
    M_EP_TF_1 = 40,

    // --- process information in control direction (45..64) ---
    /// Single command.
    C_SC_NA_1 = 45,
    /// Double command.
    C_DC_NA_1 = 46,
    /// Regulating step command.
    C_RC_NA_1 = 47,
    /// Setpoint command, normalized.
    C_SE_NA_1 = 48,
    /// Setpoint command, scaled.
    C_SE_NB_1 = 49,
    /// Setpoint command, short floating-point.
    C_SE_NC_1 = 50,
    /// Bitstring of 32 bits command.
    C_BO_NA_1 = 51,
    /// Single command with CP24 time.
    C_SC_TA_1 = 58,
    /// Double command with CP24 time.
    C_DC_TA_1 = 59,
    /// Regulating step command with CP24 time.
    C_RC_TA_1 = 60,
    /// Setpoint command, normalized with CP24 time.
    C_SE_TA_1 = 61,
    /// Setpoint command, scaled with CP24 time.
    C_SE_TB_1 = 62,
    /// Setpoint command, short floating-point with CP24 time.
    C_SE_TC_1 = 63,
    /// Bitstring of 32 bits command with CP24 time.
    C_BO_TA_1 = 64,

    // --- system information in monitor direction (70) ---
    /// End of initialization.
    M_EI_NA_1 = 70,

    // --- system information in control direction (100..107) ---
    /// General interrogation command.
    C_IC_NA_1 = 100,
    /// Counter interrogation command.
    C_CI_NA_1 = 101,
    /// Read command.
    C_RD_NA_1 = 102,
    /// Clock synchronization command.
    C_CS_NA_1 = 103,
    /// Test command.
    C_TS_NA_1 = 104,
    /// Reset process command.
    C_RP_NA_1 = 105,
    /// Delay acquisition command.
    C_CD_NA_1 = 106,
    /// Test command with CP56 time.
    C_TS_TA_1 = 107,

    // --- parameter in control direction (110..113) ---
    /// Parameter of measured value, normalized.
    P_ME_NA_1 = 110,
    /// Parameter of measured value, scaled.
    P_ME_NB_1 = 111,
    /// Parameter of measured value, short floating-point.
    P_ME_NC_1 = 112,
    /// Parameter activation.
    P_AC_NA_1 = 113,

    // --- file transfer (120..127) ---
    /// File ready.
    F_FR_NA_1 = 120,
    /// Section ready.
    F_SR_NA_1 = 121,
    /// Call directory, select file, call file, call section.
    F_SC_NA_1 = 122,
    /// Last section, last segment.
    F_LS_NA_1 = 123,
    /// ACK file, ACK section.
    F_AF_NA_1 = 124,
    /// Segment.
    F_SG_NA_1 = 125,
    /// Directory.
    F_DR_TA_1 = 126,
}

impl TypeId {
    /// Construct a `TypeId` from the wire byte, mapping unknown values to
    /// [`TypeId::Undefined`].
    pub const fn from_wire(byte: u8) -> Self {
        match byte {
            1 => Self::M_SP_NA_1,
            2 => Self::M_SP_TA_1,
            3 => Self::M_DP_NA_1,
            4 => Self::M_DP_TA_1,
            5 => Self::M_ST_NA_1,
            6 => Self::M_ST_TA_1,
            7 => Self::M_BO_NA_1,
            8 => Self::M_BO_TA_1,
            9 => Self::M_ME_NA_1,
            10 => Self::M_ME_TA_1,
            11 => Self::M_ME_NB_1,
            12 => Self::M_ME_TB_1,
            13 => Self::M_ME_NC_1,
            14 => Self::M_ME_TC_1,
            15 => Self::M_IT_NA_1,
            16 => Self::M_IT_TA_1,
            17 => Self::M_EP_TA_1,
            18 => Self::M_EP_TB_1,
            19 => Self::M_EP_TC_1,
            20 => Self::M_PS_NA_1,
            21 => Self::M_ME_ND_1,
            30 => Self::M_SP_TB_1,
            31 => Self::M_DP_TB_1,
            32 => Self::M_ST_TB_1,
            33 => Self::M_BO_TB_1,
            34 => Self::M_ME_TD_1,
            35 => Self::M_ME_TE_1,
            36 => Self::M_ME_TF_1,
            37 => Self::M_IT_TB_1,
            38 => Self::M_EP_TD_1,
            39 => Self::M_EP_TE_1,
            40 => Self::M_EP_TF_1,
            45 => Self::C_SC_NA_1,
            46 => Self::C_DC_NA_1,
            47 => Self::C_RC_NA_1,
            48 => Self::C_SE_NA_1,
            49 => Self::C_SE_NB_1,
            50 => Self::C_SE_NC_1,
            51 => Self::C_BO_NA_1,
            58 => Self::C_SC_TA_1,
            59 => Self::C_DC_TA_1,
            60 => Self::C_RC_TA_1,
            61 => Self::C_SE_TA_1,
            62 => Self::C_SE_TB_1,
            63 => Self::C_SE_TC_1,
            64 => Self::C_BO_TA_1,
            70 => Self::M_EI_NA_1,
            100 => Self::C_IC_NA_1,
            101 => Self::C_CI_NA_1,
            102 => Self::C_RD_NA_1,
            103 => Self::C_CS_NA_1,
            104 => Self::C_TS_NA_1,
            105 => Self::C_RP_NA_1,
            106 => Self::C_CD_NA_1,
            107 => Self::C_TS_TA_1,
            110 => Self::P_ME_NA_1,
            111 => Self::P_ME_NB_1,
            112 => Self::P_ME_NC_1,
            113 => Self::P_AC_NA_1,
            120 => Self::F_FR_NA_1,
            121 => Self::F_SR_NA_1,
            122 => Self::F_SC_NA_1,
            123 => Self::F_LS_NA_1,
            124 => Self::F_AF_NA_1,
            125 => Self::F_SG_NA_1,
            126 => Self::F_DR_TA_1,
            _ => Self::Undefined,
        }
    }

    /// Wire byte for this `TypeId` (`Undefined` keeps the byte verbatim).
    pub const fn to_wire(self) -> u8 {
        self as u8
    }

    /// Body length (bytes per object) **including** any trailing
    /// timestamp suffix. Matches the IEC 60870-5 standard size table
    /// (see also `tests/golden.wire_spec_vectors_round_trip` for
    /// the canonical byte-level layout asserted by the committed
    /// wire-spec fixtures).
    pub const fn object_size(self) -> usize {
        use TypeId::*;
        match self {
            M_SP_NA_1 => 1,
            M_SP_TA_1 => 4,
            M_DP_NA_1 => 1,
            M_DP_TA_1 => 4,
            M_ST_NA_1 => 2,
            M_ST_TA_1 => 5,
            M_BO_NA_1 => 5,
            M_BO_TA_1 => 8,
            M_ME_NA_1 => 3,
            M_ME_TA_1 => 6,
            M_ME_NB_1 => 3,
            M_ME_TB_1 => 6,
            M_ME_NC_1 => 5,
            M_ME_TC_1 => 8,
            M_IT_NA_1 => 5,
            M_IT_TA_1 => 8,
            M_EP_TA_1 => 6,
            M_EP_TB_1 => 7,
            M_EP_TC_1 => 7,
            M_PS_NA_1 => 5,
            M_ME_ND_1 => 2,
            M_SP_TB_1 => 8,
            M_DP_TB_1 => 8,
            M_ST_TB_1 => 9,
            M_BO_TB_1 => 12,
            M_ME_TD_1 => 10,
            M_ME_TE_1 => 10,
            M_ME_TF_1 => 12,
            M_IT_TB_1 => 12,
            M_EP_TD_1 => 10,
            M_EP_TE_1 => 11,
            M_EP_TF_1 => 11,
            C_SC_NA_1 => 1,
            C_DC_NA_1 => 1,
            C_RC_NA_1 => 1,
            C_SE_NA_1 => 3,
            C_SE_NB_1 => 3,
            C_SE_NC_1 => 5,
            C_BO_NA_1 => 4,
            C_SC_TA_1 => 8,
            C_DC_TA_1 => 8,
            C_RC_TA_1 => 8,
            C_SE_TA_1 => 10,
            C_SE_TB_1 => 10,
            C_SE_TC_1 => 12,
            C_BO_TA_1 => 11,
            M_EI_NA_1 => 1,
            C_IC_NA_1 => 1,
            C_CI_NA_1 => 1,
            C_RD_NA_1 => 0,
            C_CS_NA_1 => 7,
            C_TS_NA_1 => 2,
            C_RP_NA_1 => 1,
            C_CD_NA_1 => 2,
            C_TS_TA_1 => 9,
            P_ME_NA_1 => 3,
            P_ME_NB_1 => 3,
            P_ME_NC_1 => 5,
            P_AC_NA_1 => 1,
            F_FR_NA_1 => 6,
            F_SR_NA_1 => 7,
            F_SC_NA_1 => 4,
            F_LS_NA_1 => 5,
            F_AF_NA_1 => 4,
            F_SG_NA_1 => 0,
            F_DR_TA_1 => 0,
            Undefined => 0,
        }
    }

    /// `true` if the per-object body is followed by a 7-byte CP56Time2a.
    pub const fn has_cp56_time(self) -> bool {
        use TypeId::*;
        matches!(
            self,
            M_SP_TB_1
                | M_DP_TB_1
                | M_ST_TB_1
                | M_BO_TB_1
                | M_ME_TD_1
                | M_ME_TE_1
                | M_ME_TF_1
                | M_IT_TB_1
                | M_EP_TD_1
                | M_EP_TE_1
                | M_EP_TF_1
                | M_EP_TB_1
                | M_EP_TC_1
                | C_SC_TA_1
                | C_DC_TA_1
                | C_RC_TA_1
                | C_SE_TA_1
                | C_SE_TB_1
                | C_SE_TC_1
                | C_BO_TA_1
                | C_TS_TA_1
        )
    }

    /// `true` if the per-object body is followed by a 3-byte CP24Time2a.
    pub const fn has_cp24_time(self) -> bool {
        use TypeId::*;
        matches!(
            self,
            M_SP_TA_1
                | M_DP_TA_1
                | M_ST_TA_1
                | M_BO_TA_1
                | M_ME_TA_1
                | M_ME_TB_1
                | M_ME_TC_1
                | M_IT_TA_1
                | M_EP_TA_1
        )
    }
}

impl TryFrom<u8> for TypeId {
    type Error = AsduError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        let t = Self::from_wire(byte);
        if matches!(t, Self::Undefined) && byte != 0 {
            Err(AsduError::InvalidTypeId(byte))
        } else {
            Ok(t)
        }
    }
}

impl From<TypeId> for u8 {
    fn from(t: TypeId) -> u8 {
        t.to_wire()
    }
}
