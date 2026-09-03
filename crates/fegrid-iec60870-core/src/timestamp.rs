//! `Timestamp` enum + per-`TypeId` timestamp-kind helper.
//!
//! IEC 60870-5-101/104 information objects are optionally followed by a
//! short time tag (CP16, CP24, or CP56 — none of the IEC variants use
//! CP32 in practice). The kind of timestamp is determined entirely by
//! the `TypeId`:
//!
//! - CP24 (3 bytes): `_TA_1` family (`M_*_TA_1`).
//! - CP56 (7 bytes): `_TB_1` / `_TC_1` family + `M_EP_T*` + the
//!   control-direction `*_TA_1` family.
//!
//! `C_CS_NA_1` and `C_TS_TA_1` are NOT counted as timestamp-suffix
//! types: their per-object body **is** the CP56 (possibly preceded by
//! a 2-byte FBP for `C_TS_TA_1`). They decode via `InformationValue`'s
//! `Raw` body path, not via the `obj.timestamp` suffix path.

use crate::error::{AsduError, Result};
use crate::time::{Cp16Time2a, Cp24Time2a, Cp56Time2a};
use crate::type_id::TypeId;

/// Length in bytes of a `Timestamp` variant.
pub const fn timestamp_len(kind: TimestampKind) -> usize {
    kind.len()
}

/// Which CP timestamp kind a `TypeId` carries.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimestampKind {
    /// 2-byte millisecond-only tag.
    Cp16,
    /// 3-byte ms + minutes tag.
    Cp24,
    /// 7-byte full timestamp tag.
    Cp56,
}

impl TimestampKind {
    /// Wire byte length.
    pub const fn len(self) -> usize {
        match self {
            TimestampKind::Cp16 => 2,
            TimestampKind::Cp24 => 3,
            TimestampKind::Cp56 => 7,
        }
    }
    /// Always false (timestamps are never zero-length).
    pub const fn is_empty(self) -> bool {
        false
    }
}

/// A timestamp suffix carried by `*_TA_1` / `*_TB_1` / `*_TC_1` ASDUs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Timestamp {
    /// 2-byte ms tag.
    Cp16(Cp16Time2a),
    /// 3-byte ms + minutes tag.
    Cp24(Cp24Time2a),
    /// 7-byte full timestamp.
    Cp56(Cp56Time2a),
}

impl Timestamp {
    /// Wire byte length for this timestamp.
    pub const fn len(&self) -> usize {
        match self {
            Timestamp::Cp16(_) => 2,
            Timestamp::Cp24(_) => 3,
            Timestamp::Cp56(_) => 7,
        }
    }

    /// Always false (timestamps are never zero-length).
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Encode into a buffer; returns the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        match self {
            Timestamp::Cp16(t) => {
                t.encode(out)?;
                Ok(2)
            }
            Timestamp::Cp24(t) => {
                t.encode(out)?;
                Ok(3)
            }
            Timestamp::Cp56(t) => {
                t.encode(out)?;
                Ok(7)
            }
        }
    }

    /// Decode from `input` according to `kind`. Returns the parsed
    /// timestamp and the number of bytes consumed (always `kind.len()`).
    pub fn decode(kind: TimestampKind, input: &[u8]) -> Result<Self> {
        let need = kind.len();
        if input.len() < need {
            return Err(AsduError::BufferTooShort {
                need,
                have: input.len(),
            });
        }
        let out = match kind {
            TimestampKind::Cp16 => Timestamp::Cp16(Cp16Time2a::decode(input)?),
            TimestampKind::Cp24 => Timestamp::Cp24(Cp24Time2a::decode(input)?),
            TimestampKind::Cp56 => Timestamp::Cp56(Cp56Time2a::decode(input)?),
        };
        Ok(out)
    }
}

/// Return the timestamp kind required by `type_id`, if any.
pub fn timestamp_kind_for(type_id: TypeId) -> Option<TimestampKind> {
    use TypeId as T;
    match type_id {
        // CP24 family (M_*_TA_1, M_EP_TA_1, M_EP_TB_1, M_EP_TC_1).
        // Type ids 18/19 (M_EP_TB_1 / M_EP_TC_1) carry a CP24 suffix.
        T::M_SP_TA_1
        | T::M_DP_TA_1
        | T::M_ST_TA_1
        | T::M_BO_TA_1
        | T::M_ME_TA_1
        | T::M_ME_TB_1
        | T::M_ME_TC_1
        | T::M_IT_TA_1
        | T::M_EP_TA_1
        | T::M_EP_TB_1
        | T::M_EP_TC_1 => Some(TimestampKind::Cp24),
        // CP56 family (_TB_1, _TC_1 monitor-direction, M_EP_TD/TE/TF,
        // control-direction _TA_1, and C_TS_TA_1).
        T::M_SP_TB_1
        | T::M_DP_TB_1
        | T::M_ST_TB_1
        | T::M_BO_TB_1
        | T::M_ME_TD_1
        | T::M_ME_TE_1
        | T::M_ME_TF_1
        | T::M_IT_TB_1
        | T::M_EP_TD_1
        | T::M_EP_TE_1
        | T::M_EP_TF_1
        | T::C_SC_TA_1
        | T::C_DC_TA_1
        | T::C_RC_TA_1
        | T::C_SE_TA_1
        | T::C_SE_TB_1
        | T::C_SE_TC_1
        | T::C_BO_TA_1
        | T::C_TS_TA_1 => Some(TimestampKind::Cp56),
        // C_CS_NA_1 (103) — body IS the CP56, no separate trailing suffix.
        // All other TypeIds have no trailing timestamp.
        _ => None,
    }
}
