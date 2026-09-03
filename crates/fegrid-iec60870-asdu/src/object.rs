//! Information-object wrapper (IOA + value + optional timestamp).

use fegrid_iec60870_core::Timestamp;

use crate::values::InformationValue;

/// One information object: a `value` plus its information-object-address,
/// plus an optional per-type timestamp suffix (CP16 / CP24 / CP56).
#[derive(Debug, Clone, PartialEq)]
pub struct InformationObject {
    /// Information-object address.
    pub ioa: u32,
    /// Information body (typed).
    pub value: InformationValue,
    /// Optional trailing timestamp — its `TimestampKind` must match the
    /// enclosing ASDU's `TypeId` per `TypeId::object_size()`.
    pub timestamp: Option<Timestamp>,
}

impl InformationObject {
    /// New object without a timestamp.
    pub fn new(ioa: u32, value: InformationValue) -> Self {
        Self {
            ioa,
            value,
            timestamp: None,
        }
    }

    /// New object with an optional timestamp.
    pub fn with_timestamp(ioa: u32, value: InformationValue, timestamp: Option<Timestamp>) -> Self {
        Self {
            ioa,
            value,
            timestamp,
        }
    }
}
