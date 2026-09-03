//! Shared no_std primitives for the fegrid-iec60870 workspace.
//!
//! This crate is `no_std`-capable (compile with `default-features = false`).
//! Modules:
//!
//! - [`error`]: structured [`AsduError`] covering every protocol-decoding failure.
//! - [`params`]: [`AppLayerParameters`], [`LinkLayerParameters`] + size enums.
//! - [`type_id`]: the [`TypeId`] discriminant and per-type body-size table.
//! - [`cot`]: [`CauseOfTransmission`] + [`CotField`] (wire encode/decode).
//! - [`quality`]: [`QualityDescriptor`], [`QualityDescriptorP`], [`BinaryCounterQuality`].
//! - [`time`]: CP16/CP24/CP32/CP56 time tags with `encode`/`decode`.
//! - [`ioa`]: the [`Ioa`] newtype for information-object addresses.
//! - [`address`]: the [`CommonAddress`] newtype.
//!
//! ```
//! use fegrid_iec60870_core::{TypeId, CotSize, CauseOfTransmission, CotField};
//!
//! let id = TypeId::try_from(1u8).unwrap();
//! assert_eq!(id, TypeId::M_SP_NA_1);
//! assert_eq!(id.object_size(), 1);
//!
//! let mut buf = [0u8; 2];
//! let cot = CotField { cause: CauseOfTransmission::Spontaneous, negative_confirm: false, test: false, originator: 0, cause_raw_override: None };
//! cot.encode(CotSize::Two, &mut buf).unwrap();
//! assert_eq!(buf[0], 0x03);

#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

pub mod address;
pub mod cot;
pub mod error;
pub mod ioa;
pub mod params;
pub mod qualifier;
pub mod quality;
pub mod time;
pub mod timestamp;
pub mod type_id;
pub use address::CommonAddress;
pub use cot::{CauseOfTransmission, CotField};
pub use error::{AsduError, Result};
pub use ioa::Ioa;
pub use params::{AddressLen, AppLayerParameters, CaSize, CotSize, IoaSize, LinkLayerParameters};
pub use qualifier::{
    QualifierOfCIC, QualifierOfCommand, QualifierOfInterrogation, QualifierOfParameterActivation,
    QualifierOfParameterMV, QualifierOfRPC,
};
pub use quality::{BinaryCounterQuality, QualityDescriptor, QualityDescriptorP};
pub use time::{Cp16Time2a, Cp24Time2a, Cp32Time2a, Cp56Time2a};
pub use timestamp::{Timestamp, TimestampKind, timestamp_kind_for, timestamp_len};
pub use type_id::TypeId;
