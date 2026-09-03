//! Typed IEC 60870-5 ASDU codec.
//!
//! Public surface:
//! - [`Asdu`]: encode + decode a full ASDU.
//! - [`InformationObject`] / [`InformationValue`]: typed body.
//! - [`Vsq`], [`body_len_for_type`], [`has_cp56`], [`has_cp24`]: helpers.
//! ```ignore
//! use fegrid_iec60870_asdu::{Asdu, InformationValue, InformationObject, encode_to_vec};
//! use fegrid_iec60870_core::{AppLayerParameters, CauseOfTransmission, CotField, CommonAddress, TypeId};
//!
//! let params = AppLayerParameters::default();
//! let asdu = Asdu {
//!     type_id: TypeId::M_SP_NA_1,
//!     original_type_byte: TypeId::M_SP_NA_1 as u8,
//!     cot: CotField { cause: CauseOfTransmission::Spontaneous, negative_confirm: false, test: false, originator: 0 },
//!     common_address: CommonAddress(1),
//!     is_sequence: false,
//!     is_test: false,
//!     objects: vec![
//!         InformationObject::new(0x000100, InformationValue::SinglePoint { value: true, quality: Default::default() }),
//!     ],
//! };
//! let bytes = encode_to_vec(&params, &asdu).unwrap();
//! let parsed = Asdu::parse(&params, &bytes).unwrap();
//! assert_eq!(parsed.type_id, TypeId::M_SP_NA_1);
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;
pub mod asdu;
pub mod dispatch;
pub mod error;
pub mod file_transfer;
pub mod object;
pub mod values;
pub mod values_encode;
pub use asdu::{Asdu, Vsq, encode_to_vec, encoded_len, parse_default, parse_lenient_default};
pub use dispatch::{
    DispatchEvent, SetpointValue, activation_confirm, activation_confirm_negative,
    activation_confirm_with_cause, activation_termination, classify,
};
pub use error::{AsduError, Result};
pub use file_transfer::{FileReceiveSide, FileSendSide, FileTransferError, FileTransferResult};
pub use object::InformationObject;
pub use values::{
    BinaryCounterReading, FileAckRepr, FileCallRepr, FileLastSectionRepr, FileReadyRepr,
    InformationValue, SectionReadyRepr,
};
