//! IEC 60870-5-101 FT 1.2 link layer codec.
//!
//! Module map:
//! - [`function_codes`]: primary + secondary function-code enums.
//! - [`ft12`]: frame codec for fixed frames, variable frames, single-char ACK,
//!   plus a streaming [`Ft12Codec`] parser.
//!
//! All types are pure value types — no I/O — so they compose into any
//! transport (serial, TCP mock, tokio, etc.).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

pub mod ft12;
pub mod function_codes;
pub mod master;
pub mod slave;

pub use ft12::{
    ControlField, FixedFrame, Ft12Codec, Ft12Error, Ft12Frame, SINGLE_CHAR_ACK, SINGLE_CHAR_NAK,
    VariableFrame, parse_one,
};
pub use function_codes::{PrimaryFunctionCode, SecondaryFunctionCode};
pub use master::{AddressLen, Cs101Command, Cs101Master, Cs101MasterConfig, Cs101MasterMode};
pub use slave::{AsduHandler, ClassQueues, Cs101Slave, Dir, LinkState, PluginHook, RawMessageHook};
