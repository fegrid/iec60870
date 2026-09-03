//! IEC 60870-5-104 APCI codec + connection-state engine.
//!
//! Module map:
//! - [`params`]: APCI + ASDU parameters (k, w, t0..t3).
//! - [`apci`]: frame encode/decode for I, S, and U frames.
//! - [`sequence`]: pure-modulo sequence-number state machine.
//! - [`typestate`]: zero-sized type markers + an [`Output`] envelope that
//!   prevents invalid state transitions at compile time.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

pub mod apci;
pub mod params;
pub mod sequence;
pub mod typestate;
pub mod watchdog;
pub use apci::{
    APCI_MAX_LENGTH, APDU_MIN_LENGTH, Apdu, SeqNo, UFrame, encode_i, parse_apdu, s_frame_bytes,
    u_frame_bytes,
};

pub use params::ApciParameters;
pub use sequence::SequenceState;
pub use typestate::{
    Closed, Cs104Session, Output, SessionError, Started, Stopped, WaitingStartCon, WaitingStopCon,
};
pub use watchdog::{CloseReason, MAX_TESTFR_MISSES, Watchdog, WatchdogAction};
