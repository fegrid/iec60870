//! Top-level umbrella crate for the `fegrid-iec60870-*` family.
//!
//! Re-exports the most common types from the subcrates so that
//! application code can `use fegrid_iec60870::*`.
//!
//! Subcrates:
//! - `fegrid_iec60870_core` — type id, COT, qualifier, time, IOA.
//! - `fegrid_iec60870_asdu` — ASDU encoder + dispatcher + file
//!   transfer state machines.
//! - `fegrid_iec60870_cs101` — IEC 60870-5-101 FT 1.2 link layer
//!   plus master/slave runtime.
//! - `fegrid_iec60870_cs104` — IEC 60870-5-104 APCI typestate
//!   engine, watchdog, and raw-message handler.
//! - `fegrid_iec60870_tokio` — async transport over tokio (TCP,
//!   TLS, server runtime).

#![allow(missing_docs)]

pub mod plugin;

pub use fegrid_iec60870_asdu as asdu;
pub use fegrid_iec60870_core as core;
pub use fegrid_iec60870_cs101 as cs101;
pub use fegrid_iec60870_cs104 as cs104;

#[cfg(feature = "tokio")]
pub use fegrid_iec60870_tokio as tokio;

pub use plugin::{Plugin, PluginRegistry, PluginTrait};
