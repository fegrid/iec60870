//! Shared golden fixtures for fegrid-iec60870 conformance + app tests.
//!
//! Tests embed the absolute path to this crate's `tests/fixtures/` directory
//! at compile time, so consumers build paths via
//! `PathBuf::from(fegrid_iec60870_fixtures::FIXTURES_DIR).join("...")` without
//! any runtime indirection.

/// Absolute path to the shared fixtures directory, baked at compile time.
pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
