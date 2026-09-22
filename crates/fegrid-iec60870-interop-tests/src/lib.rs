//! IEC 60870-5 interop property tests: pure data, no business logic.
//!
//! Companion to `tests/integration.rs`. Exists so the crate has a
//! `lib` target. Every static property assertion lives in the
//! integration test binary; this file only re-exports a couple of
//! helpers used by the test body.

#![allow(dead_code)]

/// Cause-of-transmission wire byte sequence (1..=47) per IEC
/// 60870-5-101 §7.4.3. Used by the COT round-trip tests.
pub const COT_WIRE_BYTES: &[u8] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 44, 45, 46, 47,
];
