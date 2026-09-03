// Fuzz target: ASDU parser round-trip must never panic.

#![cfg_attr(feature = "libfuzzer", no_main)]

#[cfg(not(feature = "libfuzzer"))]
fn main() -> std::io::Result<()> {
    use std::io::Read;
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;
    fuzz(&data);
    Ok(())
}

use fegrid_iec60870_asdu::{encode_to_vec, parse_default, parse_lenient_default};
use fegrid_iec60870_core::AppLayerParameters;

pub fn fuzz(data: &[u8]) {
    round_trip_preserves_type_byte(data);
    lenient_parse_never_panics(data);
}

/// Strict parse -> encode -> re-parse must preserve the original type byte.
/// Returns silently on parse/encode failure (not all inputs are valid ASDUs).
fn round_trip_preserves_type_byte(data: &[u8]) {
    let Ok(parsed) = parse_default(data) else { return };
    let Ok(re_bytes) = encode_to_vec(&AppLayerParameters::default(), &parsed) else { return };
    let Ok(re_parsed) = parse_default(&re_bytes) else { return };
    debug_assert_eq!(parsed.original_type_byte, re_parsed.original_type_byte);
}

fn lenient_parse_never_panics(data: &[u8]) {
    let _ = parse_lenient_default(data);
}