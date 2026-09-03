// Fuzz target: APCI parser must never panic on arbitrary bytes.

#![cfg_attr(feature = "libfuzzer", no_main)]
#![allow(dead_code)]

#[cfg(not(feature = "libfuzzer"))]
fn main() {
    // Stub: read from stdin for ad-hoc fuzzing.
    use std::io::Read;
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).unwrap();
    fuzz(&data);
}

use fegrid_iec60870_cs104::parse_apdu;

pub fn fuzz(data: &[u8]) {
    let _ = parse_apdu(data);
}
