// Fuzz target: FT 1.2 frame parser must never panic on adversarial input.

#![cfg_attr(feature = "libfuzzer", no_main)]
#![allow(dead_code)]

#[cfg(not(feature = "libfuzzer"))]
fn main() {
    use std::io::Read;
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).unwrap();
    fuzz(&data);
}

use fegrid_iec60870_core::AddressLen;
use fegrid_iec60870_cs101::ft12::parse_one;

pub fn fuzz(data: &[u8]) {
    let _ = parse_one(data, AddressLen::Two);
    let _ = parse_one(data, AddressLen::One);
}
