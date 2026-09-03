//! Minimal CS 104 slave demo: parse a STARTDT_ACT frame from stdin hex
//! and print whether the handshake would complete.
//!
//! ```text
//! echo "68 04 07 00 00 00" | cargo run -p fegrid-iec60870-tokio --example echo_slave
//! ```

// stdout is the example's intended output (one-shot demo).
#![allow(clippy::print_stdout)]
use std::io::Read;

use fegrid_iec60870_cs104::apci::{Apdu, parse_apdu};

fn main() {
    let mut hex = String::new();
    std::io::stdin().read_to_string(&mut hex).expect("stdin");
    let bytes = parse_hex(&hex);
    match parse_apdu(&bytes) {
        Ok(Apdu::U(u)) => println!("u-frame: {u:?}"),
        Ok(other) => println!("non-u-frame: {other:?}"),
        Err(e) => println!("parse error: {e}"),
    }
}

fn parse_hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .filter_map(|t| u8::from_str_radix(t, 16).ok())
        .collect()
}
