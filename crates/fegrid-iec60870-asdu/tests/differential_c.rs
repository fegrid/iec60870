//! Differential wire-format tests against C reference captures.
//!
//! Captures live under `tests/fixtures/captured_c/<scenario>_<dir>.hex`,
//! one TCP segment per line, ASCII hex. Each segment is a CS 104 APDU:
//! `0x68 LEN LEN <4 control octets> [asdu...]`.
//!
//! For every I-frame, re-encode the captured ASDU through the Rust
//! implementation and assert byte-for-byte equality with the captured
//! payload. This is the strongest possible differential against the
//! field-proven C reference.
//!
//! Captures are produced by the docker harness in
//! `iec60870-cpp-sim/captures/`. Re-run with:
//!   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
//!     -v $(pwd)/iec60870-cpp-sim/captures/out:/out iec60870-csim <scenario>
//! and copy the resulting `*_<dir>.hex` files into this crate's
//! `tests/fixtures/captured_c/`.

use std::fs;
use std::path::PathBuf;

use fegrid_iec60870_asdu::encode_to_vec;
use fegrid_iec60870_core::AppLayerParameters;
use fegrid_iec60870_cs104::apci::{Apdu, parse_apdu};
use fegrid_iec60870_fixtures::FIXTURES_DIR;

/// Read every line of a captured file as one ASCII-hex byte vector.
fn read_hex_lines(rel: &str) -> Vec<Vec<u8>> {
    let mut path = PathBuf::from(FIXTURES_DIR);
    path.push("captured_c");
    path.push(rel);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.split_whitespace()
                .flat_map(|tok| {
                    let mut out: Vec<u8> = Vec::new();
                    let mut chars = tok.chars().peekable();
                    while chars.peek().is_some() {
                        let pair: String = chars.by_ref().take(2).collect();
                        if pair.len() != 2 {
                            panic!("odd hex digit in {l}");
                        }
                        out.push(u8::from_str_radix(&pair, 16).expect("hex parse"));
                    }
                    out
                })
                .collect()
        })
        .collect()
}

/// Re-encode every I-frame ASDU in `rel` and assert byte-for-byte match
/// with the captured payload bytes (after the 6-byte APCI header).
/// Returns the number of ASDUs round-tripped.
fn round_trip_every_asdu(rel: &str) -> usize {
    let params = AppLayerParameters::default();
    let lines = read_hex_lines(rel);
    let mut checked = 0usize;
    for (i, bytes) in lines.iter().enumerate() {
        let apdu = match parse_apdu(bytes) {
            Ok(a) => a,
            Err(e) => panic!(
                "{rel} line {i}: parse_apdu failed: {e} on bytes {:02x?}",
                bytes
            ),
        };
        if let Apdu::I {
            asdu: Some(asdu), ..
        } = apdu
        {
            let len = bytes[1] as usize;
            let total = len + 2;
            let captured_body = &bytes[6..total];
            let reencoded = encode_to_vec(&params, &asdu).expect("encode");
            assert_eq!(
                reencoded.as_slice(),
                captured_body,
                "{rel} line {i}: ASDU reencode mismatch\n  captured: {:02x?}\n  reencode: {:02x?}",
                captured_body,
                reencoded.as_slice(),
            );
            checked += 1;
        }
    }
    eprintln!("[{rel}] round-tripped {checked} captured ASDUs from the C reference");
    checked
}

#[test]
fn all_captured_asdus_round_trip_byte_identical_to_c_reference() {
    let dir = PathBuf::from(FIXTURES_DIR).join("captured_c");
    let mut total = 0usize;
    let mut files = 0usize;
    for entry in fs::read_dir(&dir).expect("captured_c readable") {
        let entry = entry.expect("entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".hex") {
            continue;
        }
        files += 1;
        total += round_trip_every_asdu(&name);
    }
    assert!(
        files >= 4,
        "expected at least 4 captured_c/*.hex files, got {files}",
    );
    assert!(
        total >= 30,
        "expected to round-trip at least 30 captured ASDUs from the C reference, got {total}",
    );
    eprintln!(
        "[ALL] round-tripped {total} captured ASDUs from the C reference across {files} captures"
    );
}

#[test]
fn captured_gi_neg_qoi21_pn_bit_set() {
    // qoi=21 (group 1, not station) must yield negative ACT_CON.
    let lines = read_hex_lines("gi_neg_qoi21_s2c.hex");
    let apdu = parse_apdu(&lines[1]).expect("parse ACT_CON");
    if let Apdu::I {
        asdu: Some(asdu), ..
    } = apdu
    {
        assert_eq!(asdu.type_id as u8, 100);
        assert_eq!(asdu.cot.cause as u8, 7);
        assert!(
            asdu.cot.negative_confirm,
            "qoi=21 must produce negative ACT_CON (P/N bit set)",
        );
    } else {
        panic!("second server APDU must be I-frame");
    }
}
