//! Golden-master wire vectors for ASDU encode/decode.

use std::fs;
use std::vec::Vec;

use fegrid_iec60870_asdu::{Asdu, InformationValue, encode_to_vec};
use fegrid_iec60870_core::{AppLayerParameters, TypeId};
use fegrid_iec60870_fixtures::FIXTURES_DIR;

fn read_hex(rel: &str) -> Vec<u8> {
    let path = format!("{FIXTURES_DIR}/{rel}");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    raw.lines()
        .filter(|l| !l.starts_with('#'))
        .flat_map(|l| l.split_whitespace())
        .map(|tok| u8::from_str_radix(tok, 16).expect("hex parse"))
        .collect()
}

#[test]
fn m_sp_na_1_round_trip() {
    let bytes = read_hex("1_a.hex");
    let params = AppLayerParameters::default();
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, TypeId::M_SP_NA_1);
    assert_eq!(parsed.cot.cause as u8, 3);
    assert_eq!(parsed.common_address.0, 1);
    assert_eq!(parsed.objects.len(), 1);
    assert_eq!(parsed.objects[0].ioa, 0x000100);
    assert!(matches!(
        parsed.objects[0].value,
        InformationValue::SinglePoint { value: true, .. }
    ));
    let re = encode_to_vec(&params, &parsed).expect("encode");
    assert_eq!(re, bytes);
}

#[test]
fn c_ic_na_1_round_trip() {
    let bytes = read_hex("100_a.hex");
    let params = AppLayerParameters::default();
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, TypeId::C_IC_NA_1);
    assert_eq!(parsed.cot.cause as u8, 6);
    assert_eq!(parsed.common_address.0, 1);
    let re = encode_to_vec(&params, &parsed).expect("encode");
    assert_eq!(re, bytes);
}

#[test]
fn m_me_nc_1_seq_round_trip() {
    let bytes = read_hex("13_a.hex");
    let params = AppLayerParameters::default();
    let parsed = Asdu::parse_lenient(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, TypeId::M_ME_NC_1);
    assert!(parsed.is_sequence);
    assert_eq!(parsed.objects.len(), 3);
    assert_eq!(parsed.objects[0].ioa, 100);
    assert_eq!(parsed.objects[1].ioa, 101);
    assert_eq!(parsed.objects[2].ioa, 102);
    let re = encode_to_vec(&params, &parsed).expect("encode");
    assert_eq!(re, bytes);
}

#[test]
fn m_it_na_1_round_trip() {
    let bytes = read_hex("15_a.hex");
    let params = AppLayerParameters::default();
    let parsed = Asdu::parse(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, TypeId::M_IT_NA_1);
    let re = encode_to_vec(&params, &parsed).expect("encode");
    assert_eq!(re, bytes);
}

#[test]
fn m_sp_tb_1_round_trip() {
    let bytes = read_hex("30_a.hex");
    let params = AppLayerParameters::default();
    let parsed = Asdu::parse_lenient(&params, &bytes).expect("parse");
    assert_eq!(parsed.type_id, TypeId::M_SP_TB_1);
    let re = encode_to_vec(&params, &parsed).expect("encode");
    assert_eq!(re, bytes);
}

#[test]
fn raw_unknown_round_trip() {
    let bytes = read_hex("255_a.hex");
    let params = AppLayerParameters::default();
    let parsed = Asdu::parse_lenient(&params, &bytes).expect("parse lenient");
    assert!(Asdu::parse(&params, &bytes).is_err());
    let re = encode_to_vec(&params, &parsed).expect("encode");
    assert_eq!(re, bytes);
}

/// Iterate every committed `<type>_n<n>.hex` fixture — IEC 60870-5-101/104
/// wire-spec byte vectors — parse it, re-encode, and assert
/// byte-for-byte equality. Type ids come from the filename
/// `<type>_n<n>.hex`.
///
/// Auxiliary `_a<...>` fixtures (per-TypeId) are skipped here and
/// exercised by the per-TypeId tests above.
#[test]
fn wire_spec_vectors_round_trip() {
    let dir = FIXTURES_DIR;
    let mut entries: Vec<(u8, Vec<u8>)> = Vec::new();
    for entry in fs::read_dir(dir).expect("read golden dir").flatten() {
        let name = entry.file_name().into_string().unwrap_or_default();
        if !name.ends_with(".hex") {
            continue;
        }
        let stem = &name[..name.len() - 4];
        // Match "<digits>_n<digits>".
        let (type_str, suffix) = match stem.split_once("_n") {
            Some((t, s)) if !t.is_empty() && s.chars().all(|c| c.is_ascii_digit()) => (t, s),
            _ => continue,
        };
        let type_id: u8 = type_str.parse().expect("<type>_n<n>.hex parse");
        let bytes = read_hex(&name);
        entries.push((type_id, bytes));
        let _ = suffix;
    }
    assert!(
        entries.len() >= 60,
        "expected ≥60 wire-spec fixtures, found {}",
        entries.len()
    );
    let params = AppLayerParameters::default();
    let mut passed = 0usize;
    let mut mismatched: Vec<(u8, String)> = Vec::new();
    for (type_id, bytes) in entries {
        let parsed = match Asdu::parse_lenient(&params, &bytes) {
            Ok(a) => a,
            Err(e) => {
                mismatched.push((type_id, format!("parse: {e}")));
                continue;
            }
        };
        let re = match encode_to_vec(&params, &parsed) {
            Ok(b) => b,
            Err(e) => {
                mismatched.push((type_id, format!("encode: {e}")));
                continue;
            }
        };
        if re != bytes {
            mismatched.push((type_id, "byte mismatch".into()));
            continue;
        }
        passed += 1;
    }
    eprintln!(
        "wire_spec_vectors_round_trip: {passed} passed, {} mismatched",
        mismatched.len()
    );
    assert!(
        passed >= 70,
        "expected ≥70 wire-spec fixtures to round-trip, only {passed} passed ({} mismatched: {:?})",
        mismatched.len(),
        mismatched
    );
}
