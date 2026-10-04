//! SQ-bit (sequence-of-information-objects) bounds regressions.
//!
//! These tests pin the behaviour so any future refactor that loosens
//! the bounds check trips here first.

use fegrid_iec60870_asdu::{parse_default, parse_lenient_default};

/// `M_SP_NA_1` (type 1) with SQ=1, count=2, payload truncated before the
/// base IOA. Reproducer input:
#[test]
fn short_sq_asdu_is_rejected_by_strict_parse() {
    let msg: [u8; 6] = [
        0x01, // M_SP_NA_1
        0x82, // SQ=1, count=2
        0x03, 0x00, // COT
        0x01, 0x00, // CA; no base IOA, no info element
    ];
    let err = parse_default(&msg).expect_err("strict parse must reject short SQ ASDU");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("BufferTooShort"),
        "expected BufferTooShort, got: {rendered}",
    );
}

#[test]
fn short_sq_asdu_is_rejected_by_lenient_parse() {
    let msg: [u8; 6] = [0x01, 0x82, 0x03, 0x00, 0x01, 0x00];
    let err = parse_lenient_default(&msg).expect_err("lenient parse must reject short SQ ASDU");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("BufferTooShort"),
        "expected BufferTooShort, got: {rendered}",
    );
}

/// Tightest valid SQ=1, count=2 input: header + 3-byte base IOA +
/// 1-byte info element per element (M_SP_NA_1 body length). Parses and
/// yields 2 objects with sequential IOAs.
#[test]
fn sq_asdu_with_minimal_valid_payload_parses() {
    let header_len = 1 + 1 + 2 + 2;
    let ioa = 3;
    let body = 1;
    let total = header_len + ioa + 2 * body;
    let mut msg = vec![0u8; total];
    msg[0] = 0x01; // M_SP_NA_1
    msg[1] = 0x82; // SQ=1, count=2
    msg[2] = 0x03;
    msg[3] = 0x00;
    msg[4] = 0x01;
    msg[5] = 0x00;
    msg[6] = 0x01;
    msg[7] = 0x00;
    msg[8] = 0x00;
    msg[10] = 0x00; // quality flag, object 1

    let asdu = parse_default(&msg).expect("minimal valid SQ ASDU must parse");
    assert_eq!(asdu.objects.len(), 2);
    assert_eq!(asdu.objects[0].ioa, 1);
    assert_eq!(asdu.objects[1].ioa, 2);
}

/// SQ=1, count=2 but payload missing the second body (off-by-one from the
/// short-payload case above): header + base IOA + only one body byte. The
/// iteration `i=1` rejects because the second body cannot fit.
#[test]
fn sq_asdu_missing_last_body_is_rejected() {
    let header_len = 1 + 1 + 2 + 2;
    let ioa = 3;
    let body = 1;
    let total = header_len + ioa + body;
    let mut msg = vec![0u8; total];
    msg[0] = 0x01;
    msg[1] = 0x82;
    msg[2] = 0x03;
    msg[3] = 0x00;
    msg[4] = 0x01;
    msg[5] = 0x00;
    msg[6] = 0x00;

    let err = parse_default(&msg).expect_err("SQ ASDU missing last body must reject");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("BufferTooShort"),
        "expected BufferTooShort, got: {rendered}",
    );
}

/// VSQ count=0 with SQ=1 is a valid edge case (IEC 60870-5-101 §7.2.2):
/// zero objects, no IOA bytes. Should parse cleanly.
#[test]
fn sq_asdu_with_zero_count_parses() {
    let header_len = 1 + 1 + 2 + 2;
    let mut msg = vec![0u8; header_len];
    msg[0] = 0x01;
    msg[1] = 0x80; // SQ=1, count=0
    msg[2] = 0x03;
    msg[3] = 0x00;
    msg[4] = 0x01;
    msg[5] = 0x00;

    let asdu = parse_default(&msg).expect("SQ count=0 ASDU must parse");
    assert!(asdu.is_sequence);
    assert_eq!(asdu.objects.len(), 0);
}
