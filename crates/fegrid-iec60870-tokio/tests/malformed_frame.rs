//! Negative-path test: malformed frames must escalate to `Malformed`.
//!
//! Verifies the tightened `ApduCodec` from G-052 — after more than the
//! configured number of consecutive non-`0x68` bytes, the decoder
//! surfaces `CodecError::Malformed` so the transport closes the
//! connection.

use bytes::BytesMut;
use tokio_util::codec::Decoder;

use fegrid_iec60870_cs104::Apdu;
use fegrid_iec60870_tokio::codec104::{ApduCodec, CodecError};

#[test]
fn resync_then_recover() {
    // A few stray bytes followed by a valid TESTFR ACT should resync
    // without raising `Malformed`.
    let mut codec = ApduCodec::with_resync_tolerance(16);
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0x00u8, 0x01, 0x02, 0x03]);
    // 4 drops in a row — still below tolerance.
    for _ in 0..4 {
        let res = codec.decode(&mut buf);
        assert!(matches!(res, Ok(None)));
    }
    // Append a TESTFR_ACT U-frame.
    let frame = Apdu::U(fegrid_iec60870_cs104::UFrame::TestFrAct);
    let bytes = fegrid_iec60870_tokio::apdu_to_wire(&frame);
    eprintln!("appending bytes: {bytes:?}");
    buf.extend_from_slice(&bytes);
    // Loop until a frame arrives — there may still be a stray drop byte
    // from the previous garbage run.
    let apdu = loop {
        match codec.decode(&mut buf) {
            Ok(Some(a)) => break a,
            Ok(None) => continue,
            Err(e) => panic!("decode error: {e}"),
        }
    };
    assert!(matches!(apdu, Apdu::U(_)));
}
#[test]
fn too_many_drops_raises_malformed() {
    // 17 garbage bytes in a row with no 0x68 — codec must surface
    // Malformed once the drop count exceeds the tolerance (16).
    let mut codec = ApduCodec::with_resync_tolerance(16);
    let mut buf = BytesMut::from(&[0xAAu8; 17][..]);
    // First 16 drops are tolerated (Ok(None)).
    for _ in 0..16 {
        let res = codec.decode(&mut buf);
        assert!(matches!(res, Ok(None)));
    }
    // 17th drop overshoots the budget — error returned.
    let res = codec.decode(&mut buf);
    assert!(
        matches!(res, Err(CodecError::Malformed { .. })),
        "expected Malformed, got {res:?}"
    );
}

#[test]
fn counter_resets_after_successful_frame() {
    // A successful APDU between two garbage runs must reset the counter.
    let mut codec = ApduCodec::with_resync_tolerance(4);
    let mut buf = BytesMut::new();
    // First garbage run: 3 bytes (under tolerance).
    buf.extend_from_slice(&[0x99, 0x99, 0x99]);
    for _ in 0..3 {
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
    }
    // Valid TESTFR ACT.
    buf.extend_from_slice(&[0x68, 0x04, 0x43, 0x00, 0x00, 0x00]);
    let apdu = loop {
        match codec.decode(&mut buf) {
            Ok(Some(a)) => break a,
            Ok(None) => continue,
            Err(e) => panic!("decode error: {e}"),
        }
    };
    assert!(matches!(apdu, Apdu::U(_)));
    assert!(buf.is_empty());
    // Second garbage run: another 4 bytes (under the post-reset tolerance).
    buf.extend_from_slice(&[0x77, 0x77, 0x77, 0x77]);
    for _ in 0..4 {
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
    }
}
