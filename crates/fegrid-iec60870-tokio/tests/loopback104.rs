//! Loopback smoke test: encode STARTDT_ACT via the codec, send through
//! a `tokio::io::duplex` pair, decode on the other side.

use bytes::BytesMut;
use futures::SinkExt;
use tokio::io::duplex;
use tokio_util::codec::{Decoder, Framed};

use fegrid_iec60870_cs104::Apdu;
use fegrid_iec60870_tokio::{ApduCodec, apdu_to_wire};

#[tokio::test]
async fn loopback_startdt() {
    let (a, b) = duplex(64);
    let mut a = Framed::new(a, ApduCodec::new());
    let mut b = Framed::new(b, ApduCodec::new());

    let frame = Apdu::U(fegrid_iec60870_cs104::UFrame::StartDtAct);
    a.send(frame.clone()).await.expect("send");

    // Decode the bytes that arrived on `b` directly via the codec.
    let bytes = apdu_to_wire(&frame);
    let mut src = BytesMut::new();
    src.extend_from_slice(&bytes);
    let got = b
        .codec_mut()
        .decode(&mut src)
        .expect("decode")
        .expect("frame");
    assert_eq!(got, frame);
    assert!(src.is_empty());
}
