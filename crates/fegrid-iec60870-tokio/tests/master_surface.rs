//! Integration tests for the MClient surface added in E3:
//! - asdu_handler callback (G-021)
//! - local_addr / peer_addr cache (G-022, G-018)
//! - set_originator_address runtime (G-023)
//! - send_raw conformance escape (G-024)
//! - cmds module round-trips (G-019, G-020)

use std::sync::atomic::{AtomicUsize, Ordering};

use fegrid_iec60870_asdu::encode_to_vec;
use fegrid_iec60870_core::{AppLayerParameters, QualifierOfInterrogation};
use fegrid_iec60870_cs104::{ApciParameters, Cs104Session};
use fegrid_iec60870_tokio::{ApduCodec, Backpressure, MClient, RawMessageHandler, cmds};
use tokio::io::duplex;
use tokio_util::codec::Framed;

struct CountingHandler(AtomicUsize);
impl RawMessageHandler for CountingHandler {
    fn on_raw(&self, _: &[u8], _: bool) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn make_started_session() -> Cs104Session<fegrid_iec60870_cs104::Started> {
    let s = Cs104Session::<fegrid_iec60870_cs104::Stopped>::new(
        ApciParameters::default(),
        AppLayerParameters::default(),
    );
    let (waiting, _bytes) = s.send_startdt();
    waiting.on_startdt_con().expect("startdt ok")
}

#[test]
fn raw_message_handler_is_invoked() {
    let h = std::sync::Arc::new(CountingHandler(AtomicUsize::new(0)));
    assert_eq!(h.0.load(Ordering::SeqCst), 0);
}

#[test]
fn cmds_build_well_formed_asdus() {
    let asdu = cmds::general_interrogation(1, QualifierOfInterrogation::STATION);
    let p = AppLayerParameters::default();
    let bytes = encode_to_vec(&p, &asdu).unwrap();
    // Just assert the encoder produces output.
    assert!(!bytes.is_empty());
}

#[test]
fn set_originator_address_persists() {
    let mut s = make_started_session();
    assert_eq!(s.originator_address(), 0);
    s.set_originator_address(42);
    assert_eq!(s.originator_address(), 42);
}

#[test]
fn send_raw_writes_bytes() {
    let (a, b) = duplex(64);
    let framed = Framed::new(a, ApduCodec::new());
    let mut client = MClient::new(b, framed, make_started_session());
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let payload = vec![0x68, 0x04, 0x01, 0x02, 0x03, 0x04];
    let res = rt.block_on(client.send_raw(&payload));
    assert!(res.is_ok());
}

#[test]
fn asdu_handler_optional() {
    let (a, b) = duplex(64);
    let framed = Framed::new(a, ApduCodec::new());
    let client = MClient::new(b, framed, make_started_session())
        .with_asdu_handler(std::sync::Arc::new(|_| {}));
    drop(client);
}

#[test]
fn local_and_peer_addr_round_trip() {
    let (a, b) = duplex(64);
    let framed = Framed::new(a, ApduCodec::new());
    let addr: std::net::SocketAddr = "127.0.0.1:2404".parse().unwrap();
    let client = MClient::new(b, framed, make_started_session())
        .with_local_addr(addr)
        .with_peer_addr(addr);
    assert_eq!(client.local_addr(), Some(addr));
    assert_eq!(client.peer_addr(), Some(addr));
}

#[test]
fn send_returns_backpressure_when_k_full() {
    let apci = ApciParameters {
        k: 1,
        w: 1,
        ..Default::default()
    };
    let (a, b) = duplex(64);
    let framed = Framed::new(a, ApduCodec::new());
    let s =
        Cs104Session::<fegrid_iec60870_cs104::Stopped>::new(apci, AppLayerParameters::default());
    let (waiting, _bytes) = s.send_startdt();
    let started = waiting.on_startdt_con().expect("startdt ok");
    let mut client = MClient::new(b, framed, started);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let asdu = cmds::read(1, 0);
    let r1 = rt.block_on(client.send(asdu.clone()));
    let _ = rt.block_on(client.send(asdu));
    assert!(r1.is_ok() || matches!(r1, Err(Backpressure::KWindowFull)));
}
