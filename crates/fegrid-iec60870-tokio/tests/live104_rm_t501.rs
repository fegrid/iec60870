//! Live CS 104 integration test against a real product on the lab network.
//!
//! Gated by `FEGRID_LIVE_TARGETS` (comma-separated `name=host[:port]`,
//! port defaults to [`IEC104_DEFAULT_PORT`]). When the named target is
//! absent the test prints a skip notice and exits cleanly — a passing
//! green run, not a failure. CA defaults to 1; override per-product with
//! `FEGRID_LIVE_CA`.
//!
//! Run via `just live-test` (recipe pre-fills the known target).

// live integration tests print skip notices and event traces; stdout is the report.
#![allow(clippy::print_stdout)]
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
use fegrid_iec60870_cs104::{ApciParameters, Apdu, SeqNo, UFrame};
use fegrid_iec60870_tokio::{ApduCodec, ConnEvent, IEC104_DEFAULT_PORT, session104};

const TARGET_NAME: &str = "rm_t501_gen1";

fn target_addr(name: &str) -> Option<(String, u16)> {
    let raw = std::env::var("FEGRID_LIVE_TARGETS").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    for entry in trimmed.split(',') {
        let (entry_name, rest) = match entry.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        if entry_name.trim() != name {
            continue;
        }
        let host_part = rest.trim();
        let (host, port) = match host_part.split_once(':') {
            Some((h, p)) => match p.trim().parse::<u16>() {
                Ok(port) => (h.trim().to_string(), port),
                Err(_) => {
                    eprintln!(
                        "SKIP: malformed FEGRID_LIVE_TARGETS entry \
                         \"{entry}\" (port not u16)"
                    );
                    return None;
                }
            },
            None => (host_part.to_string(), IEC104_DEFAULT_PORT),
        };
        return Some((host, port));
    }
    None
}

fn live_ca() -> u16 {
    match std::env::var("FEGRID_LIVE_CA") {
        Ok(s) => s.trim().parse::<u16>().unwrap_or(1),
        Err(_) => 1,
    }
}

fn gi_request_asdu(ca: u16) -> Asdu {
    Asdu {
        type_id: TypeId::C_IC_NA_1,
        original_type_byte: TypeId::C_IC_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(ca),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::InterrogationCommand { qoi: 20 },
        )],
    }
}

#[tokio::test]
async fn rm_t501_gen1_gi_handshake() {
    let Some((host, port)) = target_addr(TARGET_NAME) else {
        eprintln!("SKIP: {TARGET_NAME} not in FEGRID_LIVE_TARGETS");
        return;
    };

    let tcp = match timeout(
        Duration::from_secs(5),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            panic!("connect to {host}:{port} failed: {e}");
        }
        Err(_) => {
            panic!("connect to {host}:{port} timed out after 5s");
        }
    };

    let framed = Framed::new(tcp, ApduCodec::new());
    let (_session, mut framed, events) =
        session104::start_client(framed, ApciParameters::default())
            .await
            .expect("STARTDT handshake");
    assert_eq!(
        events,
        vec![ConnEvent::Opened, ConnEvent::StartDtConReceived],
        "unexpected ConnEvent sequence"
    );

    framed
        .send(Apdu::I {
            ns: SeqNo(0),
            nr: SeqNo(0),
            asdu: Some(gi_request_asdu(live_ca())),
        })
        .await
        .expect("send GI");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut saw_act_con = false;
    let mut saw_station_interrogation = false;
    let mut histogram: Vec<(TypeId, CauseOfTransmission)> = Vec::new();

    loop {
        let next = timeout_at(deadline, framed.next()).await;
        let frame = match next {
            Ok(Some(Ok(apdu))) => apdu,
            Ok(Some(Err(e))) => panic!("decode error during GI: {e}"),
            Ok(None) => panic!("product closed connection during GI"),
            Err(_) => break,
        };
        match frame {
            Apdu::I { asdu: Some(a), .. } => {
                histogram.push((a.type_id, a.cot.cause));
                if a.type_id == TypeId::C_IC_NA_1
                    && a.cot.cause == CauseOfTransmission::ActivationCon
                {
                    saw_act_con = true;
                }
                if a.cot.cause == CauseOfTransmission::StationInterrogation {
                    saw_station_interrogation = true;
                }
            }
            Apdu::U(UFrame::TestFrAct) => {
                framed
                    .send(Apdu::U(UFrame::TestFrCon))
                    .await
                    .expect("TESTFR_CON");
            }
            Apdu::U(_) | Apdu::I { asdu: None, .. } | Apdu::S { .. } => {}
        }
        if saw_act_con && saw_station_interrogation {
            break;
        }
    }

    println!(
        "live GI histogram ({histogram_len} frames): {histogram:?}",
        histogram_len = histogram.len(),
    );
    assert!(
        saw_act_con,
        "GI handshake missing ActivationCon; observed frames: {histogram:?}"
    );
    assert!(
        saw_station_interrogation,
        "GI handshake produced no StationInterrogation data; observed frames: {histogram:?}"
    );
}
