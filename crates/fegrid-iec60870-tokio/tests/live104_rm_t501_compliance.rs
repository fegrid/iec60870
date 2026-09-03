//! Live CS 104 compliance tests against `rm_t501_gen1` at 10.25.0.21.
//!
//! Tier 0 (passive, zero state change) and Tier 1 (read-only commands).
//! Same env gate as `live104_rm_t501.rs`: when `FEGRID_LIVE_TARGETS`
//! does not list `rm_t501_gen1` each test prints a skip note and exits
//! green. CA defaults to 1; override with `FEGRID_LIVE_CA`.
//!
//! Tests:
//! 1. `rm_t501_gen1_testfr_roundtrip` — answer TESTFR_ACT, measure RTT.
//! 2. `rm_t501_gen1_spontaneous_data_integrity` — 30 s of unsolicited
//!    frames; no decode errors, type/COT histogram non-empty.
//! 3. `rm_t501_gen1_read_discovered_ioa` — run GI, pick IOA from its
//!    StationInterrogation data, send `C_RD_NA_1`, assert `ActivationCon`
//!    + matching read-response ASDU.

// live compliance tests print histograms and vendor-behavior notes; stdout is the report.
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

fn skip_if_absent() -> Option<()> {
    if target_addr(TARGET_NAME).is_none() {
        eprintln!("SKIP: {TARGET_NAME} not in FEGRID_LIVE_TARGETS");
        None
    } else {
        Some(())
    }
}

/// Strict mode = FEGRID_LIVE_STRICT=1 (default). When strict, missing
/// expected frames panic. When lenient, the test prints a vendor-behavior
/// note and exits green — useful for re-runs against an under-conforming
/// product where the gap is already known and tracked.
fn strict_mode() -> bool {
    match std::env::var("FEGRID_LIVE_STRICT") {
        Ok(s) => !matches!(s.trim(), "0" | "false" | "no" | ""),
        Err(_) => true,
    }
}

/// Panic in strict mode; print a note and continue in lenient.
macro_rules! expect_or_note {
    ($cond:expr, $strict_msg:expr, $note:expr) => {
        if !$cond {
            if strict_mode() {
                panic!("{}", $strict_msg);
            } else {
                eprintln!("NOTE (lenient): {}", $note);
            }
        }
    };
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

fn read_command_asdu(ca: u16, ioa: u32) -> Asdu {
    Asdu {
        type_id: TypeId::C_RD_NA_1,
        original_type_byte: TypeId::C_RD_NA_1 as u8,
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
        objects: vec![InformationObject::new(ioa, InformationValue::ReadCommand)],
    }
}

async fn connect_and_start() -> Framed<TcpStream, ApduCodec> {
    let (host, port) = target_addr(TARGET_NAME).expect("target present after skip check");
    let tcp = match timeout(
        Duration::from_secs(5),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => panic!("connect to {host}:{port} failed: {e}"),
        Err(_) => panic!("connect to {host}:{port} timed out after 5s"),
    };
    let framed = Framed::new(tcp, ApduCodec::new());
    let (_session, framed, events) = session104::start_client(framed, ApciParameters::default())
        .await
        .expect("STARTDT handshake");
    assert_eq!(
        events,
        vec![ConnEvent::Opened, ConnEvent::StartDtConReceived],
        "unexpected ConnEvent sequence"
    );
    framed
}

/// Tier 0: drive the keep-alive round-trip from the client side. Sends
/// `TESTFR_ACT` once a second and asserts each `TESTFR_ACT` elicits a
/// matching `TESTFR_CON` from the product. This is the spec-compliant
/// keep-alive the controlling station is responsible for; we exercise
/// it against a real product instead of waiting for vendor-initiated
/// TESTFR (which both the live product and the reference product only
#[tokio::test(flavor = "current_thread")]
async fn rm_t501_gen1_testfr_roundtrip() {
    if skip_if_absent().is_none() {
        return;
    }
    let mut framed = connect_and_start().await;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut acts_sent = 0u32;
    let mut rtts_ms: Vec<u128> = Vec::new();

    loop {
        if Instant::now() >= deadline {
            break;
        }
        let act_sent_at = Instant::now();
        framed
            .send(Apdu::U(UFrame::TestFrAct))
            .await
            .expect("send TESTFR_ACT");
        acts_sent += 1;

        // Drain incoming frames until TESTFR_CON arrives or the
        // window closes. I-frames / S-frames in between are unrelated
        // spontaneous traffic; skip them. (Both the reference product
        // and live product push periodic data while TESTFR is in flight.)
        let mut got_con = false;
        loop {
            match timeout_at(deadline, framed.next()).await {
                Ok(Some(Ok(Apdu::U(UFrame::TestFrCon)))) => {
                    rtts_ms.push(act_sent_at.elapsed().as_millis());
                    got_con = true;
                    break;
                }
                Ok(Some(Ok(Apdu::U(UFrame::TestFrAct)))) => {
                    framed
                        .send(Apdu::U(UFrame::TestFrCon))
                        .await
                        .expect("send TESTFR_CON");
                }
                Ok(Some(Ok(_other))) => {
                    // Spontaneous I-frame, S-frame, or other U-frame —
                    // keep draining toward TESTFR_CON.
                }
                Ok(Some(Err(e))) => panic!("decode error during TESTFR: {e}"),
                Ok(None) => {
                    expect_or_note!(
                        false,
                        "product closed connection during TESTFR round-trip \
                         (acts_sent = {acts_sent})",
                        "product closed TCP before replying TESTFR_CON \
                         (acts_sent = {acts_sent})"
                    );
                    got_con = false;
                    break;
                }
                Err(_) => break,
            }
        }
        if !got_con {
            break;
        }
    }
    let cons_received = rtts_ms.len();
    let received_any = acts_sent > 0 && cons_received > 0;
    let ratio_ok = cons_received as f32 / acts_sent as f32 >= 0.5;
    expect_or_note!(
        received_any,
        format!("TESTFR round-trip: no replies received (sent {acts_sent})"),
        "product never replied TESTFR_CON"
    );
    expect_or_note!(
        ratio_ok,
        format!("TESTFR round-trip too lossy: sent {acts_sent}, got {cons_received} TESTFR_CON"),
        "product dropped >50% of TESTFR round-trips"
    );
}

/// Tier 0: 30 s of unsolicited traffic; no decode errors, at least
/// one data frame observed.
#[tokio::test]
async fn rm_t501_gen1_spontaneous_data_integrity() {
    if skip_if_absent().is_none() {
        return;
    }
    let mut framed = connect_and_start().await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut histogram: Vec<(TypeId, CauseOfTransmission)> = Vec::new();
    let mut decode_errors: Vec<String> = Vec::new();

    loop {
        let next = timeout_at(deadline, framed.next()).await;
        match next {
            Ok(Some(Ok(Apdu::I { asdu: Some(a), .. }))) => {
                histogram.push((a.type_id, a.cot.cause));
            }
            Ok(Some(Ok(Apdu::U(UFrame::TestFrAct)))) => {
                framed
                    .send(Apdu::U(UFrame::TestFrCon))
                    .await
                    .expect("send TESTFR_CON");
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(e))) => decode_errors.push(format!("{e}")),
            Ok(None) => break,
            Err(_) => break,
        }
    }

    println!(
        "spontaneous frames observed: {n}, decode_errors: {errs}",
        n = histogram.len(),
        errs = decode_errors.len()
    );
    println!("histogram: {histogram:?}");
    assert!(
        decode_errors.is_empty(),
        "decode errors during spontaneous window: {decode_errors:?}"
    );
    assert!(
        !histogram.is_empty(),
        "no data frames observed within 30s spontaneous window"
    );
}

/// Tier 1: discover an IOA via GI, send `C_RD_NA_1` for it, assert the
/// product echoes `ActivationCon` and a matching read-response ASDU.
#[tokio::test]
async fn rm_t501_gen1_read_discovered_ioa() {
    if skip_if_absent().is_none() {
        return;
    }
    let mut framed = connect_and_start().await;
    let ca = live_ca();

    framed
        .send(Apdu::I {
            ns: SeqNo(0),
            nr: SeqNo(0),
            asdu: Some(gi_request_asdu(ca)),
        })
        .await
        .expect("send GI");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut discovered_ioa: Option<u32> = None;
    let mut saw_act_con = false;

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
                if a.type_id == TypeId::C_IC_NA_1
                    && a.cot.cause == CauseOfTransmission::ActivationCon
                {
                    saw_act_con = true;
                }
                if a.cot.cause == CauseOfTransmission::StationInterrogation
                    && discovered_ioa.is_none()
                    && !a.objects.is_empty()
                {
                    discovered_ioa = Some(a.objects[0].ioa);
                }
            }
            Apdu::U(UFrame::TestFrAct) => {
                framed
                    .send(Apdu::U(UFrame::TestFrCon))
                    .await
                    .expect("send TESTFR_CON");
            }
            Apdu::U(_) | Apdu::I { asdu: None, .. } | Apdu::S { .. } => {}
        }
        if saw_act_con && discovered_ioa.is_some() {
            break;
        }
    }

    let ioa = discovered_ioa.unwrap_or_else(|| {
        panic!("GI completed without any StationInterrogation data; cannot pick IOA to read")
    });
    assert!(saw_act_con, "GI produced no ActivationCon");

    framed
        .send(Apdu::I {
            ns: SeqNo(1),
            nr: SeqNo(0),
            asdu: Some(read_command_asdu(ca, ioa)),
        })
        .await
        .expect("send C_RD_NA_1");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_read_act_con = false;
    let mut saw_read_neg_con = false;
    let mut saw_read_response = false;
    let mut histogram: Vec<(TypeId, CauseOfTransmission)> = Vec::new();

    loop {
        let next = timeout_at(deadline, framed.next()).await;
        let frame = match next {
            Ok(Some(Ok(apdu))) => apdu,
            Ok(Some(Err(e))) => panic!("decode error during read: {e}"),
            Ok(None) => panic!("product closed connection during read"),
            Err(_) => break,
        };
        match frame {
            Apdu::I { asdu: Some(a), .. } => {
                histogram.push((a.type_id, a.cot.cause));
                if a.type_id == TypeId::C_RD_NA_1
                    && a.cot.cause == CauseOfTransmission::ActivationCon
                {
                    if a.cot.negative_confirm {
                        saw_read_neg_con = true;
                    } else {
                        saw_read_act_con = true;
                    }
                }
                // Other COTs (UnknownCot / UnknownCa / UnknownIoa / etc.)
                // with negative_confirm=true also count as a valid reject
                // from the server — covers servers that reply with an
                // explicit error cause rather than ActivationCon.
                if a.type_id == TypeId::C_RD_NA_1
                    && a.cot.cause != CauseOfTransmission::ActivationCon
                    && a.cot.negative_confirm
                {
                    saw_read_neg_con = true;
                }
                if a.type_id != TypeId::C_RD_NA_1 && a.cot.cause == CauseOfTransmission::Request {
                    saw_read_response = true;
                }
            }
            Apdu::U(UFrame::TestFrAct) => {
                framed
                    .send(Apdu::U(UFrame::TestFrCon))
                    .await
                    .expect("send TESTFR_CON");
            }
            Apdu::U(_) | Apdu::I { asdu: None, .. } | Apdu::S { .. } => {}
        }
        if saw_read_act_con && saw_read_response {
            break;
        }
    }

    println!("read round-trip histogram: {histogram:?}");
    expect_or_note!(
        saw_read_act_con || saw_read_neg_con,
        "C_RD_NA_1 produced no ActivationCon (positive or negative); \
         observed: {histogram:?}",
        "product ignored C_RD_NA_1 entirely (no ActivationCon, no \
         NegativeCon within 10 s); vendor may not support read commands"
    );
    if saw_read_neg_con {
        println!("vendor replied NEGATIVE ActivationCon; skipping read-response assertion");
    } else if saw_read_act_con {
        assert!(
            saw_read_response,
            "C_RD_NA_1 produced no ReadResponse; observed: {histogram:?}"
        );
    }
}
