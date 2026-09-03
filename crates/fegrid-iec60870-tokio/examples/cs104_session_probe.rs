//! Standalone CS 104 session-level probe.
//!
//! Drives a tokio CS 104 server (raw `TcpListener` + `session104`)
//! and a tokio CS 104 client on the same event loop, runs a full
//! STARTDT -> GI -> STOPDT exchange, and prints one `[probe] ...`
//! line per step. Exits 0 on PASS and non-zero on the first missed
//! step.
//!
//! Run with:
//!
//! ```text
//! cargo run --example cs104_session_probe -p fegrid-iec60870-tokio
//! ```

#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::print_stdout)]

use std::net::SocketAddr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{
    Asdu, InformationObject, InformationValue, activation_confirm, classify,
};
use fegrid_iec60870_core::{
    CauseOfTransmission, CommonAddress, CotField, QualifierOfInterrogation, TypeId,
};
use fegrid_iec60870_cs104::typestate::SessionError;
use fegrid_iec60870_cs104::{ApciParameters, Apdu, SeqNo};
use fegrid_iec60870_tokio::{
    ApduCodec, ConnEvent, Session104Error, session104, start_client, stop_client, stop_server,
};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

type Err = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("[probe] FAIL: {e}");
        std::process::exit(1);
    }
    println!("[probe] PASS");
}

async fn run() -> Result<(), Err> {
    // 1. Bind raw listener on ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    println!("[probe] bind {addr}");

    // 2. Spawn server task: STARTDT -> receive GI -> reply ACTIVATION_CON
    //    -> STOPDT.
    let server = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await?;
        let framed = Framed::new(tcp, ApduCodec::new());
        let params = ApciParameters::default();

        // Server-side STARTDT.
        let (started, mut framed, _events) = session104::start_server(framed, params).await?;

        // Await GI request I-frame.
        let apdu = framed
            .next()
            .await
            .ok_or_else(|| -> Err { "stream closed before GI".into() })??;
        let (asdu, peer_ns) = match apdu {
            Apdu::I {
                ns, asdu: Some(a), ..
            } => (a, ns),
            other => {
                return Err::<(), Err>(format!("expected GI I-frame, got {other:?}").into());
            }
        };
        if !matches!(
            classify(&asdu),
            fegrid_iec60870_asdu::DispatchEvent::GeneralInterrogation { qoi: 20 }
        ) {
            return Err::<(), Err>(
                format!("expected general_interrogation qoi=20, got {asdu:?}").into(),
            );
        }

        // Reply ACTIVATION_CON.
        let con = activation_confirm(&asdu);
        framed
            .send(Apdu::I {
                ns: SeqNo(0),
                nr: peer_ns,
                asdu: Some(con),
            })
            .await?;

        // Server-side STOPDT: await STOPDT_ACT, reply STOPDT_CON.
        let (_stopped, _framed, _stop_events) = stop_server(framed, started).await?;
        Ok(())
    });

    // 3. Client task: STARTDT -> send GI -> read ACTIVATION_CON -> STOPDT.
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let framed = Framed::new(tcp, ApduCodec::new());
    let (session, mut framed, events) = start_client(framed, ApciParameters::default()).await?;
    println!("[probe] connect");
    require_event(&events, ConnEvent::StartDtConReceived, "startdt_con")?;
    println!("[probe] startdt_con");

    let gi = Asdu {
        type_id: TypeId::C_IC_NA_1,
        original_type_byte: TypeId::C_IC_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::interrogation_command(QualifierOfInterrogation(20)),
        )],
    };
    framed
        .send(Apdu::I {
            ns: SeqNo(0),
            nr: SeqNo(0),
            asdu: Some(gi),
        })
        .await?;

    let apdu = timeout(STEP_TIMEOUT, framed.next())
        .await
        .map_err(|_| Session104Error::StartDtTimeout)?
        .ok_or(Session104Error::Protocol(SessionError::Protocol(
            "stream closed before activation confirmation",
        )))??;
    let asdu = require_act_con(&apdu)?;
    println!(
        "[probe] act_con (type_id={:?} cot={:?})",
        asdu.type_id, asdu.cot.cause
    );

    let (_stopped, _framed, stop_events) = stop_client(framed, session).await?;
    require_event(&stop_events, ConnEvent::StopDtConReceived, "stopdt_con")?;
    println!("[probe] stopdt_con");

    let _ = server.await?;
    Ok(())
}

fn require_event(events: &[ConnEvent], want: ConnEvent, label: &str) -> Result<(), Err> {
    if events.contains(&want) {
        Ok(())
    } else {
        Err(format!("missing {label} event").into())
    }
}

fn require_act_con(apdu: &Apdu) -> Result<&Asdu, Err> {
    match apdu {
        Apdu::I {
            asdu: Some(asdu), ..
        } if asdu.type_id == TypeId::C_IC_NA_1
            && asdu.cot.cause == CauseOfTransmission::ActivationCon =>
        {
            Ok(asdu)
        }
        other => Err(format!("expected ACTIVATION_CON I-frame, got {other:?}").into()),
    }
}
