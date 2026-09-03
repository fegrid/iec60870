//! Tokio-native CS 104 demo: server task + client task running a real
//! STARTDT handshake + general-interrogation round trip over a loopback
//! TCP socket. Tokio-only — no background threads, no C library.
//!
//! Run with:
//!
//! ```text
//! cargo run -p fegrid-iec60870-tokio --example cs104_async_demo --offline
//! ```

// println! is the example's intended output (run-by-hand demo, no tracing).
#![allow(clippy::print_stdout)]
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{
    Asdu, DispatchEvent, InformationObject, InformationValue, activation_confirm,
    activation_termination, classify,
};
use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
use fegrid_iec60870_cs104::{ApciParameters, Apdu, SeqNo};
use fegrid_iec60870_tokio::{ApduCodec, ConnEvent, session104};
fn gi_request_asdu() -> Asdu {
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
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::InterrogationCommand { qoi: 20 },
        )],
    }
}

fn data_asdu(type_id: TypeId, asdu_value: InformationValue) -> Asdu {
    Asdu {
        type_id,
        original_type_byte: type_id as u8,
        cot: CotField {
            cause: CauseOfTransmission::StationInterrogation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(0x000100, asdu_value)],
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    println!("[BOOT] listening on {addr}");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let framed = Framed::new(tcp, ApduCodec::new());
        let (_session, mut framed, events) =
            session104::start_server(framed, ApciParameters::default())
                .await
                .expect("start_server");
        for e in &events {
            let _: ConnEvent = *e;
            println!("[EVENT] {e:?}");
        }

        let apdu = framed.next().await.expect("gi req frame").expect("gi req");
        let (req, peer_ns) = match apdu {
            Apdu::I {
                ns, asdu: Some(a), ..
            } => (a, ns),
            other => panic!("expected I-frame with ASDU, got {other:?}"),
        };
        assert_eq!(
            classify(&req),
            DispatchEvent::GeneralInterrogation { qoi: 20 }
        );

        let replies = [
            activation_confirm(&req),
            data_asdu(
                TypeId::M_SP_NA_1,
                InformationValue::SinglePoint {
                    value: true,
                    quality: Default::default(),
                },
            ),
            data_asdu(
                TypeId::M_ME_NB_1,
                InformationValue::MeasuredScaled {
                    value: 42,
                    quality: Default::default(),
                },
            ),
            activation_termination(&req),
        ];
        for (i, asdu) in replies.into_iter().enumerate() {
            let frame = Apdu::I {
                ns: SeqNo(i as u16),
                nr: peer_ns,
                asdu: Some(asdu),
            };
            framed.send(frame).await.expect("send reply");
        }
    });

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let framed = Framed::new(tcp, ApduCodec::new());
    let (_session, mut framed, events) =
        session104::start_client(framed, ApciParameters::default())
            .await
            .expect("start_client");
    for e in &events {
        let _: ConnEvent = *e;
        println!("[EVENT] {e:?}");
    }

    framed
        .send(Apdu::I {
            ns: SeqNo(0),
            nr: SeqNo(0),
            asdu: Some(gi_request_asdu()),
        })
        .await
        .expect("send GI");

    for _ in 0..4 {
        let frame = framed
            .next()
            .await
            .expect("reply frame")
            .expect("reply frame");
        if let Apdu::I { asdu: Some(a), .. } = frame {
            println!("[RX] type_id={:?} cot.cause={:?}", a.type_id, a.cot.cause);
        } else {
            panic!("expected I-frame with ASDU, got {frame:?}");
        }
    }

    server.await.expect("server join");
    println!("[DONE] GI round trip completed");
}
