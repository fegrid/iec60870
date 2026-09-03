//! Loopback coverage for [`fegrid_iec60870_tokio::session104`]: a
//! STARTDT handshake and full general-interrogation round trip over a
//! real TCP socket, plus the t1 STARTDT timeout.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{
    Asdu, DispatchEvent, InformationObject, InformationValue, activation_confirm,
    activation_termination, classify,
};
use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
use fegrid_iec60870_cs104::{ApciParameters, Apdu, SeqNo};
use fegrid_iec60870_tokio::{ApduCodec, ConnEvent, Session104Error, session104};

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

fn measured_scaled_asdu(ioa: u32) -> Asdu {
    Asdu {
        type_id: TypeId::M_ME_NB_1,
        original_type_byte: TypeId::M_ME_NB_1 as u8,
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
        objects: vec![InformationObject::new(
            ioa,
            InformationValue::MeasuredScaled {
                value: 42,
                quality: Default::default(),
            },
        )],
    }
}

fn single_point_asdu(ioa: u32) -> Asdu {
    Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: TypeId::M_SP_NA_1 as u8,
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
        objects: vec![InformationObject::new(
            ioa,
            InformationValue::SinglePoint {
                value: true,
                quality: Default::default(),
            },
        )],
    }
}

async fn assert_frame(
    label: &str,
    want_type: TypeId,
    want_cot: CauseOfTransmission,
    frame: Apdu,
    stream: &mut Framed<TcpStream, ApduCodec>,
) {
    match frame {
        Apdu::I { asdu: Some(a), .. } => {
            assert_eq!(a.type_id, want_type, "type id for {label}");
            assert_eq!(a.cot.cause, want_cot, "COT for {label}");
            if want_type == TypeId::M_SP_NA_1 {
                assert_eq!(
                    a.objects[0].value,
                    InformationValue::SinglePoint {
                        value: true,
                        quality: Default::default()
                    },
                    "single-point value for {label}",
                );
            }
            let _ = stream; // silence unused-warn if changed
        }
        other => panic!("{label}: expected I-frame with ASDU, got {other:?}"),
    }
}

#[tokio::test]
async fn async_gi_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Server task: accept one TCP connection, run STARTDT server-side,
    // then read the GI request I-frame and reply in the canonical
    // order: ACTIVATION_CON -> data ASDUs -> ACTIVATION_TERMINATION.
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let framed = Framed::new(tcp, ApduCodec::new());
        let (_session, mut framed, events) =
            session104::start_server(framed, ApciParameters::default())
                .await
                .expect("start_server");
        assert_eq!(
            events,
            vec![ConnEvent::Opened, ConnEvent::StartDtConReceived]
        );

        let apdu = framed.next().await.expect("gi req frame").expect("gi req");
        let (req, peeer_ns) = match apdu {
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
            single_point_asdu(0x000100),
            measured_scaled_asdu(110),
            activation_termination(&req),
        ];
        for (i, asdu) in replies.into_iter().enumerate() {
            let frame = Apdu::I {
                ns: SeqNo(i as u16),
                nr: peeer_ns,
                asdu: Some(asdu),
            };
            framed.send(frame).await.expect("send reply");
        }
    });

    // Client task: connect, run STARTDT client-side, send a GI request,
    // then read 4 reply frames in order.
    let client_tcp = TcpStream::connect(addr).await.expect("connect");
    let framed = Framed::new(client_tcp, ApduCodec::new());
    let (_session, mut framed, events) =
        session104::start_client(framed, ApciParameters::default())
            .await
            .expect("start_client");
    assert_eq!(
        events,
        vec![ConnEvent::Opened, ConnEvent::StartDtConReceived]
    );

    framed
        .send(Apdu::I {
            ns: SeqNo(0),
            nr: SeqNo(0),
            asdu: Some(gi_request_asdu()),
        })
        .await
        .expect("send GI");

    let f1 = framed.next().await.expect("f1").expect("f1");
    assert_frame(
        "ActivationCon",
        TypeId::C_IC_NA_1,
        CauseOfTransmission::ActivationCon,
        f1,
        &mut framed,
    )
    .await;
    let f2 = framed.next().await.expect("f2").expect("f2");
    assert_frame(
        "M_SP_NA_1",
        TypeId::M_SP_NA_1,
        CauseOfTransmission::StationInterrogation,
        f2,
        &mut framed,
    )
    .await;
    let f3 = framed.next().await.expect("f3").expect("f3");
    assert_frame(
        "M_ME_NB_1",
        TypeId::M_ME_NB_1,
        CauseOfTransmission::StationInterrogation,
        f3,
        &mut framed,
    )
    .await;
    let f4 = framed.next().await.expect("f4").expect("f4");
    assert_frame(
        "ActivationTermination",
        TypeId::C_IC_NA_1,
        CauseOfTransmission::ActivationTermination,
        f4,
        &mut framed,
    )
    .await;

    server.await.expect("server join");
}

#[tokio::test]
async fn startdt_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        let (_tcp, _) = listener.accept().await.expect("accept");
        // Hold the socket open, never frame anything.
        sleep(Duration::from_secs(60)).await;
    });

    let client_tcp = TcpStream::connect(addr).await.expect("connect");
    let framed = Framed::new(client_tcp, ApduCodec::new());
    let params = ApciParameters {
        t1_ms: 100,
        ..ApciParameters::default()
    };
    let result = session104::start_client(framed, params).await;
    match result {
        Err(Session104Error::StartDtTimeout) => {}
        Err(other) => panic!("expected StartDtTimeout, got {other:?}"),
        Ok(_) => panic!("expected StartDtTimeout error, got Ok"),
    }

    server.abort();
    let _ = server.await;
}
#[tokio::test]
async fn stopdt_round_trip() {
    use fegrid_iec60870_tokio::session104::{start_client, start_server, stop_client, stop_server};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let framed = Framed::new(tcp, ApduCodec::new());
        let params = ApciParameters::default();
        let (_started, framed, _events) = start_server(framed, params).await.expect("startdt");
        // Run stop_server to await STOPDT_ACT and reply STOPDT_CON.
        let (_stopped, _framed, events) = stop_server(framed, _started).await.expect("stop_server");
        assert!(events.contains(&ConnEvent::StopDtConReceived));
    });

    let client_tcp = TcpStream::connect(addr).await.expect("connect");
    let framed = Framed::new(client_tcp, ApduCodec::new());
    let params = ApciParameters::default();
    let (started, framed, _events) = start_client(framed, params).await.expect("startdt");
    let (_stopped, _framed, events) = stop_client(framed, started).await.expect("stop_client");
    assert!(events.contains(&ConnEvent::StopDtConReceived));

    server.await.expect("server");
}
