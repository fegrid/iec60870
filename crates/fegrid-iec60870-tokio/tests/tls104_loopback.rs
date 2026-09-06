//! TLS-104 loopback: STARTDT_ACT/CON + an I-frame round-trip through a
//! genuine TLS handshake.  Self-signed certs are minted at runtime via
//! `rcgen` so no fixtures are committed.

extern crate alloc;

use alloc::vec;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
use fegrid_iec60870_cs104::{Apdu, SeqNo, UFrame};
use fegrid_iec60870_tokio::tls104::{
    Tls104Acceptor, Tls104Connector, TlsClientConfig, TlsError, TlsIdentity, TlsServerConfig,
    TlsTrustRoots,
};

fn self_signed() -> (String, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert = ck.cert.pem();
    let key_pem = ck.signing_key.serialize_pem();
    (cert, key_pem)
}

fn sample_asdu() -> Asdu {
    Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: TypeId::M_SP_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0x000100,
            InformationValue::SinglePoint {
                value: true,
                quality: Default::default(),
            },
        )],
    }
}

#[tokio::test]
async fn tls_startdt_and_iframe_loopback() {
    let (cert_pem, key_pem) = self_signed();
    let identity = TlsIdentity::from_pem(&cert_pem, &key_pem).expect("identity");
    let server_cfg = TlsServerConfig::new(identity);
    let acceptor = Tls104Acceptor::new(&server_cfg).expect("acceptor");

    let trust = TlsTrustRoots::from_pem(&cert_pem).expect("trust");
    let client_cfg = TlsClientConfig::new(trust);
    let connector = Tls104Connector::new(&client_cfg, "localhost").expect("connector");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await.expect("accept");
        let mut stream = acceptor.accept(tcp).await.expect("tls accept");

        let first = stream.next().await.expect("first frame").expect("frame");
        assert_eq!(first, Apdu::U(UFrame::StartDtAct));
        stream
            .send(Apdu::U(UFrame::StartDtCon))
            .await
            .expect("send StartDtCon");

        let second = stream.next().await.expect("second frame").expect("frame");
        match &second {
            Apdu::I {
                asdu: Some(asdu), ..
            } => {
                let snapshot = asdu.clone();
                stream.send(second).await.expect("echo I-frame");
                snapshot
            }
            other => panic!("expected I-frame with ASDU, got {other:?}"),
        }
    });

    let mut client = connector.connect(addr).await.expect("connect");
    client
        .send(Apdu::U(UFrame::StartDtAct))
        .await
        .expect("send StartDtAct");
    let con = client.next().await.expect("con").expect("con");
    assert_eq!(con, Apdu::U(UFrame::StartDtCon));

    let sent = sample_asdu();
    let iframe = Apdu::I {
        ns: SeqNo(0),
        nr: SeqNo(0),
        asdu: Some(sent.clone()),
    };
    client.send(iframe).await.expect("send I-frame");

    let echoed = client.next().await.expect("echoed").expect("echoed");
    match echoed {
        Apdu::I {
            asdu: Some(asdu), ..
        } => assert_eq!(asdu, sent),
        other => panic!("expected echoed I-frame with ASDU, got {other:?}"),
    }

    let _ = server.await.expect("server task");
}

#[tokio::test]
async fn bad_root_rejected() {
    // Server gets its own self-signed cert.
    let (server_cert, server_key) = self_signed();
    let server_identity = TlsIdentity::from_pem(&server_cert, &server_key).expect("server id");
    let server_cfg = TlsServerConfig::new(server_identity);
    let acceptor = Tls104Acceptor::new(&server_cfg).expect("acceptor");

    // Client trusts a completely unrelated self-signed CA.
    let (other_cert, _other_key) = self_signed();
    let trust = TlsTrustRoots::from_pem(&other_cert).expect("other trust");
    let client_cfg = TlsClientConfig::new(trust);
    let connector = Tls104Connector::new(&client_cfg, "localhost").expect("connector");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await.expect("accept");
        let _ = acceptor.accept(tcp).await;
    });
    let result = connector.connect(addr).await;
    let _ = server.await;

    assert!(
        matches!(result, Err(TlsError::Tls(_) | TlsError::Io(_))),
        "expected TLS handshake failure, got {result:?}"
    );
}
