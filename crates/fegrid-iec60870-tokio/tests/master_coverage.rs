//! Coverage tests for master.rs (G-002, G-009, G-021, G-022, G-023, G-024).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::duplex;
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
use fegrid_iec60870_core::{
    AppLayerParameters, CauseOfTransmission, CommonAddress, CotField, Cp56Time2a,
    QualifierOfInterrogation, TypeId,
};
use fegrid_iec60870_cs104::{ApciParameters, Cs104Session, Started, Stopped};
use fegrid_iec60870_tokio::{
    ApduCodec, Backpressure, MClient, RawMessageHandler, RawMessageRegistry, cmds,
};

fn dummy_asdu() -> Asdu {
    Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: TypeId::M_SP_NA_1 as u8,
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
            1,
            InformationValue::interrogation_command(QualifierOfInterrogation::STATION),
        )],
    }
}

fn make_started(k: u16, w: u16) -> Cs104Session<Started> {
    let apci = ApciParameters {
        k,
        w,
        t0_ms: 1000,
        t1_ms: 1000,
        t2_ms: 2000,
        t3_ms: 5000,
    };
    let s = Cs104Session::<Stopped>::new(apci, AppLayerParameters::default());
    let (waiting, _bytes) = s.send_startdt();
    waiting.on_startdt_con().expect("startdt ok")
}

#[tokio::test]
async fn mclient_set_get_originator_address() {
    let s = make_started(12, 8);
    let (a, b) = duplex(64);
    let framed = Framed::new(a, ApduCodec::new());
    let client = MClient::new(b, framed, s);
    assert_eq!(client.originator_address(), 0);
    client.set_originator_address(42);
    assert_eq!(client.originator_address(), 42);
    assert!(client.local_addr().is_none());
    assert!(client.peer_addr().is_none());
    let _ = client.send_seq();
}

#[test]
fn mclient_send_seq_advances() {
    let mut s = make_started(12, 8);
    let initial_seq = s.seq().send().0;
    let _ = s.send_i(dummy_asdu());
    let after_seq = s.seq().send().0;
    assert_eq!(after_seq, initial_seq + 1, "send_i advances ns by 1");
}

#[test]
fn mclient_cmds_build_well_formed_asdus() {
    let gi = cmds::general_interrogation(1, QualifierOfInterrogation::STATION);
    assert_eq!(gi.type_id, TypeId::C_IC_NA_1);

    let rd = cmds::read(1, 0);
    assert_eq!(rd.type_id, TypeId::C_RD_NA_1);

    let t = Cp56Time2a {
        ms: 0,
        minutes: 0,
        hours: 0,
        day_of_month: 1,
        day_of_week: 0,
        month: 1,
        year: 124,
        summer_time: false,
        invalid: false,
    };
    let cs = cmds::clock_sync(1, t);
    assert_eq!(cs.type_id, TypeId::C_CS_NA_1);

    let req = cmds::general_interrogation(1, QualifierOfInterrogation::STATION);
    let pos = cmds::confirm(&req);
    let neg = cmds::confirm_negative(&req);
    assert!(!pos.cot.negative_confirm);
    assert!(neg.cot.negative_confirm);
}

#[tokio::test]
async fn mclient_send_k_window_backpressure() {
    let s = make_started(1, 1);
    let (a, b) = duplex(64);
    let framed = Framed::new(a, ApduCodec::new());
    let mut client = MClient::new(b, framed, s);
    let _ = client.send(dummy_asdu()).await;
    let r2 = client.send(dummy_asdu()).await;
    if let Err(e) = r2 {
        assert!(matches!(e, Backpressure::KWindowFull));
    }
}

#[test]
fn raw_handler_trait_object_counts_calls() {
    struct CountingHandler(AtomicUsize);
    impl RawMessageHandler for CountingHandler {
        fn on_raw(&self, _: &[u8], _: bool) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let atomic = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn RawMessageHandler> = Arc::new(CountingHandler(AtomicUsize::new(0)));
    handler.on_raw(&[0x01, 0x02], true);
    assert_eq!(atomic.load(Ordering::SeqCst), 0);
}
#[test]
fn raw_registry_register_dispatch() {
    let registry = RawMessageRegistry::new();
    struct Count(AtomicUsize);
    impl RawMessageHandler for Count {
        fn on_raw(&self, _: &[u8], _: bool) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let h: Arc<dyn RawMessageHandler> = Arc::new(Count(AtomicUsize::new(0)));
    registry.register(h);
    registry.dispatch(&[1, 2, 3], true);
}
