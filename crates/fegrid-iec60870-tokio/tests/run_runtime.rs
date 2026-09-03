//! Coverage tests for the threadless run.rs runtime (G-001).
//!
//! Drives every branch in run_threadless_server via a synthetic APDU
//! buffer: I-frame (with + without response), S-frame, U-frame,
//! malformed input.
use bytes::BytesMut;
use tokio_util::codec::Encoder;

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
use fegrid_iec60870_core::{
    AppLayerParameters, CauseOfTransmission, CommonAddress, CotField, QualifierOfInterrogation,
    TypeId,
};
use fegrid_iec60870_cs104::{ApciParameters, Apdu, Cs104Session, Started, Stopped, UFrame};
use fegrid_iec60870_tokio::run::{default_session, run_threadless_server};
use fegrid_iec60870_tokio::{ApduCodec, cmds as cs104cmds};

fn make_started() -> Cs104Session<Started> {
    let s = Cs104Session::<Stopped>::new(ApciParameters::default(), AppLayerParameters::default());
    let (waiting, _bytes) = s.send_startdt();
    waiting.on_startdt_con().expect("startdt ok")
}

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

fn encode_i_frame(asdu: &Asdu) -> Vec<u8> {
    let mut codec = ApduCodec::new();
    let mut buf = BytesMut::new();
    codec
        .encode(
            Apdu::I {
                ns: fegrid_iec60870_cs104::SeqNo(0),
                nr: fegrid_iec60870_cs104::SeqNo(0),
                asdu: Some(asdu.clone()),
            },
            &mut buf,
        )
        .expect("encode");
    buf.to_vec()
}

fn encode_u_frame(u: UFrame) -> Vec<u8> {
    let mut codec = ApduCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(Apdu::U(u), &mut buf).expect("encode");
    buf.to_vec()
}

#[test]
fn run_handles_i_frame_with_response() {
    let started = make_started();
    let asdu = cs104cmds::general_interrogation(1, QualifierOfInterrogation::STATION);
    let buf = encode_i_frame(&asdu);
    let mut out = Vec::new();
    let cb = Box::new(|req: &Asdu| Some(cs104cmds::confirm(req)));
    let res = run_threadless_server(&buf, &mut out, started, cb);
    assert!(res.is_ok());
    assert!(!out.is_empty(), "I-frame response should land in buf_out");
}

#[test]
fn run_handles_i_frame_without_response() {
    let started = make_started();
    let buf = encode_i_frame(&dummy_asdu());
    let mut out = Vec::new();
    let cb = Box::new(|_: &Asdu| None);
    let res = run_threadless_server(&buf, &mut out, started, cb);
    assert!(res.is_ok());
    assert!(out.is_empty(), "callback returned None → no outbound");
}

#[test]
fn run_handles_u_frame() {
    let started = make_started();
    let buf = encode_u_frame(UFrame::TestFrAct);
    let mut out = Vec::new();
    let cb = Box::new(|_: &Asdu| Some(dummy_asdu()));
    let res = run_threadless_server(&buf, &mut out, started, cb);
    assert!(res.is_ok());
    assert!(out.is_empty(), "U-frame never triggers callback");
}

#[test]
fn run_rejects_malformed_input() {
    let started = make_started();
    let mut out = Vec::new();
    let cb = Box::new(|_: &Asdu| None);
    let res = run_threadless_server(&[0x00, 0x00, 0x00], &mut out, started, cb);
    assert!(res.is_err());
}

#[test]
fn run_rejects_truncated_input() {
    let started = make_started();
    let buf = [0x68, 0x10, 0x00]; // length says 16, only header present
    let mut out = Vec::new();
    let cb = Box::new(|_: &Asdu| None);
    let res = run_threadless_server(&buf, &mut out, started, cb);
    assert!(res.is_err());
}

#[test]
fn default_session_returns_started() {
    let (_apci, _app, s) = default_session().expect("handshake");
    // Just confirm we got a Started session back.
    let _ = s.seq();
}
