//! Typestate connection engine.
//!
//! The connection engine never touches I/O directly — every state
//! transition returns an [`Output`] envelope that the transport layer
//! converts into socket writes / channel notifications. State markers
//! are zero-sized types so the compiler eliminates them.

use bytes::Bytes;

use fegrid_iec60870_asdu::Asdu;
use fegrid_iec60870_core::AppLayerParameters;

use crate::apci::{
    APCI_MAX_LENGTH, Apdu, SeqNo, UFrame, encode_i, parse_apdu, s_frame_bytes, u_frame_bytes,
};
use crate::params::ApciParameters;
use crate::sequence::SequenceState;
/// Zero-sized marker: TCP up, STARTDT not yet sent / received.
#[derive(Debug, Default)]
pub struct Stopped;
/// Zero-sized marker: STARTDT sent, waiting for CON.
#[derive(Debug, Default)]
pub struct WaitingStartCon;

/// Zero-sized marker: data transfer active.
#[derive(Debug, Default)]
pub struct Started;

/// Zero-sized marker: STOPDT sent, waiting for CON.
#[derive(Debug, Default)]
pub struct WaitingStopCon;

/// Zero-sized marker: connection closed (terminal).
#[derive(Debug, Default)]
pub struct Closed;

/// Instructions emitted by the engine. The transport converts these into
/// socket writes or channel sends.
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    /// Send a U-frame.
    UFrame(UFrame),
    /// Send an S-frame acking `nr`.
    SAck(SeqNo),
    /// Send an I-frame carrying the given ASDU.
    IFrame(Asdu),
    /// Close the transport.
    Close,
    /// Nothing to do (heartbeat consumed, no events).
    None,
}

/// Errors surfaced by the typestate engine.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionError {
    /// State machine received an unexpected APDU.
    Protocol(&'static str),
    /// Underlying sequence-window violation.
    Sequence(crate::apci::ApduError),
    /// Encoding buffer too small.
    BufferTooShort {
        /// Bytes needed.
        need: usize,
    },
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(s) => f.write_str(s),
            Self::Sequence(e) => write!(f, "{e}"),
            Self::BufferTooShort { need } => {
                write!(f, "encode buffer too small (need {need})")
            }
        }
    }
}

impl core::error::Error for SessionError {}

impl From<crate::apci::ApduError> for SessionError {
    fn from(e: crate::apci::ApduError) -> Self {
        Self::Sequence(e)
    }
}

/// A typed session in state `S`. Methods are only available on the
/// appropriate state, so invalid transitions fail at compile time.
#[derive(Debug, Clone)]
pub struct Cs104Session<S> {
    pub(crate) seq: SequenceState,
    pub(crate) apci: ApciParameters,
    pub(crate) asdu: AppLayerParameters,
    pub(crate) pending_out: Option<Output>,
    pub(crate) default_oa: u8,
    pub(crate) _state: core::marker::PhantomData<S>,
}

impl<S> Cs104Session<S> {
    /// Set the default Originator Address field that subsequent ASDUs
    /// encode into their COT byte (G-023).
    pub fn set_originator_address(&mut self, oa: u8) {
        self.default_oa = oa;
    }
    /// Read the default Originator Address.
    pub fn originator_address(&self) -> u8 {
        self.default_oa
    }
}

impl Cs104Session<Stopped> {
    /// Construct a fresh session in `Stopped`.
    pub fn new(apci: ApciParameters, asdu: AppLayerParameters) -> Self {
        Self {
            seq: SequenceState::new(),
            apci,
            asdu,
            pending_out: None,
            default_oa: 0,
            _state: core::marker::PhantomData,
        }
    }
    /// Send a `STARTDT_ACT`. Returns the new `WaitingStartCon` session
    /// and the frame bytes to write.
    pub fn send_startdt(self) -> (Cs104Session<WaitingStartCon>, Bytes) {
        let bytes = u_frame_bytes(UFrame::StartDtAct);
        (
            Cs104Session {
                seq: self.seq,
                apci: self.apci,
                asdu: self.asdu,
                pending_out: Some(Output::UFrame(UFrame::StartDtAct)),
                default_oa: self.default_oa,
                _state: core::marker::PhantomData,
            },
            bytes,
        )
    }

    /// Slave-side: receive `STARTDT_ACT`. Returns the `Started` session and
    /// the `STARTDT_CON` bytes to write.
    pub fn on_startdt_act(self) -> (Cs104Session<Started>, Bytes) {
        let bytes = u_frame_bytes(UFrame::StartDtCon);
        (
            Cs104Session {
                seq: self.seq,
                apci: self.apci,
                asdu: self.asdu,
                pending_out: Some(Output::UFrame(UFrame::StartDtCon)),
                default_oa: self.default_oa,
                _state: core::marker::PhantomData,
            },
            bytes,
        )
    }
}

impl Cs104Session<WaitingStartCon> {
    /// Complete the STARTDT handshake after receiving `STARTDT_CON`.
    pub fn on_startdt_con(mut self) -> Result<Cs104Session<Started>, SessionError> {
        // Reset send/recv sequence counters when the data transfer starts.
        self.seq = SequenceState::new();
        Ok(Cs104Session {
            seq: self.seq,
            apci: self.apci,
            asdu: self.asdu,
            pending_out: Some(Output::UFrame(UFrame::StartDtCon)),
            default_oa: self.default_oa,
            _state: core::marker::PhantomData,
        })
    }

    /// Handle a timeout (t1) while waiting for CON.
    pub fn on_timeout(&self) -> SessionError {
        SessionError::Protocol("t1 timeout waiting for STARTDT_CON")
    }
}

impl Cs104Session<Started> {
    /// Reserve the next send sequence number and queue an I-frame for the
    /// given ASDU. Returns the encoded frame bytes to write.
    pub fn send_i(&mut self, mut asdu: Asdu) -> Result<Bytes, SessionError> {
        let ns = self
            .seq
            .next_send(self.apci.k)
            .ok_or(SessionError::Protocol("k-window full"))?;
        // Apply the default originator address (G-023) at encode time.
        asdu.cot.originator = self.default_oa;
        let mut buf = [0u8; APCI_MAX_LENGTH as usize + 6];
        let n = encode_i(ns, self.seq.recv(), Some(&asdu), &self.asdu, &mut buf)
            .map_err(SessionError::Sequence)?;
        self.pending_out = Some(Output::IFrame(asdu));
        Ok(Bytes::copy_from_slice(&buf[..n]))
    }

    /// Generate an S-frame acking the current receive counter.
    pub fn send_s(&self) -> Bytes {
        s_frame_bytes(self.seq.recv())
    }
    /// Receive an APDU. Returns an updated session (may transition
    /// state) and the output to emit, or a protocol error.
    pub fn on_apdu(mut self, buf: &[u8]) -> Result<(Self, Output), SessionError> {
        let apdu = parse_apdu(buf)?;
        match apdu {
            Apdu::U(UFrame::StartDtAct) => {
                // Peer wants to restart — emit STARTDT_CON and reset.
                let _ = u_frame_bytes(UFrame::StartDtCon);
                self.seq = SequenceState::new();
                Ok((self, Output::UFrame(UFrame::StartDtCon)))
            }
            Apdu::U(UFrame::StopDtAct) => Ok((self, Output::UFrame(UFrame::StopDtCon))),
            Apdu::U(_) => Ok((self, Output::None)),
            Apdu::S { nr } => {
                self.seq.on_s_received(nr);
                Ok((self, Output::None))
            }
            Apdu::I { ns, nr, asdu } => {
                self.seq.on_i_received(ns)?;
                self.seq.on_s_received(nr);
                match asdu {
                    Some(a) => Ok((self, Output::IFrame(a))),
                    None => Ok((self, Output::None)),
                }
            }
        }
    }
    /// Receive an already-parsed APDU. Same semantics as
    /// [`Self::on_apdu`] but skips wire parsing — for tokio transports
    /// that already framed the stream with [`crate::apci::parse_apdu`]
    /// (e.g. `ApduCodec`).
    pub fn on_apdu_apdu(mut self, apdu: Apdu) -> Result<(Self, Output), SessionError> {
        match apdu {
            Apdu::U(UFrame::StartDtAct) => {
                // Peer wants to restart — emit STARTDT_CON and reset.
                let _ = u_frame_bytes(UFrame::StartDtCon);
                self.seq = SequenceState::new();
                Ok((self, Output::UFrame(UFrame::StartDtCon)))
            }
            Apdu::U(UFrame::StopDtAct) => Ok((self, Output::UFrame(UFrame::StopDtCon))),
            Apdu::U(_) => Ok((self, Output::None)),
            Apdu::S { nr } => {
                self.seq.on_s_received(nr);
                Ok((self, Output::None))
            }
            Apdu::I { ns, nr, asdu } => {
                self.seq.on_i_received(ns)?;
                self.seq.on_s_received(nr);
                match asdu {
                    Some(a) => Ok((self, Output::IFrame(a))),
                    None => Ok((self, Output::None)),
                }
            }
        }
    }

    /// Send a STOPDT_ACT — transitions to `WaitingStopCon`.
    pub fn send_stopdt(self) -> (Cs104Session<WaitingStopCon>, Bytes) {
        let bytes = u_frame_bytes(UFrame::StopDtAct);
        (
            Cs104Session {
                seq: self.seq,
                apci: self.apci,
                asdu: self.asdu,
                pending_out: Some(Output::UFrame(UFrame::StopDtAct)),
                default_oa: self.default_oa,
                _state: core::marker::PhantomData,
            },
            bytes,
        )
    }
    /// Send a TESTFR_ACT (k-window idle).
    pub fn send_testfr(&self) -> Bytes {
        u_frame_bytes(UFrame::TestFrAct)
    }

    /// Close the session (terminal state).
    pub fn close(self) -> Cs104Session<Closed> {
        Cs104Session {
            seq: self.seq,
            apci: self.apci,
            asdu: self.asdu,
            pending_out: Some(Output::Close),
            default_oa: self.default_oa,
            _state: core::marker::PhantomData,
        }
    }
    /// Borrow the sequence state (for tests).
    pub fn seq(&self) -> &SequenceState {
        &self.seq
    }

    /// Acknowledge an inbound S-frame (master's ack). Updates the
    /// send-window so the next `send_i` can advance. Used by the
    /// tokio server runtime to process acks without re-parsing
    /// the wire bytes.
    pub fn on_s_received(&mut self, nr: SeqNo) {
        self.seq.on_s_received(nr);
    }

    /// How many I-frames the peer has sent that we have not yet
    /// ACKed back via an S-frame. Used by the t2 watchdog.
    pub fn unacked_recv_count(&self) -> u16 {
        self.seq.unacked_recv_count()
    }

    /// Record that we emitted an S-frame acking `nr`. Updates the
    /// recv-side ack counter so the t2 watchdog knows when the
    /// peer has been caught up.
    pub fn note_s_sent(&mut self, nr: SeqNo) {
        self.seq.note_s_sent(nr);
    }
}

impl Cs104Session<WaitingStopCon> {
    /// Complete the STOPDT handshake after receiving `STOPDT_CON`.
    pub fn on_stopdt_con(self) -> Cs104Session<Stopped> {
        Cs104Session {
            seq: self.seq,
            apci: self.apci,
            asdu: self.asdu,
            pending_out: Some(Output::None),
            default_oa: self.default_oa,
            _state: core::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ApciParameters;
    use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
    use fegrid_iec60870_core::{AppLayerParameters, CauseOfTransmission, CommonAddress, CotField};

    fn params() -> (ApciParameters, AppLayerParameters) {
        (ApciParameters::default(), AppLayerParameters::default())
    }

    #[test]
    fn startdt_handshake() {
        let (apci, asdu) = params();
        let s = Cs104Session::<Stopped>::new(apci, asdu);
        let (s, bytes) = s.send_startdt();
        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0], 0x68);
        assert_eq!(bytes[2], UFrame::StartDtAct as u8);
        let mut s = s.on_startdt_con().expect("handshake");
        // Now send an I-frame.
        let asdu = Asdu {
            type_id: fegrid_iec60870_core::TypeId::M_SP_NA_1,
            original_type_byte: fegrid_iec60870_core::TypeId::M_SP_NA_1 as u8,
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
            objects: alloc::vec![InformationObject {
                ioa: 1,
                value: InformationValue::SinglePoint {
                    value: true,
                    quality: Default::default(),
                },
                timestamp: None,
            }],
        };
        let bytes = s.send_i(asdu).expect("send_i");
        assert!(bytes.len() >= 6);
    }

    #[test]

    fn slave_accepts_startdt() {
        let (apci, asdu) = params();
        let s = Cs104Session::<Stopped>::new(apci, asdu);
        let (s, con) = s.on_startdt_act();
        assert_eq!(con[2], UFrame::StartDtCon as u8);
        let _started = s;
    }

    #[test]
    fn u_frame_decode_recovers_baseline() {
        // Legitimate U-frame bytes verified against the C reference
        // (`cs104_connection.c:179-192`).
        let start_dt_act = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let stop_dt_act = [0x68, 0x04, 0x13, 0x00, 0x00, 0x00];
        let test_fr_act = [0x68, 0x04, 0x43, 0x00, 0x00, 0x00];
        assert_eq!(
            parse_apdu(&start_dt_act).unwrap(),
            Apdu::U(UFrame::StartDtAct)
        );
        assert_eq!(
            parse_apdu(&stop_dt_act).unwrap(),
            Apdu::U(UFrame::StopDtAct)
        );
        assert_eq!(
            parse_apdu(&test_fr_act).unwrap(),
            Apdu::U(UFrame::TestFrAct)
        );
    }

    /// Typestate compile-fail check: `Stopped` cannot call `send_i`.
    /// ```compile_fail
    /// use fegrid_iec60870_cs104::{Cs104Session, Stopped, ApciParameters};
    /// use fegrid_iec60870_core::AppLayerParameters;
    /// let (apci, asdu) = (ApciParameters::default(), AppLayerParameters::default());
    /// let s: Cs104Session<Stopped> = Cs104Session::new(apci, asdu);
    /// let _ = s.send_i(/* … */);
    /// ```
    #[allow(dead_code)]
    fn _stopped_send_i_forbidden() {}

    #[test]
    fn started_round_trip_i_and_s() {
        let (apci, asdu) = params();
        let s = Cs104Session::<Stopped>::new(apci, asdu);
        let (s, _) = s.send_startdt();
        let s = s.on_startdt_con().unwrap();
        let bytes = s.send_s();
        let (s, out) = s.on_apdu(&bytes).unwrap();
        assert!(matches!(out, Output::None));
        assert_eq!(s.seq().unacked_count(), 0);
    }

    #[test]
    fn on_apdu_apdu_emits_iframe_and_advances_recv() {
        let (apci, asdu) = params();
        let s = Cs104Session::<Stopped>::new(apci, asdu);
        let (s, _) = s.send_startdt();
        let s = s.on_startdt_con().unwrap();
        let sample = Asdu {
            type_id: fegrid_iec60870_core::TypeId::M_SP_NA_1,
            original_type_byte: fegrid_iec60870_core::TypeId::M_SP_NA_1 as u8,
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
            objects: alloc::vec![InformationObject {
                ioa: 1,
                value: InformationValue::SinglePoint {
                    value: true,
                    quality: Default::default(),
                },
                timestamp: None,
            }],
        };
        let apdu = Apdu::I {
            ns: SeqNo(0),
            nr: SeqNo(0),
            asdu: Some(sample.clone()),
        };
        let (s, out) = s.on_apdu_apdu(apdu).expect("on_apdu_apdu");
        assert_eq!(out, Output::IFrame(sample));
        assert_eq!(s.seq().recv(), SeqNo(1));
    }
}
