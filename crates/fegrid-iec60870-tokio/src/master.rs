//! CS 104 master (client) side driver.
//!
//! [`MClient`] wraps a `Cs104Session<Started>` and a raw-byte tokio transport
//! (`AsyncRead + AsyncWrite`). Outbound frames are written as raw bytes via
//! `AsyncWriteExt::write_all` so the typed session's pre-encoded `Bytes`
//! output lands on the wire verbatim. Inbound frames are decoded through
//! `Framed<S, ApduCodec>`.
//!
//! The companion [`cmds`] module provides free-function command encoders
//! (G-019, G-020) that build a typed `Asdu` for each standard master-side
//! command.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::Asdu;
use fegrid_iec60870_cs104::{Apdu, Cs104Session, SeqNo, Started};

use crate::codec104::{ApduCodec, apdu_to_wire};

/// Reason an `MClient::send` operation could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backpressure {
    /// The k-window is full - the application should retry after receiving
    /// an S-frame ack from the peer.
    KWindowFull,
    /// The connection has been closed.
    Closed,
}

/// Optional raw-message observer. Receives `(bytes, sent)` for every
/// outbound and inbound APDU. Default is a no-op.
pub trait RawMessageHandler: Send + Sync + 'static {
    /// Called for every byte buffer that crosses the wire.
    fn on_raw(&self, bytes: &[u8], sent: bool);
}

struct NoopHandler;
impl RawMessageHandler for NoopHandler {
    fn on_raw(&self, _: &[u8], _: bool) {}
}

/// Callback fired on every decoded inbound ASDU before it is returned
/// from `recv()`. Used for routing to application state (G-021).
pub type AsduHandler = Arc<dyn Fn(Asdu) + Send + Sync>;

/// Master/client-side CS 104 session. Holds the typed session behind a
/// `Mutex` because `send_i` needs `&mut`; holds the write-half of the
/// transport separately and the read-half as a `Framed` for typed
/// decoding.
pub struct MClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    writer: S,
    reader: Framed<S, ApduCodec>,
    session: Mutex<Cs104Session<Started>>,
    raw: Arc<dyn RawMessageHandler>,
    /// Optional ASDU callback invoked from `recv()` for each decoded
    /// inbound ASDU before the value is returned.
    asdu_handler: Option<AsduHandler>,
    /// Cached local socket address (G-022).
    local_addr: Option<std::net::SocketAddr>,
    /// Cached peer socket address (G-018).
    peer_addr: Option<std::net::SocketAddr>,
}

impl<S> MClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Wrap a STARTDT'd session + framed reader around a writable stream.
    pub fn new(writer: S, reader: Framed<S, ApduCodec>, session: Cs104Session<Started>) -> Self {
        Self {
            writer,
            reader,
            session: Mutex::new(session),
            raw: Arc::new(NoopHandler),
            asdu_handler: None,
            local_addr: None,
            peer_addr: None,
        }
    }

    /// Replace the raw-message observer.
    #[must_use]
    pub fn with_raw_message_handler(mut self, handler: Arc<dyn RawMessageHandler>) -> Self {
        self.raw = handler;
        self
    }

    /// Install the per-`recv()` callback (G-021).
    #[must_use]
    pub fn with_asdu_handler(mut self, handler: AsduHandler) -> Self {
        self.asdu_handler = Some(handler);
        self
    }

    /// Cache the local socket address (G-022).
    #[must_use]
    pub fn with_local_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.local_addr = Some(addr);
        self
    }

    /// Cache the peer socket address (G-018).
    #[must_use]
    pub fn with_peer_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    /// Cached local socket address.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.local_addr
    }

    /// Cached peer socket address.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr
    }

    /// Current send sequence number (for diagnostics).
    pub fn send_seq(&self) -> SeqNo {
        self.session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .seq()
            .send()
    }

    /// Update the Originator Address field at runtime (G-023).
    pub fn set_originator_address(&self, oa: u8) {
        let mut session = self.session.lock().unwrap_or_else(|p| p.into_inner());
        session.set_originator_address(oa);
    }

    /// Read the currently-configured Originator Address.
    pub fn originator_address(&self) -> u8 {
        self.session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .originator_address()
    }

    /// Send an ASDU. Returns the encoded I-frame bytes that were written
    /// to the socket. Returns `Err(Backpressure::KWindowFull)` if the
    /// window is full.
    pub async fn send(&mut self, asdu: Asdu) -> Result<Bytes, Backpressure> {
        let frame_bytes = {
            let mut session = self.session.lock().unwrap_or_else(|p| p.into_inner());
            session
                .send_i(asdu)
                .map_err(|_| Backpressure::KWindowFull)?
        };
        self.raw.on_raw(&frame_bytes, true);
        self.writer
            .write_all(&frame_bytes)
            .await
            .map_err(|_| Backpressure::Closed)?;
        self.writer
            .flush()
            .await
            .map_err(|_| Backpressure::Closed)?;
        Ok(frame_bytes)
    }

    /// Send an already-encoded I-frame byte buffer (G-024 conformance
    /// escape). The bytes are written verbatim.
    pub async fn send_raw(&mut self, frame: &[u8]) -> Result<(), Backpressure> {
        self.raw.on_raw(frame, true);
        self.writer
            .write_all(frame)
            .await
            .map_err(|_| Backpressure::Closed)?;
        self.writer
            .flush()
            .await
            .map_err(|_| Backpressure::Closed)?;
        Ok(())
    }

    /// Receive the next inbound APDU. Observes via the raw handler and
    /// dispatches to the per-ASDU callback (if installed).
    pub async fn recv(&mut self) -> Option<Result<Apdu, std::io::Error>> {
        let item = self.reader.next().await;
        if let Some(Ok(ref apdu)) = item {
            self.raw.on_raw(&apdu_to_wire(apdu), false);
        }
        item.map(|r| r.map_err(std::io::Error::other))
    }

    /// Borrow the typed session.
    pub fn session(&self) -> std::sync::MutexGuard<'_, Cs104Session<Started>> {
        self.session.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl<S> std::fmt::Debug for MClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MClient")
            .field(
                "send_seq",
                &self
                    .session
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .seq()
                    .send(),
            )
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

/// Singleton-style registry of `RawMessageHandler`s. Lets multiple
/// transports share a single observer instance.
#[derive(Clone, Default)]
pub struct RawMessageRegistry {
    inner: Arc<Mutex<Vec<Arc<dyn RawMessageHandler>>>>,
}

impl RawMessageRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a new observer.
    pub fn register(&self, handler: Arc<dyn RawMessageHandler>) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(handler);
    }
    /// Dispatch a raw frame to every registered observer.
    pub fn dispatch(&self, bytes: &[u8], sent: bool) {
        for h in self.inner.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            h.on_raw(bytes, sent);
        }
    }
}

/// Free-function command drivers - G-019, G-020 - that build a typed
/// `Asdu` for each standard master-side command. The caller hands the
/// result to [`MClient::send`].
pub mod cmds {
    use super::*;
    use fegrid_iec60870_asdu::{InformationObject, InformationValue};
    use fegrid_iec60870_core::{
        CauseOfTransmission, CommonAddress, CotField, QualifierOfCIC, QualifierOfInterrogation,
        TypeId,
    };

    fn build_cot() -> CotField {
        CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        }
    }

    /// Build a `C_IC_NA_1` (general interrogation) ASDU body.
    pub fn general_interrogation(ca: u16, qoi: QualifierOfInterrogation) -> Asdu {
        Asdu {
            type_id: TypeId::C_IC_NA_1,
            original_type_byte: TypeId::C_IC_NA_1 as u8,
            cot: build_cot(),
            common_address: CommonAddress(ca),
            is_sequence: false,
            is_test: false,
            objects: vec![InformationObject::new(
                0,
                InformationValue::interrogation_command(qoi),
            )],
        }
    }

    /// Build a `C_CI_NA_1` (counter interrogation) ASDU body.
    pub fn counter_interrogation(ca: u16, qcc: QualifierOfCIC) -> Asdu {
        Asdu {
            type_id: TypeId::C_CI_NA_1,
            original_type_byte: TypeId::C_CI_NA_1 as u8,
            cot: build_cot(),
            common_address: CommonAddress(ca),
            is_sequence: false,
            is_test: false,
            objects: vec![InformationObject::new(
                0,
                InformationValue::counter_interrogation_command(qcc),
            )],
        }
    }

    /// Build a `C_RD_NA_1` (read) ASDU body.
    pub fn read(ca: u16, ioa: u32) -> Asdu {
        Asdu {
            type_id: TypeId::C_RD_NA_1,
            original_type_byte: TypeId::C_RD_NA_1 as u8,
            cot: build_cot(),
            common_address: CommonAddress(ca),
            is_sequence: false,
            is_test: false,
            objects: vec![InformationObject::new(ioa, InformationValue::ReadCommand)],
        }
    }

    /// Build a `C_CS_NA_1` (clock sync) ASDU body.
    pub fn clock_sync(ca: u16, time: fegrid_iec60870_core::Cp56Time2a) -> Asdu {
        Asdu {
            type_id: TypeId::C_CS_NA_1,
            original_type_byte: TypeId::C_CS_NA_1 as u8,
            cot: build_cot(),
            common_address: CommonAddress(ca),
            is_sequence: false,
            is_test: false,
            objects: vec![InformationObject::new(
                0,
                InformationValue::ClockSyncCommand(time),
            )],
        }
    }

    /// Build a process command ASDU body from a pre-built typed value.
    /// The TypeId is inferred from the value's type byte.
    pub fn process_command(ca: u16, ioa: u32, value: InformationValue) -> Asdu {
        Asdu {
            type_id: TypeId::try_from(value.type_byte()).unwrap_or(TypeId::C_SC_NA_1),
            original_type_byte: value.type_byte(),
            cot: build_cot(),
            common_address: CommonAddress(ca),
            is_sequence: false,
            is_test: false,
            objects: vec![InformationObject::new(ioa, value)],
        }
    }

    /// Build the ACTIVATION_CON confirmation of a received request.
    pub fn confirm(request: &Asdu) -> Asdu {
        fegrid_iec60870_asdu::dispatch::activation_confirm(request)
    }

    /// Build the ACTIVATION_CON NEGATIVE confirmation of a received
    /// request. Rejects commands at the COT P/N bit level.
    pub fn confirm_negative(request: &Asdu) -> Asdu {
        fegrid_iec60870_asdu::dispatch::activation_confirm_negative(request)
    }
}
