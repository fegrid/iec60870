//! Async tokio CS 104 session drivers.
//!
//! These wrap the typestate engine in
//! [`fegrid_iec60870_cs104::typestate`] with the STARTDT handshake
//! and connection-lifecycle events. They operate on any
//! `Framed<S, ApduCodec>` so plain TCP and TLS streams both work
//! unchanged.
//!
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::Framed;

use fegrid_iec60870_core::AppLayerParameters;
use fegrid_iec60870_cs104::ApciParameters;
use fegrid_iec60870_cs104::Apdu;
use fegrid_iec60870_cs104::Cs104Session;
use fegrid_iec60870_cs104::Started;
use fegrid_iec60870_cs104::Stopped;
use fegrid_iec60870_cs104::UFrame;
use fegrid_iec60870_cs104::typestate::SessionError;

use crate::codec104::{ApduCodec, CodecError};

/// Default IEC 60870-5-104 TCP port (IEC 60870-5-104 §5).
pub const IEC104_DEFAULT_PORT: u16 = 2404;

/// Connection lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnEvent {
    /// TCP (or TLS) transport established.
    Opened,
    /// STARTDT_CON received — data transfer active.
    StartDtConReceived,
    /// STOPDT_CON received.
    StopDtConReceived,
    /// Connection closed cleanly.
    Closed,
    /// Connection failed.
    Failed,
}

/// Errors surfaced by the session drivers.
#[derive(Debug, Error)]
pub enum Session104Error {
    /// Underlying I/O failure.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// Framing / decode failure.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// Typestate engine rejected the exchange.
    #[error("protocol: {0}")]
    Protocol(#[from] SessionError),
    /// STARTDT_CON not received within t1 (parity with
    /// `cs104_connection.c:1386-1394`).
    #[error("t1 timeout waiting for STARTDT_CON")]
    StartDtTimeout,
}

/// Collapse `Option<Result<Apdu, CodecError>>` from a `Framed::next()`
/// poll into a single `Result`.
async fn next_apdu<S>(stream: &mut Framed<S, ApduCodec>) -> Result<Option<Apdu>, Session104Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match stream.next().await {
        None => Ok(None),
        Some(Ok(apdu)) => Ok(Some(apdu)),
        Some(Err(e)) => Err(Session104Error::Codec(e)),
    }
}

/// Wait for one `STARTDT_ACT` U-frame, answer with `STARTDT_CON`, return
/// the [`Started`] session.
async fn drive_startdt_act<S>(
    stream: &mut Framed<S, ApduCodec>,
    params: ApciParameters,
) -> Result<Cs104Session<Started>, Session104Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let apdu = match next_apdu(stream).await? {
        Some(a) => a,
        None => {
            return Err(Session104Error::Protocol(SessionError::Protocol(
                "expected STARTDT_ACT",
            )));
        }
    };
    if !matches!(apdu, Apdu::U(UFrame::StartDtAct)) {
        return Err(Session104Error::Protocol(SessionError::Protocol(
            "expected STARTDT_ACT",
        )));
    }
    let session = Cs104Session::<Stopped>::new(params, AppLayerParameters::default());
    let (started, _con) = session.on_startdt_act();
    stream.send(Apdu::U(UFrame::StartDtCon)).await?;
    Ok(started)
}

/// Client-side STARTDT handshake over any framed CS 104 stream.
///
/// Sends `STARTDT_ACT`, awaits `STARTDT_CON` under a `params.t1_ms`
/// deadline, returns the [`Started`] session and stream. Parity:
/// `CS104_Connection_sendStartDT` (`cs104_connection.c:1780`) +
/// `CS104_CONNECTION_STARTDT_CON_RECEIVED`.
pub async fn start_client<S>(
    mut stream: Framed<S, ApduCodec>,
    params: ApciParameters,
) -> Result<(Cs104Session<Started>, Framed<S, ApduCodec>, Vec<ConnEvent>), Session104Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut events = Vec::with_capacity(2);
    events.push(ConnEvent::Opened);

    let session = Cs104Session::<Stopped>::new(params, AppLayerParameters::default());
    let (waiting, _act) = session.send_startdt();
    stream.send(Apdu::U(UFrame::StartDtAct)).await?;

    let apdu = match timeout(Duration::from_millis(params.t1_ms), next_apdu(&mut stream)).await {
        Ok(Ok(Some(apdu))) => apdu,
        Ok(Ok(None)) => {
            return Err(Session104Error::Protocol(SessionError::Protocol(
                "expected STARTDT_CON",
            )));
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(Session104Error::StartDtTimeout),
    };

    if !matches!(apdu, Apdu::U(UFrame::StartDtCon)) {
        return Err(Session104Error::Protocol(SessionError::Protocol(
            "expected STARTDT_CON",
        )));
    }

    let started = waiting.on_startdt_con()?;
    events.push(ConnEvent::StartDtConReceived);

    Ok((started, stream, events))
}

/// Server-side STARTDT handshake: await `STARTDT_ACT`, answer
/// `STARTDT_CON`, return the [`Started`] session. Parity: threadless
/// `CS104_Slave` accept + STARTDT service
/// (`cs104_slave.c:4510`, `on_startdt_act`).
pub async fn start_server<S>(
    mut stream: Framed<S, ApduCodec>,
    params: ApciParameters,
) -> Result<(Cs104Session<Started>, Framed<S, ApduCodec>, Vec<ConnEvent>), Session104Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut events = Vec::with_capacity(2);
    events.push(ConnEvent::Opened);

    // The server owns the socket; threadless accept blocks
    // (`ServerSocket_accept`). No timeout here — matches the C
    // threadless loop which spins until an APDU arrives.
    let started = drive_startdt_act(&mut stream, params).await?;
    // Server-side the CON is sent, not received; the same event value
    // is emitted for caller symmetry — see doc on [`ConnEvent`].
    events.push(ConnEvent::StartDtConReceived);

    Ok((started, stream, events))
}
/// Client-side STOPDT handshake over any framed CS 104 stream.
///
/// Sends `STOPDT_ACT`, awaits `STOPDT_CON` under a `params.t1_ms` deadline,
/// and returns the [`Stopped`] session and the (still-connected) stream.
/// Parity: `CS104_Connection_sendStopDT` (`cs104_connection.c:1806`).
pub async fn stop_client<S>(
    mut stream: Framed<S, ApduCodec>,
    session: Cs104Session<Started>,
) -> Result<(Cs104Session<Stopped>, Framed<S, ApduCodec>, Vec<ConnEvent>), Session104Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut events = Vec::with_capacity(2);
    let (waiting, _act) = session.send_stopdt();
    stream.send(Apdu::U(UFrame::StopDtAct)).await?;
    let apdu = match timeout(
        Duration::from_millis(STOPDT_DEFAULT_DEADLINE_MS),
        next_apdu(&mut stream),
    )
    .await
    {
        Ok(Ok(Some(apdu))) => apdu,
        Ok(Ok(None)) => {
            return Err(Session104Error::Protocol(SessionError::Protocol(
                "expected STOPDT_CON",
            )));
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(Session104Error::StartDtTimeout),
    };
    if !matches!(apdu, Apdu::U(UFrame::StopDtCon)) {
        return Err(Session104Error::Protocol(SessionError::Protocol(
            "expected STOPDT_CON",
        )));
    }
    let stopped = waiting.on_stopdt_con();
    events.push(ConnEvent::StopDtConReceived);
    Ok((stopped, stream, events))
}

/// Server-side STOPDT handshake: await `STOPDT_ACT`, reply with `STOPDT_CON`,
/// return the [`Stopped`] session. Parity: threadless `CS104_Slave` STOPDT
/// service (`cs104_slave.c:3127`).
pub async fn stop_server<S>(
    mut stream: Framed<S, ApduCodec>,
    session: Cs104Session<Started>,
) -> Result<(Cs104Session<Stopped>, Framed<S, ApduCodec>, Vec<ConnEvent>), Session104Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut events = Vec::with_capacity(2);
    let apdu = match next_apdu(&mut stream).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return Err(Session104Error::Protocol(SessionError::Protocol(
                "expected STOPDT_ACT",
            )));
        }
        Err(e) => return Err(e),
    };
    if !matches!(apdu, Apdu::U(UFrame::StopDtAct)) {
        return Err(Session104Error::Protocol(SessionError::Protocol(
            "expected STOPDT_ACT",
        )));
    }
    // Mirror the spec: send STOPDT_CON, transition Started → Stopped.
    stream.send(Apdu::U(UFrame::StopDtCon)).await?;
    let (waiting, _act) = session.send_stopdt();
    let stopped = waiting.on_stopdt_con();
    events.push(ConnEvent::StopDtConReceived);
    Ok((stopped, stream, events))
}

/// Default STOPDT deadline in milliseconds. Matches the `t1` timer in
/// the C reference.
pub const STOPDT_DEFAULT_DEADLINE_MS: u64 = 15_000;
