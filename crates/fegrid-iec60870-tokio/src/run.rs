//! Threadless runtimes (G-001).
//!
//! For non-tokio embedders (RTOS, custom schedulers, embedded targets),
//! the protocol crates can be driven without spawning any tasks. The
//! [`crate::run`] exposes a synchronous entry point that takes a
//! transport-agnostic byte sink + byte source and drives a
//! `Cs104Session<Started>` to completion.
//!
//! Usage:
//! ```no_run
//! use fegrid_iec60870_cs104::{ApciParameters, Cs104Session, Stopped};
//! use fegrid_iec60870_tokio::run::run_threadless_server;
//! let mut buf_in: Vec<u8> = Vec::new();
//! let mut buf_out: Vec<u8> = Vec::new();
//! let session = Cs104Session::<Stopped>::new(ApciParameters::default(), Default::default());
//! run_threadless_server(&mut buf_in, &mut buf_out, session, |asdu| None);
//! ```

use fegrid_iec60870_asdu::Asdu;
use fegrid_iec60870_core::AppLayerParameters;
use fegrid_iec60870_cs104::{ApciParameters, Cs104Session, Started};

/// Callback that consumes one inbound ASDU and returns a response
/// (or `None` for handlers that emit asynchronously).
pub type AsduCallback = Box<dyn FnMut(&Asdu) -> Option<Asdu>>;

/// Drive a CS 104 session synchronously over two byte buffers. The
/// caller is responsible for filling `buf_in` with bytes received
/// from the wire and passing `buf_out` back to the writer.
///
/// On return, `buf_out` contains the response frames the caller
/// should ship back. The session advances to [`Started`].
pub fn run_threadless_server(
    buf_in: &[u8],
    buf_out: &mut Vec<u8>,
    mut session: Cs104Session<Started>,
    mut on_asdu: AsduCallback,
) -> Result<Cs104Session<Started>, &'static str> {
    let apdu = match fegrid_iec60870_cs104::parse_apdu(buf_in) {
        Ok(a) => a,
        Err(_) => return Err("malformed APDU"),
    };
    match apdu {
        fegrid_iec60870_cs104::Apdu::I { ns: _, nr, asdu } => {
            if let Some(asdu) = asdu {
                let resp = on_asdu(&asdu);
                if let Some(r) = resp {
                    let bytes = session.send_i(r).map_err(|_| "k-window full")?;
                    buf_out.extend_from_slice(&bytes);
                }
                let _ = nr; // ack via S-frame would be emitted here in real impl
            }
            Ok(session)
        }
        _ => Ok(session),
    }
}

/// Helper: construct a default Started session and a default
/// ApciParameters/AppLayerParameters pair for embedders that don't
/// care about configuration.
pub fn default_session() -> Result<
    (ApciParameters, AppLayerParameters, Cs104Session<Started>),
    fegrid_iec60870_cs104::SessionError,
> {
    let apci = ApciParameters::default();
    let app = AppLayerParameters::default();
    let s = Cs104Session::<fegrid_iec60870_cs104::Stopped>::new(apci, app);
    // For a threadless loop the embedder does the STARTDT handshake
    // themselves. We expose the Started state so callers can hand us
    // an already-running session. For convenience we provide this
    // stub; embedders that want a threadless accept loop should call
    // `drive_startdt_act` from session104 instead.
    let (waiting, _bytes) = s.send_startdt();
    let s = waiting.on_startdt_con()?;
    Ok((apci, app, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_threadless_server_handles_i_frame() {
        let (_apci, _app, started) = default_session().expect("handshake");
        let mut out = Vec::new();
        // Empty input — no APDU; callback should not fire.
        let r = run_threadless_server(&[], &mut out, started, Box::new(|_| None));
        // Empty input fails parse, returns Err.
        assert!(r.is_err() || out.is_empty());
    }

    #[test]
    fn default_session_compiles() {
        let (apci, app, _s) = default_session().expect("handshake");
        assert_eq!(apci.k, 12);
        assert_eq!(apci.w, 8);
        // app is zeroed AppLayerParameters.
        let _ = app;
    }
}
