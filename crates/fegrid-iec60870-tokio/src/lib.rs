//! Async tokio transport for IEC 60870-5-101/104.
//!
//! Module map:
//! - [`codec104`]: CS 104 framing over [`tokio_util::codec::Decoder`].
//! - `tls104` *(feature `tls`)*: TLS-wrapped CS 104 transport
//!   (rustls 0.23 / ring).  Reuses [`codec104::ApduCodec`] over a
//!   `tokio_rustls::TlsStream<TcpStream>`; the protocol state machine
//!   stays in `fegrid_iec60870_cs104`.
//! - [`session104`]: async STARTDT drivers + [`ConnEvent`] lifecycle events.
//!
//! All protocol logic lives in the protocol crates
//! (`fegrid_iec60870_cs104`, `fegrid_iec60870_cs101`) — this
//! crate only adapts them to `tokio_util::codec` and provides helpers
//! for running a state machine over TCP / Serial / TLS.
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod codec104;
pub mod master;
pub mod run;
pub mod server;
pub mod session104;
#[cfg(feature = "tls")]
pub mod tls104;

pub use codec104::{ApduCodec, CodecError, apdu_to_wire};
pub use master::{Backpressure, MClient, RawMessageHandler, RawMessageRegistry, cmds};
pub use run::{AsduCallback, default_session, run_threadless_server};
pub use server::{
    AsduQueue,
    CaAllowList,
    CaPredicate,
    CommandHandler,
    ConnectionEventHandler,
    ConnectionRequestHandler,
    // queue aliases
    HighPriorityQueue,
    IsCaAllowed,
    LowPriorityQueue,
    RedundancyGroup,
    Server,
    ServerConfig,
    ServerHandlers,
    ServerMode,
    default_handlers,
};
pub use session104::{
    ConnEvent, IEC104_DEFAULT_PORT, Session104Error, start_client, start_server, stop_client,
    stop_server,
};
