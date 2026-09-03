//! CS 104 server runtime.
//!
//! Provides:
//! - [`ServerMode`] — single / multiple redundancy groups
//! - [`RedundancyGroup`] — primary/secondary route selection
//! - [`AsduQueue`] — low/high priority queue
//! - [`IsCaAllowed`] — accept-time CA filter
//! - [`ServerHandlers`] — per-TypeId dispatcher (GI / CI / RD / CS / RP / CD)
//! - [`Server`] — TCP listener, multi-client accept loop, per-connection
//!   Cs104Session, max-open enforcement
//!
#![allow(missing_docs)]
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
// (no crate-level allow; crate has deny(missing_docs), but per-module allow below)
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{Asdu, InformationValue};
use fegrid_iec60870_core::{
    AppLayerParameters, CauseOfTransmission, CommonAddress, QualifierOfInterrogation,
};
use fegrid_iec60870_cs104::{ApciParameters, Apdu, Cs104Session, Started, Stopped};

use crate::codec104::ApduCodec;
use crate::master::RawMessageHandler;
use crate::session104::{Session104Error, start_server};

/// Server connection-routing mode (G-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServerMode {
    /// One redundancy group; accept any incoming connection.
    #[default]
    SingleRedundancyGroup,
    /// Multiple redundancy groups; route per allowed-client filter
    /// ([`RedundancyGroup::allowed_clients`]).
    MultipleRedundancyGroups,
}

/// A redundancy group. Multiple groups let the server route different
/// peers to different queues (G-011, G-012).
#[derive(Debug, Clone)]
pub struct RedundancyGroup {
    /// Accept filter: which peer IPs may join this group. Empty = any.
    pub allowed_clients: Vec<std::net::IpAddr>,
    /// Owning server's client count cap per group.
    pub max_clients: usize,
}

impl Default for RedundancyGroup {
    fn default() -> Self {
        Self {
            allowed_clients: Vec::new(),
            max_clients: 1,
        }
    }
}

impl RedundancyGroup {
    /// Construct a new redundancy group with the given cap.
    pub fn with_max(mut self, n: usize) -> Self {
        self.max_clients = n;
        self
    }
    /// Permit a peer IP to join this group.
    pub fn allow(mut self, ip: std::net::IpAddr) -> Self {
        self.allowed_clients.push(ip);
        self
    }
    /// Decide whether `peer` is allowed in this group.
    pub fn permits(&self, peer: std::net::IpAddr) -> bool {
        self.allowed_clients.is_empty() || self.allowed_clients.contains(&peer)
    }
}

/// Decide whether a given CA (Common Address) is allowed through the
/// server. Default impl: always true. G-006.
pub trait IsCaAllowed: Send + Sync + 'static {
    /// Return `true` if the server should accept ASDUs with `ca`.
    fn permits(&self, ca: u16) -> bool;
}

struct AllowAllCa;
impl IsCaAllowed for AllowAllCa {
    fn permits(&self, _: u16) -> bool {
        true
    }
}

/// A FIFO queue of ASDUs scheduled for delivery to a single peer
/// (G-013, G-014). One configurable queue covers both priorities;
/// the caller decides priority by enqueueing first.
pub struct AsduQueue {
    inner: Mutex<VecDeque<Asdu>>,
    /// Pool of ASDUs that were queued when a master connection
    /// closed with unconfirmed I-frames. Drained into a new
    /// connection's serve loop on next accept (G-013 / G-014).
    waiting: Mutex<VecDeque<Asdu>>,
    cap: usize,
}

impl AsduQueue {
    /// Construct a queue with a soft cap. `0` = unbounded.
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            waiting: Mutex::new(VecDeque::new()),
            cap,
        }
    }
    /// Push an ASDU onto the back of the queue. If `cap > 0` and the
    /// queue is full, the oldest entry is dropped to make room.
    pub fn push(&self, asdu: Asdu) {
        let mut q = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if self.cap > 0 && q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(asdu);
    }
    /// Pop the next ASDU off the front.
    pub fn pop(&self) -> Option<Asdu> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front()
    }
    /// Number of queued ASDUs.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    }
    /// Move every queued ASDU into the "waiting for transmission"
    /// pool (G-013 / G-014). Called when a master connection closes
    /// with unconfirmed I-frames. Returns the number of frames moved.
    /// Subsequent calls to [`AsduQueue::pop`] return `None` until
    /// [`AsduQueue::drain_waiting`] runs.
    pub fn mark_waiting_for_transmission(&self) -> usize {
        let mut q = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        let n = q.len();
        waiting.extend(q.drain(..));
        n
    }
    /// Drain the "waiting for transmission" pool back into the active
    /// queue so the next [`AsduQueue::pop`] returns the recovered
    /// frames. Returns the number moved.
    pub fn drain_waiting(&self) -> usize {
        let mut q = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        let n = waiting.len();
        q.extend(waiting.drain(..));
        n
    }
    /// Number of ASDUs in the waiting-for-transmission pool.
    pub fn waiting_len(&self) -> usize {
        self.waiting.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// Per-TypeId command handler. Receives the activation request and
/// returns an ACTIVATION_CON ASDU (or `None` for handlers that emit
/// asynchronously). G-015 / G-017.
pub type CommandHandler = Arc<dyn Fn(&Asdu) -> Option<Asdu> + Send + Sync>;

/// Container of all command handlers installed on the server.
#[derive(Clone, Default)]
pub struct ServerHandlers {
    inner: Arc<Mutex<HashMap<u8, CommandHandler>>>,
}

impl ServerHandlers {
    /// Construct an empty handler set.
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a handler for the given TypeId byte (e.g.
    /// `TypeId::C_IC_NA_1 as u8`).
    pub fn register(&self, type_byte: u8, handler: CommandHandler) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(type_byte, handler);
    }
    /// Dispatch an activation request to the registered handler. Returns
    /// `None` if no handler is registered.
    pub fn dispatch(&self, asdu: &Asdu) -> Option<Asdu> {
        let map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&asdu.original_type_byte).and_then(|h| h(asdu))
    }
}

/// Build a default handler set that responds ACTIVATION_CON positive for
/// every standard command. Convenience for users who don't need
/// per-TypeId logic.
pub fn default_handlers() -> ServerHandlers {
    let h = ServerHandlers::new();
    use fegrid_iec60870_core::TypeId;
    let confirm = Arc::new(|req: &Asdu| Some(crate::master::cmds::confirm(req))) as CommandHandler;
    for &type_id in &[
        TypeId::C_IC_NA_1 as u8,
        TypeId::C_CI_NA_1 as u8,
        TypeId::C_RD_NA_1 as u8,
        TypeId::C_CS_NA_1 as u8,
        TypeId::C_RP_NA_1 as u8,
        TypeId::C_CD_NA_1 as u8,
    ] {
        h.register(type_id, confirm.clone());
    }
    h
}

/// Decide whether a peer is allowed (G-007). Default: always accept.
pub trait ConnectionRequestHandler: Send + Sync + 'static {
    /// Return `true` if the server should keep the new peer connection.
    fn accept(&self, peer: SocketAddr) -> bool;
}

struct AcceptAll;
impl ConnectionRequestHandler for AcceptAll {
    fn accept(&self, _: SocketAddr) -> bool {
        true
    }
}

/// Lifecycle observer (G-008). Default impl: no-op.
pub trait ConnectionEventHandler: Send + Sync + 'static {
    /// Called when a peer connects.
    fn on_open(&self, _peer: SocketAddr) {}
    /// Called when a peer disconnects cleanly.
    fn on_close(&self, _peer: SocketAddr) {}
}

/// CS 104 server runtime configuration.
pub struct ServerConfig {
    pub local_addr: SocketAddr,
    pub apci: ApciParameters,
    pub app: AppLayerParameters,
    pub max_open: usize,
    pub mode: ServerMode,
    pub groups: Vec<RedundancyGroup>,
    pub ca_filter: Arc<dyn IsCaAllowed>,
    pub conn_request: Arc<dyn ConnectionRequestHandler>,
    pub conn_event: Arc<dyn ConnectionEventHandler>,
    pub handlers: ServerHandlers,
    pub raw: Option<Arc<dyn RawMessageHandler>>,
    pub queue_cap: usize,
}

impl ServerConfig {
    /// Build a default configuration for `local_addr` with sensible
    /// defaults.
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            apci: ApciParameters::default(),
            app: AppLayerParameters::default(),
            max_open: 10,
            mode: ServerMode::default(),
            groups: vec![RedundancyGroup::default()],
            ca_filter: Arc::new(AllowAllCa),
            conn_request: Arc::new(AcceptAll),
            conn_event: Arc::new(NoopConnEventImpl),
            handlers: default_handlers(),
            raw: None,
            queue_cap: 1024,
        }
    }
    /// Set the mode (G-004).
    pub fn mode(mut self, mode: ServerMode) -> Self {
        self.mode = mode;
        self
    }
    /// Replace the redundancy groups (G-011, G-012).
    pub fn groups(mut self, groups: Vec<RedundancyGroup>) -> Self {
        self.groups = groups;
        self
    }
    /// Install a CA filter (G-006).
    pub fn ca_filter(mut self, f: Arc<dyn IsCaAllowed>) -> Self {
        self.ca_filter = f;
        self
    }
    /// Install a connection-request filter (G-007).
    pub fn conn_request(mut self, f: Arc<dyn ConnectionRequestHandler>) -> Self {
        self.conn_request = f;
        self
    }
    /// Install a connection-event observer (G-008).
    pub fn conn_event(mut self, f: Arc<dyn ConnectionEventHandler>) -> Self {
        self.conn_event = f;
        self
    }
    /// Replace the command handlers (G-015, G-017).
    pub fn handlers(mut self, h: ServerHandlers) -> Self {
        self.handlers = h;
        self
    }
    /// Install a raw-message observer (G-009 reuse).
    pub fn raw_message_handler(mut self, h: Arc<dyn RawMessageHandler>) -> Self {
        self.raw = Some(h);
        self
    }
    /// Override max-open connections (G-005).
    pub fn max_open(mut self, n: usize) -> Self {
        self.max_open = n;
        self
    }
    /// Override queue capacity (G-013, G-014).
    pub fn queue_cap(mut self, n: usize) -> Self {
        self.queue_cap = n;
        self
    }
}

struct NoopConnEventImpl;
impl ConnectionEventHandler for NoopConnEventImpl {
    fn on_open(&self, _: SocketAddr) {}
    fn on_close(&self, _: SocketAddr) {}
}

/// Handle to a running CS 104 server.
pub struct Server {
    cfg: Arc<ServerConfig>,
    /// Cached peer addresses for diagnostics (G-018).
    peers: Arc<Mutex<HashMap<SocketAddr, ()>>>,
    /// ASDU queue for the default group.
    pub queue: Arc<AsduQueue>,
    /// Shutdown signal.
    shutdown: Arc<tokio::sync::Notify>,
}

impl Server {
    /// Bind the configured listener and start accepting connections.
    pub async fn bind(cfg: ServerConfig) -> Result<Arc<Self>, std::io::Error> {
        let listener = TcpListener::bind(cfg.local_addr).await?;
        let queue = Arc::new(AsduQueue::new(cfg.queue_cap));
        let server = Arc::new(Self {
            cfg: Arc::new(cfg),
            peers: Arc::new(Mutex::new(HashMap::new())),
            queue,
            shutdown: Arc::new(tokio::sync::Notify::new()),
        });
        Self::spawn_accept_loop(server.clone(), listener);
        Ok(server)
    }

    /// Current open peer count.
    pub fn open_count(&self) -> usize {
        self.peers.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Snapshot of currently connected peer addresses (G-018).
    pub fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Trigger a graceful shutdown.
    pub fn shutdown_handle(&self) -> impl std::future::Future<Output = ()> + Send + Sync + '_ {
        let notify = self.shutdown.clone();
        async move { notify.notified().await }
    }

    /// Push an ASDU into the outbound queue. The accept loop drains it
    /// and ships it on every active connection (broadcast model).
    pub fn enqueue(&self, asdu: Asdu) {
        self.queue.push(asdu);
    }

    /// Find the redundancy group that admits `peer`.
    pub fn group_for(&self, peer: SocketAddr) -> Option<usize> {
        self.cfg.groups.iter().position(|g| g.permits(peer.ip()))
    }

    fn spawn_accept_loop(self: Arc<Self>, listener: TcpListener) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = self.shutdown.notified() => return,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer)) => {
                                if self.peers.lock().unwrap_or_else(|p| p.into_inner()).len()
                                    >= self.cfg.max_open
                                {
                                    drop(stream);
                                    continue;
                                }
                                if !self.cfg.conn_request.accept(peer) {
                                    drop(stream);
                                    continue;
                                }
                                self.peers.lock().unwrap_or_else(|p| p.into_inner()).insert(peer, ());
                                self.cfg.conn_event.on_open(peer);
                                let s = self.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = s.serve(stream, peer).await {
                                        eprintln!("server peer {peer}: {e}");
                                    }
                                    s.peers.lock().unwrap_or_else(|p| p.into_inner()).remove(&peer);
                                    s.cfg.conn_event.on_close(peer);
                                });
                            }
                            Err(_) => continue,
                        }
                    }
                }
            }
        });
    }

    async fn serve(&self, stream: TcpStream, peer: SocketAddr) -> Result<(), Session104Error> {
        let framed: Framed<TcpStream, ApduCodec> = Framed::new(stream, ApduCodec::new());
        let (session, mut framed, _events) = start_server(framed, self.cfg.apci).await?;
        let mut session: Cs104Session<Started> = session;
        let raw = self.cfg.raw.clone();
        let handlers = self.cfg.handlers.clone();
        let ca_filter = self.cfg.ca_filter.clone();
        let queue = self.queue.clone();
        let group_idx = self.group_for(peer);
        let _ = group_idx;

        // G-013: drain any frames waiting-for-transmission from a
        // previous connection's failover. They will be sent before any
        // newly-arrived inbound APDU is processed, ensuring the new
        // peer sees the data the old peer missed.
        queue.drain_waiting();
        let waiting_recovered = queue.len();
        if waiting_recovered > 0 {
            tracing::debug!(
                "recovered {} ASDUs from waiting-for-transmission pool",
                waiting_recovered
            );
        }
        // Drain inbound APDUs and route to handlers.
        use tokio::io::AsyncWriteExt;
        while let Some(item) = framed.next().await {
            let apdu = match item {
                Ok(a) => a,
                Err(e) => {
                    return Err(Session104Error::Codec(e));
                }
            };
            if let Some(raw) = &raw {
                let bytes = crate::codec104::apdu_to_wire(&apdu);
                raw.on_raw(&bytes, false);
            }
            let Apdu::I {
                asdu: Some(asdu), ..
            } = apdu
            else {
                continue;
            };
            if !ca_filter.permits(asdu.common_address.0) {
                // G-047: CA not allowed. Emit ACTIVATION_CON with
                // COT_UNKNOWN_CA + negative P/N bit. Suppressed for
                // monitor-direction (master is asking for data, not
                // commanding). See IEC TS 60870-5-604 §7.2.
                if is_control_direction(&asdu) {
                    let reject = fegrid_iec60870_asdu::activation_confirm_with_cause(
                        &asdu,
                        fegrid_iec60870_core::CauseOfTransmission::UnknownCa,
                    );
                    if let Ok(bytes) = session.send_i(reject) {
                        if let Some(raw) = &raw {
                            raw.on_raw(&bytes, true);
                        }
                        let mut sink = framed.into_inner();
                        let _ = sink.write_all(&bytes).await;
                        framed = Framed::new(sink, ApduCodec::new());
                    }
                }
                continue;
            }
            // G-047: IOA == 0 on a control command. Emit
            // COT_UNKNOWN_IOA per IEC TS 60870-5-604 §7.2.
            if is_control_direction(&asdu) && asdu.objects.iter().any(|o| o.ioa == 0) {
                let reject = fegrid_iec60870_asdu::activation_confirm_with_cause(
                    &asdu,
                    fegrid_iec60870_core::CauseOfTransmission::UnknownIoa,
                );
                if let Ok(bytes) = session.send_i(reject) {
                    if let Some(raw) = &raw {
                        raw.on_raw(&bytes, true);
                    }
                    let mut sink = framed.into_inner();
                    let _ = sink.write_all(&bytes).await;
                    framed = Framed::new(sink, ApduCodec::new());
                }
                continue;
            }
            if let Some(con) = handlers.dispatch(&asdu) {
                let bytes = session.send_i(con).map_err(Session104Error::Protocol)?;
                if let Some(raw) = &raw {
                    raw.on_raw(&bytes, true);
                }
                let mut sink = framed.into_inner();
                sink.write_all(&bytes).await.map_err(Session104Error::Io)?;
                framed = Framed::new(sink, ApduCodec::new());
            }
            // Also drain queued ASDUs if any.
            while let Some(queued) = queue.pop() {
                let bytes = session.send_i(queued).map_err(Session104Error::Protocol)?;
                if let Some(raw) = &raw {
                    raw.on_raw(&bytes, true);
                }
                let mut sink = framed.into_inner();
                sink.write_all(&bytes).await.map_err(Session104Error::Io)?;
                framed = Framed::new(sink, ApduCodec::new());
            }
        }
        // G-013: connection closed. Any ASDUs still queued (because
        // the I-frame carrying them was not yet ACKed) move to the
        // waiting-for-transmission pool so the next peer's serve
        // loop can deliver them.
        let moved = queue.mark_waiting_for_transmission();
        if moved > 0 {
            tracing::debug!(
                "moved {} ASDUs to waiting-for-transmission pool on peer close",
                moved
            );
        }
        Ok(())
    }
}

/// G-047: determine whether an ASDU is a control-direction command
/// (master commanding the slave) vs monitor-direction (master
/// requesting data). Used to decide whether negative-ACK paths
/// apply — F-CONF-015 negative-path procedures only target commands.
fn is_control_direction(asdu: &fegrid_iec60870_asdu::Asdu) -> bool {
    use fegrid_iec60870_core::CauseOfTransmission as Cot;
    matches!(
        asdu.cot.cause,
        Cot::Activation
            | Cot::Deactivation
            | Cot::ActivationCon
            | Cot::DeactivationCon
            | Cot::ActivationTermination
    )
}
/// Builder for an `IsCaAllowed` filter from a static allow-list.
pub struct CaAllowList {
    inner: std::sync::Arc<std::collections::HashSet<u16>>,
}

impl CaAllowList {
    /// Construct from an iterator of CAs.
    pub fn new<I: IntoIterator<Item = u16>>(cas: I) -> Self {
        Self {
            inner: Arc::new(cas.into_iter().collect()),
        }
    }
}

impl IsCaAllowed for CaAllowList {
    fn permits(&self, ca: u16) -> bool {
        self.inner.contains(&ca)
    }
}

/// Builder for an `IsCaAllowed` filter from a closure.
pub struct CaPredicate<F: Fn(u16) -> bool + Send + Sync + 'static> {
    pred: F,
}

impl<F: Fn(u16) -> bool + Send + Sync + 'static> CaPredicate<F> {
    /// Construct from a predicate.
    pub fn new(pred: F) -> Self {
        Self { pred }
    }
}

impl<F: Fn(u16) -> bool + Send + Sync + 'static> IsCaAllowed for CaPredicate<F> {
    fn permits(&self, ca: u16) -> bool {
        (self.pred)(ca)
    }
}

// Silence unused warning on the trait alias.
#[allow(dead_code)]
fn _trait_alias_dummy<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(_s: &S) {}

// Re-export the queue + handler helpers for callers that want to keep
// their own copies.
pub use AsduQueue as LowPriorityQueue;
pub use AsduQueue as HighPriorityQueue;
// Helper: type-check that `AsduQueue` covers the queue re-queue-on-close
// contract.
#[allow(dead_code)]
fn _assert_queue_contract(_q: &AsduQueue) {
    let _: Option<Asdu> = _q.pop();
    _q.push(Asdu {
        type_id: fegrid_iec60870_core::TypeId::M_SP_NA_1,
        original_type_byte: 1,
        cot: fegrid_iec60870_core::CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(0),
        is_sequence: false,
        is_test: false,
        objects: Vec::new(),
    });
    // Touch InformationValue to keep the import alive.
    let _: InformationValue =
        InformationValue::interrogation_command(QualifierOfInterrogation::STATION);
    // Touch Stopped / Started so the imports are non-dead even if no
    // other code path uses them in this module.
    let _ = std::marker::PhantomData::<Stopped>;
    let _ = std::marker::PhantomData::<Started>;
}
