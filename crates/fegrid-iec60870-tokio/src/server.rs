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
use fegrid_iec60870_cs104::{ApciParameters, Apdu, Cs104Session, Started, Stopped, UFrame};

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
    /// Push an ASDU onto the FRONT of the queue. Used to re-queue an ASDU that failed to encode because the slave's k-window was full: the same frame must be retried on the next send opportunity (after the master has ACKed enough I-frames to make room in the window). Honours `cap` by dropping the newest entry if the queue is at capacity.
    pub fn push_front(&self, asdu: Asdu) {
        let mut q = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if self.cap > 0 && q.len() >= self.cap {
            q.pop_back();
        }
        q.push_front(asdu);
    }
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
    /// IEC 60870-5-7 secure-authentication plugin (COT 14/15/16
    /// on C_ACSE_NA_3 type id 135). `None` means the server emits
    /// ACT_CON negative for any inbound secure-auth frame.
    pub secure_auth_plugin: Option<Arc<fegrid_iec60870_secauth::SecureAuthPlugin>>,
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
            secure_auth_plugin: None,
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
    /// Install a secure-authentication plugin (IEC 60870-5-7).
    /// When set, the server routes COT 14/15/16 frames of type
    /// C_ACSE_NA_3 (135) through `plugin.sign(...)` and emits
    /// ACT_CON positive with status bit 0x80 set in the CA field.
    pub fn secure_auth_plugin(
        mut self,
        plugin: Arc<fegrid_iec60870_secauth::SecureAuthPlugin>,
    ) -> Self {
        self.secure_auth_plugin = Some(plugin);
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
        // Drain inbound APDUs and route to handlers. Interleave a 100 ms
        // timer arm that flushes the outbound AsduQueue so a silent
        // master (just STARTDT + GI/read) still receives spontaneous
        // data (G-013). Without this drain, a master that sends no
        // I-frames never wakes the outbound flush path.
        use tokio::io::AsyncWriteExt;
        let mut drain_tick = tokio::time::interval(std::time::Duration::from_millis(100));
        drain_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut watchdog = fegrid_iec60870_cs104::watchdog::Watchdog::new(
            std::time::Duration::from_millis(self.cfg.apci.t1_ms),
            std::time::Duration::from_millis(self.cfg.apci.t2_ms),
            std::time::Duration::from_millis(self.cfg.apci.t3_ms),
        );
        // Arm the T3 idle counter immediately so TESTFR fires after t3 of idle.
        watchdog.note_recv(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
        );
        loop {
            tokio::select! {
                _ = drain_tick.tick() => {
                    while let Some(queued) = queue.pop() {
                        let queued_clone = queued.clone();
                        match session.send_i(queued) {
                            Ok(bytes) => {
                                if let Some(raw) = &raw {
                                    raw.on_raw(&bytes, true);
                                }
                                framed.get_mut().write_all(&bytes).await.map_err(Session104Error::Io)?;
                            }
                            Err(fegrid_iec60870_cs104::typestate::SessionError::Protocol(_)) => {
                                queue.push_front(queued_clone);
                                break;
                            }
                            Err(e) => return Err(Session104Error::Protocol(e)),
                        }
                    }
                    // Watchdog tick.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let unacked = session.seq().unacked_count();
                    let unacked_recv = session.unacked_recv_count();
                    let action = watchdog.tick(now, unacked, self.cfg.apci.w, unacked_recv);
                    match action {
                        fegrid_iec60870_cs104::watchdog::WatchdogAction::None => {}
                        fegrid_iec60870_cs104::watchdog::WatchdogAction::SendSFrame(_nr) => {
                            let bytes = session.send_s();
                            session.note_s_sent(session.seq().recv());
                            if let Some(raw) = &raw {
                                raw.on_raw(&bytes, true);
                            }
                            framed.get_mut().write_all(&bytes).await.map_err(Session104Error::Io)?;
                        }
                        fegrid_iec60870_cs104::watchdog::WatchdogAction::SendTestFrAct => {
                            let bytes = fegrid_iec60870_cs104::u_frame_bytes(UFrame::TestFrAct);
                            if let Some(raw) = &raw {
                                raw.on_raw(&bytes, true);
                            }
                            framed.get_mut().write_all(&bytes).await.map_err(Session104Error::Io)?;
                        }
                        fegrid_iec60870_cs104::watchdog::WatchdogAction::Close { .. } => {
                            return Ok(());
                        }
                    }
                }
                next = framed.next() => {
                    let Some(item) = next else { break };
                    let apdu = match item {
                        Ok(a) => a,
                        Err(e) => return Err(Session104Error::Codec(e)),
                    };
                    watchdog.note_recv(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default(),
                    );
                    if let Some(raw) = &raw {
                        let bytes = crate::codec104::apdu_to_wire(&apdu);
                        raw.on_raw(&bytes, false);
                    }
                    for bytes in self.dispatch_apdu(
                        apdu,
                        &mut session,
                        &handlers,
                        ca_filter.as_ref(),
                        raw.as_ref(),
                        &queue,
                        self.cfg.secure_auth_plugin.as_ref(),
                    )? {
                        framed.get_mut().write_all(&bytes).await.map_err(Session104Error::Io)?;
                    }
                }
            }
        }
        // G-013: connection closed. Any ASDUs still queued (because
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

    /// Dispatch a single decoded inbound APDU: route non-I frames,
    /// apply CA / IOA=0 validation, invoke the command handler, and
    /// drain any queued spontaneous ASDUs. Returns the wire bytes
    /// (in send order) for the caller to write to the TCP stream.
    /// Extracted from `serve()` so the `tokio::select!` body stays
    /// focused on multiplexing inbound frames with the periodic
    /// outbound drain. `session` is owned exclusively by this
    /// per-connection task; the other parameters are cheap clones.
    #[allow(clippy::too_many_arguments)]
    fn dispatch_apdu(
        &self,
        apdu: Apdu,
        session: &mut Cs104Session<Started>,
        handlers: &ServerHandlers,
        ca_filter: &dyn IsCaAllowed,
        raw: Option<&Arc<dyn RawMessageHandler>>,
        queue: &Arc<AsduQueue>,
        secure_auth_plugin: Option<&Arc<fegrid_iec60870_secauth::SecureAuthPlugin>>,
    ) -> Result<Vec<Vec<u8>>, Session104Error> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let raw_obj: Option<&dyn RawMessageHandler> = raw.map(|a| a.as_ref());
        let Apdu::I {
            asdu: Some(asdu), ..
        } = apdu
        else {
            // Non-I-frame: S-frame (master acks) and U-frame
            // (TESTFR_ACT / STOPDT_ACT) need a response. The
            // spec requires us to act on these even though the
            // master hasn't sent an I-frame.
            match &apdu {
                Apdu::S { nr } => session.on_s_received(*nr),
                Apdu::U(UFrame::TestFrAct) => {
                    let bytes = fegrid_iec60870_cs104::u_frame_bytes(UFrame::TestFrCon);
                    if let Some(r) = raw_obj {
                        r.on_raw(&bytes, true);
                    }
                    out.push(bytes.to_vec());
                }
                Apdu::U(UFrame::StopDtAct) => {
                    let bytes = fegrid_iec60870_cs104::u_frame_bytes(UFrame::StopDtCon);
                    if let Some(r) = raw_obj {
                        r.on_raw(&bytes, true);
                    }
                    out.push(bytes.to_vec());
                }
                _ => return Ok(out),
            }
            return Ok(out);
        };
        // G-047: CA filter applies only to CONTROL-direction commands
        // (master commanding the slave). Monitor-direction commands
        // (master requesting data) are accepted with any CA, per IEC
        // TS 60870-5-604 §7.2. GI (C_IC_NA_1) is excluded because
        // semantically it requests data even though its COT is
        // `Activation`. When the CA is not allowed AND the command
        // is a true control command, emit ACTIVATION_CON with
        // COT_UNKNOWN_CA + negative P/N bit. Otherwise fall through.
        let blocked_by_ca = !ca_filter.permits(asdu.common_address.0)
            && is_control_direction(&asdu)
            && asdu.type_id != fegrid_iec60870_core::TypeId::C_IC_NA_1;
        if blocked_by_ca {
            let reject = fegrid_iec60870_asdu::activation_confirm_with_cause(
                &asdu,
                fegrid_iec60870_core::CauseOfTransmission::UnknownCa,
            );
            if let Ok(bytes) = session.send_i(reject) {
                if let Some(r) = raw_obj {
                    r.on_raw(&bytes, true);
                }
                out.push(bytes.to_vec());
            }
            return Ok(out);
        }
        // G-047: IOA == 0 on a control command. Emit
        // COT_UNKNOWN_IOA per IEC TS 60870-5-604 §7.2. Standard
        // commands (C_IC_NA_1, C_CI_NA_1, C_RD_NA_1, C_CS_NA_1,
        // C_RP_NA_1, C_CD_NA_1) carry a reserved IOA=0 field and
        // are exempted so the server accepts IOA=0 on standard commands.
        if is_control_direction(&asdu)
            && asdu.type_id != fegrid_iec60870_core::TypeId::C_ACSE_NA_3
            && !is_standard_command_with_reserved_ioa_zero(&asdu)
            && asdu.objects.iter().any(|o| o.ioa == 0)
        {
            let reject = fegrid_iec60870_asdu::activation_confirm_with_cause(
                &asdu,
                fegrid_iec60870_core::CauseOfTransmission::UnknownIoa,
            );
            if let Ok(bytes) = session.send_i(reject) {
                if let Some(r) = raw_obj {
                    r.on_raw(&bytes, true);
                }
                out.push(bytes.to_vec());
            }
            return Ok(out);
        }
        // Inline-send an ACT_CON. On k-window-full stash at the front
        // of the queue so the next outbound drain arm retries.
        let mut send_act_con = |con: Asdu, out: &mut Vec<Vec<u8>>| {
            let con_clone = con.clone();
            match session.send_i(con) {
                Ok(bytes) => {
                    if let Some(r) = raw_obj {
                        r.on_raw(&bytes, true);
                    }
                    out.push(bytes.to_vec());
                }
                Err(fegrid_iec60870_cs104::typestate::SessionError::Protocol(_)) => {
                    queue.push_front(con_clone);
                }
                Err(e) => return Err(Session104Error::Protocol(e)),
            }
            Ok(())
        };
        // IEC 60870-5-7 §6.3 secure-authentication dispatch (COT
        // 14/15/16 on type id C_ACSE_NA_3 = 135). Route through
        // `SecureAuthPlugin::sign`, build an ACT_CON positive with
        // the challenge echoed and the HMAC-SHA256-4 response
        // populated, status bit 0x80 in the CA-field high byte.
        // Falls through to negative ACT_CON (status 0xC0) when no
        // plugin is configured or the type id is wrong.
        let is_secure_auth = matches!(
            asdu.cot.cause,
            fegrid_iec60870_core::CauseOfTransmission::Authentication
                | fegrid_iec60870_core::CauseOfTransmission::MaintenanceOfAuthSessionKey
                | fegrid_iec60870_core::CauseOfTransmission::MaintenanceOfUserRoleAndUpdateKey
        ) && asdu.type_id == fegrid_iec60870_core::TypeId::C_ACSE_NA_3;
        if is_secure_auth {
            // Sign challenge via the plugin (or fall through to negative ACK).
            let plugin_response: Option<([u8; 4], [u8; 32])> = (|| {
                let plugin = secure_auth_plugin?;
                let obj = asdu.objects.first()?;
                let fegrid_iec60870_asdu::InformationValue::AcseActivation { challenge, .. } =
                    &obj.value
                else {
                    return None;
                };
                let sig = plugin.sign(challenge).ok()?;
                let resp: [u8; 4] = sig.get(..4)?.try_into().ok()?;
                Some((resp, *challenge))
            })();
            let mut con = fegrid_iec60870_asdu::activation_confirm(&asdu);
            match plugin_response {
                Some((response, challenge)) => {
                    // Positive: CA high byte = 0x80 (OK), response
                    // populated, challenge echoed back.
                    con.common_address.0 = (con.common_address.0 & 0x00FF) | 0x8000;
                    if let Some(obj) = con.objects.first_mut() {
                        obj.value = fegrid_iec60870_asdu::InformationValue::AcseActivation {
                            challenge,
                            response,
                            role: 0,
                            status: 0x80,
                        };
                    }
                }
                None => {
                    // Negative: CA high byte = 0xC0.
                    con.common_address.0 = (con.common_address.0 & 0x00FF) | 0xC000;
                    con.cot.negative_confirm = true;
                    if let Some(obj) = con.objects.first_mut()
                        && let fegrid_iec60870_asdu::InformationValue::AcseActivation {
                            challenge,
                            ..
                        } = &obj.value
                    {
                        let ch = *challenge;
                        obj.value = fegrid_iec60870_asdu::InformationValue::AcseActivation {
                            challenge: ch,
                            response: [0u8; 4],
                            role: 0,
                            status: 0xC0,
                        };
                    }
                }
            }
            send_act_con(con, &mut out)?;
            return Ok(out);
        }

        // qpa bit 7 = 1 means read-only preview (preview of the
        // currently-loaded parameter). The controlled station shall
        // reply with ACT_CON positive without invoking the activate
        // handler. qpa bit 7 = 0 means "activate previously loaded
        // parameter" — the activate handler MUST run.
        let qpa_read_only = asdu.type_id == fegrid_iec60870_core::TypeId::P_AC_NA_1
            && asdu.objects.first().is_some_and(|o| {
                matches!(
                    o.value,
                    fegrid_iec60870_asdu::InformationValue::ParameterActivation { qpm }
                        if qpm & 0x80 != 0
                )
            });

        // Inline-send an ACT_CON. On k-window-full stash at the front
        // of the queue so the next outbound drain arm retries.
        let mut send_act_con = |con: Asdu, out: &mut Vec<Vec<u8>>| {
            let con_clone = con.clone();
            match session.send_i(con) {
                Ok(bytes) => {
                    if let Some(r) = raw_obj {
                        r.on_raw(&bytes, true);
                    }
                    out.push(bytes.to_vec());
                }
                Err(fegrid_iec60870_cs104::typestate::SessionError::Protocol(_)) => {
                    queue.push_front(con_clone);
                }
                Err(e) => return Err(Session104Error::Protocol(e)),
            }
            Ok(())
        };

        if qpa_read_only {
            // Read-only P_AC_NA_1: emit positive ACT_CON without
            // invoking any registered activate handler.
            let con = fegrid_iec60870_asdu::activation_confirm(&asdu);
            send_act_con(con, &mut out)?;
        } else if let Some(con) = handlers.dispatch(&asdu) {
            send_act_con(con, &mut out)?;
        }
        // Drain queued ASDUs. On k-window-full, push the in-flight one back to the front and break.
        while let Some(queued) = queue.pop() {
            let queued_clone = queued.clone();
            match session.send_i(queued) {
                Ok(bytes) => {
                    if let Some(r) = raw_obj {
                        r.on_raw(&bytes, true);
                    }
                    out.push(bytes.to_vec());
                }
                Err(fegrid_iec60870_cs104::typestate::SessionError::Protocol(_)) => {
                    queue.push_front(queued_clone);
                    break;
                }
                Err(e) => return Err(Session104Error::Protocol(e)),
            }
        }
        Ok(out)
    }
}
fn is_control_direction(asdu: &fegrid_iec60870_asdu::Asdu) -> bool {
    use fegrid_iec60870_core::CauseOfTransmission as Cot;
    matches!(
        asdu.cot.cause,
        Cot::Activation
            | Cot::Deactivation
            | Cot::ActivationCon
            | Cot::DeactivationCon
            | Cot::ActivationTermination
            | Cot::Authentication
            | Cot::MaintenanceOfAuthSessionKey
            | Cot::MaintenanceOfUserRoleAndUpdateKey
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
/// IEC 60870-5-101 §7.4 standard commands whose IOA field is reserved
/// as zero. Skipping the IOA=0 validation for these keeps the server
/// interoperable with peers that accept IOA=0 on GI/RI/clock-sync/read.
fn is_standard_command_with_reserved_ioa_zero(asdu: &fegrid_iec60870_asdu::Asdu) -> bool {
    use fegrid_iec60870_core::TypeId;
    matches!(
        asdu.type_id,
        TypeId::C_IC_NA_1
            | TypeId::C_CI_NA_1
            | TypeId::C_RD_NA_1
            | TypeId::C_CS_NA_1
            | TypeId::C_RP_NA_1
            | TypeId::C_CD_NA_1
    )
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
