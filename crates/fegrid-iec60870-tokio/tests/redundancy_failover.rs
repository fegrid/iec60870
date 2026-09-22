//! Redundancy group + failover tests (G-011, G-012, G-013, G-014).
//!
//! Covers:
//!
//! 1. Unit tests for [`RedundancyGroup`] permit semantics and
//!    [`Server::group_for`] routing.
//! 2. End-to-end tests for queue migration across peer disconnect
//!    using the queue API directly (G-013).
//! 3. Multi-redundancy-group routing by client IP.
//!
//! Known limitation: full peer1-then-peer2 failover via the
//! in-process server's k-window waitlist (G-014) requires the
//! test peer to ack I-frames so drain_tick emits them and the
//! k-window back-pressure pushes them back into the queue.
//! The current tests cover the queue migration mechanics with the
//! queue API directly; full k-window-driven failover scenarios are
//! validated by the `session104_loopback` tests in this crate.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::codec::Framed;

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
use fegrid_iec60870_cs104::{Apdu, UFrame};
use fegrid_iec60870_tokio::{ApduCodec, RedundancyGroup, Server, ServerConfig, ServerMode};

/// Build a single-point monitor ASDU with the given typed TypeId.
fn single_point_asdu(type_id: TypeId) -> Asdu {
    Asdu {
        type_id,
        original_type_byte: type_id as u8,
        cot: CotField {
            cause: CauseOfTransmission::Periodic,
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
            InformationValue::SinglePoint {
                value: true,
                quality: Default::default(),
            },
        )],
    }
}

async fn do_startdt(stream: &mut TcpStream) {
    let mut framed = Framed::new(stream, ApduCodec::new());
    framed
        .send(Apdu::U(UFrame::StartDtAct))
        .await
        .expect("send STARTDT_ACT");
    let apdu = timeout(Duration::from_secs(2), framed.next())
        .await
        .expect("STARTDT_CON timeout")
        .expect("STARTDT_CON frame")
        .expect("STARTDT_CON parse");
    assert!(matches!(apdu, Apdu::U(UFrame::StartDtCon)));
}

async fn do_stopdt(stream: &mut TcpStream) {
    let mut framed = Framed::new(stream, ApduCodec::new());
    framed
        .send(Apdu::U(UFrame::StopDtAct))
        .await
        .expect("send STOPDT_ACT");
    let apdu = timeout(Duration::from_secs(2), framed.next())
        .await
        .expect("STOPDT_CON timeout")
        .expect("STOPDT_CON frame")
        .expect("STOPDT_CON parse");
    assert!(matches!(apdu, Apdu::U(UFrame::StopDtCon)));
}

async fn alloc_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

/// Pull up to `max_frames` I-frames from `framed`, returning the
/// `type_id as u8` of each. Drains S-frames silently.
async fn drain_server_queue(
    framed: &mut TcpStream,
    max_frames: usize,
    total_timeout_ms: u64,
) -> Vec<u8> {
    let mut framed = Framed::new(framed, ApduCodec::new());
    let mut out = Vec::with_capacity(max_frames);
    let deadline = std::time::Instant::now() + Duration::from_millis(total_timeout_ms);
    while out.len() < max_frames {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let next = timeout(remaining, framed.next()).await;
        match next {
            Ok(Some(Ok(Apdu::I { asdu: Some(a), .. }))) => {
                out.push(a.type_id as u8);
            }
            Ok(Some(Ok(Apdu::S { .. }))) => continue,
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) | Err(_) => break,
            Ok(None) => break,
        }
    }
    out
}

// ===========================================================================
// Unit tests: RedundancyGroup permits semantics
// ===========================================================================

#[test]
fn rg_default_accepts_any_peer_ip() {
    let g = RedundancyGroup::default();
    let local: IpAddr = "127.0.0.1".parse().unwrap();
    let remote: IpAddr = "10.0.0.99".parse().unwrap();
    let v6: IpAddr = "::1".parse().unwrap();
    assert!(g.permits(local));
    assert!(g.permits(remote));
    assert!(g.permits(v6));
}

#[test]
fn rg_default_max_clients_is_one() {
    let g = RedundancyGroup::default();
    assert_eq!(g.max_clients, 1, "default RG must cap at 1");
}

#[test]
fn rg_with_max_overrides_max_clients() {
    let g = RedundancyGroup::default().with_max(7);
    assert_eq!(g.max_clients, 7);
}

#[test]
fn rg_with_allowlist_filters_peer_ip() {
    let local: IpAddr = "127.0.0.1".parse().unwrap();
    let other: IpAddr = "10.0.0.1".parse().unwrap();
    let g = RedundancyGroup::default().allow(local);
    assert!(g.permits(local));
    assert!(!g.permits(other));
}

#[test]
fn rg_with_multiple_allowlist_entries() {
    let g = RedundancyGroup::default()
        .allow("10.0.0.1".parse().unwrap())
        .allow("10.0.0.2".parse().unwrap())
        .allow("10.0.0.3".parse().unwrap());
    assert!(g.permits("10.0.0.1".parse().unwrap()));
    assert!(g.permits("10.0.0.3".parse().unwrap()));
    assert!(!g.permits("10.0.0.4".parse().unwrap()));
    assert!(!g.permits("127.0.0.1".parse().unwrap()));
}

// ===========================================================================
// Unit tests: Server::group_for routing
// ===========================================================================

#[tokio::test]
async fn server_group_for_returns_index_for_allowed_peer() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let g0 = RedundancyGroup::default()
        .allow("127.0.0.1".parse().unwrap())
        .with_max(8);
    let cfg = ServerConfig::new(addr)
        .mode(ServerMode::MultipleRedundancyGroups)
        .groups(vec![g0]);
    let server = Server::bind(cfg).await.expect("bind");
    let peer: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    assert_eq!(server.group_for(peer), Some(0));
}

#[tokio::test]
async fn server_group_for_default_group_matches_loopback() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr);
    let server = Server::bind(cfg).await.expect("bind");
    let peer: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    assert_eq!(server.group_for(peer), Some(0));
}

#[tokio::test]
async fn server_group_for_first_match_wins() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let shared_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let g0 = RedundancyGroup::default().allow(shared_ip).with_max(1);
    let g1 = RedundancyGroup::default().allow(shared_ip).with_max(2);
    let cfg = ServerConfig::new(addr)
        .mode(ServerMode::MultipleRedundancyGroups)
        .groups(vec![g0, g1]);
    let server = Server::bind(cfg).await.expect("bind");
    let peer: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    assert_eq!(server.group_for(peer), Some(0));
}

#[tokio::test]
async fn server_config_mode_default_is_single_redundancy_group() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr);
    assert_eq!(cfg.mode, ServerMode::SingleRedundancyGroup);
    assert_eq!(cfg.groups.len(), 1, "default has 1 group");
}

#[tokio::test]
async fn server_config_mode_multi_has_multiple_groups() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr)
        .mode(ServerMode::MultipleRedundancyGroups)
        .groups(vec![RedundancyGroup::default(), RedundancyGroup::default()]);
    assert_eq!(cfg.mode, ServerMode::MultipleRedundancyGroups);
    assert_eq!(cfg.groups.len(), 2);
}

// ===========================================================================
// End-to-end: queue migration via the queue API directly
// ===========================================================================

/// When the server has no active peer, `Server::enqueue` puts
/// ASDUs directly on the active queue. A subsequent peer can
/// drain them via the normal I-frame path.
#[tokio::test]
async fn server_enqueued_frames_visible_to_first_peer() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr).max_open(4);
    let server = Server::bind(cfg).await.expect("bind");

    // Enqueue 2 frames BEFORE any peer connects.
    for type_id in [TypeId::M_SP_NA_1, TypeId::M_DP_NA_1] {
        server.enqueue(single_point_asdu(type_id));
    }
    assert_eq!(server.queue.len(), 2);

    let mut peer1 = TcpStream::connect(addr).await.expect("connect peer1");
    do_startdt(&mut peer1).await;
    let drained = drain_server_queue(&mut peer1, 2, 1500).await;
    assert_eq!(
        drained,
        vec![TypeId::M_SP_NA_1 as u8, TypeId::M_DP_NA_1 as u8]
    );

    do_stopdt(&mut peer1).await;
    drop(peer1);
}

/// `mark_waiting_for_transmission()` moves active-queue ASDUs to the
/// waiting pool; `drain_waiting()` reverses it. This is the
/// G-013 / G-014 mechanism the server's serve loop uses on peer
/// close and on peer accept.
#[tokio::test]
async fn queue_mark_waiting_then_drain_waiting_round_trip() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr);
    let server = Server::bind(cfg).await.expect("bind");

    for type_id in [TypeId::M_SP_NA_1, TypeId::M_DP_NA_1, TypeId::M_ME_NB_1] {
        server.enqueue(single_point_asdu(type_id));
    }
    assert_eq!(server.queue.len(), 3);

    // Simulate peer close without a peer: move active → waiting.
    let moved = server.queue.mark_waiting_for_transmission();
    assert_eq!(moved, 3);
    assert_eq!(server.queue.len(), 0);
    assert_eq!(server.queue.waiting_len(), 3);

    // Simulate peer accept: move waiting → active.
    let recovered = server.queue.drain_waiting();
    assert_eq!(recovered, 3);
    assert_eq!(server.queue.len(), 3);
    assert_eq!(server.queue.waiting_len(), 0);

    // Idempotent: a second drain is a no-op.
    assert_eq!(server.queue.drain_waiting(), 0);
    assert_eq!(server.queue.len(), 3);
}

/// End-to-end recovery: enqueue → mark_waiting → disconnect peer1 →
/// new peer connects → drains the recovered queue.
#[tokio::test]
async fn failover_peer2_drains_recovered_queue_via_waiting_pool() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr).max_open(4);
    let server = Server::bind(cfg).await.expect("bind");

    // No peer connected yet — enqueue 2 frames.
    for type_id in [TypeId::M_SP_NA_1, TypeId::M_DP_NA_1] {
        server.enqueue(single_point_asdu(type_id));
    }

    // Move to waiting pool (simulating peer close on a queue that
    // still held un-sent frames).
    server.queue.mark_waiting_for_transmission();
    assert_eq!(server.queue.len(), 0);
    assert_eq!(server.queue.waiting_len(), 2);

    // Peer2 connects. The server's serve loop will call
    // `queue.drain_waiting()` at the start, moving the frames back
    // to the active queue; drain_tick then ships them.
    let mut peer2 = TcpStream::connect(addr).await.expect("connect peer2");
    do_startdt(&mut peer2).await;
    let drained = drain_server_queue(&mut peer2, 2, 1500).await;
    assert_eq!(
        drained,
        vec![TypeId::M_SP_NA_1 as u8, TypeId::M_DP_NA_1 as u8],
        "peer2 received the recovered frames"
    );
    assert_eq!(server.queue.len(), 0);
    assert_eq!(server.queue.waiting_len(), 0);

    do_stopdt(&mut peer2).await;
    drop(peer2);
}

#[tokio::test]
async fn failover_max_open_drops_third_concurrent_peer() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr).max_open(2);
    let server = Server::bind(cfg).await.expect("bind");

    let mut p1 = TcpStream::connect(addr).await.expect("p1");
    let mut p2 = TcpStream::connect(addr).await.expect("p2");
    do_startdt(&mut p1).await;
    do_startdt(&mut p2).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(server.open_count(), 2);

    // Third peer is rejected at accept time (max_open cap).
    let p3 = TcpStream::connect(addr).await.expect("p3");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.open_count(), 2, "max_open=2 must reject p3");
    drop(p3);

    drop(p1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.open_count(), 1);

    let mut p4 = TcpStream::connect(addr).await.expect("p4");
    do_startdt(&mut p4).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.open_count(), 2);

    do_stopdt(&mut p2).await;
    do_stopdt(&mut p4).await;
    drop(p2);
    drop(p4);
}

// ===========================================================================
// Multi-redundancy-group routing
// ===========================================================================

#[tokio::test]
async fn multi_rg_two_groups_route_by_client_ip() {
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let g0 = RedundancyGroup::default()
        .allow("127.0.0.1".parse::<IpAddr>().unwrap())
        .with_max(4);
    let g1 = RedundancyGroup::default()
        .allow("10.99.99.99".parse::<IpAddr>().unwrap())
        .with_max(4);
    let cfg = ServerConfig::new(addr)
        .mode(ServerMode::MultipleRedundancyGroups)
        .groups(vec![g0, g1])
        .max_open(8);
    let server = Server::bind(cfg).await.expect("bind");

    let peer: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let gidx = server.group_for(peer);
    assert_eq!(gidx, Some(0), "loopback peer → g0");

    let other_peer: SocketAddr = "10.99.99.99:55555".parse().unwrap();
    let gidx2 = server.group_for(other_peer);
    assert_eq!(gidx2, Some(1), "10.99.99.99 peer → g1");

    let mut p1 = TcpStream::connect(addr).await.expect("p1");
    do_startdt(&mut p1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.open_count(), 1);

    do_stopdt(&mut p1).await;
    drop(p1);
}

#[tokio::test]
async fn multi_rg_all_groups_see_broadcast_enqueued_frames() {
    // Documents the current behaviour: frames enqueued via
    // Server::enqueue() are visible to every connected peer in
    // every group because the server has a single shared AsduQueue.
    // Per-group queues (G-011) are not yet implemented.
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let g0 = RedundancyGroup::default()
        .allow("127.0.0.1".parse::<IpAddr>().unwrap())
        .with_max(4);
    let g1 = RedundancyGroup::default()
        .allow("10.0.0.99".parse::<IpAddr>().unwrap())
        .with_max(4);
    let cfg = ServerConfig::new(addr)
        .mode(ServerMode::MultipleRedundancyGroups)
        .groups(vec![g0, g1])
        .max_open(4);
    let server = Server::bind(cfg).await.expect("bind");

    for type_id in [TypeId::M_SP_NA_1, TypeId::M_DP_NA_1] {
        server.enqueue(single_point_asdu(type_id));
    }

    let mut peer1 = TcpStream::connect(addr).await.expect("peer1");
    do_startdt(&mut peer1).await;
    let drained = drain_server_queue(&mut peer1, 2, 1500).await;
    assert_eq!(
        drained,
        vec![TypeId::M_SP_NA_1 as u8, TypeId::M_DP_NA_1 as u8]
    );

    do_stopdt(&mut peer1).await;
    drop(peer1);
}

// ===========================================================================
// Connection event tracking during failover
// ===========================================================================

#[tokio::test]
async fn failover_connection_event_open_close_count_pairs() {
    struct Counting {
        open: AtomicUsize,
        close: AtomicUsize,
    }
    impl fegrid_iec60870_tokio::ConnectionEventHandler for Counting {
        fn on_open(&self, _: SocketAddr) {
            self.open.fetch_add(1, Ordering::SeqCst);
        }
        fn on_close(&self, _: SocketAddr) {
            self.close.fetch_add(1, Ordering::SeqCst);
        }
    }
    let counter = Arc::new(Counting {
        open: AtomicUsize::new(0),
        close: AtomicUsize::new(0),
    });
    let port = alloc_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = ServerConfig::new(addr)
        .conn_event(counter.clone())
        .max_open(4);
    let _server = Server::bind(cfg).await.expect("bind");

    for _ in 0..3 {
        let s = TcpStream::connect(addr).await.expect("connect");
        tokio::time::sleep(Duration::from_millis(120)).await;
        drop(s);
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    assert_eq!(
        counter.open.load(Ordering::SeqCst),
        3,
        "3 connects → 3 on_open"
    );
    assert_eq!(
        counter.close.load(Ordering::SeqCst),
        3,
        "3 drops → 3 on_close"
    );
}
