//! Verify `MClient` + `RawMessageHandler` + `RawMessageRegistry` plumbing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fegrid_iec60870_tokio::{RawMessageHandler, RawMessageRegistry};

struct CountingHandler {
    count: AtomicUsize,
    last_sent: std::sync::Mutex<bool>,
}

impl CountingHandler {
    fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            last_sent: std::sync::Mutex::new(false),
        }
    }
}

impl RawMessageHandler for CountingHandler {
    fn on_raw(&self, _bytes: &[u8], sent: bool) {
        self.count.fetch_add(1, Ordering::SeqCst);
        *self.last_sent.lock().expect("poisoned") = sent;
    }
}

#[test]
fn raw_handler_counts_calls() {
    let h = Arc::new(CountingHandler::new());
    h.on_raw(&[0x68, 0x04], true);
    h.on_raw(&[0x68, 0x04, 0x07], false);
    assert_eq!(h.count.load(Ordering::SeqCst), 2);
    assert!(!*h.last_sent.lock().unwrap());
}

#[test]
fn registry_dispatches_to_all_handlers() {
    let registry = RawMessageRegistry::new();
    let a = Arc::new(CountingHandler::new());
    let b = Arc::new(CountingHandler::new());
    registry.register(a.clone());
    registry.register(b.clone());

    registry.dispatch(&[1, 2, 3], true);

    assert_eq!(a.count.load(Ordering::SeqCst), 1);
    assert_eq!(b.count.load(Ordering::SeqCst), 1);
}
