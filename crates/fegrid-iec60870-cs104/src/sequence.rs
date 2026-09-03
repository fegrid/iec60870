//! Mod-32768 sequence-number state machine.

use core::ops::Sub;

use crate::apci::SeqNo;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Mod-32768 arithmetic window used by [`SeqNo::sub`].
pub struct ModWindow(pub u16);

impl ModWindow {
    /// Distance from `self` to `other` going forward in [0, 32768).
    pub fn forward_distance_to(self, other: SeqNo) -> u16 {
        (other.0.wrapping_sub(self.0)) & 0x7fff
    }
}
#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for SeqNo {
    type Output = ModWindow;
    fn sub(self, rhs: Self) -> ModWindow {
        ModWindow(self.0.wrapping_sub(rhs.0) & 0x7fff)
    }
}

/// Pure-data sequence-state for a CS104 session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SequenceState {
    pub(crate) send: SeqNo,
    pub(crate) recv: SeqNo,
    pub(crate) ack_send: SeqNo,
    pub(crate) unacked_count: u16,
}

impl SequenceState {
    /// Construct a fresh state at (0, 0).
    pub fn new() -> Self {
        Self {
            send: SeqNo(0),
            recv: SeqNo(0),
            ack_send: SeqNo(0),
            unacked_count: 0,
        }
    }

    /// Current send counter.
    pub fn send(&self) -> SeqNo {
        self.send
    }

    /// Current receive counter.
    pub fn recv(&self) -> SeqNo {
        self.recv
    }

    /// Last acknowledged send counter.
    pub fn ack_send(&self) -> SeqNo {
        self.ack_send
    }

    /// How many I-frames we have sent but the peer has not yet acknowledged.
    pub fn unacked_count(&self) -> u16 {
        self.unacked_count
    }

    /// Reserve the next send sequence number; returns `None` if `k` would
    /// be exceeded (caller must wait for an ack).
    pub fn next_send(&mut self, k: u16) -> Option<SeqNo> {
        if self.unacked_count >= k {
            return None;
        }
        let n = self.send;
        self.send = n.next();
        self.unacked_count += 1;
        Some(n)
    }

    /// Apply an incoming I-frame carrying `(ns, nr)`. Returns an error
    /// when `ns` is not exactly `self.recv`.
    pub fn on_i_received(&mut self, ns: SeqNo) -> Result<(), crate::apci::ApduError> {
        if ns != self.recv {
            return Err(crate::apci::ApduError::SequenceOutOfRange(ns.0));
        }
        self.recv = ns.next();
        Ok(())
    }

    /// Apply an S-frame acking `nr`. Clears every send ≤ `nr - 1` from
    /// the in-flight queue.
    pub fn on_s_received(&mut self, nr: SeqNo) {
        let acked = nr - self.ack_send;
        self.ack_send = nr;
        if acked.0 <= self.unacked_count {
            self.unacked_count -= acked.0;
        } else {
            self.unacked_count = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_window_basic() {
        let mut s = SequenceState::new();
        // Send 3 frames.
        assert_eq!(s.next_send(8), Some(SeqNo(0)));
        assert_eq!(s.next_send(8), Some(SeqNo(1)));
        assert_eq!(s.next_send(8), Some(SeqNo(2)));
        assert_eq!(s.unacked_count(), 3);

        // Ack with nr=3 → all 3 acked.
        s.on_s_received(SeqNo(3));
        assert_eq!(s.unacked_count(), 0);
        assert_eq!(s.ack_send(), SeqNo(3));
    }

    #[test]
    fn sequence_window_k_exhausted() {
        let mut s = SequenceState::new();
        for _ in 0..4 {
            assert!(s.next_send(4).is_some());
        }
        assert!(s.next_send(4).is_none());
        s.on_s_received(SeqNo(4));
        assert!(s.next_send(4).is_some());
    }

    #[test]
    fn sequence_window_wrap() {
        let mut s = SequenceState {
            send: SeqNo(32760),
            recv: SeqNo(32760),
            ack_send: SeqNo(32760),
            unacked_count: 0,
        };
        // Start at 32760, send 8 (up to 32767 then wrap to 0).
        for _ in 0..8 {
            let _ = s.next_send(16).unwrap();
        }
        // After 8 sends, send has wrapped to 0.
        assert_eq!(s.send(), SeqNo(0));
        assert!(s.on_i_received(SeqNo(32765)).is_err());
    }

    #[test]
    fn next_send_increments_mod_32768() {
        let mut s = SequenceState {
            send: SeqNo(32767),
            recv: SeqNo(0),
            ack_send: SeqNo(0),
            unacked_count: 0,
        };
        assert_eq!(s.next_send(8), Some(SeqNo(32767)));
        assert_eq!(s.next_send(8), Some(SeqNo(0)));
    }
}
