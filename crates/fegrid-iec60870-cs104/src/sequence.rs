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
    /// Last receive counter we have ACKed back to the peer via an
    /// S-frame. `recv - ack_recv` (mod 32768) is the number of
    /// I-frames the peer sent that we haven't yet ACKed — used by
    /// the t2 watchdog to decide when to emit an S-frame ack.
    pub(crate) ack_recv: SeqNo,
    pub(crate) unacked_count: u16,
}

impl SequenceState {
    /// Construct a fresh state at (0, 0).
    pub fn new() -> Self {
        Self {
            send: SeqNo(0),
            recv: SeqNo(0),
            ack_send: SeqNo(0),
            ack_recv: SeqNo(0),
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

    /// How many I-frames the peer has sent that we have not yet
    /// ACKed via an S-frame. Distance from `self.ack_recv` to
    /// `self.recv` measured in the forward direction modulo 32768.
    /// Returns 0 once the peer has stopped sending and we've caught
    /// up. Used by the watchdog to decide when to emit a t2 S-frame.
    pub fn unacked_recv_count(&self) -> u16 {
        (self.recv.0.wrapping_sub(self.ack_recv.0)) & 0x7fff
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

    /// Record that we emitted an S-frame acking `nr`. The watchdog's
    /// t2 path checks `unacked_recv_count()` (i.e. `recv - ack_recv`)
    /// to decide when to flush the ack queue.
    pub fn note_s_sent(&mut self, nr: SeqNo) {
        self.ack_recv = nr;
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
            ack_recv: SeqNo(32760),
            unacked_count: 0,
        };
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
            ack_recv: SeqNo(0),
            unacked_count: 0,
        };
        assert_eq!(s.next_send(8), Some(SeqNo(32767)));
        assert_eq!(s.next_send(8), Some(SeqNo(0)));
    }
    // ---- C.2 [P0] k-window stress at boundary values -----------------
    //
    // See `specs/CONFIDENCE_TEST_BACKLOG.md` §C.2 for context.

    #[test]
    fn k_one_blocks_second_until_ack() {
        let mut s = SequenceState::new();
        // k=1 admits exactly one outstanding I-frame.
        assert_eq!(s.next_send(1), Some(SeqNo(0)));
        // The second send must NOT be admitted — the unACKed first
        // frame is still in flight.
        assert!(s.next_send(1).is_none());
        assert_eq!(s.unacked_count(), 1);

        // ACK the first frame → window drains, second send allowed.
        s.on_s_received(SeqNo(1));
        assert_eq!(s.unacked_count(), 0);
        assert_eq!(s.next_send(1), Some(SeqNo(1)));
        assert!(s.next_send(1).is_none());
    }

    #[test]
    fn k_zero_is_zero_window() {
        // k=0 is a degenerate config: every send attempt is rejected
        // because `unacked_count >= k` (0 >= 0) is always true. The
        // session can drain in-flight frames via `on_s_received` but
        // can never originate a new one. `ApciParameters::validate`
        // rejects k=0 at config time; this test pins the in-session
        // behaviour so any future refactor that allows k=0 in still
        // produces the expected zero-window.
        let mut s = SequenceState::new();
        assert!(s.next_send(0).is_none());
        assert!(s.next_send(0).is_none());
        assert_eq!(s.send(), SeqNo(0));
        assert_eq!(s.unacked_count(), 0);
    }

    #[test]
    fn k_max_rapid_send_loop_does_not_wrap_into_invalid_state() {
        // k=32767 is the largest legal value. With the sequence
        // space spanning [0, 32767] (inclusive, mod 32768), the
        // session must admit 32767 consecutive sends and refuse
        // the 32768th without corrupting internal counters.
        let mut s = SequenceState::new();
        for i in 0..32767u32 {
            let n = s
                .next_send(32767)
                .unwrap_or_else(|| panic!("send {i} refused mid-loop"));
            assert_eq!(n.0 as u32, i);
        }
        assert_eq!(s.unacked_count(), 32767);
        // 32768th send must be refused — window is full.
        assert!(s.next_send(32767).is_none());
        // Counter must not have advanced past 32767 even though the
        // attempt failed.
        assert_eq!(s.send(), SeqNo(32767));
        assert_eq!(s.unacked_count(), 32767);
        // Full ACK drains the window; the next send consumes the
        // pre-increment `send` counter (still at the wrap-around
        // SeqNo(32767)) and advances `send` to SeqNo(0).
        s.on_s_received(SeqNo(32767));
        assert_eq!(s.unacked_count(), 0);
        assert_eq!(s.next_send(32767), Some(SeqNo(32767)));
        assert_eq!(s.send(), SeqNo(0));
    }

    // ---- C.3 [P1] Sequence-number wrap mid-exchange -------------------

    #[test]
    fn sequence_window_wrap_with_continuous_traffic() {
        // Pre-set both sides near the wrap point, then exchange 100
        // I-frames in each direction. The send counter must wrap
        // cleanly across the 32767→0 boundary and `on_i_received`
        // must still reject out-of-order frames after the wrap.
        let mut s = SequenceState {
            send: SeqNo(32760),
            recv: SeqNo(32760),
            ack_send: SeqNo(32760),
            ack_recv: SeqNo(32760),
            unacked_count: 0,
        };

        // 100 consecutive sends with k=8; window fills after the
        // 8th frame so the test exercises both the wrap and the
        // backpressure path under it. Whenever the window fills we
        // drain it (mirrors a real-world ack cadence at speed) so
        // every iteration makes progress.
        for i in 0..100u32 {
            if s.next_send(8).is_none() {
                s.on_s_received(s.send());
                assert!(s.next_send(8).is_some(), "send {i} refused after drain");
            }
        }
        // After 100 sends we must have wrapped exactly once.
        assert_eq!(s.send(), SeqNo(((32760u32 + 100) % 32768) as u16));

        // Now feed 100 incoming I-frames. Each `on_i_received` must
        // accept exactly the frame that follows `recv` and reject
        // every other value.
        for i in 0..100u32 {
            // The frame we *expect* to accept is the one that matches
            // `recv` before this iteration. After accepting it, `recv`
            // advances by one — every other sequence number must be
            // rejected.
            let expected = SeqNo(((32760u32 + i) % 32768) as u16);
            s.on_i_received(expected)
                .unwrap_or_else(|e| panic!("on_i_received({expected:?}) rejected: {e:?}"));

            // After accepting `expected`, `recv = expected + 1`. A
            // frame at `expected + 2` is one ahead of what `recv` now
            // expects; it must be rejected. (`expected + 1` would
            // equal the new `recv` and is the *next* acceptable
            // frame — NOT a wrong value.)
            let wrong_ahead = SeqNo(((32760u32 + i + 2) % 32768) as u16);
            let wrong_behind = SeqNo(((32760u32 + i).wrapping_sub(1) % 32768) as u16);
            let wrong_mid = SeqNo(((32760u32 + i + 50) % 32768) as u16);
            assert!(
                s.on_i_received(wrong_ahead).is_err(),
                "wrong_ahead {wrong_ahead:?} must be rejected"
            );
            assert!(
                s.on_i_received(wrong_behind).is_err(),
                "wrong_behind {wrong_behind:?} must be rejected"
            );
            assert!(
                s.on_i_received(wrong_mid).is_err(),
                "wrong_mid {wrong_mid:?} must be rejected"
            );
        }
        // After accepting 100 frames from 32760, `recv` must have
        // wrapped exactly once too.
        assert_eq!(s.recv(), SeqNo(((32760u32 + 100) % 32768) as u16));
    }

    #[test]
    fn sequence_window_recv_wrap_rejects_post_wrap_duplicate() {
        // Tight wrap scenario: start at SeqNo(32765) and accept the
        // last two valid frames (32765, 32766, 32767). After 32767
        // the next `recv` is SeqNo(0). Replaying any of the just-
        // consumed values must fail because the implementation only
        // accepts *exactly* `recv`.
        let mut s = SequenceState {
            send: SeqNo(0),
            recv: SeqNo(32765),
            ack_send: SeqNo(0),
            ack_recv: SeqNo(32765),
            unacked_count: 0,
        };
        s.on_i_received(SeqNo(32765)).unwrap();
        assert_eq!(s.recv(), SeqNo(32766));
        s.on_i_received(SeqNo(32766)).unwrap();
        assert_eq!(s.recv(), SeqNo(32767));
        s.on_i_received(SeqNo(32767)).unwrap();
        assert_eq!(s.recv(), SeqNo(0));
        // Post-wrap: the next expected receive is SeqNo(0). Replaying
        // any of 32765..32767 (already consumed) must fail.
        for n in [32765u16, 32766, 32767] {
            assert!(s.on_i_received(SeqNo(n)).is_err(), "stale {n} accepted");
        }
        // And an out-of-order-ahead frame (SeqNo(1)) must also fail.
        assert!(s.on_i_received(SeqNo(1)).is_err());
    }
    #[test]
    fn apci_k_zero_rejected_by_validate() {
        // The config-validation contract: k=0 is meaningless (zero-
        // window) and must be rejected. Any positive k ≥ w must
        // validate cleanly.
        use crate::params::ApciParameters;
        let bad = ApciParameters {
            k: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err(), "k=0 must be rejected");

        // Sanity-check a sweep of legal k's paired with a legal w
        // (k ≥ w, both non-zero, both ≤ 32767).
        for (k, w) in [(1u16, 1u16), (4, 4), (12, 8), (32767, 32767)] {
            let ok = ApciParameters {
                k,
                w,
                ..Default::default()
            };
            assert!(ok.validate().is_ok(), "k={k}, w={w} must validate");
        }
    }

    #[test]
    fn apci_w_zero_rejected_by_validate() {
        // Symmetric contract for `w`: a zero `w` disables every
        // S-frame ack (the watchdog's t2 path would never flush).
        // Must be rejected.
        use crate::params::ApciParameters;
        let bad = ApciParameters {
            w: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err(), "w=0 must be rejected");

        let ok = ApciParameters {
            w: 1,
            ..Default::default()
        };
        assert!(ok.validate().is_ok(), "w=1 must validate");
    }

    #[test]
    fn apci_k_must_be_at_least_w() {
        // IEC 60870-5-104 §6: k ≥ w (the window must hold at least
        // the unconfirmed-I batch). Validate enforces the invariant.
        use crate::params::ApciParameters;
        let bad = ApciParameters {
            k: 4,
            w: 8,
            ..Default::default()
        };
        assert!(bad.validate().is_err(), "k=4, w=8 must be rejected");

        let ok = ApciParameters {
            k: 8,
            w: 8,
            ..Default::default()
        };
        assert!(ok.validate().is_ok(), "k=w=8 must validate");
    }

    #[test]
    fn apci_k_above_mod_space_rejected_by_validate() {
        // The wire format uses 15-bit sequence numbers (mod 32768).
        // A k > 32767 is impossible to encode on the wire; reject.
        use crate::params::ApciParameters;
        let bad = ApciParameters {
            k: 32768,
            ..Default::default()
        };
        assert!(bad.validate().is_err(), "k=32768 must be rejected");
    }
}
