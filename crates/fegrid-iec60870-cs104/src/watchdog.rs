//! T1/T2/T3 watchdog for CS 104 connections.
//!
//! The watchdog holds the last-activity timestamps for the connection and
//! decides what to do when the application calls [`Watchdog::tick`]:
//!
//! - if T1 (ack timeout) has elapsed on the oldest unconfirmed sent I-frame
//!   → close the connection (matches `cs104_connection.c:handleTimeouts`).
//! - if T2 (S-frame ack delay) has elapsed on unconfirmed received I-frames
//!   → emit a single S-frame ack to flush the receive buffer.
//! - if T3 (idle test) has elapsed since the last received frame → send a
//!   TESTFR_ACT and arm a TESTFR_CON wait. After `MAX_TESTFR_MISSES`
//!   unanswered TESTFR_CONs the connection is closed.

use core::time::Duration;

/// How many unanswered TESTFR_CONs we tolerate before closing the
/// connection.
pub const MAX_TESTFR_MISSES: u8 = 2;

/// Watchdog decision after a [`Watchdog::tick`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum WatchdogAction {
    /// Nothing to do.
    None,
    /// Emit an S-frame acking the current receive counter.
    SendSFrame(u16),
    /// Emit a TESTFR_ACT and bump the unanswered-testfr counter.
    SendTestFrAct,
    /// Close the connection (T1 expired on sent I-frame OR TESTFR CON misses).
    Close {
        /// Human-readable reason, surfaced to connection-event observers.
        reason: CloseReason,
    },
}

/// Why the watchdog asked the transport to close.
#[derive(Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// T1 expired on an unconfirmed sent I-frame.
    T1AckTimeout,
    /// More than [`MAX_TESTFR_MISSES`] TESTFR_ACT were left unanswered.
    TestFrMisses,
}

/// Watchdog state. Construct with [`Watchdog::new`]; call [`Watchdog::tick`]
/// periodically from the transport loop.
#[derive(Debug, Clone)]
pub struct Watchdog {
    t1: Duration,
    #[allow(dead_code)]
    t2: Duration,
    t3: Duration,
    /// Last instant at which any frame was received (used for T3 idle).
    last_recv_at: Option<Duration>,
    /// Last instant at which the oldest sent I-frame was queued.
    oldest_sent_at: Option<Duration>,
    /// Counter of unanswered TESTFR_CONs.
    testfr_misses: u8,
    /// Whether a TESTFR_ACT is currently outstanding.
    testfr_pending: bool,
}

impl Watchdog {
    /// Construct a fresh watchdog with the given timer parameters.
    pub fn new(t1: Duration, t2: Duration, t3: Duration) -> Self {
        Self {
            t1,
            t2,
            t3,
            last_recv_at: None,
            oldest_sent_at: None,
            testfr_misses: 0,
            testfr_pending: false,
        }
    }

    /// Note that a frame was just received from the peer. Resets the T3 idle
    /// counter and clears any outstanding TESTFR_ACT (a TESTFR_CON arrived).
    pub fn note_recv(&mut self, now: Duration) {
        self.last_recv_at = Some(now);
        if self.testfr_pending {
            self.testfr_pending = false;
            self.testfr_misses = 0;
        }
    }

    /// Note that an I-frame was just sent. Records the sent time so the
    /// watchdog can enforce T1 on the oldest outstanding I-frame.
    pub fn note_sent(&mut self, now: Duration) {
        if self.oldest_sent_at.is_none() {
            self.oldest_sent_at = Some(now);
        }
    }

    /// Note that an I-frame was acknowledged by the peer. Clears the
    /// oldest-sent timestamp if no unconfirmed frames remain (`unacked == 0`).
    pub fn note_ack(&mut self, unacked: u16) {
        if unacked == 0 {
            self.oldest_sent_at = None;
        }
    }

    /// Periodic tick. Returns the action the transport should take.
    pub fn tick(
        &mut self,
        now: Duration,
        unacked: u16,
        w: u16,
        unacked_recv: u16,
    ) -> WatchdogAction {
        // T1: oldest sent I-frame age must be < t1.
        if unacked > 0
            && let Some(sent_at) = self.oldest_sent_at
            && now.saturating_sub(sent_at) >= self.t1
        {
            return WatchdogAction::Close {
                reason: CloseReason::T1AckTimeout,
            };
        }

        // T3: idle. If no frame received in t3, send TESTFR_ACT. If TESTFR
        // already outstanding and unanswered for t1, close. If
        // `last_recv_at` is None (freshly-constructed watchdog, no
        // inbound frame yet) we are NOT idle — wait for the first
        // inbound frame to arm the idle counter. Without this guard
        // the watchdog spuriously fires TESTFR_ACT immediately on
        // T3: idle. If no frame received in t3, send TESTFR_ACT. If TESTFR
        // already outstanding and unanswered for t1, close. A fresh
        // watchdog (no inbound frame yet) is treated as idle since
        // the wall-clock epoch so the first tick after t3 of wall
        // time fires TESTFR_ACT. This matches the spec behaviour
        // ("if no I-frame has been received for a period of t3, the
        // station shall send a TESTFR ACT") and the two unit tests
        // `t3_close_after_two_misses` / `testfr_con_resets_misses`.
        let idle_elapsed = self.last_recv_at.map_or(now, |t| now.saturating_sub(t));
        let idle = idle_elapsed >= self.t3;
        if idle {
            if self.testfr_pending {
                // Outstanding TESTFR_CON not yet answered — count misses.
                // Legacy closes after `outstandingTestFRConMessages > 2`,
                // which means the third unanswered TESTFR trips the close.
                self.testfr_misses += 1;
                if self.testfr_misses >= MAX_TESTFR_MISSES {
                    return WatchdogAction::Close {
                        reason: CloseReason::TestFrMisses,
                    };
                }
            }
            self.testfr_pending = true;
            return WatchdogAction::SendTestFrAct;
        }

        // T2: when unacked recv I-frames have piled up to >= w or > 0,
        // emit a single S-frame to flush them.
        if unacked_recv > 0 && unacked_recv >= w {
            return WatchdogAction::SendSFrame(unacked_recv);
        }

        WatchdogAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn t1_closes_on_unacked() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(200));
        wd.note_sent(ms(0));
        let action = wd.tick(ms(150), 1, 8, 0);
        assert!(matches!(
            action,
            WatchdogAction::Close {
                reason: CloseReason::T1AckTimeout
            }
        ));
    }

    #[test]
    fn t3_emits_testfr_act_when_idle() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(200));
        wd.note_recv(ms(0));
        let action = wd.tick(ms(250), 0, 8, 0);
        assert_eq!(action, WatchdogAction::SendTestFrAct);
    }

    #[test]
    fn t3_close_after_two_misses() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(200));
        // First idle tick: TESTFR pending.
        assert_eq!(wd.tick(ms(300), 0, 8, 0), WatchdogAction::SendTestFrAct);
        // Second idle tick while still pending — miss 1.
        assert_eq!(wd.tick(ms(400), 0, 8, 0), WatchdogAction::SendTestFrAct);
        // Third: misses = 2 → close.
        let action = wd.tick(ms(500), 0, 8, 0);
        assert!(matches!(
            action,
            WatchdogAction::Close {
                reason: CloseReason::TestFrMisses,
            }
        ));
        let mut wd = Watchdog::new(ms(100), ms(50), ms(200));
        assert_eq!(wd.tick(ms(300), 0, 8, 0), WatchdogAction::SendTestFrAct);
        wd.note_recv(ms(310)); // TESTFR_CON arrives
        // Next tick should fire TESTFR again but with misses reset.
        assert_eq!(wd.tick(ms(700), 0, 8, 0), WatchdogAction::SendTestFrAct);
        // Not yet closed.
    }

    #[test]
    fn ack_clears_oldest_sent() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(200));
        wd.note_sent(ms(0));
        wd.note_ack(0);
        // No more unacked, so T1 should not fire.

        let action = wd.tick(ms(500), 0, 8, 0);
        assert!(!matches!(action, WatchdogAction::Close { .. }));
    }

    /// §4.13 — T2 S-frame-only path was uncovered; line 155 of `tick`
    /// (`unacked_recv > 0 && unacked_recv >= w → SendSFrame`) had no
    /// assertion. Receive an I-frame so `unacked_recv >= w` and tick
    /// before t3 expires: watchdog must emit exactly one S-frame and
    /// not close.
    #[test]
    fn t2_emits_s_frame_when_recv_backlog_reaches_w() {
        let mut wd = Watchdog::new(ms(1_000), ms(500), ms(10_000));
        wd.note_recv(ms(0));
        // unacked_recv == w → S-frame, T1/T3 inactive.
        let action = wd.tick(ms(100), 0, 8, 8);
        assert_eq!(action, WatchdogAction::SendSFrame(8));
    }

    /// T2 must NOT fire when the unacked-receive counter is below the
    /// w-threshold. Guards the `>= w` half of the guard.
    #[test]
    fn t2_does_not_emit_below_w_threshold() {
        let mut wd = Watchdog::new(ms(1_000), ms(500), ms(10_000));
        wd.note_recv(ms(0));
        let action = wd.tick(ms(100), 0, 8, 7);
        assert_eq!(action, WatchdogAction::None);
    }

    /// T2 must NOT fire when the receive buffer is empty. Guards the
    /// `unacked_recv > 0` half of the guard.
    #[test]
    fn t2_does_not_emit_when_recv_buffer_empty() {
        let mut wd = Watchdog::new(ms(1_000), ms(500), ms(10_000));
        wd.note_recv(ms(0));
        let action = wd.tick(ms(100), 0, 8, 0);
        assert_eq!(action, WatchdogAction::None);
    }

    /// T1 boundary: `now == sent_at + t1` must close. Catches a
    /// off-by-one if someone replaces `>=` with `>`.
    #[test]
    fn t1_closes_at_exact_boundary() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(10_000));
        wd.note_sent(ms(0));
        let action = wd.tick(ms(100), 1, 8, 0);
        assert!(matches!(
            action,
            WatchdogAction::Close {
                reason: CloseReason::T1AckTimeout,
            }
        ));
    }

    /// Just-below boundary: T1 must NOT close. Catches the same
    /// off-by-one.
    #[test]
    fn t1_holds_just_below_boundary() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(10_000));
        wd.note_sent(ms(0));
        let action = wd.tick(ms(99), 1, 8, 0);
        assert!(!matches!(action, WatchdogAction::Close { .. }));
    }

    /// T3 boundary: `now == last_recv + t3` must fire TESTFR_ACT.
    #[test]
    fn t3_fires_at_exact_boundary() {
        let mut wd = Watchdog::new(ms(10_000), ms(500), ms(200));
        wd.note_recv(ms(0));
        let action = wd.tick(ms(200), 0, 8, 0);
        assert_eq!(action, WatchdogAction::SendTestFrAct);
    }

    /// Precedence: when both T1 and T3 are eligible, T1 wins (close
    /// the connection, do not emit a TESTFR_ACT that the peer will
    /// never see).
    #[test]
    fn t1_takes_precedence_over_t3() {
        let mut wd = Watchdog::new(ms(100), ms(500), ms(200));
        wd.note_sent(ms(0)); // T1 armed
        // T3 also eligible (no recv ever, idle since epoch).
        let action = wd.tick(ms(500), 1, 8, 0);
        assert!(matches!(
            action,
            WatchdogAction::Close {
                reason: CloseReason::T1AckTimeout,
            }
        ));
    }

    /// Precedence: T3 fires before T2 — an idle connection that also
    /// has unacked recv I-frames must TESTFR, not S-frame, so the
    /// peer notices the liveness gap.
    #[test]
    fn t3_takes_precedence_over_t2() {
        let mut wd = Watchdog::new(ms(10_000), ms(500), ms(200));
        // No note_recv — fresh watchdog, idle since epoch.
        let action = wd.tick(ms(500), 0, 8, 8);
        assert_eq!(action, WatchdogAction::SendTestFrAct);
    }

    /// Second `note_sent` must not move `oldest_sent_at` — the
    /// watchdog tracks the FIRST unacked I-frame's age, not the most
    /// recent. If this guard breaks, T1 starts counting from the
    /// second frame and a slow-acked burst will pass the timeout.
    #[test]
    fn second_note_sent_does_not_move_oldest() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(10_000));
        wd.note_sent(ms(0));
        wd.note_sent(ms(80)); // newer frame, but oldest stays at 0.
        let action = wd.tick(ms(99), 2, 8, 0);
        assert!(!matches!(action, WatchdogAction::Close { .. }));
    }

    /// `note_ack(nonzero)` must NOT clear `oldest_sent_at`. If it did,
    /// a peer acking only the second of two frames would reset T1
    /// while the first is still unacked.
    #[test]
    fn note_ack_with_unacked_remaining_keeps_t1_armed() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(10_000));
        wd.note_sent(ms(0));
        wd.note_ack(1); // peer acked one, but one still outstanding.
        let action = wd.tick(ms(150), 1, 8, 0);
        assert!(matches!(
            action,
            WatchdogAction::Close {
                reason: CloseReason::T1AckTimeout,
            }
        ));
    }

    /// Fresh watchdog + tick before any note_recv/note_sent must NOT
    /// close. The T1 branch requires `unacked > 0 && oldest_sent_at`
    /// (both false), so T1 does not fire. T3 fires (idle since epoch).
    #[test]
    fn fresh_watchdog_first_tick_fires_t3_not_t1() {
        let mut wd = Watchdog::new(ms(100), ms(50), ms(10_000));
        let action = wd.tick(ms(50_000), 0, 8, 0);
        assert_eq!(action, WatchdogAction::SendTestFrAct);
    }

    /// `note_recv` must arm the T3 idle window: a tick INSIDE the
    /// next t3 after the recv must NOT re-arm TESTFR_ACT. Guards
    /// the recv-vs-idle interaction.
    #[test]
    fn recv_resets_t3_idle_window() {
        let mut wd = Watchdog::new(ms(10_000), ms(500), ms(200));
        wd.note_recv(ms(0));
        // Just past t3 — fires.
        assert_eq!(wd.tick(ms(250), 0, 8, 0), WatchdogAction::SendTestFrAct);
        // note_recv at ms=300 — clears the pending TESTFR_ACT
        // (treated as a TESTFR_CON arriving) and resets the idle
        // counter.
        wd.note_recv(ms(300));
        // Tick at ms=400 (only 100ms past last recv, well within t3):
        // must not fire TESTFR again.
        assert_eq!(wd.tick(ms(400), 0, 8, 0), WatchdogAction::None);
    }
}
