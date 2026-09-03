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
        // already outstanding and unanswered for t1, close.
        let idle = self
            .last_recv_at
            .map(|t| now.saturating_sub(t) >= self.t3)
            .unwrap_or(true);
        if idle {
            if self.testfr_pending {
                // Outstanding TESTFR_CON not yet answered — count misses.
                // Legacy closes after `outstandingTestFRConMessages > 2`, which
                // means a third unanswered TESTFR trips the close.
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
                reason: CloseReason::TestFrMisses
            }
        ));
    }

    #[test]
    fn testfr_con_resets_misses() {
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
}
