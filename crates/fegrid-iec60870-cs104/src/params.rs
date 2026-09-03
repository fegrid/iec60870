//! APCI parameters (k, w, t0..t3).
//!

/// APCI session parameters (all times in milliseconds).

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ApciParameters {
    /// Maximum number of unacknowledged I-frames (`k`).
    pub k: u16,
    /// Latest acknowledge after `w` received I-frames.
    pub w: u16,
    /// Connection-establishment timeout.
    pub t0_ms: u64,
    /// Send-or-test timeout.
    pub t1_ms: u64,
    /// Acknowledge timeout.
    pub t2_ms: u64,
    /// Idle (test-fr) timeout.
    pub t3_ms: u64,
}

impl Default for ApciParameters {
    fn default() -> Self {
        Self {
            k: 12,
            w: 8,
            t0_ms: 10_000,
            t1_ms: 15_000,
            t2_ms: 10_000,
            t3_ms: 20_000,
        }
    }
}
