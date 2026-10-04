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

/// Maximum legal value for `k` and `w`. The CS 104 wire format
/// encodes sequence numbers in 15 bits (mod 32768), so a window
/// wider than the sequence space is meaningless.
pub const MAX_K: u16 = 32767;
/// Maximum legal value for `w` (the S-frame ack threshold). See
/// [`MAX_K`] for the rationale: the 15-bit mod space caps both
/// values at 32767.
pub const MAX_W: u16 = 32767;

impl ApciParameters {
    /// Reject parameter combinations that would deadlock the session
    /// or are unrepresentable on the wire.
    ///
    /// * `k == 0` — zero-window; no I-frame can ever be sent.
    /// * `w == 0` — never ack; the t2 watchdog's flush path runs
    ///   forever without progress.
    /// * `k < w` — IEC 60870-5-104 §5.5 requires the unacknowledged
    ///   window to be at least as large as the S-frame ack threshold.
    /// * `k > MAX_K` — wider than the 15-bit sequence-number mod
    ///   space; impossible to encode on the wire.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.k == 0 {
            return Err("k must be ≥ 1");
        }
        if self.w == 0 {
            return Err("w must be ≥ 1");
        }
        if self.k < self.w {
            return Err("k must be ≥ w (IEC 60870-5-104 §5.5)");
        }
        if self.k > MAX_K || self.w > MAX_W {
            return Err("k and w must fit in the 15-bit sequence mod space (≤ 32767)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_104_5_5_01_k_within_modulus_bound() {
        // 104 §5.5: k shall never exceed n − 1 for modulo n operation. The
        // 15-bit CS104 sequence modulus caps k at 32767.
        assert_eq!(MAX_K, 32767);
        let at_bound = ApciParameters {
            k: MAX_K,
            w: 8,
            ..Default::default()
        };
        assert!(at_bound.validate().is_ok(), "k == n-1 must validate");
        let above = ApciParameters {
            k: MAX_K + 1,
            w: 8,
            ..Default::default()
        };
        assert!(above.validate().is_err(), "k above n-1 must be rejected");
    }

    #[test]
    fn spec_104_5_5_02_w_within_two_thirds_of_k() {
        // 104 §5.5 recommends w ≤ two-thirds of k; the default parameter set
        // sits exactly on that recommendation.
        let default = ApciParameters::default();
        assert_eq!(default.k, 12);
        assert_eq!(default.w, 8);
        assert!(default.w <= default.k * 2 / 3);
        // Validation only requires k >= w, so a w above the recommendation is
        // accepted (see the `note` on record 104-5.5-02).
        let above = ApciParameters {
            k: 12,
            w: 12,
            ..Default::default()
        };
        assert!(above.validate().is_ok());
        assert!(above.w > above.k * 2 / 3);
    }
}
