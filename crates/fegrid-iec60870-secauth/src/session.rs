//! IEC 60870-5-7 secure-authentication session state machine.
//!
//! Implements the 4-message key-change procedure and the challenge/
//! response protocol that the spec attaches to COTs 14 (Authentication),
//! 15 (MaintenanceOfAuthSessionKey), and 16
//! (MaintenanceOfUserRoleAndUpdateKey). Modelled after opendnp3's
//! secure-auth state machine: a single `SecureSession` value
//! transitions through Idle → AwaitingChallenge → Active (or
//! AuthFailed on tamper).
//!
//! The status returned by the slave side is reported through the high
//! bits of the CA field of the response ASDU. This module exposes
//! the bit pattern as `ca_status_for_activation_con` /
//! `ca_status_for_activation_con_with_ca` so the higher-layer
//! encoder can compose the wire bytes.
//!
//! ## Cryptography
//!
//! Challenge responses are HMAC-SHA256 over
//! `(session_key || sequence_counter || challenge)` truncated to 4
//! bytes, mirroring opendnp3's SA-V5-HMAC-SHA256-4 mode. Keys are
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Length (bytes) of the session key — fixed by SHA-256's block size.
pub const SESSION_KEY_LEN: usize = 32;

/// Length (bytes) of the master's challenge — per IEC 60870-5-7
/// "Authentication Challenge" APDU.
pub const CHALLENGE_LEN: usize = 32;

/// Length (bytes) of the truncated HMAC response (opendnp3 SA-V5
/// mode: HMAC-SHA256-4).
pub const RESPONSE_LEN: usize = 4;

/// State of a single `SecureSession` instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session established. Challenges are rejected.
    Idle,
    /// Update-key change in progress (COT 16 follow-up). Challenges
    /// still accepted but counted against the new key after the
    /// Confirm.
    AwaitingChallenge,
    /// Session live — challenge/response works.
    Active,
    /// Auth tamper detected. State is terminal until re-keyed.
    AuthFailed,
}

/// Outcome of a `on_challenge_response` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// HMAC verified.
    Success,
    /// HMAC mismatched — caller should report negative ACK.
    Failed,
}

/// Which phase of the 4-step key change is expected next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyChangePhase {
    /// After Generate-Request → expecting Generate-Confirm.
    GenerateConfirmExpected,
    /// After Activate-Request → expecting Activate-Confirm.
    ActivateConfirmExpected,
    /// After Update-Key Request → expecting Update-Key Confirm.
    UpdateConfirmExpected,
}

/// Error type for the session state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Construction rejected an all-zero session key.
    ZeroKey,
    /// A 4-message key-change step arrived out of order.
    UnexpectedPhase {
        /// State expected by the caller.
        expected: SessionState,
        /// State observed at the time of the call.
        got: SessionState,
    },
    /// The proposed session key length is not 32 bytes.
    BadKeyLength(usize),
    /// The challenge length is not 32 bytes.
    BadChallengeLength(usize),
    /// Challenge attempted before the session is Active.
    NotReady,
    /// Auth tamper detected: response HMAC does not match.
    AuthFailed,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroKey => f.write_str("session key is all zeros"),
            Self::UnexpectedPhase { expected, got } => {
                write!(f, "expected state {:?}, got {:?}", expected, got)
            }
            Self::BadKeyLength(n) => write!(f, "bad key length {n}, expected 32"),
            Self::BadChallengeLength(n) => {
                write!(f, "bad challenge length {n}, expected 32")
            }
            Self::NotReady => f.write_str("session not in Active state"),
            Self::AuthFailed => f.write_str("authentication failed"),
        }
    }
}

impl std::error::Error for SessionError {}

/// 32-byte session key.
pub type SessionKey = [u8; SESSION_KEY_LEN];

/// The single secure-authentication session state machine.
///
/// Construct with a 32-byte session key, drive it through the
/// key-change procedure, then call `on_challenge_request` /
/// `on_challenge_response` for each COT 14 exchange.
#[derive(Debug, Clone)]
pub struct SecureSession {
    state: SessionState,
    /// Key negotiated during the key-change procedure.
    session_key: SessionKey,
    /// Monotonically increasing sequence number folded into HMAC.
    seq: u32,
    /// Active challenge in-flight. Reset on each request.
    pending_challenge: Option<[u8; CHALLENGE_LEN]>,
}

impl SecureSession {
    /// Construct a new Idle session with the given 32-byte session
    /// key. Returns Err if `key` is all zeros (footgun avoidance).
    pub fn try_new(key: SessionKey) -> Result<Self, SessionError> {
        if key.iter().all(|b| *b == 0) {
            return Err(SessionError::ZeroKey);
        }
        Ok(Self::new_unchecked(key))
    }

    /// Construct with a possibly-zero session key. Test-only /
    /// scaffolding use; production code should prefer `try_new`.
    pub fn new(key: SessionKey) -> Self {
        Self::new_unchecked(key)
    }

    fn new_unchecked(key: SessionKey) -> Self {
        Self {
            state: SessionState::Idle,
            session_key: key,
            seq: 0,
            pending_challenge: None,
        }
    }

    /// Current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Sequence counter incremented on each challenge request.
    pub fn sequence_counter(&self) -> u32 {
        self.seq
    }

    /// Current session key (32 bytes).
    pub fn session_key(&self) -> &SessionKey {
        &self.session_key
    }

    // -----------------------------------------------------------------
    // COT 15 — Maintenance of Authentication Session Key
    // -----------------------------------------------------------------

    /// Step 1 of 4: Generate-Key-Request.
    pub fn on_key_change_generate_request(
        &mut self,
        _challenge_seq_no: u32,
    ) -> Result<KeyChangePhase, SessionError> {
        if self.state != SessionState::Idle && self.state != SessionState::Active {
            return Err(SessionError::UnexpectedPhase {
                expected: SessionState::Idle,
                got: self.state,
            });
        }
        self.state = SessionState::AwaitingChallenge;
        Ok(KeyChangePhase::GenerateConfirmExpected)
    }

    /// Step 2 of 4: Generate-Key-Confirm (carries the new 32-byte
    /// session key).
    pub fn on_key_change_generate_confirm(&mut self, new_key: &[u8]) -> Result<(), SessionError> {
        if new_key.len() != SESSION_KEY_LEN {
            return Err(SessionError::BadKeyLength(new_key.len()));
        }
        if self.state != SessionState::AwaitingChallenge {
            return Err(SessionError::UnexpectedPhase {
                expected: SessionState::AwaitingChallenge,
                got: self.state,
            });
        }
        self.session_key.copy_from_slice(new_key);
        // Stay in AwaitingChallenge — caller must next call
        // on_key_change_activate_request.
        Ok(())
    }

    /// Step 3 of 4: Activate-Key-Request.
    pub fn on_key_change_activate_request(&mut self) -> Result<KeyChangePhase, SessionError> {
        if self.state != SessionState::AwaitingChallenge {
            return Err(SessionError::UnexpectedPhase {
                expected: SessionState::AwaitingChallenge,
                got: self.state,
            });
        }
        // Do not transition yet — Activate-Confirm must arrive.
        Ok(KeyChangePhase::ActivateConfirmExpected)
    }

    /// Step 4 of 4: Activate-Key-Confirm. Promotes session to Active.
    pub fn on_key_change_activate_confirm(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::AwaitingChallenge {
            return Err(SessionError::UnexpectedPhase {
                expected: SessionState::AwaitingChallenge,
                got: self.state,
            });
        }
        self.state = SessionState::Active;
        self.seq = 0;
        Ok(())
    }

    // -----------------------------------------------------------------
    // COT 14 — Authentication Challenge
    // -----------------------------------------------------------------

    /// Outstation side: process the master's 32-byte challenge and
    /// return the truncated HMAC-SHA256-4 response.
    pub fn on_challenge_request(
        &mut self,
        challenge: &[u8],
    ) -> Result<[u8; RESPONSE_LEN], SessionError> {
        if self.state != SessionState::Active {
            return Err(SessionError::NotReady);
        }
        if challenge.len() != CHALLENGE_LEN {
            return Err(SessionError::BadChallengeLength(challenge.len()));
        }
        let mut challenge_arr = [0u8; CHALLENGE_LEN];
        challenge_arr.copy_from_slice(challenge);
        self.seq = self.seq.wrapping_add(1);
        let resp = hmac_sha256_4(&self.session_key, self.seq, &challenge_arr);
        self.pending_challenge = Some(challenge_arr);
        Ok(resp)
    }

    /// Outstation side: validate the master's response against the
    /// most recent `on_challenge_request`. Returns `Success` or
    /// `Failed` and transitions to `AuthFailed` on mismatch.
    pub fn on_challenge_response(
        &mut self,
        response: &[u8],
    ) -> Result<ChallengeStatus, SessionError> {
        if self.state != SessionState::Active {
            return Err(SessionError::NotReady);
        }
        let challenge = self.pending_challenge.ok_or(SessionError::NotReady)?;
        let expected = hmac_sha256_4(&self.session_key, self.seq, &challenge);
        self.pending_challenge = None;
        if response.len() < RESPONSE_LEN || response[..RESPONSE_LEN] != expected[..] {
            self.state = SessionState::AuthFailed;
            return Err(SessionError::AuthFailed);
        }
        Ok(ChallengeStatus::Success)
    }

    // -----------------------------------------------------------------
    // COT 16 — Maintenance of User Role and Update Key
    // -----------------------------------------------------------------

    /// Update-key change request. Active → AwaitingChallenge.
    pub fn on_update_key_change_request(
        &mut self,
        new_update_key: &[u8],
    ) -> Result<KeyChangePhase, SessionError> {
        if self.state != SessionState::Active {
            return Err(SessionError::NotReady);
        }
        if new_update_key.len() != SESSION_KEY_LEN {
            return Err(SessionError::BadKeyLength(new_update_key.len()));
        }
        self.session_key.copy_from_slice(new_update_key);
        self.state = SessionState::AwaitingChallenge;
        Ok(KeyChangePhase::UpdateConfirmExpected)
    }

    /// Update-key change confirm. AwaitingChallenge → Active.
    pub fn on_update_key_change_confirm(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::AwaitingChallenge {
            return Err(SessionError::UnexpectedPhase {
                expected: SessionState::AwaitingChallenge,
                got: self.state,
            });
        }
        self.state = SessionState::Active;
        Ok(())
    }

    // -----------------------------------------------------------------
    // CA status helpers
    // -----------------------------------------------------------------

    /// Compose the high-bits + CA field for an ACTIVATION_CON.
    /// Positive → bit 0x80; negative → bits 0xC0.
    pub fn ca_status_for_activation_con(&self, positive: bool) -> u16 {
        self.ca_status_for_activation_con_with_ca(positive, 0)
    }

    /// Same as `ca_status_for_activation_con` but takes the actual
    /// common-address value (low byte) so the caller doesn't need
    /// to OR the CA back in.
    pub fn ca_status_for_activation_con_with_ca(&self, positive: bool, ca: u16) -> u16 {
        let status = if positive { 0x80 } else { 0xC0 };
        // CA is low byte (8-bit range per spec). Status bits live in
        // the high byte.
        (status << 8) | (ca & 0x00FF)
    }
}

/// Compute HMAC-SHA256(key, seq || challenge), truncated to 4 bytes.
fn hmac_sha256_4(key: &[u8], seq: u32, challenge: &[u8; CHALLENGE_LEN]) -> [u8; RESPONSE_LEN] {
    let mut mac = <HmacSha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&seq.to_be_bytes());
    mac.update(challenge);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; RESPONSE_LEN];
    out.copy_from_slice(&full[..RESPONSE_LEN]);
    out
}
