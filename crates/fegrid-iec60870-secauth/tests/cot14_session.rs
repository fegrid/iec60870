//! IEC 60870-5-7 secure-authentication session state machine.
//!
//! Mirrors the opendnp3 secure-auth (SA) pattern for the IEC
//! 60870-5-104 application layer. Two COTs drive the protocol:
//!
//! - COT 14 (Authentication) — challenge / response exchange.
//! - COT 15 (MaintenanceOfAuthSessionKey) — key change procedure
//!   (4-message Generate-Key-Request / Confirm / Activate-Key-Request
//!   / Confirm).
//! - COT 16 (MaintenanceOfUserRoleAndUpdateKey) — user-role + update
//!   key change.
//!
//! The status is carried in the high bits of the CA field of the
//! response ASDU:
//!
//! - bit 0x80 = ACTIVATION_CON bit set (positive ACK)
//! - bit 0xC0 = ACTIVATION_CON negative (auth failure)
//!
//! This file is TDD: every `#[test]` here asserts a public contract
//! of `fegrid_iec60870_secauth::session::SecureSession`; the
//! production module under `src/session.rs` exists only to make these
//! tests pass.

use fegrid_iec60870_secauth::session::{
    ChallengeStatus, KeyChangePhase, SecureSession, SessionError, SessionState,
};

// ===========================================================================
// State machine: Idle → AwaitingChallenge → Active / AuthFailed
// ===========================================================================

#[test]
fn fresh_session_is_idle() {
    let s = SecureSession::new([0u8; 32]);
    assert_eq!(s.state(), SessionState::Idle);
}

#[test]
fn challenge_before_key_change_is_rejected() {
    // Per IEC 60870-5-7: the session key must be established (4-step
    // key change procedure) before any challenge can be issued.
    let mut s = SecureSession::new([0u8; 32]);
    let err = s
        .on_challenge_request(b"random-challenge-bytes-32-bytes-pls")
        .unwrap_err();
    assert!(matches!(err, SessionError::NotReady));
}

#[test]
fn invalid_challenge_length_is_rejected() {
    // Challenge length: per spec, 32 bytes for HMAC-SHA256-4 mode.
    let mut s = SecureSession::new([0u8; 32]);
    complete_key_change(&mut s, [0xAA; 32]);
    assert_eq!(s.state(), SessionState::Active);
    let err = s.on_challenge_request(b"short").unwrap_err();
    assert!(matches!(err, SessionError::BadChallengeLength(5)));
    let err = s.on_challenge_request(&[0u8; 64]).unwrap_err();
    assert!(matches!(err, SessionError::BadChallengeLength(64)));
}

#[test]
fn session_key_zero_rejected_on_construction() {
    // All-zero key is a footgun — refuse at construction.
    let err = SecureSession::try_new([0u8; 32]).unwrap_err();
    assert!(matches!(err, SessionError::ZeroKey));
}

// ===========================================================================
// Key change procedure (COT 15) — 4-message exchange
// ===========================================================================

#[test]
fn key_change_full_procedure_completes() {
    let mut s = SecureSession::new([0u8; 32]);
    // Step 1: Generate Key Request.
    let phase = s.on_key_change_generate_request(0xDEAD_BEEF_u32).unwrap();
    assert_eq!(phase, KeyChangePhase::GenerateConfirmExpected);
    // Step 2: Generate Key Confirm (carries the new 32-byte key).
    s.on_key_change_generate_confirm(&new_session_key())
        .unwrap();
    // Step 3: Activate Key Request.
    let phase = s.on_key_change_activate_request().unwrap();
    assert_eq!(phase, KeyChangePhase::ActivateConfirmExpected);
    // Step 4: Activate Key Confirm.
    s.on_key_change_activate_confirm().unwrap();
    assert_eq!(s.state(), SessionState::Active);
}

#[test]
fn key_change_out_of_order_fails_cleanly() {
    let mut s = SecureSession::new([0u8; 32]);
    // Skip the Generate-Request, jump straight to Confirm.
    let err = s
        .on_key_change_generate_confirm(&new_session_key())
        .unwrap_err();
    assert!(matches!(err, SessionError::UnexpectedPhase { .. }));
    assert_eq!(s.state(), SessionState::Idle);
}

#[test]
fn key_change_repeat_generate_after_confirm_fails() {
    let mut s = SecureSession::new([0u8; 32]);
    s.on_key_change_generate_request(1).unwrap();
    s.on_key_change_generate_confirm(&new_session_key())
        .unwrap();
    // Second Generate-Request after Confirm is illegal.
    let err = s.on_key_change_generate_request(2).unwrap_err();
    assert!(matches!(err, SessionError::UnexpectedPhase { .. }));
}

#[test]
fn key_change_confirm_with_wrong_key_size_fails() {
    let mut s = SecureSession::new([0u8; 32]);
    s.on_key_change_generate_request(1).unwrap();
    let err = s.on_key_change_generate_confirm(&[0u8; 16]).unwrap_err();
    assert!(matches!(err, SessionError::BadKeyLength(16)));
}

// ===========================================================================
// Challenge / response (COT 14)
// ===========================================================================

#[test]
fn challenge_response_round_trip_succeeds() {
    let mut s = SecureSession::new([0u8; 32]);
    complete_key_change(&mut s, [0x42; 32]);

    // Master → outstation: 32-byte challenge.
    let challenge = [0u8; 32];
    let response = s.on_challenge_request(&challenge).expect("challenge ok");
    assert_eq!(response.len(), 4, "HMAC-SHA256-4 truncated to 4 bytes");

    // Outstation → master: response back. The same session must
    // validate the response (HMAC matches with the same key).
    let status = s.on_challenge_response(&response).expect("response ok");
    assert_eq!(status, ChallengeStatus::Success);
}

#[test]
fn challenge_response_tampered_fails_authentication() {
    let mut s = SecureSession::new([0u8; 32]);
    complete_key_change(&mut s, [0x42; 32]);

    let challenge = [0u8; 32];
    let mut response = s.on_challenge_request(&challenge).expect("challenge ok");
    response[0] ^= 0x01; // flip one bit

    let err = s.on_challenge_response(&response).unwrap_err();
    assert!(matches!(err, SessionError::AuthFailed));
    // State must transition to AuthFailed after a single failure
    // (per spec, no retry on tamper).
    assert_eq!(s.state(), SessionState::AuthFailed);
}

#[test]
fn challenge_response_with_different_key_fails() {
    // Two sessions with different keys — challenge from one should
    // not validate on the other.
    let mut s1 = SecureSession::new([0u8; 32]);
    let mut s2 = SecureSession::new([0u8; 32]);
    complete_key_change(&mut s1, [0x42; 32]);
    complete_key_change(&mut s2, [0x99; 32]);
    let challenge = [0u8; 32];
    let response = s1.on_challenge_request(&challenge).expect("s1 ok");
    // and on_challenge_response errors out with NotReady. Instead,
    // issue a challenge on s2 to populate pending_challenge, then
    // pass s1's response to s2 — the HMAC will not match (different
    // session key) and s2 must report AuthFailed.
    let _ = s2.on_challenge_request(&challenge).expect("s2 ok");
    let err = s2.on_challenge_response(&response).unwrap_err();
    assert!(matches!(err, SessionError::AuthFailed));
}

#[test]
fn repeated_challenges_advance_sequence() {
    let mut s = SecureSession::new([0u8; 32]);
    complete_key_change(&mut s, [0x42; 32]);

    // Two consecutive challenges with the same input should yield
    // different HMACs if the implementation incorporates a sequence
    // number (CS104 SA-V5 mode). Per spec, the challenge response
    // includes a 4-byte sequence number in the HMAC input.
    let c = [0u8; 32];
    let r1 = s.on_challenge_request(&c).unwrap();
    let r2 = s.on_challenge_request(&c).unwrap();
    assert_ne!(r1, r2, "different sequence numbers → different HMACs");
    assert_eq!(s.sequence_counter(), 2);
}

#[test]
fn challenge_response_in_idle_state_fails() {
    // Fresh session (Idle) → cannot answer challenge.
    let mut s = SecureSession::new([0u8; 32]);
    let err = s.on_challenge_response(&[0u8; 4]).unwrap_err();
    assert!(matches!(err, SessionError::NotReady));
}

// ===========================================================================
// Status reporting — CA field high bits
// ===========================================================================

#[test]
fn ca_status_positive_activation_con_bit() {
    // ACTIVATION_CON positive → CA bit 0x80 set.
    let s = SecureSession::new([0u8; 32]);
    let ca = s.ca_status_for_activation_con(true);
    assert_eq!(ca & 0x8000, 0x8000, "high byte bit 0x80 set (positive)");
}

#[test]
fn ca_status_negative_activation_con_bits() {
    // ACTIVATION_CON negative → CA bits 0xC0 set.
    let s = SecureSession::new([0u8; 32]);
    let ca = s.ca_status_for_activation_con(false);
    assert_eq!(ca & 0xC000, 0xC000, "high byte bits 0xC0 set (negative)");
}

#[test]
fn ca_status_preserves_low_bits() {
    // ca_status_for_* must not stomp on the low 8 bits that carry
    // the actual common address (1..=65534).
    let s = SecureSession::new([0u8; 32]);
    let ca_pos = s.ca_status_for_activation_con_with_ca(true, 7);
    assert_eq!(ca_pos & 0x00FF, 0x07, "low byte = CA=7");
    assert_eq!(ca_pos & 0x8000, 0x8000, "positive bit set in high byte");
}

#[test]
fn ca_status_negative_also_preserves_low_bits() {
    let s = SecureSession::new([0u8; 32]);
    let ca_neg = s.ca_status_for_activation_con_with_ca(false, 0xABCD);
    assert_eq!(ca_neg & 0x00FF, 0xCD, "low byte preserved");
    assert_eq!(ca_neg & 0xC000, 0xC000, "negative bits set");
}

// ===========================================================================
// COT 16 — Maintenance of User Role and Update Key
// ===========================================================================

#[test]
fn user_role_change_proceeds_after_active() {
    let mut s = SecureSession::new([0u8; 32]);
    complete_key_change(&mut s, [0x42; 32]);
    // After session is Active, an update-key change (COT 16) is
    // legal. It transitions back to Active with the new update key.
    let phase = s.on_update_key_change_request(&[0u8; 32]).unwrap();
    assert_eq!(phase, KeyChangePhase::UpdateConfirmExpected);
    s.on_update_key_change_confirm().unwrap();
    assert_eq!(s.state(), SessionState::Active);
}

#[test]
fn update_key_change_before_active_fails() {
    let mut s = SecureSession::new([0u8; 32]);
    let err = s.on_update_key_change_request(&[0u8; 32]).unwrap_err();
    assert!(matches!(err, SessionError::NotReady));
}

// ===========================================================================
// Helpers
// ===========================================================================

fn complete_key_change(s: &mut SecureSession, new_key: [u8; 32]) {
    s.on_key_change_generate_request(1).unwrap();
    s.on_key_change_generate_confirm(&new_key).unwrap();
    s.on_key_change_activate_request().unwrap();
    s.on_key_change_activate_confirm().unwrap();
    assert_eq!(s.state(), SessionState::Active);
}

fn new_session_key() -> [u8; 32] {
    [0xAB; 32]
}
