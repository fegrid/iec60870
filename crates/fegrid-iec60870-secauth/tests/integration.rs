//! Integration tests for the secure-authentication plugin scaffold.
//!
//! Exercises real sign/verify roundtrips, custom challenge handlers,
//! and the algorithm enum against the public surface exported from
//! `fegrid_iec60870_secauth`. Companion to the unit tests in
//! `src/lib.rs::tests`; the unit tests cover the API shape, this
//! file covers end-to-end behaviour.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fegrid_iec60870_secauth::{
    AuthAlgorithm, ChallengeHandler, KeyProvider, SecAuthError, SecureAuthBuilder, SecureAuthPlugin,
};

/// A `KeyProvider` that echoes the challenge as the signature. Simple,
/// sufficient for roundtrip tests. The `counter` records how many
/// `sign` calls happened, so tests can verify the plugin used the
/// provider rather than a cached value.
struct EchoProvider {
    algo: AuthAlgorithm,
    counter: AtomicUsize,
}

impl KeyProvider for EchoProvider {
    fn algorithm(&self) -> AuthAlgorithm {
        self.algo
    }
    fn sign(&self, challenge: &[u8]) -> Result<Vec<u8>, SecAuthError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(challenge.to_vec())
    }
    fn verify(&self, challenge: &[u8], signature: &[u8]) -> Result<bool, SecAuthError> {
        Ok(challenge == signature)
    }
}

/// A `ChallengeHandler` that XORs the challenge with a one-byte pad
/// before signing. Lets tests verify the handler is actually called
/// rather than the default being substituted.
struct XorHandler {
    pad: u8,
    calls: AtomicUsize,
}

impl ChallengeHandler for XorHandler {
    fn respond(
        &self,
        provider: &dyn KeyProvider,
        challenge: &[u8],
    ) -> Result<Vec<u8>, SecAuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let transformed: Vec<u8> = challenge.iter().map(|b| b ^ self.pad).collect();
        provider.sign(&transformed)
    }
}

fn echo_plugin(algo: AuthAlgorithm) -> (Arc<EchoProvider>, SecureAuthPlugin) {
    let provider = Arc::new(EchoProvider {
        algo,
        counter: AtomicUsize::new(0),
    });
    let plugin = SecureAuthBuilder::new()
        .provider(provider.clone())
        .build()
        .expect("build with provider");
    (provider, plugin)
}

#[test]
fn sign_then_verify_roundtrip_succeeds() {
    let (_provider, plugin) = echo_plugin(AuthAlgorithm::GmacSha256);
    let challenge = b"challenge-payload-001";
    let sig = plugin.sign(challenge).expect("sign");
    assert_eq!(sig, challenge);
    assert!(plugin.verify(challenge, &sig).expect("verify"));
}

#[test]
fn verify_rejects_tampered_signature() {
    let (_provider, plugin) = echo_plugin(AuthAlgorithm::GmacSha256);
    let challenge = b"original";
    let sig = plugin.sign(challenge).expect("sign");
    // Tamper: flip one byte of the signature.
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0xff;
    assert!(!plugin.verify(challenge, &bad_sig).expect("verify"));
}

#[test]
fn verify_rejects_signature_for_different_challenge() {
    let (_provider, plugin) = echo_plugin(AuthAlgorithm::GmacSha256);
    let sig = plugin.sign(b"challenge-A").expect("sign");
    assert!(!plugin.verify(b"challenge-B", &sig).expect("verify"));
}

#[test]
fn provider_sign_counter_advances_on_each_call() {
    let (provider, plugin) = echo_plugin(AuthAlgorithm::GmacSha256);
    assert_eq!(provider.counter.load(Ordering::SeqCst), 0);
    let _ = plugin.sign(b"first").unwrap();
    assert_eq!(provider.counter.load(Ordering::SeqCst), 1);
    let _ = plugin.sign(b"second").unwrap();
    let _ = plugin.sign(b"third").unwrap();
    assert_eq!(provider.counter.load(Ordering::SeqCst), 3);
}

#[test]
fn custom_challenge_handler_is_invoked() {
    let plugin = SecureAuthBuilder::new()
        .provider(provider_from_echo())
        .challenge_handler(Arc::new(XorHandler {
            pad: 0x5a,
            calls: AtomicUsize::new(0),
        }))
        .build()
        .expect("build");

    // XorHandler feeds the transformed challenge to KeyProvider::sign,
    // which (for EchoProvider) echoes it back unchanged. So the
    // signature should equal the XORed challenge.
    let challenge = b"hello";
    let sig = plugin.sign(challenge).expect("sign");
    let expected: Vec<u8> = challenge.iter().map(|b| b ^ 0x5a).collect();
    assert_eq!(sig, expected);
}

fn provider_from_echo() -> Arc<dyn KeyProvider> {
    Arc::new(EchoProvider {
        algo: AuthAlgorithm::EcDsa,
        counter: AtomicUsize::new(0),
    })
}

#[test]
fn algorithm_negotiation_round_trip() {
    for algo in [
        AuthAlgorithm::GmacSha256,
        AuthAlgorithm::EcDsa,
        AuthAlgorithm::RsaSha256,
    ] {
        let (_provider, plugin) = echo_plugin(algo);
        assert_eq!(plugin.algorithm(), algo);
    }
}

#[test]
fn builder_without_provider_yields_error() {
    let r = SecureAuthBuilder::new().build();
    match r {
        Err(SecAuthError::Crypto(msg)) => {
            assert!(msg.contains("missing"), "error msg mentions missing: {msg}");
        }
        Err(e) => panic!("expected Crypto error, got {e:?}"),
        Ok(_) => panic!("expected error from missing provider, got Ok"),
    }
}

#[test]
fn empty_signature_from_provider_is_caught() {
    struct EmptyProvider;
    impl KeyProvider for EmptyProvider {
        fn algorithm(&self) -> AuthAlgorithm {
            AuthAlgorithm::RsaSha256
        }
        fn sign(&self, _challenge: &[u8]) -> Result<Vec<u8>, SecAuthError> {
            Ok(Vec::new())
        }
        fn verify(&self, _challenge: &[u8], _sig: &[u8]) -> Result<bool, SecAuthError> {
            Ok(false)
        }
    }
    let plugin = SecureAuthBuilder::new()
        .provider(Arc::new(EmptyProvider))
        .build()
        .unwrap();
    // The plugin doesn't itself validate empty signature; the
    // verifier downstream does. The plugin returns Ok(Vec::new()) and
    // downstream code is expected to treat that as invalid. Assert
    // the contract: the plugin does NOT panic and the verify returns
    // false for an empty signature.
    let sig = plugin.sign(b"challenge").expect("sign");
    assert!(sig.is_empty());
    assert!(!plugin.verify(b"challenge", &sig).expect("verify"));
}

#[test]
fn is_auth_cot_distinguishes_secure_from_regular() {
    // Originator bit 0x40 + CA bit 0x80 → secure auth activation.
    assert!(fegrid_iec60870_secauth::is_auth_cot(0x40, 0x80));
    // Either bit missing → not secure.
    assert!(!fegrid_iec60870_secauth::is_auth_cot(0x00, 0x80));
    assert!(!fegrid_iec60870_secauth::is_auth_cot(0x40, 0x00));
    assert!(!fegrid_iec60870_secauth::is_auth_cot(0x00, 0x00));
}
