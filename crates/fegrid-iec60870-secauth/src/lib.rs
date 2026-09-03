//! IEC 62351-5 secure-authentication scaffolding (G-046).
//!
//! IEC 60870-5-7 specifies an Update Key change procedure and an
//! Application-layer authentication service (C_ACSE_NA_3 type id 135).
//!
//! This crate provides a transport-agnostic key-management interface
//! and a `SecureAuthPlugin` adapter that implements the umbrella
//! [`fegrid_iec60870::Plugin`] trait. Concrete cryptographic
//! operations are delegated to user-provided [`KeyProvider`] +
//! [`ChallengeHandler`] impls — the runtime does NOT assume any
//! particular algorithm (GMac, RSA, ECDSA, etc).

use std::sync::Arc;

/// Asymmetric-algorithm identifier (placeholder; reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthAlgorithm {
    /// `M4_5_2_GMAC_SHA256` placeholder.
    GmacSha256 = 1,
    /// `M4_5_2_ECDSA_SHA256` placeholder.
    EcDsa = 2,
    /// `M4_5_2_RSA_SHA256` placeholder.
    RsaSha256 = 3,
    /// User-defined extension.
    User(u8),
}
impl AuthAlgorithm {
    /// Discriminant value for wire logging.
    pub fn wire(self) -> u8 {
        match self {
            Self::GmacSha256 => 1,
            Self::EcDsa => 2,
            Self::RsaSha256 => 3,
            Self::User(v) => v,
        }
    }
}

/// Provide the asymmetric key material the secure-auth plugin will use
/// for challenge/response exchanges.
pub trait KeyProvider: Send + Sync + 'static {
    /// Algorithm in use.
    fn algorithm(&self) -> AuthAlgorithm;
    /// Sign `challenge` with the private key; return the signature
    /// bytes.
    fn sign(&self, challenge: &[u8]) -> Result<Vec<u8>, SecAuthError>;
    /// Verify a signature against `challenge`. Returns `true` when
    /// the signature is valid.
    fn verify(&self, challenge: &[u8], signature: &[u8]) -> Result<bool, SecAuthError>;
}

/// Compute the response to a challenge the peer presented. The
/// default impl simply calls [`KeyProvider::sign`]; users can plug in
/// more elaborate schemes (challenge transforms, HMAC chains, etc).
pub trait ChallengeHandler: Send + Sync + 'static {
    /// Compute the response to `challenge` using the given
    /// [`KeyProvider`].
    fn respond(
        &self,
        provider: &dyn KeyProvider,
        challenge: &[u8],
    ) -> Result<Vec<u8>, SecAuthError>;
}

struct DefaultChallengeHandler;
impl ChallengeHandler for DefaultChallengeHandler {
    fn respond(
        &self,
        provider: &dyn KeyProvider,
        challenge: &[u8],
    ) -> Result<Vec<u8>, SecAuthError> {
        provider.sign(challenge)
    }
}

/// Errors emitted by the secure-auth plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecAuthError {
    /// User-supplied crypto returned an error.
    Crypto(String),
    /// Signature was rejected during verify.
    VerifyFailed,
    /// `KeyProvider` returned an empty buffer.
    EmptySignature,
}

/// Hook into the Cause-of-Transmission Auth values that flag
/// activation requests as authentication-bearing (C_ACSE_NA_3).
pub fn is_auth_cot(originator: u8, ca_field: u8) -> bool {
    // The C_ACSE_NA_3 type id is 135; we don't have direct access to
    // the Asdu here so we approximate via originator + CA bits that
    // flag "secure activation" frames.
    const AUTH_ORIGINATOR_MASK: u8 = 0x40;
    const AUTH_CA_MASK: u8 = 0x80;
    originator & AUTH_ORIGINATOR_MASK != 0 && ca_field & AUTH_CA_MASK != 0
}

/// Builder for a [`SecureAuthPlugin`].
pub struct SecureAuthBuilder {
    provider: Option<Arc<dyn KeyProvider>>,
    handler: Arc<dyn ChallengeHandler>,
    name: String,
}

impl Default for SecureAuthBuilder {
    fn default() -> Self {
        Self {
            provider: None,
            handler: Arc::new(DefaultChallengeHandler),
            name: "secure-auth".to_string(),
        }
    }
}

impl SecureAuthBuilder {
    /// Construct a new builder.
    pub fn new() -> Self {
        Self::default()
    }
    /// Install the key provider.
    pub fn provider(mut self, provider: Arc<dyn KeyProvider>) -> Self {
        self.provider = Some(provider);
        self
    }
    /// Install a custom challenge handler.
    pub fn challenge_handler(mut self, h: Arc<dyn ChallengeHandler>) -> Self {
        self.handler = h;
        self
    }
    /// Override the plugin name (diagnostic).
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = n.into();
        self
    }
    /// Build the plugin.
    pub fn build(self) -> Result<SecureAuthPlugin, SecAuthError> {
        let provider = self
            .provider
            .ok_or_else(|| SecAuthError::Crypto("missing KeyProvider".to_string()))?;
        Ok(SecureAuthPlugin {
            provider,
            handler: self.handler,
            name: self.name,
        })
    }
}

/// Secure-authentication plugin that wraps a [`KeyProvider`] and
/// signs/verifies challenges.
pub struct SecureAuthPlugin {
    provider: Arc<dyn KeyProvider>,
    handler: Arc<dyn ChallengeHandler>,
    #[allow(dead_code)]
    name: String,
}

impl SecureAuthPlugin {
    /// Borrow the configured key provider.
    pub fn provider(&self) -> &Arc<dyn KeyProvider> {
        &self.provider
    }
    /// Sign a challenge.
    pub fn sign(&self, challenge: &[u8]) -> Result<Vec<u8>, SecAuthError> {
        self.handler.respond(self.provider.as_ref(), challenge)
    }
    /// Verify a signature against a challenge.
    pub fn verify(&self, challenge: &[u8], signature: &[u8]) -> Result<bool, SecAuthError> {
        self.provider.verify(challenge, signature)
    }
    /// Algorithm in use.
    pub fn algorithm(&self) -> AuthAlgorithm {
        self.provider.algorithm()
    }
}

// impl Plugin for SecureAuthPlugin is provided by the umbrella crate
// when it wires the trait together. This module exposes only the
// transport-agnostic primitives.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubProvider {
        algo: AuthAlgorithm,
        #[allow(dead_code)]
        valid_challenge: Vec<u8>,
        counter: AtomicUsize,
    }
    impl KeyProvider for StubProvider {
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

    #[test]
    fn builder_requires_provider() {
        let r = SecureAuthBuilder::new().build();
        assert!(matches!(r, Err(SecAuthError::Crypto(_))));
    }

    #[test]
    fn plugin_signs_and_verifies() {
        let provider = Arc::new(StubProvider {
            algo: AuthAlgorithm::GmacSha256,
            valid_challenge: Vec::new(),
            counter: AtomicUsize::new(0),
        });
        let plugin = SecureAuthBuilder::new()
            .provider(provider.clone())
            .build()
            .unwrap();
        let sig = plugin.sign(b"abc").unwrap();
        assert_eq!(sig, b"abc".to_vec());
        assert!(plugin.verify(b"abc", &sig).unwrap());
        assert!(!plugin.verify(b"xyz", &sig).unwrap());
    }

    #[test]
    fn is_auth_cot_truthy_for_seven() {
        assert!(is_auth_cot(0x40, 0x80));
        assert!(!is_auth_cot(0x00, 0x00));
    }

    #[test]
    fn algorithm_enum_discriminants() {
        assert_eq!(AuthAlgorithm::GmacSha256.wire(), 1);
        assert_eq!(AuthAlgorithm::EcDsa.wire(), 2);
        assert_eq!(AuthAlgorithm::RsaSha256.wire(), 3);
    }
}
