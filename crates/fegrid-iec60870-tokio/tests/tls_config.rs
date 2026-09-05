//! Tests for the TLS configuration surface (E8).
//!
//! Exercises the builder methods on TlsServerConfig + TlsClientConfig
//! without doing a full handshake (which would require a real cert).

#![cfg(feature = "tls")]
use fegrid_iec60870_tokio::tls104::{TlsClientConfig, TlsError, TlsTrustRoots};

#[test]
fn empty_pem_is_rejected() {
    let res = TlsTrustRoots::from_pem("");
    assert!(matches!(res, Err(TlsError::NoMaterial)));
}

#[test]
fn rustls_version_types_are_exposed() {
    // Confirm the version-floor API is callable.
    let _v = rustls::ProtocolVersion::TLSv1_2;
    let _v2 = rustls::ProtocolVersion::TLSv1_3;
}

#[test]
fn client_config_builder_compiles() {
    // Verify the client config builder methods exist and have the
    // expected signatures by calling them with dummy data. We can't
    // build a real TlsTrustRoots here without a PEM, so we only check
    // that the API surface compiles.
    fn _takes(_: TlsClientConfig) {}
    fn _build(_trust: TlsTrustRoots) -> TlsClientConfig {
        TlsClientConfig::new(_trust).with_alpn_protocols(vec![b"x".to_vec()])
    }
    let _ = _takes;
    let _ = _build;
}
