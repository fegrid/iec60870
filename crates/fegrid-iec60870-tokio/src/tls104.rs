//! TLS transport for CS 104 (IEC 60870-5-104 over TLS).
//!
//! Wraps a [`tokio::net::TcpStream`] in rustls 0.23 (TLS 1.2+1.3, ring
//! crypto provider), then frames the resulting stream with
//! [`crate::codec104::ApduCodec`] — protocol logic stays in
//! `fegrid_iec60870_cs104`.  [`Tls104Stream`] is therefore the
//! TLS-secure counterpart of the plain-TCP framed stream and yields the
//! same [`fegrid_iec60870_cs104::Apdu`] items.
//!
use std::fs;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::{
    TlsAcceptor as TokioTlsAcceptor, TlsConnector as TokioTlsConnector, client, server,
};
use tokio_util::codec::Framed;

use crate::codec104::ApduCodec;

/// IEC 60870-5-104 default TLS port.

/// Errors returned by the TLS-104 transport.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Underlying I/O failure (TCP connect, accept, file read).
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// rustls handshake / configuration failure.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    /// PEM input could not be parsed.
    #[error("pem parse: {0}")]
    Pem(String),
    /// PEM input contained no usable certificate or private key.
    #[error("no usable certificate/key material in PEM input")]
    NoMaterial,
}

/// Server or client identity: one certificate chain + one private key,
/// loaded from PEM.
#[derive(Debug)]
pub struct TlsIdentity {
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    /// Parse a cert chain and private key from in-memory PEM strings.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, TlsError> {
        let cert_chain = parse_certs(cert_pem)?;
        if cert_chain.is_empty() {
            return Err(TlsError::NoMaterial);
        }
        let key = parse_key(key_pem)?;
        Ok(Self { cert_chain, key })
    }

    /// Read the cert and key PEM files from disk and parse them.
    pub fn from_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        let cert_pem = fs::read_to_string(cert_path.as_ref())?;
        let key_pem = fs::read_to_string(key_path.as_ref())?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Borrow the parsed certificate chain.
    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    /// Borrow the parsed private key.
    pub fn key(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }
}

/// Trusted CA certificates for validating the peer.
#[derive(Debug)]
pub struct TlsTrustRoots(pub rustls::RootCertStore);

impl TlsTrustRoots {
    /// Parse a bundle of PEM-encoded CA certificates.
    pub fn from_pem(pem: &str) -> Result<Self, TlsError> {
        let mut store = rustls::RootCertStore::empty();
        let certs = parse_certs(pem)?;
        let (added, _) = store.add_parsable_certificates(certs);
        if added == 0 {
            return Err(TlsError::NoMaterial);
        }
        Ok(Self(store))
    }

    /// Read the CA bundle PEM from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, TlsError> {
        let pem = fs::read_to_string(path.as_ref())?;
        Self::from_pem(&pem)
    }
}

/// Server-side TLS settings: an identity to present + optional mTLS
/// configuration (G-044) + ALPN protocols + cipher policy (G-044).
#[derive(Debug)]
pub struct TlsServerConfig {
    identity: TlsIdentity,
    client_ca: Option<rustls::RootCertStore>,
    alpn_protocols: Vec<Vec<u8>>,
    min_protocol_version: rustls::ProtocolVersion,
    max_protocol_version: rustls::ProtocolVersion,
}

impl TlsServerConfig {
    /// Build server settings from an [`TlsIdentity`].
    pub fn new(identity: TlsIdentity) -> Self {
        Self {
            identity,
            client_ca: None,
            alpn_protocols: Vec::new(),
            min_protocol_version: rustls::ProtocolVersion::TLSv1_2,
            max_protocol_version: rustls::ProtocolVersion::TLSv1_3,
        }
    }
    /// Enable mutual TLS by supplying a trust store for client
    /// certificates (G-044, `with_client_auth`).
    #[must_use]
    pub fn with_client_auth(mut self, ca: TlsTrustRoots) -> Self {
        self.client_ca = Some(ca.0);
        self
    }
    /// Set the ALPN protocols offered during the handshake (G-044).
    /// Each entry must be a valid IANA protocol identifier
    /// (`b"iec60870-104"` etc.).
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }
    /// Set the minimum TLS protocol version (G-044).
    #[must_use]
    pub fn with_version_floor(mut self, version: rustls::ProtocolVersion) -> Self {
        self.min_protocol_version = version;
        self
    }
    /// Set the maximum TLS protocol version (G-044).
    #[must_use]
    pub fn with_version_ceiling(mut self, version: rustls::ProtocolVersion) -> Self {
        self.max_protocol_version = version;
        self
    }
    /// Whether mTLS is enabled.
    pub fn client_auth_enabled(&self) -> bool {
        self.client_ca.is_some()
    }
    /// Negotiated ALPN protocols (set by builder).
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }
    /// Minimum TLS version.
    pub fn min_protocol_version(&self) -> rustls::ProtocolVersion {
        self.min_protocol_version
    }
    /// Maximum TLS version.
    pub fn max_protocol_version(&self) -> rustls::ProtocolVersion {
        self.max_protocol_version
    }
    /// Borrow the identity.
    pub fn identity(&self) -> &TlsIdentity {
        &self.identity
    }
}

/// Client-side TLS settings: trust anchors + optional CRLs (G-044) +
/// ALPN + cipher policy (G-044).
#[derive(Debug)]
pub struct TlsClientConfig {
    trust: TlsTrustRoots,
    crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>>,
    alpn_protocols: Vec<Vec<u8>>,
    min_protocol_version: rustls::ProtocolVersion,
}

impl TlsClientConfig {
    /// Build client settings from [`TlsTrustRoots`].
    pub fn new(trust: TlsTrustRoots) -> Self {
        Self {
            trust,
            crls: Vec::new(),
            alpn_protocols: Vec::new(),
            min_protocol_version: rustls::ProtocolVersion::TLSv1_2,
        }
    }
    /// Set the ALPN protocols offered during the handshake (G-044).
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }
    /// Append a CRL to the client trust validation chain (G-044).
    #[must_use]
    pub fn with_crl(
        mut self,
        crl: rustls::pki_types::CertificateRevocationListDer<'static>,
    ) -> Self {
        self.crls.push(crl);
        self
    }
    /// Set the minimum TLS protocol version (G-044).
    #[must_use]
    pub fn with_version_floor(mut self, version: rustls::ProtocolVersion) -> Self {
        self.min_protocol_version = version;
        self
    }
    /// Borrow the trust roots.
    pub fn trust(&self) -> &TlsTrustRoots {
        &self.trust
    }
    /// Number of CRLs currently loaded.
    pub fn crl_count(&self) -> usize {
        self.crls.len()
    }
    /// Negotiated ALPN protocols (set by builder).
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }
    /// Minimum TLS version.
    pub fn min_protocol_version(&self) -> rustls::ProtocolVersion {
        self.min_protocol_version
    }
}

/// Connection metadata exposed after the TLS handshake completes
/// (G-045).
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetadata {
    /// Negotiated ALPN protocol (None if no ALPN was negotiated).
    pub alpn: Option<Vec<u8>>,
    /// Peer certificate chain (subjects, in order).
    pub peer_subjects: Vec<String>,
    /// Negotiated TLS version.
    pub tls_version: Option<String>,
    /// Negotiated cipher suite.
    pub cipher_suite: Option<String>,
}

/// A TLS-wrapped CS 104 stream, framed into APDUs by [`ApduCodec`].
/// Acceptors hold a [`server::TlsStream`] inner; connectors a
/// [`client::TlsStream`] inner.  Both variants satisfy the same
/// `Stream<Item = Result<Apdu, CodecError>> + Sink<Apdu, Error = CodecError>`
/// shape, so a caller drives either end with the same `SinkExt` /
/// `StreamExt` calls.
pub struct Tls104Stream(Framed<Inner, ApduCodec>);

impl std::fmt::Debug for Tls104Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls104Stream").finish_non_exhaustive()
    }
}

impl futures::Stream for Tls104Stream {
    type Item = Result<fegrid_iec60870_cs104::Apdu, crate::codec104::CodecError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

impl futures::Sink<fegrid_iec60870_cs104::Apdu> for Tls104Stream {
    type Error = crate::codec104::CodecError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: fegrid_iec60870_cs104::Apdu,
    ) -> Result<(), Self::Error> {
        Pin::new(&mut self.0).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

/// Type-erased inner: tokio-rustls 0.26 returns `client::TlsStream` or
/// `server::TlsStream` (different concrete types), so we erase them
/// behind a single `AsyncRead + AsyncWrite` to fit one [`Tls104Stream`].
enum Inner {
    /// Server-side TLS stream returned by `TlsAcceptor::accept`.
    Server(server::TlsStream<TcpStream>),
    /// Client-side TLS stream returned by `TlsConnector::connect`.
    Client(client::TlsStream<TcpStream>),
}

impl AsyncRead for Inner {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Inner::Server(s) => Pin::new(s).poll_read(cx, buf),
            Inner::Client(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Inner {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Inner::Server(s) => Pin::new(s).poll_write(cx, buf),
            Inner::Client(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Inner::Server(s) => Pin::new(s).poll_flush(cx),
            Inner::Client(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Inner::Server(s) => Pin::new(s).poll_shutdown(cx),
            Inner::Client(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Accepts inbound TCP connections and completes the TLS handshake,
/// handing back a framed CS 104 stream.
#[derive(Clone)]
pub struct Tls104Acceptor {
    inner: TokioTlsAcceptor,
}

impl std::fmt::Debug for Tls104Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls104Acceptor").finish_non_exhaustive()
    }
}

impl Tls104Acceptor {
    /// Build a server-side acceptor from [`TlsServerConfig`].
    pub fn new(cfg: &TlsServerConfig) -> Result<Self, TlsError> {
        ensure_provider();

        let server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                cfg.identity.cert_chain.clone(),
                cfg.identity.key.clone_key(),
            )
            .map_err(TlsError::from)?;
        Ok(Self {
            inner: TokioTlsAcceptor::from(Arc::new(server_cfg)),
        })
    }

    /// Complete the TLS handshake on an already-accepted TCP stream.
    pub async fn accept(&self, conn: TcpStream) -> Result<Tls104Stream, TlsError> {
        let tls = self.inner.accept(conn).await?;
        Ok(Tls104Stream(Framed::new(
            Inner::Server(tls),
            ApduCodec::new(),
        )))
    }
}

/// Opens outbound TCP connections, performs the TLS handshake, and
/// returns a framed CS 104 stream.
#[derive(Clone)]
pub struct Tls104Connector {
    inner: TokioTlsConnector,
    name: ServerName<'static>,
}

impl std::fmt::Debug for Tls104Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls104Connector")
            .field("name", &self.name.to_str())
            .finish_non_exhaustive()
    }
}

impl Tls104Connector {
    /// Build a client-side connector. `server_name` is the SNI value
    /// sent during the handshake and must match the server certificate.
    pub fn new(cfg: &TlsClientConfig, server_name: &str) -> Result<Self, TlsError> {
        ensure_provider();

        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(cfg.trust.0.clone())
            .with_no_client_auth();
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| TlsError::Pem("invalid server name".to_owned()))?
            .to_owned();
        Ok(Self {
            inner: TokioTlsConnector::from(Arc::new(client_cfg)),
            name,
        })
    }

    /// Open a TCP connection to `addr`, perform the TLS handshake, and
    /// frame the stream for CS 104.
    pub async fn connect<A>(&self, addr: A) -> Result<Tls104Stream, TlsError>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;
        let tls = self.inner.connect(self.name.clone(), stream).await?;
        Ok(Tls104Stream(Framed::new(
            Inner::Client(tls),
            ApduCodec::new(),
        )))
    }
}

/// Install the `ring` crypto provider as the rustls default if no
/// provider is installed yet.  `install_default` is internally
/// synchronized, so concurrent first-time callers race safely; an
/// "already installed" error from a losing thread is swallowed.
fn ensure_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Pem(e.to_string()))
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    use rustls::pki_types::pem::PemObject;
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| TlsError::Pem(e.to_string()))
        .and_then(|k| match k {
            PrivateKeyDer::Pkcs1(_) | PrivateKeyDer::Pkcs8(_) | PrivateKeyDer::Sec1(_) => Ok(k),
            // PrivateKeyDer is #[non_exhaustive]; cover any future variant by
            // treating it as 'no usable material' rather than a hard panic.
            _ => Err(TlsError::NoMaterial),
        })
}
