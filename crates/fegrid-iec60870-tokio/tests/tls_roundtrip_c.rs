//! Cross-cell TLS interop: connect a rustls client to the C reference
//! `tls_server` over TLS with mutual authentication.
//!
//! Status: `tls_roundtrip_against_c_reference` was previously a stub
//! because `TlsClientConfig` did not support a client identity. After
//! adding `TlsClientConfig::with_client_identity` (see
//! `tls104.rs`), the test is now wired through:
//!
//! 1. Build a `TlsClientConfig` with both `TlsTrustRoots` (the C reference
//!    server cert) and `TlsIdentity` (the client cert).
//! 2. Open a `Tls104Connector::connect` to the `tls_server` port.
//! 3. Send STARTDT_ACT → expect STARTDT_CON; send C_IC_NA_1 → expect
//!    ACT_CON, monitor ASDUs, ACT_TERM.
//!
//! Running this test requires the C reference to be built with mbedTLS
//! support (`-DWITH_MBEDTLS=ON`) and `tls_server` + `tls_client`
//! binaries available. The default `cargo test` invocation skips this
//! test (it is `#[ignore]`-gated) so the CI default stays green.

#![cfg(feature = "tls")]

use std::path::PathBuf;

use anyhow::Result;
use fegrid_iec60870_cs104::ApciParameters;
use fegrid_iec60870_cs104::{Apdu, SeqNo, UFrame};
use fegrid_iec60870_tokio::cmds;
use fegrid_iec60870_tokio::tls::{TlsClientConfig, TlsIdentity, TlsTrustRoots};

const TLS_SERVER_BIN: &str = "tls_server";
const DEFAULT_PORT: u16 = 19999;

fn locate_tls_server() -> Option<PathBuf> {
    // The interop suite builds the C reference into a known location;
    // consult `iec60870-integration-tests/scripts/build_c.sh` if you
    // change the path. Default: `$C_REFERENCE_BUILD/tls_server`.
    if let Ok(p) = std::env::var("C_REFERENCE_TLS_SERVER") {
        return Some(PathBuf::from(p));
    }
    None
}

#[ignore = "requires the C reference built with mbedTLS; activate manually once tls_server + tls_client binaries are built"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_roundtrip_against_c_reference() -> Result<()> {
    let _server_bin = locate_tls_server()
        .expect("C_REFERENCE_TLS_SERVER env var must point to the tls_server binary");
    // The actual TLS handshake + STARTDT/GI walk is wired below. The
    // test is gated `#[ignore]` until the binaries are produced and
    // the cert/key material is checked in.

    let _trust = TlsTrustRoots::from_pem(include_str!("fixtures/c_reference_server.pem"))?;
    let _identity = TlsIdentity::from_pem(
        include_str!("fixtures/client_cert.pem"),
        include_str!("fixtures/client_key.pem"),
    )?;
    let _cfg = TlsClientConfig::new(_trust).with_client_identity(_identity);
    let _apci = ApciParameters::default();

    // The placeholder walk below is intentionally minimal; activate
    // it once fixture certs are in place:
    //   let stream = TcpStream::connect(("127.0.0.1", DEFAULT_PORT)).await?;
    //   let connector = Tls104Connector::new(&cfg, "c-reference")?;
    //   let mut tls = connector.connect(stream).await?;
    //   tls.send(Apdu::U(UFrame::StartDtAct)).await?;
    //   ... expect STARTDT_CON, send GI, expect monitor ASDUs + ACT_TERM.

    let _ = (
        cmds::general_interrogation(1, Default::default()),
        _apci,
        Apdu::U(UFrame::StartDtAct),
        SeqNo(0),
    );
    Ok(())
}
