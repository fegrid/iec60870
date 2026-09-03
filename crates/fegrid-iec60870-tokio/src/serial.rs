//! IEC 60870-5-101 serial transport.
//!
//! Wraps a serial2-tokio async stream so the CS 101 codec can drive a
//! real TTY port (`/dev/ttyUSB0`, `/dev/ttyS0`, etc.) (G-064).
//!
//! The [`SerialPort::open`] helper opens the port with IEC defaults
//! (8N1, 9600 baud, no flow control) and hands back a single
//! `SerialPort` that implements `AsyncRead + AsyncWrite`. The caller
//! feeds the resulting stream into the CS 101 codec via
//! [`crate::cs101::Ft12Codec`].

#![cfg(feature = "serial")]

/// Re-export the serial2-tokio `SerialPort` type so callers don't need
/// to add serial2-tokio as a direct dep.
pub use serial2_tokio::SerialPort;

/// Baud rate applied by [`open_with_defaults`] (8N1, no flow control).
pub const DEFAULT_BAUD_RATE: u32 = 9600;

/// Open a serial port with IEC 60870-5-101 defaults.
///
/// `path` is the device path (`/dev/ttyUSB0`, `COM3` on Windows).
/// Returns a `serial2_tokio::SerialPort` that implements
/// `AsyncRead + AsyncWrite`. The caller passes it directly to the CS
/// 101 codec's `Framed<S, Ft12Codec>` adapter.
pub async fn open_with_defaults(path: &str) -> std::io::Result<SerialPort> {
    let port = SerialPort::open(path, DEFAULT_BAUD_RATE)?;
    // The serial2-tokio default already applies 8N1, no parity, no flow
    // control; this wrapper exists to document the contract and to
    // centralize the IEC 60870-5-101 baud-rate choice.
    Ok(port)
}

/// Open a serial port at a custom baud rate.
pub async fn open_with_baud(path: &str, baud_rate: u32) -> std::io::Result<SerialPort> {
    let port = SerialPort::open(path, baud_rate)?;
    Ok(port)
}

/// Bridge that hands out a borrowed `SerialPort` from a `tokio::sync::Mutex`
/// — useful when multiple tasks need to share a port.
pub struct SharedSerialPort {
    inner: tokio::sync::Mutex<SerialPort>,
}

impl SharedSerialPort {
    /// Wrap a freshly opened `SerialPort`.
    pub fn new(port: SerialPort) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(port),
        }
    }
    /// Acquire an exclusive guard to drive the port.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, SerialPort> {
        self.inner.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_baud_is_9600() {
        assert_eq!(DEFAULT_BAUD_RATE, 9600);
    }

    #[tokio::test]
    async fn open_missing_path_errors() {
        // Opening a path that doesn't exist returns Err; we don't care
        // about the specific error kind.
        let res = open_with_defaults("/dev/this-port-does-not-exist-1234").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn open_with_custom_baud_propagates_err() {
        let res = open_with_baud("/dev/this-port-does-not-exist-1234", 19200).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn shared_serial_port_lock_returns_guard() {
        // We can't actually open a real port in CI, but we can verify
        // the wrapper compiles + the lock() method signature is correct
        // by using a stub.
        // The lock() future requires a port; use an error path that
        // produces no port for a clean compile-time test.
        let res = open_with_defaults("/dev/null-missing").await;
        if let Ok(port) = res {
            let shared = SharedSerialPort::new(port);
            let _g = shared.lock().await;
        }
    }
}
