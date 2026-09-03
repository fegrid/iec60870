//! CS 104 framing over `tokio_util::codec::{Decoder, Encoder}`.
//!
//! [`ApduCodec`] turns a byte stream into a sequence of [`Apdu`] items and
//! back. It is purely a transport adapter; the protocol state machine
//! lives in `fegrid_iec60870_cs104`.

use bytes::{Bytes, BytesMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

use fegrid_iec60870_cs104::apci::{ApduError, parse_apdu};
use fegrid_iec60870_cs104::{Apdu, encode_i, s_frame_bytes, u_frame_bytes};

/// Errors surfaced by [`ApduCodec::decode`].
#[derive(Debug, Error)]
pub enum CodecError {
    /// APDU decoder rejected the framed bytes.
    #[error("apdu decode: {0}")]
    Apdu(#[from] ApduError),
    /// Malformed frame persisted past `max_resync_drops` consecutive bytes
    /// without recovering the framing; the transport MUST close.
    #[error("malformed: gave up after {drops} consecutive drops")]
    Malformed {
        /// Consecutive drop count at the close decision.
        drops: usize,
    },
    /// Reserved for future variants.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}
/// CS 104 framing codec.
/// CS 104 framing codec. Counts consecutive non-`0x68` resync drops and
/// closes the connection if the framing does not recover within
/// `max_resync_drops` bytes (default: 16 — enough to ride out a single
/// TCP segment worth of garbage, not enough to mask a broken peer).
#[derive(Debug)]
pub struct ApduCodec {
    /// Maximum number of bytes the codec may drop while trying to find the
    /// next `0x68` start octet before declaring the stream malformed.
    max_resync_drops: usize,
    /// Current run of consecutive drops since the last successful APDU.
    drops: usize,
}

impl Default for ApduCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl ApduCodec {
    /// Construct a fresh codec with the default resync tolerance.
    pub fn new() -> Self {
        Self::with_resync_tolerance(16)
    }

    /// Construct a codec with a custom maximum resync-drop count. The
    /// decoder closes the connection (returns [`CodecError::Malformed`])
    /// if it has to drop more than `max_resync_drops` bytes in a row
    /// without recovering the APCI framing.
    pub fn with_resync_tolerance(max_resync_drops: usize) -> Self {
        Self {
            max_resync_drops,
            drops: 0,
        }
    }
}

impl Decoder for ApduCodec {
    type Item = Apdu;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Apdu>, CodecError> {
        if src.is_empty() {
            return Ok(None);
        }
        if src[0] != 0x68 {
            // Resync: drop one byte and ask for more. If we've already
            // dropped too many bytes since the last successful frame the
            // peer is presumed broken — surface a `Malformed` error so
            // the transport closes. Count drops even when the buffer
            // shrinks below the 2-byte inspection minimum: the budget
            // tracks total garbage, not inspectable garbage.
            self.drops += 1;
            let _ = src.split_to(1);
            if self.drops > self.max_resync_drops {
                let drops = self.drops;
                self.drops = 0;
                return Err(CodecError::Malformed { drops });
            }
            if src.len() < 2 {
                return Ok(None);
            }
            return Ok(None);
        }
        if src.len() < 2 {
            return Ok(None);
        }
        let len = src[1] as usize;
        let total = len + 2;
        if src.len() < total {
            return Ok(None);
        }
        let frame = src.split_to(total).freeze();
        match parse_apdu(&frame) {
            Ok(apdu) => {
                self.drops = 0;
                Ok(Some(apdu))
            }
            Err(e) => {
                // Reset the drop counter on a real APDU-shaped frame so a
                // rare parse failure doesn't poison the resync budget.
                self.drops = 0;
                Err(CodecError::Apdu(e))
            }
        }
    }
}

impl Encoder<Apdu> for ApduCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Apdu, dst: &mut BytesMut) -> Result<(), CodecError> {
        dst.extend_from_slice(&apdu_to_wire(&item));
        Ok(())
    }
}

/// Encode an APDU to bytes.
pub fn apdu_to_wire(apdu: &Apdu) -> Bytes {
    match apdu {
        Apdu::U(u) => u_frame_bytes(*u),
        Apdu::S { nr } => s_frame_bytes(*nr),
        Apdu::I { ns, nr, asdu } => {
            let mut buf = [0u8; 260];
            let params = fegrid_iec60870_core::AppLayerParameters::default();
            match encode_i(*ns, *nr, asdu.as_ref(), &params, &mut buf) {
                Ok(n) => Bytes::copy_from_slice(&buf[..n]),
                Err(_) => Bytes::new(), // unreachable: 260-byte buffer always fits
            }
        }
    }
}
