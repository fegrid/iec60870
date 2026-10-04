//! APCI frame codec (I, S, U).
//!
//! Wire layout per IEC 60870-5-104 §5:
//! - All APDUs start with `0x68 <len-2> 0x68 ...` (the leading two bytes are
//!   the start octet + length; `len` counts every byte after the length,
//!   i.e. the full APDU = `len + 2` bytes total).
//! - Control field is bytes 2..=5:
//!   - I-frame: byte2 = `(send % 128) * 2`, byte3 = `send / 128`,
//!     byte4 = `(recv % 128) * 2`, byte5 = `recv / 128`.
//!   - S-frame: byte2 = `0x01`, byte3 = `0x00`, byte4 = `(recv % 128) * 2`,
//!   - U-frame: byte2 lower nibble encodes the U-type, upper bits ignored.
//!

use bytes::Bytes;
use thiserror::Error;

use fegrid_iec60870_asdu::Asdu;

/// Length byte value below which an APDU is rejected as malformed.
pub const APDU_MIN_LENGTH: u8 = 4;
/// Maximum length byte — FT 1.2 caps APDUs at 255 bytes total, so the
/// length field maxes out at 253.
pub const APCI_MAX_LENGTH: u8 = 253;

/// Sequence number mod 32768 (0..32768).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct SeqNo(pub u16);

impl SeqNo {
    /// Increment mod 32768.
    pub fn next(self) -> Self {
        Self((self.0 + 1) % 32768)
    }

    /// Wire encoding (2 bytes LE).
    pub fn to_wire(self) -> [u8; 2] {
        let lo = (self.0 % 128) as u8 * 2;
        let hi = (self.0 / 128) as u8;
        [lo, hi]
    }

    /// Decode wire form (2 bytes LE).
    pub fn from_wire(b: [u8; 2]) -> Self {
        Self(u16::from(b[0] / 2) + u16::from(b[1]) * 128)
    }
}

/// U-format frame type.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UFrame {
    /// STARTDT_ACT (PRM=1).
    StartDtAct = 0x07,
    /// STARTDT_CON (PRM=0).
    StartDtCon = 0x0b,
    /// STOPDT_ACT (PRM=1).
    StopDtAct = 0x13,
    /// STOPDT_CON (PRM=0).
    StopDtCon = 0x23,
    /// TESTFR_ACT (PRM=1).
    TestFrAct = 0x43,
    /// TESTFR_CON (PRM=0).
    TestFrCon = 0x83,
}

/// A decoded APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum Apdu {
    /// I-frame (information).
    I {
        /// Send sequence number.
        ns: SeqNo,
        /// Receive sequence number.
        nr: SeqNo,
        /// Optional ASDU payload (present iff length > 4).
        asdu: Option<Asdu>,
    },
    /// S-frame (supervisory, ack-only).
    S {
        /// Receive sequence number being acked.
        nr: SeqNo,
    },
    /// U-frame (unnumbered control).
    U(UFrame),
}

/// Errors emitted by [`parse_apdu`].
#[derive(Debug, Clone, Error, PartialEq)]
pub enum ApduError {
    /// Buffer shorter than the minimum APDU (4 bytes).
    #[error("apdu too short: {have} bytes")]
    TooShort {
        /// Bytes available.
        have: usize,
    },
    /// Length byte would extend past the buffer.
    #[error("length mismatch: declared {declared} > available {available}")]
    LengthMismatch {
        /// Length byte value.
        declared: usize,
        /// Bytes available.
        available: usize,
    },
    /// Length byte is below [`APDU_MIN_LENGTH`].
    #[error("invalid length byte 0x{0:02x}")]
    InvalidLength(u8),
    /// First byte was not the APCI start octet (`0x68`).
    #[error("invalid start byte 0x{0:02x}")]
    InvalidStartByte(u8),
    /// Frame type could not be determined from the control field.
    #[error("unrecognized control field 0x{0:02x}")]
    InvalidControlField(u8),
    /// Sequence number overflow.
    #[error("sequence out of range: {0}")]
    SequenceOutOfRange(u16),
    /// ASDU parse failure (forwarded).
    #[error("asdu parse error: {0}")]
    Asdu(#[from] fegrid_iec60870_asdu::AsduError),
}

/// Parse a complete APDU from `buf`. The buffer must start with `0x68` and
/// contain at least `length + 2` bytes.
pub fn parse_apdu(buf: &[u8]) -> Result<Apdu, ApduError> {
    if buf.len() < 2 {
        return Err(ApduError::TooShort { have: buf.len() });
    }
    if buf[0] != 0x68 {
        return Err(ApduError::InvalidStartByte(buf[0]));
    }
    let len = buf[1] as usize;
    if len < APDU_MIN_LENGTH as usize {
        return Err(ApduError::InvalidLength(len as u8));
    }
    let total = len + 2;
    if buf.len() < total {
        return Err(ApduError::LengthMismatch {
            declared: total,
            available: buf.len(),
        });
    }
    let cf = buf[2];
    if cf & 0x01 == 0 {
        let ns = SeqNo::from_wire([buf[2], buf[3]]);
        let nr = SeqNo::from_wire([buf[4], buf[5]]);
        let asdu = if len > 4 {
            let params = fegrid_iec60870_core::AppLayerParameters::default();
            let payload = &buf[6..total];
            Some(Asdu::parse(&params, payload)?)
        } else {
            None
        };
        Ok(Apdu::I { ns, nr, asdu })
    } else if cf == 0x01 {
        let nr = SeqNo::from_wire([buf[3], buf[4]]);
        Ok(Apdu::S { nr })
    } else if cf & 0x03 == 0x03 {
        let u = match cf {
            0x07 => UFrame::StartDtAct,
            0x0b => UFrame::StartDtCon,
            0x13 => UFrame::StopDtAct,
            0x23 => UFrame::StopDtCon,
            0x43 => UFrame::TestFrAct,
            0x83 => UFrame::TestFrCon,
            other => return Err(ApduError::InvalidControlField(other)),
        };
        Ok(Apdu::U(u))
    } else {
        Err(ApduError::InvalidControlField(cf))
    }
}

#[allow(clippy::disallowed_methods, clippy::expect_used)]
fn write_u(u: UFrame) -> [u8; 6] {
    let mut buf = [0u8; 6];
    let _ = encode_u_frame(u, &mut buf).expect("6-byte buffer always fits");
    buf
}

#[allow(clippy::disallowed_methods, clippy::expect_used)]
fn write_s(nr: SeqNo) -> [u8; 6] {
    let mut buf = [0u8; 6];
    let _ = encode_s(nr, &mut buf).expect("6-byte buffer always fits");
    buf
}

/// Encode a U-frame into `out`. Returns the number of bytes written (6).
#[allow(clippy::disallowed_methods)]
pub fn encode_u_frame(u: UFrame, out: &mut [u8]) -> Result<usize, ApduError> {
    if out.len() < 6 {
        return Err(ApduError::TooShort { have: out.len() });
    }
    out[0] = 0x68;
    out[1] = 4;
    out[2] = u as u8;
    out[3] = 0;
    out[4] = 0;
    out[5] = 0;
    Ok(6)
}

/// Encode an S-frame. Returns the number of bytes written (6).
#[allow(clippy::disallowed_methods)]
pub fn encode_s(nr: SeqNo, out: &mut [u8]) -> Result<usize, ApduError> {
    if out.len() < 6 {
        return Err(ApduError::TooShort { have: out.len() });
    }
    let nr_bytes = nr.to_wire();
    out[0] = 0x68;
    out[1] = 4;
    out[2] = 0x01;
    out[3] = nr_bytes[0];
    out[4] = nr_bytes[1];
    out[5] = 0;
    Ok(6)
}

/// Encode an I-frame header (6 bytes) + optional ASDU payload. Returns
/// the total length written.
#[allow(clippy::disallowed_methods)]
pub fn encode_i(
    ns: SeqNo,
    nr: SeqNo,
    asdu: Option<&Asdu>,
    params: &fegrid_iec60870_core::AppLayerParameters,
    out: &mut [u8],
) -> Result<usize, ApduError> {
    if out.len() < 6 {
        return Err(ApduError::TooShort { have: out.len() });
    }
    let ns_bytes = ns.to_wire();
    let nr_bytes = nr.to_wire();
    out[0] = 0x68;
    out[1] = 0;
    out[2] = ns_bytes[0];
    out[3] = ns_bytes[1];
    out[4] = nr_bytes[0];
    out[5] = nr_bytes[1];
    let mut written = 6;
    if let Some(asdu) = asdu {
        let n = fegrid_iec60870_asdu::encode_to_vec(params, asdu).map_err(ApduError::Asdu)?;
        if out.len() < 6 + n.len() {
            return Err(ApduError::TooShort { have: out.len() });
        }
        out[6..6 + n.len()].copy_from_slice(&n);
        written += n.len();
    }
    out[1] = (written - 2) as u8;
    Ok(written)
}

/// Encode a U-frame into a freshly-allocated `Bytes` (6-byte, infallible).
pub fn u_frame_bytes(u: UFrame) -> Bytes {
    Bytes::copy_from_slice(&write_u(u))
}

/// Encode an S-frame into a freshly-allocated `Bytes` (6-byte, infallible).
pub fn s_frame_bytes(nr: SeqNo) -> Bytes {
    Bytes::copy_from_slice(&write_s(nr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u_frame_round_trip() {
        let mut buf = [0u8; 6];
        let n = encode_u_frame(UFrame::StartDtAct, &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(buf, [0x68, 0x04, 0x07, 0x00, 0x00, 0x00]);
        assert_eq!(parse_apdu(&buf).unwrap(), Apdu::U(UFrame::StartDtAct));
    }

    #[test]
    fn seq_no_wire_round_trip() {
        for raw in [0u16, 1, 127, 128, 255, 32767] {
            let s = SeqNo(raw);
            let w = s.to_wire();
            assert_eq!(SeqNo::from_wire(w), s, "roundtrip {raw}");
        }
    }

    #[test]
    fn i_frame_no_asdu() {
        let mut buf = [0u8; 6];
        let n = encode_i(
            SeqNo(7),
            SeqNo(13),
            None,
            &fegrid_iec60870_core::AppLayerParameters::default(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 6);
        let apdu = parse_apdu(&buf).unwrap();
        match apdu {
            Apdu::I { ns, nr, asdu } => {
                assert_eq!(ns, SeqNo(7));
                assert_eq!(nr, SeqNo(13));
                assert!(asdu.is_none());
            }
            _ => panic!("not I"),
        }
    }
}
