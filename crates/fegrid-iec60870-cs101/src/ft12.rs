//! FT 1.2 link-layer frame codec.
//!
//! Frame kinds:
//! - **Variable**: `[0x68][L][L][0x68][CF][addr][user-data][checksum][0x16]`,
//!   where `L = 1 + addr_len + data_len`, `L` is repeated twice, and `0x68`
//!   is repeated at byte 3.
//!
//! Checksum = wrapping u8 sum of all bytes between the two start bytes
//! and the checksum (inclusive of CF and address).
//!
//! Decoder behavior:
//! - Garbage before the start byte → `Ft12Error::Resync(skip)` carrying
//!   the count of skipped bytes (mirrors the C reference's receive state
//!   machine).
//! - Truncated trailing bytes → `Ft12Error::NeedMore` — never consumes on error.

use bytes::Bytes;

use fegrid_iec60870_core::{AddressLen, AsduError, LinkLayerParameters, Result};

/// Start byte of a fixed-length FT 1.2 frame.
pub const START_FIXED: u8 = 0x10;
/// Start byte of a variable-length FT 1.2 frame.
pub const START_VARIABLE: u8 = 0x68;
/// End byte of every FT 1.2 frame.
pub const END_BYTE: u8 = 0x16;
/// Single-character ACK.
pub const SINGLE_CHAR_ACK: u8 = 0xE5;
/// Single-character NAK (negative acknowledgement).
pub const SINGLE_CHAR_NAK: u8 = 0xA2;

/// Control field byte (one byte at the front of every FT 1.2 frame).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ControlField(pub u8);

impl ControlField {
    /// DIR/PRM bit — `true` for primary, `false` for secondary.
    pub fn dir(self) -> bool {
        (self.0 & 0x80) != 0
    }
    /// ACD bit (secondary frames only).
    pub fn acd(self) -> bool {
        (self.0 & 0x20) != 0
    }
    /// DFC bit (secondary frames only).
    pub fn dfc(self) -> bool {
        (self.0 & 0x10) != 0
    }
    /// FCB bit (primary frames only) — frame-count bit.
    pub fn fcb(self) -> bool {
        (self.0 & 0x40) != 0
    }
    /// FCV bit (primary frames only) — frame-count valid.
    pub fn fcv(self) -> bool {
        (self.0 & 0x20) != 0
    }
    /// 4-bit function code.
    pub fn fc(self) -> u8 {
        self.0 & 0x0f
    }
}

/// Fixed-length frame.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FixedFrame {
    /// Control field byte.
    pub control: ControlField,
    /// Link address (1 or 2 bytes LE).
    pub address: u16,
}

impl FixedFrame {
    /// Number of bytes in the serialized form (5 or 6).
    pub const fn encoded_len(addr_len: AddressLen) -> usize {
        1 + 1 + addr_len as usize + 1 + 1
    }

    /// Serialize into `out`. Returns the number of bytes written.
    pub fn encode(&self, addr_len: AddressLen, out: &mut [u8]) -> Result<usize> {
        let n = Self::encoded_len(addr_len);
        if out.len() < n {
            return Err(AsduError::BufferTooShort {
                need: n,
                have: out.len(),
            });
        }
        out[0] = START_FIXED;
        out[1] = self.control.0;
        let addr_bytes = self.address.to_le_bytes();
        let al = addr_len as usize;
        out[2..2 + al].copy_from_slice(&addr_bytes[..al]);
        let checksum = wrapping_sum(&out[1..2 + al]);
        out[2 + al] = checksum;
        out[3 + al] = END_BYTE;
        Ok(n)
    }
}

/// Variable-length frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableFrame {
    /// Control field byte.
    pub control: ControlField,
    /// Link address.
    pub address: u16,
    /// User data payload (zero-copy view into the source buffer when parsed).
    pub user_data: Bytes,
}

impl VariableFrame {
    /// Total length of the serialized form.
    pub fn encoded_len(&self, addr_len: AddressLen) -> usize {
        5 + addr_len as usize + self.user_data.len() + 2
    }

    /// Serialize into `out`. Returns the number of bytes written.
    pub fn encode(&self, addr_len: AddressLen, out: &mut [u8]) -> Result<usize> {
        let n = self.encoded_len(addr_len);
        if out.len() < n {
            return Err(AsduError::BufferTooShort {
                need: n,
                have: out.len(),
            });
        }
        let al = addr_len as usize;
        out[0] = START_VARIABLE;
        // IEC 60870-5-101 FT 1.2 variable-frame layout:
        //   [0x68, L, L, 0x68, CF, addr[1|2], user_data..., cksum, 0x16]
        // L is repeated twice and the START byte is repeated at byte 3.
        // L = 1 (CF) + al + user_data.len(); fits in one byte because FT 1.2
        // caps user data at 249 bytes + header < 256.
        let l = (1 + al + self.user_data.len()) as u8;
        out[1] = l;
        out[2] = l;
        out[3] = START_VARIABLE;
        out[4] = self.control.0;
        let addr_bytes = self.address.to_le_bytes();
        out[5..5 + al].copy_from_slice(&addr_bytes[..al]);
        let body_start = 5 + al;
        out[body_start..body_start + self.user_data.len()].copy_from_slice(&self.user_data);
        let chk_off = body_start + self.user_data.len();
        let checksum = wrapping_sum(&out[4..chk_off]);
        out[chk_off] = checksum;
        out[chk_off + 1] = END_BYTE;
        Ok(n)
    }
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ft12Frame {
    /// Single-byte ACK (`0xE5`).
    SingleCharAck,
    /// Single-byte NAK (`0xA2`) — negative acknowledgement, indicating
    /// the slave could not accept the previous frame.
    NegativeAck,
    /// Fixed-length frame.
    Fixed(FixedFrame),
    /// Variable-length frame.
    Variable(VariableFrame),
}

/// Errors produced by [`Ft12Codec::decode`].
#[derive(Debug, PartialEq, Eq)]
pub enum Ft12Error {
    /// Buffer exhausted before a complete frame was parsed.
    NeedMore,
    /// Skipped `skip` bytes of garbage before the next start byte.
    Resync(usize),
    /// Variable-frame length byte declared a length too small or too big.
    LengthMismatch {
        /// Declared length L.
        declared: usize,
        /// Bytes currently in the buffer.
        available: usize,
    },
    /// Checksum mismatch.
    Checksum {
        /// Expected (computed) value.
        expected: u8,
        /// Found (carried) value.
        found: u8,
    },
    /// Invalid control field bits.
    InvalidControlField(u8),
    /// Invalid start byte.
    InvalidStartByte(u8),
}

impl core::fmt::Display for Ft12Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NeedMore => f.write_str("need more bytes"),
            Self::Resync(n) => write!(f, "resync skipped {n} bytes"),
            Self::LengthMismatch {
                declared,
                available,
            } => {
                write!(f, "length {declared} > available {available}")
            }
            Self::Checksum { expected, found } => {
                write!(f, "checksum 0x{expected:02x} != 0x{found:02x}")
            }
            Self::InvalidControlField(b) => write!(f, "invalid control field 0x{b:02x}"),
            Self::InvalidStartByte(b) => write!(f, "invalid start byte 0x{b:02x}"),
        }
    }
}

/// State handle for parsing a stream of FT 1.2 bytes into [`Ft12Frame`].
///
/// The codec intentionally does **not** buffer partial frames between calls —
/// callers that need streaming should manage their own buffer and call
/// [`parse_one`] on the joined slice. This keeps the codec alloc-free.
#[derive(Debug, Default)]
pub struct Ft12Codec;

impl Ft12Codec {
    /// Construct a new codec.
    pub fn new() -> Self {
        Self
    }

    /// Bytes currently buffered (always 0).
    pub fn buffered_len(&self) -> usize {
        0
    }

    /// Reset the codec (no state retained).
    pub fn reset(&mut self) {}

    /// Feed `input` bytes into the codec. Returns the first complete
    /// frame plus the number of `input` bytes consumed.
    pub fn decode(
        &mut self,
        input: &[u8],
        params: &LinkLayerParameters,
    ) -> core::result::Result<(Ft12Frame, usize), Ft12Error> {
        parse_one(input, params.address_length)
    }
}

/// Strip leading garbage from a byte slice, returning the skip count
/// plus the remaining slice.
fn skip_garbage(input: &[u8]) -> (usize, &[u8]) {
    let mut idx = 0;
    while idx < input.len() {
        let b = input[idx];
        if b == START_FIXED || b == START_VARIABLE || b == SINGLE_CHAR_ACK || b == SINGLE_CHAR_NAK {
            break;
        }
        idx += 1;
    }
    (idx, &input[idx..])
}

fn wrapping_sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, b| acc.wrapping_add(*b))
}

/// Parse exactly one frame from the front of `input`. Returns
/// `(frame, consumed)` on success. Returns
/// [`Ft12Error::Resync`] if garbage precedes the start byte, or
/// [`Ft12Error::NeedMore`] if the buffer is too short to contain a
/// full frame.
pub fn parse_one(
    input: &[u8],
    addr_len: AddressLen,
) -> core::result::Result<(Ft12Frame, usize), Ft12Error> {
    if input.is_empty() {
        return Err(Ft12Error::NeedMore);
    }
    let (skipped, rest) = skip_garbage(input);
    if skipped > 0 {
        return Err(Ft12Error::Resync(skipped));
    }
    match rest[0] {
        SINGLE_CHAR_ACK => Ok((Ft12Frame::SingleCharAck, 1)),
        SINGLE_CHAR_NAK => Ok((Ft12Frame::NegativeAck, 1)),
        START_FIXED => parse_fixed(rest, addr_len).map(|(f, n)| (Ft12Frame::Fixed(f), n)),
        START_VARIABLE => parse_variable(rest, addr_len).map(|(f, n)| (Ft12Frame::Variable(f), n)),
        b => Err(Ft12Error::InvalidStartByte(b)),
    }
}
fn parse_fixed(
    input: &[u8],
    addr_len: AddressLen,
) -> core::result::Result<(FixedFrame, usize), Ft12Error> {
    let al = addr_len as usize;
    debug_assert!(al == 1 || al == 2, "address length must be 1 or 2 bytes");
    let n = FixedFrame::encoded_len(addr_len);
    debug_assert!(
        n == 5 || n == 6,
        "fixed-frame length must be 5 (1-byte addr) or 6 (2-byte addr), got {n}"
    );
    if input.len() < n {
        return Err(Ft12Error::NeedMore);
    }
    if input[n - 1] != END_BYTE {
        return Err(Ft12Error::Resync(1));
    }
    let control = ControlField(input[1]);
    let addr = match al {
        1 => u16::from(input[2]),
        2 => u16::from_le_bytes([input[2], input[3]]),
        _ => return Err(Ft12Error::InvalidControlField(al as u8)),
    };
    let checksum = wrapping_sum(&input[1..2 + al]);
    let carried = input[2 + al];
    if checksum != carried {
        return Err(Ft12Error::Checksum {
            expected: checksum,
            found: carried,
        });
    }
    Ok((
        FixedFrame {
            control,
            address: addr,
        },
        n,
    ))
}

fn parse_variable(
    input: &[u8],
    addr_len: AddressLen,
) -> core::result::Result<(VariableFrame, usize), Ft12Error> {
    // Layout: [0x68, L, L, 0x68, CF, addr[1|2], user_data..., cksum, 0x16]
    if input.len() < 5 {
        return Err(Ft12Error::NeedMore);
    }
    if input[0] != START_VARIABLE || input[1] != input[2] || input[3] != START_VARIABLE {
        return Err(Ft12Error::InvalidStartByte(input[0]));
    }
    let al = addr_len as usize;
    let l = input[1] as usize;
    if l < 1 + al {
        return Err(Ft12Error::LengthMismatch {
            declared: l,
            available: input.len(),
        });
    }
    let data_len = l - (1 + al);
    let total = 5 + al + data_len + 2;
    if input.len() < total {
        return Err(Ft12Error::NeedMore);
    }
    if input[total - 1] != END_BYTE {
        return Err(Ft12Error::Resync(1));
    }
    let control = ControlField(input[4]);
    let addr = match al {
        1 => u16::from(input[5]),
        2 => u16::from_le_bytes([input[5], input[6]]),
        _ => return Err(Ft12Error::InvalidControlField(al as u8)),
    };
    let body_start = 5 + al;
    let body_end = body_start + data_len;
    let checksum = wrapping_sum(&input[4..body_end]);
    let carried = input[body_end];
    if checksum != carried {
        return Err(Ft12Error::Checksum {
            expected: checksum,
            found: carried,
        });
    }
    let user_data = Bytes::copy_from_slice(&input[body_start..body_end]);
    Ok((
        VariableFrame {
            control,
            address: addr,
            user_data,
        },
        total,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fegrid_iec60870_core::LinkLayerParameters;

    fn params(addr_len: AddressLen) -> LinkLayerParameters {
        LinkLayerParameters {
            address_length: addr_len,
            ..LinkLayerParameters::default()
        }
    }

    #[test]
    fn fixed_round_trip_two_byte_addr() {
        let params = params(AddressLen::Two);
        // ResetRemoteLink (PRM=1, FC=0) → CF = 0x80.
        let cf = 0x80;
        let original = FixedFrame {
            control: ControlField(cf),
            address: 0x0102,
        };
        let mut buf = [0u8; 16];
        let n = original.encode(params.address_length, &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(buf[0], START_FIXED);
        assert_eq!(buf[n - 1], END_BYTE);
        let (frame, used) = parse_one(&buf, params.address_length).unwrap();
        assert_eq!(used, 6);
        match frame {
            Ft12Frame::Fixed(f) => {
                assert_eq!(f.control.0, cf);
                assert_eq!(f.address, 0x0102);
            }
            _ => panic!("not a fixed frame"),
        }
    }

    #[test]
    fn fixed_round_trip_one_byte_addr() {
        let params = params(AddressLen::One);
        let original = FixedFrame {
            control: ControlField(0x80),
            address: 0x0007,
        };
        let mut buf = [0u8; 16];
        let n = original.encode(params.address_length, &mut buf).unwrap();
        assert_eq!(n, 5);
        let (frame, used) = parse_one(&buf, params.address_length).unwrap();
        assert_eq!(used, 5);
        match frame {
            Ft12Frame::Fixed(f) => assert_eq!(f.address, 7),
            _ => panic!("not a fixed frame"),
        }
    }

    #[test]
    fn spec_101_6_1_01_ft12_frame_format() {
        let p = params(AddressLen::Two);
        let original = VariableFrame {
            // secondary RESP_USER_DATA (PRM=0, FC=8)
            control: ControlField(0x08),
            address: 0x0102,
            user_data: Bytes::copy_from_slice(&[0xAA, 0xBB, 0xCC]),
        };
        // Layout: 0x68, L, L, 0x68, CF, addr[2], data[3], checksum, 0x16.
        // L = 1 + 2 + 3 = 6.
        let mut buf = [0u8; 32];
        let n = original.encode(p.address_length, &mut buf).unwrap();
        assert_eq!(n, 5 + 2 + 3 + 2);
        let (frame, used) = parse_one(&buf, p.address_length).unwrap();
        assert_eq!(used, n);
        match frame {
            Ft12Frame::Variable(f) => {
                assert_eq!(f.control.0, 0x08);
                assert_eq!(f.address, 0x0102);
                assert_eq!(&f.user_data[..], &[0xAA, 0xBB, 0xCC][..]);
            }
            _ => panic!("not a variable frame"),
        }
    }

    #[test]
    fn single_char_ack() {
        let p = params(AddressLen::Two);
        let bytes = [SINGLE_CHAR_ACK];
        let (frame, used) = parse_one(&bytes, p.address_length).unwrap();
        assert_eq!(used, 1);
        assert!(matches!(frame, Ft12Frame::SingleCharAck));
    }

    #[test]
    fn garbage_then_frame() {
        let p = params(AddressLen::Two);
        // 0xFF 0x00 0x10 0x80 0x02 0x01 0x83 0x16
        // skip=2, then fixed frame (CF=0x80 ResetRemoteLink, addr=0x0102, sum=0x83).
        let bytes = [0xFF, 0x00, 0x10, 0x80, 0x02, 0x01, 0x83, 0x16];
        // First call: skip garbage.
        let (skipped, after_skip) = match parse_one(&bytes, p.address_length) {
            Err(Ft12Error::Resync(k)) => (k, &bytes[k..]),
            other => panic!("expected Resync, got {other:?}"),
        };
        assert_eq!(skipped, 2);
        // Second call on the post-skip slice returns the frame.
        let (frame, used) = parse_one(after_skip, p.address_length).unwrap();
        assert_eq!(used, bytes.len() - 2);
        assert!(matches!(frame, Ft12Frame::Fixed(_)));
    }

    #[test]
    fn truncated_returns_need_more() {
        let p = params(AddressLen::Two);
        let bytes = [START_FIXED, 0x80, 0x01];
        assert_eq!(
            parse_one(&bytes, p.address_length),
            Err(Ft12Error::NeedMore)
        );
    }

    #[test]
    fn bad_checksum() {
        let p = params(AddressLen::Two);
        let bytes = [START_FIXED, 0x80, 0x02, 0x01, 0x00, END_BYTE];
        match parse_one(&bytes, p.address_length) {
            Err(Ft12Error::Checksum { .. }) => {}
            other => panic!("expected Checksum error, got {other:?}"),
        }
    }

    #[test]
    fn codec_skips_then_decodes() {
        let p = params(AddressLen::Two);
        let mut codec = Ft12Codec::new();
        // 2 garbage bytes followed by a valid fixed frame.
        let f = FixedFrame {
            control: ControlField(0x80),
            address: 0x1234,
        };
        let mut buf = [0u8; 16];
        let n = f.encode(p.address_length, &mut buf).unwrap();
        let mut stream = alloc::vec![0xAA, 0xBB];
        stream.extend_from_slice(&buf[..n]);
        assert_eq!(codec.decode(&stream, &p), Err(Ft12Error::Resync(2)));
        let (frame, used) = codec.decode(&buf[..n], &p).unwrap();
        assert_eq!(used, n);
        assert!(matches!(frame, Ft12Frame::Fixed(_)));
    }

    #[test]
    fn single_char_nak() {
        let p = params(AddressLen::Two);
        let bytes = [SINGLE_CHAR_NAK];
        let (frame, used) = parse_one(&bytes, p.address_length).unwrap();
        assert_eq!(used, 1);
        assert!(matches!(frame, Ft12Frame::NegativeAck));
    }

    #[test]
    fn control_field_fcb_fcv() {
        // PRM=1, FCV=1, FCB=1, FC=0 → CF = 0x80 | 0x40 | 0x20 | 0x00 = 0xE0.
        let cf = ControlField(0xE0);
        assert!(cf.dir());
        assert!(cf.fcv());
        assert!(cf.fcb());
        assert_eq!(cf.fc(), 0x00);
        // PRM=0, FC=11 → CF = 0x0B → no FCB/FCV semantics expected.
        let cf2 = ControlField(0x0B);
        assert!(!cf2.dir());
        assert!(!cf2.fcb());
        assert!(!cf2.fcv());
        assert_eq!(cf2.fc(), 0x0B);
    }

    #[test]
    fn fixed_frame_lengths() {
        // AddressLen::One → 5 bytes; AddressLen::Two → 6 bytes.
        assert_eq!(FixedFrame::encoded_len(AddressLen::One), 5);
        assert_eq!(FixedFrame::encoded_len(AddressLen::Two), 6);
        let f = FixedFrame {
            control: ControlField(0x80),
            address: 0x01,
        };
        let mut buf = [0u8; 8];
        assert_eq!(f.encode(AddressLen::One, &mut buf).unwrap(), 5);
        assert_eq!(f.encode(AddressLen::Two, &mut buf).unwrap(), 6);
    }

    #[test]
    fn command_frame_parity_round_trip() {
        // Each of these is a primary (PRM=1) command; round-trip through encode→parse_one.
        let p = params(AddressLen::Two);
        let commands: &[(u8, &str)] = &[
            (0x40, "ResetRemoteLink"),
            (0xC0, "ResetUserProcess"),
            (0xE0, "TestLink (FCV=1, FCB=1)"),
            (0x70, "RequestLinkStatus"),
        ];
        for &(cf, label) in commands {
            let f = FixedFrame {
                control: ControlField(cf),
                address: 0x0001,
            };
            let mut buf = [0u8; 8];
            let n = f.encode(p.address_length, &mut buf).unwrap();
            assert_eq!(n, 6, "{label}: encoded length");
            assert_eq!(buf[0], START_FIXED, "{label}: start byte");
            assert_eq!(buf[n - 1], END_BYTE, "{label}: end byte");
            let (frame, used) = parse_one(&buf[..n], p.address_length).unwrap();
            assert_eq!(used, n, "{label}: consumed");
            match frame {
                Ft12Frame::Fixed(parsed) => {
                    assert_eq!(parsed.control.0, cf, "{label}: control field");
                    assert_eq!(parsed.address, 0x0001, "{label}: address");
                }
                _ => panic!("{label}: not a fixed frame"),
            }
        }
    }
}
