//! CP16 / CP24 / CP32 / CP56 time tags.

use crate::error::{AsduError, Result};

/// CP16Time2a — 2 bytes: millisecond count 0..59_999, little-endian.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct Cp16Time2a {
    /// Milliseconds within minute.
    pub ms: u16,
}

impl Cp16Time2a {
    /// Encode to 2 bytes (LE).
    #[inline]
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < 2 {
            return Err(AsduError::BufferTooShort {
                need: 2,
                have: out.len(),
            });
        }
        out[..2].copy_from_slice(&self.ms.to_le_bytes());
        Ok(())
    }

    /// Decode from a 2-byte buffer.
    #[inline]
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 2 {
            return Err(AsduError::BufferTooShort {
                need: 2,
                have: input.len(),
            });
        }
        Ok(Self {
            ms: u16::from_le_bytes([input[0], input[1]]),
        })
    }
}

/// CP24Time2a — 3 bytes: ms (LE) + minutes | flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct Cp24Time2a {
    /// Milliseconds within minute.
    pub ms: u16,
    /// Minutes 0..59.
    pub minutes: u8,
    /// Whether the time tag is invalid.
    pub invalid: bool,
    /// Whether summer-time is in effect.
    pub summer_time: bool,
}

impl Cp24Time2a {
    /// Encode to 3 bytes.
    #[inline]
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < 3 {
            return Err(AsduError::BufferTooShort {
                need: 3,
                have: out.len(),
            });
        }
        out[..2].copy_from_slice(&self.ms.to_le_bytes());
        let mut b = self.minutes & 0x3f;
        if self.summer_time {
            b |= 0x40;
        }
        if self.invalid {
            b |= 0x80;
        }
        out[2] = b;
        Ok(())
    }

    /// Decode from a 3-byte buffer.
    #[inline]
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 3 {
            return Err(AsduError::BufferTooShort {
                need: 3,
                have: input.len(),
            });
        }
        let ms = u16::from_le_bytes([input[0], input[1]]);
        let b = input[2];
        Ok(Self {
            ms,
            minutes: b & 0x3f,
            invalid: (b & 0x80) != 0,
            summer_time: (b & 0x40) != 0,
        })
    }
}

/// CP32Time2a — 4 bytes: ms + minutes + hours + flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct Cp32Time2a {
    /// Milliseconds within minute.
    pub ms: u16,
    /// Minutes 0..59.
    pub minutes: u8,
    /// Hours 0..23.
    pub hours: u8,
    /// Invalid flag.
    pub invalid: bool,
    /// Summer-time flag.
    pub summer_time: bool,
}

impl Cp32Time2a {
    /// Encode to 4 bytes.
    #[inline]
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < 4 {
            return Err(AsduError::BufferTooShort {
                need: 4,
                have: out.len(),
            });
        }
        out[..2].copy_from_slice(&self.ms.to_le_bytes());
        let mut m = self.minutes & 0x3f;
        if self.summer_time {
            m |= 0x40;
        }
        if self.invalid {
            m |= 0x80;
        }
        out[2] = m;
        let mut h = self.hours & 0x1f;
        if self.summer_time {
            h |= 0x80;
        }
        out[3] = h;
        Ok(())
    }

    /// Decode from a 4-byte buffer.
    #[inline]
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 4 {
            return Err(AsduError::BufferTooShort {
                need: 4,
                have: input.len(),
            });
        }
        let ms = u16::from_le_bytes([input[0], input[1]]);
        let mb = input[2];
        let hb = input[3];
        Ok(Self {
            ms,
            minutes: mb & 0x3f,
            invalid: (mb & 0x80) != 0,
            summer_time: (mb & 0x40) != 0,
            hours: hb & 0x1f,
        })
    }
}

/// CP56Time2a — 7 bytes: ms, minutes, hours, day-of-month + DoW, month, year.
///
/// Wire byte layout per IEC 60870-5-101 §7.2.6.18:
/// |------|------------------------------------------|
/// | 0    | ms LSB                                   |
/// | 1    | ms MSB                                   |
/// | 2    | `minutes & 0x3f \| SU << 6 \| IV << 7`   |
/// | 3    | `hours & 0x1f \| SU << 7`                |
/// | 4    | `day & 0x1f \| (dow & 0x07) << 5`        |
/// | 5    | `month & 0x0f`                           |
/// | 6    | `year & 0x7f`                            |
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct Cp56Time2a {
    /// Milliseconds within minute (0..59_999).
    pub ms: u16,
    /// Minutes 0..59.
    pub minutes: u8,
    /// Hours 0..23.
    pub hours: u8,
    /// Day of month 1..31.
    pub day_of_month: u8,
    /// Day of week 0..7 (0 = unused).
    pub day_of_week: u8,
    /// Month 1..12.
    pub month: u8,
    /// Year 0..99 (1900..1999 when ORed with 0x00, 2000..2099 with 0x64).
    pub year: u8,
    /// Invalid flag.
    pub invalid: bool,
    /// Summer-time flag.
    pub summer_time: bool,
}

impl Cp56Time2a {
    /// Encode to 7 bytes.
    #[inline]
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < 7 {
            return Err(AsduError::BufferTooShort {
                need: 7,
                have: out.len(),
            });
        }
        out[..2].copy_from_slice(&self.ms.to_le_bytes());
        let mut mb = self.minutes & 0x3f;
        if self.summer_time {
            mb |= 0x40;
        }
        if self.invalid {
            mb |= 0x80;
        }
        out[2] = mb;
        let mut hb = self.hours & 0x1f;
        if self.summer_time {
            hb |= 0x80;
        }
        out[3] = hb;
        let mut db = self.day_of_month & 0x1f;
        db |= (self.day_of_week & 0x07) << 5;
        out[4] = db;
        out[5] = self.month & 0x0f;
        out[6] = self.year & 0x7f;
        Ok(())
    }

    /// Decode from a 7-byte buffer.
    #[inline]
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 7 {
            return Err(AsduError::BufferTooShort {
                need: 7,
                have: input.len(),
            });
        }
        let ms = u16::from_le_bytes([input[0], input[1]]);
        let mb = input[2];
        let hb = input[3];
        let db = input[4];
        Ok(Self {
            ms,
            minutes: mb & 0x3f,
            summer_time: (mb & 0x40) != 0,
            invalid: (mb & 0x80) != 0,
            hours: hb & 0x1f,
            day_of_month: db & 0x1f,
            day_of_week: (db >> 5) & 0x07,
            month: input[5] & 0x0f,
            year: input[6] & 0x7f,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-computed CP56Time2a byte vector: bytes
    /// `85 49 0c 09 55 03 11` decode to ms-since-epoch `1490087538821`.
    #[test]
    fn cp56_hand_vector_decodes() {
        let input = [0x85, 0x49, 0x0c, 0x09, 0x55, 0x03, 0x11];
        let t = Cp56Time2a::decode(&input).expect("decode");
        assert_eq!(t.ms, 0x4985);
        assert_eq!(t.minutes, 0x0c);
        assert_eq!(t.hours, 0x09);
        assert_eq!(t.day_of_month, 0x15);
        assert_eq!(t.day_of_week, 0x02);
        assert_eq!(t.month, 0x03);
        assert_eq!(t.year, 0x11);
        assert!(!t.summer_time);
        assert!(!t.invalid);
    }

    #[test]
    fn cp56_round_trip() {
        let t = Cp56Time2a {
            ms: 12_345,
            minutes: 34,
            hours: 12,
            day_of_month: 15,
            day_of_week: 3,
            month: 11,
            year: 27,
            invalid: false,
            summer_time: true,
        };
        let mut buf = [0u8; 7];
        t.encode(&mut buf).expect("encode");
        let t2 = Cp56Time2a::decode(&buf).expect("decode");
        assert_eq!(t, t2);
    }

    #[test]
    fn cp24_round_trip() {
        let t = Cp24Time2a {
            ms: 1234,
            minutes: 5,
            invalid: true,
            summer_time: false,
        };
        let mut buf = [0u8; 3];
        t.encode(&mut buf).unwrap();
        let t2 = Cp24Time2a::decode(&buf).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn cp16_round_trip() {
        let t = Cp16Time2a { ms: 59_999 };
        let mut buf = [0u8; 2];
        t.encode(&mut buf).unwrap();
        let t2 = Cp16Time2a::decode(&buf).unwrap();
        assert_eq!(t, t2);
    }
}
