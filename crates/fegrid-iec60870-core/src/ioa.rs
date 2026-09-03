//! Information-object-address newtype.

use crate::error::{AsduError, Result};
use crate::params::IoaSize;

/// Information-object-address field (1, 2, or 3 bytes, little-endian on the wire).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ioa(pub u32);

impl Ioa {
    /// New address with the value rounded to the configured `IoaSize` range.
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Wire length in bytes for the given [`IoaSize`].
    pub const fn encoded_size(size: IoaSize) -> usize {
        size as usize
    }

    /// Encode into a caller buffer.
    #[inline]
    pub fn encode(&self, size: IoaSize, out: &mut [u8]) -> Result<()> {
        let needed = size as usize;
        if out.len() < needed {
            return Err(AsduError::BufferTooShort {
                need: needed,
                have: out.len(),
            });
        }
        match size {
            IoaSize::One => {
                if self.0 >= 0x100 {
                    return Err(AsduError::InvalidNumericField(
                        "IOA exceeds 1-byte range".into(),
                    ));
                }
                out[0] = self.0 as u8;
            }
            IoaSize::Two => {
                if self.0 >= 0x10000 {
                    return Err(AsduError::InvalidNumericField(
                        "IOA exceeds 2-byte range".into(),
                    ));
                }
                out[..2].copy_from_slice(&(self.0 as u16).to_le_bytes());
            }
            IoaSize::Three => {
                if self.0 >= 0x1000000 {
                    return Err(AsduError::InvalidNumericField(
                        "IOA exceeds 3-byte range".into(),
                    ));
                }
                out[..3].copy_from_slice(&self.0.to_le_bytes()[..3]);
            }
        }
        Ok(())
    }

    /// Decode from the supplied buffer.
    #[inline]
    pub fn decode(size: IoaSize, input: &[u8]) -> Result<Self> {
        let needed = size as usize;
        if input.len() < needed {
            return Err(AsduError::BufferTooShort {
                need: needed,
                have: input.len(),
            });
        }
        let value = match size {
            IoaSize::One => u32::from(input[0]),
            IoaSize::Two => u32::from(u16::from_le_bytes([input[0], input[1]])),
            IoaSize::Three => u32::from_le_bytes([input[0], input[1], input[2], 0]),
        };
        Ok(Self(value))
    }
}
