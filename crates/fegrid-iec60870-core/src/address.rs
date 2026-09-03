//! Common-address newtype.

use crate::error::{AsduError, Result};
use crate::params::CaSize;

/// Common-address field (1 or 2 bytes, little-endian on the wire).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CommonAddress(pub u16);

impl CommonAddress {
    /// New common-address with the value validated against `CaSize`.
    pub fn new(size: CaSize, value: u16) -> Result<Self> {
        match size {
            CaSize::One if value >= 0x100 => Err(AsduError::InvalidNumericField(
                "common address exceeds 1-byte range".into(),
            )),
            _ => Ok(Self(value)),
        }
    }

    /// Encode into the supplied buffer.
    #[inline]
    pub fn encode(&self, size: CaSize, out: &mut [u8]) -> Result<()> {
        let needed = size as usize;
        if out.len() < needed {
            return Err(AsduError::BufferTooShort {
                need: needed,
                have: out.len(),
            });
        }
        match size {
            CaSize::One => out[0] = self.0 as u8,
            CaSize::Two => {
                out[..2].copy_from_slice(&self.0.to_le_bytes());
            }
        }
        Ok(())
    }
    /// Decode from the supplied buffer.
    #[inline]
    pub fn decode(size: CaSize, input: &[u8]) -> Result<Self> {
        let needed = size as usize;
        if input.len() < needed {
            return Err(AsduError::BufferTooShort {
                need: needed,
                have: input.len(),
            });
        }
        let value = match size {
            CaSize::One => u16::from(input[0]),
            CaSize::Two => u16::from_le_bytes([input[0], input[1]]),
        };
        Ok(Self(value))
    }
}
