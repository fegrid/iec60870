//! Crate-wide error type for IEC 60870-5 framing.

#[cfg(feature = "std")]
extern crate std;

use alloc::string::String;
use thiserror::Error;

/// All protocol-decoding failures reported by this crate.
///
/// Each variant carries enough structured context to be matched without
/// resorting to string parsing. Errors are pure data — no `unwrap`/`expect`
/// in the library surfaces them.
#[derive(Debug, Error)]
pub enum AsduError {
    /// Buffer did not contain enough bytes for the requested field.
    #[error("buffer too short: need {need}, have {have}")]
    BufferTooShort {
        /// Bytes required to satisfy the request.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },

    /// Declared length disagrees with content-derived length.
    #[error("length field mismatch: declared {declared}, actual {actual}")]
    LengthFieldMismatch {
        /// Value declared in the length field.
        declared: usize,
        /// Value derived from trailing content.
        actual: usize,
    },

    /// `TypeId` discriminant was not in the defined set.
    #[error("invalid type id: 0x{0:02x}")]
    InvalidTypeId(u8),

    /// Cause-of-transmission value was not in the defined set.
    #[error("invalid cause of transmission: 0x{0:02x}")]
    InvalidCause(u8),

    /// Control field bits do not match any frame type.
    #[error("invalid control field: 0x{0:02x}")]
    InvalidControlField(u8),

    /// Checksum byte did not equal the computed sum.
    #[error("invalid checksum: expected 0x{expected:02x}, computed 0x{computed:02x}")]
    InvalidChecksum {
        /// Byte carried in the frame.
        expected: u8,
        /// Byte computed from preceding bytes.
        computed: u8,
    },

    /// Start byte was not the expected magic value.
    #[error("invalid start byte: 0x{0:02x}")]
    InvalidStartByte(u8),

    /// Declared object count exceeded the configured maximum.
    #[error("too many objects: declared {declared}, max {max}")]
    TooManyObjects {
        /// Count declared in the VSQ.
        declared: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Operation valid in general but not for the configured profile.
    #[error("operation not supported by the configured profile")]
    UnsupportedByProfile,

    /// Underlying I/O failure. Only available with the `std` feature.
    #[cfg(feature = "std")]
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Caller supplied an empty or malformed numeric field.
    #[error("invalid numeric field: {0}")]
    InvalidNumericField(String),
}

impl Clone for AsduError {
    fn clone(&self) -> Self {
        match self {
            Self::BufferTooShort { need, have } => Self::BufferTooShort {
                need: *need,
                have: *have,
            },
            Self::LengthFieldMismatch { declared, actual } => Self::LengthFieldMismatch {
                declared: *declared,
                actual: *actual,
            },
            Self::InvalidTypeId(b) => Self::InvalidTypeId(*b),
            Self::InvalidCause(b) => Self::InvalidCause(*b),
            Self::InvalidControlField(b) => Self::InvalidControlField(*b),
            Self::InvalidChecksum { expected, computed } => Self::InvalidChecksum {
                expected: *expected,
                computed: *computed,
            },
            Self::InvalidStartByte(b) => Self::InvalidStartByte(*b),
            Self::TooManyObjects { declared, max } => Self::TooManyObjects {
                declared: *declared,
                max: *max,
            },
            Self::UnsupportedByProfile => Self::UnsupportedByProfile,
            #[cfg(feature = "std")]
            Self::Io(_) => Self::Io(std::io::Error::other("io error cloned without payload")),
            Self::InvalidNumericField(s) => Self::InvalidNumericField(s.clone()),
        }
    }
}

impl PartialEq for AsduError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::BufferTooShort { need: a, have: b },
                Self::BufferTooShort { need: c, have: d },
            ) => a == c && b == d,
            (
                Self::LengthFieldMismatch {
                    declared: a,
                    actual: b,
                },
                Self::LengthFieldMismatch {
                    declared: c,
                    actual: d,
                },
            ) => a == c && b == d,
            (Self::InvalidTypeId(a), Self::InvalidTypeId(b)) => a == b,
            (Self::InvalidCause(a), Self::InvalidCause(b)) => a == b,
            (Self::InvalidControlField(a), Self::InvalidControlField(b)) => a == b,
            (
                Self::InvalidChecksum {
                    expected: a,
                    computed: b,
                },
                Self::InvalidChecksum {
                    expected: c,
                    computed: d,
                },
            ) => a == c && b == d,
            (Self::InvalidStartByte(a), Self::InvalidStartByte(b)) => a == b,
            (
                Self::TooManyObjects {
                    declared: a,
                    max: b,
                },
                Self::TooManyObjects {
                    declared: c,
                    max: d,
                },
            ) => a == c && b == d,
            (Self::UnsupportedByProfile, Self::UnsupportedByProfile) => true,
            (Self::InvalidNumericField(a), Self::InvalidNumericField(b)) => a == b,
            _ => false,
        }
    }
}

/// Convenience alias used across the crate.
pub type Result<T, E = AsduError> = core::result::Result<T, E>;
