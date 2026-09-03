//! Cause-of-transmission field.

use crate::error::{AsduError, Result};
use crate::params::CotSize;

/// Cause-of-transmission values 1..47 per IEC 60870-5-101 §7.4.3.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CauseOfTransmission {
    /// Periodic (cyclic) data transmission.
    Periodic = 1,
    /// Background scan.
    Background = 2,
    /// Spontaneous event.
    Spontaneous = 3,
    /// Initialized after restart.
    Initialized = 4,
    /// Requested by master.
    Request = 5,
    /// Activation (command).
    Activation = 6,
    /// Activation confirmation.
    ActivationCon = 7,
    /// Deactivation (command).
    Deactivation = 8,
    /// Deactivation confirmation.
    DeactivationCon = 9,
    /// Activation termination.
    ActivationTermination = 10,
    /// Return information caused by a remote command.
    ReturnInfoRemote = 11,
    /// Return information caused by a local command.
    ReturnInfoLocal = 12,
    /// File transfer.
    FileTransfer = 13,
    /// Authentication challenge.
    Authentication = 14,
    /// Maintenance of authentication session key.
    MaintenanceOfAuthSessionKey = 15,
    /// Maintenance of user-role and update key.
    MaintenanceOfUserRoleAndUpdateKey = 16,
    /// Interrogated by station (group 0).
    StationInterrogation = 20,
    /// Interrogated by group 1.
    Group1Interrogation = 21,
    /// Interrogated by group 2.
    Group2Interrogation = 22,
    /// Interrogated by group 3.
    Group3Interrogation = 23,
    /// Interrogated by group 4.
    Group4Interrogation = 24,
    /// Interrogated by group 5.
    Group5Interrogation = 25,
    /// Interrogated by group 6.
    Group6Interrogation = 26,
    /// Interrogated by group 7.
    Group7Interrogation = 27,
    /// Interrogated by group 8.
    Group8Interrogation = 28,
    /// Interrogated by group 9.
    Group9Interrogation = 29,
    /// Interrogated by group 10.
    Group10Interrogation = 30,
    /// Interrogated by group 11.
    Group11Interrogation = 31,
    /// Interrogated by group 12.
    Group12Interrogation = 32,
    /// Interrogated by group 13.
    Group13Interrogation = 33,
    /// Interrogated by group 14.
    Group14Interrogation = 34,
    /// Interrogated by group 15.
    Group15Interrogation = 35,
    /// Interrogated by group 16.
    Group16Interrogation = 36,
    /// Requested by general counter.
    RequestedByGeneralCounter = 37,
    /// Requested by group 1 counter.
    RequestedByGroup1Counter = 38,
    /// Requested by group 2 counter.
    RequestedByGroup2Counter = 39,
    /// Requested by group 3 counter.
    RequestedByGroup3Counter = 40,
    /// Requested by group 4 counter.
    RequestedByGroup4Counter = 41,
    /// Unknown type id.
    UnknownTypeId = 44,
    /// Unknown cause of transmission.
    UnknownCot = 45,
    /// Unknown common address.
    UnknownCa = 46,
    /// Unknown information object address.
    UnknownIoa = 47,
}

impl CauseOfTransmission {
    /// Wire value (0 is "Unused", never carried by valid frames).
    pub const fn to_wire(self) -> u8 {
        self as u8
    }

    /// Construct from a wire value; accepts the legal set only.
    pub const fn from_wire(byte: u8) -> Result<Self> {
        use CauseOfTransmission::*;
        let result = match byte {
            1 => Periodic,
            2 => Background,
            3 => Spontaneous,
            4 => Initialized,
            5 => Request,
            6 => Activation,
            7 => ActivationCon,
            8 => Deactivation,
            9 => DeactivationCon,
            10 => ActivationTermination,
            11 => ReturnInfoRemote,
            12 => ReturnInfoLocal,
            13 => FileTransfer,
            14 => Authentication,
            15 => MaintenanceOfAuthSessionKey,
            16 => MaintenanceOfUserRoleAndUpdateKey,
            20 => StationInterrogation,
            21 => Group1Interrogation,
            22 => Group2Interrogation,
            23 => Group3Interrogation,
            24 => Group4Interrogation,
            25 => Group5Interrogation,
            26 => Group6Interrogation,
            27 => Group7Interrogation,
            28 => Group8Interrogation,
            29 => Group9Interrogation,
            30 => Group10Interrogation,
            31 => Group11Interrogation,
            32 => Group12Interrogation,
            33 => Group13Interrogation,
            34 => Group14Interrogation,
            35 => Group15Interrogation,
            36 => Group16Interrogation,
            37 => RequestedByGeneralCounter,
            38 => RequestedByGroup1Counter,
            39 => RequestedByGroup2Counter,
            40 => RequestedByGroup3Counter,
            41 => RequestedByGroup4Counter,
            44 => UnknownTypeId,
            45 => UnknownCot,
            46 => UnknownCa,
            47 => UnknownIoa,
            _ => return Err(AsduError::InvalidCause(byte)),
        };
        Ok(result)
    }
}

impl TryFrom<u8> for CauseOfTransmission {
    type Error = AsduError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_wire(byte)
    }
}

impl From<CauseOfTransmission> for u8 {
    fn from(c: CauseOfTransmission) -> u8 {
        c.to_wire()
    }
}

/// Cause-of-transmission field as carried on the wire: the 6-bit cause plus
/// the P/N and T flags, optionally followed by an originator-address octet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CotField {
    /// Typed cause of transmission. May be [`CauseOfTransmission::UnknownCot`]
    /// if the wire byte was outside the defined set; in that case
    /// `cause_raw_override` carries the actual wire byte.
    pub cause: CauseOfTransmission,
    /// Negative-confirm flag.
    pub negative_confirm: bool,
    /// Test flag.
    pub test: bool,
    /// Originator address (only meaningful when COT field is 2 bytes).
    pub originator: u8,
    /// Optional raw cause byte used in preference to `cause as u8` on
    /// encode. Set by [`CotField::decode`] when the wire byte is outside
    /// the standard set, or by callers that need byte-exact parity.
    pub cause_raw_override: Option<u8>,
}

impl Default for CotField {
    fn default() -> Self {
        Self {
            cause: CauseOfTransmission::UnknownCot,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        }
    }
}

impl CotField {
    /// Encode into the supplied buffer, returning the number of bytes written.
    #[inline]
    pub fn encode(&self, size: CotSize, out: &mut [u8]) -> Result<usize> {
        let needed = size as usize;
        if out.len() < needed {
            return Err(AsduError::BufferTooShort {
                need: needed,
                have: out.len(),
            });
        }
        let cause_byte = self
            .cause_raw_override
            .unwrap_or_else(|| self.cause.to_wire());
        let mut byte = cause_byte & 0x3f;
        if self.negative_confirm {
            byte |= 0x40;
        }
        if self.test {
            byte |= 0x80;
        }
        out[0] = byte;
        if matches!(size, CotSize::Two) {
            out[1] = self.originator;
            Ok(2)
        } else {
            Ok(1)
        }
    }

    /// Decode from a wire buffer; the buffer is expected to be at least
    /// `size as usize` bytes long.
    #[inline]
    pub fn decode(size: CotSize, input: &[u8]) -> Result<Self> {
        let needed = size as usize;
        if input.len() < needed {
            return Err(AsduError::BufferTooShort {
                need: needed,
                have: input.len(),
            });
        }
        let byte = input[0];
        let cause_raw = byte & 0x3f;
        let cause =
            CauseOfTransmission::from_wire(cause_raw).unwrap_or(CauseOfTransmission::UnknownCot);
        let cause_raw_override = if matches!(cause, CauseOfTransmission::UnknownCot) {
            Some(cause_raw)
        } else {
            None
        };
        let originator = if matches!(size, CotSize::Two) {
            input[1]
        } else {
            0
        };
        Ok(Self {
            cause,
            negative_confirm: (byte & 0x40) != 0,
            test: (byte & 0x80) != 0,
            originator,
            cause_raw_override,
        })
    }
}
