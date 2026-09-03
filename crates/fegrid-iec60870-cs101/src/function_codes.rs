//! FT 1.2 function codes (primary + secondary).
//!
//! Wire layout in the CF byte (bit7=DIR/PRM, bit6=ACD, bit5=DFC, bits0..3=FC).

use fegrid_iec60870_core::{AsduError, Result};

/// Function codes for primary → secondary frames (PRM=1).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PrimaryFunctionCode {
    /// Reset remote link.
    ResetRemoteLink = 0,
    /// Reset user process (CU).
    ResetUserProcess = 1,
    /// Test function for link.
    TestFunctionForLink = 2,
    /// Send/confirm user data class 1/2.
    UserDataConfirmed = 3,
    /// Send/no-reply user data.
    UserDataNoReply = 4,
    /// Reserved by IEC 60870-5-1.
    Reserved56 = 5,
    /// Reserved by IEC 60870-5-1.
    Reserved57 = 6,
    /// Reset frame-count bit (FCB).
    ResetFcb = 7,
    /// Request for access demand.
    RequestForAccessDemand = 8,
    /// Request link status.
    RequestLinkStatus = 9,
    /// Request user data class 1.
    RequestUserDataClass1 = 10,
    /// Request user data class 2.
    RequestUserDataClass2 = 11,
}

impl PrimaryFunctionCode {
    /// Wire value.
    pub const fn wire(self) -> u8 {
        self as u8
    }

    /// Decode a 4-bit primary function code (low nibble of CF).
    pub fn try_from_wire(bits: u8) -> Result<Self> {
        Ok(match bits & 0x0f {
            0 => Self::ResetRemoteLink,
            1 => Self::ResetUserProcess,
            2 => Self::TestFunctionForLink,
            3 => Self::UserDataConfirmed,
            4 => Self::UserDataNoReply,
            7 => Self::ResetFcb,
            8 => Self::RequestForAccessDemand,
            9 => Self::RequestLinkStatus,
            10 => Self::RequestUserDataClass1,
            11 => Self::RequestUserDataClass2,
            other => return Err(AsduError::InvalidControlField(other)),
        })
    }
}
impl TryFrom<u8> for PrimaryFunctionCode {
    type Error = AsduError;
    fn try_from(value: u8) -> Result<Self> {
        Self::try_from_wire(value)
    }
}
/// Function codes for secondary → primary frames (PRM=0).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum SecondaryFunctionCode {
    /// ACK.
    Ack = 0,
    /// NACK.
    Nack = 1,
    /// Response: user data.
    RespUserData = 8,
    /// Response: NACK, no data.
    RespNackNoData = 9,
    /// Status of link or access demand.
    StatusOfLinkOrAccessDemand = 11,
    /// Service not functioning.
    ServiceNotFunctioning = 14,
    /// Service not implemented.
    ServiceNotImplemented = 15,
}

impl SecondaryFunctionCode {
    /// Wire value.
    pub const fn wire(self) -> u8 {
        self as u8
    }

    /// Decode a 4-bit secondary function code.
    pub fn try_from_wire(bits: u8) -> Result<Self> {
        Ok(match bits & 0x0f {
            0 => Self::Ack,
            1 => Self::Nack,
            8 => Self::RespUserData,
            9 => Self::RespNackNoData,
            11 => Self::StatusOfLinkOrAccessDemand,
            14 => Self::ServiceNotFunctioning,
            15 => Self::ServiceNotImplemented,
            other => return Err(AsduError::InvalidControlField(other)),
        })
    }
}
impl TryFrom<u8> for SecondaryFunctionCode {
    type Error = AsduError;
    fn try_from(value: u8) -> Result<Self> {
        Self::try_from_wire(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_try_from_wire() {
        assert_eq!(
            PrimaryFunctionCode::try_from_wire(0).unwrap(),
            PrimaryFunctionCode::ResetRemoteLink
        );
        assert!(PrimaryFunctionCode::try_from_wire(5).is_err());
    }
}
