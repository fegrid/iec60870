//! Qualifier octet enums for IEC 60870-5 control-direction commands.
//!
//! Each qualifier is a single byte whose bit pattern is fixed by the
//! standard. Newtypes wrap the raw byte to give compile-time type
//! safety on the slave side: a `QualifierOfInterrogation` cannot be
//! confused with a `QualifierOfCIC`. Conversion to/from the raw byte
//! is always explicit.

/// Qualifier of interrogation (`C_IC_NA_1`, QOI).
///
/// Standard values from IEC 60870-5-101 §7.3.1.100.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct QualifierOfInterrogation(pub u8);

impl QualifierOfInterrogation {
    /// Station interrogation (QOI = 20).
    pub const STATION: Self = Self(20);

    /// Interrogation of group `n` in 1..=16 (QOI = n).
    #[inline]
    pub const fn group(n: u8) -> Self {
        Self(n)
    }

    /// Raw octet value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Construct from any byte (no validation — the standard reserves
    /// values above 36 for vendor use).
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }
}

impl Default for QualifierOfInterrogation {
    fn default() -> Self {
        Self::STATION
    }
}

impl core::fmt::Display for QualifierOfInterrogation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            20 => f.write_str("station"),
            21..=36 => write!(f, "group{}", self.0 - 20),
            other => write!(f, "vendor({other})"),
        }
    }
}

/// Qualifier of counter-interrogation command (`C_CI_NA_1`, QCC).
///
/// Standard values from IEC 60870-5-101 §7.3.1.101.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct QualifierOfCIC(pub u8);

impl QualifierOfCIC {
    /// QCC = 0..=4 → counter groups 1..5, read without freeze.
    pub const GROUP_1_READ: Self = Self(0x05);
    /// Group 1, freeze + read.
    pub const GROUP_1_FREEZE_READ: Self = Self(0x45);
    /// Group 2, freeze + read.
    pub const GROUP_2_FREEZE_READ: Self = Self(0x46);
    /// Group 3, freeze + read.
    pub const GROUP_3_FREEZE_READ: Self = Self(0x47);
    /// Group 4, freeze + read.
    pub const GROUP_4_FREEZE_READ: Self = Self(0x48);
    /// General, freeze + read.
    pub const GENERAL_FREEZE_READ: Self = Self(0x49);

    /// Raw octet value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Construct from any byte (no validation — the standard reserves
    /// values above 0x49 for vendor use).
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }
}

impl Default for QualifierOfCIC {
    fn default() -> Self {
        Self::GENERAL_FREEZE_READ
    }
}

impl core::fmt::Display for QualifierOfCIC {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let freeze = (self.0 & 0x40) != 0;
        let group = self.0 & 0x3F;
        match group {
            0..=4 => write!(
                f,
                "group{} {}",
                group + 1,
                if freeze { "freeze+read" } else { "read" }
            ),
            5 => write!(f, "general {}", if freeze { "freeze+read" } else { "read" }),
            other => write!(f, "vendor(0x{other:02x})"),
        }
    }
}

/// Qualifier of reset-process command (`C_RP_NA_1`, QRP).
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct QualifierOfRPC(pub u8);

impl QualifierOfRPC {
    /// General reset of process (QRP = 1).
    pub const GENERAL_RESET: Self = Self(1);
    /// Reset of event buffers (QRP = 2).
    pub const RESET_EVENT_BUFFERS: Self = Self(2);

    /// Raw octet value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Construct from any byte.
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }
}

impl Default for QualifierOfRPC {
    fn default() -> Self {
        Self::GENERAL_RESET
    }
}

/// Qualifier of command (`C_*_NA_1` commands, QOC).
///
/// Combines the 2-bit select/execute mode and the 5-bit qualifier.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct QualifierOfCommand(pub u8);

impl QualifierOfCommand {
    /// Qualifier bits 0..=31 (5 bits).
    #[inline]
    pub const fn qualifier(self) -> u8 {
        self.0 & 0x1F
    }

    /// Select vs execute (bit 5 = 0 = execute, 1 = select).
    #[inline]
    pub const fn is_select(self) -> bool {
        (self.0 & 0x20) != 0
    }

    /// Construct from raw byte.
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    /// Build a qualifier with `select` flag and 5-bit qualifier value.
    #[inline]
    pub const fn new(select: bool, qu: u8) -> Self {
        Self((if select { 0x20 } else { 0 }) | (qu & 0x1F))
    }
}

/// Qualifier of parameter of measured value (`P_ME_*` parameters, QPM).
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct QualifierOfParameterMV(pub u8);

impl QualifierOfParameterMV {
    /// Threshold for limit transmission.
    pub const THRESHOLD: Self = Self(1);

    /// Smoothing factor.
    pub const SMOOTHING: Self = Self(2);

    /// Low limit (for measured value).
    pub const LOW_LIMIT: Self = Self(3);

    /// High limit (for measured value).
    pub const HIGH_LIMIT: Self = Self(4);

    /// Raw octet value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Construct from any byte.
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }
}

impl Default for QualifierOfParameterMV {
    fn default() -> Self {
        Self::THRESHOLD
    }
}

/// Qualifier of parameter activation (`P_AC_NA_1`, QPA).
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct QualifierOfParameterActivation(pub u8);

impl QualifierOfParameterActivation {
    /// Activate the addressed parameter (QPA = 1).
    pub const ACTIVATE: Self = Self(1);

    /// Deactivate the addressed parameter (QPA = 2).
    pub const DEACTIVATE: Self = Self(2);

    /// Raw octet value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Construct from any byte.
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }
}

impl Default for QualifierOfParameterActivation {
    fn default() -> Self {
        Self::ACTIVATE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrogation_station_is_20() {
        assert_eq!(QualifierOfInterrogation::STATION.raw(), 20);
        assert_eq!(QualifierOfInterrogation::group(1).raw(), 1);
        assert_eq!(QualifierOfInterrogation::group(16).raw(), 16);
    }

    #[test]
    fn cic_freeze_read_group1() {
        let q = QualifierOfCIC::GROUP_1_FREEZE_READ;
        assert_eq!(q.raw(), 0x45);
    }

    #[test]
    fn rpc_constants() {
        assert_eq!(QualifierOfRPC::GENERAL_RESET.raw(), 1);
        assert_eq!(QualifierOfRPC::RESET_EVENT_BUFFERS.raw(), 2);
    }

    #[test]
    fn qoc_select_bit() {
        let q = QualifierOfCommand::new(true, 7);
        assert!(q.is_select());
        assert_eq!(q.qualifier(), 7);
        let q = QualifierOfCommand::new(false, 0);
        assert!(!q.is_select());
    }

    #[test]
    fn qpm_constants() {
        assert_eq!(QualifierOfParameterMV::THRESHOLD.raw(), 1);
        assert_eq!(QualifierOfParameterMV::SMOOTHING.raw(), 2);
    }

    #[test]
    fn qpa_constants() {
        assert_eq!(QualifierOfParameterActivation::ACTIVATE.raw(), 1);
        assert_eq!(QualifierOfParameterActivation::DEACTIVATE.raw(), 2);
    }
}
