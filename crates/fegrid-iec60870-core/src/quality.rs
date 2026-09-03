//! Quality descriptors.

use bitflags::bitflags;

bitflags! {
    /// Quality descriptor for single- and double-point values.
    ///
    /// Bit layout per IEC 60870-5-101 §7.2.6.16 (SIQ / DIQ). The
    /// bits `RESERVED_2` / `RESERVED_3` (0x04, 0x08) are reserved by
    /// the standard for single-point info; we expose them here so
    /// encode/decode round-trips byte-identical.
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct QualityDescriptor: u8 {
        /// On/off (single-point) or transient/intermediate (double-point) bit.
        const SPI = 0x01;
        /// Reserved (single-point) or transient flag (double-point).
        const RESERVED_OR_DPI = 0x02;
        /// Reserved (single-point).
        const RESERVED_2 = 0x04;
        /// Reserved (single-point).
        const RESERVED_3 = 0x08;
        /// Blocked flag (BL).
        const BLOCKED = 0x10;
        /// Substitution flag.
        const SUBSTITUTED = 0x20;
        /// Topical / non-topical (blocked) flag.
        const NON_TOPICAL = 0x40;
        /// Validity (invalid) flag.
        const INVALID = 0x80;
    }
}

bitflags! {
    /// Quality descriptor for measured values (QDS).
    ///
    /// Adds the overflow and elapsed-time bits beyond [`QualityDescriptor`].
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct QualityDescriptorP: u8 {
        /// Overflow flag.
        const OVERFLOW = 0x01;
        /// Elapsed-time invalid flag.
        const ELAPSED_TIME_INVALID = 0x08;
        /// Substituted.
        const SUBSTITUTED = 0x20;
        /// Non-topical (blocked).
        const NON_TOPICAL = 0x40;
        /// Invalid.
        const INVALID = 0x80;
    }
}

bitflags! {
    /// Quality descriptor for binary counters (BCR).
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct BinaryCounterQuality: u8 {
        /// Carry flag.
        const CARRY = 0x01;
        /// Counter adjusted.
        const ADJUSTED = 0x20;
        /// Invalid.
        const INVALID = 0x80;
    }
}
