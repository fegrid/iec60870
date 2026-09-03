//! Application- and link-layer parameter structs.

/// Cause-of-transmission field size (1 or 2 bytes).
///
/// The 2-byte form carries an additional originator address octet.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum CotSize {
    /// 1-byte COT (cause only).
    One = 1,
    /// 2-byte COT (cause + originator address).
    #[default]
    Two = 2,
}

/// Common-address field size (1 or 2 bytes).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum CaSize {
    /// 1-byte CA.
    One = 1,
    /// 2-byte CA.
    #[default]
    Two = 2,
}

/// Information-object-address field size (1, 2, or 3 bytes).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum IoaSize {
    /// 1-byte IOA (0..256).
    One = 1,
    /// 2-byte IOA (0..65536).
    Two = 2,
    /// 3-byte IOA (0..2^24).
    #[default]
    Three = 3,
}

/// Application-layer parameter block exchanged at session setup.
///
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AppLayerParameters {
    /// Size of the cause-of-transmission field.
    pub size_of_cot: CotSize,
    /// Size of the common-address field.
    pub size_of_ca: CaSize,
    /// Size of the information-object-address field.
    pub size_of_ioa: IoaSize,
    /// Maximum ASDU length in bytes (249 for IEC 104, 255 otherwise).
    pub max_size_of_asdu: u8,
}

impl Default for AppLayerParameters {
    fn default() -> Self {
        Self {
            size_of_cot: CotSize::Two,
            size_of_ca: CaSize::Two,
            size_of_ioa: IoaSize::Three,
            max_size_of_asdu: 249,
        }
    }
}

impl AppLayerParameters {
    /// Total length of the fixed ASDU header (type + vsq + cot + ca).
    pub const fn header_size(&self) -> usize {
        2 + self.size_of_cot as usize + self.size_of_ca as usize
    }

    /// Bytes per IOA.
    pub const fn ioa_size(&self) -> usize {
        self.size_of_ioa as usize
    }
}

/// Link-layer address size (1 or 2 bytes).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum AddressLen {
    /// 1-byte link address.
    One = 1,
    /// 2-byte link address.
    #[default]
    Two = 2,
}

/// FT 1.2 link-layer parameter block.
///
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LinkLayerParameters {
    /// Link-address field size.
    pub address_length: AddressLen,
    /// When `true`, the slave replies with a single `0xE5` byte in place of a
    /// full ACK frame for short requests.
    pub use_single_char_ack: bool,
    /// Time (ms) the slave waits before timing out a not-yet-acknowledged I-frame.
    pub timeout_ack_ms: u32,
    /// Repeat-interval (ms) for unacknowledged link-layer requests.
    pub timeout_repeat_ms: u32,
}

impl Default for LinkLayerParameters {
    fn default() -> Self {
        Self {
            address_length: AddressLen::Two,
            use_single_char_ack: true,
            timeout_ack_ms: 500,
            timeout_repeat_ms: 5000,
        }
    }
}
