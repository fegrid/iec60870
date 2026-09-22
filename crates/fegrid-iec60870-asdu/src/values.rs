//! Typed information-object values for IEC 60870-5.
//!
//! Every fixed-size `TypeId` carries a typed variant here. Only the
//! variable-body `F_SG_NA_1` (125) and `F_DR_TA_1` (126) types, plus any
//! unknown wire byte, still parse/serialize through
//! [`InformationValue::Raw`] — the parser never rejects unknown-but-valid
//! wire payloads. `C_TS_TA_1` (107) decodes to the typed
//! [`InformationValue::TestCommand`] variant; its trailing CP56 lives in
//! `Asdu::objects[].value` (alongside FBP) rather than in the
//! `InformationObject::timestamp` suffix slot, so it remains a
//! variable-shape raw-equivalent at the strict-parse boundary.
use alloc::vec::Vec;

use fegrid_iec60870_core::{
    BinaryCounterQuality, Cp56Time2a, QualifierOfCIC, QualifierOfInterrogation, QualifierOfRPC,
    QualityDescriptor, QualityDescriptorP,
};

// Re-export module — kept minimal so external code can import the bitflags

/// One unit of CP56 time-tagged information (common suffix of `*_TB_1` types).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TimedSuffix {
    /// 7-byte CP56Time2a trailing each TB/TC object.
    pub time: Cp56Time2a,
}

/// Integrated-totals body.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BinaryCounterReading {
    /// 32-bit counter (BCD or binary — convention depends on qualifier).
    pub counter: i32,
    /// 4-bit sequence number (0..15).
    pub sequence: u8,
    /// Carry + adjust + invalid quality bits.
    pub quality: BinaryCounterQuality,
}

impl BinaryCounterReading {
    /// Encode the 5-byte BCR body.
    pub fn encode(&self, out: &mut [u8]) -> crate::error::Result<()> {
        if out.len() < 5 {
            return Err(crate::error::AsduError::BufferTooShort {
                need: 5,
                have: out.len(),
            });
        }
        out[..4].copy_from_slice(&self.counter.to_le_bytes());
        out[4] = (self.sequence & 0x1f) | self.quality.bits();
        Ok(())
    }

    /// Decode the 5-byte BCR body.
    pub fn decode(input: &[u8]) -> crate::error::Result<Self> {
        if input.len() < 5 {
            return Err(crate::error::AsduError::BufferTooShort {
                need: 5,
                have: input.len(),
            });
        }
        let counter = i32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        let b = input[4];
        let quality = BinaryCounterQuality::from_bits_truncate(b & 0xe0);
        Ok(Self {
            counter,
            sequence: b & 0x1f,
            quality,
        })
    }
}

/// Every information-object value type known to the codec.
///
/// Variants are grouped by IEC 60870-5-101 §7.3.1 — names match the
/// standard's TypeId suffixes. See [`crate::object::InformationObject`]
/// for the IOA-wrapped form.
#[derive(Debug, Clone, PartialEq)]
#[allow(non_camel_case_types)]
pub enum InformationValue {
    /// Single-point: 1 byte SIQ.
    SinglePoint {
        /// On/off.
        value: bool,
        /// Quality bits.
        quality: QualityDescriptor,
    },
    /// Double-point: 1 byte DIQ.
    DoublePoint {
        /// 2-bit state (0..3).
        state: u8,
        /// Quality bits.
        quality: QualityDescriptor,
    },
    /// Step position: VTI (1 byte) + QDS.
    StepPosition {
        /// -64..+63.
        value: i8,
        /// Transient flag.
        transient: bool,
        /// Quality bits.
        quality: QualityDescriptor,
    },
    /// Bitstring of 32 bits + QDS.
    BitString32 {
        /// 32-bit bitstring.
        value: u32,
        /// Quality bits.
        quality: QualityDescriptor,
    },
    /// Measured value, normalized: 2 bytes NVA + QDS.
    MeasuredNormalized {
        /// -1..+1 mapped to -32768..+32767.
        value: i16,
        /// Quality bits.
        quality: QualityDescriptorP,
    },
    /// Measured value, scaled: 2 bytes SVA + QDS.
    MeasuredScaled {
        /// Integer in scaled units.
        value: i16,
        /// Quality bits.
        quality: QualityDescriptorP,
    },
    /// Measured value, short floating-point: 4 bytes IEEE754 + QDS.
    MeasuredFloat {
        /// IEEE-754 single-precision value.
        value: f32,
        /// Quality bits.
        quality: QualityDescriptorP,
    },
    /// Measured value, normalized without quality descriptor.
    MeasuredNormalizedNoQ {
        /// -1..+1 mapped to -32768..+32767.
        value: i16,
    },
    /// Integrated totals: 5 bytes BCR.
    IntegratedTotals(BinaryCounterReading),
    /// Single command (1 byte SCO).
    SingleCommand {
        /// On/off.
        on: bool,
        /// Select (1) vs execute (0).
        select: bool,
        /// Qualifier 0..31 (0 = no additional qualification).
        qu: u8,
    },
    /// Double command (1 byte DCO).
    DoubleCommand {
        /// 2-bit state.
        state: u8,
        /// Select vs execute.
        select: bool,
        /// Qualifier 0..31.
        qu: u8,
    },
    /// Regulating step command (1 byte RCO).
    RegulatingStepCommand {
        /// -64..+63.
        value: i8,
        /// Up vs down (true = up).
        up: bool,
        /// Select vs execute.
        select: bool,
        /// Qualifier 0..31.
        qu: u8,
    },
    /// Setpoint, normalized (2 bytes NVA + 1 byte QL).
    SetpointNormalized {
        /// -1..+1.
        value: i16,
        /// Qualifier 0..255.
        ql: u8,
    },
    /// Setpoint, scaled (2 bytes SVA + 1 byte QL).
    SetpointScaled {
        /// Integer.
        value: i16,
        /// Qualifier.
        ql: u8,
    },
    /// Setpoint, short floating-point (4 bytes IEEE754 + 1 byte QL).
    SetpointFloat {
        /// IEEE-754 value.
        value: f32,
        /// Qualifier.
        ql: u8,
    },
    /// 32-bit bitstring command (4 bytes).
    Bitstring32Command {
        /// 32-bit value.
        value: u32,
    },
    /// General / counter interrogation (1 byte QOI/QCC).
    InterrogationCommand {
        /// 1-byte QOI or QCC.
        qoi: u8,
    },
    /// Read command — no body.
    ReadCommand,
    /// Clock sync (7 bytes CP56Time2a).
    ClockSyncCommand(Cp56Time2a),
    /// Test command (2 bytes FBP).
    TestCommand {
        /// Test sequence.
        fbp: u16,
    },
    /// Reset process command (1 byte QRP).
    ResetProcessCommand {
        /// Qualifier 0..255.
        qrp: u8,
    },
    /// Delay acquisition (2 bytes DOW + hours).
    DelayCommand {
        /// Day-of-week-with-activation.
        dow: u8,
        /// Hours.
        hours: u8,
    },
    /// End-of-initialization (1 byte COI).
    EndOfInitialization {
        /// COI value.
        coi: u8,
    },
    /// Protection event of protection equipment: SEP (1) + CP16-elapsed (2).
    /// Wire types M_EP_TA_1 (17) and M_EP_TD_1 (38) — trailing CP24/CP56
    /// time tag is carried in `InformationObject::timestamp`.
    ProtectionEvent {
        /// Single-event indicator (1 byte).
        event: u8,
        /// Elapsed time in milliseconds, CP16 (2 bytes LE, 0..65535).
        elapsed_ms: u16,
    },
    /// Packed start events of protection equipment: SEP (1) + QDP (1)
    /// + CP16-elapsed (2). Wire types M_EP_TB_1 (18) and M_EP_TE_1 (39).
    PackedStartEvent {
        /// Start event (1 byte).
        event: u8,
        /// Quality descriptor for protection events (1 byte).
        qdp: u8,
        /// Elapsed time in milliseconds, CP16 (2 bytes LE, 0..65535).
        elapsed_ms: u16,
    },
    /// Packed output circuit info of protection equipment: OCI (1) +
    /// QDP (1) + CP16-operating-time (2). Wire types M_EP_TC_1 (19) and
    /// M_EP_TF_1 (40).
    PackedOutputEvent {
        /// Output circuit info (1 byte).
        oci: u8,
        /// Quality descriptor for protection events (1 byte).
        qdp: u8,
        /// Operating time in milliseconds, CP16 (2 bytes LE, 0..65535).
        elapsed_ms: u16,
    },
    /// Packed single-point with status-change detection (M_PS_NA_1):
    /// SCD (4 bytes) + QDS (1 byte).
    PackedStartEvents {
        /// Status-change detection bitmap.
        scd: u32,
        /// Quality descriptor.
        quality: QualityDescriptor,
    },
    /// Parameter of measured value, normalized: NVA (2 bytes) + QPM (1 byte).
    /// Wire types P_ME_NA_1 (110).
    ParameterNormalized {
        /// -1..+1 mapped to -32768..+32767.
        value: i16,
        /// Qualifier of parameter measurement.
        qpm: u8,
    },
    /// Parameter of measured value, scaled: SVA (2 bytes) + QPM (1 byte).
    /// Wire type P_ME_NB_1 (111).
    ParameterScaled {
        /// Integer in scaled units.
        value: i16,
        /// Qualifier of parameter measurement.
        qpm: u8,
    },
    /// Parameter of measured value, short floating-point: IEEE754 (4 bytes)
    /// + QPM (1 byte). Wire type P_ME_NC_1 (112).
    ParameterFloat {
        /// IEEE-754 single-precision value.
        value: f32,
        /// Qualifier of parameter measurement.
        qpm: u8,
    },
    /// Parameter activation: 1 byte QPM. Wire type P_AC_NA_1 (113).
    ParameterActivation {
        /// Qualifier of parameter activation.
        qpm: u8,
    },
    /// File ready: NOF (2) + LOF (3) + FRQ (1). F_FR_NA_1 (120).
    FileReady {
        /// Name of file (NOF).
        name: u16,
        /// Length of file (LOF, 24-bit per IEC 60870-5 §7.3.1.120).
        length: u32,
        /// File-ready qualifier (FRQ).
        frq: u8,
    },
    /// Section ready: NOF (2) + NOS (1) + LOS (3) + SRQ (1). F_SR_NA_1 (121).
    SectionReady {
        /// Name of file (NOF).
        name: u16,
        /// Name of section (NOS, 1 byte per IEC 60870-5 §7.3.1.121).
        section: u8,
        /// Length of section (LOS, 24-bit per IEC 60870-5 §7.3.1.121).
        length: u32,
        /// Section-ready qualifier (SRQ).
        srq: u8,
    },
    /// Call directory, select file, call file or section: NOF (2) + NOS (1)
    /// + SCQ (1). F_SC_NA_1 (122).
    FileCall {
        /// Name of file (NOF).
        name: u16,
        /// Number of section or directory entry (NOS).
        section: u8,
        /// Select / call qualifier (SCQ).
        scq: u8,
    },
    /// Last section / last segment: NOF (2) + NOS (1) + LSQ (1) + CHS (1).
    /// F_LS_NA_1 (123).
    FileLastSection {
        /// Name of file (NOF).
        name: u16,
        /// Number of section (NOS).
        section: u8,
        /// Last-section qualifier (LSQ).
        lsq: u8,
        /// Section checksum (CHS).
        checksum: u8,
    },
    /// Ack file / ack section: NOF (2) + NOS (1) + AFQ (1). F_AF_NA_1 (124).
    FileAck {
        /// Name of file (NOF).
        name: u16,
        /// Number of section (NOS).
        section: u8,
        /// Ack-file qualifier (AFQ).
        afq: u8,
    },
    /// File segment: NOF (2) + NOS (1) + LOS (1) + `data[LOS]`. F_SG_NA_1 (125).
    /// Variable-length body — the segment data length is carried in `los`.
    FileSegment {
        /// Name of file (NOF).
        name: u16,
        /// Name of section (NOS).
        section: u8,
        /// Length of segment (LOS), 0..=63 (max fits in CS 101 max-asdu).
        los: u8,
        /// Segment data bytes (`los` bytes follow).
        data: Vec<u8>,
    },
    /// File directory: NOF (2) + LOF (3) + SOF (1) + CP56Time2a (7). F_DR_TA_1 (126).
    FileDirectory {
        /// Name of file (NOF).
        name: u16,
        /// Length of file (LOF, 24-bit).
        length_of_file: u32,
        /// Status of file (SOF) — bit flags: STATUS (0x07), LFD (0x10), FOR (0x20).
        sof: u8,
        /// File creation time (CP56Time2a).
        creation_time: Cp56Time2a,
    },
    /// IEC 60870-5-7 §6.3 Authentication challenge / response
    /// (C_ACSE_NA_3, type id 135). Fixed 38-byte body:
    /// challenge(32) + response(4) + role(1) + status(1).
    AcseActivation {
        /// 256-bit challenge issued by the authenticator.
        challenge: [u8; 32],
        /// Truncated HMAC-SHA256-4 response computed by the
        /// challengee. All zeros on the initial ChallengeRequest;
        /// populated by the ChallengeResponse.
        response: [u8; 4],
        /// User role per IEC 60870-5-7 §6.4. 0 = default.
        role: u8,
        /// Status octet: bit 7 = OK, bits 6-4 = algorithm
        /// identifier (see `AuthAlgorithm::wire` in
        /// `fegrid_iec60870_secauth`), bits 3-0 reserved.
        status: u8,
    },
    /// Round-trips verbatim; never decoded to typed data. Timestamps are
    /// not part of this blob — see [`crate::object::InformationObject`].
    Raw {
        /// The wire type-id byte.
        type_id: u8,
        /// Body bytes exactly as decoded.
        bytes: Vec<u8>,
    },
}

/// F_FR_NA_1 fields, lifted out of `InformationValue::FileReady` for
/// downstream consumers that prefer a plain struct over the enum.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FileReadyRepr {
    /// NOF.
    pub name: u16,
    /// LOF (24-bit per IEC 60870-5 §7.3.1.120).
    pub length: u32,
    /// FRQ.
    pub frq: u8,
}

/// F_SR_NA_1 fields.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SectionReadyRepr {
    /// NOF.
    pub name: u16,
    /// NOS (1 byte per IEC 60870-5 §7.3.1.121).
    pub section: u8,
    /// LOS (24-bit per IEC 60870-5 §7.3.1.121).
    pub length: u32,
    /// SRQ.
    pub srq: u8,
}

/// F_SC_NA_1 fields.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FileCallRepr {
    /// NOF.
    pub name: u16,
    /// NOS.
    pub section: u8,
    /// SCQ.
    pub scq: u8,
}

/// F_LS_NA_1 fields.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FileLastSectionRepr {
    /// NOF.
    pub name: u16,
    /// NOS.
    pub section: u8,
    /// LSQ.
    pub lsq: u8,
    /// CHS.
    pub checksum: u8,
}

/// F_AF_NA_1 fields.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FileAckRepr {
    /// NOF.
    pub name: u16,
    /// NOS.
    pub section: u8,
    /// AFQ.
    pub afq: u8,
}

impl InformationValue {
    /// Typed accessor for the `InterrogationCommand.qoi` byte.
    #[must_use]
    pub fn qoi(&self) -> Option<QualifierOfInterrogation> {
        match self {
            Self::InterrogationCommand { qoi } => Some(QualifierOfInterrogation(*qoi)),
            _ => None,
        }
    }

    /// Build an `InterrogationCommand` from a typed qualifier.
    #[must_use]
    pub fn interrogation_command(qoi: QualifierOfInterrogation) -> Self {
        Self::InterrogationCommand { qoi: qoi.raw() }
    }

    /// Typed accessor interpreting the wire byte as QCC. Both `C_IC_NA_1`
    /// (QOI) and `C_CI_NA_1` (QCC) ride in the [`Self::InterrogationCommand`]
    /// variant — the dispatcher distinguishes them. Use this only when the
    /// type id is known to be `C_CI_NA_1`.
    #[must_use]
    pub fn qcc(&self) -> Option<QualifierOfCIC> {
        match self {
            Self::InterrogationCommand { qoi } => Some(QualifierOfCIC(*qoi)),
            _ => None,
        }
    }

    /// Build a `CounterInterrogationCommand` ASDU body from a typed QCC.
    /// Returns an `InterrogationCommand`-shaped variant (the C library
    /// also models QCC under the same wire field; the dispatcher is what
    /// distinguishes them).
    #[must_use]
    pub fn counter_interrogation_command(qcc: QualifierOfCIC) -> Self {
        Self::InterrogationCommand { qoi: qcc.raw() }
    }

    /// Typed accessor for the `ResetProcessCommand.qrp` byte.
    #[must_use]
    pub fn qrp(&self) -> Option<QualifierOfRPC> {
        match self {
            Self::ResetProcessCommand { qrp } => Some(QualifierOfRPC(*qrp)),
            _ => None,
        }
    }

    /// Build a `ResetProcessCommand` from a typed qualifier.
    #[must_use]
    pub fn reset_process_command(qrp: QualifierOfRPC) -> Self {
        Self::ResetProcessCommand { qrp: qrp.raw() }
    }
}
