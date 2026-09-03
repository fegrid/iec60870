//! Encode/Decode for the typed [`InformationValue`] variants.
//!
//! Body sizes are sourced from
//! [`fegrid_iec60870_core::TypeId::object_size`], which mirrors
//! the IEC 60870-5 standard body layout (canonical wire form asserted
//! by `tests/golden.wire_spec_vectors_round_trip`). The trailing
//! timestamp (CP16/CP24/CP56) lives outside the body — see
//! [`crate::object::InformationObject`].

use fegrid_iec60870_core::{Cp56Time2a, QualityDescriptor, QualityDescriptorP, TypeId};

use crate::error::{AsduError, Result};
use crate::values::{BinaryCounterReading, InformationValue};
/// Body length (bytes per object, including timestamp suffix).
pub fn body_len_for_type(type_id: u8) -> usize {
    TypeId::from_wire(type_id).object_size()
}

/// Returns `true` if the per-object body for `type_id` is followed by a
/// 7-byte CP56Time2a timestamp.
pub fn has_cp56(type_id: u8) -> bool {
    use fegrid_iec60870_core::timestamp_kind_for;
    matches!(
        timestamp_kind_for(TypeId::from_wire(type_id)),
        Some(fegrid_iec60870_core::TimestampKind::Cp56)
    )
}

/// Returns `true` if the per-object body for `type_id` is followed by a
/// 3-byte CP24Time2a timestamp.
pub fn has_cp24(type_id: u8) -> bool {
    use fegrid_iec60870_core::timestamp_kind_for;
    matches!(
        timestamp_kind_for(TypeId::from_wire(type_id)),
        Some(fegrid_iec60870_core::TimestampKind::Cp24)
    )
}

/// Pre-timestamp body length (body minus any trailing CP16/CP24/CP56).
pub fn body_only_len(type_id: u8) -> usize {
    use fegrid_iec60870_core::timestamp_kind_for;
    let total = body_len_for_type(type_id);
    match timestamp_kind_for(TypeId::from_wire(type_id)) {
        Some(fegrid_iec60870_core::TimestampKind::Cp56) => total - 7,
        Some(fegrid_iec60870_core::TimestampKind::Cp24) => total - 3,
        Some(fegrid_iec60870_core::TimestampKind::Cp16) => total - 2,
        None => total,
    }
}

impl InformationValue {
    /// Body bytes excluding any trailing timestamp. For `Raw` returns the
    /// full byte count (caller is responsible for splitting body / ts when
    /// the strict parse path is used).
    pub fn body_len(&self) -> usize {
        match self {
            InformationValue::Raw { bytes, .. } => bytes.len(),
            InformationValue::FileSegment { los, data, .. } => {
                // 2 (NOF) + 1 (NOS) + 1 (LOS) + data.len().
                assert_eq!(
                    *los as usize,
                    data.len(),
                    "FileSegment LOS must equal data.len()"
                );
                4 + data.len()
            }
            InformationValue::FileDirectory { .. } => 13,
            _ => body_only_len(self.type_byte()),
        }
    }

    /// Wire type-id byte for this value.
    pub fn type_byte(&self) -> u8 {
        use InformationValue::*;
        match self {
            Raw { type_id, .. } => *type_id,
            SinglePoint { .. } => 1,
            DoublePoint { .. } => 3,
            StepPosition { .. } => 5,
            BitString32 { .. } => 7,
            MeasuredNormalized { .. } => 9,
            MeasuredScaled { .. } => 11,
            MeasuredFloat { .. } => 13,
            MeasuredNormalizedNoQ { .. } => 21,
            IntegratedTotals(_) => 15,
            SingleCommand { .. } => 45,
            DoubleCommand { .. } => 46,
            RegulatingStepCommand { .. } => 47,
            SetpointNormalized { .. } => 48,
            SetpointScaled { .. } => 49,
            SetpointFloat { .. } => 50,
            Bitstring32Command { .. } => 51,
            InterrogationCommand { .. } => 100,
            ReadCommand => 102,
            ClockSyncCommand(_) => 103,
            TestCommand { .. } => 104,
            ResetProcessCommand { .. } => 105,
            DelayCommand { .. } => 106,
            EndOfInitialization { .. } => 70,
            ProtectionEvent { .. } => 17,
            PackedStartEvent { .. } => 18,
            PackedOutputEvent { .. } => 39,
            PackedStartEvents { .. } => 20,
            ParameterNormalized { .. } => 110,
            ParameterScaled { .. } => 111,
            ParameterFloat { .. } => 112,
            ParameterActivation { .. } => 113,
            FileReady { .. } => 120,
            SectionReady { .. } => 121,
            FileCall { .. } => 122,
            FileLastSection { .. } => 123,
            FileAck { .. } => 124,
            FileSegment { .. } => 125,
            FileDirectory { .. } => 126,
        }
    }

    /// Encode the value body (timestamp excluded) into `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        use InformationValue::*;
        let need = self.body_len();
        if out.len() < need {
            return Err(AsduError::BufferTooShort {
                need,
                have: out.len(),
            });
        }
        match self {
            SinglePoint { value, quality } => {
                let mut b = 0u8;
                if *value {
                    b |= 0x01;
                }
                b |= quality.bits();
                out[0] = b;
            }
            DoublePoint { state, quality } => {
                let mut b = state & 0x03;
                b |= (quality.bits() & 0xfc) & 0xfc;
                out[0] = b;
            }
            StepPosition {
                value,
                transient,
                quality,
            } => {
                let mut v = (*value as u8) & 0x7f;
                if *transient {
                    v |= 0x80;
                }
                out[0] = v;
                out[1] = quality.bits();
            }
            BitString32 { value, quality } => {
                let bytes = value.to_le_bytes();
                out[0..4].copy_from_slice(&bytes);
                out[4] = quality.bits();
            }
            MeasuredNormalized { value, quality } | MeasuredScaled { value, quality } => {
                let bytes = value.to_le_bytes();
                out[0..2].copy_from_slice(&bytes);
                out[2] = quality.bits();
            }
            MeasuredFloat { value, quality } => {
                let bytes = value.to_le_bytes();
                out[0..4].copy_from_slice(&bytes);
                out[4] = quality.bits();
            }
            MeasuredNormalizedNoQ { value } => {
                let bytes = value.to_le_bytes();
                out[0..2].copy_from_slice(&bytes);
            }
            IntegratedTotals(bcr) => {
                bcr.encode(&mut out[0..5])?;
            }
            SingleCommand { on, select, qu } => {
                let mut b = (qu & 0x1f) << 2;
                if *select {
                    b |= 0x80;
                }
                if *on {
                    b |= 0x01;
                }
                out[0] = b;
            }
            DoubleCommand { state, select, qu } => {
                let mut b = state & 0x03;
                b |= (qu & 0x1f) << 2;
                if *select {
                    b |= 0x80;
                }
                out[0] = b;
            }
            RegulatingStepCommand {
                value,
                up,
                select,
                qu,
            } => {
                let mut b = (*value as u8) & 0x3f;
                b |= (qu & 0x1f) << 2;
                if *select {
                    b |= 0x40;
                }
                if *up {
                    b |= 0x80;
                }
                out[0] = b;
            }
            SetpointNormalized { value, ql } | SetpointScaled { value, ql } => {
                let bytes = value.to_le_bytes();
                out[0..2].copy_from_slice(&bytes);
                out[2] = *ql;
            }
            SetpointFloat { value, ql } => {
                let bytes = value.to_le_bytes();
                out[0..4].copy_from_slice(&bytes);
                out[4] = *ql;
            }
            Bitstring32Command { value } => {
                let bytes = value.to_le_bytes();
                out[0..4].copy_from_slice(&bytes);
            }
            InterrogationCommand { qoi } => {
                out[0] = *qoi;
            }
            ReadCommand => {}
            ClockSyncCommand(t) => {
                t.encode(&mut out[0..7])?;
            }
            TestCommand { fbp } => {
                out[0] = (fbp & 0xff) as u8;
                out[1] = ((fbp >> 8) & 0xff) as u8;
            }
            ResetProcessCommand { qrp } => {
                out[0] = *qrp;
            }
            DelayCommand { dow, hours } => {
                out[0] = *dow;
                out[1] = *hours;
            }
            EndOfInitialization { coi } => {
                out[0] = *coi;
            }
            ProtectionEvent { event, elapsed_ms } => {
                out[0] = *event;
                out[1..3].copy_from_slice(&elapsed_ms.to_le_bytes());
            }
            PackedStartEvent {
                event,
                qdp,
                elapsed_ms,
            } => {
                out[0] = *event;
                out[1] = *qdp;
                out[2..4].copy_from_slice(&elapsed_ms.to_le_bytes());
            }
            PackedOutputEvent {
                oci,
                qdp,
                elapsed_ms,
            } => {
                out[0] = *oci;
                out[1] = *qdp;
                out[2..4].copy_from_slice(&elapsed_ms.to_le_bytes());
            }
            PackedStartEvents { scd, quality } => {
                out[0..4].copy_from_slice(&scd.to_le_bytes());
                out[4] = quality.bits();
            }
            ParameterNormalized { value, qpm } | ParameterScaled { value, qpm } => {
                out[0..2].copy_from_slice(&value.to_le_bytes());
                out[2] = *qpm;
            }
            ParameterFloat { value, qpm } => {
                out[0..4].copy_from_slice(&value.to_le_bytes());
                out[4] = *qpm;
            }
            ParameterActivation { qpm } => {
                out[0] = *qpm;
            }
            FileReady { name, length, frq } => {
                out[0..2].copy_from_slice(&name.to_le_bytes());
                let bytes = length.to_le_bytes();
                out[2] = bytes[0];
                out[3] = bytes[1];
                out[4] = bytes[2];
                out[5] = *frq;
            }
            SectionReady {
                name,
                section,
                length,
                srq,
            } => {
                out[0..2].copy_from_slice(&name.to_le_bytes());
                out[2] = *section;
                let bytes = length.to_le_bytes();
                out[3] = bytes[0];
                out[4] = bytes[1];
                out[5] = bytes[2];
                out[6] = *srq;
            }
            FileCall { name, section, scq } => {
                out[0..2].copy_from_slice(&name.to_le_bytes());
                out[2] = *section;
                out[3] = *scq;
            }
            FileLastSection {
                name,
                section,
                lsq,
                checksum,
            } => {
                out[0..2].copy_from_slice(&name.to_le_bytes());
                out[2] = *section;
                out[3] = *lsq;
                out[4] = *checksum;
            }
            FileAck { name, section, afq } => {
                out[0..2].copy_from_slice(&name.to_le_bytes());
                out[2] = *section;
                out[3] = *afq;
            }
            FileSegment {
                name,
                section,
                los,
                data,
            } => {
                out[0..2].copy_from_slice(&name.to_le_bytes());
                out[2] = *section;
                out[3] = *los;
                out[4..4 + data.len()].copy_from_slice(data);
            }
            FileDirectory {
                name,
                length_of_file,
                sof,
                creation_time,
            } => {
                out[0..2].copy_from_slice(&name.to_le_bytes());
                out[2..5].copy_from_slice(&length_of_file.to_le_bytes()[..3]);
                out[5] = *sof;
                let mut ts = [0u8; 7];
                creation_time
                    .encode(&mut ts)
                    .map_err(|_| AsduError::BufferTooShort { need: 7, have: 0 })?;
                out[6..13].copy_from_slice(&ts);
            }
            Raw { bytes, .. } => {
                out[..bytes.len()].copy_from_slice(bytes);
            }
        }
        Ok(need)
    }

    /// Decode the body from `input` (timestamp excluded).
    pub fn decode(type_id: u8, input: &[u8]) -> Result<Self> {
        use InformationValue::*;
        // Pre-compute body_only_len for use in the body-only length check below.
        // The 125/126 arms re-validate length themselves because their bodies
        // are either variable (F_SG_NA_1) or embed a CP56 inside the body
        // (F_DR_TA_1).
        let body_only = body_only_len(type_id);
        // Variable-length F_SG_NA_1 (125) needs `4 + LOS` bytes; F_DR_TA_1 (126)
        // embeds a CP56 inside its 13-byte body. Validate them up front so the
        // generic body_only check (which assumes trailing-CP56 stripping) does
        // not clip these payloads.
        match type_id {
            125 => {
                if input.len() < 4 {
                    return Err(AsduError::BufferTooShort {
                        need: 4,
                        have: input.len(),
                    });
                }
                let los = input[3] as usize;
                if input.len() < 4 + los {
                    return Err(AsduError::BufferTooShort {
                        need: 4 + los,
                        have: input.len(),
                    });
                }
            }
            126 => {
                if input.len() < 13 {
                    return Err(AsduError::BufferTooShort {
                        need: 13,
                        have: input.len(),
                    });
                }
            }
            _ => {
                if input.len() < body_only {
                    return Err(AsduError::BufferTooShort {
                        need: body_only,
                        have: input.len(),
                    });
                }
            }
        }
        let out = match type_id {
            // SIQ body: M_SP_NA_1 (1), M_SP_TA_1 (2), M_SP_TB_1 (30).
            1 | 2 | 30 => SinglePoint {
                value: input[0] & 0x01 != 0,
                quality: QualityDescriptor::from_bits_truncate(input[0] & 0xfe),
            },
            // DIQ body: M_DP_NA_1 (3), M_DP_TA_1 (4), M_DP_TB_1 (31).
            3 | 4 | 31 => DoublePoint {
                state: input[0] & 0x03,
                quality: QualityDescriptor::from_bits_truncate(input[0] & 0x7c),
            },
            // VTI+QDS body: M_ST_NA_1 (5), M_ST_TA_1 (6), M_ST_TB_1 (32).
            5 | 6 | 32 => StepPosition {
                value: {
                    let v = input[0] & 0x7f;
                    if v & 0x40 != 0 {
                        (v | 0x80) as i8
                    } else {
                        v as i8
                    }
                },
                transient: input[0] & 0x80 != 0,
                quality: QualityDescriptor::from_bits_truncate(input[1]),
            },
            // BSI+QDS body: M_BO_NA_1 (7), M_BO_TA_1 (8), M_BO_TB_1 (33).
            7 | 8 | 33 => BitString32 {
                value: u32::from_le_bytes([input[0], input[1], input[2], input[3]]),
                quality: QualityDescriptor::from_bits_truncate(input[4]),
            },
            // NVA+QDS body: M_ME_NA_1 (9), M_ME_TA_1 (10), M_ME_TD_1 (34).
            9 | 10 | 34 => MeasuredNormalized {
                value: i16::from_le_bytes([input[0], input[1]]),
                quality: QualityDescriptorP::from_bits_truncate(input[2]),
            },
            // SVA+QDS body: M_ME_NB_1 (11), M_ME_TB_1 (12), M_ME_TE_1 (35).
            11 | 12 | 35 => MeasuredScaled {
                value: i16::from_le_bytes([input[0], input[1]]),
                quality: QualityDescriptorP::from_bits_truncate(input[2]),
            },
            // IEEE754+QDS body: M_ME_NC_1 (13), M_ME_TC_1 (14), M_ME_TF_1 (36).
            13 | 14 | 36 => MeasuredFloat {
                value: f32::from_le_bytes([input[0], input[1], input[2], input[3]]),
                quality: QualityDescriptorP::from_bits_truncate(input[4]),
            },
            // M_ME_ND_1 (21) — no QDS.
            21 => MeasuredNormalizedNoQ {
                value: i16::from_le_bytes([input[0], input[1]]),
            },
            // BCR body: M_IT_NA_1 (15), M_IT_TA_1 (16), M_IT_TB_1 (37).
            15 | 16 | 37 => IntegratedTotals(BinaryCounterReading::decode(&input[..5])?),
            // SCO body: C_SC_NA_1 (45), C_SC_TA_1 (58).
            45 | 58 => SingleCommand {
                on: input[0] & 0x01 != 0,
                select: input[0] & 0x80 != 0,
                qu: (input[0] >> 2) & 0x1f,
            },
            // RCO body: C_RC_NA_1 (47), C_RC_TA_1 (60).
            47 | 60 => RegulatingStepCommand {
                value: (input[0] & 0x3f) as i8,
                up: input[0] & 0x80 != 0,
                select: input[0] & 0x40 != 0,
                qu: (input[0] >> 2) & 0x1f,
            },
            // NVA+QL body: C_SE_NA_1 (48), C_SE_TA_1 (61).
            48 | 61 => SetpointNormalized {
                value: i16::from_le_bytes([input[0], input[1]]),
                ql: input[2],
            },
            // SVA+QL body: C_SE_NB_1 (49), C_SE_TB_1 (62).
            49 | 62 => SetpointScaled {
                value: i16::from_le_bytes([input[0], input[1]]),
                ql: input[2],
            },
            // IEEE754+QL body: C_SE_NC_1 (50), C_SE_TC_1 (63).
            50 | 63 => SetpointFloat {
                value: f32::from_le_bytes([input[0], input[1], input[2], input[3]]),
                ql: input[4],
            },
            // BSI body: C_BO_NA_1 (51), C_BO_TA_1 (64).
            51 | 64 => Bitstring32Command {
                value: u32::from_le_bytes([input[0], input[1], input[2], input[3]]),
            },
            // QOI/QCC body: C_IC_NA_1 (100), C_CI_NA_1 (101).
            100 | 101 => InterrogationCommand { qoi: input[0] },
            102 => ReadCommand,
            // CP56-only body: C_CS_NA_1 (103).
            103 => ClockSyncCommand(Cp56Time2a::decode(&input[..7])?),
            104 => TestCommand {
                fbp: u16::from_le_bytes([input[0], input[1]]),
            },
            46 | 59 => DoubleCommand {
                state: input[0] & 0x03,
                select: input[0] & 0x80 != 0,
                qu: (input[0] >> 2) & 0x1f,
            },
            // M_EP_TA_1 (17) and M_EP_TD_1 (38) — SEP(1) + CP16(2).
            17 | 38 => ProtectionEvent {
                event: input[0],
                elapsed_ms: u16::from_le_bytes([input[1], input[2]]),
            },
            // M_EP_TB_1 (18) and M_EP_TE_1 (39) — SEP(1) + QDP(1) + CP16(2).
            18 | 39 => PackedStartEvent {
                event: input[0],
                qdp: input[1],
                elapsed_ms: u16::from_le_bytes([input[2], input[3]]),
            },
            // M_EP_TC_1 (19) and M_EP_TF_1 (40) — OCI(1) + QDP(1) + CP16(2).
            19 | 40 => PackedOutputEvent {
                oci: input[0],
                qdp: input[1],
                elapsed_ms: u16::from_le_bytes([input[2], input[3]]),
            },
            // M_PS_NA_1 (20) — SCD(4) + QDS(1).
            20 => PackedStartEvents {
                scd: u32::from_le_bytes([input[0], input[1], input[2], input[3]]),
                quality: QualityDescriptor::from_bits_truncate(input[4]),
            },
            107 => Raw {
                type_id,
                bytes: input[..body_only].to_vec(),
            },
            110 => ParameterNormalized {
                value: i16::from_le_bytes([input[0], input[1]]),
                qpm: input[2],
            },
            // P_ME_NB_1 (111): SVA(2) + QPM(1).
            111 => ParameterScaled {
                value: i16::from_le_bytes([input[0], input[1]]),
                qpm: input[2],
            },
            // P_ME_NC_1 (112): IEEE754(4) + QPM(1).
            112 => ParameterFloat {
                value: f32::from_le_bytes([input[0], input[1], input[2], input[3]]),
                qpm: input[4],
            },
            // P_AC_NA_1 (113): QPM(1).
            113 => ParameterActivation { qpm: input[0] },
            // F_FR_NA_1 (120): NOF(2) + LOF(3) + FRQ(1).
            120 => FileReady {
                name: u16::from_le_bytes([input[0], input[1]]),
                length: u32::from_le_bytes([input[2], input[3], input[4], 0]),
                frq: input[5],
            },
            // F_SR_NA_1 (121): NOF(2) + NOS(1) + LOS(3) + SRQ(1).
            121 => SectionReady {
                name: u16::from_le_bytes([input[0], input[1]]),
                section: input[2],
                length: u32::from_le_bytes([input[3], input[4], input[5], 0]),
                srq: input[6],
            },
            // F_SC_NA_1 (122): NOF(2) + NOS(1) + SCQ(1).
            122 => FileCall {
                name: u16::from_le_bytes([input[0], input[1]]),
                section: input[2],
                scq: input[3],
            },
            // F_LS_NA_1 (123): NOF(2) + NOS(1) + LSQ(1) + CHS(1).
            123 => FileLastSection {
                name: u16::from_le_bytes([input[0], input[1]]),
                section: input[2],
                lsq: input[3],
                checksum: input[4],
            },
            // F_AF_NA_1 (124): NOF(2) + NOS(1) + AFQ(1).
            124 => FileAck {
                name: u16::from_le_bytes([input[0], input[1]]),
                section: input[2],
                afq: input[3],
            },
            // F_SG_NA_1 (125): NOF(2) + NOS(1) + LOS(1) + data[LOS]. Variable-length.
            125 => {
                if input.len() < 4 {
                    return Err(AsduError::BufferTooShort {
                        need: 4,
                        have: input.len(),
                    });
                }
                let los = input[3] as usize;
                if input.len() < 4 + los {
                    return Err(AsduError::BufferTooShort {
                        need: 4 + los,
                        have: input.len(),
                    });
                }
                FileSegment {
                    name: u16::from_le_bytes([input[0], input[1]]),
                    section: input[2],
                    los: los as u8,
                    data: input[4..4 + los].to_vec(),
                }
            }
            // F_DR_TA_1 (126): NOF(2) + LOF(3) + SOF(1) + CP56Time2a(7).
            126 => FileDirectory {
                name: u16::from_le_bytes([input[0], input[1]]),
                length_of_file: u32::from_le_bytes([input[2], input[3], input[4], 0]) & 0x00ff_ffff,
                sof: input[5],
                creation_time: Cp56Time2a::decode(&input[6..13])?,
            },
            // Anything else: round-trip as Raw so we never lose bytes.
            _ => Raw {
                type_id,
                bytes: input[..body_only].to_vec(),
            },
        };
        Ok(out)
    }
}
