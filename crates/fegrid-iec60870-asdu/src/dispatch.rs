//! Pure event dispatcher for received ASDUs.
//!
//! [`classify`] maps an [`Asdu`] into a [`DispatchEvent`] (a flat
//! `enum` covering every typed message in the plan). The dispatcher
//! never mutates or consumes the input — it inspects the parsed
//! structure and yields a value-only summary. Confirmation builders
//! [`activation_confirm`] / [`activation_termination`] clone the
//! request and rewrite the cause of transmission for the typical
//! "ACTIVATION → ACTIVATION_CON" / "… → ACTIVATION_TERMINATION"
//! response handshake.

extern crate alloc;
use fegrid_iec60870_core::Cp56Time2a;
use fegrid_iec60870_core::TypeId;

use crate::asdu::Asdu;
use crate::values::InformationValue;

/// The setpoint value carried by a `Setpoint` event.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SetpointValue {
    /// -1..+1 mapped to i16.
    Normalized(i16),
    /// Integer in scaled units.
    Scaled(i16),
    /// IEEE-754 single precision.
    Float(f32),
}

/// Tagged union of every dispatched event.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum DispatchEvent {
    /// C_IC_NA_1 activation.
    GeneralInterrogation {
        /// QOI byte.
        qoi: u8,
    },
    /// C_CI_NA_1 activation.
    CounterInterrogation {
        /// QCC byte (stored in `qoi`; same wire position).
        qcc: u8,
    },
    /// C_RD_NA_1 read.
    ReadCommand,
    /// C_CS_NA_1 clock sync.
    ClockSync(Cp56Time2a),
    /// C_TS_NA_1 test (or 107 / C_TS_TA_1).
    TestCommand {
        /// Test sequence (FBP).
        fbp: u16,
    },
    /// C_RP_NA_1 reset process.
    ResetProcess {
        /// QRP byte.
        qrp: u8,
    },
    /// C_CD_NA_1 delay acquisition.
    DelayAcquisition {
        /// Day-of-week modifier.
        dow: u8,
        /// Hours.
        hours: u8,
    },
    /// C_SC_NA_1 / C_SC_TA_1 single command.
    SingleCommand {
        /// On/off.
        on: bool,
        /// Select (true) vs execute (false).
        select: bool,
        /// Qualifier 0..31.
        qu: u8,
        /// Information-object address.
        ioa: u32,
    },
    /// C_DC_NA_1 / C_DC_TA_1 double command.
    DoubleCommand {
        /// 2-bit state.
        state: u8,
        /// Select vs execute.
        select: bool,
        /// Qualifier 0..31.
        qu: u8,
        /// Information-object address.
        ioa: u32,
    },
    /// C_RC_NA_1 / C_RC_TA_1 regulating step command.
    RegulatingStepCommand {
        /// -64..+63.
        value: i8,
        /// Up (true) vs down (false).
        up: bool,
        /// Select vs execute.
        select: bool,
        /// Qualifier 0..31.
        qu: u8,
        /// Information-object address.
        ioa: u32,
    },
    /// C_SE_NA_1 / C_SE_NB_1 / C_SE_NC_1 setpoint.
    Setpoint {
        /// Setpoint value (typed).
        value: SetpointValue,
        /// Qualifier 0..255.
        ql: u8,
        /// Information-object address.
        ioa: u32,
    },
    /// C_BO_NA_1 / C_BO_TA_1 bitstring of 32 bits command.
    BitstringCommand {
        /// 32-bit value.
        value: u32,
        /// Information-object address.
        ioa: u32,
    },
    /// Parameter activation (P_ME_NA_1 / P_ME_NB_1 / P_ME_NC_1 / P_AC_NA_1).
    /// Carries the IOA only — the IOA lookup table maps the IOA to the
    /// existing value (the request is destructive).
    ParameterLoad {
        /// Information-object address.
        ioa: u32,
    },
    /// F_FR_NA_1 file ready.
    FileReady(crate::values::FileReadyRepr),
    /// F_SR_NA_1 section ready.
    SectionReady(crate::values::SectionReadyRepr),
    /// F_SC_NA_1 call / select / directory.
    FileCall(crate::values::FileCallRepr),
    /// F_LS_NA_1 last section.
    FileLastSection(crate::values::FileLastSectionRepr),
    /// F_AF_NA_1 ack.
    FileAck(crate::values::FileAckRepr),
    /// Monitor-direction process data (M_*).
    ProcessData,
    /// Anything that doesn't fit the above.
    Other,
}

/// Pull the single-object value/ioa out of `asdu` — `None` when there
/// isn't exactly one object.
fn single_object(asdu: &Asdu) -> Option<(&InformationValue, u32)> {
    let obj = asdu.objects.first()?;
    if asdu.objects.len() != 1 {
        return None;
    }
    Some((&obj.value, obj.ioa))
}

/// Classify `asdu` into a [`DispatchEvent`].
pub fn classify(asdu: &Asdu) -> DispatchEvent {
    use DispatchEvent::*;
    use SetpointValue::*;
    use TypeId::*;
    match asdu.type_id {
        C_IC_NA_1 => match single_object(asdu) {
            Some((InformationValue::InterrogationCommand { qoi }, _)) => {
                GeneralInterrogation { qoi: *qoi }
            }
            _ => Other,
        },
        C_CI_NA_1 => match single_object(asdu) {
            Some((InformationValue::InterrogationCommand { qoi }, _)) => {
                CounterInterrogation { qcc: *qoi }
            }
            _ => Other,
        },
        C_RD_NA_1 => ReadCommand,
        C_CS_NA_1 => match single_object(asdu) {
            Some((InformationValue::ClockSyncCommand(t), _)) => ClockSync(*t),
            _ => Other,
        },
        C_TS_NA_1 => match single_object(asdu) {
            Some((InformationValue::TestCommand { fbp }, _)) => TestCommand { fbp: *fbp },
            _ => Other,
        },
        C_TS_TA_1 => {
            // 107 still decodes to Raw — surface it as TestCommand by
            // reading FBP from the first 2 bytes of the body.
            match single_object(asdu) {
                Some((
                    InformationValue::Raw {
                        type_id: 107,
                        bytes,
                    },
                    _,
                )) if bytes.len() >= 2 => TestCommand {
                    fbp: u16::from_le_bytes([bytes[0], bytes[1]]),
                },
                _ => Other,
            }
        }
        C_RP_NA_1 => match single_object(asdu) {
            Some((InformationValue::ResetProcessCommand { qrp }, _)) => ResetProcess { qrp: *qrp },
            _ => Other,
        },
        C_CD_NA_1 => match single_object(asdu) {
            Some((InformationValue::DelayCommand { dow, hours }, _)) => DelayAcquisition {
                dow: *dow,
                hours: *hours,
            },
            _ => Other,
        },
        C_SC_NA_1 | C_SC_TA_1 => match single_object(asdu) {
            Some((InformationValue::SingleCommand { on, select, qu }, ioa)) => SingleCommand {
                on: *on,
                select: *select,
                qu: *qu,
                ioa,
            },
            _ => Other,
        },
        C_DC_NA_1 | C_DC_TA_1 => match single_object(asdu) {
            Some((InformationValue::DoubleCommand { state, select, qu }, ioa)) => DoubleCommand {
                state: *state,
                select: *select,
                qu: *qu,
                ioa,
            },
            _ => Other,
        },
        C_RC_NA_1 | C_RC_TA_1 => match single_object(asdu) {
            Some((
                InformationValue::RegulatingStepCommand {
                    value,
                    up,
                    select,
                    qu,
                },
                ioa,
            )) => RegulatingStepCommand {
                value: *value,
                up: *up,
                select: *select,
                qu: *qu,
                ioa,
            },
            _ => Other,
        },
        C_SE_NA_1 | C_SE_TA_1 => match single_object(asdu) {
            Some((InformationValue::SetpointNormalized { value, ql }, ioa)) => Setpoint {
                value: Normalized(*value),
                ql: *ql,
                ioa,
            },
            _ => Other,
        },
        C_SE_NB_1 | C_SE_TB_1 => match single_object(asdu) {
            Some((InformationValue::SetpointScaled { value, ql }, ioa)) => Setpoint {
                value: Scaled(*value),
                ql: *ql,
                ioa,
            },
            _ => Other,
        },
        C_SE_NC_1 | C_SE_TC_1 => match single_object(asdu) {
            Some((InformationValue::SetpointFloat { value, ql }, ioa)) => Setpoint {
                value: Float(*value),
                ql: *ql,
                ioa,
            },
            _ => Other,
        },
        C_BO_NA_1 | C_BO_TA_1 => match single_object(asdu) {
            Some((InformationValue::Bitstring32Command { value }, ioa)) => {
                BitstringCommand { value: *value, ioa }
            }
            _ => Other,
        },
        P_ME_NA_1 | P_ME_NB_1 | P_ME_NC_1 | P_AC_NA_1 => match single_object(asdu) {
            Some((_, ioa)) => ParameterLoad { ioa },
            None => Other,
        },
        F_FR_NA_1 => match single_object(asdu) {
            Some((InformationValue::FileReady { name, length, frq }, _)) => {
                FileReady(crate::values::FileReadyRepr {
                    name: *name,
                    length: *length,
                    frq: *frq,
                })
            }
            Some((
                InformationValue::Raw {
                    type_id: 120,
                    bytes,
                },
                _,
            )) if bytes.len() >= 6 => FileReady(crate::values::FileReadyRepr {
                name: u16::from_le_bytes([bytes[0], bytes[1]]),
                length: u32::from_le_bytes([bytes[2], bytes[3], bytes[4], 0]),
                frq: bytes[5],
            }),
            _ => Other,
        },
        F_SR_NA_1 => match single_object(asdu) {
            Some((
                InformationValue::SectionReady {
                    name,
                    section,
                    length,
                    srq,
                },
                _,
            )) => SectionReady(crate::values::SectionReadyRepr {
                name: *name,
                section: *section,
                length: *length,
                srq: *srq,
            }),
            Some((
                InformationValue::Raw {
                    type_id: 121,
                    bytes,
                },
                _,
            )) if bytes.len() >= 7 => SectionReady(crate::values::SectionReadyRepr {
                name: u16::from_le_bytes([bytes[0], bytes[1]]),
                section: bytes[2],
                length: u32::from_le_bytes([bytes[3], bytes[4], bytes[5], 0]),
                srq: bytes[6],
            }),
            _ => Other,
        },
        F_SC_NA_1 => match single_object(asdu) {
            Some((InformationValue::FileCall { name, section, scq }, _)) => {
                FileCall(crate::values::FileCallRepr {
                    name: *name,
                    section: *section,
                    scq: *scq,
                })
            }
            Some((
                InformationValue::Raw {
                    type_id: 122,
                    bytes,
                },
                _,
            )) if bytes.len() >= 4 => FileCall(crate::values::FileCallRepr {
                name: u16::from_le_bytes([bytes[0], bytes[1]]),
                section: bytes[2],
                scq: bytes[3],
            }),
            _ => Other,
        },
        F_LS_NA_1 => match single_object(asdu) {
            Some((
                InformationValue::FileLastSection {
                    name,
                    section,
                    lsq,
                    checksum,
                },
                _,
            )) => FileLastSection(crate::values::FileLastSectionRepr {
                name: *name,
                section: *section,
                lsq: *lsq,
                checksum: *checksum,
            }),
            Some((
                InformationValue::Raw {
                    type_id: 123,
                    bytes,
                },
                _,
            )) if bytes.len() >= 5 => FileLastSection(crate::values::FileLastSectionRepr {
                name: u16::from_le_bytes([bytes[0], bytes[1]]),
                section: bytes[2],
                lsq: bytes[3],
                checksum: bytes[4],
            }),
            _ => Other,
        },
        F_AF_NA_1 => match single_object(asdu) {
            Some((InformationValue::FileAck { name, section, afq }, _)) => {
                FileAck(crate::values::FileAckRepr {
                    name: *name,
                    section: *section,
                    afq: *afq,
                })
            }
            Some((
                InformationValue::Raw {
                    type_id: 124,
                    bytes,
                },
                _,
            )) if bytes.len() >= 4 => FileAck(crate::values::FileAckRepr {
                name: u16::from_le_bytes([bytes[0], bytes[1]]),
                section: bytes[2],
                afq: bytes[3],
            }),
            _ => Other,
        },
        // Monitor direction process data.
        M_SP_NA_1 | M_SP_TA_1 | M_DP_NA_1 | M_DP_TA_1 | M_ST_NA_1 | M_ST_TA_1 | M_BO_NA_1
        | M_BO_TA_1 | M_ME_NA_1 | M_ME_TA_1 | M_ME_NB_1 | M_ME_TB_1 | M_ME_NC_1 | M_ME_TC_1
        | M_IT_NA_1 | M_IT_TA_1 | M_EP_TA_1 | M_EP_TB_1 | M_EP_TC_1 | M_PS_NA_1 | M_ME_ND_1
        | M_SP_TB_1 | M_DP_TB_1 | M_ST_TB_1 | M_BO_TB_1 | M_ME_TD_1 | M_ME_TE_1 | M_ME_TF_1
        | M_IT_TB_1 | M_EP_TD_1 | M_EP_TE_1 | M_EP_TF_1 | M_EI_NA_1 => ProcessData,
        Undefined => Other,
        _ => Other,
    }
}

/// Build the ACTIVATION_CON confirmation of `request`. Standard slave
/// reply to a single-object command activation.
///
/// `negative` flips the COT P/N bit so the slave can reject the command.
/// Returns the rebuilt [`Asdu`].
pub fn activation_confirm(request: &Asdu) -> Asdu {
    confirm_with(
        request,
        fegrid_iec60870_core::CauseOfTransmission::ActivationCon,
        false,
    )
}

/// Build the ACTIVATION_CON with a specific (typically negative) cause
/// of transmission. Used by slave runtime to emit `COT_UNKNOWN_CA`,
/// `COT_UNKNOWN_IOA`, `COT_UNKNOWN_COT`, or `COT_UNKNOWN_TYPE_ID`
/// when rejecting a command (G-047, F-CONF-015 negative-path
/// conformance).
///
/// The P/N bit is set so the master can distinguish positive-ack from
/// negative-ack on the wire. Returns the rebuilt [`Asdu`].
pub fn activation_confirm_with_cause(
    request: &Asdu,
    cause: fegrid_iec60870_core::CauseOfTransmission,
) -> Asdu {
    confirm_with(request, cause, true)
}

/// Like [`activation_confirm`] but with the negative-acknowledgement flag set.
/// Used when the slave rejects an activation with a negative COT (P/N bit = 1).
pub fn activation_confirm_negative(request: &Asdu) -> Asdu {
    confirm_with(
        request,
        fegrid_iec60870_core::CauseOfTransmission::ActivationCon,
        true,
    )
}

/// Build the ACTIVATION_TERMINATION confirmation of `request`. Standard
/// slave reply that signals the activation finished successfully.
pub fn activation_termination(request: &Asdu) -> Asdu {
    confirm_with(
        request,
        fegrid_iec60870_core::CauseOfTransmission::ActivationTermination,
        false,
    )
}

fn confirm_with(
    request: &Asdu,
    cause: fegrid_iec60870_core::CauseOfTransmission,
    negative: bool,
) -> Asdu {
    let mut response = request.clone();
    response.cot.cause = cause;
    response.cot.negative_confirm = negative;
    response
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::object::InformationObject;
    use alloc::vec::Vec;
    use fegrid_iec60870_core::{
        AppLayerParameters, CauseOfTransmission, CommonAddress, CotField, TypeId,
    };
    fn build_asdu(t: TypeId, cot: CauseOfTransmission, items: Vec<InformationObject>) -> Asdu {
        Asdu {
            type_id: t,
            original_type_byte: t as u8,
            cot: CotField {
                cause: cot,
                negative_confirm: false,
                test: false,
                originator: 0,
                cause_raw_override: None,
            },
            common_address: CommonAddress(1),
            is_sequence: false,
            is_test: false,
            objects: items,
        }
    }

    #[test]
    fn classifies_general_interrogation() {
        let asdu = build_asdu(
            TypeId::C_IC_NA_1,
            CauseOfTransmission::Activation,
            alloc::vec![InformationObject::new(
                1,
                InformationValue::InterrogationCommand { qoi: 20 },
            )],
        );
        assert_eq!(
            classify(&asdu),
            DispatchEvent::GeneralInterrogation { qoi: 20 }
        );
    }

    #[test]
    fn classifies_counter_interrogation() {
        let asdu = build_asdu(
            TypeId::C_CI_NA_1,
            CauseOfTransmission::Activation,
            alloc::vec![InformationObject::new(
                1,
                InformationValue::InterrogationCommand { qoi: 5 },
            )],
        );
        assert_eq!(
            classify(&asdu),
            DispatchEvent::CounterInterrogation { qcc: 5 }
        );
    }

    #[test]
    fn classifies_single_command() {
        let asdu = build_asdu(
            TypeId::C_SC_NA_1,
            CauseOfTransmission::Activation,
            alloc::vec![InformationObject::new(
                0x010203,
                InformationValue::SingleCommand {
                    on: true,
                    select: false,
                    qu: 0x05,
                },
            )],
        );
        assert_eq!(
            classify(&asdu),
            DispatchEvent::SingleCommand {
                on: true,
                select: false,
                qu: 0x05,
                ioa: 0x010203,
            }
        );
    }

    #[test]
    fn classifies_parameter_load() {
        let asdu = build_asdu(
            TypeId::P_ME_NC_1,
            CauseOfTransmission::Activation,
            alloc::vec![InformationObject::new(
                0x020304,
                InformationValue::ParameterFloat { value: 1.0, qpm: 0 },
            )],
        );
        assert_eq!(
            classify(&asdu),
            DispatchEvent::ParameterLoad { ioa: 0x020304 }
        );
    }

    #[test]
    fn spec_104_6_01_valid_asdu_set() {
        let asdu = build_asdu(
            TypeId::M_SP_NA_1,
            CauseOfTransmission::Spontaneous,
            alloc::vec![InformationObject::new(
                1,
                InformationValue::SinglePoint {
                    value: true,
                    quality: fegrid_iec60870_core::QualityDescriptor::default(),
                },
            )],
        );
        assert_eq!(classify(&asdu), DispatchEvent::ProcessData);
    }

    #[test]
    fn classifies_unknown_as_other() {
        let asdu = build_asdu(
            TypeId::Undefined,
            CauseOfTransmission::Spontaneous,
            alloc::vec![InformationObject::new(
                1,
                InformationValue::Raw {
                    type_id: 200,
                    bytes: alloc::vec![0, 0, 0],
                },
            )],
        );
        assert_eq!(classify(&asdu), DispatchEvent::Other);
    }

    #[test]
    fn activation_confirm_round_trips() {
        let request = build_asdu(
            TypeId::C_IC_NA_1,
            CauseOfTransmission::Activation,
            alloc::vec![InformationObject::new(
                1,
                InformationValue::InterrogationCommand { qoi: 20 },
            )],
        );
        let confirm = activation_confirm(&request);
        assert_eq!(confirm.type_id, TypeId::C_IC_NA_1);
        assert_eq!(confirm.cot.cause, CauseOfTransmission::ActivationCon);
        assert_eq!(confirm.common_address, request.common_address);
        assert_eq!(confirm.objects, request.objects);
        let params = AppLayerParameters::default();
        let bytes = crate::encode_to_vec(&params, &confirm).expect("encode");
        let parsed = Asdu::parse(&params, &bytes).unwrap();
        assert_eq!(parsed.type_id, TypeId::C_IC_NA_1);
        assert_eq!(parsed.cot.cause, CauseOfTransmission::ActivationCon);
    }

    #[test]
    fn activation_termination_sets_termination() {
        let request = build_asdu(
            TypeId::C_SC_NA_1,
            CauseOfTransmission::Activation,
            alloc::vec![InformationObject::new(
                1,
                InformationValue::SingleCommand {
                    on: true,
                    select: false,
                    qu: 0,
                },
            )],
        );
        let term = activation_termination(&request);
        assert_eq!(term.cot.cause, CauseOfTransmission::ActivationTermination);
    }
}
