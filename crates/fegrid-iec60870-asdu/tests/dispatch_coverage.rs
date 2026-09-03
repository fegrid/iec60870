//! Coverage tests for dispatch.rs classify() and the activation_* helpers.

use fegrid_iec60870_asdu::{
    Asdu, InformationObject, InformationValue,
    dispatch::{
        DispatchEvent, SetpointValue, activation_confirm, activation_confirm_negative,
        activation_termination, classify,
    },
};
use fegrid_iec60870_core::{
    CauseOfTransmission, CommonAddress, CotField, Cp56Time2a, QualifierOfCIC,
    QualifierOfInterrogation, TypeId,
};

fn make(type_id: TypeId, value: InformationValue) -> Asdu {
    Asdu {
        type_id,
        original_type_byte: type_id as u8,
        cot: CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(0x010203, value)],
    }
}

fn make_process() -> Asdu {
    Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: TypeId::M_SP_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![],
    }
}

fn make_other() -> Asdu {
    Asdu {
        type_id: TypeId::C_IC_NA_1,
        original_type_byte: TypeId::C_IC_NA_1 as u8,
        cot: CotField {
            cause: CauseOfTransmission::Activation,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![],
    }
}

#[test]
fn classify_general_interrogation() {
    let asdu = make(
        TypeId::C_IC_NA_1,
        InformationValue::interrogation_command(QualifierOfInterrogation::STATION),
    );
    match classify(&asdu) {
        DispatchEvent::GeneralInterrogation { qoi } => assert_eq!(qoi, 20),
        other => panic!("expected GeneralInterrogation, got {other:?}"),
    }
}

#[test]
fn classify_counter_interrogation() {
    let asdu = make(
        TypeId::C_CI_NA_1,
        InformationValue::counter_interrogation_command(QualifierOfCIC::GROUP_1_FREEZE_READ),
    );
    match classify(&asdu) {
        DispatchEvent::CounterInterrogation { qcc } => assert_eq!(qcc, 69),
        other => panic!("expected CounterInterrogation, got {other:?}"),
    }
}

#[test]
fn classify_read_command() {
    let asdu = make(TypeId::C_RD_NA_1, InformationValue::ReadCommand);
    assert!(matches!(classify(&asdu), DispatchEvent::ReadCommand));
}

#[test]
fn classify_clock_sync() {
    let t = Cp56Time2a {
        ms: 12345,
        minutes: 6,
        hours: 12,
        day_of_month: 15,
        day_of_week: 3,
        month: 8,
        year: 126,
        summer_time: false,
        invalid: false,
    };
    let asdu = make(TypeId::C_CS_NA_1, InformationValue::ClockSyncCommand(t));
    assert!(matches!(classify(&asdu), DispatchEvent::ClockSync(_)));
}

#[test]
fn classify_test_command_na() {
    let asdu = make(
        TypeId::C_TS_NA_1,
        InformationValue::TestCommand { fbp: 0x1234 },
    );
    match classify(&asdu) {
        DispatchEvent::TestCommand { fbp } => assert_eq!(fbp, 0x1234),
        other => panic!("expected TestCommand, got {other:?}"),
    }
}

#[test]
fn classify_test_command_ta_raw() {
    // C_TS_TA_1 (type id 107) decoded as Raw with 2-byte FBP.
    let asdu = make(
        TypeId::C_TS_TA_1,
        InformationValue::Raw {
            type_id: 107,
            bytes: vec![0x34, 0x12],
        },
    );
    match classify(&asdu) {
        DispatchEvent::TestCommand { fbp } => assert_eq!(fbp, 0x1234),
        other => panic!("expected TestCommand from raw, got {other:?}"),
    }
}

#[test]
fn classify_reset_process() {
    let asdu = make(
        TypeId::C_RP_NA_1,
        InformationValue::ResetProcessCommand { qrp: 1 },
    );
    match classify(&asdu) {
        DispatchEvent::ResetProcess { qrp } => assert_eq!(qrp, 1),
        other => panic!("expected ResetProcess, got {other:?}"),
    }
}

#[test]
fn classify_delay_acquisition() {
    let asdu = make(
        TypeId::C_CD_NA_1,
        InformationValue::DelayCommand { dow: 3, hours: 5 },
    );
    match classify(&asdu) {
        DispatchEvent::DelayAcquisition { dow, hours } => {
            assert_eq!(dow, 3);
            assert_eq!(hours, 5);
        }
        other => panic!("expected DelayAcquisition, got {other:?}"),
    }
}

#[test]
fn classify_single_command() {
    let asdu = make(
        TypeId::C_SC_NA_1,
        InformationValue::SingleCommand {
            on: true,
            select: false,
            qu: 0,
        },
    );
    match classify(&asdu) {
        DispatchEvent::SingleCommand {
            on,
            select,
            qu,
            ioa,
        } => {
            assert!(on);
            assert!(!select);
            assert_eq!(qu, 0);
            assert_eq!(ioa, 0x010203);
        }
        other => panic!("expected SingleCommand, got {other:?}"),
    }
}

#[test]
fn classify_double_command() {
    let asdu = make(
        TypeId::C_DC_NA_1,
        InformationValue::DoubleCommand {
            state: 2,
            select: false,
            qu: 1,
        },
    );
    match classify(&asdu) {
        DispatchEvent::DoubleCommand {
            state,
            select,
            qu,
            ioa,
        } => {
            assert_eq!(state, 2);
            assert!(!select);
            assert_eq!(qu, 1);
            assert_eq!(ioa, 0x010203);
        }
        other => panic!("expected DoubleCommand, got {other:?}"),
    }
}

#[test]
fn classify_regulating_step_command() {
    let asdu = make(
        TypeId::C_RC_NA_1,
        InformationValue::RegulatingStepCommand {
            value: -3,
            up: true,
            select: false,
            qu: 0,
        },
    );
    match classify(&asdu) {
        DispatchEvent::RegulatingStepCommand {
            value,
            up,
            select,
            qu,
            ioa,
        } => {
            assert_eq!(value, -3);
            assert!(up);
            assert!(!select);
            assert_eq!(qu, 0);
            assert_eq!(ioa, 0x010203);
        }
        other => panic!("expected RegulatingStepCommand, got {other:?}"),
    }
}

#[test]
fn classify_setpoint_short_float() {
    let asdu = make(
        TypeId::C_SE_NC_1,
        InformationValue::SetpointFloat {
            value: 1.5f32,
            ql: 0,
        },
    );
    match classify(&asdu) {
        DispatchEvent::Setpoint { value, ql, ioa } => {
            assert!(matches!(value, SetpointValue::Float(_)));
            assert_eq!(ql, 0);
            assert_eq!(ioa, 0x010203);
        }
        other => panic!("expected Setpoint, got {other:?}"),
    }
}

#[test]
fn classify_bitstring_command() {
    let asdu = make(
        TypeId::C_BO_NA_1,
        InformationValue::Bitstring32Command { value: 0xDEADBEEF },
    );
    match classify(&asdu) {
        DispatchEvent::BitstringCommand { value, ioa } => {
            assert_eq!(value, 0xDEADBEEF);
            assert_eq!(ioa, 0x010203);
        }
        other => panic!("expected BitstringCommand, got {other:?}"),
    }
}

#[test]
fn classify_parameter_load() {
    let asdu = make(TypeId::P_AC_NA_1, InformationValue::ReadCommand);
    match classify(&asdu) {
        DispatchEvent::ParameterLoad { ioa } => assert_eq!(ioa, 0x010203),
        other => panic!("expected ParameterLoad, got {other:?}"),
    }
}

#[test]
fn classify_process_data_fallback() {
    assert!(matches!(
        classify(&make_process()),
        DispatchEvent::ProcessData
    ));
}

#[test]
fn classify_other_for_malformed_single_object() {
    assert!(matches!(classify(&make_other()), DispatchEvent::Other));
}

#[test]
fn classify_other_for_wrong_payload_type() {
    let asdu = make(TypeId::C_IC_NA_1, InformationValue::ReadCommand);
    assert!(matches!(classify(&asdu), DispatchEvent::Other));
}

#[test]
fn activation_confirm_copies_qualifiers() {
    let asdu = make(
        TypeId::C_IC_NA_1,
        InformationValue::interrogation_command(QualifierOfInterrogation::STATION),
    );
    let confirm = activation_confirm(&asdu);
    assert_eq!(confirm.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(!confirm.cot.negative_confirm);
    assert_eq!(confirm.original_type_byte, TypeId::C_IC_NA_1 as u8);
}

#[test]
fn activation_confirm_negative_sets_n_flag() {
    let asdu = make(
        TypeId::C_SC_NA_1,
        InformationValue::SingleCommand {
            on: true,
            select: false,
            qu: 0,
        },
    );
    let neg = activation_confirm_negative(&asdu);
    assert_eq!(neg.cot.cause, CauseOfTransmission::ActivationCon);
    assert!(neg.cot.negative_confirm);
}

#[test]
fn activation_termination_keeps_cause() {
    let asdu = make(
        TypeId::C_SC_NA_1,
        InformationValue::SingleCommand {
            on: true,
            select: false,
            qu: 0,
        },
    );
    let term = activation_termination(&asdu);
    assert_eq!(term.cot.cause, CauseOfTransmission::ActivationTermination);
}

#[test]
fn classify_file_events() {
    let asdu = make(TypeId::F_FR_NA_1, InformationValue::ReadCommand);
    let _ = classify(&asdu);
}
