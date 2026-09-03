//! Coverage tests for qualifier.rs.

use fegrid_iec60870_core::{
    QualifierOfCIC, QualifierOfCommand, QualifierOfInterrogation, QualifierOfParameterActivation,
    QualifierOfParameterMV, QualifierOfRPC,
};

#[test]
fn qualifier_of_interrogation_full_coverage() {
    assert_eq!(QualifierOfInterrogation::STATION.raw(), 20);
    assert_eq!(
        QualifierOfInterrogation::STATION,
        QualifierOfInterrogation::group(20)
    );
    assert_eq!(
        QualifierOfInterrogation::from_byte(25),
        QualifierOfInterrogation::group(25)
    );
    assert_eq!(
        QualifierOfInterrogation::default(),
        QualifierOfInterrogation::STATION
    );
    assert_eq!(format!("{}", QualifierOfInterrogation::STATION), "station");
    assert_eq!(format!("{}", QualifierOfInterrogation::group(25)), "group5");
    assert!(format!("{}", QualifierOfInterrogation::from_byte(99)).starts_with("vendor("));
    assert_eq!(QualifierOfInterrogation::from_byte(99).raw(), 99);
    assert_eq!(
        format!("{}", QualifierOfInterrogation::group(36)),
        "group16"
    );
}

#[test]
fn qualifier_of_cic_full_coverage() {
    assert_eq!(QualifierOfCIC::GROUP_1_READ.raw(), 0x05);
    assert_eq!(QualifierOfCIC::GROUP_1_FREEZE_READ.raw(), 0x45);
    assert_eq!(QualifierOfCIC::GROUP_2_FREEZE_READ.raw(), 0x46);
    assert_eq!(QualifierOfCIC::GROUP_3_FREEZE_READ.raw(), 0x47);
    assert_eq!(QualifierOfCIC::GROUP_4_FREEZE_READ.raw(), 0x48);
    assert_eq!(QualifierOfCIC::GENERAL_FREEZE_READ.raw(), 0x49);
    assert_eq!(
        QualifierOfCIC::from_byte(0x05),
        QualifierOfCIC::GROUP_1_READ
    );
    assert_eq!(QualifierOfCIC::GROUP_3_FREEZE_READ.raw(), 0x47);
    assert!(!format!("{}", QualifierOfCIC::GROUP_1_READ).is_empty());
    assert!(format!("{}", QualifierOfCIC::from_byte(99)).starts_with("vendor("));
}

#[test]
fn qualifier_of_rpc_full_coverage() {
    assert_eq!(QualifierOfRPC::GENERAL_RESET.raw(), 1);
    assert_eq!(QualifierOfRPC::RESET_EVENT_BUFFERS.raw(), 2);
    assert_eq!(QualifierOfRPC::default(), QualifierOfRPC::GENERAL_RESET);
    assert_eq!(QualifierOfRPC::from_byte(1), QualifierOfRPC::GENERAL_RESET);
    assert_eq!(QualifierOfRPC::from_byte(99).raw(), 99);
}

#[test]
fn qualifier_of_command_full_coverage() {
    let q = QualifierOfCommand::new(true, 7);
    assert!(q.is_select());
    assert_eq!(q.qualifier(), 7);
    assert_eq!(q.0, 0x20 | 7);

    let q = QualifierOfCommand::new(false, 0);
    assert!(!q.is_select());
    assert_eq!(q.qualifier(), 0);

    let q = QualifierOfCommand::from_byte(0xFF);
    assert!(q.is_select());
    assert_eq!(q.qualifier(), 31);

    assert_eq!(QualifierOfCommand::default(), QualifierOfCommand(0));
    assert_eq!(QualifierOfCommand::new(true, 31).0, 0x3F);
}

#[test]
fn qualifier_of_parameter_mv_full_coverage() {
    assert_eq!(QualifierOfParameterMV::THRESHOLD.raw(), 1);
    assert_eq!(QualifierOfParameterMV::SMOOTHING.raw(), 2);
    assert_eq!(QualifierOfParameterMV::LOW_LIMIT.raw(), 3);
    assert_eq!(QualifierOfParameterMV::HIGH_LIMIT.raw(), 4);
    assert_eq!(
        QualifierOfParameterMV::default(),
        QualifierOfParameterMV::THRESHOLD
    );
    assert_eq!(QualifierOfParameterMV::from_byte(99).raw(), 99);
}

#[test]
fn qualifier_of_parameter_activation_full_coverage() {
    assert_eq!(QualifierOfParameterActivation::ACTIVATE.raw(), 1);
    assert_eq!(QualifierOfParameterActivation::DEACTIVATE.raw(), 2);
    assert_eq!(
        QualifierOfParameterActivation::default(),
        QualifierOfParameterActivation::ACTIVATE
    );
    assert_eq!(QualifierOfParameterActivation::from_byte(99).raw(), 99);
}
