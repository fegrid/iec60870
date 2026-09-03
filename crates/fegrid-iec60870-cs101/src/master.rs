//! CS 101 master (control direction) runtime.
//!
//! The CS 101 master drives FT 1.2 link-layer polling: it issues
//! [`PrimaryFunctionCode`] commands, watches for single-char ACK, and
//! consumes responses. Three modes are exposed:
//!
//! - balanced (G-036): strict request/response, expects each primary
//!   transfer to be confirmed by a secondary frame before the next.
//! - unbalanced (G-037): only broadcasts (no responses expected).
//! - multi-slave (G-038): a single physical line with multiple
//!   link-layer addresses; the master routes responses by address.

extern crate alloc;

use alloc::vec::Vec;

use fegrid_iec60870_asdu::Asdu;

use crate::function_codes::PrimaryFunctionCode;

/// CS 101 master mode (G-036 / G-037 / G-038).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cs101MasterMode {
    /// Balanced: each primary expects a secondary before the next.
    #[default]
    Balanced,
    /// Unbalanced: broadcast only.
    Unbalanced,
    /// Multi-slave: balanced with per-address routing.
    MultiSlave,
}

/// CS 101 master configuration.
#[derive(Debug, Clone)]
pub struct Cs101MasterConfig {
    /// Link layer address length (1 or 2 octets).
    pub address_len: AddressLen,
    /// Common address used for broadcasts.
    pub common_address: u16,
    /// Master mode.
    pub mode: Cs101MasterMode,
    /// Per-slave link addresses for [`Cs101MasterMode::MultiSlave`].
    pub slaves: Vec<u16>,
}

/// Common-address length for the FT 1.2 link layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressLen {
    /// 1 octet.
    #[default]
    One,
    /// 2 octets.
    Two,
}

impl Cs101MasterConfig {
    /// Construct a balanced master with default link address.
    pub fn balanced() -> Self {
        Self {
            address_len: AddressLen::One,
            common_address: 1,
            mode: Cs101MasterMode::Balanced,
            slaves: Vec::new(),
        }
    }
    /// Construct an unbalanced broadcast master.
    pub fn unbalanced() -> Self {
        Self {
            address_len: AddressLen::One,
            common_address: 0xFFFF,
            mode: Cs101MasterMode::Unbalanced,
            slaves: Vec::new(),
        }
    }
    /// Construct a multi-slave master with the given slave addresses.
    pub fn multi_slave(slaves: Vec<u16>) -> Self {
        Self {
            address_len: AddressLen::One,
            common_address: 0xFFFF,
            mode: Cs101MasterMode::MultiSlave,
            slaves,
        }
    }
}

/// Outbound primary-function command (G-039).
#[derive(Debug, Clone)]
pub struct Cs101Command {
    /// Primary function code.
    pub function: PrimaryFunctionCode,
    /// Link address to send to (broadcast = 0xFFFF).
    pub link_address: u16,
    /// ASDU payload (None for link-management commands that have no ASDU).
    pub asdu: Option<Asdu>,
}

/// CS 101 master runtime. Owns no I/O — the caller drives it via
/// [`Cs101Master::next_request`] (output) + [`Cs101Master::on_response`]
/// (input). This keeps the runtime transport-agnostic and trivial to
/// unit-test.
#[derive(Debug)]
pub struct Cs101Master {
    cfg: Cs101MasterConfig,
    fcb: bool,
    outstanding: Option<Cs101Command>,
}

impl Cs101Master {
    /// Construct a new master with the given config.
    pub fn new(cfg: Cs101MasterConfig) -> Self {
        Self {
            cfg,
            fcb: false,
            outstanding: None,
        }
    }
    /// Borrow the configuration.
    pub fn config(&self) -> &Cs101MasterConfig {
        &self.cfg
    }
    /// Current frame-count bit.
    pub fn fcb(&self) -> bool {
        self.fcb
    }
    /// Flip the FCB and return the next primary command for the wire.
    /// Returns `None` when no command is needed.
    pub fn next_request(&mut self, cmd: Cs101Command) -> Cs101Command {
        self.outstanding = Some(cmd.clone());
        self.fcb = !self.fcb;
        cmd
    }
    /// Feed a response ASDU from the slave. The caller passes the link
    /// address + the ASDU; the master validates that the response
    /// belongs to the outstanding request. Returns `true` when the
    /// pending command has been acknowledged.
    pub fn on_response(&mut self, link_address: u16, _asdu: Option<Asdu>) -> bool {
        if let Some(pending) = &self.outstanding
            && pending.link_address == link_address
        {
            self.outstanding = None;
            return true;
        }
        false
    }
    /// Whether a primary request is still outstanding.
    pub fn has_outstanding(&self) -> bool {
        self.outstanding.is_some()
    }
    /// Reset the master: clear FCB + outstanding state.
    pub fn reset_cu(&mut self) {
        self.fcb = false;
        self.outstanding = None;
    }
}

/// Command encoders (G-039, G-040, G-041).
pub mod cmds {
    use super::*;
    use fegrid_iec60870_core::QualifierOfInterrogation;

    /// Build a general-interrogation command (G-039).
    pub fn general_interrogation(link_address: u16, qoi: QualifierOfInterrogation) -> Cs101Command {
        use fegrid_iec60870_asdu::{InformationObject, InformationValue};
        use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
        let asdu = Asdu {
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
            objects: alloc::vec![InformationObject::new(
                0,
                InformationValue::interrogation_command(qoi),
            )],
        };
        Cs101Command {
            function: PrimaryFunctionCode::UserDataConfirmed,
            link_address,
            asdu: Some(asdu),
        }
    }

    /// Build a read command (G-040).
    pub fn read(link_address: u16) -> Cs101Command {
        use fegrid_iec60870_asdu::{InformationObject, InformationValue};
        use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
        let asdu = Asdu {
            type_id: TypeId::C_RD_NA_1,
            original_type_byte: TypeId::C_RD_NA_1 as u8,
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
            objects: alloc::vec![InformationObject::new(0, InformationValue::ReadCommand)],
        };
        Cs101Command {
            function: PrimaryFunctionCode::UserDataConfirmed,
            link_address,
            asdu: Some(asdu),
        }
    }

    /// Build a clock-sync command (G-041).
    pub fn clock_sync(link_address: u16, time: fegrid_iec60870_core::Cp56Time2a) -> Cs101Command {
        use fegrid_iec60870_asdu::{InformationObject, InformationValue};
        use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};
        let asdu = Asdu {
            type_id: TypeId::C_CS_NA_1,
            original_type_byte: TypeId::C_CS_NA_1 as u8,
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
            objects: alloc::vec![InformationObject::new(
                0,
                InformationValue::ClockSyncCommand(time),
            )],
        };
        Cs101Command {
            function: PrimaryFunctionCode::UserDataConfirmed,
            link_address,
            asdu: Some(asdu),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fegrid_iec60870_core::QualifierOfInterrogation;

    #[test]
    fn balanced_default() {
        let m = Cs101Master::new(Cs101MasterConfig::balanced());
        assert_eq!(m.config().mode, Cs101MasterMode::Balanced);
    }

    #[test]
    fn unbalanced_broadcast() {
        let m = Cs101Master::new(Cs101MasterConfig::unbalanced());
        assert_eq!(m.config().common_address, 0xFFFF);
        assert_eq!(m.config().mode, Cs101MasterMode::Unbalanced);
    }

    #[test]
    fn multi_slave_lists_addresses() {
        let m = Cs101Master::new(Cs101MasterConfig::multi_slave(alloc::vec![1, 2, 3]));
        assert_eq!(m.config().slaves, alloc::vec![1, 2, 3]);
        assert_eq!(m.config().mode, Cs101MasterMode::MultiSlave);
    }

    #[test]
    fn fcb_flips_on_each_request() {
        let mut m = Cs101Master::new(Cs101MasterConfig::balanced());
        let cmd = cmds::read(1);
        let _ = m.next_request(cmd.clone());
        assert!(m.fcb());
        let _ = m.next_request(cmd);
        assert!(!m.fcb());
    }

    #[test]
    fn outstanding_cleared_on_response() {
        let mut m = Cs101Master::new(Cs101MasterConfig::balanced());
        let cmd = cmds::read(1);
        let _ = m.next_request(cmd);
        assert!(m.has_outstanding());
        assert!(m.on_response(1, None));
        assert!(!m.has_outstanding());
    }

    #[test]
    fn wrong_link_does_not_clear() {
        let mut m = Cs101Master::new(Cs101MasterConfig::multi_slave(alloc::vec![1, 2]));
        let _ = m.next_request(cmds::read(1));
        assert!(!m.on_response(2, None));
        assert!(m.has_outstanding());
    }

    #[test]
    fn reset_cu_clears_state() {
        let mut m = Cs101Master::new(Cs101MasterConfig::balanced());
        let _ = m.next_request(cmds::read(1));
        m.reset_cu();
        assert!(!m.has_outstanding());
        assert!(!m.fcb());
    }

    #[test]
    fn general_interrogation_command_builds() {
        let cmd = cmds::general_interrogation(1, QualifierOfInterrogation::STATION);
        assert!(cmd.asdu.is_some());
    }
}
