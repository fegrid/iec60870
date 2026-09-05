//! File-transfer protocol state machines (IEC 60870-5 §7.3.1.120-126).
//!
//! Two pure typestate engines:
//! - [`FileSendSide`]: the party that pulls a file (typically the
//!   controlling/master). Walks `Idle -> WaitingFileReady -> Receiving
//!   -> Done` and emits a sequence of `FileCall` (F_SC_NA_1) plus a
//!   final `FileAck` (F_AF_NA_1) acknowledgment.
//! - [`FileReceiveSide`]: the party that owns the file (typically the
//!   controlled/slave). Walks `Idle -> Selected -> Done` and emits a
//!   `FileReady` (F_FR_NA_1) followed by per-section `SectionReady` /
//!   `FileLastSection` (F_SR_NA_1 / F_LS_NA_1) replies.
//!
//! Every transition returns `(Self<NewState>, Asdu)`. The transport is
//! responsible for wiring the `Asdu` onto the wire; the engines never
//! touch I/O. Errors are plain data and feed the `Display`/`Error`
//! impls on [`FileTransferError`].
//!
//! All emitted ASDUs use `cot.cause = CauseOfTransmission::FileTransfer`
//! and a single information object with `ioa = 0` (the IEC convention:
//! identity rides in the file-name field, not the IOA).

extern crate alloc;

use alloc::fmt;

use fegrid_iec60870_core::{CauseOfTransmission, CommonAddress, CotField, TypeId};

use crate::asdu::Asdu;
use crate::object::InformationObject;
use crate::values::InformationValue;

/// Errors surfaced by the file-transfer engines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTransferError {
    /// Inbound `Asdu` carried the wrong type id.
    UnexpectedType {
        /// Type id the receiver was waiting for.
        expected: u8,
        /// Type id the inbound `Asdu` actually had.
        got: u8,
    },
    /// Inbound `Asdu` carried the wrong file name.
    WrongFile {
        /// File name the receiver was operating on.
        expected: u16,
        /// File name the inbound `Asdu` actually carried.
        got: u16,
    },
    /// Inbound `Asdu` carried the wrong section index.
    WrongSection {
        /// Section index the receiver was waiting for.
        expected: u16,
        /// Section index the inbound `Asdu` actually carried.
        got: u16,
    },
    /// Inbound `Asdu` carried no information objects.
    NoObjects,
    /// Protocol-level mismatch described by a static string.
    Protocol(&'static str),
}

impl fmt::Display for FileTransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedType { expected, got } => {
                write!(f, "unexpected type id {got} (wanted {expected})")
            }
            Self::WrongFile { expected, got } => {
                write!(f, "wrong file {got} (wanted {expected})")
            }
            Self::WrongSection { expected, got } => {
                write!(f, "wrong section {got} (wanted {expected})")
            }
            Self::NoObjects => f.write_str("inbound ASDU carried no information objects"),
            Self::Protocol(s) => f.write_str(s),
        }
    }
}
impl core::error::Error for FileTransferError {}

/// Convenience result alias for the file-transfer engines.
pub type FileTransferResult<T> = Result<T, FileTransferError>;

/// Build a single-object file-transfer `Asdu`.
fn file_asdu(common_address: CommonAddress, value: InformationValue) -> Asdu {
    Asdu {
        type_id: TypeId::from_wire(value.type_byte()),
        original_type_byte: value.type_byte(),
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address,
        is_sequence: false,
        is_test: false,
        objects: alloc::vec![InformationObject::new(0, value)],
    }
}

// ---- Send side: pulls a file from the receiver. ----

/// Marker: send-side not yet started.
#[derive(Debug, Default, Clone, Copy)]
pub struct Idle;
/// Marker: send-side waiting for `FileReady` after issuing the select call.
#[derive(Debug, Default, Clone, Copy)]
pub struct WaitingFileReady;
/// Marker: send-side collecting sections.
#[derive(Debug, Default, Clone, Copy)]
pub struct Receiving;
/// Marker: send-side completed the transfer.
#[derive(Debug, Default, Clone, Copy)]
pub struct Done;

/// Send-side machine state.
///
/// Generic `S` is one of [`Idle`], [`WaitingFileReady`], [`Receiving`],
/// [`Done`]. Each transition consumes `self` and returns the new
/// state alongside the outbound [`Asdu`] to ship.
#[derive(Debug, Clone)]
pub struct FileSendSide<S> {
    /// File name (NOF) being transferred.
    pub name: u16,
    /// Section index expected next.
    pub section: u16,
    /// Phantom state marker.
    pub(crate) _state: core::marker::PhantomData<S>,
}

impl FileSendSide<Idle> {
    /// Begin a transfer against `file_name` and `common_address`. The
    /// returned `Asdu` is `FileCall { name, section: 0, scq: 0x01 }`
    /// (select file) — wire type F_SC_NA_1.
    pub fn call_file(
        file_name: u16,
        common_address: CommonAddress,
    ) -> (FileSendSide<WaitingFileReady>, Asdu) {
        let outbound = file_asdu(
            common_address,
            InformationValue::FileCall {
                name: file_name,
                section: 0,
                scq: 0x01,
            },
        );
        (
            FileSendSide::<WaitingFileReady> {
                name: file_name,
                section: 1,
                _state: core::marker::PhantomData,
            },
            outbound,
        )
    }
}

impl FileSendSide<WaitingFileReady> {
    /// Validate an inbound `FileReady` and emit `FileCall` for section 1.
    pub fn on_file_ready(
        self,
        inbound: &Asdu,
    ) -> FileTransferResult<(FileSendSide<Receiving>, Asdu)> {
        let expected_type = 120u8;
        if inbound.original_type_byte != expected_type {
            return Err(FileTransferError::UnexpectedType {
                expected: expected_type,
                got: inbound.original_type_byte,
            });
        }
        let obj = inbound
            .objects
            .first()
            .ok_or(FileTransferError::NoObjects)?;
        let value = match &obj.value {
            InformationValue::FileReady {
                name,
                length: _,
                frq: _,
            } => *name,
            _ => {
                return Err(FileTransferError::UnexpectedType {
                    expected: expected_type,
                    got: inbound.original_type_byte,
                });
            }
        };
        if value != self.name {
            return Err(FileTransferError::WrongFile {
                expected: self.name,
                got: value,
            });
        }
        let outbound = file_asdu(
            inbound.common_address,
            InformationValue::FileCall {
                name: self.name,
                section: self.section as u8,
                scq: 0x02,
            },
        );
        Ok((
            FileSendSide::<Receiving> {
                name: self.name,
                section: self.section,
                _state: core::marker::PhantomData,
            },
            outbound,
        ))
    }
}

impl FileSendSide<Receiving> {
    /// Validate an inbound `SectionReady` and emit the next `FileCall`.
    pub fn on_section_ready(
        self,
        inbound: &Asdu,
    ) -> FileTransferResult<(FileSendSide<Receiving>, Asdu)> {
        let expected_type = 121u8;
        if inbound.original_type_byte != expected_type {
            return Err(FileTransferError::UnexpectedType {
                expected: expected_type,
                got: inbound.original_type_byte,
            });
        }
        let obj = inbound
            .objects
            .first()
            .ok_or(FileTransferError::NoObjects)?;
        let (name, section, _length) = match &obj.value {
            InformationValue::SectionReady {
                name,
                section,
                length,
                srq: _,
            } => (*name, *section, *length),
            _ => {
                return Err(FileTransferError::UnexpectedType {
                    expected: expected_type,
                    got: inbound.original_type_byte,
                });
            }
        };
        if name != self.name {
            return Err(FileTransferError::WrongFile {
                expected: self.name,
                got: name,
            });
        }
        if u16::from(section) != self.section {
            return Err(FileTransferError::WrongSection {
                expected: self.section,
                got: u16::from(section),
            });
        }
        let outbound = file_asdu(
            inbound.common_address,
            InformationValue::FileCall {
                name: self.name,
                section: self.section as u8,
                scq: 0x02,
            },
        );
        Ok((
            FileSendSide {
                name: self.name,
                section: self.section + 1,
                _state: core::marker::PhantomData,
            },
            outbound,
        ))
    }

    /// Validate an inbound `FileLastSection` and emit the final `FileAck`.
    pub fn on_last_section(self, inbound: &Asdu) -> FileTransferResult<(FileSendSide<Done>, Asdu)> {
        let expected_type = 123u8;
        if inbound.original_type_byte != expected_type {
            return Err(FileTransferError::UnexpectedType {
                expected: expected_type,
                got: inbound.original_type_byte,
            });
        }
        let obj = inbound
            .objects
            .first()
            .ok_or(FileTransferError::NoObjects)?;
        let (name, section, _checksum) = match &obj.value {
            InformationValue::FileLastSection {
                name,
                section,
                lsq: _,
                checksum,
            } => (*name, *section, *checksum),
            _ => {
                return Err(FileTransferError::UnexpectedType {
                    expected: expected_type,
                    got: inbound.original_type_byte,
                });
            }
        };
        if name != self.name {
            return Err(FileTransferError::WrongFile {
                expected: self.name,
                got: name,
            });
        }
        if section as u16 != self.section {
            return Err(FileTransferError::WrongSection {
                expected: self.section,
                got: section as u16,
            });
        }
        let outbound = file_asdu(
            inbound.common_address,
            InformationValue::FileAck {
                name: self.name,
                section: self.section as u8,
                afq: 0x01,
            },
        );
        Ok((
            FileSendSide {
                name: self.name,
                section: self.section,
                _state: core::marker::PhantomData,
            },
            outbound,
        ))
    }
}

// ---- Receive side: owns the file, replies to the sender. ----

/// Marker: receiver not yet selected.
#[derive(Debug, Default, Clone, Copy)]
pub struct RIdle;
/// Marker: receiver has selected a file; ready to serve sections.
#[derive(Debug, Default, Clone, Copy)]
pub struct Selected;
/// Marker: receiver completed.
#[derive(Debug, Default, Clone, Copy)]
pub struct RDone;

/// Receive-side machine state. Generic `S` is one of [`RIdle`],
/// [`Selected`], [`RDone`].
#[derive(Debug, Clone)]
pub struct FileReceiveSide<S> {
    /// File name (NOF) the receiver selected.
    pub name: u16,
    /// Section index the receiver is serving next.
    pub section: u16,
    /// Phantom state marker.
    pub(crate) _state: core::marker::PhantomData<S>,
}

impl FileReceiveSide<RIdle> {
    /// Start a receive session for `file_name`. The returned `Asdu` is
    /// `FileReady { name, length, frq: 0 }` — wire type F_FR_NA_1.
    pub fn on_call(
        file_name: u16,
        file_length: u32,
        inbound: &Asdu,
    ) -> FileTransferResult<(FileReceiveSide<Selected>, Asdu)> {
        let expected_type = 122u8;
        if inbound.original_type_byte != expected_type {
            return Err(FileTransferError::UnexpectedType {
                expected: expected_type,
                got: inbound.original_type_byte,
            });
        }
        let obj = inbound
            .objects
            .first()
            .ok_or(FileTransferError::NoObjects)?;
        let (name, _section, scq) = match &obj.value {
            InformationValue::FileCall { name, section, scq } => (*name, *section, *scq),
            _ => {
                return Err(FileTransferError::UnexpectedType {
                    expected: expected_type,
                    got: inbound.original_type_byte,
                });
            }
        };
        if name != file_name {
            return Err(FileTransferError::WrongFile {
                expected: file_name,
                got: name,
            });
        }
        if scq != 0x01 {
            return Err(FileTransferError::Protocol(
                "first FileCall expected select (scq=0x01)",
            ));
        }
        let outbound = file_asdu(
            inbound.common_address,
            InformationValue::FileReady {
                name: file_name,
                length: file_length,
                frq: 0,
            },
        );
        Ok((
            FileReceiveSide {
                name: file_name,
                section: 1,
                _state: core::marker::PhantomData,
            },
            outbound,
        ))
    }
}

impl FileReceiveSide<Selected> {
    /// Serve the next section. `last_section = true` emits the final
    /// `FileLastSection` (F_LS_NA_1); otherwise `SectionReady`
    /// (F_SR_NA_1) is returned.
    pub fn on_section_call(
        self,
        inbound: &Asdu,
        section_data_length: u32,
        last_section: bool,
    ) -> FileTransferResult<(FileReceiveSide<Selected>, Asdu)> {
        let expected_type = 122u8;
        if inbound.original_type_byte != expected_type {
            return Err(FileTransferError::UnexpectedType {
                expected: expected_type,
                got: inbound.original_type_byte,
            });
        }
        let obj = inbound
            .objects
            .first()
            .ok_or(FileTransferError::NoObjects)?;
        let (name, section, scq) = match &obj.value {
            InformationValue::FileCall { name, section, scq } => (*name, *section, *scq),
            _ => {
                return Err(FileTransferError::UnexpectedType {
                    expected: expected_type,
                    got: inbound.original_type_byte,
                });
            }
        };
        if name != self.name {
            return Err(FileTransferError::WrongFile {
                expected: self.name,
                got: name,
            });
        }
        if section as u16 != self.section {
            return Err(FileTransferError::WrongSection {
                expected: self.section,
                got: section as u16,
            });
        }
        if scq != 0x02 {
            return Err(FileTransferError::Protocol(
                "FileCall expected call-section (scq=0x02)",
            ));
        }
        let outbound = if last_section {
            file_asdu(
                inbound.common_address,
                InformationValue::FileLastSection {
                    name: self.name,
                    section: self.section as u8,
                    lsq: 0x01,
                    checksum: 0,
                },
            )
        } else {
            file_asdu(
                inbound.common_address,
                InformationValue::SectionReady {
                    name: self.name,
                    section: self.section as u8,
                    length: section_data_length,
                    srq: 0x01,
                },
            )
        };
        let next_section = self.section + 1;
        Ok((
            FileReceiveSide {
                name: self.name,
                section: next_section,
                _state: core::marker::PhantomData,
            },
            outbound,
        ))
    }

    /// Acknowledge the receiver's `FileLastSection` and transition to Done.
    pub fn on_ack(self, inbound: &Asdu) -> FileTransferResult<FileReceiveSide<RDone>> {
        let expected_type = 124u8;
        if inbound.original_type_byte != expected_type {
            return Err(FileTransferError::UnexpectedType {
                expected: expected_type,
                got: inbound.original_type_byte,
            });
        }
        let obj = inbound
            .objects
            .first()
            .ok_or(FileTransferError::NoObjects)?;
        let (name, _section, _afq) = match &obj.value {
            InformationValue::FileAck { name, section, afq } => (*name, *section, *afq),
            _ => {
                return Err(FileTransferError::UnexpectedType {
                    expected: expected_type,
                    got: inbound.original_type_byte,
                });
            }
        };
        if name != self.name {
            return Err(FileTransferError::WrongFile {
                expected: self.name,
                got: name,
            });
        }
        Ok(FileReceiveSide {
            name: self.name,
            section: self.section,
            _state: core::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values::InformationValue;

    fn make_call(name: u16, section: u8, scq: u8) -> Asdu {
        file_asdu(
            CommonAddress(1),
            InformationValue::FileCall { name, section, scq },
        )
    }

    fn make_ready(name: u16, length: u32) -> Asdu {
        file_asdu(
            CommonAddress(1),
            InformationValue::FileReady {
                name,
                length,
                frq: 0,
            },
        )
    }

    fn make_section(name: u16, section: u8, length: u32, srq: u8) -> Asdu {
        file_asdu(
            CommonAddress(1),
            InformationValue::SectionReady {
                name,
                section,
                length,
                srq,
            },
        )
    }
    fn make_last_section(name: u16, section: u8, checksum: u8) -> Asdu {
        file_asdu(
            CommonAddress(1),
            InformationValue::FileLastSection {
                name,
                section,
                lsq: 0x01,
                checksum,
            },
        )
    }

    fn make_ack(name: u16, section: u8, afq: u8) -> Asdu {
        file_asdu(
            CommonAddress(1),
            InformationValue::FileAck { name, section, afq },
        )
    }

    #[test]
    fn send_side_happy_path_emits_expected_sequence() {
        let (send, out0) = FileSendSide::call_file(7, CommonAddress(1));
        assert_eq!(out0.original_type_byte, 122);

        let inbound_ready = make_ready(7, 0x1234);
        let (send, out1) = send.on_file_ready(&inbound_ready).expect("file_ready");
        assert_eq!(out1.original_type_byte, 122);

        let inbound_section1 = make_section(7, 1, 0xa1, 0x01);
        let (send, out2) = send.on_section_ready(&inbound_section1).expect("section1");
        assert_eq!(out2.original_type_byte, 122);

        let inbound_section2 = make_section(7, 2, 0xa2, 0x01);
        let (send, out3) = send.on_section_ready(&inbound_section2).expect("section2");
        assert_eq!(out3.original_type_byte, 122);

        let inbound_last = make_last_section(7, 3, 0xa3);
        let (_send, out4) = send.on_last_section(&inbound_last).expect("last");
        assert_eq!(out4.original_type_byte, 124);

        let sequence = [out0, out1, out2, out3, out4]
            .iter()
            .map(|a| a.original_type_byte)
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(sequence, alloc::vec![122, 122, 122, 122, 124]);
    }

    #[test]
    fn receive_side_happy_path_emits_expected_sequence() {
        let call_select = make_call(7, 0, 0x01);
        let (recv, out0) = FileReceiveSide::on_call(7, 0x1234u32, &call_select).expect("on_call");
        assert_eq!(out0.original_type_byte, 120);

        let call_section1 = make_call(7, 1, 0x02);
        let (recv, out1) = recv
            .on_section_call(&call_section1, 0x100, false)
            .expect("section1");
        assert_eq!(out1.original_type_byte, 121);

        let call_section2 = make_call(7, 2, 0x02);
        let (recv, out2) = recv
            .on_section_call(&call_section2, 0x80, false)
            .expect("section2");
        assert_eq!(out2.original_type_byte, 121);

        let call_last_section = make_call(7, 3, 0x02);
        let (recv, out3) = recv
            .on_section_call(&call_last_section, 0x40, true)
            .expect("last_section");
        assert_eq!(out3.original_type_byte, 123);

        let ack = make_ack(7, 3, 0x01);
        let _recv = recv.on_ack(&ack).expect("ack");

        let sequence = [out0, out1, out2, out3]
            .iter()
            .map(|a| a.original_type_byte)
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(sequence, alloc::vec![120, 121, 121, 123]);
    }

    #[test]
    fn send_side_rejects_wrong_type_at_file_ready() {
        let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
        let bogus = make_ack(7, 0, 0x01);
        match send.on_file_ready(&bogus) {
            Err(FileTransferError::UnexpectedType { expected, got }) => {
                assert_eq!(expected, 120);
                assert_eq!(got, 124);
            }
            other => panic!("expected UnexpectedType, got {other:?}"),
        }
    }

    #[test]
    fn send_side_rejects_wrong_file_at_file_ready() {
        let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
        let inbound = make_ready(8, 0x100);
        match send.on_file_ready(&inbound) {
            Err(FileTransferError::WrongFile { expected, got }) => {
                assert_eq!(expected, 7);
                assert_eq!(got, 8);
            }
            other => panic!("expected WrongFile, got {other:?}"),
        }
    }

    #[test]
    fn send_side_rejects_wrong_section_at_section_ready() {
        let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
        let inbound_ready = make_ready(7, 0x100);
        let (send, _) = send.on_file_ready(&inbound_ready).expect("file_ready");
        // Expects section=1; deliver section=2.
        let inbound = make_section(7, 2, 0xa1, 0x01);
        match send.on_section_ready(&inbound) {
            Err(FileTransferError::WrongSection { expected, got }) => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected WrongSection, got {other:?}"),
        }
    }

    #[test]
    fn receive_side_rejects_non_select_first_call() {
        let bad_select = make_call(7, 0, 0x02); // scq=0x02 not 0x01
        match FileReceiveSide::on_call(7, 0x100u32, &bad_select) {
            Err(FileTransferError::Protocol(_)) => {}
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }
}
