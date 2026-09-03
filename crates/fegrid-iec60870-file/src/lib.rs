//! IEC 60870-5 file-transfer service layer (G-042).
//!
//! Re-exports the typed file-transfer state machines from
//! [`fegrid_iec60870_asdu::file_transfer`] and adds the
//! application-level traits that the CS 104 server / CS 101 slave use
//! to dispatch directory listings, file selection, and section
//! transfers:
//!
//! - [`FilesAvailable`] — list of files the server can serve.
//! - [`FileServer`] — the application-side server hook (read-only
//!   view of the underlying file table; the actual transfer state
//!   machine lives in the asdu crate).
//! - [`FileClient`] — the application-side client hook.
//! - [`FileError`] — the 9 error codes per IEC 60870-5 file transfer.
//!
//! The transport-level wiring (driving the asdu state machine over
//! the CS 104 server's plugin hook G-010 / G-034) lives in the
//! `fegrid-iec60870-tokio` crate's server module.

#![deny(missing_docs)]

pub use fegrid_iec60870_asdu::file_transfer::{
    FileReceiveSide, FileSendSide, FileTransferError, FileTransferResult, Idle, RDone, RIdle,
    Receiving, Selected,
};

/// File-transfer error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileError {
    /// No error.
    Ok = 0,
    /// Slave is waiting for the transfer to begin.
    WaitingForTransfer = 1,
    /// Requested file does not exist.
    NoFile = 2,
    /// Requested file exists but is not yet ready.
    FileNotReady = 3,
    /// Requested file is ready for transfer.
    FileReady = 4,
    /// Transfer timed out.
    Timeout = 5,
    /// Transfer was aborted.
    Aborted = 6,
    /// A file section was received.
    SectionReceived = 7,
    /// A file section was sent.
    SectionSent = 8,
    /// Unknown / unrecognized error.
    Unknown = 9,
}

/// Application-side file listing. The server implements this to tell
/// the master which files are available for download (F_DR_TA_1).
pub trait FilesAvailable: Send + Sync + 'static {
    /// Return the names of all files available to the requesting peer.
    /// May filter by CA / peer IP / role.
    fn list(&self) -> Vec<String>;
}

/// File-provider-server hook installed on the CS 104 server. Receives
/// section-fetch requests and hands back the bytes for the requested
/// (file_name, section) pair.
pub trait FileServer: Send + Sync + 'static {
    /// Return the bytes for a given file section. Returns
    /// `Ok(Some(bytes))` on success, `Ok(None)` when the section does
    /// not exist, or `Err(FileError)` for protocol-level failures.
    fn read_section(&self, file_name: &str, section: u32) -> FileTransferResult<Option<Vec<u8>>>;
}

/// Default [`FileServer`] backed by a `HashMap<String, Vec<Vec<u8>>>`
/// where each entry is a list of section bodies.
pub struct InMemoryFileServer {
    files: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<Vec<u8>>>>>,
}

impl Default for InMemoryFileServer {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryFileServer {
    /// Construct an empty in-memory file server.
    pub fn new() -> Self {
        Self {
            files: std::sync::Arc::new(std::sync::RwLock::new(Default::default())),
        }
    }
    /// Register a file with its sections.
    pub fn register(&self, file_name: &str, sections: Vec<Vec<u8>>) {
        self.files
            .write()
            .expect("poisoned")
            .insert(file_name.to_string(), sections);
    }
    /// Number of registered files.
    pub fn len(&self) -> usize {
        self.files.read().expect("poisoned").len()
    }
    /// True iff no files registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FilesAvailable for InMemoryFileServer {
    fn list(&self) -> Vec<String> {
        self.files
            .read()
            .expect("poisoned")
            .keys()
            .cloned()
            .collect()
    }
}

impl FileServer for InMemoryFileServer {
    fn read_section(&self, file_name: &str, section: u32) -> FileTransferResult<Option<Vec<u8>>> {
        let g = self.files.read().expect("poisoned");
        let Some(secs) = g.get(file_name) else {
            return Ok(None);
        };
        if section == 0 || (section as usize) > secs.len() {
            return Ok(None);
        }
        Ok(Some(secs[(section - 1) as usize].clone()))
    }
}

/// File-client hook installed on the CS 104 master side. Receives
/// section bytes as the master downloads a file.
pub trait FileClient: Send + Sync + 'static {
    /// Receive one section.
    fn on_section(&self, file_name: &str, section: u32, bytes: &[u8]);
}

/// Callback signature for [`FileClient::on_section`].
pub type SectionCb = Box<dyn Fn(&str, u32, &[u8]) + Send + Sync>;
/// Default [`FileClient`] that writes to a `Vec<u8>` callback.
pub struct InMemoryFileClient {
    on_section: SectionCb,
}

impl InMemoryFileClient {
    /// Construct from a callback.
    pub fn new<F: Fn(&str, u32, &[u8]) + Send + Sync + 'static>(cb: F) -> Self {
        Self {
            on_section: Box::new(cb),
        }
    }
}

impl FileClient for InMemoryFileClient {
    fn on_section(&self, file_name: &str, section: u32, bytes: &[u8]) {
        (self.on_section)(file_name, section, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_server_register_and_list() {
        let s = InMemoryFileServer::new();
        s.register("a.bin", vec![vec![1, 2], vec![3, 4]]);
        s.register("b.bin", vec![vec![5, 6]]);
        let names = s.list();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a.bin".to_string()));
        assert!(names.contains(&"b.bin".to_string()));
    }

    #[test]
    fn in_memory_server_read_section() {
        let s = InMemoryFileServer::new();
        s.register("x.bin", vec![vec![1, 2, 3], vec![4, 5, 6]]);
        let r = s.read_section("x.bin", 1).unwrap();
        assert_eq!(r, Some(vec![1, 2, 3]));
        let r = s.read_section("x.bin", 2).unwrap();
        assert_eq!(r, Some(vec![4, 5, 6]));
        let r = s.read_section("x.bin", 3).unwrap();
        assert_eq!(r, None);
    }

    #[test]
    fn in_memory_server_unknown_file_errors() {
        let s = InMemoryFileServer::new();
        let r = s.read_section("missing.bin", 1);
        assert!(matches!(r, Ok(None)));
    }

    #[test]
    fn file_error_codes_match_iec_values() {
        assert_eq!(FileError::Ok as u8, 0);
        assert_eq!(FileError::WaitingForTransfer as u8, 1);
        assert_eq!(FileError::NoFile as u8, 2);
        assert_eq!(FileError::FileNotReady as u8, 3);
        assert_eq!(FileError::FileReady as u8, 4);
        assert_eq!(FileError::Timeout as u8, 5);
        assert_eq!(FileError::Aborted as u8, 6);
        assert_eq!(FileError::SectionReceived as u8, 7);
        assert_eq!(FileError::SectionSent as u8, 8);
        assert_eq!(FileError::Unknown as u8, 9);
    }

    #[test]
    fn in_memory_client_receives_sections() {
        use std::sync::Mutex;
        let received = std::sync::Arc::new(Mutex::new(Vec::new()));
        let r2 = received.clone();
        let c = InMemoryFileClient::new(move |name, section, bytes| {
            r2.lock()
                .expect("poisoned")
                .push((name.to_string(), section, bytes.to_vec()));
        });
        c.on_section("a.bin", 1, &[1, 2, 3]);
        c.on_section("a.bin", 2, &[4, 5, 6]);
        let r = received.lock().expect("poisoned");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].1, 1);
        assert_eq!(r[1].2, vec![4, 5, 6]);
    }

    #[test]
    fn files_available_list_default_empty() {
        let s = InMemoryFileServer::new();
        assert!(s.is_empty());
        assert_eq!(s.list().len(), 0);
    }
}
