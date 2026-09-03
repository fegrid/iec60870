//! File-transfer integration test (E9).
//!
//! 1 MiB worth of sections registered with InMemoryFileServer; verifies
//! listing and section fetch round-trip.
use fegrid_iec60870_file::{FileServer, FilesAvailable, InMemoryFileServer};

#[test]
fn one_mib_via_1024_sections() {
    let server = InMemoryFileServer::new();
    const SECTIONS: usize = 1024;
    const SECTION_SIZE: usize = 1024; // 1 MiB total
    let mut all = Vec::with_capacity(SECTIONS);
    for i in 0..SECTIONS {
        let mut buf = vec![0u8; SECTION_SIZE];
        buf[0] = (i & 0xFF) as u8;
        all.push(buf);
    }
    server.register("big.bin", all);

    // Listing works.
    let list = server.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0], "big.bin");

    // Every section reads back the right prefix.
    for i in 1..=SECTIONS {
        let bytes = server.read_section("big.bin", i as u32).unwrap().unwrap();
        assert_eq!(bytes.len(), SECTION_SIZE);
        assert_eq!(bytes[0], ((i - 1) & 0xFF) as u8);
    }

    // Out-of-range section returns Ok(None).
    assert!(
        server
            .read_section("big.bin", (SECTIONS + 1) as u32)
            .unwrap()
            .is_none()
    );
    // Missing file returns Ok(None).
    assert!(server.read_section("missing.bin", 1).unwrap().is_none());
}

#[test]
fn empty_server_listing() {
    let server = InMemoryFileServer::new();
    assert!(server.is_empty());
    assert!(server.list().is_empty());
}

#[test]
fn multi_file_listing() {
    let server = InMemoryFileServer::new();
    for name in &["a.bin", "b.bin", "c.bin"] {
        server.register(name, vec![vec![1, 2, 3]]);
    }
    assert_eq!(server.len(), 3);
    let list = server.list();
    assert!(list.contains(&"a.bin".to_string()));
    assert!(list.contains(&"b.bin".to_string()));
    assert!(list.contains(&"c.bin".to_string()));
}
