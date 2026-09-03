//! Integration tests for [`AsduError`] covering every variant's
//! `Display`, `Clone`, and `PartialEq` implementation.

use std::io;

use fegrid_iec60870_core::AsduError;

#[test]
fn buffer_too_short_display_and_eq() {
    let a = AsduError::BufferTooShort { need: 4, have: 2 };
    assert_eq!(a.to_string(), "buffer too short: need 4, have 2");
    let b = a.clone();
    assert_eq!(a, b);
    let c = AsduError::BufferTooShort { need: 4, have: 3 };
    assert_ne!(a, c);
}

#[test]
fn length_field_mismatch_display_and_eq() {
    let a = AsduError::LengthFieldMismatch {
        declared: 5,
        actual: 6,
    };
    assert_eq!(a.to_string(), "length field mismatch: declared 5, actual 6");
    let b = a.clone();
    assert_eq!(a, b);
    let c = AsduError::LengthFieldMismatch {
        declared: 7,
        actual: 6,
    };
    assert_ne!(a, c);
}

#[test]
fn invalid_type_id_display_and_eq() {
    let a = AsduError::InvalidTypeId(0xAB);
    assert_eq!(a.to_string(), "invalid type id: 0xab");
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, AsduError::InvalidTypeId(0xCD));
}

#[test]
fn invalid_cause_display_and_eq() {
    let a = AsduError::InvalidCause(0x1A);
    assert_eq!(a.to_string(), "invalid cause of transmission: 0x1a");
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, AsduError::InvalidCause(0x1B));
}

#[test]
fn invalid_control_field_display_and_eq() {
    let a = AsduError::InvalidControlField(0x55);
    assert_eq!(a.to_string(), "invalid control field: 0x55");
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, AsduError::InvalidControlField(0x66));
}

#[test]
fn invalid_checksum_display_and_eq() {
    let a = AsduError::InvalidChecksum {
        expected: 0x10,
        computed: 0x20,
    };
    assert_eq!(
        a.to_string(),
        "invalid checksum: expected 0x10, computed 0x20"
    );
    let b = a.clone();
    assert_eq!(a, b);
    let c = AsduError::InvalidChecksum {
        expected: 0x10,
        computed: 0x21,
    };
    assert_ne!(a, c);
}

#[test]
fn invalid_start_byte_display_and_eq() {
    let a = AsduError::InvalidStartByte(0x68);
    assert_eq!(a.to_string(), "invalid start byte: 0x68");
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, AsduError::InvalidStartByte(0x10));
}

#[test]
fn too_many_objects_display_and_eq() {
    let a = AsduError::TooManyObjects {
        declared: 100,
        max: 50,
    };
    assert_eq!(a.to_string(), "too many objects: declared 100, max 50");
    let b = a.clone();
    assert_eq!(a, b);
    let c = AsduError::TooManyObjects {
        declared: 101,
        max: 50,
    };
    assert_ne!(a, c);
}

#[test]
fn unsupported_by_profile_display_and_eq() {
    let a = AsduError::UnsupportedByProfile;
    assert_eq!(
        a.to_string(),
        "operation not supported by the configured profile"
    );
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn io_display_includes_inner_message() {
    let inner = io::Error::new(io::ErrorKind::ConnectionReset, "peer closed");
    let a: AsduError = inner.into();
    let s = a.to_string();
    assert!(s.contains("i/o error"), "{s}");
    assert!(s.contains("peer closed"), "{s}");
}

#[test]
fn io_clone_uses_sentinel_message() {
    let inner = io::Error::new(io::ErrorKind::ConnectionReset, "peer closed");
    let a: AsduError = inner.into();
    let b = a.clone();
    // std::io::Error doesn't implement PartialEq, so the impl's wildcard
    // branch returns false for any Io pair — that's the documented
    // limitation. The interesting behavior is that Clone rewrites the
    // payload to a sentinel message visible via Display.
    assert!(b.to_string().contains("io error cloned without payload"));
    assert!(a.to_string().contains("peer closed"));
}

#[test]
fn invalid_numeric_field_display_and_eq() {
    let a = AsduError::InvalidNumericField("too big".into());
    assert_eq!(a.to_string(), "invalid numeric field: too big");
    let b = a.clone();
    assert_eq!(a, b);
    let c = AsduError::InvalidNumericField("too small".into());
    assert_ne!(a, c);
}

#[test]
fn partial_eq_across_variants_is_false() {
    let a = AsduError::BufferTooShort { need: 1, have: 0 };
    assert_ne!(a, AsduError::UnsupportedByProfile);
    assert_ne!(a, AsduError::InvalidTypeId(0));
    // Same-name variants with distinct inner discriminants are not equal.
    assert_ne!(AsduError::InvalidTypeId(1), AsduError::InvalidCause(1));
}

#[test]
fn debug_is_nonempty() {
    let e = AsduError::UnsupportedByProfile;
    assert!(!format!("{e:?}").is_empty());
}
