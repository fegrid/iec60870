//! Integration tests for the quality-descriptor bitflags.

use fegrid_iec60870_core::{BinaryCounterQuality, QualityDescriptor, QualityDescriptorP};

#[test]
fn quality_descriptor_individual_bits() {
    let q = QualityDescriptor::SPI;
    assert_eq!(q.bits(), 0x01);
    let q = QualityDescriptor::RESERVED_OR_DPI;
    assert_eq!(q.bits(), 0x02);
    let q = QualityDescriptor::SUBSTITUTED;
    assert_eq!(q.bits(), 0x20);
    let q = QualityDescriptor::NON_TOPICAL;
    assert_eq!(q.bits(), 0x40);
    let q = QualityDescriptor::INVALID;
    assert_eq!(q.bits(), 0x80);
}

#[test]
fn quality_descriptor_combine() {
    let q = QualityDescriptor::SPI | QualityDescriptor::INVALID;
    assert_eq!(q.bits(), 0x81);
    assert!(q.contains(QualityDescriptor::SPI));
    assert!(q.contains(QualityDescriptor::INVALID));
}

#[test]
fn quality_descriptor_p_bits() {
    let q = QualityDescriptorP::OVERFLOW;
    assert_eq!(q.bits(), 0x01);
    let q = QualityDescriptorP::ELAPSED_TIME_INVALID;
    assert_eq!(q.bits(), 0x08);
    let q = QualityDescriptorP::SUBSTITUTED;
    assert_eq!(q.bits(), 0x20);
    let q = QualityDescriptorP::NON_TOPICAL;
    assert_eq!(q.bits(), 0x40);
    let q = QualityDescriptorP::INVALID;
    assert_eq!(q.bits(), 0x80);
}

#[test]
fn binary_counter_quality_bits() {
    assert_eq!(BinaryCounterQuality::CARRY.bits(), 0x01);
    assert_eq!(BinaryCounterQuality::ADJUSTED.bits(), 0x20);
    assert_eq!(BinaryCounterQuality::INVALID.bits(), 0x80);
}

#[test]
fn bitflags_default_is_empty() {
    assert_eq!(QualityDescriptor::default().bits(), 0);
    assert_eq!(QualityDescriptorP::default().bits(), 0);
    assert_eq!(BinaryCounterQuality::default().bits(), 0);
}
