//! Integration tests for parameter struct defaults + header sizing.

use fegrid_iec60870_core::{AppLayerParameters, CaSize, CotSize, IoaSize, LinkLayerParameters};

#[test]
fn app_layer_defaults_match_cs104_baseline() {
    let p = AppLayerParameters::default();
    assert_eq!(p.size_of_cot, CotSize::Two);
    assert_eq!(p.size_of_ca, CaSize::Two);
    assert_eq!(p.size_of_ioa, IoaSize::Three);
    assert_eq!(p.max_size_of_asdu, 249);
    // header = 2 (typeid+vsq) + cot(2) + ca(2) = 6
    assert_eq!(p.header_size(), 6);
}

#[test]
fn app_layer_compact_header_size() {
    let p = AppLayerParameters {
        size_of_cot: CotSize::One,
        size_of_ca: CaSize::One,
        size_of_ioa: IoaSize::One,
        ..AppLayerParameters::default()
    };
    // 2 + 1 + 1 = 4
    assert_eq!(p.header_size(), 4);
    assert_eq!(p.ioa_size(), 1);
}

#[test]
fn link_layer_defaults() {
    let p = LinkLayerParameters::default();
    assert!(p.use_single_char_ack);
    assert_eq!(p.timeout_ack_ms, 500);
    assert_eq!(p.timeout_repeat_ms, 5000);
}
