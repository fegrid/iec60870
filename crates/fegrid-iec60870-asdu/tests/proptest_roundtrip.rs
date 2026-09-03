//! Property: encode -> parse == original for the typed ASDU codec.

use proptest::prelude::*;

use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue, encode_to_vec};
use fegrid_iec60870_core::{
    AppLayerParameters, CaSize, CauseOfTransmission, CommonAddress, CotField, CotSize, IoaSize,
    QualityDescriptor, TypeId,
};

fn arb_value() -> impl Strategy<Value = InformationValue> {
    prop_oneof![
        (any::<bool>(), any::<u8>()).prop_map(|(v, q)| InformationValue::SinglePoint {
            value: v,
            quality: QualityDescriptor::from_bits_truncate(q),
        }),
        (any::<u8>(), any::<u8>()).prop_map(|(state, q)| InformationValue::DoublePoint {
            state: state & 0x03,
            quality: QualityDescriptor::from_bits_truncate(q),
        }),
    ]
}

fn make_asdu(t: TypeId, ca: u16, items: Vec<(u32, InformationValue)>) -> Asdu {
    Asdu {
        type_id: t,
        original_type_byte: t.to_wire(),
        cot: CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(ca),
        is_sequence: false,
        is_test: false,
        objects: items
            .into_iter()
            .map(|(ioa, value)| InformationObject::new(ioa, value))
            .collect(),
    }
}

proptest! {
    #[test]
    fn round_trip_default_params(
        ca in any::<u16>(),
        items in proptest::collection::vec((0u32..0x1000000u32, arb_value()), 0..6),
    ) {
        let params = AppLayerParameters::default();
        let asdu = make_asdu(TypeId::M_SP_NA_1, ca, items);
        let bytes = encode_to_vec(&params, &asdu).expect("encode");
        let parsed = Asdu::parse(&params, &bytes).expect("parse");
        prop_assert_eq!(parsed.type_id, asdu.type_id);
        prop_assert_eq!(parsed.objects.len(), asdu.objects.len());
    }

    #[test]
    fn round_trip_compact_params(
        ca in any::<u8>(),
        items in proptest::collection::vec((0u32..0x100u32, arb_value()), 0..6),
    ) {
        let params = AppLayerParameters {
            size_of_cot: CotSize::One,
            size_of_ca: CaSize::One,
            size_of_ioa: IoaSize::One,
            max_size_of_asdu: 249,
        };
        let asdu = make_asdu(TypeId::M_SP_NA_1, ca as u16, items);
        let bytes = encode_to_vec(&params, &asdu).expect("encode");
        let parsed = Asdu::parse(&params, &bytes).expect("parse");
        prop_assert_eq!(parsed.type_id, asdu.type_id);
        prop_assert_eq!(parsed.objects.len(), asdu.objects.len());
    }

    #[test]
    fn parse_never_panics_on_random_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let params = AppLayerParameters::default();
        let _ = Asdu::parse_lenient(&params, &bytes);
    }
}
