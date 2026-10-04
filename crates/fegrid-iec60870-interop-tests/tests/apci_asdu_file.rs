//! IEC 60870-5 interop property tests: APCI framing, ASDU body,
//! file-transfer state machines.
//!
//! Companion to `tests/integration.rs`. Adds coverage that the existing
//! macro-driven file leaves thin: APCI encode/decode across every
//! frame type + error path, ASDU per-TypeId body length + nested
//! timestamp framing, and `FileSendSide` / `FileReceiveSide` happy
//! paths + error paths.
//!
//! Pure data, no I/O. Run with
//! `cargo test -p fegrid-iec60870-interop-tests --test apci_asdu_file`.

use fegrid_iec60870_asdu::file_transfer::{
    FileReceiveSide, FileSendSide, FileTransferError, WaitingFileReady,
};
use fegrid_iec60870_asdu::values_encode::body_only_len;
use fegrid_iec60870_asdu::{
    Asdu, BinaryCounterReading, InformationObject, InformationValue, body_len_for_type,
    encode_to_vec, has_cp24, has_cp56, parse_default, parse_lenient_default,
};
use fegrid_iec60870_core::{
    AppLayerParameters, BinaryCounterQuality, CaSize, CauseOfTransmission, CommonAddress, CotField,
    CotSize, Cp56Time2a, Ioa, IoaSize, QualityDescriptor, QualityDescriptorP, Result as CoreResult,
    Timestamp, TimestampKind, TypeId, timestamp_kind_for,
};
use fegrid_iec60870_cs104::apci::{ApduError, encode_s, encode_u_frame};
use fegrid_iec60870_cs104::{
    APCI_MAX_LENGTH, APDU_MIN_LENGTH, Apdu, SeqNo, UFrame, encode_i, parse_apdu, s_frame_bytes,
    u_frame_bytes,
};

// =====================================================================
// APCI: control-field classification, SeqNo arithmetic, encode/decode.
// =====================================================================

#[test]
fn apci_constants_sane() {
    let min = APDU_MIN_LENGTH;
    let max = APCI_MAX_LENGTH;
    assert!(min >= 4);
    assert!(max <= 253);
    assert!(min < max);
}

#[test]
fn apci_seq_no_default_zero() {
    assert_eq!(SeqNo::default(), SeqNo(0));
}

#[test]
fn apci_seq_no_next_wraps_at_32768() {
    assert_eq!(SeqNo(32767).next(), SeqNo(0));
    assert_eq!(SeqNo(0).next(), SeqNo(1));
    assert_eq!(SeqNo(32766).next(), SeqNo(32767));
}

#[test]
fn apci_seq_no_wire_byte_lsb_even() {
    // LSB byte on wire is always even (SeqNo's low 7 bits, shifted left 1).
    for raw in [0u16, 1, 2, 63, 64, 127, 128, 255, 32767] {
        let w = SeqNo(raw).to_wire();
        assert_eq!(w[0] % 2, 0, "SeqNo({raw}).to_wire()[0] must be even");
    }
}

#[test]
fn apci_u_frame_wire_bytes_known_shapes() {
    // STARTDT_ACT: 68 04 07 00 00 00
    assert_eq!(
        u_frame_bytes(UFrame::StartDtAct).as_ref(),
        &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00]
    );
    // STARTDT_CON: 68 04 0B 00 00 00
    assert_eq!(
        u_frame_bytes(UFrame::StartDtCon).as_ref(),
        &[0x68, 0x04, 0x0b, 0x00, 0x00, 0x00]
    );
    // STOPDT_ACT: 68 04 13 00 00 00
    assert_eq!(
        u_frame_bytes(UFrame::StopDtAct).as_ref(),
        &[0x68, 0x04, 0x13, 0x00, 0x00, 0x00]
    );
    // STOPDT_CON: 68 04 23 00 00 00
    assert_eq!(
        u_frame_bytes(UFrame::StopDtCon).as_ref(),
        &[0x68, 0x04, 0x23, 0x00, 0x00, 0x00]
    );
    // TESTFR_ACT: 68 04 43 00 00 00
    assert_eq!(
        u_frame_bytes(UFrame::TestFrAct).as_ref(),
        &[0x68, 0x04, 0x43, 0x00, 0x00, 0x00]
    );
    // TESTFR_CON: 68 04 83 00 00 00
    assert_eq!(
        u_frame_bytes(UFrame::TestFrCon).as_ref(),
        &[0x68, 0x04, 0x83, 0x00, 0x00, 0x00]
    );
}

#[test]
fn apci_u_frame_round_trip_all_six() {
    for u in [
        UFrame::StartDtAct,
        UFrame::StartDtCon,
        UFrame::StopDtAct,
        UFrame::StopDtCon,
        UFrame::TestFrAct,
        UFrame::TestFrCon,
    ] {
        let bytes = u_frame_bytes(u);
        assert_eq!(parse_apdu(&bytes).unwrap(), Apdu::U(u));
    }
}

#[test]
fn apci_u_frame_encode_short_buffer_errors() {
    let mut buf = [0u8; 5];
    let res = encode_u_frame(UFrame::StartDtAct, &mut buf);
    assert!(matches!(res, Err(ApduError::TooShort { have: 5 })));
}

#[test]
fn apci_s_frame_round_trip() {
    let bytes = s_frame_bytes(SeqNo(42));
    // S-frame layout: 68 04 01 <nr_lo> <nr_hi> 00
    assert_eq!(&bytes[..], &[0x68, 0x04, 0x01, 0x54, 0x00, 0x00]);
    assert_eq!(parse_apdu(&bytes).unwrap(), Apdu::S { nr: SeqNo(42) });
}

#[test]
fn apci_s_frame_encode_short_buffer_errors() {
    let mut buf = [0u8; 5];
    let res = encode_s(SeqNo(0), &mut buf);
    assert!(matches!(res, Err(ApduError::TooShort { have: 5 })));
}

#[test]
fn apci_s_frame_max_seq_no() {
    // 32767 → nr_lo = 254 (32767 % 128 = 127 → *2 = 254), nr_hi = 255
    let bytes = s_frame_bytes(SeqNo(32767));
    assert_eq!(bytes[3], 0xFE);
    assert_eq!(bytes[4], 0xFF);
    assert_eq!(parse_apdu(&bytes).unwrap(), Apdu::S { nr: SeqNo(32767) });
}

#[test]
fn apci_i_frame_no_asdu_round_trip() {
    let params = AppLayerParameters::default();
    let mut buf = [0u8; 6];
    let n = encode_i(SeqNo(7), SeqNo(13), None, &params, &mut buf).unwrap();
    assert_eq!(n, 6);
    // I-frame LSB bit of byte 2 is 0 (even), byte 3 is high byte of send.
    // 7 → lo=14, hi=0. 13 → lo=26, hi=0.
    assert_eq!(buf, [0x68, 0x04, 14, 0, 26, 0]);
    let parsed = parse_apdu(&buf).unwrap();
    match parsed {
        Apdu::I { ns, nr, asdu } => {
            assert_eq!(ns, SeqNo(7));
            assert_eq!(nr, SeqNo(13));
            assert!(asdu.is_none());
        }
        other => panic!("expected I-frame, got {other:?}"),
    }
}

#[test]
fn apci_i_frame_with_asdu_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: 1,
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
        objects: vec![InformationObject::new(
            0x000001,
            InformationValue::SinglePoint {
                value: true,
                quality: QualityDescriptor::SPI,
            },
        )],
    };
    let mut buf = [0u8; 32];
    let n = encode_i(SeqNo(100), SeqNo(200), Some(&asdu), &params, &mut buf).unwrap();
    assert!(n >= 6);
    // Length byte = total - 2.
    assert_eq!(buf[1] as usize, n - 2);
    let parsed = parse_apdu(&buf).unwrap();
    match parsed {
        Apdu::I {
            ns,
            nr,
            asdu: Some(decoded),
        } => {
            assert_eq!(ns, SeqNo(100));
            assert_eq!(nr, SeqNo(200));
            assert_eq!(decoded.type_id, TypeId::M_SP_NA_1);
            assert_eq!(decoded.objects.len(), 1);
        }
        other => panic!("expected I-frame w/ ASDU, got {other:?}"),
    }
}

#[test]
fn apci_i_frame_short_buffer_errors() {
    let params = AppLayerParameters::default();
    let mut buf = [0u8; 5];
    let res = encode_i(SeqNo(0), SeqNo(0), None, &params, &mut buf);
    assert!(matches!(res, Err(ApduError::TooShort { have: 5 })));
}

#[test]
fn apci_parse_rejects_wrong_start_byte() {
    let res = parse_apdu(&[0x69, 0x04, 0x07, 0x00, 0x00, 0x00]);
    assert!(matches!(res, Err(ApduError::InvalidStartByte(0x69))));
}

#[test]
fn apci_parse_rejects_below_min_length() {
    // 0x68 with length byte 2 (below APDU_MIN_LENGTH of 4).
    let res = parse_apdu(&[0x68, 0x02, 0x07, 0x00, 0x00, 0x00]);
    assert!(matches!(res, Err(ApduError::InvalidLength(2))));
}

#[test]
fn apci_parse_rejects_length_mismatch() {
    // Length byte claims 10 but only 6 bytes follow.
    let res = parse_apdu(&[0x68, 0x0A, 0x07, 0x00, 0x00, 0x00]);
    assert!(matches!(res, Err(ApduError::LengthMismatch { .. })));
}

#[test]
fn apci_parse_rejects_too_short_buffer() {
    // Single byte.
    let res = parse_apdu(&[0x68]);
    assert!(matches!(res, Err(ApduError::TooShort { have: 1 })));
}

#[test]
fn apci_parse_rejects_invalid_control_field() {
    // 0x05: LSB=1 (not I), not 0x01 (not S), (cf & 0x03) == 0x01 (not U).
    let res = parse_apdu(&[0x68, 0x04, 0x05, 0x00, 0x00, 0x00]);
    assert!(matches!(res, Err(ApduError::InvalidControlField(0x05))));
}

#[test]
fn apci_parse_rejects_unknown_u_frame_subtype() {
    // U-frame slot (cf & 0x03 == 0x03) but value 0x33 is undefined.
    let res = parse_apdu(&[0x68, 0x04, 0x33, 0x00, 0x00, 0x00]);
    assert!(matches!(res, Err(ApduError::InvalidControlField(0x33))));
}

// =====================================================================
// ASDU: TypeId body length + timestamp suffix invariants.
// =====================================================================

#[test]
fn asdu_body_only_len_strips_cp24_for_ta_family() {
    // M_SP_TA_1: total 4 (1 body + 3 CP24). Body-only = 1.
    assert_eq!(body_only_len(TypeId::M_SP_TA_1.to_wire()), 1);
    assert_eq!(
        timestamp_kind_for(TypeId::M_SP_TA_1),
        Some(TimestampKind::Cp24)
    );
    assert!(has_cp24(2));
    assert!(!has_cp56(2));
}

#[test]
fn asdu_body_only_len_strips_cp56_for_tb_family() {
    // M_SP_TB_1: total 8 (1 body + 7 CP56). Body-only = 1.
    assert_eq!(TypeId::M_SP_TB_1.object_size(), 8);
    assert_eq!(body_only_len(TypeId::M_SP_TB_1.to_wire()), 1);
    assert!(!has_cp24(30));
}

#[test]
fn asdu_no_timestamp_for_m_sp_na() {
    assert_eq!(timestamp_kind_for(TypeId::M_SP_NA_1), None);
    assert_eq!(body_only_len(TypeId::M_SP_NA_1.to_wire()), 1);
}
#[test]
fn asdu_no_timestamp_for_command_na_family() {
    for t in [
        TypeId::C_SC_NA_1,
        TypeId::C_DC_NA_1,
        TypeId::C_RC_NA_1,
        TypeId::C_SE_NA_1,
        TypeId::C_SE_NB_1,
        TypeId::C_SE_NC_1,
        TypeId::C_BO_NA_1,
    ] {
        assert_eq!(
            timestamp_kind_for(t),
            None,
            "control NA family must have no ts"
        );
    }
}

#[test]
fn asdu_body_len_table_matches_typeid() {
    // For every fixed-size TypeId, the table-driven length must agree
    // with `TypeId::object_size()`.
    let fixed: &[(u8, TypeId)] = &[
        (1, TypeId::M_SP_NA_1),
        (2, TypeId::M_SP_TA_1),
        (3, TypeId::M_DP_NA_1),
        (4, TypeId::M_DP_TA_1),
        (5, TypeId::M_ST_NA_1),
        (7, TypeId::M_BO_NA_1),
        (9, TypeId::M_ME_NA_1),
        (11, TypeId::M_ME_NB_1),
        (13, TypeId::M_ME_NC_1),
        (15, TypeId::M_IT_NA_1),
        (20, TypeId::M_PS_NA_1),
        (21, TypeId::M_ME_ND_1),
        (30, TypeId::M_SP_TB_1),
        (45, TypeId::C_SC_NA_1),
        (51, TypeId::C_BO_NA_1),
        (70, TypeId::M_EI_NA_1),
        (100, TypeId::C_IC_NA_1),
        (102, TypeId::C_RD_NA_1),
        (110, TypeId::P_ME_NA_1),
        (113, TypeId::P_AC_NA_1),
        (120, TypeId::F_FR_NA_1),
        (121, TypeId::F_SR_NA_1),
        (122, TypeId::F_SC_NA_1),
        (123, TypeId::F_LS_NA_1),
        (124, TypeId::F_AF_NA_1),
    ];
    for (wire, t) in fixed {
        assert_eq!(
            body_len_for_type(*wire),
            t.object_size(),
            "wire {wire} disagrees with TypeId"
        );
    }
}

#[test]
fn asdu_param_ioa_size_one_two_three_matches_enum() {
    let p = AppLayerParameters {
        size_of_cot: CotSize::Two,
        size_of_ca: CaSize::Two,
        size_of_ioa: IoaSize::One,
        max_size_of_asdu: 249,
    };
    assert_eq!(p.ioa_size(), 1);
    assert_eq!(p.header_size(), 6);
    let p = AppLayerParameters {
        size_of_ioa: IoaSize::Two,
        ..p
    };
    assert_eq!(p.ioa_size(), 2);
    assert_eq!(p.header_size(), 6);
    let p = AppLayerParameters {
        size_of_ioa: IoaSize::Three,
        ..p
    };
    assert_eq!(p.ioa_size(), 3);
    assert_eq!(p.header_size(), 6);
}

#[test]
fn asdu_ioa_encode_decode_round_trip_one_byte() {
    let p = AppLayerParameters {
        size_of_ioa: IoaSize::One,
        ..AppLayerParameters::default()
    };
    for raw in [0u32, 1, 127, 255] {
        let mut buf = [0u8; 1];
        Ioa(raw).encode(p.size_of_ioa, &mut buf).unwrap();
        let back = Ioa::decode(p.size_of_ioa, &buf).unwrap();
        assert_eq!(back.0, raw);
    }
}

#[test]
fn asdu_ioa_encode_decode_round_trip_two_bytes() {
    let p = AppLayerParameters {
        size_of_ioa: IoaSize::Two,
        ..AppLayerParameters::default()
    };
    for raw in [0u32, 1, 255, 256, 0xFFFF] {
        let mut buf = [0u8; 2];
        Ioa(raw).encode(p.size_of_ioa, &mut buf).unwrap();
        let back = Ioa::decode(p.size_of_ioa, &buf).unwrap();
        assert_eq!(back.0, raw);
    }
}

#[test]
fn asdu_ioa_encode_rejects_out_of_range_one_byte() {
    let p = AppLayerParameters {
        size_of_ioa: IoaSize::One,
        ..AppLayerParameters::default()
    };
    let mut buf = [0u8; 1];
    let res = Ioa(0x100).encode(p.size_of_ioa, &mut buf);
    assert!(res.is_err());
}

#[test]
fn asdu_ioa_encode_rejects_out_of_range_two_bytes() {
    let p = AppLayerParameters {
        size_of_ioa: IoaSize::Two,
        ..AppLayerParameters::default()
    };
    let mut buf = [0u8; 2];
    let res = Ioa(0x1_0000).encode(p.size_of_ioa, &mut buf);
    assert!(res.is_err());
}

#[test]
fn asdu_ioa_encode_rejects_short_buffer() {
    let p = AppLayerParameters {
        size_of_ioa: IoaSize::Three,
        ..AppLayerParameters::default()
    };
    let mut buf = [0u8; 2];
    let res = Ioa(1).encode(p.size_of_ioa, &mut buf);
    assert!(res.is_err());
}

#[test]
fn asdu_ca_encode_one_byte_max_value() {
    let ca = CommonAddress(0xFF);
    let mut buf = [0u8; 1];
    ca.encode(CaSize::One, &mut buf).unwrap();
    assert_eq!(buf[0], 0xFF);
    let back = CommonAddress::decode(CaSize::One, &buf).unwrap();
    assert_eq!(back.0, 0xFF);
}

#[test]
fn asdu_ca_new_rejects_out_of_range_one_byte() {
    let res = CommonAddress::new(CaSize::One, 0x100);
    assert!(res.is_err());
}

#[test]
fn asdu_ca_new_accepts_two_byte_max() {
    let res = CommonAddress::new(CaSize::Two, 0xFFFF).unwrap();
    assert_eq!(res.0, 0xFFFF);
}

#[test]
fn asdu_cot_field_encode_default_one_byte() {
    let mut buf = [0u8; 2];
    let f = CotField {
        cause: CauseOfTransmission::Spontaneous,
        negative_confirm: false,
        test: false,
        originator: 0,
        cause_raw_override: None,
    };
    let n = f.encode(CotSize::One, &mut buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(buf[0], 3);
}

#[test]
fn asdu_cot_field_originator_byte_is_second() {
    let mut buf = [0u8; 2];
    let f = CotField {
        cause: CauseOfTransmission::Activation,
        negative_confirm: false,
        test: false,
        originator: 0xAA,
        cause_raw_override: None,
    };
    let n = f.encode(CotSize::Two, &mut buf).unwrap();
    assert_eq!(n, 2);
    // 6 | 0x40=0 | 0x80=0 → 0x06
    assert_eq!(buf[0], 0x06);
    assert_eq!(buf[1], 0xAA);
}

#[test]
fn asdu_cot_field_negative_confirm_and_test_flags() {
    let mut buf = [0u8; 2];
    let f = CotField {
        cause: CauseOfTransmission::ActivationCon,
        negative_confirm: true,
        test: true,
        originator: 0,
        cause_raw_override: None,
    };
    let n = f.encode(CotSize::Two, &mut buf).unwrap();
    assert_eq!(n, 2);
    // 7 | 0x40 | 0x80 = 0xC7
    assert_eq!(buf[0], 0xC7);
    let decoded = CotField::decode(CotSize::Two, &buf).unwrap();
    assert!(decoded.negative_confirm);
    assert!(decoded.test);
    assert_eq!(decoded.cause, CauseOfTransmission::ActivationCon);
}

#[test]
fn asdu_cot_field_raw_override_passthrough() {
    // cause_raw_override = 13 (file transfer) is in the legal set,
    // but we use override = 50 to assert byte-exact round-trip.
    let mut buf = [0u8; 2];
    let f = CotField {
        cause: CauseOfTransmission::Spontaneous,
        negative_confirm: false,
        test: false,
        originator: 0,
        cause_raw_override: Some(50),
    };
    let n = f.encode(CotSize::One, &mut buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(buf[0] & 0x3f, 50);
}

#[test]
fn asdu_timestamp_kind_per_type_family_consistent() {
    // Monitor-direction TA family → CP24.
    for t in [
        TypeId::M_SP_TA_1,
        TypeId::M_DP_TA_1,
        TypeId::M_ST_TA_1,
        TypeId::M_BO_TA_1,
        TypeId::M_ME_TA_1,
        TypeId::M_ME_TB_1,
        TypeId::M_ME_TC_1,
        TypeId::M_IT_TA_1,
        TypeId::M_EP_TA_1,
        TypeId::M_EP_TB_1,
        TypeId::M_EP_TC_1,
    ] {
        assert_eq!(
            timestamp_kind_for(t),
            Some(TimestampKind::Cp24),
            "{t:?} must be CP24"
        );
    }
    // Monitor-direction TB/TC family → CP56.
    for t in [
        TypeId::M_SP_TB_1,
        TypeId::M_DP_TB_1,
        TypeId::M_ST_TB_1,
        TypeId::M_BO_TB_1,
        TypeId::M_ME_TD_1,
        TypeId::M_ME_TE_1,
        TypeId::M_ME_TF_1,
        TypeId::M_IT_TB_1,
        TypeId::M_EP_TD_1,
        TypeId::M_EP_TE_1,
        TypeId::M_EP_TF_1,
    ] {
        assert_eq!(
            timestamp_kind_for(t),
            Some(TimestampKind::Cp56),
            "{t:?} must be CP56"
        );
    }
    // Control-direction _TA_1 → CP56.
    for t in [
        TypeId::C_SC_TA_1,
        TypeId::C_DC_TA_1,
        TypeId::C_RC_TA_1,
        TypeId::C_SE_TA_1,
        TypeId::C_SE_TB_1,
        TypeId::C_SE_TC_1,
        TypeId::C_BO_TA_1,
        TypeId::C_TS_TA_1,
    ] {
        assert_eq!(
            timestamp_kind_for(t),
            Some(TimestampKind::Cp56),
            "{t:?} must be CP56"
        );
    }
}

#[test]
fn asdu_asdu_encoded_len_matches_encode_for_single_object() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: 1,
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
        objects: vec![InformationObject::new(
            1,
            InformationValue::SinglePoint {
                value: false,
                quality: QualityDescriptor::empty(),
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    // encoded_len(NonSq) = header(6) + 1*ioa(3) + 1*body(1) = 10
    assert_eq!(bytes.len(), 10);
}

#[test]
fn asdu_seq_increments_ioa_for_each_object() {
    // SQ-bit ON: only the first IOA is encoded.
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: 1,
        cot: CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: true,
        is_test: false,
        objects: (0..5)
            .map(|i| {
                InformationObject::new(
                    100 + i,
                    InformationValue::SinglePoint {
                        value: i % 2 == 0,
                        quality: QualityDescriptor::empty(),
                    },
                )
            })
            .collect(),
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    assert!(parsed.is_sequence);
    let ioas: Vec<u32> = parsed.objects.iter().map(|o| o.ioa).collect();
    assert_eq!(ioas, vec![100, 101, 102, 103, 104]);
}

#[test]
fn asdu_negative_confirm_in_cot_survives_round_trip() {
    let params = AppLayerParameters::default();
    let mut asdu = Asdu {
        type_id: TypeId::C_SC_NA_1,
        original_type_byte: 45,
        cot: CotField {
            cause: CauseOfTransmission::ActivationCon,
            negative_confirm: true,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            1,
            InformationValue::SingleCommand {
                on: false,
                select: false,
                qu: 0,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    assert!(parsed.cot.negative_confirm);
    assert_eq!(parsed.cot.cause, CauseOfTransmission::ActivationCon);
    // Flip back to positive and re-encode; negative_confirm must clear.
    asdu.cot.negative_confirm = false;
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    assert!(!parsed.cot.negative_confirm);
}

#[test]
fn asdu_originator_byte_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::M_SP_NA_1,
        original_type_byte: 1,
        cot: CotField {
            cause: CauseOfTransmission::Spontaneous,
            negative_confirm: false,
            test: false,
            originator: 0x42,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            1,
            InformationValue::SinglePoint {
                value: true,
                quality: QualityDescriptor::SPI,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    // CotSize::Two → originator is byte[3].
    assert_eq!(bytes[3], 0x42);
    let parsed = parse_default(&bytes).unwrap();
    assert_eq!(parsed.cot.originator, 0x42);
}

#[test]
fn asdu_binary_counter_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::M_IT_NA_1,
        original_type_byte: 15,
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
        objects: vec![InformationObject::new(
            1,
            InformationValue::IntegratedTotals(BinaryCounterReading {
                counter: 0x12345678,
                sequence: 7,
                quality: BinaryCounterQuality::ADJUSTED,
            }),
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::IntegratedTotals(bcr) => {
            assert_eq!(bcr.counter, 0x12345678);
            assert_eq!(bcr.sequence, 7);
            assert_eq!(bcr.quality, BinaryCounterQuality::ADJUSTED);
        }
        other => panic!("expected BCR, got {other:?}"),
    }
}

#[test]
fn asdu_typed_single_command_quality_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::C_SC_NA_1,
        original_type_byte: 45,
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
        objects: vec![InformationObject::new(
            0x1234,
            InformationValue::SingleCommand {
                on: true,
                select: true,
                qu: 0x07,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::SingleCommand { on, select, qu } => {
            assert!(*on);
            assert!(*select);
            assert_eq!(*qu, 0x07);
        }
        other => panic!("expected SingleCommand, got {other:?}"),
    }
}

#[test]
fn asdu_qds_invalid_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::M_ME_NB_1,
        original_type_byte: 11,
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
        objects: vec![InformationObject::new(
            1,
            InformationValue::MeasuredScaled {
                value: -1234,
                quality: QualityDescriptorP::INVALID | QualityDescriptorP::SUBSTITUTED,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::MeasuredScaled { value, quality } => {
            assert_eq!(*value, -1234);
            assert_eq!(
                *quality,
                QualityDescriptorP::INVALID | QualityDescriptorP::SUBSTITUTED
            );
        }
        other => panic!("expected MeasuredScaled, got {other:?}"),
    }
}

#[test]
fn asdu_with_cp56_timestamp_round_trip() {
    let params = AppLayerParameters::default();
    let cp = Cp56Time2a::default();
    let asdu = Asdu {
        type_id: TypeId::M_SP_TB_1,
        original_type_byte: 30,
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
        objects: vec![InformationObject::with_timestamp(
            1,
            InformationValue::SinglePoint {
                value: true,
                quality: QualityDescriptor::SPI,
            },
            Some(Timestamp::Cp56(cp)),
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    assert!(parsed.objects[0].timestamp.is_some());
}

#[test]
fn asdu_strict_rejects_unknown_type_id() {
    // Hand-craft an ASDU claiming type 200, which is undefined.
    let bytes = vec![200, 0x01, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00];
    let res: CoreResult<Asdu> = parse_default(&bytes);
    assert!(res.is_err());
}

#[test]
fn asdu_lenient_accepts_unknown_type_id_with_raw_value() {
    // Type 128 is undefined → from_wire returns Undefined, body_len_for_type = 0.
    // Lenient parser must NOT reject it.
    let bytes = vec![128, 0x01, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01];
    let parsed = parse_lenient_default(&bytes).unwrap();
    assert_eq!(parsed.original_type_byte, 128);
    assert_eq!(parsed.objects.len(), 1);
    match &parsed.objects[0].value {
        InformationValue::Raw { type_id, .. } => {
            assert_eq!(*type_id, 128);
        }
        other => panic!("expected Raw, got {other:?}"),
    }
}

#[test]
fn asdu_strict_rejects_truncated_object_body() {
    // Header complete (6 bytes), VSQ count=1, but object body is shorter
    // than required (M_SP_NA_1 needs 1 byte body, IOA=3 bytes).
    let bytes = vec![0x01, 0x01, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01];
    let res: CoreResult<Asdu> = parse_default(&bytes);
    assert!(res.is_err());
}

// =====================================================================
// File transfer: send-side happy path + per-step error paths.
// =====================================================================

fn make_call(name: u16, section: u8, scq: u8) -> Asdu {
    Asdu {
        type_id: TypeId::F_SC_NA_1,
        original_type_byte: 122,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileCall { name, section, scq },
        )],
    }
}

fn make_ready(name: u16, length: u32) -> Asdu {
    Asdu {
        type_id: TypeId::F_FR_NA_1,
        original_type_byte: 120,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileReady {
                name,
                length,
                frq: 0,
            },
        )],
    }
}

fn make_section(name: u16, section: u8, length: u32, srq: u8) -> Asdu {
    Asdu {
        type_id: TypeId::F_SR_NA_1,
        original_type_byte: 121,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::SectionReady {
                name,
                section,
                length,
                srq,
            },
        )],
    }
}

fn make_last_section(name: u16, section: u8, checksum: u8) -> Asdu {
    Asdu {
        type_id: TypeId::F_LS_NA_1,
        original_type_byte: 123,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileLastSection {
                name,
                section,
                lsq: 0x01,
                checksum,
            },
        )],
    }
}

fn make_ack(name: u16, section: u8, afq: u8) -> Asdu {
    Asdu {
        type_id: TypeId::F_AF_NA_1,
        original_type_byte: 124,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileAck { name, section, afq },
        )],
    }
}

fn make_segment(name: u16, section: u8, data: Vec<u8>) -> Asdu {
    Asdu {
        type_id: TypeId::F_SG_NA_1,
        original_type_byte: 125,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileSegment {
                name,
                section,
                los: data.len() as u8,
                data,
            },
        )],
    }
}

fn empty_file_asdu(type_byte: u8) -> Asdu {
    Asdu {
        type_id: TypeId::from_wire(type_byte),
        original_type_byte: type_byte,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
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
fn file_send_side_call_emits_select_file() {
    let (send, out) = FileSendSide::call_file(7, CommonAddress(1));
    let _ = send;
    assert_eq!(out.original_type_byte, 122);
    assert_eq!(out.objects.len(), 1);
    match &out.objects[0].value {
        InformationValue::FileCall { name, section, scq } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 0);
            assert_eq!(*scq, 0x01);
        }
        other => panic!("expected FileCall, got {other:?}"),
    }
    assert_eq!(out.cot.cause, CauseOfTransmission::FileTransfer);
}

#[test]
fn file_send_side_call_advances_state_to_waiting_ready() {
    let (send, _): (FileSendSide<WaitingFileReady>, _) =
        FileSendSide::call_file(99, CommonAddress(1));
    let _ = send;
}

#[test]
fn file_send_side_file_ready_emits_call_section() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let inbound = make_ready(7, 0x1234);
    let (send, out) = send.on_file_ready(&inbound).unwrap();
    let _ = send;
    assert_eq!(out.original_type_byte, 122);
    match &out.objects[0].value {
        InformationValue::FileCall { name, section, scq } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 1);
            assert_eq!(*scq, 0x02);
        }
        other => panic!("expected FileCall section, got {other:?}"),
    }
}

#[test]
fn file_send_side_file_ready_rejects_wrong_type() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let bogus = make_ack(7, 0, 0x01);
    let err = send.on_file_ready(&bogus).unwrap_err();
    match err {
        FileTransferError::UnexpectedType { expected, got } => {
            assert_eq!(expected, 120);
            assert_eq!(got, 124);
        }
        other => panic!("expected UnexpectedType, got {other:?}"),
    }
}

#[test]
fn file_send_side_file_ready_rejects_wrong_file() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let inbound = make_ready(8, 0x100);
    let err = send.on_file_ready(&inbound).unwrap_err();
    match err {
        FileTransferError::WrongFile { expected, got } => {
            assert_eq!(expected, 7);
            assert_eq!(got, 8);
        }
        other => panic!("expected WrongFile, got {other:?}"),
    }
}

#[test]
fn file_send_side_file_ready_rejects_empty_objects() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let bogus = empty_file_asdu(120);
    let err = send.on_file_ready(&bogus).unwrap_err();
    assert_eq!(err, FileTransferError::NoObjects);
}

#[test]
fn file_send_side_section_ready_emits_next_call() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let inbound = make_section(7, 1, 0x80, 0x01);
    let (send, out) = send.on_section_ready(&inbound).unwrap();
    let _ = send;
    match &out.objects[0].value {
        InformationValue::FileCall { name, section, scq } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 1);
            assert_eq!(*scq, 0x02);
        }
        other => panic!("expected FileCall, got {other:?}"),
    }
}

#[test]
fn file_send_side_section_ready_increments_section() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let (send, out) = send
        .on_section_ready(&make_section(7, 1, 0x80, 0x01))
        .unwrap();
    match &out.objects[0].value {
        InformationValue::FileCall { section, .. } => assert_eq!(*section, 1),
        _ => unreachable!(),
    }
    // After on_section_ready the machine expects section 2 next.
    let inbound2 = make_section(7, 2, 0x40, 0x01);
    let (_send, out2) = send.on_section_ready(&inbound2).unwrap();
    match &out2.objects[0].value {
        InformationValue::FileCall { section, .. } => assert_eq!(*section, 2),
        _ => unreachable!(),
    }
}

#[test]
fn file_send_side_section_ready_rejects_wrong_section() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let bogus = make_section(7, 5, 0x80, 0x01);
    let err = send.on_section_ready(&bogus).unwrap_err();
    match err {
        FileTransferError::WrongSection { expected, got } => {
            assert_eq!(expected, 1);
            assert_eq!(got, 5);
        }
        other => panic!("expected WrongSection, got {other:?}"),
    }
}

#[test]
fn file_send_side_section_ready_rejects_wrong_file() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let bogus = make_section(8, 1, 0x80, 0x01);
    let err = send.on_section_ready(&bogus).unwrap_err();
    assert!(matches!(err, FileTransferError::WrongFile { .. }));
}

#[test]
fn file_send_side_section_ready_rejects_wrong_type() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let bogus = make_ack(7, 1, 0x01);
    let err = send.on_section_ready(&bogus).unwrap_err();
    assert!(matches!(err, FileTransferError::UnexpectedType { .. }));
}

#[test]
fn file_send_side_last_section_emits_ack() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let (send, _) = send
        .on_section_ready(&make_section(7, 1, 0x80, 0x01))
        .unwrap();
    let (_send, out) = send
        .on_last_section(&make_last_section(7, 2, 0xA5))
        .unwrap();
    assert_eq!(out.original_type_byte, 124);
    match &out.objects[0].value {
        InformationValue::FileAck { name, section, afq } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 2);
            assert_eq!(*afq, 0x01);
        }
        other => panic!("expected FileAck, got {other:?}"),
    }
}

#[test]
fn file_send_side_last_section_rejects_wrong_section() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let (send, _) = send
        .on_section_ready(&make_section(7, 1, 0x80, 0x01))
        .unwrap();
    let bogus = make_last_section(7, 99, 0xA5);
    let err = send.on_last_section(&bogus).unwrap_err();
    assert!(matches!(err, FileTransferError::WrongSection { .. }));
}

#[test]
fn file_send_side_last_section_rejects_wrong_type() {
    let (send, _) = FileSendSide::call_file(7, CommonAddress(1));
    let (send, _) = send.on_file_ready(&make_ready(7, 0x100)).unwrap();
    let (send, _) = send
        .on_section_ready(&make_section(7, 1, 0x80, 0x01))
        .unwrap();
    let bogus = make_section(7, 2, 0x80, 0x01);
    let err = send.on_last_section(&bogus).unwrap_err();
    assert!(matches!(err, FileTransferError::UnexpectedType { .. }));
}

// =====================================================================
// File transfer: receive-side happy path + error paths.
// =====================================================================

#[test]
fn file_receive_side_call_select_emits_file_ready() {
    let inbound = make_call(7, 0, 0x01);
    let (_recv, out) = FileReceiveSide::on_call(7, 0x1234u32, &inbound).unwrap();
    assert_eq!(out.original_type_byte, 120);
    match &out.objects[0].value {
        InformationValue::FileReady { name, length, frq } => {
            assert_eq!(*name, 7);
            assert_eq!(*length, 0x1234);
            assert_eq!(*frq, 0);
        }
        other => panic!("expected FileReady, got {other:?}"),
    }
}

#[test]
fn file_receive_side_rejects_non_select_first_call() {
    let inbound = make_call(7, 0, 0x02);
    let err = FileReceiveSide::on_call(7, 0x100u32, &inbound).unwrap_err();
    assert!(matches!(err, FileTransferError::Protocol(_)));
}

#[test]
fn file_receive_side_rejects_wrong_file_name() {
    let inbound = make_call(8, 0, 0x01);
    let err = FileReceiveSide::on_call(7, 0x100u32, &inbound).unwrap_err();
    match err {
        FileTransferError::WrongFile { expected, got } => {
            assert_eq!(expected, 7);
            assert_eq!(got, 8);
        }
        other => panic!("expected WrongFile, got {other:?}"),
    }
}

#[test]
fn file_receive_side_rejects_wrong_type_at_select() {
    let inbound = make_ack(7, 0, 0x01);
    let err = FileReceiveSide::on_call(7, 0x100u32, &inbound).unwrap_err();
    assert!(matches!(err, FileTransferError::UnexpectedType { .. }));
}

#[test]
fn file_receive_side_rejects_empty_objects_at_select() {
    let bogus = empty_file_asdu(122);
    let err = FileReceiveSide::on_call(7, 0x100u32, &bogus).unwrap_err();
    assert_eq!(err, FileTransferError::NoObjects);
}

#[test]
fn file_receive_side_section_call_emits_section_ready() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let inbound = make_call(7, 1, 0x02);
    let (_recv, out) = recv.on_section_call(&inbound, 0x80, false).unwrap();
    assert_eq!(out.original_type_byte, 121);
    match &out.objects[0].value {
        InformationValue::SectionReady {
            name,
            section,
            length,
            srq,
        } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 1);
            assert_eq!(*length, 0x80);
            assert_eq!(*srq, 0x01);
        }
        other => panic!("expected SectionReady, got {other:?}"),
    }
}

#[test]
fn file_receive_side_section_call_emits_last_section_when_flagged() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let inbound = make_call(7, 1, 0x02);
    let (recv, out) = recv.on_section_call(&inbound, 0x40, true).unwrap();
    let _ = recv;
    assert_eq!(out.original_type_byte, 123);
    match &out.objects[0].value {
        InformationValue::FileLastSection {
            name,
            section,
            lsq,
            checksum,
        } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 1);
            assert_eq!(*lsq, 0x01);
            assert_eq!(*checksum, 0);
        }
        other => panic!("expected FileLastSection, got {other:?}"),
    }
}

#[test]
fn file_receive_side_section_call_rejects_select_qualifier() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let inbound = make_call(7, 1, 0x01); // SCQ=0x01 in section call → protocol error.
    let err = recv.on_section_call(&inbound, 0x80, false).unwrap_err();
    assert!(matches!(err, FileTransferError::Protocol(_)));
}

#[test]
fn file_receive_side_section_call_rejects_wrong_section() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let inbound = make_call(7, 99, 0x02);
    let err = recv.on_section_call(&inbound, 0x80, false).unwrap_err();
    match err {
        FileTransferError::WrongSection { expected, got } => {
            assert_eq!(expected, 1);
            assert_eq!(got, 99);
        }
        other => panic!("expected WrongSection, got {other:?}"),
    }
}

#[test]
fn file_receive_side_section_call_rejects_wrong_file() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let inbound = make_call(8, 1, 0x02);
    let err = recv.on_section_call(&inbound, 0x80, false).unwrap_err();
    assert!(matches!(err, FileTransferError::WrongFile { .. }));
}

#[test]
fn file_receive_side_ack_closes_session() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let inbound = make_ack(7, 1, 0x01);
    let _recv = recv.on_ack(&inbound).unwrap();
}

#[test]
fn file_receive_side_ack_rejects_wrong_type() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let bogus = make_section(7, 1, 0x80, 0x01);
    let err = recv.on_ack(&bogus).unwrap_err();
    assert!(matches!(err, FileTransferError::UnexpectedType { .. }));
}

#[test]
fn file_receive_side_ack_rejects_wrong_file() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let bogus = make_ack(8, 1, 0x01);
    let err = recv.on_ack(&bogus).unwrap_err();
    assert!(matches!(err, FileTransferError::WrongFile { .. }));
}

// =====================================================================
// File transfer: F_SG_NA_1 segment wire round-trip + F_DR_TA_1 directory.
// =====================================================================

#[test]
fn file_segment_encode_decode_round_trip() {
    let params = AppLayerParameters::default();
    let data = vec![0xAAu8, 0xBB, 0xCC, 0xDD];
    let asdu = make_segment(7, 3, data.clone());
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    assert_eq!(parsed.objects.len(), 1);
    match &parsed.objects[0].value {
        InformationValue::FileSegment {
            name,
            section,
            los,
            data: out_data,
        } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 3);
            assert_eq!(*los as usize, data.len());
            assert_eq!(out_data, &data);
        }
        other => panic!("expected FileSegment, got {other:?}"),
    }
}

#[test]
fn file_segment_zero_length_body() {
    let params = AppLayerParameters::default();
    let asdu = make_segment(7, 1, vec![]);
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::FileSegment { los, data, .. } => {
            assert_eq!(*los, 0);
            assert!(data.is_empty());
        }
        other => panic!("expected FileSegment, got {other:?}"),
    }
}

#[test]
fn file_segment_rejects_truncated_data() {
    // Build wire form for an F_SG_NA_1 claiming 4 data bytes, but only 2
    // bytes follow. Parser must reject.
    // Hand-construct: type=125, vsq=01, cot=FileTransfer (13), ca=1, ioa=0,
    // nof=7 (LE), section=3, los=4, then only 2 data bytes.
    let mut bytes = vec![125, 0x01, 0x03, 0x00, 0x00, 0x01];
    // 3-byte IOA, value 0.
    bytes.extend_from_slice(&[0x00, 0x00, 0x00]);
    // F_SG_NA_1 body: NOF(2) + NOS(1) + LOS(1) + data[LOS].
    bytes.extend_from_slice(&7u16.to_le_bytes());
    bytes.push(3);
    bytes.push(4);
    bytes.push(0xAA);
    bytes.push(0xBB);
    let res: CoreResult<Asdu> = parse_default(&bytes);
    assert!(res.is_err());
}

#[test]
fn file_directory_round_trip() {
    let params = AppLayerParameters::default();
    let cp = Cp56Time2a::default();
    let asdu = Asdu {
        type_id: TypeId::F_DR_TA_1,
        original_type_byte: 126,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileDirectory {
                name: 42,
                length_of_file: 0x123456,
                sof: 0x21,
                creation_time: cp,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    // F_DR_TA_1: NOF(2) + LOF(3) + SOF(1) + CP56(7) = 13 body bytes.
    // Total = 6 header + 3 ioa + 13 body = 22.
    assert_eq!(bytes.len(), 22);
    let parsed = parse_default(&bytes).unwrap();
    assert_eq!(parsed.objects.len(), 1);
    match &parsed.objects[0].value {
        InformationValue::FileDirectory {
            name,
            length_of_file,
            sof,
            creation_time,
        } => {
            assert_eq!(*name, 42);
            assert_eq!(*length_of_file, 0x123456);
            assert_eq!(*sof, 0x21);
            assert_eq!(*creation_time, cp);
        }
        other => panic!("expected FileDirectory, got {other:?}"),
    }
}

#[test]
fn file_directory_length_of_file_truncated_to_24_bits() {
    // Wire form stores LOF as 24-bit; high byte must be dropped on decode.
    let params = AppLayerParameters::default();
    let cp = Cp56Time2a::default();
    let asdu = Asdu {
        type_id: TypeId::F_DR_TA_1,
        original_type_byte: 126,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileDirectory {
                name: 1,
                length_of_file: 0xFF_123456,
                sof: 0,
                creation_time: cp,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::FileDirectory { length_of_file, .. } => {
            // High byte (0xFF) is dropped on the wire.
            assert_eq!(*length_of_file, 0x12_3456);
        }
        _ => unreachable!(),
    }
}

#[test]
fn file_ready_repr_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_FR_NA_1,
        original_type_byte: 120,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileReady {
                name: 1234,
                length: 0xABCDEF,
                frq: 0x05,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::FileReady { name, length, frq } => {
            assert_eq!(*name, 1234);
            assert_eq!(*length, 0xABCDEF);
            assert_eq!(*frq, 0x05);
        }
        other => panic!("expected FileReady, got {other:?}"),
    }
}

#[test]
fn file_call_repr_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_SC_NA_1,
        original_type_byte: 122,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileCall {
                name: 42,
                section: 7,
                scq: 0x02,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::FileCall { name, section, scq } => {
            assert_eq!(*name, 42);
            assert_eq!(*section, 7);
            assert_eq!(*scq, 0x02);
        }
        other => panic!("expected FileCall, got {other:?}"),
    }
}

#[test]
fn file_last_section_repr_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_LS_NA_1,
        original_type_byte: 123,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileLastSection {
                name: 100,
                section: 5,
                lsq: 0x01,
                checksum: 0xCC,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::FileLastSection {
            name,
            section,
            lsq,
            checksum,
        } => {
            assert_eq!(*name, 100);
            assert_eq!(*section, 5);
            assert_eq!(*lsq, 0x01);
            assert_eq!(*checksum, 0xCC);
        }
        other => panic!("expected FileLastSection, got {other:?}"),
    }
}

#[test]
fn file_ack_repr_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_AF_NA_1,
        original_type_byte: 124,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::FileAck {
                name: 7,
                section: 99,
                afq: 0x01,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::FileAck { name, section, afq } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 99);
            assert_eq!(*afq, 0x01);
        }
        other => panic!("expected FileAck, got {other:?}"),
    }
}

#[test]
fn file_section_ready_repr_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::F_SR_NA_1,
        original_type_byte: 121,
        cot: CotField {
            cause: CauseOfTransmission::FileTransfer,
            negative_confirm: false,
            test: false,
            originator: 0,
            cause_raw_override: None,
        },
        common_address: CommonAddress(1),
        is_sequence: false,
        is_test: false,
        objects: vec![InformationObject::new(
            0,
            InformationValue::SectionReady {
                name: 7,
                section: 3,
                length: 0x010203,
                srq: 0x01,
            },
        )],
    };
    let bytes = encode_to_vec(&params, &asdu).unwrap();
    let parsed = parse_default(&bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::SectionReady {
            name,
            section,
            length,
            srq,
        } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 3);
            assert_eq!(*length, 0x010203);
            assert_eq!(*srq, 0x01);
        }
        other => panic!("expected SectionReady, got {other:?}"),
    }
}

// =====================================================================
// Cross-cutting: file-transfer ASDUs all carry COT=FileTransfer.
// =====================================================================

#[test]
fn file_transfer_engine_emits_file_transfer_cause() {
    let (send, out) = FileSendSide::call_file(7, CommonAddress(1));
    assert_eq!(send.name, 7);
    assert_eq!(out.cot.cause, CauseOfTransmission::FileTransfer);
    assert!(!out.cot.negative_confirm);
    assert!(!out.cot.test);
}

#[test]
fn file_transfer_engine_emits_ioa_zero() {
    // IEC convention: identity rides in the file-name field, not the IOA.
    let (send, out) = FileSendSide::call_file(7, CommonAddress(1));
    let _ = send;
    assert_eq!(out.objects[0].ioa, 0);

    let (recv, out) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let _ = recv;
    assert_eq!(out.objects[0].ioa, 0);
}

#[test]
fn file_transfer_engine_preserves_common_address() {
    let (send, out) = FileSendSide::call_file(7, CommonAddress(0x1234));
    let _ = send;
    assert_eq!(out.common_address, CommonAddress(0x1234));

    let (recv, out) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    let _ = recv;
    // Reply carries inbound's common_address (CommonAddress(1)).
    assert_eq!(out.common_address, CommonAddress(1));
}

// =====================================================================
// End-to-end: APCI + ASDU integration. A typed I-frame survives the
// full round-trip through the CS 104 codec.
// =====================================================================

#[test]
fn apci_asdu_i_frame_with_typed_asdu_survives_round_trip() {
    let params = AppLayerParameters::default();
    let asdu = Asdu {
        type_id: TypeId::M_ME_NC_1,
        original_type_byte: 13,
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
        objects: vec![InformationObject::new(
            0x0100,
            InformationValue::MeasuredFloat {
                value: 1.2345_f32,
                quality: QualityDescriptorP::empty(),
            },
        )],
    };
    let mut buf = [0u8; 64];
    let n = encode_i(SeqNo(50), SeqNo(75), Some(&asdu), &params, &mut buf).unwrap();
    let parsed = parse_apdu(&buf[..n]).unwrap();
    match parsed {
        Apdu::I {
            ns,
            nr,
            asdu: Some(decoded),
        } => {
            assert_eq!(ns, SeqNo(50));
            assert_eq!(nr, SeqNo(75));
            assert_eq!(decoded.type_id, TypeId::M_ME_NC_1);
            match &decoded.objects[0].value {
                InformationValue::MeasuredFloat { value, .. } => {
                    assert!((*value - 1.2345).abs() < 1e-6);
                }
                other => panic!("expected MeasuredFloat, got {other:?}"),
            }
        }
        other => panic!("expected I-frame with ASDU, got {other:?}"),
    }
}

#[test]
fn apci_s_frame_does_not_consume_asdu_bytes() {
    // S-frame has no ASDU payload — the parser must return `asdu: None`
    // and the length byte stays at 4.
    let bytes = s_frame_bytes(SeqNo(0));
    assert_eq!(bytes[1], 4);
    let parsed = parse_apdu(&bytes).unwrap();
    match parsed {
        Apdu::S { nr } => assert_eq!(nr, SeqNo(0)),
        other => panic!("expected S-frame, got {other:?}"),
    }
}

#[test]
fn apci_u_frame_does_not_consume_asdu_bytes() {
    let bytes = u_frame_bytes(UFrame::StartDtAct);
    assert_eq!(bytes[1], 4);
    assert_eq!(parse_apdu(&bytes).unwrap(), Apdu::U(UFrame::StartDtAct));
}

// =====================================================================
// File-transfer error: Display + Error trait surfaces.
// =====================================================================

#[test]
fn file_transfer_error_display_unexpected_type() {
    let err = FileTransferError::UnexpectedType {
        expected: 120,
        got: 124,
    };
    let s = format!("{err}");
    assert!(s.contains("unexpected type id"));
    assert!(s.contains("124"));
}

#[test]
fn file_transfer_error_display_wrong_file() {
    let err = FileTransferError::WrongFile {
        expected: 7,
        got: 8,
    };
    let s = format!("{err}");
    assert!(s.contains("wrong file"));
    assert!(s.contains("8"));
}

#[test]
fn file_transfer_error_display_wrong_section() {
    let err = FileTransferError::WrongSection {
        expected: 1,
        got: 5,
    };
    let s = format!("{err}");
    assert!(s.contains("wrong section"));
    assert!(s.contains("5"));
}

#[test]
fn file_transfer_error_display_no_objects() {
    let err = FileTransferError::NoObjects;
    assert!(format!("{err}").contains("no information objects"));
}

#[test]
fn file_transfer_error_display_protocol() {
    let err = FileTransferError::Protocol("custom violation");
    assert_eq!(format!("{err}"), "custom violation");
}

// =====================================================================
// File-transfer negative-path coverage (Item 3, TIER1_TODO.md).
// ---------------------------------------------------------------------
// Locks in wire-level reject paths and engine-level state-machine
// invariants that the happy-path tests above do not exercise. The
// engines operate on F_SC_NA_1 / F_FR_NA_1 / F_SR_NA_1 / F_LS_NA_1
// / F_AF_NA_1 only; F_SG_NA_1 (file segment) is wire-only and is
// covered at the parser layer below.
// =====================================================================

/// Wire frame where LOS=10 but only 5 data bytes follow. Strict parser
/// must reject because the body is shorter than LOS claims.
#[test]
fn ft_bad_los_length_mismatch_rejected() {
    // type=125, vsq=01, cot=FileTransfer (13), ca=1, 3-byte IOA=0,
    // then F_SG_NA_1 body: NOF(2)=7, NOS=1, LOS=10, then only 5 bytes.
    let mut bytes = vec![125, 0x01, 0x03, 0x00, 0x00, 0x01];
    bytes.extend_from_slice(&[0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&7u16.to_le_bytes());
    bytes.push(1);
    bytes.push(10); // LOS claim
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42]); // only 5
    let res: CoreResult<Asdu> = parse_default(&bytes);
    assert!(
        res.is_err(),
        "LOS=10 with 5 data bytes must be rejected by strict parser"
    );
}

/// Wire frame where LOS=20
/// must reject; the truncation is large (10 missing bytes).
#[test]
fn ft_truncated_segment_payload_rejected() {
    let mut bytes = vec![125, 0x01, 0x03, 0x00, 0x00, 0x01];
    bytes.extend_from_slice(&[0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&7u16.to_le_bytes());
    bytes.push(2);
    bytes.push(20); // LOS claim
    bytes.extend(std::iter::repeat_n(0x55u8, 10)); // only 10 of 20
    let res: CoreResult<Asdu> = parse_default(&bytes);
    assert!(
        res.is_err(),
        "LOS=20 with 10 data bytes must be rejected by strict parser"
    );
}

/// After F_LS_NA_1 closes a transfer
/// just-closed (file, section) must be rejected at the receiver.
/// The engines do not accept F_SG_NA_1 in any state — they consume
/// F_SC_NA_1 from the controlling side only — so the rejection happens
/// at the type-byte check on any inbound section call. After the
/// FileLastSection is emitted the receiver counter advances to section
/// 2, so a re-request for the just-closed section 1 is rejected with
/// WrongSection.
#[test]
fn ft_section_after_last_section_rejected() {
    // Walk the receive-side to the state where FileLastSection was
    // emitted for section 1. Receiver is then Selected{section=2}.
    let (recv, fr) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    assert_eq!(fr.original_type_byte, 120, "FileReady emitted");

    let (recv, ls) = recv
        .on_section_call(&make_call(7, 1, 0x02), 0x40, true)
        .unwrap();

    assert_eq!(ls.original_type_byte, 123, "F_LS_NA_1 emitted");

    // (file=7, section=1) re-request is rejected: expected section is 2.
    let err = recv
        .on_section_call(&make_call(7, 1, 0x02), 0x80, false)
        .unwrap_err();
    match err {
        FileTransferError::WrongSection { expected, got } => {
            assert_eq!(expected, 2, "receiver advanced past closed section");
            assert_eq!(got, 1, "re-request for the just-closed section");
        }
        other => panic!("expected WrongSection, got {other:?}"),
    }

    // And an F_SG_NA_1 segment for (file=7, section=1) round-trips on
    // the wire — the engines simply have no entry point that accepts
    // it, which is the negative-path contract at the engine layer.
    let segment = make_segment(7, 1, vec![0xAA, 0xBB]);
    let params = AppLayerParameters::default();
    let seg_bytes = encode_to_vec(&params, &segment).unwrap();
    let parsed = parse_default(&seg_bytes).unwrap();
    match &parsed.objects[0].value {
        InformationValue::FileSegment {
            name,
            section,
            los,
            data,
        } => {
            assert_eq!(*name, 7);
            assert_eq!(*section, 1);
            assert_eq!(*los, 2);
            assert_eq!(data, &vec![0xAA, 0xBB]);
        }
        other => panic!("expected FileSegment, got {other:?}"),
    }
}

/// Out-of-order section numbers must be rejected. Sequence 0,1,3 (skip 2)
/// → the receiver expects section 2 but receives section 3.
#[test]
fn ft_out_of_order_section_numbers_rejected() {
    let (recv, _) = FileReceiveSide::on_call(7, 0x100, &make_call(7, 0, 0x01)).unwrap();
    // section 1: served.
    let (recv, _) = recv
        .on_section_call(&make_call(7, 1, 0x02), 0x80, false)
        .unwrap();
    // skip 2; ask for 3.
    let err = recv
        .on_section_call(&make_call(7, 3, 0x02), 0x80, false)
        .unwrap_err();
    match err {
        FileTransferError::WrongSection { expected, got } => {
            assert_eq!(expected, 2);
            assert_eq!(got, 3);
        }
        other => panic!("expected WrongSection, got {other:?}"),
    }
}

/// File selection cancellation (F_SC_NA_1 with scq=0x03 per IEC
/// 60870-5-101 §7.3.6.3) is rejected by the current receiver:
/// the first FileCall MUST carry scq=0x01 (select). Any other qualifier
/// at select time is a protocol violation.
///
/// TODO(file-transfer-cancel): the receiver currently rejects the
/// cancel with `Protocol("first FileCall expected select (scq=0x01)")`
/// instead of transitioning back to RIdle and emitting a negative
/// FileAck (afq=NOT_READY). When that explicit cancel path lands, this
/// test should be updated to assert the RDone transition.
#[test]
fn ft_file_selection_cancellation_rejected() {
    let inbound = make_call(7, 0, 0x03); // 0x03 = de-select / cancel.
    let err = FileReceiveSide::on_call(7, 0x100, &inbound).unwrap_err();
    match err {
        FileTransferError::Protocol(msg) => {
            assert!(
                msg.contains("select") && msg.contains("0x01"),
                "protocol message must reference select qualifier 0x01, got: {msg:?}"
            );
        }
        other => panic!("expected Protocol error for cancel, got {other:?}"),
    }
}

/// Lock in the exact Display strings for `FileTransferError::WrongFile`
/// and `FileTransferError::WrongSection`. These strings feed log
/// pipelines and downstream user-facing error messages; changing them
/// is a wire-visible contract change.
#[test]
fn ft_error_display_wrong_file_and_wrong_section_strings() {
    let wrong_file = FileTransferError::WrongFile {
        expected: 7,
        got: 8,
    };
    assert_eq!(format!("{wrong_file}"), "wrong file 8 (wanted 7)");

    let wrong_section = FileTransferError::WrongSection {
        expected: 1,
        got: 5,
    };
    assert_eq!(format!("{wrong_section}"), "wrong section 5 (wanted 1)");

    // Error trait must be implementable (used by `?` propagation in
    // callers that box dyn Error into a parent state machine).
    fn assert_error<E: core::error::Error>(_: &E) {}
    assert_error(&wrong_file);
    assert_error(&wrong_section);
}
