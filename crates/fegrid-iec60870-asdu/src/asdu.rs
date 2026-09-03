//! ASDU: full wire-level encode/decode.

use alloc::vec::Vec;

use bytes::BufMut;

use fegrid_iec60870_core::{
    AppLayerParameters, AsduError, CommonAddress, CotField, Ioa, Result, Timestamp, TimestampKind,
    TypeId, timestamp_kind_for,
};

use crate::object::InformationObject;
use crate::values::InformationValue;
use crate::values_encode::body_len_for_type;

/// Variable-structure qualifier byte.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Vsq {
    /// `true` if the IOAs increment sequentially.
    pub is_sequence: bool,
    /// Number of information objects (1..128; 0 = "not used" / one object per
    /// address).
    pub count: u8,
}

impl Vsq {
    fn encode(self) -> u8 {
        let mut b = self.count & 0x7f;
        if self.is_sequence {
            b |= 0x80;
        }
        b
    }

    fn decode(byte: u8) -> Self {
        Self {
            is_sequence: (byte & 0x80) != 0,
            count: byte & 0x7f,
        }
    }
}

/// Application Service Data Unit.
#[derive(Debug, Clone, PartialEq)]
pub struct Asdu {
    /// Type identification (typed enum — [`TypeId::Undefined`] for unknown bytes).
    pub type_id: TypeId,
    /// Raw wire byte for the type id (preserved even when [`TypeId::Undefined`]).
    pub original_type_byte: u8,
    /// Cause-of-transmission field.
    pub cot: CotField,
    /// Common address (station address).
    pub common_address: CommonAddress,
    /// SQ bit (only first object carries an IOA when `true`).
    pub is_sequence: bool,
    /// Test flag from the VSQ (alias of COT test flag).
    pub is_test: bool,
    /// Information objects.
    pub objects: Vec<InformationObject>,
}

impl Asdu {
    /// Parse an ASDU from the supplied byte buffer.
    pub fn parse(params: &AppLayerParameters, input: &[u8]) -> Result<Self> {
        Self::parse_inner(params, input, false)
    }

    /// Lenient variant: unknown type-ids are wrapped in [`InformationValue::Raw`].
    pub fn parse_lenient(params: &AppLayerParameters, input: &[u8]) -> Result<Self> {
        Self::parse_inner(params, input, true)
    }

    fn parse_inner(params: &AppLayerParameters, input: &[u8], lenient: bool) -> Result<Self> {
        let header_len = params.header_size();
        if input.len() < header_len {
            return Err(AsduError::BufferTooShort {
                need: header_len,
                have: input.len(),
            });
        }
        let type_byte = input[0];
        let vsq_byte = input[1];
        let vsq = Vsq::decode(vsq_byte);
        let type_id = TypeId::from_wire(type_byte);
        if !lenient && matches!(type_id, TypeId::Undefined) && type_byte != 0 {
            return Err(AsduError::InvalidTypeId(type_byte));
        }

        let cot_bytes = &input[2..2 + params.size_of_cot as usize];
        let cot = CotField::decode(params.size_of_cot, cot_bytes)?;

        let ca_off = 2 + params.size_of_cot as usize;
        let ca_bytes = &input[ca_off..ca_off + params.size_of_ca as usize];
        let common_address = CommonAddress::decode(params.size_of_ca, ca_bytes)?;

        // Per-object total bytes (including any trailing timestamp).
        let total_obj_size = body_len_for_type(type_byte);

        let mut cursor = header_len;
        let mut objects: Vec<InformationObject> = Vec::with_capacity(vsq.count as usize);

        for i in 0..vsq.count as usize {
            let ioa_bytes = if i == 0 || !vsq.is_sequence {
                params.ioa_size()
            } else {
                0
            };
            // F_DR_TA_1 (126) carries its CP56 inside a fixed 13-byte body,
            // not as a trailing timestamp. F_SG_NA_1 (125) is variable-length —
            // peek LOS from the wire to size the per-object slice before the
            // generic length check.
            let dynamic_body_len = match type_byte {
                126 => Some(13),
                125 if input.len() >= cursor + ioa_bytes + 4 => {
                    let los = input[cursor + ioa_bytes + 3] as usize;
                    Some(4 + los)
                }
                _ => None,
            };
            let total_obj_size = if let Some(n) = dynamic_body_len {
                n
            } else {
                total_obj_size
            };
            let needed = cursor + ioa_bytes + total_obj_size;
            if input.len() < needed {
                return Err(AsduError::BufferTooShort {
                    need: needed,
                    have: input.len(),
                });
            }
            let ioa = if i == 0 || !vsq.is_sequence {
                let parsed = Ioa::decode(params.size_of_ioa, &input[cursor..])?;
                cursor += params.ioa_size();
                parsed.0
            } else {
                objects[i - 1].ioa + 1
            };

            // body_only = total minus trailing timestamp size.
            let body_only = total_obj_size.saturating_sub(timestamp_len_for(type_byte));
            let body_end = cursor + body_only;
            let total_end = body_end + timestamp_len_for(type_byte);

            let (value, timestamp) = if lenient {
                // Lenient: take everything verbatim as a Raw value, no
                // typed timestamp.
                let total_bytes = input[cursor..total_end].to_vec();
                cursor = total_end;
                (
                    InformationValue::Raw {
                        type_id: type_byte,
                        bytes: total_bytes,
                    },
                    None,
                )
            } else {
                // Strict path: decode the typed value from body bytes.
                let value = InformationValue::decode(type_byte, &input[cursor..body_end])?;
                cursor = body_end;
                let ts = if let Some(kind) = timestamp_kind_for(TypeId::from_wire(type_byte)) {
                    let t = Timestamp::decode(kind, &input[cursor..total_end])?;
                    cursor = total_end;
                    Some(t)
                } else {
                    None
                };
                (value, ts)
            };

            objects.push(InformationObject::with_timestamp(ioa, value, timestamp));
        }

        Ok(Self {
            type_id,
            original_type_byte: type_byte,
            cot,
            common_address,
            is_sequence: vsq.is_sequence,
            is_test: cot.test,
            objects,
        })
    }

    /// Encode into the supplied buffer. Returns the number of bytes written.
    pub fn encode(&self, params: &AppLayerParameters, out: &mut [u8]) -> Result<usize> {
        let header_len = params.header_size();
        let total_obj = self.objects.len();
        let vsq_count = u8::try_from(total_obj).map_err(|_| AsduError::TooManyObjects {
            declared: total_obj,
            max: 127,
        })?;
        let exact = encoded_len(params, self);
        if out.len() < exact {
            return Err(AsduError::BufferTooShort {
                need: exact,
                have: out.len(),
            });
        }

        out[0] = if matches!(self.type_id, TypeId::Undefined) {
            self.original_type_byte
        } else {
            self.type_id.to_wire()
        };
        out[1] = Vsq {
            is_sequence: self.is_sequence,
            count: vsq_count,
        }
        .encode();
        self.cot.encode(params.size_of_cot, &mut out[2..])?;
        let ca_off = 2 + params.size_of_cot as usize;
        self.common_address
            .encode(params.size_of_ca, &mut out[ca_off..])?;

        let mut cursor = header_len;
        for (i, obj) in self.objects.iter().enumerate() {
            if i == 0 || !self.is_sequence {
                Ioa(obj.ioa)
                    .encode(
                        params.size_of_ioa,
                        &mut out[cursor..cursor + params.ioa_size()],
                    )
                    .map_err(|_| AsduError::InvalidNumericField("IOA encode".into()))?;
                cursor += params.ioa_size();
            }
            // Body bytes (timestamp excluded).
            let body_len = obj.value.body_len();
            obj.value.encode(&mut out[cursor..cursor + body_len])?;
            cursor += body_len;
            // Trailing timestamp (if any). Strict-parsed `Raw` values
            // carry only the body, so the timestamp must be emitted
            // separately.
            if let Some(ts) = &obj.timestamp {
                let written = ts.encode(&mut out[cursor..cursor + ts.len()])?;
                cursor += written;
            }
        }
        Ok(cursor)
    }

    /// Encode into a [`bytes::BufMut`].
    pub fn encode_into(&self, params: &AppLayerParameters, buf: &mut impl BufMut) -> Result<usize> {
        let mut tmp = alloc::vec![0u8; 1024];
        let n = self.encode(params, &mut tmp)?;
        buf.put_slice(&tmp[..n]);
        Ok(n)
    }
}

/// Trailing-timestamp byte length for `type_byte`. Returns 0 if the type
/// has no timestamp suffix.
fn timestamp_len_for(type_byte: u8) -> usize {
    use fegrid_iec60870_core::timestamp_kind_for;
    match timestamp_kind_for(TypeId::from_wire(type_byte)) {
        Some(TimestampKind::Cp16) => 2,
        Some(TimestampKind::Cp24) => 3,
        Some(TimestampKind::Cp56) => 7,
        None => 0,
    }
}

/// Compute the encoded length of `asdu` without allocating an output buffer.
///
/// Walks every object's actual body length plus its optional trailing
/// timestamp suffix (CP16/CP24/CP56). For variable-length types like
/// `F_SG_NA_1` (125) the actual `data.len()` is used.
pub fn encoded_len(params: &AppLayerParameters, asdu: &Asdu) -> usize {
    let ioa_count = if asdu.is_sequence {
        1
    } else {
        asdu.objects.len()
    };
    let max_per_obj = asdu
        .objects
        .iter()
        .map(|o| o.value.body_len() + o.timestamp.as_ref().map_or(0, |t| t.len()))
        .max()
        .unwrap_or(0);
    params.header_size() + ioa_count * params.ioa_size() + asdu.objects.len() * max_per_obj
}

/// Convenience wrapper: parse with default parameters.
pub fn parse_default(input: &[u8]) -> Result<Asdu> {
    Asdu::parse(&AppLayerParameters::default(), input)
}

/// Convenience wrapper: lenient parse with default parameters.
pub fn parse_lenient_default(input: &[u8]) -> Result<Asdu> {
    Asdu::parse_lenient(&AppLayerParameters::default(), input)
}

/// Convenience wrapper: encode with default parameters into a `Vec`.
pub fn encode_to_vec(params: &AppLayerParameters, asdu: &Asdu) -> Result<Vec<u8>> {
    let mut buf = alloc::vec![0u8; encoded_len(params, asdu)];
    let n = asdu.encode(params, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}
