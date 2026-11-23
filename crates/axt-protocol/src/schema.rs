//! Avro schemas, their Parsing Canonical Form and their fingerprints (AXT
//! `spec/envelope.md`, section 5).

use std::fmt;

use crate::avro;
use crate::error::{Error, ErrorCode};
use crate::value::Value;

/// The CRC-64-AVRO fingerprint of a schema: its 8 bytes in little-endian order, as a
/// single-object encoding writes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 8]);

impl Fingerprint {
    /// The CRC-64-AVRO of `data`, such as of a schema's Parsing Canonical Form.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        Self(crc64_avro(data).to_le_bytes())
    }
}

impl fmt::Display for Fingerprint {
    /// The bytes in lower-case hexadecimal, such as `8a8f25cce724dd63` for `"null"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// The CRC-64-AVRO (Rabin) fingerprint of the Avro specification.
fn crc64_avro(data: &[u8]) -> u64 {
    const EMPTY: u64 = 0xc15d_213a_a4d7_a795;
    let mut fp = EMPTY;
    for &byte in data {
        fp ^= u64::from(byte);
        for _ in 0..8 {
            // The polynomial when the bit shifted out is set, nothing otherwise.
            let mask = 0u64.wrapping_sub(fp & 1);
            fp = fp.wrapping_shr(1) ^ (EMPTY & mask);
        }
    }
    fp
}

/// An Avro schema, read without its logical types: its values are those of the
/// underlying types, which leaves its Parsing Canonical Form and fingerprint as they are.
#[derive(Debug, Clone)]
pub struct Schema {
    avro: apache_avro::Schema,
    canonical_form: String,
    fingerprint: Fingerprint,
}

impl Schema {
    /// Parses the JSON text of a schema.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::DoesNotResolve`] for a text that is not JSON or not an Avro schema.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let avro = avro::parse(text).map_err(|e| Error::axt(ErrorCode::DoesNotResolve, e))?;
        let canonical_form =
            avro::canonical_form(&avro).map_err(|e| Error::axt(ErrorCode::DoesNotResolve, e))?;
        let fingerprint = Fingerprint::of(canonical_form.as_bytes());
        Ok(Self {
            avro,
            canonical_form,
            fingerprint,
        })
    }

    /// The Parsing Canonical Form.
    #[must_use]
    pub fn canonical_form(&self) -> &str {
        &self.canonical_form
    }

    /// The CRC-64-AVRO fingerprint of the Parsing Canonical Form.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Decodes the single-object encoding of one datum of this schema that fills
    /// `bytes` exactly; the text says why it does not.
    pub(crate) fn decode_single_object(&self, bytes: &[u8]) -> Result<Value, String> {
        let (fingerprint, payload) =
            avro::split_single_object(bytes).ok_or("no single-object encoding")?;
        if fingerprint != self.fingerprint.0 {
            return Err(format!(
                "the fingerprint {} is not that of the schema, {}",
                Fingerprint(fingerprint),
                self.fingerprint
            ));
        }
        avro::decode(&self.avro, payload)
    }

    /// Decodes one datum of this schema, without a single-object header, that fills
    /// `bytes` exactly; the text says why it does not.
    pub(crate) fn decode_datum(&self, bytes: &[u8]) -> Result<Value, String> {
        avro::decode(&self.avro, bytes)
    }

    /// The Avro binary encoding of `value` as a datum of this schema.
    pub(crate) fn encode_datum(&self, value: &Value) -> Result<Vec<u8>, String> {
        avro::encode(&self.avro, value)
    }

    /// The datum of this schema for `json`, a value in the form of
    /// `spec/conformance.md`, section 3.3.
    pub(crate) fn datum_of_json(&self, json: &serde_json::Value) -> Result<Value, String> {
        avro::from_json(&self.avro, json)
    }

    /// The path of the first problem in `value`, a datum of this schema at `path`, that
    /// `rule` finds in the records and arrays of records of the schema.
    pub(crate) fn first_problem(
        &self,
        value: &Value,
        path: &str,
        rule: &dyn Fn(avro::Met<'_>, &Value, &str) -> avro::Verdict,
    ) -> Result<Option<String>, String> {
        avro::first_problem(&self.avro, value, path, rule)
    }

    /// The single-object encoding of `value` as a datum of this schema.
    pub(crate) fn encode_single_object(&self, value: &Value) -> Result<Vec<u8>, String> {
        let payload = avro::encode(&self.avro, value)?;
        Ok(avro::single_object(self.fingerprint.0, &payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_fingerprints_of_the_avro_specification() {
        // The fingerprints the Avro specification lists for primitive schemas.
        for (text, hex) in [
            ("\"null\"", "8a8f25cce724dd63"),
            ("\"boolean\"", "64f7d4a478fc429f"),
            ("\"int\"", "8f5c393f1ad57572"),
        ] {
            let schema = Schema::parse(text).unwrap();
            assert_eq!(schema.canonical_form(), text);
            assert_eq!(schema.fingerprint().to_string(), hex);
        }
    }

    #[test]
    fn a_logical_type_leaves_the_canonical_form_as_it_is() {
        let schema = Schema::parse(r#"{"type":"string","logicalType":"uuid"}"#).unwrap();
        assert_eq!(schema.canonical_form(), "\"string\"");
        assert_eq!(schema.fingerprint().to_string(), "c70345637248018f");
    }

    #[test]
    fn the_canonical_form_drops_docs_and_qualifies_names() {
        let schema = Schema::parse(
            r#"{"type": "record", "name": "Memo", "namespace": "com.example", "doc": "x",
                "fields": [{"name": "text", "type": "string", "doc": "y"},
                           {"name": "again", "type": {"type": "fixed", "name": "F", "size": 2}},
                           {"name": "more", "type": "F"}]}"#,
        )
        .unwrap();
        assert_eq!(
            schema.canonical_form(),
            r#"{"name":"com.example.Memo","type":"record","fields":[{"name":"text","type":"string"},{"name":"again","type":{"name":"com.example.F","type":"fixed","size":2}},{"name":"more","type":"com.example.F"}]}"#
        );
    }

    #[test]
    fn a_text_that_is_no_schema_does_not_resolve() {
        for text in ["{", r#"{"type":"nothing"}"#] {
            let e = Schema::parse(text).unwrap_err();
            assert_eq!(e.code(), Some(ErrorCode::DoesNotResolve));
        }
    }

    #[test]
    fn odd_attributes_never_panic() {
        // Attributes that the canonical form reads as numbers, where a type has none.
        for text in [
            r#"{"type":"record","name":"R","fields":[],"size":"x"}"#,
            r#"{"type":"array","items":"int","precision":1.5}"#,
            r#"{"type":"enum","name":"E","symbols":["A"],"scale":{}}"#,
            r#"{"type":"map","values":"int","size":-1}"#,
            r#"{"type":"fixed","name":"F","size":"2"}"#,
            r#"{"type":"bytes","precision":"p","scale":"s"}"#,
        ] {
            let _ = Schema::parse(text);
        }
    }

    #[test]
    fn a_single_object_of_another_schema_is_not_decoded() {
        let long = Schema::parse("\"long\"").unwrap();
        let int = Schema::parse("\"int\"").unwrap();
        let bytes = long.encode_single_object(&Value::Long(3)).unwrap();
        assert_eq!(long.decode_single_object(&bytes).unwrap(), Value::Long(3));
        assert!(int.decode_single_object(&bytes).is_err());
    }
}
