//! The answers of the conformance adapter (AXT `spec/conformance.md`, section 6).
//!
//! Behind the feature `conformance`, which only the crate `axt-conformance-adapter` turns on.
//! It is a test tool, not part of the public API.

use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

use crate::envelope::{self, Envelope, Kind, RecordRef};
use crate::error::{Error, ErrorCode};
use crate::schema::Schema;
use crate::value::Value;

/// The categories of `spec/conformance.md`, section 2.1, that the adapter answers. A category
/// is listed only once all of its vectors pass.
pub const IMPLEMENTED_CATEGORIES: &[&str] = &["encoding"];

/// The version of the vector file format the adapter reads.
pub const VECTOR_FORMAT: i64 = 1;

/// One operation of a vector: its input, its result or a rejection.
type Operation = fn(&Map<String, Json>) -> Result<Json, Failure>;

/// Why an operation has no result.
#[derive(Debug)]
pub enum Failure {
    /// The request cannot be read: a fault of the input, not of the library.
    BadRequest(String),
    /// The library rejected the input, or its store failed.
    Library(Error),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self::Library(e)
    }
}

/// The adapter: the categories it answers.
#[derive(Debug, Default)]
pub struct Adapter {
    /// Categories under construction that a local run asks for too (`--also <category>`);
    /// never set in CI.
    pub extra_categories: Vec<String>,
}

impl Adapter {
    /// Answers one request of the runner.
    #[must_use]
    pub fn answer(&self, request: &Json) -> Json {
        let Some(request) = request.as_object() else {
            return json!({"id": null, "failure": "the request is not a JSON object"});
        };
        let id = request.get("id").cloned().unwrap_or(Json::Null);
        let op = request.get("op").and_then(Json::as_str).unwrap_or_default();
        let input = request.get("input");
        if op == "hello" {
            let format = input.and_then(|i| i.get("format")).and_then(Json::as_i64);
            if format != Some(VECTOR_FORMAT) {
                return json!({
                    "id": id,
                    "failure": format!("vector format {format:?} is not {VECTOR_FORMAT}"),
                });
            }
            let mut categories: Vec<Json> =
                IMPLEMENTED_CATEGORIES.iter().map(|c| json!(c)).collect();
            categories.extend(self.extra_categories.iter().map(|c| json!(c)));
            return json!({
                "id": id,
                "output": {
                    "name": format!("axt-protocol (AXT {})", crate::AXT_VERSION),
                    "categories": categories,
                },
            });
        }
        let Some(operation) = operation(op) else {
            return json!({"id": id, "unsupported": true});
        };
        let Some(input) = input.and_then(Json::as_object) else {
            return json!({"id": id, "failure": "the input is not a JSON object"});
        };
        match operation(input) {
            Ok(output) => json!({"id": id, "output": output}),
            Err(Failure::BadRequest(message)) => json!({"id": id, "failure": message}),
            Err(Failure::Library(Error::Axt { code, field, .. })) => {
                let mut reject = Map::new();
                reject.insert("error".into(), json!(code.as_str()));
                if code == ErrorCode::ValueInvalid {
                    reject.insert("field".into(), json!(field));
                }
                json!({"id": id, "output": {"reject": reject}})
            }
            Err(Failure::Library(e @ Error::Store(_))) => {
                json!({"id": id, "failure": e.to_string()})
            }
        }
    }
}

/// The operation of a name, if the adapter performs it.
fn operation(op: &str) -> Option<Operation> {
    Some(match op {
        "fingerprint" => fingerprint,
        "decode_message" => decode_message,
        "decode_body" => decode_body,
        "encode_message" => encode_message,
        _ => return None,
    })
}

/// An accepted result.
fn accept(value: Json) -> Json {
    json!({"accept": value})
}

/// `fingerprint` (section 5.1): the Parsing Canonical Form and the fingerprint of a schema.
fn fingerprint(input: &Map<String, Json>) -> Result<Json, Failure> {
    let schema = Schema::parse(string(input, "schema")?)
        .map_err(|e| Failure::BadRequest(format!("not a schema: {e}")))?;
    Ok(accept(json!({
        "canonical_form": schema.canonical_form(),
        "fingerprint": hex(&schema.fingerprint().0),
    })))
}

/// `decode_message` (section 5.1): the envelope of a live message.
fn decode_message(input: &Map<String, Json>) -> Result<Json, Failure> {
    let envelope = envelope::decode_message(&bytes(input.get("message"))?)?;
    Ok(accept(json!({
        "format": envelope::ENVELOPE_FORMAT,
        "kind": envelope.kind.symbol(),
        "sender": hex(&envelope.sender),
        "record": envelope.record.map(|r| json!({"id": r.id, "version": r.version})),
        "body": hex(&envelope.body),
        "signature": hex(&envelope.signature),
    })))
}

/// `decode_body` (section 5.1): a body decoded with its kind's schema.
fn decode_body(input: &Map<String, Json>) -> Result<Json, Failure> {
    let kind = Kind::from_symbol(string(input, "kind")?)?;
    if kind.body_schema().is_none() {
        return Err(Failure::BadRequest(format!(
            "decode_body takes no {}",
            kind.symbol()
        )));
    }
    let value = envelope::decode_body(kind, &bytes(input.get("body"))?)?;
    Ok(accept(json!({"value": value_json(&value)})))
}

/// `encode_message` (section 5.1): the live message of an envelope.
fn encode_message(input: &Map<String, Json>) -> Result<Json, Failure> {
    let record = match input.get("record") {
        None | Some(Json::Null) => None,
        Some(record) => match (
            record.get("id").and_then(Json::as_str),
            record.get("version").and_then(Json::as_i64),
        ) {
            (Some(id), Some(version)) => Some(RecordRef {
                id: id.into(),
                version,
            }),
            _ => {
                return Err(Failure::BadRequest(
                    "record is neither null nor an id and a version".into(),
                ));
            }
        },
    };
    let format = input.get("format").and_then(Json::as_i64);
    if format != Some(i64::from(envelope::ENVELOPE_FORMAT)) {
        return Err(Failure::BadRequest(format!("format {format:?} is not 1")));
    }
    let message = envelope::encode_message(&Envelope {
        kind: Kind::from_symbol(string(input, "kind")?)?,
        sender: sized(input, "sender")?,
        record,
        body: bytes(input.get("body"))?,
        signature: sized(input, "signature")?,
    })?;
    Ok(accept(json!({"message": hex(&message)})))
}

/// The member `name` of the input as a string.
fn string<'a>(input: &'a Map<String, Json>, name: &str) -> Result<&'a str, Failure> {
    input
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| Failure::BadRequest(format!("{name} is not a string")))
}

/// The member `name` of the input as Bytes of exactly `N` bytes.
fn sized<const N: usize>(input: &Map<String, Json>, name: &str) -> Result<[u8; N], Failure> {
    let value = bytes(input.get(name))?;
    value
        .as_slice()
        .try_into()
        .map_err(|_| Failure::BadRequest(format!("{name} has {} bytes, not {N}", value.len())))
}

/// Bytes in either form of `spec/conformance.md`, section 3.2.
fn bytes(value: Option<&Json>) -> Result<Vec<u8>, Failure> {
    match value {
        Some(Json::String(text)) => unhex(text),
        Some(Json::Object(form)) => {
            let deflated = form.get("deflate").and_then(Json::as_str);
            let length = form
                .get("length")
                .and_then(Json::as_u64)
                .and_then(|l| usize::try_from(l).ok());
            let digest = form.get("sha256").and_then(Json::as_str);
            let (Some(deflated), Some(length), Some(digest)) = (deflated, length, digest) else {
                return Err(Failure::BadRequest(
                    "bytes need deflate, length and sha256".into(),
                ));
            };
            // Inflating stops at the length given, so no input inflates beyond it.
            let inflated =
                miniz_oxide::inflate::decompress_to_vec_with_limit(&unhex(deflated)?, length)
                    .map_err(|e| Failure::BadRequest(format!("the bytes do not inflate: {e}")))?;
            if inflated.len() != length || hex(&Sha256::digest(&inflated)) != digest {
                return Err(Failure::BadRequest(
                    "the inflated bytes do not match length and sha256".into(),
                ));
            }
            Ok(inflated)
        }
        _ => Err(Failure::BadRequest(
            "bytes are neither a hex string nor deflated".into(),
        )),
    }
}

/// The bytes of a string of hexadecimal digits.
fn unhex(text: &str) -> Result<Vec<u8>, Failure> {
    let bad = || Failure::BadRequest("bytes are no hex string of even length".into());
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return Err(bad());
    }
    let (pairs, _) = digits.as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair.as_slice())
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .ok_or_else(bad)
        })
        .collect()
}

/// Bytes as lower-case hexadecimal digits.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a String cannot fail.
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A decoded value in the JSON form of `spec/conformance.md`, section 3.3.
fn value_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Boolean(b) => json!(b),
        Value::Int(i) => json!(i),
        Value::Long(l) => json!(l),
        // The shortest decimal that reads back to the float, not to its widening.
        Value::Float(f) => f
            .to_string()
            .parse::<f64>()
            .ok()
            .map_or(Json::Null, |d| json!(d)),
        Value::Double(d) => json!(d),
        Value::Bytes(b) | Value::Fixed(b) => json!(hex(b)),
        Value::String(s) => json!(s),
        Value::Enum { symbol, .. } => json!(symbol),
        Value::Array(items) => Json::Array(items.iter().map(value_json).collect()),
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), value_json(v)))
                .collect(),
        ),
        Value::Record(fields) => Json::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), value_json(v)))
                .collect(),
        ),
        Value::Union { branch, value, .. } => json!({ branch.as_str(): value_json(value) }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(op: &str, input: Json) -> Json {
        Adapter::default().answer(&json!({"id": "t", "op": op, "input": input}))
    }

    #[test]
    fn hello_names_the_encoding_category() {
        let answer = ask("hello", json!({"format": 1}));
        assert_eq!(answer["output"]["categories"], json!(["encoding"]));
    }

    #[test]
    fn a_fingerprint_is_its_eight_bytes_in_little_endian_order() {
        let answer = ask("fingerprint", json!({"schema": "\"null\""}));
        assert_eq!(
            answer["output"],
            json!({"accept": {"canonical_form": "\"null\"", "fingerprint": "8a8f25cce724dd63"}})
        );
        assert!(
            ask("fingerprint", json!({"schema": "{"}))
                .get("failure")
                .is_some()
        );
    }

    #[test]
    fn a_rejection_names_its_code_and_a_field_only_for_value_invalid() {
        let answer = ask("decode_message", json!({"message": "c301"}));
        assert_eq!(
            answer["output"],
            json!({"reject": {"error": "INVALID_MESSAGE"}})
        );
        let answer = ask("decode_body", json!({"kind": "DATA", "body": ""}));
        assert!(answer.get("failure").is_some());
    }

    #[test]
    fn bytes_are_read_in_both_forms() {
        assert_eq!(bytes(Some(&json!("00ff"))).unwrap(), [0, 255]);
        assert!(bytes(Some(&json!("0"))).is_err());
        assert!(bytes(Some(&json!("zz"))).is_err());
        let data = vec![7u8; 1000];
        let deflated = miniz_oxide::deflate::compress_to_vec(&data, 6);
        let form = json!({
            "deflate": hex(&deflated),
            "length": 1000,
            "sha256": hex(&Sha256::digest(&data)),
        });
        assert_eq!(bytes(Some(&form)).unwrap(), data);
        let mut short = form.clone();
        short["length"] = json!(999);
        assert!(bytes(Some(&short)).is_err());
        let mut wrong = form;
        wrong["sha256"] = json!(hex(&[0; 32]));
        assert!(bytes(Some(&wrong)).is_err());
    }

    #[test]
    fn a_union_of_several_branches_is_written_under_the_branch_name() {
        let value = Value::Union {
            index: 1,
            branch: "axt.StringField".into(),
            value: Box::new(Value::Record(vec![(
                "multiline".into(),
                Value::Boolean(false),
            )])),
        };
        assert_eq!(
            value_json(&value),
            json!({"axt.StringField": {"multiline": false}})
        );
        assert_eq!(value_json(&Value::Float(0.1)), json!(0.1));
    }
}
