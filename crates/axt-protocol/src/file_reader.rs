//! Reading an AXT file: the whole file is checked before any record of it is applied
//! (AXT `spec/transports.md`, section 2.2; `spec/keys.md`, section 2.5;
//! `spec/envelope.md`, section 4).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use serde_json::Value as Json;
use sha2::{Digest, Sha256};

use crate::container::{Container, rejected};
use crate::device_sets::{DeviceChange, Key};
use crate::ed25519::verify_strict;
use crate::envelope::{Envelope, Kind, decode_body, decode_message, envelope_fingerprint};
use crate::error::{Error, ErrorCode};
use crate::manifest::fit;
use crate::record_decoder::decode_record;
use crate::records::{
    Applied, ElementMerge, HeldRecord, Outcome, RecordKind, RecordMessage, RecordPolicy,
    apply_record_message, element_merge_of, record_key,
};
use crate::schema::Schema;
use crate::schemas::axt_schema;
use crate::signing::verify_live_message;
use crate::type_description::TypeDescription;
use crate::value::Value;

/// The prefix of the bytes the header signature of a file covers.
const HEADER_PREFIX: &[u8] = b"AXT-v1 file header\0";

/// The bytes the header signature of a file covers: the prefix, the key in `axt.sender`
/// and the SHA-256 of the value of `axt.schemas`, of no bytes without one.
pub(crate) fn file_header_signed_bytes(sender: &[u8], schemas: Option<&[u8]>) -> Vec<u8> {
    let digest = Sha256::digest(schemas.unwrap_or_default());
    [HEADER_PREFIX, sender, digest.as_slice()].concat()
}

/// The bytes of the metadata value of `key`, `length` bytes in lower-case hexadecimal.
fn unhex_meta<const N: usize>(value: Option<&Vec<u8>>, key: &str) -> Result<[u8; N], Error> {
    let value = value.ok_or_else(|| rejected(format!("the file has no {key}")))?;
    let not_hex = || rejected(format!("{key} is not {N} bytes in lower-case hexadecimal"));
    let (pairs, rest) = value.as_chunks::<2>();
    if !rest.is_empty() || pairs.len() != N {
        return Err(not_hex());
    }
    let digit = |d: u8| match d {
        b'0'..=b'9' => Some(d.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(d.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let bytes: Vec<u8> = pairs
        .iter()
        .map(|[h, l]| Some(digit(*h)?.wrapping_shl(4) | digit(*l)?))
        .collect::<Option<_>>()
        .ok_or_else(not_hex)?;
    bytes.as_slice().try_into().map_err(|_| not_hex())
}

/// One record message of a file, checked.
#[derive(Debug, Clone)]
pub(crate) struct FileMessage {
    pub(crate) envelope: Envelope,
}

impl FileMessage {
    /// The record the message is about; a checked record message has one.
    pub(crate) fn record(&self) -> (&str, i64) {
        self.envelope
            .record
            .as_ref()
            .map_or(("", 0), |r| (r.id.as_str(), r.version))
    }
}

/// A file that passed every check of the whole: its sender, the writer schemas of its
/// header, and its messages in their order.
#[derive(Debug, Clone)]
pub(crate) struct CheckedFile {
    /// The key in `axt.sender`.
    pub(crate) sender: Key,
    /// The types of `axt.schemas`, by the fingerprint of their derived schema.
    pub(crate) schemas: BTreeMap<[u8; 8], TypeDescription>,
    /// The `DEVICE_ADD` and `DEVICE_REMOVE` messages at its start, as live messages.
    pub(crate) chain: Vec<Vec<u8>>,
    /// The body of its `MANIFEST`, or `None`.
    pub(crate) manifest: Option<Vec<u8>>,
    /// Its record messages, `DATA`, `DELETE` and `WITHDRAW`.
    pub(crate) records: Vec<FileMessage>,
}

impl CheckedFile {
    /// The writer type of the `DATA` `message`; a checked file has it.
    pub(crate) fn writer_of(&self, message: &FileMessage) -> Option<&TypeDescription> {
        let (fingerprint, _) = crate::avro::split_single_object(&message.envelope.body)?;
        self.schemas.get(&fingerprint)
    }
}

/// Whether `kind` is that of a record message.
fn is_record_kind(kind: Kind) -> bool {
    matches!(kind, Kind::Data | Kind::Delete | Kind::Withdraw)
}

/// The types of the value of `axt.schemas`.
fn file_schemas(value: &[u8]) -> Result<BTreeMap<[u8; 8], TypeDescription>, Error> {
    let list: Json =
        serde_json::from_slice(value).map_err(|_| rejected("axt.schemas is no JSON"))?;
    let list = list
        .as_array()
        .ok_or_else(|| rejected("axt.schemas is no JSON array"))?;
    let mut schemas = BTreeMap::new();
    for item in list {
        let (Some(description), Some(schema)) = (
            item.as_object().and_then(|o| o.get("description")),
            item.as_object().and_then(|o| o.get("schema")),
        ) else {
            return Err(rejected("axt.schemas holds an entry without its members"));
        };
        let not_valid =
            |_| rejected("axt.schemas holds a description that is not valid, or no schema");
        let description = TypeDescription::from_json(description).map_err(not_valid)?;
        let schema = Schema::parse(&schema.to_string()).map_err(not_valid)?;
        if schema.canonical_form() != description.schema().canonical_form() {
            return Err(rejected(
                "a schema in axt.schemas is not its derived schema",
            ));
        }
        let fingerprint = description.fingerprint().0;
        if schemas.insert(fingerprint, description).is_some() {
            return Err(rejected("two schemas in axt.schemas have one fingerprint"));
        }
    }
    Ok(schemas)
}

/// Checks `file` as a whole (transports.md, section 2.2, the rows that reject the whole
/// file).
///
/// # Errors
///
/// `FILE_REJECTED` for a file rejected as a whole.
pub(crate) fn check_file(file: &[u8]) -> Result<CheckedFile, Error> {
    let container = Container::read(file)?;
    let metadata = &container.metadata;
    let avro_schema = metadata
        .get("avro.schema")
        .ok_or_else(|| rejected("the file has no avro.schema"))?;
    let avro_schema =
        std::str::from_utf8(avro_schema).map_err(|_| rejected("avro.schema is no UTF-8"))?;
    let envelope =
        axt_schema("axt.Envelope").ok_or_else(|| rejected("the envelope schema is missing"))?;
    let format_1 = Schema::parse(avro_schema)
        .map_err(|_| rejected("avro.schema is no schema"))?
        .canonical_form()
        == envelope.canonical_form();
    if !format_1 {
        return Err(rejected("avro.schema is not the envelope of format 1"));
    }
    let sender: Key = unhex_meta(metadata.get("axt.sender"), "axt.sender")?;
    let signature: [u8; 64] = unhex_meta(metadata.get("axt.signature"), "axt.signature")?;
    let schemas_value = metadata.get("axt.schemas").map(Vec::as_slice);
    if !verify_strict(
        &sender,
        &file_header_signed_bytes(&sender, schemas_value),
        &signature,
    ) {
        return Err(rejected("the header signature does not verify"));
    }
    let schemas = match schemas_value {
        Some(value) => file_schemas(value)?,
        None => BTreeMap::new(),
    };
    let fingerprint = envelope_fingerprint()?.0;
    let mut chain = Vec::new();
    let mut manifest: Option<Vec<u8>> = None;
    let mut records = Vec::new();
    for datum in &container.datums {
        let message = [[0xc3, 0x01].as_slice(), &fingerprint, datum].concat();
        let envelope = decode_message(&message)
            .map_err(|e| rejected(format!("a datum is no valid message: {e}")))?;
        let kind = envelope.kind;
        let symbol = kind.symbol();
        let is_device = matches!(kind, Kind::DeviceAdd | Kind::DeviceRemove);
        if !is_device && kind != Kind::Manifest && !is_record_kind(kind) {
            return Err(rejected(format!("a file holds no {symbol}")));
        }
        let after_others = manifest.is_some() || !records.is_empty();
        if is_device && after_others {
            return Err(rejected(format!(
                "a {symbol} after another kind of message"
            )));
        }
        if kind == Kind::Manifest && after_others {
            return Err(rejected("a second MANIFEST, or one after a record message"));
        }
        if envelope.record.is_some() != is_record_kind(kind) {
            return Err(rejected(format!(
                "a {symbol} with a record where none belongs, or none"
            )));
        }
        if kind == Kind::Delete && !envelope.body.is_empty() {
            return Err(rejected("a DELETE with a body"));
        }
        if kind == Kind::Data {
            let (body_fingerprint, _) = crate::avro::split_single_object(&envelope.body)
                .ok_or_else(|| rejected("a DATA whose body is no single-object encoding"))?;
            if !schemas.contains_key(&body_fingerprint) {
                return Err(rejected("a DATA whose fingerprint is not in axt.schemas"));
            }
        } else if kind.body_schema().is_some() && decode_body(kind, &envelope.body).is_err() {
            return Err(rejected(format!("a {symbol} whose body is not its kind's")));
        }
        if !verify_live_message(&message, &envelope.sender) {
            return Err(rejected("a message whose signature does not verify"));
        }
        if is_device {
            if !DeviceChange::decode(&message).is_ok_and(|c| c.device_verifies()) {
                return Err(rejected(format!(
                    "a {symbol} fails step 2 of keys.md, section 5.5"
                )));
            }
            chain.push(message);
            continue;
        }
        if envelope.sender != sender {
            return Err(rejected("a message of another sender than axt.sender"));
        }
        if kind == Kind::Manifest {
            manifest = Some(envelope.body);
        } else {
            records.push(FileMessage { envelope });
        }
    }
    Ok(CheckedFile {
        sender,
        schemas,
        chain,
        manifest,
        records,
    })
}

/// The reader of a file: its own manifest, its reader schemas, and the keys of its own
/// set, by which it takes a `WITHDRAW`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FileReader<'a> {
    /// The reader's own manifest, decoded.
    pub(crate) manifest: &'a Value,
    /// Its reader schemas by full name, as texts.
    pub(crate) readers: &'a BTreeMap<String, String>,
    /// The current keys of its own set.
    pub(crate) current: &'a BTreeSet<Key>,
    /// The removed keys of its own set.
    pub(crate) removed: &'a BTreeSet<Key>,
}

/// What a reader did with one record message of a file: its outcome, or why it was not
/// applied (`spec/transports.md`, section 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordResult {
    /// The message was applied with this outcome.
    Outcome(Outcome),
    /// A `WITHDRAW` to an app that is not this one, which leaves the file standing.
    Ignored,
    /// A `DATA` of a type that does not fit the app's manifest.
    DoesNotFit,
    /// The file's sender is a removed key, so that nothing of it is applied.
    SenderRemoved,
    /// The message was rejected with this code, such as `RECORD_ID_INVALID`,
    /// `VERSION_INVALID`, `TYPE_CHANGED`, `DOES_NOT_RESOLVE`, `UNDECODABLE` or
    /// `VALUE_INVALID`.
    Rejected(ErrorCode),
}

impl RecordResult {
    /// The result as the specification writes it, such as `APPLIED` or `DOES_NOT_FIT`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outcome(outcome) => outcome.as_str(),
            Self::Ignored => "IGNORED",
            Self::DoesNotFit => "DOES_NOT_FIT",
            Self::SenderRemoved => "SENDER_REMOVED",
            Self::Rejected(code) => code.as_str(),
        }
    }
}

impl fmt::Display for RecordResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a reader did with one record message of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecordResult {
    /// The record's id, as its sender wrote it.
    pub id: String,
    /// The message's version.
    pub version: i64,
    /// The outcome, or why it was not applied.
    pub result: RecordResult,
}

/// One record message read: what the reader did with it, and for an applied message what
/// the receiver holds now.
#[derive(Debug, Clone)]
pub(crate) struct ReadRecord {
    pub(crate) result: FileRecordResult,
    pub(crate) applied: Option<Applied>,
}

/// What a `DATA` is to the reader: its type, its value and what merges per element; or
/// why it is not applied.
fn read_data(
    file: &CheckedFile,
    message: &FileMessage,
    reader: FileReader<'_>,
    held: Option<&HeldRecord>,
) -> Result<(String, Value, ElementMerge), RecordResult> {
    let writer = file
        .writer_of(message)
        .ok_or(RecordResult::Rejected(ErrorCode::SchemaUnknown))?;
    let type_name = writer.name().to_owned();
    if held
        .and_then(|h| h.type_name.as_deref())
        .is_some_and(|held_type| held_type != type_name)
    {
        return Err(RecordResult::Rejected(ErrorCode::TypeChanged));
    }
    let code = |e: Error| RecordResult::Rejected(e.code().unwrap_or(ErrorCode::Undecodable));
    if !fit(reader.manifest, writer.schema_text(), &[])
        .map_err(code)?
        .fits
    {
        return Err(RecordResult::DoesNotFit);
    }
    let reader_schema = reader
        .readers
        .get(&type_name)
        .map(|text| Schema::parse(text))
        .transpose()
        .map_err(code)?;
    let value = decode_record(
        writer.schema(),
        reader_schema.as_ref(),
        &message.envelope.body,
        true,
    )
    .map_err(code)?;
    let readers = reader
        .readers
        .iter()
        .map(|(name, text)| Ok((name.clone(), Schema::parse(text)?)))
        .collect::<Result<HashMap<_, _>, Error>>()
        .map_err(code)?;
    let elements = element_merge_of(
        reader_schema.as_ref().unwrap_or(writer.schema()),
        file.schemas.values().map(TypeDescription::schema),
        readers,
    );
    Ok((type_name, value, elements))
}

/// Reads the records of `file` as `reader`, with what it holds of the sender's records in
/// `held` by record key and its user's values in `current`. Applies each record message
/// by the version rule, and leaves the rest unapplied with the reason (transports.md,
/// section 2.2).
pub(crate) fn read_file_records(
    file: &CheckedFile,
    reader: FileReader<'_>,
    held: &mut HashMap<String, HeldRecord>,
    current: &mut HashMap<String, Option<Value>>,
    policy: &RecordPolicy,
) -> Vec<ReadRecord> {
    let mut results = Vec::new();
    for message in &file.records {
        let (id, version) = message.record();
        let result = |result: RecordResult| ReadRecord {
            result: FileRecordResult {
                id: id.to_owned(),
                version,
                result,
            },
            applied: None,
        };
        let Some(key) = record_key(id) else {
            results.push(result(RecordResult::Rejected(ErrorCode::RecordIdInvalid)));
            continue;
        };
        if version < 1 {
            results.push(result(RecordResult::Rejected(ErrorCode::VersionInvalid)));
            continue;
        }
        let mut data = None;
        let kind = match message.envelope.kind {
            Kind::Withdraw => {
                let to = decode_body(Kind::Withdraw, &message.envelope.body)
                    .ok()
                    .and_then(|body| match body.field("to") {
                        Some(Value::Fixed(to)) => Key::try_from(to.as_slice()).ok(),
                        _ => None,
                    });
                if !to
                    .is_some_and(|to| reader.current.contains(&to) || reader.removed.contains(&to))
                {
                    results.push(result(RecordResult::Ignored));
                    continue;
                }
                RecordKind::Withdraw
            }
            Kind::Delete => RecordKind::Delete,
            _ => match read_data(file, message, reader, held.get(&key)) {
                Ok(read) => {
                    data = Some(read);
                    RecordKind::Data
                }
                Err(why) => {
                    results.push(result(why));
                    continue;
                }
            },
        };
        let default_elements = ElementMerge::default();
        let (type_name, value, elements) = match &data {
            Some((type_name, value, elements)) => (Some(type_name.as_str()), Some(value), elements),
            None => (None, None, &default_elements),
        };
        let applied = apply_record_message(
            held.get(&key),
            current.get(&key).and_then(Option::as_ref),
            RecordMessage {
                kind,
                version,
                type_name,
                value,
            },
            policy,
            elements,
        );
        match applied {
            Ok(applied) => {
                held.insert(key.clone(), applied.held.clone());
                current.insert(key, applied.value.clone());
                let mut read = result(RecordResult::Outcome(applied.outcome));
                read.applied = Some(applied);
                results.push(read);
            }
            Err(e) => results.push(result(RecordResult::Rejected(
                e.code().unwrap_or(ErrorCode::InvalidMessage),
            ))),
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::container::write_container;
    use crate::device_sets::fixtures::{
        TestKey, device_add, device_add_with, signed_message, tampered,
    };
    use crate::ed25519::sign;
    use crate::envelope::{RecordRef, encode_message};
    use crate::records::HeldState;
    use crate::schemas::axt_schema_text;
    use crate::signing::signed_bytes_of_live_message;
    use crate::value::hex;

    const ID: &str = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80";

    /// org.example.Memo, of one required text.
    fn memo_type() -> TypeDescription {
        TypeDescription::from_json(&json!({
            "name": "memo", "doc": "A memo.", "texts": {},
            "kind": {"axt.ObjectField": {"name": "org.example.Memo", "version": 1, "fields": [
                {"name": "text", "doc": "The text.", "texts": {}, "required": true,
                 "kind": {"axt.StringField": {}}},
            ]}},
        }))
        .unwrap()
    }

    /// The entry of Memo in `axt.schemas`.
    fn memo_entry() -> Json {
        let memo = memo_type();
        json!({
            "description": memo.to_json(),
            "schema": serde_json::from_str::<Json>(memo.schema_text()).unwrap(),
        })
    }

    fn memo_body(text: &str) -> Vec<u8> {
        memo_type()
            .schema()
            .encode_single_object(&Value::Record(vec![(
                "text".into(),
                Value::String(text.into()),
            )]))
            .unwrap()
    }

    fn record(signer: &TestKey, kind: Kind, id: &str, version: i64, body: Vec<u8>) -> Vec<u8> {
        let mut message = encode_message(&Envelope {
            kind,
            sender: signer.public,
            record: Some(RecordRef {
                id: id.into(),
                version,
            }),
            body,
            signature: [0; 64],
        })
        .unwrap();
        let signature = sign(
            &signer.seed,
            &signed_bytes_of_live_message(&message).unwrap(),
        );
        let end = message.len() - 64;
        message[end..].copy_from_slice(&signature);
        message
    }

    /// A file of `messages` by `sender`, with `schemas` as `axt.schemas` (Memo by
    /// default), and the metadata of `overrides` in place of the file's (`None` removes
    /// one).
    fn file_of(
        sender: &TestKey,
        messages: &[Vec<u8>],
        schemas: Option<Vec<u8>>,
        overrides: &[(&str, Option<Vec<u8>>)],
    ) -> Vec<u8> {
        let signature = sign(
            &sender.seed,
            &file_header_signed_bytes(&sender.public, schemas.as_deref()),
        );
        let mut metadata: Vec<(&str, Vec<u8>)> = vec![(
            "avro.schema",
            axt_schema_text("axt.Envelope").unwrap().as_bytes().to_vec(),
        )];
        if let Some(schemas) = schemas {
            metadata.push(("axt.schemas", schemas));
        }
        metadata.push(("axt.sender", hex(&sender.public).into_bytes()));
        metadata.push(("axt.signature", hex(&signature).into_bytes()));
        for (key, value) in overrides {
            metadata.retain(|(k, _)| k != key);
            if let Some(value) = value {
                metadata.push((key, value.clone()));
            }
        }
        let datums: Vec<Vec<u8>> = messages.iter().map(|m| m[10..].to_vec()).collect();
        write_container(&metadata, &datums, [0; 16], false)
    }

    fn memo_schemas() -> Option<Vec<u8>> {
        Some(json!([memo_entry()]).to_string().into_bytes())
    }

    fn is_rejected(result: Result<CheckedFile, Error>) -> bool {
        result.is_err_and(|e| e.code() == Some(ErrorCode::FileRejected))
    }

    #[test]
    fn a_good_file_with_and_without_deflate() {
        let a = TestKey::named("file a");
        let message = record(&a, Kind::Data, ID, 1, memo_body("x"));
        for deflate in [false, true] {
            let file = file_of(&a, std::slice::from_ref(&message), memo_schemas(), &[]);
            let file = if deflate {
                let read = Container::read(&file).unwrap();
                let metadata: Vec<(&str, Vec<u8>)> = read
                    .metadata
                    .iter()
                    .filter(|(k, _)| *k != "avro.codec")
                    .map(|(k, v)| (k.as_str(), v.clone()))
                    .collect();
                write_container(&metadata, &read.datums, [1; 16], true)
            } else {
                file
            };
            let checked = check_file(&file).unwrap();
            assert_eq!(checked.records.len(), 1);
            assert_eq!(checked.sender, a.public);
            assert_eq!(
                checked.writer_of(&checked.records[0]).unwrap().name(),
                "org.example.Memo"
            );
        }
    }

    #[test]
    fn the_header_rules_reject_the_whole_file() {
        let a = TestKey::named("file a");
        let message = record(&a, Kind::Data, ID, 1, memo_body("x"));
        let upper = hex(&a.public).to_uppercase().into_bytes();
        for override_ in [
            ("avro.schema", None),
            ("avro.schema", Some(b"\"int\"".to_vec())),
            ("avro.schema", Some(vec![0xff])),
            ("avro.schema", Some(b"{".to_vec())),
            ("axt.sender", None),
            ("axt.sender", Some(upper)),
            ("axt.signature", Some("00".repeat(64).into_bytes())),
        ] {
            let file = file_of(
                &a,
                std::slice::from_ref(&message),
                memo_schemas(),
                std::slice::from_ref(&override_),
            );
            assert!(is_rejected(check_file(&file)), "{override_:?}");
        }
        let entry = memo_entry();
        for schemas in [
            "[".to_owned(),
            "{}".to_owned(),
            "[1]".to_owned(),
            json!([entry, entry]).to_string(),
            json!([{"description": entry["description"]}]).to_string(),
            json!([{"description": {}, "schema": entry["schema"]}]).to_string(),
            json!([{"description": entry["description"], "schema": "int"}]).to_string(),
            json!([{"description": entry["description"], "schema": "string"}]).to_string(),
        ] {
            let file = file_of(
                &a,
                std::slice::from_ref(&message),
                Some(schemas.clone().into_bytes()),
                &[],
            );
            assert!(is_rejected(check_file(&file)), "{schemas}");
        }
        assert!(is_rejected(check_file(&file_of(
            &a,
            std::slice::from_ref(&message),
            None,
            &[]
        ))));
        let mut bad_utf8 = memo_schemas().unwrap();
        bad_utf8[0] = 0xff;
        assert!(is_rejected(check_file(&file_of(
            &a,
            &[message],
            Some(bad_utf8),
            &[]
        ))));
    }

    #[test]
    fn the_message_rules_reject_the_whole_file() {
        let (a, b) = (TestKey::named("file a"), TestKey::named("file b"));
        let data = record(&a, Kind::Data, ID, 1, memo_body("x"));
        let manifest_body = axt_schema("axt.Manifest")
            .unwrap()
            .encode_single_object(&Value::Record(vec![
                ("revision".into(), Value::Long(1)),
                ("app_name".into(), Value::String("a".into())),
                ("app_url".into(), Value::Null),
                ("formats".into(), Value::Array(vec![Value::Int(1)])),
                ("takes".into(), Value::Array(vec![])),
                ("any_type".into(), Value::Null),
                ("sends".into(), Value::Null),
                ("encryption_key".into(), Value::Null),
                ("relay".into(), Value::Null),
            ]))
            .unwrap();
        let manifest = signed_message(&a, Kind::Manifest, manifest_body);
        let resync = axt_schema("axt.Resync")
            .unwrap()
            .encode_single_object(&Value::Record(vec![(
                "to".into(),
                Value::Fixed(b.public.to_vec()),
            )]))
            .unwrap();
        let string = Schema::parse("\"string\"")
            .unwrap()
            .encode_single_object(&Value::String("x".into()))
            .unwrap();
        let mut no_envelope = data.clone();
        no_envelope[10] = 4;
        let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
            (
                "a kind a file does not hold",
                vec![signed_message(&a, Kind::Resync, resync)],
            ),
            (
                "a device change after a record",
                vec![data.clone(), device_add(&a, &b)],
            ),
            (
                "a second manifest",
                vec![manifest.clone(), manifest.clone()],
            ),
            (
                "a manifest after a record",
                vec![data.clone(), manifest.clone()],
            ),
            (
                "a DATA without a record",
                vec![signed_message(&a, Kind::Data, memo_body("x"))],
            ),
            (
                "a DELETE with a body",
                vec![record(&a, Kind::Delete, ID, 2, memo_body("x"))],
            ),
            (
                "a DATA of no single-object body",
                vec![record(&a, Kind::Data, ID, 1, vec![0; 3])],
            ),
            (
                "a DATA of an unknown fingerprint",
                vec![record(&a, Kind::Data, ID, 1, string)],
            ),
            (
                "a manifest of another body",
                vec![signed_message(&a, Kind::Manifest, vec![0; 12])],
            ),
            ("a bad signature", vec![tampered(data.clone())]),
            (
                "a device change with a bad proof",
                vec![device_add_with(&a, &b, Some([0; 64]), None)],
            ),
            (
                "another sender",
                vec![record(&b, Kind::Data, ID, 1, memo_body("x"))],
            ),
            ("no envelope", vec![no_envelope]),
        ];
        for (why, messages) in cases {
            let file = file_of(&a, &messages, memo_schemas(), &[]);
            assert!(is_rejected(check_file(&file)), "{why}");
        }
        // A chain, then a manifest and the records, is a good file.
        let file = file_of(
            &a,
            &[device_add(&a, &b), manifest, data],
            memo_schemas(),
            &[],
        );
        let checked = check_file(&file).unwrap();
        assert_eq!(checked.chain.len(), 1);
        assert!(checked.manifest.is_some());
    }

    #[test]
    fn records_of_a_file_ids_versions_fit_withdrawals() {
        let (a, b) = (TestKey::named("file a"), TestKey::named("file b"));
        let manifest = Value::Record(vec![
            ("revision".into(), Value::Long(1)),
            ("app_name".into(), Value::String("r".into())),
            ("app_url".into(), Value::Null),
            ("formats".into(), Value::Array(vec![Value::Int(1)])),
            (
                "takes".into(),
                Value::Array(vec![Value::Record(vec![
                    ("type".into(), Value::String("org.example.Memo".into())),
                    ("min_version".into(), Value::Int(1)),
                    ("max_version".into(), Value::Null),
                    ("purpose".into(), Value::String("x".into())),
                    ("purpose_translations".into(), Value::Map(BTreeMap::new())),
                ])]),
            ),
            ("any_type".into(), Value::Null),
            ("sends".into(), Value::Null),
            ("encryption_key".into(), Value::Null),
            ("relay".into(), Value::Null),
        ]);
        let withdraw = axt_schema("axt.Withdraw")
            .unwrap()
            .encode_single_object(&Value::Record(vec![(
                "to".into(),
                Value::Fixed(b.public.to_vec()),
            )]))
            .unwrap();
        let file = check_file(&file_of(
            &a,
            &[
                record(&a, Kind::Data, "bad", 1, memo_body("x")),
                record(&a, Kind::Data, ID, 0, memo_body("x")),
                record(&a, Kind::Data, ID, 1, memo_body("x")),
                record(&a, Kind::Withdraw, ID, 2, withdraw),
                record(&a, Kind::Delete, ID, 3, Vec::new()),
            ],
            memo_schemas(),
            &[],
        ))
        .unwrap();
        let readers = BTreeMap::from([(
            "org.example.Memo".to_owned(),
            r#"{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"n","type":"int"}]}"#
                .to_owned(),
        )]);
        let none = BTreeSet::new();
        let codes = |reads: Vec<ReadRecord>| {
            reads
                .into_iter()
                .map(|r| r.result.result.as_str())
                .collect::<Vec<_>>()
        };
        let reader = FileReader {
            manifest: &manifest,
            readers: &readers,
            current: &none,
            removed: &none,
        };
        let results = read_file_records(
            &file,
            reader,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &RecordPolicy::default(),
        );
        assert_eq!(
            codes(results),
            [
                "RECORD_ID_INVALID",
                "VERSION_INVALID",
                "DOES_NOT_RESOLVE",
                "IGNORED",
                "APPLIED"
            ]
        );
        let own = BTreeSet::from([b.public]);
        let no_readers = BTreeMap::new();
        let reader = FileReader {
            manifest: &manifest,
            readers: &no_readers,
            current: &own,
            removed: &none,
        };
        let mut held = HashMap::from([(
            ID.to_owned(),
            HeldRecord {
                version: 0,
                state: HeldState::There,
                type_name: Some("org.example.Other".into()),
                taken: Some(Value::Record(vec![])),
                kept_against: None,
            },
        )]);
        let results = read_file_records(
            &file,
            reader,
            &mut held,
            &mut HashMap::new(),
            &RecordPolicy::default(),
        );
        assert_eq!(
            codes(results),
            [
                "RECORD_ID_INVALID",
                "VERSION_INVALID",
                "TYPE_CHANGED",
                "WITHDRAWN",
                "APPLIED"
            ]
        );
        assert_eq!(held[ID].state, HeldState::Tombstone);
        // A type that does not fit.
        let empty = Value::Record(vec![("takes".into(), Value::Array(vec![]))]);
        let reader = FileReader {
            manifest: &empty,
            readers: &no_readers,
            current: &own,
            removed: &none,
        };
        let results = read_file_records(
            &file,
            reader,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &RecordPolicy::default(),
        );
        assert_eq!(codes(results)[2], "DOES_NOT_FIT");
    }

    #[test]
    fn a_record_result_reads_as_the_specification_writes_it() {
        assert_eq!(RecordResult::Outcome(Outcome::Merged).to_string(), "MERGED");
        assert_eq!(RecordResult::SenderRemoved.as_str(), "SENDER_REMOVED");
        assert_eq!(
            RecordResult::Rejected(ErrorCode::Undecodable).as_str(),
            "UNDECODABLE"
        );
    }

    #[cfg(feature = "conformance")]
    fn manifest_body(formats: i32, any_type: bool) -> Vec<u8> {
        let any = if any_type {
            Value::Record(vec![
                ("purpose".into(), Value::String("Anything.".into())),
                ("purpose_translations".into(), Value::Map(BTreeMap::new())),
            ])
        } else {
            Value::Null
        };
        axt_schema("axt.Manifest")
            .unwrap()
            .encode_single_object(&Value::Record(vec![
                ("revision".into(), Value::Long(1)),
                ("app_name".into(), Value::String("a".into())),
                ("app_url".into(), Value::Null),
                ("formats".into(), Value::Array(vec![Value::Int(formats)])),
                ("takes".into(), Value::Array(vec![])),
                ("any_type".into(), any),
                ("sends".into(), Value::Null),
                ("encryption_key".into(), Value::Null),
                ("relay".into(), Value::Null),
            ]))
            .unwrap()
    }

    #[cfg(feature = "conformance")]
    #[test]
    fn the_adapter_reads_files() {
        use crate::device_sets::fixtures::device_remove;
        let (a, b) = (TestKey::named("file a"), TestKey::named("file b"));
        let body = manifest_body(2, true);
        let ask = |file: &[u8], keys: Json| {
            crate::conformance::Adapter::default().answer(&json!({
                "id": "f", "op": "read_file",
                "input": {"file": hex(file), "reader": {
                    "manifest": hex(&body), "readers": {}, "keys": keys}},
            }))["output"]
                .clone()
        };
        let file = file_of(
            &a,
            &[
                device_add(&a, &b),
                signed_message(&a, Kind::Manifest, body.clone()),
                record(&a, Kind::Data, ID, 1, memo_body("x")),
            ],
            memo_schemas(),
            &[],
        );
        let reply = &ask(&file, Json::Null)["accept"];
        assert_eq!(reply["manifest"], "invalid");
        assert_eq!(reply["chain"][0]["result"], "APPLIED");
        assert_eq!(reply["records"][0]["result"], "APPLIED");
        assert_eq!(
            ask(&[0; 4], Json::Null),
            json!({"reject": {"error": "FILE_REJECTED"}})
        );
        let removed = file_of(
            &b,
            &[
                device_add(&b, &a),
                device_remove(&a, &b),
                record(&b, Kind::Data, ID, 1, memo_body("x")),
            ],
            memo_schemas(),
            &[],
        );
        let reply = &ask(&removed, json!({"current": [], "removed": []}))["accept"];
        assert_eq!(reply["records"][0]["result"], "SENDER_REMOVED");
        assert_eq!(reply["manifest"], "none");
        let bad = crate::conformance::Adapter::default().answer(&json!({
            "id": "f", "op": "read_file",
            "input": {"file": "", "reader": {"manifest": hex(&body), "readers": 1}},
        }));
        assert!(bad["failure"].is_string());
    }

    #[cfg(feature = "conformance")]
    #[test]
    fn a_manifest_that_is_valid_is_used() {
        let a = TestKey::named("file a");
        let body = manifest_body(1, false);
        let file = file_of(
            &a,
            &[signed_message(&a, Kind::Manifest, body.clone())],
            None,
            &[],
        );
        let reply = crate::conformance::Adapter::default().answer(&json!({
            "id": "f", "op": "read_file",
            "input": {"file": hex(&file), "reader": {"manifest": hex(&body), "readers": {}}},
        }));
        assert_eq!(reply["output"]["accept"]["manifest"], "used");
    }
}
