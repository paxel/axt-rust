//! The answers of the conformance adapter (AXT `spec/conformance.md`, section 6).
//!
//! Behind the feature `conformance`, which only the crate `axt-conformance-adapter` turns on.
//! It is a test tool, not part of the public API.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

use crate::bricks::{self, Kind as Brick};
use crate::device_sets::{
    self, DeviceChange, DeviceSetReceiver, JoinAction, KeptRecord, Key, KnownSender, Member,
    RecordState,
};
use crate::ed25519;
use crate::envelope::{self, Envelope, Kind, RecordRef};
use crate::error::{Error, ErrorCode};
use crate::keys::{EncryptionSeed, SigningSeed};
use crate::record_decoder;
use crate::schema::Schema;
use crate::sealing;
use crate::signing;
use crate::type_description::TypeDescription;
use crate::value::Value;
use crate::zone_rules::{self, Anchor, DateTime, Duration, TzdbZoneRules, WallClock, Zoned};

/// The categories of `spec/conformance.md`, section 2.1, that the adapter answers. A category
/// is listed only once all of its vectors pass.
pub const IMPLEMENTED_CATEGORIES: &[&str] = &["encoding", "bricks", "types", "time", "keys"];

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
        "decode_record" => decode_record,
        "derive" => derive,
        "describe" => describe,
        "check_record" => check_record,
        "resolve_date_time" => resolve_date_time,
        "add_duration" => add_duration,
        "public_key" => public_key,
        "sign" => sign,
        "verify" => verify,
        "check_signing_key" => check_signing_key,
        "check_encryption_key" => check_encryption_key,
        "short_fingerprint" => short_fingerprint,
        "verify_message" => verify_message,
        "device_add" => device_add,
        "device_join" => device_join,
        "join_chain" => join_chain,
        "device_sets" => device_sets,
        "padded_length" => padded_length,
        "seal" => seal,
        "open" => open,
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

/// `decode_record` (sections 5.2 and 5.16): a record read with its writer schema, as the
/// reader schema when one is given.
fn decode_record(input: &Map<String, Json>) -> Result<Json, Failure> {
    let writer = Schema::parse(string(input, "writer_schema")?)?;
    let reader = match input.get("reader_schema") {
        None | Some(Json::Null) => None,
        Some(Json::String(text)) => Some(Schema::parse(text)?),
        Some(_) => {
            return Err(Failure::BadRequest(
                "reader_schema is neither a string nor null".into(),
            ));
        }
    };
    let value =
        record_decoder::decode_record(&writer, reader.as_ref(), &bytes(input.get("body"))?, true)?;
    Ok(accept(json!({"value": value_json(&value)})))
}

/// The valid description that the member `description` of the input encodes.
fn description(input: &Map<String, Json>) -> Result<TypeDescription, Failure> {
    let datum = bricks::decode_description(&bytes(input.get("description"))?)?;
    Ok(TypeDescription::from_datum(datum)?)
}

/// `derive` (section 5.16): the schema derived from a description.
fn derive(input: &Map<String, Json>) -> Result<Json, Failure> {
    let description = description(input)?;
    let schema = description.schema();
    Ok(accept(json!({
        "schema": description.schema_text(),
        "canonical_form": schema.canonical_form(),
        "fingerprint": hex(&schema.fingerprint().0),
    })))
}

/// `describe` (section 5.16): what a receiver shows of a type or of one of its fields.
fn describe(input: &Map<String, Json>) -> Result<Json, Failure> {
    let description = description(input)?;
    let languages = input
        .get("languages")
        .and_then(Json::as_array)
        .and_then(|l| {
            l.iter()
                .map(|tag| tag.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| Failure::BadRequest("languages is not a list of strings".into()))?;
    let root = description.root();
    match input.get("field") {
        None | Some(Json::Null) => match &root.kind {
            Brick::Object(object) => Ok(accept(bricks::describe_object(
                &root.texts,
                object,
                &languages,
            ))),
            _ => Err(Failure::BadRequest("the root is not an object".into())),
        },
        Some(Json::String(path)) => {
            let field = bricks::field_at(root, path)
                .ok_or_else(|| Failure::BadRequest(format!("no field {path}")))?;
            Ok(accept(bricks::describe_field(field, &languages)))
        }
        Some(_) => Err(Failure::BadRequest("field is not a string".into())),
    }
}

/// `check_record` (section 5.16): whether a record keeps the checks of its description.
fn check_record(input: &Map<String, Json>) -> Result<Json, Failure> {
    let description = description(input)?;
    bricks::check_record(&description, &bytes(input.get("body"))?)?;
    Ok(accept(json!({})))
}

/// `resolve_date_time` (section 5.12): a `DateTime` as a receiver with the zone rules of the
/// vectors takes it for a field with an anchor.
fn resolve_date_time(input: &Map<String, Json>) -> Result<Json, Failure> {
    let anchor = match input.get("anchor").and_then(Json::as_str) {
        Some("local") => Anchor::Local,
        Some("instant") => Anchor::Instant,
        other => return Err(Failure::BadRequest(format!("no anchor {other:?}"))),
    };
    let resolved = zone_rules::resolve_date_time(&TzdbZoneRules, &date_time(input)?, anchor)
        .ok_or_else(|| Failure::BadRequest("the reading is out of range".into()))?;
    Ok(accept(json!({"date_time": date_time_json(&resolved)})))
}

/// `add_duration` (section 5.12): a `DateTime` plus a `Duration`.
fn add_duration(input: &Map<String, Json>) -> Result<Json, Failure> {
    let duration = object(input, "duration")?;
    let duration = Duration {
        months: integer(duration, "months")?,
        days: integer(duration, "days")?,
        millis: integer(duration, "millis")?,
    };
    let sum = zone_rules::add_duration(&TzdbZoneRules, &date_time(input)?, duration)
        .ok_or_else(|| Failure::BadRequest("the sum is out of range".into()))?;
    Ok(accept(json!({"date_time": date_time_json(&sum)})))
}

/// A rejection with `code`, as an operation's result.
fn reject(code: ErrorCode) -> Failure {
    Failure::Library(Error::axt(code, code.as_str()))
}

/// `public_key` (section 5.5): the Ed25519 public key of a seed.
fn public_key(input: &Map<String, Json>) -> Result<Json, Failure> {
    let seed = SigningSeed::new(sized(input, "seed")?);
    Ok(accept(
        json!({"public_key": hex(&ed25519::public_key_of(&seed))}),
    ))
}

/// `sign` (section 5.5): the Ed25519 signature of data with a seed.
fn sign(input: &Map<String, Json>) -> Result<Json, Failure> {
    let seed = SigningSeed::new(sized(input, "seed")?);
    let signature = ed25519::sign(&seed, &bytes(input.get("data"))?);
    Ok(accept(json!({"signature": hex(&signature)})))
}

/// `verify` (section 5.5): the strict verification of a signature.
fn verify(input: &Map<String, Json>) -> Result<Json, Failure> {
    if ed25519::verify_strict(
        &bytes(input.get("public_key"))?,
        &bytes(input.get("data"))?,
        &bytes(input.get("signature"))?,
    ) {
        Ok(accept(json!({})))
    } else {
        Err(reject(ErrorCode::SignatureInvalid))
    }
}

/// `check_signing_key` (section 5.5): whether a public key passes steps 2 and 3.
fn check_signing_key(input: &Map<String, Json>) -> Result<Json, Failure> {
    if ed25519::is_point_of_order_l(&bytes(input.get("public_key"))?) {
        Ok(accept(json!({})))
    } else {
        Err(reject(ErrorCode::KeyInvalid))
    }
}

/// `check_encryption_key` (section 5.5): whether an X25519 key is not of small order.
fn check_encryption_key(input: &Map<String, Json>) -> Result<Json, Failure> {
    if sealing::is_small_order_encryption_key(&bytes(input.get("encryption_key"))?) {
        Err(reject(ErrorCode::EncryptionKeyInvalid))
    } else {
        Ok(accept(json!({})))
    }
}

/// `short_fingerprint` (section 5.5): the short fingerprint of a public key.
fn short_fingerprint(input: &Map<String, Json>) -> Result<Json, Failure> {
    let fingerprint = signing::short_fingerprint(&bytes(input.get("public_key"))?);
    Ok(accept(json!({"short_fingerprint": fingerprint})))
}

/// `verify_message` (section 5.5): whether a live message's signature verifies with its
/// sender.
fn verify_message(input: &Map<String, Json>) -> Result<Json, Failure> {
    let message = bytes(input.get("message"))?;
    let envelope = envelope::decode_message(&message)?;
    if signing::verify_live_message(&message, &envelope.sender) {
        Ok(accept(json!({})))
    } else {
        Err(reject(ErrorCode::SignatureInvalid))
    }
}

/// `device_add` (section 5.5): steps 1 and 2 of a `DEVICE_ADD`.
fn device_add(input: &Map<String, Json>) -> Result<Json, Failure> {
    let change = DeviceChange::decode(&bytes(input.get("message"))?)?;
    if !change.is_add() {
        return Err(Failure::BadRequest("not a DEVICE_ADD".into()));
    }
    if !change.signature_verifies() {
        return Err(reject(ErrorCode::SignatureInvalid));
    }
    if !change.device_verifies() {
        return Err(reject(ErrorCode::DeviceRejected));
    }
    Ok(accept(json!({
        "member": hex(&change.signer),
        "device": hex(&change.device),
    })))
}

/// A key of 32 bytes in hexadecimal digits.
fn key(value: &Json) -> Result<Key, Failure> {
    let text = value
        .as_str()
        .ok_or_else(|| Failure::BadRequest("a key is not a string".into()))?;
    unhex(text)?
        .as_slice()
        .try_into()
        .map_err(|_| Failure::BadRequest("a key is not 32 bytes".into()))
}

/// A list of keys.
fn keys(value: Option<&Json>) -> Result<BTreeSet<Key>, Failure> {
    value
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("keys are not a list of strings".into()))?
        .iter()
        .map(key)
        .collect()
}

/// `device_join` (section 5.5): what a member does with a `DEVICE_JOIN`.
fn device_join(input: &Map<String, Json>) -> Result<Json, Failure> {
    let message = bytes(input.get("message"))?;
    let member = object(input, "member")?;
    let member_key = key(member
        .get("key")
        .ok_or_else(|| Failure::BadRequest("member has no key".into()))?)?;
    let current = keys(member.get("current"))?;
    let removed = keys(member.get("removed"))?;
    let first = match input.get("first") {
        None | Some(Json::Null) => None,
        Some(first) => Some(key(first)?),
    };
    let member = Member {
        key: &member_key,
        current: &current,
        removed: &removed,
    };
    let action = device_sets::answer_device_join(&message, &member, first.as_ref())?;
    Ok(accept(json!({
        "device": hex(&envelope::decode_message(&message)?.sender),
        "action": match action {
            JoinAction::Ask => "ask",
            JoinAction::SendChain => "send_chain",
            JoinAction::Ignore => "ignore",
        },
    })))
}

/// A chain: a list of messages.
fn chain(value: Option<&Json>) -> Result<Vec<Vec<u8>>, Failure> {
    value
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("chain is not a list".into()))?
        .iter()
        .map(|message| bytes(Some(message)))
        .collect()
}

/// `join_chain` (section 5.5): whether a new device takes the chain it is sent.
fn join_chain(input: &Map<String, Json>) -> Result<Json, Failure> {
    let member = key(input.get("member").unwrap_or(&Json::Null))?;
    let device = key(input.get("device").unwrap_or(&Json::Null))?;
    if device_sets::takes_join_chain(&chain(input.get("chain"))?, &member, &device) {
        Ok(accept(json!({})))
    } else {
        Err(reject(ErrorCode::JoinInvalid))
    }
}

/// A known sender in the JSON form of the vectors.
fn known_sender(value: &Json) -> Result<KnownSender, Failure> {
    let value = value
        .as_object()
        .ok_or_else(|| Failure::BadRequest("a sender is not an object".into()))?;
    let records = value
        .get("records")
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("records is no list".into()))?
        .iter()
        .map(|record| {
            let record = record
                .as_object()
                .ok_or_else(|| Failure::BadRequest("a record is not an object".into()))?;
            let state = match record.get("state").and_then(Json::as_str) {
                Some("tombstone") => RecordState::Tombstone,
                _ => RecordState::There,
            };
            Ok((
                string(record, "id")?.to_owned(),
                KeptRecord {
                    version: integer(record, "version")?,
                    state,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Failure>>()?;
    Ok(KnownSender {
        name: string(value, "name")?.to_owned(),
        current: keys(value.get("current"))?,
        removed: keys(value.get("removed"))?,
        records,
    })
}

/// The receiver's senders in the JSON form of the vectors, sorted by name.
fn senders_json(receiver: &DeviceSetReceiver) -> Json {
    let mut senders: Vec<&KnownSender> = receiver.senders.iter().collect();
    senders.sort_by(|a, b| a.name.cmp(&b.name));
    let keys_json = |keys: &BTreeSet<Key>| keys.iter().map(|k| hex(k)).collect::<Vec<_>>();
    senders
        .into_iter()
        .map(|sender| {
            json!({
                "name": sender.name,
                "current": keys_json(&sender.current),
                "removed": keys_json(&sender.removed),
                "records": sender.records.iter().map(|(id, record)| json!({
                    "id": id,
                    "version": record.version,
                    "state": match record.state {
                        RecordState::There => "there",
                        RecordState::Tombstone => "tombstone",
                    },
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// `device_sets` (section 5.5): a receiver that takes chains of additions and removals.
fn device_sets(input: &Map<String, Json>) -> Result<Json, Failure> {
    let (Some(senders), Some(steps)) = (
        input.get("senders").and_then(Json::as_array),
        input.get("steps").and_then(Json::as_array),
    ) else {
        return Err(Failure::BadRequest(
            "senders and steps must be lists".into(),
        ));
    };
    let mut receiver = DeviceSetReceiver {
        senders: senders.iter().map(known_sender).collect::<Result<_, _>>()?,
        refused: keys(input.get("refused"))?,
    };
    let mut results = Vec::with_capacity(steps.len());
    for step in steps {
        let step = step
            .as_object()
            .ok_or_else(|| Failure::BadRequest("a step is no object".into()))?;
        let outcome = receiver.receive_chain(&chain(step.get("chain"))?);
        let step_key = match step.get("key") {
            None | Some(Json::Null) => None,
            Some(value) => Some(key(value)?),
        };
        results.push(json!({
            "results": outcome.into_iter().map(|r| r.code()).collect::<Vec<_>>(),
            "key_state": step_key.map(|k| receiver.state_of(&k).name()),
            "key_sender": step_key.and_then(|k| receiver.current_sender_of(&k).map(|s| s.name.clone())),
            "senders": senders_json(&receiver),
        }));
    }
    Ok(json!({"steps": results}))
}

/// `padded_length` (section 5.5): the padded length P(n).
fn padded_length(input: &Map<String, Json>) -> Result<Json, Failure> {
    let length = input
        .get("length")
        .and_then(Json::as_u64)
        .ok_or_else(|| Failure::BadRequest("length is no integer".into()))?;
    let padded = sealing::padded_length(length)
        .ok_or_else(|| Failure::BadRequest("the padded length is out of range".into()))?;
    Ok(accept(json!({"padded_length": padded})))
}

/// `seal` (section 5.5): a message sealed for an encryption key.
fn seal(input: &Map<String, Json>) -> Result<Json, Failure> {
    let sealed = sealing::seal(
        &bytes(input.get("message"))?,
        &sized(input, "encryption_key")?,
    )?;
    Ok(accept(json!({"sealed": hex(&sealed)})))
}

/// `open` (section 5.5): a sealed message opened with the first private key that opens it.
fn open(input: &Map<String, Json>) -> Result<Json, Failure> {
    let private_keys = input
        .get("private_keys")
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("private_keys is no list".into()))?
        .iter()
        .map(|k| key(k).map(EncryptionSeed::new))
        .collect::<Result<Vec<_>, _>>()?;
    let message = sealing::open(&bytes(input.get("sealed"))?, &private_keys)?;
    Ok(accept(json!({"message": hex(&message)})))
}

/// The member `date_time` of the input: a `DateTime` with either all of `zone`,
/// `offset_seconds` and `instant_ms` or none of them.
fn date_time(input: &Map<String, Json>) -> Result<DateTime, Failure> {
    let v = object(input, "date_time")?;
    let wall = WallClock {
        year: integer(v, "year")?,
        month: integer(v, "month")?,
        day: integer(v, "day")?,
        hour: integer(v, "hour")?,
        minute: integer(v, "minute")?,
        second: integer(v, "second")?,
        millisecond: integer(v, "millisecond")?,
    };
    let parts = (v.get("zone"), v.get("offset_seconds"), v.get("instant_ms"));
    let zoned = match parts {
        (Some(Json::Null), Some(Json::Null), Some(Json::Null)) => None,
        (Some(Json::String(zone)), Some(_), Some(_)) => Some(Zoned {
            zone: zone.clone(),
            offset_seconds: integer(v, "offset_seconds")?,
            instant_ms: integer(v, "instant_ms")?,
        }),
        _ => {
            return Err(Failure::BadRequest(
                "date_time has neither all nor none of zone, offset_seconds and instant_ms".into(),
            ));
        }
    };
    Ok(DateTime { wall, zoned })
}

/// A `DateTime` in the JSON form of the vectors.
fn date_time_json(date_time: &DateTime) -> Json {
    let w = &date_time.wall;
    let z = date_time.zoned.as_ref();
    json!({
        "year": w.year,
        "month": w.month,
        "day": w.day,
        "hour": w.hour,
        "minute": w.minute,
        "second": w.second,
        "millisecond": w.millisecond,
        "zone": z.map(|z| z.zone.clone()),
        "offset_seconds": z.map(|z| z.offset_seconds),
        "instant_ms": z.map(|z| z.instant_ms),
    })
}

/// The member `name` of the input as an object.
fn object<'a>(input: &'a Map<String, Json>, name: &str) -> Result<&'a Map<String, Json>, Failure> {
    input
        .get(name)
        .and_then(Json::as_object)
        .ok_or_else(|| Failure::BadRequest(format!("{name} is not an object")))
}

/// The member `name` of the input as an integer.
fn integer(input: &Map<String, Json>, name: &str) -> Result<i64, Failure> {
    input
        .get(name)
        .and_then(Json::as_i64)
        .ok_or_else(|| Failure::BadRequest(format!("{name} is not an integer")))
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
    crate::value::hex(bytes)
}

/// A decoded value in the JSON form of `spec/conformance.md`, section 3.3.
fn value_json(value: &Value) -> Json {
    value.to_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(op: &str, input: Json) -> Json {
        Adapter::default().answer(&json!({"id": "t", "op": op, "input": input}))
    }

    #[test]
    fn hello_names_the_implemented_categories() {
        let answer = ask("hello", json!({"format": 1}));
        assert_eq!(
            answer["output"]["categories"],
            json!(["encoding", "bricks", "types", "time", "keys"])
        );
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
    fn a_date_time_is_resolved_and_added_to_with_every_field() {
        let floating = json!({
            "year": 9999, "month": 12, "day": 31, "hour": 23, "minute": 0, "second": 0,
            "millisecond": 0, "zone": null, "offset_seconds": null, "instant_ms": null,
        });
        let answer = ask(
            "resolve_date_time",
            json!({"date_time": floating, "anchor": "instant"}),
        );
        assert_eq!(answer["output"], json!({"accept": {"date_time": floating}}));
        let earlier = json!({"months": 0, "days": 0, "millis": -3_600_000});
        let answer = ask(
            "add_duration",
            json!({"date_time": floating, "duration": earlier}),
        );
        assert_eq!(answer["output"]["accept"]["date_time"]["hour"], 22);
        assert!(answer["output"]["accept"]["date_time"]["zone"].is_null());
    }

    #[test]
    fn a_request_the_time_operations_cannot_read_is_a_failure() {
        let floating = json!({
            "year": 9999, "month": 12, "day": 31, "hour": 23, "minute": 0, "second": 0,
            "millisecond": 0, "zone": null, "offset_seconds": null, "instant_ms": null,
        });
        let answer = ask(
            "resolve_date_time",
            json!({"date_time": floating, "anchor": "nope"}),
        );
        assert!(answer.get("failure").is_some());
        let mut partial = floating.clone();
        partial["zone"] = json!("Europe/Berlin");
        let answer = ask(
            "resolve_date_time",
            json!({"date_time": partial, "anchor": "local"}),
        );
        assert!(answer.get("failure").is_some());
        let hour = json!({"months": 0, "days": 0, "millis": 3_600_000});
        let answer = ask(
            "add_duration",
            json!({"date_time": floating, "duration": hour}),
        );
        assert!(answer.get("failure").is_some());
    }

    #[test]
    fn public_key_sign_and_verify() {
        let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let answer = ask("public_key", json!({"seed": seed}));
        assert_eq!(answer["output"], json!({"accept": {"public_key": public}}));
        let answer = ask("sign", json!({"seed": seed, "data": ""}));
        let signature = answer["output"]["accept"]["signature"].clone();
        let answer = ask(
            "verify",
            json!({"public_key": public, "data": "", "signature": signature}),
        );
        assert_eq!(answer["output"], json!({"accept": {}}));
        let answer = ask(
            "verify",
            json!({"public_key": public, "data": "01", "signature": signature}),
        );
        assert_eq!(
            answer["output"],
            json!({"reject": {"error": "SIGNATURE_INVALID"}})
        );
        // A wrong length is a rejection, not a failure.
        let answer = ask(
            "verify",
            json!({"public_key": "00", "data": "", "signature": signature}),
        );
        assert_eq!(
            answer["output"],
            json!({"reject": {"error": "SIGNATURE_INVALID"}})
        );
        assert!(
            ask("public_key", json!({"seed": "00"}))
                .get("failure")
                .is_some()
        );
    }

    #[test]
    fn the_checks_of_keys_and_the_short_fingerprint() {
        let old = "1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a";
        let answer = ask("check_signing_key", json!({"public_key": old}));
        assert_eq!(answer["output"], json!({"accept": {}}));
        let answer = ask("check_signing_key", json!({"public_key": hex(&[0; 32])}));
        assert_eq!(
            answer["output"],
            json!({"reject": {"error": "KEY_INVALID"}})
        );
        let answer = ask(
            "check_encryption_key",
            json!({"encryption_key": hex(&[0; 32])}),
        );
        assert_eq!(
            answer["output"],
            json!({"reject": {"error": "ENCRYPTION_KEY_INVALID"}})
        );
        let answer = ask("short_fingerprint", json!({"public_key": old}));
        assert_eq!(
            answer["output"],
            json!({"accept": {"short_fingerprint": "24773 42899 01908 98427 81734"}})
        );
    }

    #[test]
    fn device_changes_joins_and_chains() {
        use crate::device_sets::fixtures::{TestKey, device_add, device_join, tampered};
        let a = TestKey::named("a");
        let b = TestKey::named("b");
        let add = hex(&device_add(&a, &b));
        let answer = ask("device_add", json!({"message": add}));
        assert_eq!(
            answer["output"],
            json!({"accept": {"member": hex(&a.public), "device": hex(&b.public)}})
        );
        let answer = ask(
            "device_add",
            json!({"message": hex(&tampered(device_add(&a, &b)))}),
        );
        assert_eq!(
            answer["output"],
            json!({"reject": {"error": "SIGNATURE_INVALID"}})
        );
        let member = json!({"key": hex(&a.public), "current": [], "removed": []});
        let join = hex(&device_join(&b, &a, None));
        let answer = ask(
            "device_join",
            json!({"message": join, "member": member, "first": null}),
        );
        assert_eq!(
            answer["output"],
            json!({"accept": {"device": hex(&b.public), "action": "ask"}})
        );
        let input = json!({"chain": [add], "member": hex(&a.public), "device": hex(&b.public)});
        assert_eq!(ask("join_chain", input)["output"], json!({"accept": {}}));
        let input = json!({"chain": [], "member": hex(&a.public), "device": hex(&b.public)});
        assert_eq!(
            ask("join_chain", input)["output"],
            json!({"reject": {"error": "JOIN_INVALID"}})
        );
    }

    #[test]
    fn a_device_sets_session_answers_each_step() {
        use crate::device_sets::fixtures::{TestKey, device_add};
        let a = TestKey::named("a");
        let b = TestKey::named("b");
        let input = json!({
            "senders": [{
                "name": "s",
                "current": [hex(&a.public)],
                "removed": [],
                "records": [{"id": "r1", "version": 2, "state": "tombstone"}],
            }],
            "refused": [],
            "steps": [
                {"chain": [hex(&device_add(&a, &b))], "key": hex(&b.public)},
                {"chain": [], "key": null},
            ],
        });
        let answer = ask("device_sets", input);
        let steps = &answer["output"]["steps"];
        assert_eq!(steps[0]["results"], json!(["APPLIED"]));
        assert_eq!(steps[0]["key_state"], "current");
        assert_eq!(steps[0]["key_sender"], "s");
        let mut current = vec![hex(&a.public), hex(&b.public)];
        current.sort();
        assert_eq!(
            steps[0]["senders"],
            json!([{
                "name": "s",
                "current": current,
                "removed": [],
                "records": [{"id": "r1", "version": 2, "state": "tombstone"}],
            }])
        );
        assert_eq!(steps[1]["results"], json!([]));
        assert!(steps[1]["key_state"].is_null());
        assert!(steps[1]["key_sender"].is_null());
    }

    #[test]
    fn padded_length_seal_and_open() {
        let answer = ask("padded_length", json!({"length": 1024}));
        assert_eq!(answer["output"], json!({"accept": {"padded_length": 1088}}));
        let private = "8a5e1abca252aefadec7cf0764f52c64b587cdbef900ea3d9046cbf51bc6ed97";
        let public = "34fa7e71770d8d94c76001ac8d575609f005981f80c115bb7a8fe312687ea40b";
        let answer = ask("seal", json!({"message": "c301", "encryption_key": public}));
        let sealed = answer["output"]["accept"]["sealed"].clone();
        assert_eq!(sealed.as_str().unwrap().len(), 2 * 1073);
        let answer = ask(
            "open",
            json!({"sealed": sealed, "private_keys": [hex(&[1; 32]), private]}),
        );
        assert_eq!(answer["output"], json!({"accept": {"message": "c301"}}));
        let answer = ask("open", json!({"sealed": sealed, "private_keys": []}));
        assert_eq!(answer["output"], json!({"reject": {"error": "NOT_OPENED"}}));
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
}
