//! The answers of the conformance adapter (AXT `spec/conformance.md`, section 6).
//!
//! Behind the feature `conformance`, which only the crate `axt-conformance-adapter` turns on.
//! It is a test tool, not part of the public API.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

use crate::bricks::{self, Kind as Brick};
use crate::device_sets::{
    self, DeviceChange, DeviceSetReceiver, JoinAction, KeptRecord, Key, KeyState, KnownSender,
    Member, RecordState,
};
use crate::ed25519;
use crate::envelope::{self, Envelope, Kind, RecordRef};
use crate::error::{Error, ErrorCode};
use crate::file_reader;
use crate::keys::{EncryptionSeed, SigningSeed};
use crate::links;
use crate::live_session::LiveApp;
use crate::manifest;
use crate::proposals::{
    HeldOwnerRecord, OpenProposal, OwnRecord, OwnerManifest, OwnerState, ProposalAnswer,
    ProposalOwner, ProposalProposer, ProposalReceiver, Stop,
};
use crate::record_decoder;
use crate::records::{
    self, Applied, DeleteWithLocalChanges, ElementKey, ElementMerge, HeldRecord, HeldState,
    LocalChanges, Outcome, RecordKind, RecordMessage, RecordPolicy,
};
use crate::relation_index::{HeldRelation, RelationResolver};
use crate::schema::Schema;
use crate::sealing;
use crate::shares::{self, Acked, Owes, Sent};
use crate::signing;
use crate::type_description::TypeDescription;
use crate::value::Value;
use crate::zone_rules::{self, Anchor, DateTime, Duration, TzdbZoneRules, WallClock, Zoned};

/// The categories of `spec/conformance.md`, section 2.1, that the adapter answers. A category
/// is listed only once all of its vectors pass.
pub const IMPLEMENTED_CATEGORIES: &[&str] = &[
    "encoding", "bricks", "types", "time", "keys", "manifest", "records", "file", "protocol",
    "shares",
];

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
        "check_manifest" => check_manifest,
        "fit" => fit,
        "apply" => apply,
        "relations" => relations,
        "read_file" => read_file,
        "choose_format" => choose_format,
        "contact_key" => contact_key,
        "resend_after_removal" => resend_after_removal,
        "session" => session,
        "receive" => apply,
        "take_version" => take_version,
        "owed" => owed,
        "acked" => acked,
        "pass_withdrawal" => pass_withdrawal,
        "join_receivers" => join_receivers,
        "offer_types" => offer_types,
        "shared_value" => shared_value,
        "owner" => owner,
        "proposer" => proposer,
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
        ..DeviceSetReceiver::default()
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

/// `relations` (section 5.3): a receiver that resolves the relations it holds across
/// senders while it follows the devices of its known senders.
fn relations(input: &Map<String, Json>) -> Result<Json, Failure> {
    let (Some(senders), Some(relations), Some(steps)) = (
        input.get("senders").and_then(Json::as_array),
        input.get("relations").and_then(Json::as_array),
        input.get("steps").and_then(Json::as_array),
    ) else {
        return Err(Failure::BadRequest(
            "senders, relations and steps must be lists".into(),
        ));
    };
    let mut receiver = DeviceSetReceiver {
        senders: senders.iter().map(known_sender).collect::<Result<_, _>>()?,
        refused: keys(input.get("refused"))?,
        ..DeviceSetReceiver::default()
    };
    let own = known_sender(input.get("own").unwrap_or(&Json::Null))?;
    let held = relations
        .iter()
        .map(|relation| {
            let relation = relation
                .as_object()
                .ok_or_else(|| Failure::BadRequest("a relation is not an object".into()))?;
            let holder = object(relation, "holder")?;
            let target = object(relation, "target")?;
            Ok(HeldRelation {
                id: string(relation, "id")?.to_owned(),
                holder_sender: string(holder, "sender")?.to_owned(),
                holder_id: string(holder, "id")?.to_owned(),
                target_sender: match target.get("sender") {
                    None | Some(Json::Null) => None,
                    Some(sender) => Some(key(sender)?),
                },
                target_id: string(target, "id")?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let mut results = Vec::with_capacity(steps.len());
    for step in steps {
        let step = step
            .as_object()
            .ok_or_else(|| Failure::BadRequest("a step is no object".into()))?;
        if step.contains_key("chain") {
            let outcome = receiver.receive_chain(&chain(step.get("chain"))?);
            results.push(json!({
                "results": outcome.into_iter().map(|r| r.code()).collect::<Vec<_>>(),
            }));
            continue;
        }
        let resolver = RelationResolver {
            receiver: &receiver,
            own: &own,
        };
        results.push(json!({
            "relations": held.iter().map(|relation| {
                let resolution = resolver.resolve(relation);
                json!({
                    "id": relation.id,
                    "sender": resolution.sender,
                    "resolved": resolution.resolved,
                })
            }).collect::<Vec<_>>(),
            "linked_from": resolver.linked_from(&held).into_iter().map(|linked| json!({
                "sender": linked.sender,
                "id": linked.id,
                "from": linked.from.into_iter().map(|from| json!({
                    "sender": from.sender,
                    "id": from.id,
                    "relation": from.relation,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({"steps": results}))
}

/// A policy of `apply` (section 5.3) and of `receive` (section 5.15).
fn record_policy(value: Option<&Json>) -> Result<RecordPolicy, Failure> {
    let value = value
        .and_then(Json::as_object)
        .ok_or_else(|| Failure::BadRequest("policy is not an object".into()))?;
    let removal = |name: &str| match value.get(name).and_then(Json::as_str) {
        Some("delete") => Ok(DeleteWithLocalChanges::Delete),
        Some("keep") => Ok(DeleteWithLocalChanges::Keep),
        other => Err(Failure::BadRequest(format!(
            "no policy {other:?} for {name}"
        ))),
    };
    Ok(RecordPolicy {
        local_changes: match value.get("local_changes").and_then(Json::as_str) {
            Some("per_field") => LocalChanges::PerField,
            Some("whole_record_keep") => LocalChanges::WholeRecordKeep,
            Some("whole_record_take") => LocalChanges::WholeRecordTake,
            other => return Err(Failure::BadRequest(format!("no policy {other:?}"))),
        },
        delete_with_local_changes: removal("delete_with_local_changes")?,
        withdraw_with_local_changes: match value.get("withdraw_with_local_changes") {
            None | Some(Json::Null) => None,
            Some(_) => Some(removal("withdraw_with_local_changes")?),
        },
    })
}

/// A record value of `apply` in the form of section 3.3, read by its shape, as the input
/// has no schema: objects as records, integers as longs, and the data of an extension,
/// an object of exactly `name` and `data`, as bytes.
fn shaped_value(json: &Json) -> Result<Value, Failure> {
    Ok(match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Boolean(*b),
        Json::Number(n) => match n.as_i64() {
            Some(i) => Value::Long(i),
            None => Value::Double(n.as_f64().unwrap_or_default()),
        },
        Json::String(s) => Value::String(s.clone()),
        Json::Array(items) => {
            Value::Array(items.iter().map(shaped_value).collect::<Result<_, _>>()?)
        }
        Json::Object(members) => {
            if let (2, Some(Json::String(name)), Some(Json::String(data))) =
                (members.len(), members.get("name"), members.get("data"))
            {
                return Ok(Value::Record(vec![
                    ("name".into(), Value::String(name.clone())),
                    ("data".into(), Value::Bytes(unhex(data)?)),
                ]));
            }
            Value::Record(
                members
                    .iter()
                    .map(|(name, v)| Ok((name.clone(), shaped_value(v)?)))
                    .collect::<Result<_, Failure>>()?,
            )
        }
    })
}

/// The key of `element` when it is an element of a list merged per element: a relation
/// or an extension, told by its shape.
fn element_key_of(element: &Value) -> Option<ElementKey> {
    match element {
        Value::Record(_)
            if matches!(element.field("id"), Some(Value::String(_)))
                && matches!(element.field("target"), Some(Value::Record(_))) =>
        {
            Some(ElementKey::Id)
        }
        Value::Record(fields)
            if fields.len() == 2
                && matches!(element.field("name"), Some(Value::String(_)))
                && matches!(element.field("data"), Some(Value::Bytes(_))) =>
        {
            Some(ElementKey::Name)
        }
        _ => None,
    }
}

/// The lists of `values` merged per element: those that hold relations or extensions.
fn element_lists(values: &[Option<&Value>]) -> HashMap<String, ElementKey> {
    let mut lists = HashMap::new();
    for value in values.iter().flatten() {
        if let Value::Record(fields) = value {
            for (name, field) in fields {
                if let Value::Array(items) = field {
                    for key in items.iter().filter_map(element_key_of) {
                        lists.insert(name.clone(), key);
                    }
                }
            }
        }
    }
    lists
}

/// The result of one record message of `apply`.
fn applied_json(applied: &Applied) -> Json {
    json!({
        "outcome": applied.outcome.as_str(),
        "receiver_version": applied.held.version,
        "kept_fields": applied.kept_fields,
        "state": applied.held.state.code(),
        "value": applied.value.as_ref().map_or(Json::Null, value_json),
    })
}

/// A record key of the input, or the rejection of the library.
fn input_record_key(input: &Map<String, Json>) -> Result<String, Failure> {
    Ok(records::checked_record_key(string(input, "id")?)?)
}

/// `apply` (section 5.3): one receiver and the records of one sender, starting empty
/// (`spec/records.md`, sections 5 to 7); its user's changes are kept as the current
/// values.
fn apply(input: &Map<String, Json>) -> Result<Json, Failure> {
    let policy = record_policy(input.get("policy"))?;
    let events = input
        .get("events")
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("events is no list".into()))?;
    let mut writers = HashMap::new();
    let mut own = HashMap::new();
    for text in input
        .get("extensions")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let text = text
            .as_str()
            .ok_or_else(|| Failure::BadRequest("an extension is no schema text".into()))?;
        let schema = Schema::parse(text)?;
        writers.insert(schema.fingerprint().0, schema.clone());
        own.insert(schema.type_name(), schema);
    }
    let mut held: HashMap<String, HeldRecord> = HashMap::new();
    let mut current: HashMap<String, Value> = HashMap::new();
    let mut steps = Vec::with_capacity(events.len());
    for event in events {
        let event = event
            .as_object()
            .ok_or_else(|| Failure::BadRequest("an event is no object".into()))?;
        if let Some(take) = event.get("local_take").and_then(Json::as_object) {
            let key = input_record_key(take)?;
            let applied = held
                .get(&key)
                .and_then(records::take_kept_removal)
                .ok_or_else(|| Failure::BadRequest("nothing kept to take".into()))?;
            held.insert(key.clone(), applied.held.clone());
            current.remove(&key);
            steps.push(applied_json(&applied));
        } else if let Some(change) = event.get("local_change").and_then(Json::as_object) {
            let key = input_record_key(change)?;
            let value = shaped_value(change.get("value").unwrap_or(&Json::Null))?;
            let record = current
                .entry(key)
                .or_insert_with(|| Value::Record(Vec::new()));
            records::set_field(record, string(change, "field")?, value);
            steps.push(json!({}));
        } else if let Some(delete) = event.get("local_delete").and_then(Json::as_object) {
            let key = input_record_key(delete)?;
            let record = held
                .get_mut(&key)
                .ok_or_else(|| Failure::BadRequest("no record to delete".into()))?;
            record.state = HeldState::DeletedByUser;
            record.taken = None;
            record.kept_against = None;
            current.remove(&key);
            steps.push(json!({}));
        } else if let Some(message) = event.get("message").and_then(Json::as_object) {
            let key = match input_record_key(message) {
                Ok(key) => key,
                Err(Failure::Library(e)) => {
                    steps.push(json!({"error": e.code().map(ErrorCode::as_str)}));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let version = integer(message, "version")?;
            let kind = match message.get("kind").and_then(Json::as_str) {
                Some("DATA") => RecordKind::Data,
                Some("DELETE") => RecordKind::Delete,
                Some("WITHDRAW") => RecordKind::Withdraw,
                other => return Err(Failure::BadRequest(format!("no record kind {other:?}"))),
            };
            let value = match message.get("value") {
                None | Some(Json::Null) => None,
                Some(value) => Some(shaped_value(value)?),
            };
            let was = held.get(&key);
            let user = current.get(&key);
            let elements = ElementMerge {
                lists: element_lists(&[value.as_ref(), user, was.and_then(|h| h.taken.as_ref())]),
                writers: writers.clone(),
                own: own.clone(),
            };
            let applied = records::apply_record_message(
                was,
                user,
                RecordMessage {
                    kind,
                    version,
                    type_name: message.get("type").and_then(Json::as_str),
                    value: value.as_ref(),
                },
                &policy,
                &elements,
            );
            match applied {
                Ok(applied) => {
                    steps.push(applied_json(&applied));
                    match &applied.value {
                        Some(value) => current.insert(key.clone(), value.clone()),
                        None => current.remove(&key),
                    };
                    held.insert(key, applied.held);
                }
                Err(e) => steps.push(json!({"error": e.code().map(ErrorCode::as_str)})),
            }
        } else {
            return Err(Failure::BadRequest("an event of no known form".into()));
        }
    }
    Ok(json!({"steps": steps}))
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

/// `check_manifest` (section 5.4): the manifest of a valid body.
fn check_manifest(input: &Map<String, Json>) -> Result<Json, Failure> {
    let format = integer(input, "envelope_format")?;
    let manifest = manifest::check_manifest(&bytes(input.get("body"))?, format)?;
    Ok(accept(json!({"manifest": value_json(&manifest)})))
}

/// `fit` (section 5.4): whether a type fits a manifest, and the purpose sentence shown.
fn fit(input: &Map<String, Json>) -> Result<Json, Failure> {
    let languages = input
        .get("languages")
        .and_then(Json::as_array)
        .and_then(|l| {
            l.iter()
                .map(|t| t.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| Failure::BadRequest("languages is not a list of strings".into()))?;
    let decoded = envelope::decode_body(Kind::Manifest, &bytes(input.get("manifest"))?)?;
    let result = manifest::fit(&decoded, string(input, "schema")?, &languages)?;
    Ok(accept(
        json!({"fits": result.fits, "purpose": result.purpose}),
    ))
}

/// `read_file` (section 5.7): a file read as a reader whose user accepted its sender,
/// that knows the sender by the key in `axt.sender` alone and holds no record of it yet.
fn read_file(input: &Map<String, Json>) -> Result<Json, Failure> {
    let reader = object(input, "reader")?;
    let manifest = envelope::decode_body(Kind::Manifest, &bytes(reader.get("manifest"))?)?;
    let readers = schema_texts(reader.get("readers"))?;
    let (current, removed) = match reader.get("keys").and_then(Json::as_object) {
        Some(own) => (keys(own.get("current"))?, keys(own.get("removed"))?),
        None => (BTreeSet::new(), BTreeSet::new()),
    };
    let file = file_reader::check_file(&bytes(input.get("file"))?)?;
    let mut receiver = DeviceSetReceiver {
        senders: vec![KnownSender {
            name: "sender".into(),
            current: BTreeSet::from([file.sender]),
            ..KnownSender::default()
        }],
        ..DeviceSetReceiver::default()
    };
    let outcome = receiver.receive_chain(&file.chain);
    let chain = file
        .chain
        .iter()
        .zip(&outcome)
        .map(|(message, result)| {
            let change = DeviceChange::decode(message)?;
            Ok(json!({
                "kind": if change.is_add() { "DEVICE_ADD" } else { "DEVICE_REMOVE" },
                "signer": hex(&change.signer),
                "device": hex(&change.device),
                "result": result.code(),
            }))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let manifest_state = match &file.manifest {
        None => "none",
        Some(body) if manifest::check_manifest(body, 1).is_ok() => "used",
        Some(_) => "invalid",
    };
    let records: Vec<Json> = if receiver.state_of(&file.sender) == KeyState::Removed {
        file.records
            .iter()
            .map(|message| {
                let (id, version) = message.record();
                json!({"id": id, "version": version, "result": "SENDER_REMOVED"})
            })
            .collect()
    } else {
        let reader = file_reader::FileReader {
            manifest: &manifest,
            readers: &readers,
            current: &current,
            removed: &removed,
        };
        file_reader::read_file_records(
            &file,
            reader,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &RecordPolicy::default(),
        )
        .into_iter()
        .map(|read| {
            json!({
                "id": read.result.id,
                "version": read.result.version,
                "result": read.result.result.as_str(),
            })
        })
        .collect()
    };
    Ok(accept(json!({
        "sender": hex(&file.sender),
        "chain": chain,
        "manifest": manifest_state,
        "records": records,
    })))
}

/// Reader schemas by full name, as schema texts; none when absent.
fn schema_texts(value: Option<&Json>) -> Result<BTreeMap<String, String>, Failure> {
    let mut readers = BTreeMap::new();
    if let Some(given) = value {
        let given = given
            .as_object()
            .ok_or_else(|| Failure::BadRequest("readers is not an object".into()))?;
        for (name, text) in given {
            let text = text.as_str().ok_or_else(|| {
                Failure::BadRequest("readers is not an object of schema texts".into())
            })?;
            readers.insert(name.clone(), text.to_owned());
        }
    }
    Ok(readers)
}

/// A list of integers.
fn integers(value: Option<&Json>, name: &str) -> Result<Vec<i64>, Failure> {
    value
        .and_then(Json::as_array)
        .and_then(|list| list.iter().map(Json::as_i64).collect::<Option<Vec<_>>>())
        .ok_or_else(|| Failure::BadRequest(format!("{name} is not a list of integers")))
}

/// `choose_format` (section 5.6): the highest envelope format both apps read, or `null`.
fn choose_format(input: &Map<String, Json>) -> Result<Json, Failure> {
    let theirs: BTreeSet<i64> = integers(input.get("theirs"), "theirs")?
        .into_iter()
        .collect();
    let common = integers(input.get("own"), "own")?
        .into_iter()
        .filter(|f| theirs.contains(f))
        .max();
    Ok(accept(json!({"format": common})))
}

/// `contact_key` (section 5.6): the key to which a sender offers (protocol.md, section
/// 9.1): the last key that sent a valid message other than a change of devices or a
/// manifest, of those that are current and whose manifest the sender holds; otherwise
/// every such key.
fn contact_key(input: &Map<String, Json>) -> Result<Json, Failure> {
    let current = keys(input.get("current"))?;
    let manifests = keys(input.get("manifests"))?;
    let got = input
        .get("got")
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("got is no list".into()))?;
    let mut last = None;
    for message in got {
        let message = message
            .as_object()
            .ok_or_else(|| Failure::BadRequest("a message of got is no object".into()))?;
        let message_key = key(message.get("key").unwrap_or(&Json::Null))?;
        let kind = message.get("kind").and_then(Json::as_str);
        if !current.contains(&message_key)
            || !manifests.contains(&message_key)
            || matches!(kind, Some("DEVICE_ADD" | "DEVICE_REMOVE" | "MANIFEST"))
        {
            continue;
        }
        last = Some(message_key);
    }
    let chosen: Vec<String> = match last {
        Some(last) => vec![hex(&last)],
        None => current
            .iter()
            .filter(|k| manifests.contains(*k))
            .map(|k| hex(k))
            .collect(),
    };
    Ok(accept(json!({"keys": chosen})))
}

/// `resend_after_removal` (section 5.6): the ids of the records a sender sends again,
/// whose only outcomes are of removed keys, or that have none (protocol.md, sections 7.4
/// and 11).
fn resend_after_removal(input: &Map<String, Json>) -> Result<Json, Failure> {
    let removed = keys(input.get("removed"))?;
    let records = input
        .get("records")
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("records is no list".into()))?;
    let mut ids = Vec::new();
    for record in records {
        let outcomes = match record.get("outcomes") {
            None | Some(Json::Null) => Map::new(),
            Some(Json::Object(outcomes)) => outcomes.clone(),
            Some(_) => return Err(Failure::BadRequest("outcomes is no object".into())),
        };
        let mut all_removed = true;
        for name in outcomes.keys() {
            all_removed &= removed.contains(&key(&json!(name))?);
        }
        if all_removed {
            ids.push(record.get("id").cloned().unwrap_or(Json::Null));
        }
    }
    Ok(accept(json!({"ids": ids})))
}

/// `session` (section 5.6): one app in one live connection with another app whose key
/// its user has accepted (protocol.md, sections 3 to 9 and 14).
fn session(input: &Map<String, Json>) -> Result<Json, Failure> {
    let app_input = object(input, "app")?;
    let user_takes = app_input
        .get("user_takes")
        .and_then(Json::as_array)
        .and_then(|takes| {
            takes
                .iter()
                .map(|t| t.as_str().map(str::to_owned))
                .collect::<Option<BTreeSet<_>>>()
        })
        .ok_or_else(|| Failure::BadRequest("user_takes is not a list of strings".into()))?;
    // The app reads envelope format 1 alone; the formats are read but change nothing.
    integers(app_input.get("formats"), "formats")?;
    let mut app = LiveApp::open(
        SigningSeed::new(sized(app_input, "seed")?),
        &bytes(app_input.get("manifest"))?,
        schema_texts(app_input.get("readers"))?,
        user_takes,
        sized(app_input, "peer")?,
    )?;
    let steps = input
        .get("steps")
        .and_then(Json::as_array)
        .ok_or_else(|| Failure::BadRequest("steps is no list".into()))?;
    let mut answers = Vec::new();
    for step in steps {
        let step = step
            .as_object()
            .ok_or_else(|| Failure::BadRequest("a step is no object".into()))?;
        let replies =
            |replies: &[Vec<u8>]| -> Vec<String> { replies.iter().map(|r| hex(r)).collect() };
        answers.push(if let Some(message) = step.get("receive") {
            let received = app.receive(&bytes(Some(message))?)?;
            json!({
                "outcome": received.outcome.map(|o| o.as_str()),
                "close": received.close,
                "replies": replies(&received.replies),
            })
        } else if step.contains_key("flush_acks") {
            let (_, sent) = app.flush_acks()?;
            json!({"replies": replies(&sent)})
        } else if step.contains_key("offer") {
            let offer = object(step, "offer")?;
            let types = offer
                .get("types")
                .and_then(Json::as_array)
                .ok_or_else(|| Failure::BadRequest("types is no list".into()))?
                .iter()
                .map(|t| {
                    let t = t
                        .as_object()
                        .ok_or_else(|| Failure::BadRequest("a type is no object".into()))?;
                    let description =
                        bricks::description_from_json(t.get("description").unwrap_or(&Json::Null))?;
                    Ok((description, integer(t, "count")?))
                })
                .collect::<Result<Vec<_>, Failure>>()?;
            let message = app.offer(string(offer, "offer_id")?, &types)?;
            json!({"message": hex(&message)})
        } else if step.contains_key("close") {
            app.close_connection();
            json!({})
        } else if step.contains_key("query") {
            let query = object(step, "query")?;
            if query.contains_key("accepted") {
                json!({"accepted": app.accepted(string(query, "accepted")?)})
            } else if query.contains_key("outcome") {
                let of = object(query, "outcome")?;
                let outcome = app.outcome_of(string(of, "id")?, integer(of, "version")?);
                json!({"outcome": outcome.map(|o| o.as_str())})
            } else if query.contains_key("record") {
                let held = app.record(string(query, "record")?);
                json!({
                    "record": held.map(|h| json!({"version": h.version, "state": h.state.code()})),
                })
            } else {
                json!({"errors": app.errors()})
            }
        } else {
            return Err(Failure::BadRequest("a step of no known form".into()));
        });
    }
    Ok(json!({"steps": answers}))
}

/// A version of the input in decimal text, or `None` for `null` or no member.
fn version_text(input: &Map<String, Json>, name: &str) -> Result<Option<i64>, Failure> {
    match input.get(name) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(text)) => text
            .parse()
            .map(Some)
            .map_err(|_| Failure::BadRequest(format!("{name} is no decimal text"))),
        Some(_) => Err(Failure::BadRequest(format!("{name} is no decimal text"))),
    }
}

/// A version of the input in decimal text that must be there.
fn required_version(input: &Map<String, Json>, name: &str) -> Result<i64, Failure> {
    version_text(input, name)?.ok_or_else(|| Failure::BadRequest(format!("{name} is missing")))
}

/// A version as decimal text, or `null`.
fn text_of(version: Option<i64>) -> Json {
    version.map_or(Json::Null, |v| json!(v.to_string()))
}

/// The member `name` of the input as a flag: true only for `true`.
fn flag(input: &Map<String, Json>, name: &str) -> bool {
    input.get(name) == Some(&Json::Bool(true))
}

/// A record kind of the input.
fn record_kind(value: Option<&Json>) -> Result<RecordKind, Failure> {
    match value.and_then(Json::as_str) {
        Some("DATA") => Ok(RecordKind::Data),
        Some("DELETE") => Ok(RecordKind::Delete),
        Some("WITHDRAW") => Ok(RecordKind::Withdraw),
        other => Err(Failure::BadRequest(format!("no record kind {other:?}"))),
    }
}

/// An outcome of the input, or `None` for `null`.
fn outcome(value: Option<&Json>) -> Result<Option<Outcome>, Failure> {
    match value {
        None | Some(Json::Null) => Ok(None),
        Some(value) => [
            Outcome::Applied,
            Outcome::Merged,
            Outcome::Kept,
            Outcome::Duplicate,
            Outcome::Stale,
            Outcome::Withdrawn,
        ]
        .into_iter()
        .find(|o| value.as_str() == Some(o.as_str()))
        .map(Some)
        .ok_or_else(|| Failure::BadRequest(format!("no outcome {value}"))),
    }
}

/// `take_version` (section 5.15): the next version of an installation that counts.
fn take_version(input: &Map<String, Json>) -> Result<Json, Failure> {
    let (version, state_stamp) = shares::take_version(
        input.get("occasion").and_then(Json::as_str) == Some("share_again"),
        required_version(input, "highest_given")?,
        required_version(input, "state_stamp")?,
    )
    .ok_or_else(|| Failure::BadRequest("the versions are spent".into()))?;
    Ok(accept(json!({
        "version": text_of(Some(version)),
        "state_stamp": text_of(Some(state_stamp)),
    })))
}

/// `owed` (section 5.15): what a device owes a receiver of one record.
fn owed(input: &Map<String, Json>) -> Result<Json, Failure> {
    let last = match input.get("last") {
        Some(Json::Object(last)) => Some(Sent {
            kind: record_kind(last.get("kind"))?,
            version: required_version(last, "version")?,
        }),
        _ => None,
    };
    let (owes, version) = shares::owed(
        flag(input, "shared"),
        flag(input, "deleted"),
        required_version(input, "version")?,
        version_text(input, "withdrawal")?,
        last,
    );
    Ok(accept(
        json!({"owes": owes.code(), "version": text_of(version)}),
    ))
}

/// `acked` (section 5.15): the outcome a device holds after one entry of an `ACK`.
fn acked(input: &Map<String, Json>) -> Result<Json, Failure> {
    let (taken, then, to_pass) = shares::acked(Acked {
        sent: record_kind(input.get("sent"))?,
        held: outcome(input.get("held"))?,
        outcome: outcome(input.get("outcome"))?
            .ok_or_else(|| Failure::BadRequest("outcome is missing".into()))?,
        receiver_version: required_version(input, "receiver_version")?,
        shared: flag(input, "shared"),
        withdrawal: version_text(input, "withdrawal")?,
        state_stamp: required_version(input, "state_stamp")?,
        sibling_stamp: version_text(input, "sibling_stamp")?,
        sibling: flag(input, "sibling"),
    });
    Ok(accept(json!({
        "outcome": taken.as_str(),
        "then": then.code(),
        "to_pass": text_of(to_pass),
    })))
}

/// `pass_withdrawal` (section 5.15): what a device does with the version to pass.
fn pass_withdrawal(input: &Map<String, Json>) -> Result<Json, Failure> {
    let then = shares::pass_withdrawal(
        flag(input, "shared"),
        version_text(input, "withdrawal")?,
        required_version(input, "to_pass")?,
        required_version(input, "state_stamp")?,
    );
    Ok(accept(json!({"then": then.code(), "to_pass": null})))
}

/// The objects of the list `name` of the input.
fn objects<'a>(
    input: &'a Map<String, Json>,
    name: &str,
) -> Result<Vec<&'a Map<String, Json>>, Failure> {
    match input.get(name) {
        None | Some(Json::Null) => Ok(Vec::new()),
        Some(Json::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_object()
                    .ok_or_else(|| Failure::BadRequest(format!("{name} holds no object")))
            })
            .collect(),
        Some(_) => Err(Failure::BadRequest(format!("{name} is no list"))),
    }
}

/// `join_receivers` (section 5.15): the record toward receivers that join.
fn join_receivers(input: &Map<String, Json>) -> Result<Json, Failure> {
    if !input.get("receivers").is_some_and(Json::is_array) {
        return Err(Failure::BadRequest("receivers is no list".into()));
    }
    let receivers = objects(input, "receivers")?
        .into_iter()
        .map(|r| Ok((flag(r, "shared"), version_text(r, "withdrawal")?)))
        .collect::<Result<Vec<_>, Failure>>()?;
    let (shared, withdrawal, new_state_stamp) = shares::join_receivers(&receivers);
    Ok(accept(json!({
        "shared": shared,
        "withdrawal": text_of(withdrawal),
        "new_state_stamp": new_state_stamp,
    })))
}

/// `offer_types` (section 5.15): the types a device offers a receiver of another user.
fn offer_types(input: &Map<String, Json>) -> Result<Json, Failure> {
    if !input.get("records").is_some_and(Json::is_array) {
        return Err(Failure::BadRequest("records is no list".into()));
    }
    let records = objects(input, "records")?
        .into_iter()
        .map(|r| {
            Ok((
                string(r, "type")?.to_owned(),
                r.get("owes")
                    .and_then(Json::as_str)
                    .and_then(Owes::from_code)
                    .unwrap_or(Owes::Nothing),
                flag(r, "delivered"),
            ))
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let types: Vec<Json> = shares::offer_types(&records)
        .into_iter()
        .map(|(t, count)| json!({"type": t, "count": count}))
        .collect();
    Ok(accept(json!({"types": types})))
}

/// The strings of the list `name` of the input; none where it is absent.
fn strings(input: &Map<String, Json>, name: &str) -> Result<Vec<String>, Failure> {
    match input.get(name) {
        None | Some(Json::Null) => Ok(Vec::new()),
        Some(Json::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Failure::BadRequest(format!("{name} is not a list of strings")))
            })
            .collect(),
        Some(_) => Err(Failure::BadRequest(format!(
            "{name} is not a list of strings"
        ))),
    }
}

/// A record value of the vectors read by its shape, as [`shaped_value`] reads it, with
/// the `sender` of each relation's target, a key in hexadecimal text, as its bytes.
fn vector_value(json: &Json) -> Result<Value, Failure> {
    let mut value = shaped_value(json)?;
    senders_as_bytes(&mut value);
    Ok(value)
}

/// `value` with the hexadecimal `sender` of each relation's target as its bytes.
fn senders_as_bytes(value: &mut Value) {
    match value {
        Value::Record(fields) => {
            let is_relation = fields.iter().any(|(n, _)| n == "id")
                && fields
                    .iter()
                    .any(|(n, v)| n == "target" && matches!(v, Value::Record(_)));
            for (name, inner) in fields.iter_mut() {
                if is_relation
                    && name == "target"
                    && let Value::Record(target) = inner
                {
                    for (member, sender) in target.iter_mut() {
                        if member == "sender"
                            && let Value::String(text) = sender
                            && let Ok(bytes) = unhex(text)
                            && bytes.len() == 32
                        {
                            *sender = Value::Fixed(bytes);
                        }
                    }
                }
                senders_as_bytes(inner);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(senders_as_bytes),
        Value::Map(entries) => entries.values_mut().for_each(senders_as_bytes),
        _ => {}
    }
}

/// `shared_value` (section 5.15): the record as the sender sends it to one receiver
/// (`spec/shares.md`, section 19.1); relations and extensions are found by their shape,
/// as the input has no schema.
fn shared_value(input: &Map<String, Json>) -> Result<Json, Failure> {
    let given = input
        .get("value")
        .filter(|v| v.is_object())
        .ok_or_else(|| Failure::BadRequest("value is not an object".into()))?;
    if flag(input, "own_user") || flag(input, "links") {
        return Ok(accept(json!({"value": given})));
    }
    let shared: HashSet<String> = strings(input, "shared")?.into_iter().collect();
    let own_keys = strings(input, "own_keys")?
        .iter()
        .map(|k| key(&json!(k)))
        .collect::<Result<BTreeSet<Key>, Failure>>()?;
    fn walk(value: &Value, shared: &HashSet<String>, own_keys: &BTreeSet<Key>) -> Value {
        match value {
            Value::Array(list)
                if !list.is_empty()
                    && list
                        .iter()
                        .all(|e| element_key_of(e) == Some(ElementKey::Id)) =>
            {
                Value::Array(links::shared_relations(list, shared, own_keys))
            }
            Value::Array(list)
                if !list.is_empty()
                    && list
                        .iter()
                        .all(|e| element_key_of(e) == Some(ElementKey::Name)) =>
            {
                Value::Array(Vec::new())
            }
            Value::Record(fields) => Value::Record(
                fields
                    .iter()
                    .map(|(n, v)| (n.clone(), walk(v, shared, own_keys)))
                    .collect(),
            ),
            Value::Array(list) => {
                Value::Array(list.iter().map(|v| walk(v, shared, own_keys)).collect())
            }
            other => other.clone(),
        }
    }
    let value = walk(&vector_value(given)?, &shared, &own_keys);
    Ok(accept(json!({"value": value_json(&value)})))
}

/// The replies of a step in hexadecimal text.
fn replies_json(replies: &[Vec<u8>]) -> Vec<String> {
    replies.iter().map(|r| hex(r)).collect()
}

/// The steps of the input.
fn steps_of(input: &Map<String, Json>) -> Result<Vec<&Map<String, Json>>, Failure> {
    if !input.get("steps").is_some_and(Json::is_array) {
        return Err(Failure::BadRequest("steps is no list".into()));
    }
    objects(input, "steps")
}

/// An integer of the input that is a JSON number, or 0 where it is absent.
fn count(input: &Map<String, Json>, name: &str) -> Result<i64, Failure> {
    match input.get(name) {
        None | Some(Json::Null) => Ok(0),
        Some(_) => integer(input, name),
    }
}

/// `owner` (section 5.15): one installation of the owner of shared records
/// (`spec/shares.md`, sections 12 to 18).
fn owner(input: &Map<String, Json>) -> Result<Json, Failure> {
    let device = object(input, "device")?;
    let receivers = objects(device, "receivers")?
        .into_iter()
        .map(|r| {
            Ok(ProposalReceiver {
                name: string(r, "name")?.to_owned(),
                current: keys(r.get("current"))?,
                removed: keys(r.get("removed"))?,
                own_user: flag(r, "own_user"),
                links: flag(r, "links"),
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let records = objects(device, "records")?
        .into_iter()
        .map(|r| {
            Ok(OwnRecord {
                id: string(r, "id")?.to_owned(),
                type_name: string(r, "type")?.to_owned(),
                version: required_version(r, "version")?,
                deleted: r.get("state").and_then(Json::as_str) == Some("deleted"),
                value: match r.get("value") {
                    None | Some(Json::Null) => Value::Record(Vec::new()),
                    Some(value) => vector_value(value)?,
                },
                shared: strings(r, "shared")?.into_iter().collect(),
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let open = objects(device, "open")?
        .into_iter()
        .map(|o| {
            Ok(OpenProposal {
                receiver: string(o, "receiver")?.to_owned(),
                proposal_id: string(o, "proposal_id")?.to_owned(),
                id: string(o, "id")?.to_owned(),
                version: 0,
                value_bytes: usize::try_from(count(o, "value_bytes")?)
                    .map_err(|_| Failure::BadRequest("value_bytes is negative".into()))?,
                message: None,
                signer: None,
                fields: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let answer_of = |a: &Map<String, Json>| -> Result<ProposalAnswer, Failure> {
        Ok(ProposalAnswer {
            receiver: string(a, "receiver")?.to_owned(),
            proposal_id: string(a, "proposal_id")?.to_owned(),
            answer: string(a, "answer")?.to_owned(),
            id: string(a, "id")?.to_owned(),
            version: integer(a, "version")?,
        })
    };
    let stop_of = |s: &Map<String, Json>| -> Result<Stop, Failure> {
        Ok(Stop {
            receiver: string(s, "receiver")?.to_owned(),
            id: s.get("id").and_then(Json::as_str).map(str::to_owned),
            type_name: s.get("type").and_then(Json::as_str).map(str::to_owned),
        })
    };
    let mut owner = ProposalOwner::start(
        SigningSeed::new(sized(device, "seed")?),
        OwnerState {
            siblings: match device.get("siblings") {
                None | Some(Json::Null) => BTreeSet::new(),
                Some(siblings) => keys(Some(siblings))?,
            },
            proposals: strings(device, "proposals")?.into_iter().collect(),
            schemas: strings(device, "schemas")?,
            receivers,
            records,
            readers: match device.get("readers") {
                None | Some(Json::Null) => None,
                Some(readers) => Some(schema_texts(Some(readers))?),
            },
            open,
            answers: objects(device, "answers")?
                .into_iter()
                .map(answer_of)
                .collect::<Result<_, _>>()?,
            stops: objects(device, "stopped")?
                .into_iter()
                .map(stop_of)
                .collect::<Result<_, _>>()?,
        },
    )?;
    let mut out = Vec::new();
    for step in steps_of(input)? {
        out.push(if let Some(message) = step.get("receive") {
            let received = owner.receive(&bytes(Some(message))?)?;
            json!({"result": received.result, "replies": replies_json(&received.replies)})
        } else if step.contains_key("answer") {
            let a = object(step, "answer")?;
            let answered = owner.answer(
                string(a, "receiver")?,
                string(a, "proposal_id")?,
                string(a, "answer")?,
            )?;
            json!({
                "made": answered.made,
                "replies": replies_json(&answered.replies),
                "update": answered.update.map(|(version, value)| json!({
                    "version": version.to_string(),
                    "value": value_json(&value),
                })),
            })
        } else if step.contains_key("answered") {
            owner.answered(answer_of(object(step, "answered")?)?);
            json!({})
        } else if step.contains_key("stop") {
            owner.stop(stop_of(object(step, "stop")?)?);
            json!({})
        } else if step.contains_key("change") {
            let c = object(step, "change")?;
            owner.change(
                string(c, "id")?,
                string(c, "action")?,
                c.get("receiver").and_then(Json::as_str),
            );
            json!({})
        } else if step.contains_key("manifest") {
            owner.proposals = strings(step, "manifest")?.into_iter().collect();
            json!({})
        } else if step.contains_key("query") {
            let mut open: Vec<_> = owner.open.iter().collect();
            open.sort_by(|a, b| (&a.receiver, &a.proposal_id).cmp(&(&b.receiver, &b.proposal_id)));
            let mut answers: Vec<_> = owner.answers.iter().collect();
            answers
                .sort_by(|a, b| (&a.receiver, &a.proposal_id).cmp(&(&b.receiver, &b.proposal_id)));
            let mut records: Vec<_> = owner.records.iter().collect();
            records.sort_by(|a, b| a.id.cmp(&b.id));
            json!({
                "open": open.iter().map(|p| json!({
                    "receiver": p.receiver,
                    "proposal_id": p.proposal_id,
                    "id": p.id,
                    "message_hash": p.message.as_ref().map(|m| hex(&Sha256::digest(m))),
                })).collect::<Vec<_>>(),
                "answers": answers.iter().map(|a| json!({
                    "receiver": a.receiver,
                    "proposal_id": a.proposal_id,
                    "answer": a.answer,
                    "id": a.id,
                    "version": a.version,
                })).collect::<Vec<_>>(),
                "records": records.iter().map(|r| json!({
                    "id": r.id,
                    "version": r.version.to_string(),
                    "state": if r.deleted { "deleted" } else { "there" },
                    "value": value_json(&r.value),
                })).collect::<Vec<_>>(),
            })
        } else {
            return Err(Failure::BadRequest("a step of no known form".into()));
        });
    }
    Ok(json!({"steps": out}))
}

/// The bytes of each field by name, or `None` for `null` or no member.
fn value_bytes(value: Option<&Json>) -> Result<Option<BTreeMap<String, Vec<u8>>>, Failure> {
    match value {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Object(values)) => values
            .iter()
            .map(|(name, v)| Ok((name.clone(), bytes(Some(v))?)))
            .collect::<Result<_, Failure>>()
            .map(Some),
        Some(_) => Err(Failure::BadRequest("values is no object".into())),
    }
}

/// `proposer` (section 5.15): one installation of a receiver that proposes changes
/// (`spec/shares.md`, sections 13 to 16).
fn proposer(input: &Map<String, Json>) -> Result<Json, Failure> {
    let device = object(input, "device")?;
    let mut manifests = HashMap::new();
    if let Some(given) = device.get("manifests").and_then(Json::as_object) {
        for (k, m) in given {
            let m = m
                .as_object()
                .ok_or_else(|| Failure::BadRequest("a manifest is no object".into()))?;
            manifests.insert(
                key(&json!(k))?,
                OwnerManifest {
                    revision: integer(m, "revision")?,
                    proposals: strings(m, "proposals")?.into_iter().collect(),
                },
            );
        }
    }
    let records = objects(device, "records")?
        .into_iter()
        .map(|r| {
            Ok(HeldOwnerRecord {
                id: string(r, "id")?.to_owned(),
                type_name: string(r, "type")?.to_owned(),
                version: required_version(r, "version")?,
                last: string(r, "last")?.to_owned(),
                schema: string(r, "schema")?.to_owned(),
                values: value_bytes(r.get("values"))?.unwrap_or_default(),
                deleted: flag(r, "deleted"),
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let owner_keys = strings(device, "owner")?
        .iter()
        .map(|k| key(&json!(k)))
        .collect::<Result<Vec<Key>, Failure>>()?;
    let mut proposer = ProposalProposer::start(
        SigningSeed::new(sized(device, "seed")?),
        owner_keys,
        manifests,
        records,
        strings(device, "proposal_ids")?,
        &strings(device, "schemas")?,
    )?;
    let messages = |messages: &[Vec<u8>]| json!({"messages": replies_json(messages)});
    let mut out = Vec::new();
    for step in steps_of(input)? {
        out.push(if step.contains_key("propose") {
            let p = object(step, "propose")?;
            let values = p
                .get("values")
                .and_then(Json::as_object)
                .ok_or_else(|| Failure::BadRequest("values is no object".into()))?
                .iter()
                .map(|(name, v)| {
                    Ok((
                        name.clone(),
                        match v {
                            Json::Null => None,
                            v => Some(bytes(Some(v))?),
                        },
                    ))
                })
                .collect::<Result<Vec<_>, Failure>>()?;
            let message = proposer.propose(
                string(p, "id")?,
                &key(p.get("to").unwrap_or(&Json::Null))?,
                &values,
                flag(p, "relay"),
            )?;
            json!({"message": message.map(|m| hex(&m))})
        } else if let Some(message) = step.get("receive") {
            let received = proposer.receive(&bytes(Some(message))?)?;
            json!({"result": received.result, "replies": replies_json(&received.replies)})
        } else if step.contains_key("record") {
            let r = object(step, "record")?;
            proposer.record_message(
                string(r, "id")?,
                string(r, "kind")?,
                required_version(r, "version")?,
                value_bytes(r.get("values"))?,
            );
            json!({})
        } else if step.contains_key("manifest") {
            let m = object(step, "manifest")?;
            proposer.manifest(
                key(m.get("key").unwrap_or(&Json::Null))?,
                OwnerManifest {
                    revision: integer(m, "revision")?,
                    proposals: strings(m, "proposals")?.into_iter().collect(),
                },
            );
            json!({})
        } else if let Some(removed) = step.get("remove") {
            messages(&proposer.remove(&key(removed)?)?)
        } else if let Some(connected) = step.get("connect") {
            messages(&proposer.connect(&key(connected)?))
        } else if step.contains_key("days") {
            messages(&proposer.days(integer(step, "days")?))
        } else if step.contains_key("query") {
            let query = proposer.query(string(step, "query")?);
            json!({
                "status": query.as_ref().map(|(status, _)| status.clone()),
                "resend": query.is_some_and(|(_, resend)| resend),
            })
        } else {
            return Err(Failure::BadRequest("a step of no known form".into()));
        });
    }
    Ok(json!({"steps": out}))
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
            json!([
                "encoding", "bricks", "types", "time", "keys", "manifest", "records", "file",
                "protocol", "shares"
            ])
        );
    }

    #[test]
    fn the_adapter_answers_the_sender_operations() {
        let output = |op: &str, input: Json| ask(op, input)["output"].clone();
        assert_eq!(
            output(
                "take_version",
                json!({"occasion": "withdraw", "highest_given": "3", "state_stamp": "3"})
            ),
            json!({"accept": {"version": "4", "state_stamp": "3"}})
        );
        assert_eq!(
            output(
                "owed",
                json!({"shared": false, "deleted": false, "version": "7", "withdrawal": "6",
                    "last": {"kind": "WITHDRAW", "version": "6"}})
            ),
            json!({"accept": {"owes": "WITHDRAW", "version": "6"}})
        );
        assert_eq!(
            output(
                "acked",
                json!({"held": null, "receiver_version": "7", "shared": false,
                    "withdrawal": "6", "state_stamp": "5", "sibling_stamp": null,
                    "sibling": true, "sent": "WITHDRAW", "outcome": "STALE"})
            ),
            json!({"accept": {"outcome": "STALE", "then": "wait", "to_pass": "7"}})
        );
        assert_eq!(
            output(
                "pass_withdrawal",
                json!({"shared": true, "withdrawal": "6", "to_pass": "8", "state_stamp": "7"})
            ),
            json!({"accept": {"then": "send_state", "to_pass": null}})
        );
        assert_eq!(
            output(
                "join_receivers",
                json!({"receivers": [{"shared": true, "withdrawal": null}]})
            ),
            json!({"accept": {"shared": true, "withdrawal": null, "new_state_stamp": false}})
        );
        assert_eq!(
            output(
                "offer_types",
                json!({"records": [{"type": "a", "owes": "DATA", "delivered": false}]})
            ),
            json!({"accept": {"types": [{"type": "a", "count": 1}]}})
        );
        let id = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80";
        let policy = json!({
            "local_changes": "per_field",
            "delete_with_local_changes": "delete",
            "withdraw_with_local_changes": "keep",
        });
        let receive = output(
            "receive",
            json!({"policy": policy, "events": [
                {"message": {"kind": "DATA", "id": id, "version": 1, "type": "a.M",
                    "value": {"t": "a"}}},
                {"local_change": {"id": id, "field": "t", "value": "b"}},
                {"message": {"kind": "WITHDRAW", "id": id, "version": 2}},
                {"local_take": {"id": id}},
            ]}),
        );
        assert_eq!(receive["steps"][3]["outcome"], "WITHDRAWN");
        for (op, bad) in [
            (
                "owed",
                json!({"shared": true, "deleted": false, "version": 7, "withdrawal": null,
                    "last": null}),
            ),
            (
                "owed",
                json!({"shared": true, "deleted": false, "version": "7", "withdrawal": null,
                    "last": {"kind": "X", "version": "1"}}),
            ),
            ("join_receivers", json!({"receivers": 1})),
            ("offer_types", json!({"records": 1})),
            (
                "receive",
                json!({"policy": {"local_changes": "per_field",
                    "delete_with_local_changes": "delete"},
                    "events": [{"local_take": {"id": id}}]}),
            ),
        ] {
            assert!(ask(op, bad.clone())["failure"].is_string(), "{op} {bad}");
        }
    }

    #[test]
    fn the_adapter_sorts_open_proposals_of_one_receiver_by_id() {
        let id = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80";
        let reply = ask(
            "owner",
            json!({
                "device": {
                    "seed": "01".repeat(32),
                    "open": [
                        {"receiver": "p", "proposal_id": "b", "id": id},
                        {"receiver": "p", "proposal_id": "a", "id": id},
                    ],
                },
                "steps": [{"query": true}],
            }),
        );
        let open = reply["output"]["steps"][0]["open"].as_array().unwrap();
        let ids: Vec<&Json> = open.iter().map(|p| &p["proposal_id"]).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn a_shared_value_keeps_the_relations_to_shared_records_of_the_own_set() {
        let shared = "0b6f4a3e-8c1d-4f27-9e5a-2d7c41b8e093";
        let own = "1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a";
        let relation = |id: &str, target: &str, sender: Json| {
            json!({"id": id, "kind": "axt.related",
                "target": {"id": target, "sender": sender, "type": "a.T", "text": ""},
                "note": "", "start": null, "end": null, "attributes": {}})
        };
        let kept = relation("f1b3d5a7-2c4e-4f60-8a1b-3c5d7e9f0a2b", shared, json!(own));
        let value = json!({
            "title": "Vet",
            "relations": [
                kept,
                relation("6c8e0a2b-4d6f-4a81-9c3e-5f7a9b1d3e60", shared, json!("ab".repeat(32))),
                relation("a2c4e6f8-0b1d-4e3f-8a5c-7e9f1b3d5a70", "5d2e9c71-3a4b-4e8f-b6d0-7f1a2c9e4b58", Json::Null),
            ],
            "extensions": [{"name": "a.E", "data": "c301"}],
        });
        let input = |links: bool| {
            json!({"type": "a.T", "value": value, "links": links, "own_user": false,
                "shared": [shared], "own_keys": [own]})
        };
        let reply = ask("shared_value", input(false));
        assert_eq!(
            reply["output"]["accept"]["value"],
            json!({"title": "Vet", "relations": [kept], "extensions": []})
        );
        let reply = ask("shared_value", input(true));
        assert_eq!(reply["output"]["accept"]["value"], value);
    }

    #[test]
    fn the_adapter_plays_a_session_of_apply() {
        let id = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80";
        let policy = json!({
            "local_changes": "whole_record_keep",
            "delete_with_local_changes": "delete",
        });
        let reply = ask(
            "apply",
            json!({
                "policy": policy,
                "events": [
                    {"message": {"kind": "DATA", "id": id, "version": 1, "type": "a.M",
                        "value": {"t": "a", "e": [{"name": "a.E", "data": "c301"}]}}},
                    {"local_change": {"id": id, "field": "t", "value": "b"}},
                    {"local_delete": {"id": id}},
                    {"message": {"kind": "WITHDRAW", "id": id, "version": 2}},
                    {"message": {"kind": "DELETE", "id": "x", "version": 2}},
                ],
            }),
        );
        let steps = reply["output"]["steps"].as_array().unwrap();
        assert_eq!(
            steps[0]["value"]["e"],
            json!([{"name": "a.E", "data": "c301"}])
        );
        assert_eq!(steps[1], json!({}));
        assert_eq!(steps[3]["outcome"], "WITHDRAWN");
        assert_eq!(steps[3]["state"], "deleted_by_user");
        assert_eq!(steps[4], json!({"error": "RECORD_ID_INVALID"}));
        let session = |policy: &Json, events: Json| json!({"policy": policy, "events": events});
        for bad in [
            json!({"policy": 1, "events": []}),
            json!({"policy": {"local_changes": "x", "delete_with_local_changes": "delete"},
                "events": []}),
            json!({"policy": {"local_changes": "per_field", "delete_with_local_changes": "x"},
                "events": []}),
            json!({"policy": policy, "events": 1}),
            session(&policy, json!([1])),
            session(&policy, json!([{}])),
            session(&policy, json!([{"local_delete": {"id": id}}])),
            session(&policy, json!([{"local_take": {"id": id}}])),
            session(
                &policy,
                json!([{"message": {"kind": "X", "id": id, "version": 1}}]),
            ),
            session(
                &policy,
                json!([{"message": {"kind": "DATA", "id": id, "version": "1"}}]),
            ),
        ] {
            assert!(ask("apply", bad.clone())["failure"].is_string(), "{bad}");
        }
        let kept = ask(
            "apply",
            json!({
                "policy": {"local_changes": "per_field", "delete_with_local_changes": "keep"},
                "events": [
                    {"message": {"kind": "DATA", "id": id, "version": 1, "type": "a.M",
                        "value": {"t": "a"}}},
                    {"local_change": {"id": id, "field": "t", "value": "b"}},
                    {"message": {"kind": "DELETE", "id": id, "version": 2}},
                    {"local_take": {"id": id}},
                ],
            }),
        );
        let steps = kept["output"]["steps"].as_array().unwrap();
        assert_eq!(steps[2]["outcome"], "KEPT");
        assert_eq!(steps[3]["outcome"], "APPLIED");
        assert_eq!(steps[3]["state"], "tombstone");
    }

    #[test]
    fn a_request_relations_cannot_read_is_a_failure() {
        let own = json!({"name": "me", "current": [], "removed": [], "records": []});
        for bad in [
            json!({"own": own, "senders": [], "refused": [], "relations": 1, "steps": []}),
            json!({"own": 1, "senders": [], "refused": [], "relations": [], "steps": []}),
            json!({"own": own, "senders": [], "refused": [], "relations": [{"id": "r"}],
                "steps": []}),
            json!({"own": own, "senders": [], "refused": [], "relations": [], "steps": [1]}),
        ] {
            assert!(
                ask("relations", bad.clone())["failure"].is_string(),
                "{bad}"
            );
        }
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

    #[test]
    fn the_adapter_checks_manifests_and_fits() {
        let schema = crate::schemas::axt_schema("axt.Manifest").unwrap();
        let manifest = json!({
            "revision": 1, "app_name": "cat-a-log", "app_url": null, "formats": [1],
            "takes": [{
                "type": "axt.example.v1.Pet", "min_version": 1, "max_version": null,
                "purpose": "A Pet becomes an animal.", "purpose_translations": {},
            }],
            "any_type": null, "sends": null, "encryption_key": null, "relay": null,
        });
        let body = hex(&schema
            .encode_single_object(&schema.datum_of_json(&manifest).unwrap())
            .unwrap());
        let ok = ask(
            "check_manifest",
            json!({"body": body, "envelope_format": 1}),
        );
        assert_eq!(ok["output"]["accept"]["manifest"], manifest);
        let bad = ask(
            "check_manifest",
            json!({"body": body, "envelope_format": 2}),
        );
        assert_eq!(
            bad["output"],
            json!({"reject": {"error": "MANIFEST_INVALID"}})
        );
        let unreadable = ask(
            "check_manifest",
            json!({"body": body, "envelope_format": "1"}),
        );
        assert!(unreadable["failure"].is_string());
        let fits = ask(
            "fit",
            json!({
                "manifest": body,
                "schema": r#"{"type":"record","name":"Pet","namespace":"axt.example.v1","fields":[]}"#,
                "languages": ["de"],
            }),
        );
        assert_eq!(
            fits["output"],
            json!({"accept": {"fits": true, "purpose": "A Pet becomes an animal."}})
        );
        let unreadable = ask(
            "fit",
            json!({"manifest": body, "schema": "\"int\"", "languages": [1]}),
        );
        assert!(unreadable["failure"].is_string());
    }

    #[test]
    fn the_format_both_read_the_contact_key_and_what_is_sent_again() {
        assert_eq!(
            ask("choose_format", json!({"own": [1, 2, 3], "theirs": [3, 1]})),
            json!({"id": "t", "output": {"accept": {"format": 3}}})
        );
        assert_eq!(
            ask("choose_format", json!({"own": [1], "theirs": [2]})),
            json!({"id": "t", "output": {"accept": {"format": null}}})
        );
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        let got = |messages: Json| {
            ask(
                "contact_key",
                json!({"current": [b, a, c], "manifests": [a, b], "got": messages}),
            )["output"]["accept"]["keys"]
                .clone()
        };
        assert_eq!(got(json!([])), json!([a, b]));
        assert_eq!(
            got(
                json!([{"key": b, "kind": "DATA"}, {"key": a, "kind": "MANIFEST"},
                       {"key": c, "kind": "DATA"}])
            ),
            json!([b])
        );
        let answer = ask(
            "resend_after_removal",
            json!({"removed": [a], "records": [
                {"id": "x", "outcomes": {a.clone(): "APPLIED"}},
                {"id": "y", "outcomes": {a.clone(): "APPLIED", b.clone(): "APPLIED"}},
                {"id": "z", "outcomes": {}},
            ]}),
        );
        assert_eq!(answer["output"]["accept"]["ids"], json!(["x", "z"]));
        assert!(ask("contact_key", json!({"current": [], "manifests": []}))["failure"].is_string());
    }

    #[test]
    fn a_session_answers_each_step() {
        let seed = "11".repeat(32);
        let peer = hex(&ed25519::public_key_of(&SigningSeed::new([0x22; 32])));
        let manifest = envelope::encode_message(&Envelope {
            kind: Kind::Manifest,
            sender: [0; 32],
            record: None,
            body: Vec::new(),
            signature: [0; 64],
        })
        .unwrap();
        let own_manifest = crate::schemas::axt_schema("axt.Manifest")
            .unwrap()
            .encode_single_object(
                &crate::schemas::axt_schema("axt.Manifest")
                    .unwrap()
                    .datum_of_json(&json!({
                        "revision": 1, "app_name": "app", "app_url": null, "formats": [1],
                        "takes": [], "any_type": null, "sends": null,
                        "encryption_key": null, "relay": null,
                    }))
                    .unwrap(),
            )
            .unwrap();
        let description = json!({
            "name": "root", "doc": "A type.", "texts": {},
            "kind": {"axt.ObjectField": {"name": "org.example.Memo", "fields": []}},
        });
        let app = json!({
            "seed": seed,
            "manifest": hex(&own_manifest),
            "formats": [1],
            "readers": {},
            "user_takes": [],
            "peer": peer,
        });
        let answer = ask(
            "session",
            json!({
                "app": app,
                "steps": [
                    {"receive": hex(&manifest)},
                    {"offer": {"offer_id": "6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b",
                               "types": [{"description": description, "count": 2}]}},
                    {"flush_acks": true},
                    {"close": true},
                    {"query": {"accepted": "org.example.Memo"}},
                    {"query": {"outcome": {"id": "x", "version": 1}}},
                    {"query": {"record": "x"}},
                    {"query": {"errors": true}},
                ],
            }),
        );
        let steps = answer["output"]["steps"].as_array().unwrap();
        assert_eq!(
            steps[0],
            json!({"outcome": null, "close": false, "replies": []}),
            "a message that does not verify before any manifest"
        );
        let offer =
            envelope::decode_message(&unhex(steps[1]["message"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(offer.kind, Kind::Offer);
        assert_eq!(
            hex(&offer.sender),
            hex(&ed25519::public_key_of(&SigningSeed::new([0x11; 32])))
        );
        assert!(signing::verify_live_message(
            &unhex(steps[1]["message"].as_str().unwrap()).unwrap(),
            &offer.sender
        ));
        assert_eq!(steps[2], json!({"replies": []}));
        assert_eq!(steps[3], json!({}));
        assert_eq!(steps[4], json!({"accepted": false}));
        assert_eq!(steps[5], json!({"outcome": null}));
        assert_eq!(steps[6], json!({"record": null}));
        assert_eq!(steps[7], json!({"errors": []}));
        let bad = ask("session", json!({"app": app, "steps": [{"dance": true}]}));
        assert!(bad["failure"].is_string());
    }
}
