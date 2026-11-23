//! Proposals: a receiver proposes a change of a record to its owner, and the owner's
//! user answers (AXT `spec/shares.md`, sections 12 to 20).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use crate::avro::split_single_object;
use crate::device_sets::Key;
use crate::ed25519;
use crate::element_parts::{
    PartName, decode_element_part, element_of, element_problem, encode_element_part,
    goes_without_links, key_text, part_name,
};
use crate::envelope::{self, Envelope, Kind, RecordRef};
use crate::error::{Error, ErrorCode};
use crate::keys::SigningSeed;
use crate::limits::{
    PROTOCOL_ERROR_RECORD_ID, SHARES_OPEN, SHARES_OPEN_PER_RECORD, SHARES_OPEN_VALUE_BYTES,
    SHARES_PROPOSAL_FIELD_NAME, SHARES_PROPOSAL_FIELDS, SHARES_PROPOSAL_VALUE_BYTES,
};
use crate::record_decoder::check_value;
use crate::records::{ElementKey, element_lists_of, record_key, same_value, set_field};
use crate::schema::Schema;
use crate::schemas::axt_schema;
use crate::signing::{signed_bytes_of_live_message, verify_live_message};
use crate::value::{Value, hex};

/// One entry of the `fields` of a `PROPOSAL`: the field's name, the fingerprint of the
/// schema of its value, and the value's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The field's name, or the name of a part.
    pub(crate) name: String,
    /// The fingerprint of the schema the value is written with.
    pub(crate) schema: [u8; 8],
    /// The value's bytes.
    pub(crate) value: Vec<u8>,
}

impl Entry {
    fn to_json(&self) -> Json {
        json!({"name": self.name, "schema": hex(&self.schema), "value": hex(&self.value)})
    }
}

/// A live message of `kind` from `key`, signed with `seed`, about `record`, with the body
/// `body` of the specification's schema `schema` in the form of `spec/conformance.md`,
/// section 3.3.
fn signed(
    seed: &SigningSeed,
    key: &Key,
    kind: Kind,
    record: Option<RecordRef>,
    schema: &str,
    body: &Json,
) -> Result<Vec<u8>, Error> {
    let invalid = |e: String| Error::axt(ErrorCode::InvalidMessage, e);
    let schema =
        axt_schema(schema).ok_or_else(|| invalid(format!("the schema {schema} is missing")))?;
    let body = schema
        .encode_single_object(&schema.datum_of_json(body).map_err(invalid)?)
        .map_err(invalid)?;
    let mut message = envelope::encode_message(&Envelope {
        kind,
        sender: *key,
        record,
        body,
        signature: [0; 64],
    })?;
    let unsigned = signed_bytes_of_live_message(&message)
        .ok_or_else(|| invalid("the message is too short".into()))?;
    let signature = ed25519::sign(seed, &unsigned);
    if let Some((_, last)) = message.split_last_chunk_mut::<64>() {
        *last = signature;
    }
    Ok(message)
}

/// The `ERROR` from `key` to `to` about `message`.
#[expect(
    clippy::too_many_arguments,
    reason = "the members of an ERROR, as the specification lists them"
)]
fn error_message(
    seed: &SigningSeed,
    key: &Key,
    message: &[u8],
    to: &Key,
    code: ErrorCode,
    record: Option<&RecordRef>,
    fingerprint: Option<&[u8; 8]>,
    field: Option<&str>,
) -> Result<Vec<u8>, Error> {
    let record = record
        .filter(|r| r.id.len() <= PROTOCOL_ERROR_RECORD_ID)
        .map(|r| json!({"id": r.id, "version": r.version}));
    signed(
        seed,
        key,
        Kind::Error,
        None,
        "axt.Error",
        &json!({
            "to": hex(to),
            "code": code.as_str(),
            "message_hash": hex(&Sha256::digest(message)),
            "record": record,
            "fingerprint": fingerprint.map(|f| hex(f)),
            "field": field,
            "detail": "",
        }),
    )
}

/// The string of the field `name` of a record, or `None`.
fn text<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    match value.field(name) {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

/// The bytes of the field `name` of a record, fixed or bytes, or `None`.
fn bytes_of<'a>(value: &'a Value, name: &str) -> Option<&'a [u8]> {
    match value.field(name) {
        Some(Value::Bytes(b) | Value::Fixed(b)) => Some(b),
        _ => None,
    }
}

/// The items of a list; none for another value.
fn list_of(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

/// The entries of the body of a `PROPOSAL`.
fn entries_of(body: &Value) -> Vec<Entry> {
    list_of(body.field("fields"))
        .iter()
        .map(|f| Entry {
            name: text(f, "name").unwrap_or_default().to_owned(),
            schema: bytes_of(f, "schema")
                .and_then(|b| b.try_into().ok())
                .unwrap_or_default(),
            value: bytes_of(f, "value").unwrap_or_default().to_vec(),
        })
        .collect()
}

/// The part of `name` up to the first `.` or `[`: the top-level field of a path.
fn top_of(path: &str) -> &str {
    path.split(['.', '[']).next().unwrap_or(path)
}

/// Whether `a` and `b` are the same record id, ignoring case.
fn same_id(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// A receiver of the owner's records, as the owner's device knows it.
#[derive(Debug, Clone)]
pub(crate) struct ProposalReceiver {
    /// The receiver's name.
    pub(crate) name: String,
    /// Its current keys.
    pub(crate) current: BTreeSet<Key>,
    /// Its removed keys.
    pub(crate) removed: BTreeSet<Key>,
    /// Whether it is an app of the owner's own user.
    pub(crate) own_user: bool,
    /// Whether its shares let the links of its records go along (section 19.1).
    pub(crate) links: bool,
}

impl ProposalReceiver {
    /// Whether it gets every record whole, its links included.
    fn gets_links(&self) -> bool {
        self.own_user || self.links
    }
}

/// A record of the owner's own set.
#[derive(Debug, Clone)]
pub(crate) struct OwnRecord {
    /// The record's id.
    pub(crate) id: String,
    /// The full name of its type.
    pub(crate) type_name: String,
    /// Its version.
    pub(crate) version: i64,
    /// Whether it is deleted.
    pub(crate) deleted: bool,
    /// Its value.
    pub(crate) value: Value,
    /// The names of the receivers it is shared with.
    pub(crate) shared: BTreeSet<String>,
}

/// An open proposal at the owner.
#[derive(Debug, Clone)]
pub(crate) struct OpenProposal {
    /// The name of the receiver that proposed it.
    pub(crate) receiver: String,
    /// The proposal's id.
    pub(crate) proposal_id: String,
    /// The id of the proposal's record.
    pub(crate) id: String,
    /// The record's version that the proposal was made for.
    pub(crate) version: i64,
    /// Its value bytes.
    pub(crate) value_bytes: usize,
    /// The `PROPOSAL`, where the device holds it.
    pub(crate) message: Option<Vec<u8>>,
    /// The key that signed it.
    pub(crate) signer: Option<Key>,
    /// Its entries.
    pub(crate) fields: Vec<Entry>,
}

/// An answer that the owner's app holds.
#[derive(Debug, Clone)]
pub(crate) struct ProposalAnswer {
    /// The name of the receiver that proposed it.
    pub(crate) receiver: String,
    /// The proposal's id.
    pub(crate) proposal_id: String,
    /// `ACCEPTED` or `DECLINED`.
    pub(crate) answer: String,
    /// The id of the proposal's record.
    pub(crate) id: String,
    /// The record's version that the proposal was made for.
    pub(crate) version: i64,
}

/// A stop of a receiver's proposals, for one record, one type, or all.
#[derive(Debug, Clone)]
pub(crate) struct Stop {
    /// The receiver's name.
    pub(crate) receiver: String,
    /// The record it stops, if one.
    pub(crate) id: Option<String>,
    /// The type it stops, if one.
    pub(crate) type_name: Option<String>,
}

/// The result of a received message: `taken`, `repeat`, `replaced`, `ignored` or
/// `rejected`, and the replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Received {
    /// What became of the message.
    pub(crate) result: &'static str,
    /// The messages sent back.
    pub(crate) replies: Vec<Vec<u8>>,
}

impl Received {
    fn of(result: &'static str) -> Self {
        Self {
            result,
            replies: Vec::new(),
        }
    }
}

/// What an answer of the owner's user made.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Answered {
    /// Whether the answer was made.
    pub(crate) made: bool,
    /// The `PROPOSAL_REPLY`, where one is sent.
    pub(crate) replies: Vec<Vec<u8>>,
    /// For `ACCEPTED`, the record's new version and value.
    pub(crate) update: Option<(i64, Value)>,
}

impl Answered {
    fn not_made() -> Self {
        Self {
            made: false,
            replies: Vec::new(),
            update: None,
        }
    }
}

/// What the owner's device holds when it starts.
pub(crate) struct OwnerState {
    /// The keys of its siblings.
    pub(crate) siblings: BTreeSet<Key>,
    /// The types for which its manifest takes proposals.
    pub(crate) proposals: BTreeSet<String>,
    /// The schema texts it holds.
    pub(crate) schemas: Vec<String>,
    /// Its receivers.
    pub(crate) receivers: Vec<ProposalReceiver>,
    /// Its records.
    pub(crate) records: Vec<OwnRecord>,
    /// Its reader schema texts by type, if it has its own.
    pub(crate) readers: Option<BTreeMap<String, String>>,
    /// The open proposals.
    pub(crate) open: Vec<OpenProposal>,
    /// The answers its app's records hold.
    pub(crate) answers: Vec<ProposalAnswer>,
    /// The stops of its user.
    pub(crate) stops: Vec<Stop>,
}

/// One installation of the owner of shared records, which counts its versions and takes
/// proposals of its receivers.
pub(crate) struct ProposalOwner {
    seed: SigningSeed,
    key: Key,
    siblings: BTreeSet<Key>,
    /// The types for which its manifest takes proposals.
    pub(crate) proposals: BTreeSet<String>,
    /// The schemas it holds, each fingerprint once, in the order given.
    schemas: Vec<Schema>,
    receivers: Vec<ProposalReceiver>,
    /// Its records.
    pub(crate) records: Vec<OwnRecord>,
    readers: Option<BTreeMap<String, String>>,
    /// The open proposals.
    pub(crate) open: Vec<OpenProposal>,
    /// The answers its app's records hold.
    pub(crate) answers: Vec<ProposalAnswer>,
    stops: Vec<Stop>,
}

impl ProposalOwner {
    /// The owner with the signing key `seed` and the state `state`.
    ///
    /// # Errors
    ///
    /// `DOES_NOT_RESOLVE` for a schema text that is no schema.
    pub(crate) fn start(seed: SigningSeed, state: OwnerState) -> Result<Self, Error> {
        let mut schemas: Vec<Schema> = Vec::new();
        for text in &state.schemas {
            let schema = Schema::parse(text)?;
            if schemas
                .iter()
                .all(|s| s.fingerprint() != schema.fingerprint())
            {
                schemas.push(schema);
            }
        }
        Ok(Self {
            key: ed25519::public_key_of(&seed),
            seed,
            siblings: state.siblings,
            proposals: state.proposals,
            schemas,
            receivers: state.receivers,
            records: state.records,
            readers: state.readers,
            open: state.open,
            answers: state.answers,
            stops: state.stops,
        })
    }

    fn schema(&self, fingerprint: &[u8; 8]) -> Option<&Schema> {
        self.schemas
            .iter()
            .find(|s| s.fingerprint().0 == *fingerprint)
    }

    fn receiver_of(&self, key: &Key) -> Option<&ProposalReceiver> {
        self.receivers
            .iter()
            .find(|r| r.current.contains(key) || r.removed.contains(key))
    }

    fn record_at(&self, id: &str) -> Option<usize> {
        self.records.iter().position(|r| same_id(&r.id, id))
    }

    fn record(&self, id: &str) -> Option<&OwnRecord> {
        self.records.iter().find(|r| same_id(&r.id, id))
    }

    fn stopped(&self, receiver: &str, record: &OwnRecord) -> bool {
        stopped(&self.stops, receiver, record)
    }

    /// The schema of the record's type that the device holds, or `None`.
    fn type_schema(&self, record: &OwnRecord) -> Option<&Schema> {
        self.schemas
            .iter()
            .find(|s| s.record_name().as_deref() == Some(record.type_name.as_str()))
    }

    /// The ids of the records shared with `receiver`, and the keys of the own set, which
    /// decide what goes along without the links.
    fn links_of(&self, receiver: &ProposalReceiver) -> (HashSet<String>, BTreeSet<Key>) {
        let shared = self
            .records
            .iter()
            .filter(|r| !r.deleted && r.shared.contains(&receiver.name))
            .map(|r| r.id.clone())
            .collect();
        let mut own_keys = self.siblings.clone();
        own_keys.insert(self.key);
        (shared, own_keys)
    }

    /// Whether an entry of `fields` is a part of an element that `record` holds and the
    /// shares of `receiver` left out (section 20.2).
    fn left_out_part(
        &self,
        record: &OwnRecord,
        receiver: &ProposalReceiver,
        fields: &[Entry],
    ) -> bool {
        let Some(schema) = self.type_schema(record) else {
            return false;
        };
        if receiver.gets_links() {
            return false;
        }
        let lists = element_lists_of(schema);
        let (shared, own_keys) = self.links_of(receiver);
        fields.iter().any(|field| {
            let Ok(Some(part)) = part_name(&field.name) else {
                return false;
            };
            let Some(&kind) = lists.get(&part.list) else {
                return false;
            };
            let Some(Value::Array(list)) = record.value.field(&part.list) else {
                return false;
            };
            element_of(kind, list, &part.key)
                .is_some_and(|e| !goes_without_links(kind, e, &shared, &own_keys))
        })
    }

    /// `proposed`, a list proposed whole, with every element of `held` that the shares of
    /// `receiver` left out kept after it, unless the proposal holds its key (section
    /// 19.3).
    fn keep_left_out(
        &self,
        kind: ElementKey,
        proposed: &[Value],
        held: &[Value],
        receiver: &ProposalReceiver,
    ) -> Vec<Value> {
        let (shared, own_keys) = self.links_of(receiver);
        let keys: HashSet<String> = proposed.iter().map(|e| key_text(kind, e)).collect();
        proposed
            .iter()
            .cloned()
            .chain(
                held.iter()
                    .filter(|e| {
                        !keys.contains(&key_text(kind, e))
                            && !goes_without_links(kind, e, &shared, &own_keys)
                    })
                    .cloned(),
            )
            .collect()
    }

    fn reply(
        &self,
        to: &Key,
        id: &str,
        version: i64,
        proposal_id: &str,
        answer: &str,
    ) -> Result<Vec<u8>, Error> {
        signed(
            &self.seed,
            &self.key,
            Kind::ProposalReply,
            Some(RecordRef {
                id: id.to_owned(),
                version,
            }),
            "axt.ProposalReply",
            &json!({"to": hex(to), "proposal_id": proposal_id, "answer": answer}),
        )
    }

    /// Processes a `PROPOSAL` of a key of a receiver, a sibling or its own (sections 13.3
    /// and 13.4).
    ///
    /// # Errors
    ///
    /// Only when a reply cannot be written.
    pub(crate) fn receive(&mut self, message: &[u8]) -> Result<Received, Error> {
        let Ok(envelope) = envelope::decode_message(message) else {
            // No sender can be told, so it is rejected without a report.
            return Ok(Received::of("rejected"));
        };
        let signer = envelope.sender;
        if signer == self.key {
            return Ok(Received::of("ignored"));
        }
        let receiver = self.receiver_of(&signer).cloned();
        if receiver.is_none() && !self.siblings.contains(&signer) {
            return Ok(Received::of("ignored"));
        }
        let reject = |owner: &Self,
                      code: ErrorCode,
                      fingerprint: Option<&[u8; 8]>,
                      field: Option<&str>|
         -> Result<Received, Error> {
            Ok(Received {
                result: "rejected",
                replies: vec![error_message(
                    &owner.seed,
                    &owner.key,
                    message,
                    &signer,
                    code,
                    envelope.record.as_ref(),
                    fingerprint,
                    field,
                )?],
            })
        };
        if !verify_live_message(message, &signer) {
            return Ok(Received {
                result: "rejected",
                replies: vec![error_message(
                    &self.seed,
                    &self.key,
                    message,
                    &signer,
                    ErrorCode::SignatureInvalid,
                    None,
                    None,
                    None,
                )?],
            });
        }
        if receiver
            .as_ref()
            .is_some_and(|r| r.removed.contains(&signer))
        {
            return Ok(Received::of("ignored"));
        }
        if envelope.kind != Kind::Proposal {
            return reject(self, ErrorCode::InvalidMessage, None, None);
        }
        let Some(reference) = envelope.record.clone() else {
            return reject(self, ErrorCode::InvalidMessage, None, None);
        };
        let Ok(body) = envelope::decode_body(Kind::Proposal, &envelope.body) else {
            return reject(self, ErrorCode::InvalidMessage, None, None);
        };
        if bytes_of(&body, "to") != Some(self.key.as_slice()) {
            return Ok(Received::of("ignored"));
        }
        if record_key(&reference.id).is_none() {
            return reject(self, ErrorCode::RecordIdInvalid, None, None);
        }
        if reference.version < 1 {
            return reject(self, ErrorCode::VersionInvalid, None, None);
        }
        let proposal_id = text(&body, "proposal_id").unwrap_or_default().to_owned();
        let fields = entries_of(&body);
        let mut names: HashSet<String> = HashSet::new();
        let names_break = fields.iter().any(|f| {
            !(1..=SHARES_PROPOSAL_FIELD_NAME).contains(&f.name.len())
                || !names.insert(f.name.clone())
        });
        if record_key(&proposal_id).is_none()
            || fields.is_empty()
            || fields.len() > SHARES_PROPOSAL_FIELDS
            || names_break
        {
            return reject(self, ErrorCode::InvalidMessage, None, None);
        }
        let name = receiver.as_ref().map(|r| r.name.as_str());
        // A repeat of an answered proposal gets its reply again (13.4).
        if let Some(answer) = self
            .answers
            .iter()
            .find(|a| Some(a.receiver.as_str()) == name && a.proposal_id == proposal_id)
        {
            return Ok(Received {
                result: "repeat",
                replies: vec![self.reply(
                    &signer,
                    &answer.id,
                    answer.version,
                    &proposal_id,
                    &answer.answer,
                )?],
            });
        }
        let value_bytes = fields
            .iter()
            .fold(0usize, |n, f| n.saturating_add(f.value.len()));
        if let Some(held) = self
            .open
            .iter_mut()
            .find(|p| Some(p.receiver.as_str()) == name && p.proposal_id == proposal_id)
        {
            let higher = held
                .message
                .as_ref()
                .is_some_and(|m| hex(&Sha256::digest(message)) > hex(&Sha256::digest(m)));
            if higher {
                held.message = Some(message.to_vec());
                held.signer = Some(signer);
                held.fields = fields;
                return Ok(Received::of("replaced"));
            }
            return Ok(Received::of("repeat"));
        }
        let record = self.record(&reference.id).cloned();
        let (Some(receiver), Some(record)) = (receiver, record) else {
            return reject(self, ErrorCode::ProposalsNotTaken, None, None);
        };
        let of_proposer: Vec<&OpenProposal> = self
            .open
            .iter()
            .filter(|p| p.receiver == receiver.name)
            .collect();
        let open_bytes = of_proposer
            .iter()
            .fold(0usize, |n, p| n.saturating_add(p.value_bytes));
        let for_record = of_proposer
            .iter()
            .filter(|p| same_id(&p.id, &record.id))
            .count();
        if record.deleted
            || !(record.shared.contains(&receiver.name) || receiver.own_user)
            || !self.proposals.contains(&record.type_name)
            || self.stopped(&receiver.name, &record)
            || value_bytes > SHARES_PROPOSAL_VALUE_BYTES
            || open_bytes.saturating_add(value_bytes) > SHARES_OPEN_VALUE_BYTES
            || for_record >= SHARES_OPEN_PER_RECORD
            || of_proposer.len() >= SHARES_OPEN
            || self.left_out_part(&record, &receiver, &fields)
        {
            return reject(self, ErrorCode::ProposalsNotTaken, None, None);
        }
        if let Some(unknown) = fields.iter().find(|f| self.schema(&f.schema).is_none()) {
            return reject(self, ErrorCode::SchemaUnknown, Some(&unknown.schema), None);
        }
        for field in &fields {
            let Some(schema) = self.schema(&field.schema) else {
                continue;
            };
            let part = match part_name(&field.name) {
                Ok(part) => part,
                Err(e) => {
                    return reject(
                        self,
                        e.code().unwrap_or(ErrorCode::InvalidMessage),
                        None,
                        None,
                    );
                }
            };
            if let Some(part) = part {
                if names.contains(&part.list) {
                    return reject(self, ErrorCode::InvalidMessage, None, None);
                }
                let problem = if part.field.is_none() {
                    self.check_element_part(&record, schema, &part, field)
                } else {
                    self.check_extension_part(&record, schema, &part, field)
                };
                if let Some((code, path)) = problem {
                    return reject(self, code, None, path.as_deref());
                }
                continue;
            }
            let found = (schema.record_name().as_deref() == Some(record.type_name.as_str()))
                .then(|| schema.field_schema(&field.name))
                .flatten();
            let Some(found) = found else {
                return reject(self, ErrorCode::InvalidMessage, None, None);
            };
            let Ok(value) = found.decode_datum(&field.value) else {
                return reject(self, ErrorCode::Undecodable, None, None);
            };
            if let Err(e) = check_value(&found, &value, &field.name, 1) {
                return reject(self, code_of(&e), None, field_of(&e));
            }
        }
        self.open.push(OpenProposal {
            receiver: receiver.name.clone(),
            proposal_id,
            id: reference.id,
            version: reference.version,
            value_bytes,
            message: Some(message.to_vec()),
            signer: Some(signer),
            fields,
        });
        Ok(Received::of("taken"))
    }

    /// The list field of `part` in `schema` when it is a schema of the record's type in
    /// which the list is merged per element: its key and the schema of its items.
    fn element_list(
        record: &OwnRecord,
        schema: &Schema,
        part: &PartName,
    ) -> Option<(ElementKey, Schema)> {
        if schema.record_name().as_deref() != Some(record.type_name.as_str()) {
            return None;
        }
        let kind = *element_lists_of(schema).get(&part.list)?;
        let items = schema.field_schema(&part.list)?.items_schema()?;
        Some((kind, items))
    }

    /// Steps 7 to 9 for an element part (section 20.1): the error, or `None`.
    fn check_element_part(
        &self,
        record: &OwnRecord,
        schema: &Schema,
        part: &PartName,
        field: &Entry,
    ) -> Option<(ErrorCode, Option<String>)> {
        let invalid = Some((ErrorCode::InvalidMessage, None));
        let Some((kind, items)) = Self::element_list(record, schema, part) else {
            return invalid;
        };
        if kind == ElementKey::Id && record_key(&part.key).as_deref() != Some(part.key.as_str()) {
            return invalid;
        }
        let element = match decode_element_part(&items, &field.value) {
            Ok(element) => element?,
            Err(e) => return Some((code_of(&e), None)),
        };
        element_problem(kind, &field.name, &part.key, &element)
            .map(|path| (ErrorCode::ValueInvalid, Some(path)))
    }

    /// The schema of the field of a part within an extension in the entry's `schema`,
    /// when the device holds a schema of the record's type with the list as a list of
    /// extensions.
    fn extension_field(
        &self,
        record: &OwnRecord,
        schema: &Schema,
        part: &PartName,
    ) -> Option<Schema> {
        let holds = self.schemas.iter().any(|s| {
            s.record_name().as_deref() == Some(record.type_name.as_str())
                && element_lists_of(s).get(&part.list) == Some(&ElementKey::Name)
        });
        if !holds || schema.record_name().as_deref() != Some(part.key.as_str()) {
            return None;
        }
        schema.field_schema(part.field.as_deref()?)
    }

    /// Steps 7 to 9 for a part within an extension: the error, or `None`.
    fn check_extension_part(
        &self,
        record: &OwnRecord,
        schema: &Schema,
        part: &PartName,
        field: &Entry,
    ) -> Option<(ErrorCode, Option<String>)> {
        let Some(found) = self.extension_field(record, schema, part) else {
            return Some((ErrorCode::InvalidMessage, None));
        };
        let Ok(value) = found.decode_datum(&field.value) else {
            return Some((ErrorCode::Undecodable, None));
        };
        check_value(&found, &value, &field.name, 1)
            .err()
            .map(|e| (code_of(&e), field_of(&e).map(str::to_owned)))
    }

    /// The decoded value of `field` of an open proposal, read with its entry's schema and
    /// resolved against the reader schema, or `None` when the device cannot show it.
    fn show(&self, record: &OwnRecord, field: &Entry) -> Option<Value> {
        let schema = self.schema(&field.schema)?;
        if let Some(part) = part_name(&field.name).ok()? {
            if part.field.is_none() {
                let (_, items) = Self::element_list(record, schema, &part)?;
                return Some(
                    decode_element_part(&items, &field.value)
                        .ok()?
                        .unwrap_or(Value::Null),
                );
            }
            let found = self.extension_field(record, schema, &part)?;
            return found.decode_datum(&field.value).ok();
        }
        let found = schema.field_schema(&field.name)?;
        let value = match self.readers.as_ref().and_then(|r| r.get(&record.type_name)) {
            Some(text) => {
                let reader = Schema::parse(text).ok()?.field_schema(&field.name)?;
                let resolution = found.resolution(&reader).ok()?;
                found.decode_datum_as(&resolution, &field.value).ok()?
            }
            None => found.decode_datum(&field.value).ok()?,
        };
        check_value(&found, &value, &field.name, 1).ok()?;
        Some(value)
    }

    /// Its user answers an open proposal (sections 15.1 and 15.2).
    ///
    /// # Errors
    ///
    /// When a reply cannot be written or an extension cannot be set.
    pub(crate) fn answer(
        &mut self,
        receiver: &str,
        proposal_id: &str,
        answer: &str,
    ) -> Result<Answered, Error> {
        let Some(at) = self
            .open
            .iter()
            .position(|p| p.receiver == receiver && p.proposal_id == proposal_id)
        else {
            return Ok(Answered::not_made());
        };
        let Some(proposal) = self.open.get(at).cloned() else {
            return Ok(Answered::not_made());
        };
        let Some(record) = self.record(&proposal.id).cloned() else {
            return Ok(Answered::not_made());
        };
        if record.deleted {
            return Ok(Answered::not_made());
        }
        let accepted = answer == "ACCEPTED";
        let mut shown = Vec::new();
        if accepted {
            if proposal.message.is_none() {
                return Ok(Answered::not_made());
            }
            for field in &proposal.fields {
                let Some(value) = self.show(&record, field) else {
                    return Ok(Answered::not_made());
                };
                shown.push(value);
            }
        }
        self.open.remove(at);
        self.answers.push(ProposalAnswer {
            receiver: receiver.to_owned(),
            proposal_id: proposal_id.to_owned(),
            answer: answer.to_owned(),
            id: proposal.id.clone(),
            version: proposal.version,
        });
        let proposer = self.receivers.iter().find(|r| r.name == receiver).cloned();
        let mut replies = Vec::new();
        if let Some(signer) = proposal.signer
            && !proposer
                .as_ref()
                .is_some_and(|r| r.removed.contains(&signer))
        {
            replies.push(self.reply(
                &signer,
                &proposal.id,
                proposal.version,
                proposal_id,
                answer,
            )?);
        }
        if !accepted {
            return Ok(Answered {
                made: true,
                replies,
                update: None,
            });
        }
        let proposer = proposer.ok_or_else(|| {
            Error::axt(
                ErrorCode::InvalidMessage,
                format!("{receiver} is no receiver"),
            )
        })?;
        let mut value = record.value.clone();
        let lists = self
            .type_schema(&record)
            .map(element_lists_of)
            .unwrap_or_default();
        for (field, proposed) in proposal.fields.iter().zip(shown) {
            let part = part_name(&field.name)?;
            match part {
                None => {
                    let new = match lists.get(&field.name) {
                        Some(&kind) if !proposer.gets_links() => Value::Array(self.keep_left_out(
                            kind,
                            list_of(Some(&proposed)),
                            list_of(value.field(&field.name)),
                            &proposer,
                        )),
                        _ => proposed,
                    };
                    set_field(&mut value, &field.name, new);
                }
                Some(part) if part.field.is_none() => {
                    let Some(&kind) = lists.get(&part.list) else {
                        continue;
                    };
                    let mut list = list_of(value.field(&part.list)).to_vec();
                    let at = list.iter().position(|e| key_text(kind, e) == part.key);
                    match (proposed, at) {
                        (Value::Null, Some(at)) => {
                            list.remove(at);
                        }
                        (Value::Null, None) => {}
                        (element, Some(at)) => {
                            if let Some(slot) = list.get_mut(at) {
                                *slot = element;
                            }
                        }
                        (element, None) => list.push(element),
                    }
                    set_field(&mut value, &part.list, Value::Array(list));
                }
                Some(part) => {
                    if let Some(within) = self.set_within(value.field(&part.list), &part, field)? {
                        set_field(&mut value, &part.list, within);
                    }
                }
            }
        }
        let version = record
            .version
            .checked_add(1)
            .ok_or_else(|| Error::axt(ErrorCode::VersionInvalid, "the versions are spent"))?;
        if let Some(own) = self
            .record_at(&record.id)
            .and_then(|i| self.records.get_mut(i))
        {
            own.version = version;
            own.value = value.clone();
        }
        Ok(Answered {
            made: true,
            replies,
            update: Some((version, value)),
        })
    }

    /// The list of extensions `list` with the field of `part` set within its extension,
    /// encoded again with the device's own schema of the type (section 20.3); `None` where
    /// it is no list.
    fn set_within(
        &self,
        list: Option<&Value>,
        part: &PartName,
        field: &Entry,
    ) -> Result<Option<Value>, Error> {
        let Some(Value::Array(list)) = list else {
            return Ok(None);
        };
        let undecodable = |e: String| Error::axt(ErrorCode::Undecodable, e);
        let missing = || undecodable(format!("no schema of {}", part.key));
        let entry = self.schema(&field.schema).ok_or_else(missing)?;
        let own = self
            .schemas
            .iter()
            .find(|s| s.record_name().as_deref() == Some(part.key.as_str()))
            .ok_or_else(missing)?;
        let name = part.field.as_deref().ok_or_else(missing)?;
        let mut out = Vec::with_capacity(list.len());
        for element in list {
            if text(element, "name") != Some(part.key.as_str()) {
                out.push(element.clone());
                continue;
            }
            let data = bytes_of(element, "data").unwrap_or_default();
            let (fingerprint, payload) =
                split_single_object(data).ok_or_else(|| undecodable("no single object".into()))?;
            let writer = self.schema(&fingerprint).unwrap_or(own);
            let mut decoded = writer
                .decode_datum_as(&writer.resolution(own).map_err(undecodable)?, payload)
                .map_err(undecodable)?;
            let own_field = own.field_schema(name).ok_or_else(missing)?;
            let entry_field = entry.field_schema(name).ok_or_else(missing)?;
            let set = entry_field
                .decode_datum_as(
                    &entry_field.resolution(&own_field).map_err(undecodable)?,
                    &field.value,
                )
                .map_err(undecodable)?;
            set_field(&mut decoded, name, set);
            out.push(Value::Record(vec![
                ("name".into(), Value::String(part.key.clone())),
                (
                    "data".into(),
                    Value::Bytes(own.encode_single_object(&decoded).map_err(undecodable)?),
                ),
            ]));
        }
        Ok(Some(Value::Array(out)))
    }

    /// An answer of a sibling comes into the app's records; `ACCEPTED` stands.
    pub(crate) fn answered(&mut self, answer: ProposalAnswer) {
        self.open
            .retain(|p| !(p.receiver == answer.receiver && p.proposal_id == answer.proposal_id));
        match self
            .answers
            .iter_mut()
            .find(|a| a.receiver == answer.receiver && a.proposal_id == answer.proposal_id)
        {
            None => self.answers.push(answer),
            Some(held) => {
                if answer.answer == "ACCEPTED" {
                    held.answer = answer.answer;
                }
            }
        }
    }

    /// Its user stops the proposals of a receiver (section 18.4).
    pub(crate) fn stop(&mut self, stop: Stop) {
        self.stops.push(stop.clone());
        let records = &self.records;
        let stops = &self.stops;
        self.open.retain(|p| {
            let record = records.iter().find(|r| same_id(&r.id, &p.id));
            !(p.receiver == stop.receiver
                && record.is_some_and(|r| stopped(stops, &stop.receiver, r)))
        });
    }

    /// The record is deleted (`delete`), no longer shared with a receiver (`unshare`), or
    /// shared again (section 15.4).
    pub(crate) fn change(&mut self, id: &str, action: &str, receiver: Option<&str>) {
        let Some(record) = self.record_at(id).and_then(|i| self.records.get_mut(i)) else {
            return;
        };
        match action {
            "delete" => {
                record.deleted = true;
                self.open.retain(|p| !same_id(&p.id, id));
            }
            "unshare" => {
                if let Some(receiver) = receiver {
                    record.shared.remove(receiver);
                }
                self.open
                    .retain(|p| !(Some(p.receiver.as_str()) == receiver && same_id(&p.id, id)));
            }
            _ => {
                if let Some(receiver) = receiver {
                    record.shared.insert(receiver.to_owned());
                }
            }
        }
    }
}

/// Whether `stops` stop the proposals of `receiver` for `record`.
fn stopped(stops: &[Stop], receiver: &str, record: &OwnRecord) -> bool {
    stops.iter().any(|s| {
        s.receiver == receiver
            && s.id.as_deref().is_none_or(|id| same_id(id, &record.id))
            && s.type_name.as_deref().is_none_or(|t| t == record.type_name)
    })
}

/// The code of an error of the library.
fn code_of(e: &Error) -> ErrorCode {
    e.code().unwrap_or(ErrorCode::InvalidMessage)
}

/// The `field` of an error of the library.
fn field_of(e: &Error) -> Option<&str> {
    match e {
        Error::Axt { field, .. } => field.as_deref(),
        Error::Store(_) => None,
    }
}

/// Whether `bytes` are the datum `value` of `schema`: the same bytes, or bytes that read
/// as the same value, as the entries of a map may be written in any order.
fn same_datum(schema: &Schema, value: &Value, bytes: &[u8]) -> Result<bool, Error> {
    let written = schema
        .encode_datum(value)
        .map_err(|e| Error::axt(ErrorCode::Undecodable, e))?;
    Ok(written == bytes
        || schema
            .decode_datum(bytes)
            .is_ok_and(|read| same_value(&read, value)))
}

/// Whether `bytes` are the element part of `element` under `items` (see [`same_datum`]).
fn same_element_part(items: &Schema, element: Option<&Value>, bytes: &[u8]) -> Result<bool, Error> {
    let written =
        encode_element_part(items, element).map_err(|e| Error::axt(ErrorCode::Undecodable, e))?;
    Ok(written == bytes
        || decode_element_part(items, bytes).is_ok_and(|read| match (&read, element) {
            (Some(read), Some(element)) => same_value(read, element),
            (None, None) => true,
            _ => false,
        }))
}

/// A record of the owner that a proposer holds.
#[derive(Debug, Clone)]
pub(crate) struct HeldOwnerRecord {
    /// The record's id.
    pub(crate) id: String,
    /// The full name of its type.
    pub(crate) type_name: String,
    /// The version it holds.
    pub(crate) version: i64,
    /// The kind of the last record message of the owner, such as `DATA`.
    pub(crate) last: String,
    /// The writer schema text of the record.
    pub(crate) schema: String,
    /// The bytes of each field's value as the record holds it.
    pub(crate) values: BTreeMap<String, Vec<u8>>,
    /// Whether it is deleted.
    pub(crate) deleted: bool,
}

/// A proposal that a proposer sent.
#[derive(Debug, Clone)]
struct SentProposal {
    id: String,
    proposal_id: String,
    to: Key,
    message: Vec<u8>,
    fields: Vec<Entry>,
    relay: bool,
    status: Option<String>,
    settled: bool,
    days_since_sent: i64,
}

/// A block of new proposals for a record, after an error (section 16.3).
#[derive(Debug, Clone)]
struct Block {
    code: String,
    field: Option<String>,
    value: Option<Vec<u8>>,
}

/// What a proposer knows of a key of the owner: the revision of its manifest and the
/// types for which it takes proposals.
#[derive(Debug, Clone, Default)]
pub(crate) struct OwnerManifest {
    /// The manifest's revision.
    pub(crate) revision: i64,
    /// The types for which it takes proposals.
    pub(crate) proposals: BTreeSet<String>,
}

/// One installation of a receiver that proposes changes of the records of one owner
/// (sections 13.1, 14.2 and 16).
pub(crate) struct ProposalProposer {
    seed: SigningSeed,
    key: Key,
    owner: Vec<Key>,
    manifests: HashMap<Key, OwnerManifest>,
    records: Vec<HeldOwnerRecord>,
    ids: VecDeque<String>,
    extensions: HashMap<[u8; 8], Schema>,
    sent: Vec<SentProposal>,
    blocks: HashMap<String, Block>,
}

impl ProposalProposer {
    /// A proposer with the signing key `seed`, the keys of the `owner`, their manifests,
    /// the owner's records it holds, the proposal ids it takes in turn, and `schemas`,
    /// the writer schema texts of the extension types it holds.
    ///
    /// # Errors
    ///
    /// `DOES_NOT_RESOLVE` for a schema text that is no schema.
    pub(crate) fn start(
        seed: SigningSeed,
        owner: Vec<Key>,
        manifests: HashMap<Key, OwnerManifest>,
        records: Vec<HeldOwnerRecord>,
        proposal_ids: Vec<String>,
        schemas: &[String],
    ) -> Result<Self, Error> {
        let mut extensions = HashMap::new();
        for text in schemas {
            let schema = Schema::parse(text)?;
            if schema.record_name().is_some() {
                extensions.insert(schema.fingerprint().0, schema);
            }
        }
        Ok(Self {
            key: ed25519::public_key_of(&seed),
            seed,
            owner,
            manifests,
            records,
            ids: proposal_ids.into(),
            extensions,
            sent: Vec::new(),
            blocks: HashMap::new(),
        })
    }

    fn record_at(&self, id: &str) -> Option<usize> {
        self.records.iter().position(|r| same_id(&r.id, id))
    }

    fn record(&self, id: &str) -> Option<&HeldOwnerRecord> {
        self.records.iter().find(|r| same_id(&r.id, id))
    }

    fn takes(&self, key: &Key, type_name: &str) -> bool {
        self.owner.contains(key)
            && self
                .manifests
                .get(key)
                .is_some_and(|m| m.proposals.contains(type_name))
    }

    fn proposal(
        &self,
        to: &Key,
        record: &HeldOwnerRecord,
        proposal_id: &str,
        fields: &[Entry],
    ) -> Result<Vec<u8>, Error> {
        signed(
            &self.seed,
            &self.key,
            Kind::Proposal,
            Some(RecordRef {
                id: record.id.clone(),
                version: record.version,
            }),
            "axt.Proposal",
            &json!({
                "to": hex(to),
                "proposal_id": proposal_id,
                "fields": fields.iter().map(Entry::to_json).collect::<Vec<_>>(),
            }),
        )
    }

    /// Its user proposes `values`, the bytes of each field or part by name in order, for
    /// the record `id` to the key `to`; the `PROPOSAL`, or `None` where nothing is
    /// proposed.
    ///
    /// # Errors
    ///
    /// When the record's schema is no record schema, a value it holds cannot be read, or
    /// no proposal id is left.
    pub(crate) fn propose(
        &mut self,
        id: &str,
        to: &Key,
        values: &[(String, Option<Vec<u8>>)],
        relay: bool,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(record) = self.record(id).cloned() else {
            return Ok(None);
        };
        if record.deleted || record.last != "DATA" || !self.takes(to, &record.type_name) {
            return Ok(None);
        }
        let schema = Schema::parse(&record.schema)?;
        let mut fields = Vec::new();
        for (name, value) in values {
            let Some(value) = value else {
                continue;
            };
            let Ok(part) = part_name(name) else {
                continue;
            };
            if let Some(part) = part {
                if let Some(entry) = self.part_entry(&record, &schema, name, &part, value)? {
                    fields.push(entry);
                }
                continue;
            }
            let Some(found) = schema.field_schema(name) else {
                continue;
            };
            if let Some(kept) = record.values.get(name) {
                let same = match (found.decode_datum(kept), found.decode_datum(value)) {
                    (Ok(a), Ok(b)) => same_value(&a, &b),
                    (Err(_), Err(_)) => kept == value,
                    _ => false,
                };
                if same {
                    continue;
                }
            }
            fields.push(Entry {
                name: name.clone(),
                schema: schema.fingerprint().0,
                value: value.clone(),
            });
        }
        if fields.is_empty() {
            return Ok(None);
        }
        if let Some(block) = self.blocks.get(&record.id.to_lowercase()) {
            if block.code != "VALUE_INVALID" {
                return Ok(None);
            }
            let top = block.field.as_deref().map(top_of);
            let proposed = values
                .iter()
                .find(|(n, _)| Some(n.as_str()) == top)
                .and_then(|(_, v)| v.as_ref());
            if proposed.is_some() && proposed == block.value.as_ref() {
                return Ok(None);
            }
        }
        let proposal_id = self
            .ids
            .pop_front()
            .ok_or_else(|| Error::axt(ErrorCode::InvalidMessage, "no proposal id is left"))?;
        let message = self.proposal(to, &record, &proposal_id, &fields)?;
        self.sent.push(SentProposal {
            id: record.id.clone(),
            proposal_id,
            to: *to,
            message: message.clone(),
            fields,
            relay,
            status: None,
            settled: false,
            days_since_sent: 0,
        });
        Ok(Some(message))
    }

    /// The entry of the part `name` with `value`, or `None` where its value is that of
    /// the kept `DATA` or it names nothing the proposer can propose (section 20.1).
    fn part_entry(
        &self,
        record: &HeldOwnerRecord,
        schema: &Schema,
        name: &str,
        part: &PartName,
        value: &[u8],
    ) -> Result<Option<Entry>, Error> {
        let undecodable = |e: String| Error::axt(ErrorCode::Undecodable, e);
        let Some(&kind) = element_lists_of(schema).get(&part.list) else {
            return Ok(None);
        };
        let Some(list_schema) = schema.field_schema(&part.list) else {
            return Ok(None);
        };
        let kept = match record.values.get(&part.list) {
            None => Vec::new(),
            Some(bytes) => match list_schema.decode_datum(bytes).map_err(undecodable)? {
                Value::Array(items) => items,
                _ => Vec::new(),
            },
        };
        let element = element_of(kind, &kept, &part.key);
        let Some(field_name) = part.field.as_deref() else {
            let items = list_schema
                .items_schema()
                .ok_or_else(|| undecodable("the list has no items".into()))?;
            if same_element_part(&items, element, value)? {
                return Ok(None);
            }
            return Ok(Some(Entry {
                name: name.to_owned(),
                schema: schema.fingerprint().0,
                value: value.to_vec(),
            }));
        };
        let Some(data) = element.and_then(|e| bytes_of(e, "data")) else {
            return Ok(None);
        };
        let Some((fingerprint, payload)) = split_single_object(data) else {
            return Ok(None);
        };
        let Some(writer) = self.extensions.get(&fingerprint) else {
            return Ok(None);
        };
        let Some(field_schema) = writer.field_schema(field_name) else {
            return Ok(None);
        };
        let decoded = writer.decode_datum(payload).map_err(undecodable)?;
        let before = decoded.field(field_name).unwrap_or(&Value::Null);
        if same_datum(&field_schema, before, value)? {
            return Ok(None);
        }
        Ok(Some(Entry {
            name: name.to_owned(),
            schema: writer.fingerprint().0,
            value: value.to_vec(),
        }))
    }

    /// Processes a `PROPOSAL_REPLY` or an `ERROR` (sections 14.2 and 16.3).
    ///
    /// # Errors
    ///
    /// Only when a reply cannot be written.
    pub(crate) fn receive(&mut self, message: &[u8]) -> Result<Received, Error> {
        let Ok(envelope) = envelope::decode_message(message) else {
            return Ok(Received::of("ignored"));
        };
        let reject = |proposer: &Self, code: ErrorCode, with_record: bool| {
            Ok(Received {
                result: "rejected",
                replies: vec![error_message(
                    &proposer.seed,
                    &proposer.key,
                    message,
                    &envelope.sender,
                    code,
                    envelope.record.as_ref().filter(|_| with_record),
                    None,
                    None,
                )?],
            })
        };
        if !verify_live_message(message, &envelope.sender) {
            return reject(self, ErrorCode::SignatureInvalid, false);
        }
        let sender = envelope.sender;
        if envelope.kind == Kind::Error {
            let Ok(body) = envelope::decode_body(Kind::Error, &envelope.body) else {
                return Ok(Received::of("ignored"));
            };
            if bytes_of(&body, "to") != Some(self.key.as_slice()) {
                return Ok(Received::of("ignored"));
            }
            let hash = bytes_of(&body, "message_hash").unwrap_or_default();
            let Some(proposal) = self
                .sent
                .iter_mut()
                .find(|p| p.to == sender && Sha256::digest(&p.message).as_slice() == hash)
            else {
                return Ok(Received::of("ignored"));
            };
            if proposal.status.is_some() || proposal.settled {
                return Ok(Received::of("ignored"));
            }
            let code = match body.field("code") {
                Some(Value::Enum { symbol, .. }) => symbol.clone(),
                _ => String::new(),
            };
            if code == "FORMAT_UNSUPPORTED" {
                return Ok(Received::of("taken"));
            }
            proposal.settled = true;
            proposal.status = Some(code.clone());
            if matches!(
                code.as_str(),
                "PROPOSALS_NOT_TAKEN" | "SCHEMA_UNKNOWN" | "VALUE_INVALID"
            ) {
                let field = text(&body, "field").map(str::to_owned);
                let value = field.as_deref().and_then(|f| {
                    proposal
                        .fields
                        .iter()
                        .find(|e| e.name == top_of(f))
                        .map(|e| e.value.clone())
                });
                let id = proposal.id.to_lowercase();
                self.blocks.insert(id, Block { code, field, value });
            }
            return Ok(Received::of("taken"));
        }
        if envelope.kind != Kind::ProposalReply {
            return Ok(Received::of("ignored"));
        }
        let Some(reference) = envelope.record.as_ref() else {
            return reject(self, ErrorCode::InvalidMessage, true);
        };
        let Ok(body) = envelope::decode_body(Kind::ProposalReply, &envelope.body) else {
            return reject(self, ErrorCode::InvalidMessage, true);
        };
        if bytes_of(&body, "to") != Some(self.key.as_slice()) {
            return Ok(Received::of("ignored"));
        }
        let proposal_id = text(&body, "proposal_id").unwrap_or_default();
        let at = if self.owner.contains(&sender) {
            self.sent.iter().position(|p| p.proposal_id == proposal_id)
        } else {
            None
        };
        let Some(proposal) = at.and_then(|i| self.sent.get(i)) else {
            return Ok(Received::of("ignored"));
        };
        let version = envelope::decode_message(&proposal.message)
            .ok()
            .and_then(|e| e.record)
            .map(|r| r.version);
        if reference.id != proposal.id || Some(reference.version) != version {
            return reject(self, ErrorCode::InvalidMessage, true);
        }
        let answer = match body.field("answer") {
            Some(Value::Enum { symbol, .. }) => symbol.clone(),
            _ => String::new(),
        };
        // Any reply to its own proposals ends a block of new proposals (16.3).
        self.blocks.retain(|_, b| b.code != "PROPOSALS_NOT_TAKEN");
        let Some(proposal) = at.and_then(|i| self.sent.get_mut(i)) else {
            return Ok(Received::of("ignored"));
        };
        match proposal.status.as_deref() {
            Some("DECLINED") if answer == "ACCEPTED" => {
                proposal.status = Some(answer);
                Ok(Received::of("taken"))
            }
            Some("ACCEPTED" | "DECLINED") => Ok(Received::of("ignored")),
            _ => {
                proposal.status = Some(answer);
                proposal.settled = true;
                Ok(Received::of("taken"))
            }
        }
    }

    /// A record message of the owner reaches it and is applied.
    pub(crate) fn record_message(
        &mut self,
        id: &str,
        kind: &str,
        version: i64,
        values: Option<BTreeMap<String, Vec<u8>>>,
    ) {
        let Some(record) = self.record_at(id).and_then(|i| self.records.get_mut(i)) else {
            return;
        };
        if version > record.version {
            record.version = version;
            kind.clone_into(&mut record.last);
            if let Some(values) = values {
                record.values = values;
            }
            self.blocks.remove(&record.id.to_lowercase());
        }
    }

    /// A manifest of a key of the owner reaches it.
    pub(crate) fn manifest(&mut self, key: Key, manifest: OwnerManifest) {
        let revision = manifest.revision;
        let had = self.manifests.insert(key, manifest);
        if had.is_none_or(|h| revision > h.revision) {
            self.blocks
                .retain(|_, b| b.code != "PROPOSALS_NOT_TAKEN" && b.code != "SCHEMA_UNKNOWN");
        }
    }

    /// Whether `p` has neither a reply nor an error, for a record whose last message from
    /// the owner is a `DATA`.
    fn unsettled(&self, p: &SentProposal) -> bool {
        !p.settled && p.status.is_none() && self.record(&p.id).is_some_and(|r| r.last == "DATA")
    }

    /// Whether `p` is sent again: unsettled, to a current key of the owner.
    fn pending(&self, p: &SentProposal) -> bool {
        self.unsettled(p) && self.owner.contains(&p.to)
    }

    /// The key `removed` is removed from the owner: the proposals to it go to another
    /// current key whose manifest takes proposals for the type.
    ///
    /// # Errors
    ///
    /// When a proposal cannot be written.
    pub(crate) fn remove(&mut self, removed: &Key) -> Result<Vec<Vec<u8>>, Error> {
        if let Some(at) = self.owner.iter().position(|k| k == removed) {
            self.owner.remove(at);
        }
        let mut messages = Vec::new();
        for i in 0..self.sent.len() {
            let Some(p) = self.sent.get(i) else {
                continue;
            };
            if p.to != *removed || !self.unsettled(p) {
                continue;
            }
            let Some(record) = self.record(&p.id) else {
                continue;
            };
            let Some(to) = self
                .owner
                .iter()
                .find(|k| self.takes(k, &record.type_name))
                .copied()
            else {
                continue;
            };
            let message = self.proposal(&to, record, &p.proposal_id, &p.fields)?;
            if let Some(p) = self.sent.get_mut(i) {
                p.to = to;
                p.message.clone_from(&message);
            }
            messages.push(message);
        }
        Ok(messages)
    }

    /// A live connection with the device of `key` begins: the proposals sent to it again.
    pub(crate) fn connect(&self, key: &Key) -> Vec<Vec<u8>> {
        self.sent
            .iter()
            .filter(|p| p.to == *key && self.pending(p))
            .map(|p| p.message.clone())
            .collect()
    }

    /// `days` days pass: proposals sent through the relay go again after 14.
    pub(crate) fn days(&mut self, days: i64) -> Vec<Vec<u8>> {
        let pending: Vec<bool> = self
            .sent
            .iter()
            .map(|p| p.relay && self.pending(p))
            .collect();
        let mut messages = Vec::new();
        for (p, pending) in self.sent.iter_mut().zip(pending) {
            if !pending {
                continue;
            }
            p.days_since_sent = p.days_since_sent.saturating_add(days);
            if p.days_since_sent >= 14 {
                p.days_since_sent = 0;
                messages.push(p.message.clone());
            }
        }
        messages
    }

    /// The status of a proposal, `open` while it has none, and whether it is sent again.
    pub(crate) fn query(&self, proposal_id: &str) -> Option<(String, bool)> {
        let p = self.sent.iter().find(|p| p.proposal_id == proposal_id)?;
        Some((
            p.status.clone().unwrap_or_else(|| "open".into()),
            self.pending(p),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::axt_schema_text;

    const MEMO: &str = r#"{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"text","type":"string"},{"name":"when","type":{"type":"record","name":"Date","namespace":"axt","fields":[{"name":"year","type":["null","int"]},{"name":"month","type":["null","int"]},{"name":"day","type":["null","int"]}]}}]}"#;
    const ID: &str = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80";
    const PROPOSAL_ID: &str = "7b3e9d21-4c8a-4f6e-9a1b-5d2c8e4f6a70";
    const R1: &str = "f1b3d5a7-2c4e-4f60-8a1b-3c5d7e9f0a2b";

    fn seed(n: u8) -> SigningSeed {
        SigningSeed::new([n; 32])
    }

    fn key(n: u8) -> Key {
        ed25519::public_key_of(&seed(n))
    }

    const OWNER: u8 = 1;
    const PROPOSER: u8 = 2;
    const STRANGER: u8 = 3;

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::Record(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect())
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn schema(text: &str) -> Schema {
        Schema::parse(text).unwrap()
    }

    /// The bytes of `value` under the schema of the field `name` of `of`.
    fn field_bytes(of: &str, name: &str, value: &Value) -> Vec<u8> {
        schema(of)
            .field_schema(name)
            .unwrap()
            .encode_datum(value)
            .unwrap()
    }

    fn text_bytes(value: &str) -> Vec<u8> {
        field_bytes(MEMO, "text", &s(value))
    }

    fn proposal(signer: u8, schema_text: &str, values: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let fingerprint = schema(schema_text).fingerprint().0;
        let fields: Vec<Json> = values
            .iter()
            .map(|(name, value)| {
                json!({"name": name, "schema": hex(&fingerprint), "value": hex(value)})
            })
            .collect();
        signed(
            &seed(signer),
            &key(signer),
            Kind::Proposal,
            Some(RecordRef {
                id: ID.into(),
                version: 1,
            }),
            "axt.Proposal",
            &json!({"to": hex(&key(OWNER)), "proposal_id": PROPOSAL_ID, "fields": fields}),
        )
        .unwrap()
    }

    fn receiver(removed: &[u8], links: bool) -> ProposalReceiver {
        ProposalReceiver {
            name: "p".into(),
            current: BTreeSet::from([key(PROPOSER)]),
            removed: removed.iter().map(|n| key(*n)).collect(),
            own_user: false,
            links,
        }
    }

    fn own_record(type_name: &str, value: Value) -> OwnRecord {
        OwnRecord {
            id: ID.into(),
            type_name: type_name.into(),
            version: 1,
            deleted: false,
            value,
            shared: BTreeSet::from(["p".to_owned()]),
        }
    }

    fn memo_owner(readers: Option<&str>, open: Vec<OpenProposal>, removed: &[u8]) -> ProposalOwner {
        ProposalOwner::start(
            seed(OWNER),
            OwnerState {
                siblings: BTreeSet::new(),
                proposals: BTreeSet::from(["org.example.Memo".to_owned()]),
                schemas: vec![MEMO.into()],
                receivers: vec![receiver(removed, false)],
                records: vec![own_record(
                    "org.example.Memo",
                    record(vec![("text", s("a"))]),
                )],
                readers: readers
                    .map(|r| BTreeMap::from([("org.example.Memo".to_owned(), r.to_owned())])),
                open,
                answers: Vec::new(),
                stops: Vec::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn the_owner_ignores_strangers_and_removed_keys() {
        let mut owner = memo_owner(None, Vec::new(), &[STRANGER]);
        let taken = owner.receive(&proposal(PROPOSER, MEMO, &[("text", text_bytes("b"))]));
        assert_eq!(taken.unwrap().result, "taken");
        let mut unknown = memo_owner(None, Vec::new(), &[]);
        let nobody = unknown.receive(&proposal(9, MEMO, &[("text", text_bytes("b"))]));
        assert_eq!(nobody.unwrap(), Received::of("ignored"));
        let removed = owner.receive(&proposal(STRANGER, MEMO, &[("text", text_bytes("b"))]));
        assert_eq!(removed.unwrap(), Received::of("ignored"));
        let own = owner.receive(&proposal(OWNER, MEMO, &[("text", text_bytes("b"))]));
        assert_eq!(own.unwrap(), Received::of("ignored"));
        assert_eq!(owner.receive(&[1, 2, 3]).unwrap(), Received::of("rejected"));
    }

    #[test]
    fn the_owner_shows_values_through_its_reader_or_cannot() {
        let mut with_reader = memo_owner(Some(MEMO), Vec::new(), &[]);
        with_reader
            .receive(&proposal(PROPOSER, MEMO, &[("text", text_bytes("b"))]))
            .unwrap();
        let made = with_reader.answer("p", PROPOSAL_ID, "ACCEPTED").unwrap();
        assert!(made.made);
        assert_eq!(made.replies.len(), 1);
        let (version, value) = made.update.unwrap();
        assert_eq!(version, 2);
        assert_eq!(value.field("text"), Some(&s("b")));
        let mut other_reader = memo_owner(
            Some(
                r#"{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"text","type":"int"}]}"#,
            ),
            Vec::new(),
            &[],
        );
        other_reader
            .receive(&proposal(PROPOSER, MEMO, &[("text", text_bytes("b"))]))
            .unwrap();
        let answered = other_reader.answer("p", PROPOSAL_ID, "ACCEPTED").unwrap();
        assert!(!answered.made);
        let date = field_bytes(
            MEMO,
            "when",
            &record(vec![
                ("year", Value::Null),
                ("month", Value::Null),
                ("day", Value::Null),
            ]),
        );
        let mut bad_time = memo_owner(Some(MEMO), Vec::new(), &[]);
        let rejected = bad_time
            .receive(&proposal(PROPOSER, MEMO, &[("when", date)]))
            .unwrap();
        assert_eq!(rejected.result, "rejected");
        let error = envelope::decode_message(&rejected.replies[0]).unwrap();
        let body = envelope::decode_body(error.kind, &error.body).unwrap();
        assert_eq!(text(&body, "field"), Some("when"));
    }

    #[test]
    fn an_open_proposal_of_the_input_cannot_be_accepted_and_a_sibling_answers() {
        let open = OpenProposal {
            receiver: "p".into(),
            proposal_id: PROPOSAL_ID.into(),
            id: ID.into(),
            version: 1,
            value_bytes: 0,
            message: None,
            signer: None,
            fields: Vec::new(),
        };
        let mut owner = memo_owner(None, vec![open], &[]);
        assert!(!owner.answer("p", PROPOSAL_ID, "ACCEPTED").unwrap().made);
        let answer = |answer: &str| ProposalAnswer {
            receiver: "p".into(),
            proposal_id: "other".into(),
            answer: answer.into(),
            id: ID.into(),
            version: 1,
        };
        owner.answered(answer("DECLINED"));
        owner.answered(answer("ACCEPTED"));
        owner.answered(answer("DECLINED"));
        assert_eq!(owner.answers.len(), 1);
        assert_eq!(owner.answers[0].answer, "ACCEPTED");
    }

    #[test]
    fn the_proposer_ignores_what_is_no_reply_and_takes_later_records() {
        let mut proposer = ProposalProposer::start(
            seed(PROPOSER),
            vec![key(OWNER)],
            HashMap::from([(
                key(OWNER),
                OwnerManifest {
                    revision: 1,
                    proposals: BTreeSet::from(["org.example.Memo".to_owned()]),
                },
            )]),
            vec![HeldOwnerRecord {
                id: ID.into(),
                type_name: "org.example.Memo".into(),
                version: 1,
                last: "DATA".into(),
                schema: MEMO.into(),
                values: BTreeMap::from([("text".to_owned(), vec![0xff])]),
                deleted: false,
            }],
            vec![PROPOSAL_ID.into()],
            &[],
        )
        .unwrap();
        let values = [("text".to_owned(), Some(text_bytes("b")))];
        let message = proposer.propose(ID, &key(OWNER), &values, false).unwrap();
        assert!(message.is_some());
        assert_eq!(proposer.query(PROPOSAL_ID), Some(("open".into(), true)));
        assert_eq!(proposer.receive(&[0; 3]).unwrap(), Received::of("ignored"));
        // Messages of the owner with a body of no schema: an ERROR, and an ACK.
        for kind in [Kind::Error, Kind::Ack] {
            let mut message = envelope::encode_message(&Envelope {
                kind,
                sender: key(OWNER),
                record: None,
                body: vec![0; 3],
                signature: [0; 64],
            })
            .unwrap();
            let signature = ed25519::sign(
                &seed(OWNER),
                &signed_bytes_of_live_message(&message).unwrap(),
            );
            message
                .split_last_chunk_mut::<64>()
                .unwrap()
                .1
                .copy_from_slice(&signature);
            assert_eq!(proposer.receive(&message).unwrap(), Received::of("ignored"));
        }
        proposer.record_message(
            ID,
            "DATA",
            2,
            Some(BTreeMap::from([("text".to_owned(), text_bytes("c"))])),
        );
        assert_eq!(proposer.records[0].version, 2);
        assert_eq!(
            proposer.records[0].values.get("text"),
            Some(&text_bytes("c"))
        );
        proposer.record_message(ID, "DATA", 1, None);
        proposer.record_message("other", "DATA", 9, None);
        assert_eq!(proposer.records[0].version, 2);
        // Without a proposal id left, nothing can be proposed.
        let values = [("text".to_owned(), Some(text_bytes("d")))];
        assert!(proposer.propose(ID, &key(OWNER), &values, false).is_err());
    }

    /// The schema text of a record `name` of the fields `fields`, JSON values.
    fn record_schema(name: &str, fields: Vec<(&str, Json)>) -> String {
        let fields: Vec<Json> = fields
            .into_iter()
            .map(|(n, t)| json!({"name": n, "type": t}))
            .collect();
        json!({"type": "record", "name": name, "namespace": "org.example", "fields": fields})
            .to_string()
    }

    fn published(name: &str) -> Json {
        serde_json::from_str(axt_schema_text(name).unwrap()).unwrap()
    }

    fn note() -> String {
        record_schema(
            "Note",
            vec![
                (
                    "relations",
                    json!({"type": "array", "items": published("axt.Relation")}),
                ),
                (
                    "extensions",
                    json!({"type": "array", "items": published("axt.Extension")}),
                ),
            ],
        )
    }

    fn cat() -> String {
        record_schema(
            "Cat",
            vec![("fur", json!("string")), ("when", published("axt.Date"))],
        )
    }

    fn relation(id: &str, kind: &str) -> Value {
        record(vec![
            ("id", s(id)),
            ("kind", s(kind)),
            (
                "target",
                Value::Union {
                    index: 1,
                    branch: "axt.RelationOutsideTarget".into(),
                    value: Box::new(record(vec![
                        ("uri", s("https://example.org")),
                        ("text", s("")),
                    ])),
                },
            ),
            ("note", s("")),
            ("start", Value::Null),
            ("end", Value::Null),
            ("attributes", Value::Map(BTreeMap::new())),
        ])
    }

    fn cat_data(fur: &str) -> Vec<u8> {
        schema(&cat())
            .encode_single_object(&record(vec![
                ("fur", s(fur)),
                (
                    "when",
                    record(vec![
                        ("year", Value::Int(2026)),
                        ("month", Value::Null),
                        ("day", Value::Null),
                    ]),
                ),
            ]))
            .unwrap()
    }

    fn extension(name: &str, data: Vec<u8>) -> Value {
        record(vec![("name", s(name)), ("data", Value::Bytes(data))])
    }

    fn other_data() -> Vec<u8> {
        [vec![0xc3, 0x01], vec![0; 8], vec![0]].concat()
    }

    fn note_owner() -> ProposalOwner {
        ProposalOwner::start(
            seed(OWNER),
            OwnerState {
                siblings: BTreeSet::new(),
                proposals: BTreeSet::from(["org.example.Note".to_owned()]),
                schemas: vec![note(), cat()],
                receivers: vec![receiver(&[], true)],
                records: vec![own_record(
                    "org.example.Note",
                    record(vec![
                        ("relations", Value::Array(vec![relation(R1, "axt.related")])),
                        (
                            "extensions",
                            Value::Array(vec![
                                extension("org.example.Other", other_data()),
                                extension("org.example.Cat", cat_data("tabby")),
                            ]),
                        ),
                    ]),
                )],
                readers: None,
                open: Vec::new(),
                answers: Vec::new(),
                stops: Vec::new(),
            },
        )
        .unwrap()
    }

    /// The result of a proposal of `values` at the owner of a note, with the code and the
    /// field of its error.
    fn received(
        schema_text: &str,
        values: &[(&str, Vec<u8>)],
    ) -> (String, Option<String>, Option<String>) {
        let mut owner = note_owner();
        let r = owner
            .receive(&proposal(PROPOSER, schema_text, values))
            .unwrap();
        let Some(reply) = r.replies.first() else {
            return (r.result.into(), None, None);
        };
        let envelope = envelope::decode_message(reply).unwrap();
        let body = envelope::decode_body(envelope.kind, &envelope.body).unwrap();
        let code = match body.field("code") {
            Some(Value::Enum { symbol, .. }) => Some(symbol.clone()),
            _ => None,
        };
        (
            r.result.into(),
            code,
            text(&body, "field").map(str::to_owned),
        )
    }

    fn rejected(code: &str, field: Option<&str>) -> (String, Option<String>, Option<String>) {
        (
            "rejected".into(),
            Some(code.into()),
            field.map(str::to_owned),
        )
    }

    #[test]
    fn parts_that_are_not_valid_are_rejected() {
        let items = schema(&note())
            .field_schema("relations")
            .unwrap()
            .items_schema()
            .unwrap();
        let element = encode_element_part(&items, Some(&relation(R1, "axt.related"))).unwrap();
        let note = note();
        let cat = cat();
        let part = format!("relations/{R1}");
        assert_eq!(
            received(&note, &[("a/b/c/d", element.clone())]),
            rejected("INVALID_MESSAGE", None)
        );
        assert_eq!(
            received(&note, &[("relations/not-a-uuid", element)]),
            rejected("INVALID_MESSAGE", None)
        );
        assert_eq!(
            received(&note, &[(&part, vec![5])]),
            rejected("UNDECODABLE", None)
        );
        assert_eq!(
            received(&note, &[(&part, vec![2, 0x7f])]),
            rejected("UNDECODABLE", None)
        );
        let bad_kind = encode_element_part(&items, Some(&relation(R1, "nokind"))).unwrap();
        assert_eq!(
            received(&note, &[(&part, bad_kind)]),
            rejected("VALUE_INVALID", Some(&format!("{part}.kind")))
        );
        assert_eq!(
            received(&cat, &[("extensions/org.example.Cat/fur", vec![0x7f])]),
            rejected("UNDECODABLE", None)
        );
        let bad_date = field_bytes(
            &cat,
            "when",
            &record(vec![
                ("year", Value::Int(2026)),
                ("month", Value::Int(13)),
                ("day", Value::Null),
            ]),
        );
        assert_eq!(
            received(&cat, &[("extensions/org.example.Cat/when", bad_date)]),
            rejected("VALUE_INVALID", Some("extensions/org.example.Cat/when"))
        );
        assert_eq!(
            received(&cat, &[("extensions/org.example.Cat/nope", vec![0])]),
            rejected("INVALID_MESSAGE", None)
        );
    }

    #[test]
    fn a_field_within_an_extension_is_set_and_the_others_stay() {
        let mut owner = note_owner();
        let fur = field_bytes(&cat(), "fur", &s("black"));
        let taken = owner
            .receive(&proposal(
                PROPOSER,
                &cat(),
                &[("extensions/org.example.Cat/fur", fur)],
            ))
            .unwrap();
        assert_eq!(taken.result, "taken");
        let made = owner.answer("p", PROPOSAL_ID, "ACCEPTED").unwrap();
        let (_, value) = made.update.unwrap();
        assert_eq!(
            value.field("extensions"),
            Some(&Value::Array(vec![
                extension("org.example.Other", other_data()),
                extension("org.example.Cat", cat_data("black")),
            ]))
        );
    }

    #[test]
    fn a_relation_with_attributes_proposed_as_it_is_is_no_change() {
        // The entries of a map are encoded in any order, so the same relation may come as
        // other bytes; it is still the relation the record holds.
        let note = note();
        let mut held = relation(R1, "axt.related");
        set_field(
            &mut held,
            "attributes",
            Value::Map(BTreeMap::from([
                ("org.example.a".to_owned(), s("1")),
                ("org.example.b".to_owned(), s("2")),
                ("org.example.c".to_owned(), s("3")),
            ])),
        );
        let relations = Value::Array(vec![held.clone()]);
        let items = schema(&note)
            .field_schema("relations")
            .unwrap()
            .items_schema()
            .unwrap();
        let part = format!("relations/{R1}");
        for _ in 0..20 {
            let proposer = ProposalProposer::start(
                seed(PROPOSER),
                vec![key(OWNER)],
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                &[],
            )
            .unwrap();
            let record = HeldOwnerRecord {
                id: ID.into(),
                type_name: "org.example.Note".into(),
                version: 1,
                last: "DATA".into(),
                schema: note.clone(),
                values: BTreeMap::from([(
                    "relations".to_owned(),
                    field_bytes(&note, "relations", &relations),
                )]),
                deleted: false,
            };
            let value = encode_element_part(&items, Some(&held)).unwrap();
            let name = part_name(&part).unwrap().unwrap();
            let entry = proposer
                .part_entry(&record, &schema(&note), &part, &name, &value)
                .unwrap();
            assert_eq!(entry, None);
        }
    }

    #[test]
    fn the_proposer_proposes_only_the_parts_that_differ() {
        let note = note();
        let note_schema = schema(&note);
        let relations = Value::Array(vec![relation(R1, "axt.related")]);
        let unknown = [vec![0xc3, 0x01], vec![1; 8]].concat();
        let extensions = Value::Array(vec![
            extension("org.example.Cat", cat_data("tabby")),
            extension("org.example.Unknown", unknown),
        ]);
        let mut proposer = ProposalProposer::start(
            seed(PROPOSER),
            vec![key(OWNER)],
            HashMap::from([(
                key(OWNER),
                OwnerManifest {
                    revision: 1,
                    proposals: BTreeSet::from(["org.example.Note".to_owned()]),
                },
            )]),
            vec![HeldOwnerRecord {
                id: ID.into(),
                type_name: "org.example.Note".into(),
                version: 1,
                last: "DATA".into(),
                schema: note.clone(),
                values: BTreeMap::from([
                    (
                        "relations".to_owned(),
                        field_bytes(&note, "relations", &relations),
                    ),
                    (
                        "extensions".to_owned(),
                        field_bytes(&note, "extensions", &extensions),
                    ),
                ]),
                deleted: false,
            }],
            vec![PROPOSAL_ID.into()],
            &[cat(), "\"string\"".into()],
        )
        .unwrap();
        let items = note_schema
            .field_schema("relations")
            .unwrap()
            .items_schema()
            .unwrap();
        let fur = |v: &str| Some(field_bytes(&cat(), "fur", &s(v)));
        let part = format!("relations/{R1}");
        let unchanged = [
            ("a//b".to_owned(), Some(vec![0])),
            ("nolist/x".to_owned(), Some(vec![0])),
            (
                part.clone(),
                Some(encode_element_part(&items, Some(&relation(R1, "axt.related"))).unwrap()),
            ),
            ("extensions/org.example.Cat/fur".to_owned(), fur("tabby")),
            ("extensions/org.example.Gone/fur".to_owned(), fur("x")),
            ("extensions/org.example.Unknown/fur".to_owned(), fur("x")),
            ("extensions/org.example.Cat/nope".to_owned(), fur("x")),
        ];
        assert_eq!(
            proposer
                .propose(ID, &key(OWNER), &unchanged, false)
                .unwrap(),
            None
        );
        let removal = [(part.clone(), Some(vec![0]))];
        let message = proposer
            .propose(ID, &key(OWNER), &removal, false)
            .unwrap()
            .unwrap();
        let envelope = envelope::decode_message(&message).unwrap();
        let body = envelope::decode_body(envelope.kind, &envelope.body).unwrap();
        let entries = entries_of(&body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, part);
    }
}
