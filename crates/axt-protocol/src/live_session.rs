//! One app in one live connection with another app: manifests, offers, answers, record
//! messages, acknowledgements and errors (AXT `spec/protocol.md`, sections 3 to 9 and 14).
//!
//! Internal to the library; only the conformance adapter plays it (`session`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use crate::avro::split_single_object;
use crate::device_sets::{ChangeResult, DeviceSetReceiver, Key, KeyState, KnownSender};
use crate::ed25519;
use crate::envelope::{self, ENVELOPE_FORMAT, Envelope, Kind, RecordRef};
use crate::error::{Error, ErrorCode};
use crate::keys::SigningSeed;
use crate::limits::{PROTOCOL_ACK_RECORDS, PROTOCOL_ERROR_RECORD_ID, PROTOCOL_OFFER_TYPES};
use crate::manifest::{check_manifest, fit};
use crate::record_decoder::{check_axt_names, decode_record};
use crate::records::{
    ElementMerge, HeldRecord, Outcome, RecordKind, RecordMessage, RecordPolicy,
    apply_record_message, checked_record_key, record_key,
};
use crate::schema::Schema;
use crate::schemas::axt_schema;
use crate::signing::{signed_bytes_of_live_message, verify_live_message};
use crate::type_description::TypeDescription;
use crate::value::{Value, hex};

/// The answer of a [`LiveApp::receive`] step.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Received {
    /// The outcome of a record message processed to one.
    pub(crate) outcome: Option<Outcome>,
    /// Whether the app closes the connection.
    pub(crate) close: bool,
    /// The messages the app sends in reply.
    pub(crate) replies: Vec<Vec<u8>>,
}

/// An entry of an `ACK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AckEntry {
    /// The record's id, as the sender wrote it.
    pub(crate) id: String,
    /// The version of the record message.
    pub(crate) version: i64,
    /// What the receiver did with it.
    pub(crate) outcome: Outcome,
    /// The version the receiver holds now.
    pub(crate) receiver_version: i64,
    /// For `MERGED`: the fields whose values the receiver kept.
    pub(crate) kept_fields: Vec<String>,
}

/// A type the other app offers in the current connection.
struct Current {
    type_name: String,
    schema: Schema,
    text: String,
    accepted: bool,
}

/// A type the app offered: the offer's id and the other app's answer, once it has one.
struct OwnOffer {
    offer_id: String,
    answer: Option<String>,
}

/// Why a message is not processed.
enum Stop {
    /// It is ignored without a report.
    Ignored,
    /// It is rejected with an `ERROR`.
    Rejected {
        code: ErrorCode,
        fingerprint: Option<[u8; 8]>,
        field: Option<String>,
    },
    /// The app failed to write its answer.
    Failed(Error),
}

impl From<Error> for Stop {
    fn from(e: Error) -> Self {
        Self::Failed(e)
    }
}

/// A rejection with `code` alone.
fn reject(code: ErrorCode) -> Stop {
    Stop::Rejected {
        code,
        fingerprint: None,
        field: None,
    }
}

/// A rejection with the code and the field of `e`.
fn reject_with(e: Error) -> Stop {
    match e {
        Error::Axt { code, field, .. } => Stop::Rejected {
            code,
            fingerprint: None,
            field,
        },
        e @ Error::Store(_) => Stop::Failed(e),
    }
}

/// Whether a message of `kind` carries a `record` (section 2).
const fn carries_record(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Data
            | Kind::Delete
            | Kind::Withdraw
            | Kind::Change
            | Kind::Resync
            | Kind::Forward
            | Kind::Proposal
            | Kind::ProposalReply
    )
}

/// The members of decoded bodies, which their schemas guarantee; a value of another
/// shape is an invalid message.
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, Stop> {
    match value.field(name) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(reject(ErrorCode::InvalidMessage)),
    }
}

fn long(value: &Value, name: &str) -> Result<i64, Stop> {
    match value.field(name) {
        Some(Value::Long(n)) => Ok(*n),
        _ => Err(reject(ErrorCode::InvalidMessage)),
    }
}

fn symbol<'a>(value: &'a Value, name: &str) -> Result<&'a str, Stop> {
    match value.field(name) {
        Some(Value::Enum { symbol, .. }) => Ok(symbol),
        _ => Err(reject(ErrorCode::InvalidMessage)),
    }
}

fn list<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], Stop> {
    match value.field(name) {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(reject(ErrorCode::InvalidMessage)),
    }
}

fn key_of(value: &Value, name: &str) -> Option<Key> {
    match value.field(name) {
        Some(Value::Fixed(bytes)) => Key::try_from(bytes.as_slice()).ok(),
        _ => None,
    }
}

/// The full name of the object type at the root of a description: the `name` of its
/// `axt.ObjectField`; `None` for a description of another kind.
fn object_name(description: &Value) -> Option<&str> {
    match description.field("kind") {
        Some(Value::Union { branch, value, .. }) if branch == "axt.ObjectField" => {
            match value.field("name") {
                Some(Value::String(name)) => Some(name),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The outcome of its symbol.
fn outcome_of(symbol: &str) -> Option<Outcome> {
    [
        Outcome::Applied,
        Outcome::Merged,
        Outcome::Kept,
        Outcome::Duplicate,
        Outcome::Stale,
        Outcome::Withdrawn,
    ]
    .into_iter()
    .find(|o| o.as_str() == symbol)
}

/// The key of a record message's outcome: the record key and the version.
fn slot(key: &str, version: i64) -> String {
    format!("{key}/{version}")
}

/// One app in live connections with one other app, whose key its user has accepted.
pub(crate) struct LiveApp {
    seed: SigningSeed,
    /// The app's own key.
    key: Key,
    manifest: Value,
    readers: BTreeMap<String, String>,
    user_takes: BTreeSet<String>,
    /// The other app's key, the connection key.
    peer: Key,
    receiver: DeviceSetReceiver,

    // State of the connection.
    signed_manifest: bool,
    peer_manifest: Option<Value>,
    peer_offers: HashMap<String, Vec<(String, String)>>,
    current: BTreeMap<String, Current>,
    held_errors: Vec<Vec<u8>>,

    // State across connections.
    held: HashMap<String, HeldRecord>,
    values: HashMap<String, Option<Value>>,
    owed_acks: Vec<AckEntry>,
    own_offers: HashMap<String, OwnOffer>,
    made_offers: HashSet<String>,
    offer_types: HashMap<String, BTreeSet<String>>,
    outcomes: HashMap<String, Outcome>,
    errors: Vec<String>,
}

impl LiveApp {
    /// An app with the signing key `seed` and the body of its own `MANIFEST`, its reader
    /// schemas by full name and the types its user takes, in a live connection whose
    /// `HELLO` proved `peer`.
    ///
    /// # Errors
    ///
    /// `INVALID_MESSAGE` for a manifest body that is no `axt.Manifest`.
    pub(crate) fn open(
        seed: SigningSeed,
        manifest_body: &[u8],
        readers: BTreeMap<String, String>,
        user_takes: BTreeSet<String>,
        peer: Key,
    ) -> Result<Self, Error> {
        let manifest = envelope::decode_body(Kind::Manifest, manifest_body)?;
        Ok(Self {
            key: ed25519::public_key_of(&seed),
            seed,
            manifest,
            readers,
            user_takes,
            peer,
            receiver: DeviceSetReceiver {
                senders: vec![KnownSender {
                    name: "peer".into(),
                    current: BTreeSet::from([peer]),
                    ..KnownSender::default()
                }],
                ..DeviceSetReceiver::default()
            },
            signed_manifest: false,
            peer_manifest: None,
            peer_offers: HashMap::new(),
            current: BTreeMap::new(),
            held_errors: Vec::new(),
            held: HashMap::new(),
            values: HashMap::new(),
            owed_acks: Vec::new(),
            own_offers: HashMap::new(),
            made_offers: HashSet::new(),
            offer_types: HashMap::new(),
            outcomes: HashMap::new(),
            errors: Vec::new(),
        })
    }

    /// A live message of `kind` with the body `json` of `schema`, signed.
    fn send(&self, schema: &str, kind: Kind, json: &Json) -> Result<Vec<u8>, Error> {
        let invalid = |e: String| Error::axt(ErrorCode::InvalidMessage, e);
        let schema =
            axt_schema(schema).ok_or_else(|| invalid(format!("the schema {schema} is missing")))?;
        let value = schema.datum_of_json(json).map_err(invalid)?;
        self.send_value(schema, kind, &value)
    }

    /// A live message of `kind` with the body `value` of `schema`, signed.
    fn send_value(&self, schema: &Schema, kind: Kind, value: &Value) -> Result<Vec<u8>, Error> {
        let invalid = |e: String| Error::axt(ErrorCode::InvalidMessage, e);
        let body = schema.encode_single_object(value).map_err(invalid)?;
        let mut message = envelope::encode_message(&Envelope {
            kind,
            sender: self.key,
            record: None,
            body,
            signature: [0; 64],
        })?;
        let signed = signed_bytes_of_live_message(&message)
            .ok_or_else(|| invalid("the message is too short".into()))?;
        let signature = ed25519::sign(&self.seed, &signed);
        if let Some((_, last)) = message.split_last_chunk_mut::<64>() {
            *last = signature;
        }
        Ok(message)
    }

    /// The `ERROR` about `message` (section 8).
    fn error(
        &self,
        message: &[u8],
        code: ErrorCode,
        record: Option<&RecordRef>,
        fingerprint: Option<[u8; 8]>,
        field: Option<String>,
    ) -> Result<Vec<u8>, Error> {
        let record = record
            .filter(|r| r.id.len() <= PROTOCOL_ERROR_RECORD_ID)
            .map(|r| json!({"id": r.id, "version": r.version}));
        self.send(
            "axt.Error",
            Kind::Error,
            &json!({
                "to": hex(&self.peer),
                "code": code.as_str(),
                "message_hash": hex(&Sha256::digest(message)),
                "record": record,
                "fingerprint": fingerprint.map(|f| hex(&f)),
                "field": field,
                "detail": "",
            }),
        )
    }

    /// A reply of one `ERROR` about `message`.
    fn error_reply(
        &self,
        message: &[u8],
        code: ErrorCode,
        record: Option<&RecordRef>,
        fingerprint: Option<[u8; 8]>,
        field: Option<String>,
    ) -> Result<Received, Error> {
        Ok(Received {
            replies: vec![self.error(message, code, record, fingerprint, field)?],
            ..Received::default()
        })
    }

    /// The connection ends; offers end with it (section 4.3).
    pub(crate) fn close_connection(&mut self) {
        self.signed_manifest = false;
        self.peer_manifest = None;
        self.peer_offers.clear();
        self.current.clear();
        self.held_errors.clear();
    }

    /// Processes one live message of the other app.
    ///
    /// # Errors
    ///
    /// Only when the app fails to write a reply, which the embedded schemas rule out.
    pub(crate) fn receive(&mut self, message: &[u8]) -> Result<Received, Error> {
        let envelope = match envelope::decode_message(message) {
            Ok(envelope) => envelope,
            Err(e) => {
                if !self.signed_manifest {
                    return Ok(Received::default());
                }
                let code = e.code().unwrap_or(ErrorCode::InvalidMessage);
                let fingerprint = if code == ErrorCode::FormatUnsupported {
                    message.get(2..10).and_then(|f| <[u8; 8]>::try_from(f).ok())
                } else {
                    None
                };
                return self.error_reply(message, code, None, fingerprint, None);
            }
        };
        let kind = envelope.kind;
        if !verify_live_message(message, &envelope.sender) {
            if !self.signed_manifest {
                return Ok(Received::default());
            }
            return self.error_reply(message, ErrorCode::SignatureInvalid, None, None, None);
        }
        if matches!(kind, Kind::DeviceAdd | Kind::DeviceRemove) {
            return self.chain(message);
        }
        if kind == Kind::DeviceJoin {
            return Ok(Received::default());
        }
        if self.receiver.state_of(&envelope.sender) == KeyState::Removed
            || envelope.sender != self.peer
        {
            return Ok(Received::default());
        }
        if envelope.record.is_some() != carries_record(kind) {
            if !self.signed_manifest {
                return Ok(Received::default());
            }
            return self.error_reply(
                message,
                ErrorCode::InvalidMessage,
                envelope.record.as_ref(),
                None,
                None,
            );
        }
        if kind == Kind::Manifest {
            return self.on_manifest(message, &envelope);
        }
        // Nothing but a MANIFEST is processed before a valid one (section 3.1).
        if self.peer_manifest.is_none() {
            return Ok(Received::default());
        }
        match self.process(&envelope) {
            Ok(received) => Ok(received),
            Err(Stop::Ignored) => Ok(Received::default()),
            Err(Stop::Rejected {
                code,
                fingerprint,
                field,
            }) => self.error_reply(message, code, envelope.record.as_ref(), fingerprint, field),
            Err(Stop::Failed(e)) => Err(e),
        }
    }

    /// A `DEVICE_ADD` or a `DEVICE_REMOVE` (keys.md, section 5.5).
    fn chain(&mut self, message: &[u8]) -> Result<Received, Error> {
        let results = self.receiver.receive_chain(&[message.to_vec()]);
        let mut replies = Vec::new();
        if results.first() == Some(&ChangeResult::DeviceRejected) {
            let error = self.error(message, ErrorCode::DeviceRejected, None, None, None)?;
            if self.signed_manifest {
                replies.push(error);
            } else {
                // Reported once the connection has a MANIFEST (section 3.3).
                self.held_errors.push(error);
            }
        }
        let close = self.receiver.state_of(&self.peer) == KeyState::Removed;
        if close {
            // The offers made to the removed key and by it end (section 4.3).
            self.own_offers.clear();
            self.current.clear();
        }
        Ok(Received {
            outcome: None,
            close,
            replies,
        })
    }

    /// A `MANIFEST` of the other app (section 3).
    fn on_manifest(&mut self, message: &[u8], envelope: &Envelope) -> Result<Received, Error> {
        self.signed_manifest = true;
        let mut replies = std::mem::take(&mut self.held_errors);
        match check_manifest(&envelope.body, i64::from(ENVELOPE_FORMAT)) {
            Ok(manifest) => self.peer_manifest = Some(manifest),
            Err(e) => replies.push(self.error(
                message,
                e.code().unwrap_or(ErrorCode::InvalidMessage),
                None,
                None,
                None,
            )?),
        }
        Ok(Received {
            replies,
            ..Received::default()
        })
    }

    /// The body of `envelope`, decoded with its kind's schema.
    fn body(envelope: &Envelope) -> Result<Value, Stop> {
        envelope::decode_body(envelope.kind, &envelope.body)
            .map_err(|_| reject(ErrorCode::InvalidMessage))
    }

    /// Ignores a message whose `to` is not the app's key.
    fn check_to(&self, body: &Value) -> Result<(), Stop> {
        if key_of(body, "to") == Some(self.key) {
            Ok(())
        } else {
            Err(Stop::Ignored)
        }
    }

    fn process(&mut self, envelope: &Envelope) -> Result<Received, Stop> {
        match envelope.kind {
            Kind::Offer => self.on_offer(envelope),
            Kind::Accept | Kind::Decline => self.on_answer(envelope),
            Kind::Ack => self.on_ack(envelope),
            Kind::Error => {
                self.on_error(envelope);
                Ok(Received::default())
            }
            Kind::Data | Kind::Delete | Kind::Withdraw => self.on_record(envelope),
            // Only between the devices of one set (sync.md, section 7.1).
            Kind::Change | Kind::Resync | Kind::Forward => Err(reject(ErrorCode::InvalidMessage)),
            _ => Ok(Received::default()),
        }
    }

    /// An `OFFER` (section 5).
    fn on_offer(&mut self, envelope: &Envelope) -> Result<Received, Stop> {
        let body = Self::body(envelope)?;
        self.check_to(&body)?;
        let offer_id = text(&body, "offer_id")?.to_owned();
        if let Some(answers) = self.peer_offers.get(&offer_id) {
            return Ok(Received {
                replies: self.answer(&offer_id, answers)?,
                ..Received::default()
            });
        }
        let types = list(&body, "types")?;
        if record_key(&offer_id).is_none() || types.is_empty() || types.len() > PROTOCOL_OFFER_TYPES
        {
            return Err(reject(ErrorCode::OfferInvalid));
        }
        // A description that is not valid is declined, not the offer (section 4.2).
        let mut parsed: Vec<(String, Option<TypeDescription>)> = Vec::new();
        for entry in types {
            if long(entry, "count")? < 0 {
                return Err(reject(ErrorCode::OfferInvalid));
            }
            let description = entry
                .field("description")
                .ok_or_else(|| reject(ErrorCode::InvalidMessage))?;
            let name = object_name(description)
                .ok_or_else(|| reject(ErrorCode::OfferInvalid))?
                .to_owned();
            let described = TypeDescription::from_datum(description.clone()).ok();
            // The full name is in the Parsing Canonical Form, so two types of one
            // fingerprint have one name as well.
            if parsed.iter().any(|(n, _)| *n == name) {
                return Err(reject(ErrorCode::OfferInvalid));
            }
            parsed.push((name, described));
        }
        let mut answers = Vec::new();
        for (name, described) in parsed {
            let answer = match &described {
                None => "DESCRIPTION_INVALID",
                Some(described)
                    if !fit(&self.manifest, described.schema_text(), &[]).is_ok_and(|f| f.fits) =>
                {
                    "DOES_NOT_FIT"
                }
                Some(described) if !self.resolves(&name, described.schema()) => "DOES_NOT_RESOLVE",
                Some(_) if self.user_takes.contains(&name) => "ACCEPT",
                Some(_) => "NOT_WANTED",
            };
            match described {
                Some(described) => {
                    self.current.insert(
                        name.clone(),
                        Current {
                            type_name: name.clone(),
                            schema: described.schema().clone(),
                            text: described.schema_text().to_owned(),
                            accepted: answer == "ACCEPT",
                        },
                    );
                }
                None => {
                    self.current.remove(&name);
                }
            }
            answers.push((name, answer.to_owned()));
        }
        let replies = self.answer(&offer_id, &answers)?;
        self.peer_offers.insert(offer_id, answers);
        Ok(Received {
            replies,
            ..Received::default()
        })
    }

    /// Whether an offered `writer` of the type `name` resolves against the app's reader
    /// schema of that name, if it has one. The reader is the one of the offered full
    /// name, so only the resolution itself can fail.
    fn resolves(&self, name: &str, writer: &Schema) -> bool {
        check_axt_names(writer).is_ok()
            && self.readers.get(name).is_none_or(|text| {
                Schema::parse(text).is_ok_and(|reader| writer.resolution(&reader).is_ok())
            })
    }

    /// The `ACCEPT` and the `DECLINE` of the answers to the offer `offer_id`.
    fn answer(&self, offer_id: &str, answers: &[(String, String)]) -> Result<Vec<Vec<u8>>, Error> {
        let accepted: Vec<&str> = answers
            .iter()
            .filter(|(_, a)| a == "ACCEPT")
            .map(|(name, _)| name.as_str())
            .collect();
        let declined: Vec<Json> = answers
            .iter()
            .filter(|(_, a)| a != "ACCEPT")
            .map(|(name, reason)| json!({"type": name, "reason": reason}))
            .collect();
        let mut replies = Vec::new();
        let to = hex(&self.peer);
        if !accepted.is_empty() {
            replies.push(self.send(
                "axt.Accept",
                Kind::Accept,
                &json!({"to": to, "offer_id": offer_id, "types": accepted}),
            )?);
        }
        if !declined.is_empty() {
            replies.push(self.send(
                "axt.Decline",
                Kind::Decline,
                &json!({"to": to, "offer_id": offer_id, "types": declined}),
            )?);
        }
        Ok(replies)
    }

    /// An `ACCEPT` or a `DECLINE` of an offer of the app (section 5.2).
    fn on_answer(&mut self, envelope: &Envelope) -> Result<Received, Stop> {
        let body = Self::body(envelope)?;
        self.check_to(&body)?;
        let offer_id = text(&body, "offer_id")?.to_owned();
        let accept = envelope.kind == Kind::Accept;
        let mut answered: Vec<(String, String)> = Vec::new();
        for entry in list(&body, "types")? {
            answered.push(if accept {
                match entry {
                    Value::String(name) => (name.clone(), "ACCEPT".to_owned()),
                    _ => return Err(reject(ErrorCode::InvalidMessage)),
                }
            } else {
                (
                    text(entry, "type")?.to_owned(),
                    symbol(entry, "reason")?.to_owned(),
                )
            });
        }
        if !self.made_offers.contains(&offer_id) {
            return Ok(Received::default());
        }
        let names: HashSet<&str> = answered.iter().map(|(n, _)| n.as_str()).collect();
        let offered = self.offer_types.get(&offer_id);
        if names.len() != answered.len()
            || answered
                .iter()
                .any(|(n, _)| !offered.is_some_and(|o| o.contains(n)))
        {
            return Err(reject(ErrorCode::InvalidMessage));
        }
        for (name, answer) in answered {
            if let Some(own) = self
                .own_offers
                .get_mut(&name)
                .filter(|own| own.offer_id == offer_id && own.answer.is_none())
            {
                own.answer = Some(answer);
            }
        }
        Ok(Received::default())
    }

    /// An `ACK` of the app's record messages (section 7).
    fn on_ack(&mut self, envelope: &Envelope) -> Result<Received, Stop> {
        let body = Self::body(envelope)?;
        self.check_to(&body)?;
        let records = list(&body, "records")?;
        let mut seen = HashSet::new();
        let mut taken = Vec::new();
        for entry in records {
            let key =
                record_key(text(entry, "id")?).ok_or_else(|| reject(ErrorCode::InvalidMessage))?;
            let version = long(entry, "version")?;
            let outcome = symbol(entry, "outcome")?;
            let receiver_version = long(entry, "receiver_version")?;
            let kept = list(entry, "kept_fields")?
                .iter()
                .map(|field| match field {
                    Value::String(field) => Ok(field.as_str()),
                    _ => Err(reject(ErrorCode::InvalidMessage)),
                })
                .collect::<Result<Vec<_>, Stop>>()?;
            let distinct: HashSet<&str> = kept.iter().copied().collect();
            let version_fits = if outcome == "STALE" {
                receiver_version > version
            } else {
                receiver_version == version
            };
            if version < 1
                || !seen.insert(slot(&key, version))
                || !version_fits
                || (outcome == "MERGED") == kept.is_empty()
                || distinct.len() != kept.len()
            {
                return Err(reject(ErrorCode::InvalidMessage));
            }
            let outcome = outcome_of(outcome).ok_or_else(|| reject(ErrorCode::InvalidMessage))?;
            taken.push((slot(&key, version), outcome));
        }
        if records.is_empty() || records.len() > PROTOCOL_ACK_RECORDS {
            return Err(reject(ErrorCode::InvalidMessage));
        }
        for (slot, outcome) in taken {
            let had = self.outcomes.get(&slot).copied();
            let stands = match had {
                None | Some(Outcome::Duplicate) => false,
                Some(Outcome::Kept | Outcome::Merged) if outcome == Outcome::Applied => false,
                Some(Outcome::Kept) if outcome == Outcome::Withdrawn => false,
                Some(_) => true,
            };
            if !stands {
                self.outcomes.insert(slot, outcome);
            }
        }
        Ok(Received::default())
    }

    /// An `ERROR` about a message of the app (section 8); one that cannot be processed is
    /// dropped.
    fn on_error(&mut self, envelope: &Envelope) {
        let Ok(body) = envelope::decode_body(Kind::Error, &envelope.body) else {
            return;
        };
        if key_of(&body, "to") != Some(self.key) {
            return;
        }
        if let Some(record @ Value::Record(_)) = body.field("record")
            && let (Ok(id), Ok(version)) = (text(record, "id"), long(record, "version"))
            && let Some(key) = record_key(id)
            && self.outcomes.contains_key(&slot(&key, version))
        {
            return;
        }
        if let Ok(code) = symbol(&body, "code") {
            self.errors.push(code.to_owned());
        }
    }

    /// Whether the app accepted any type of the current offers.
    fn accepted_any(&self) -> bool {
        self.current.values().any(|c| c.accepted)
    }

    /// A `DATA`, `DELETE` or `WITHDRAW` (section 6; records.md, sections 5 to 7).
    fn on_record(&mut self, envelope: &Envelope) -> Result<Received, Stop> {
        let record = envelope
            .record
            .as_ref()
            .ok_or_else(|| reject(ErrorCode::InvalidMessage))?;
        let kind = envelope.kind;
        if kind == Kind::Delete && !envelope.body.is_empty() {
            return Err(reject(ErrorCode::InvalidMessage));
        }
        if kind == Kind::Withdraw {
            self.check_to(&Self::body(envelope)?)?;
        }
        let key = checked_record_key(&record.id).map_err(reject_with)?;
        if record.version < 1 {
            return Err(reject(ErrorCode::VersionInvalid));
        }
        let held = self.held.get(&key).cloned();
        let held_type = held.as_ref().and_then(|h| h.type_name.clone());
        let mut writer = None;
        match kind {
            Kind::Data => {
                let (fingerprint, _) = split_single_object(&envelope.body)
                    .ok_or_else(|| reject(ErrorCode::InvalidMessage))?;
                let current = self
                    .current
                    .values()
                    .find(|c| c.schema.fingerprint().0 == fingerprint)
                    .ok_or(Stop::Rejected {
                        code: ErrorCode::SchemaUnknown,
                        fingerprint: Some(fingerprint),
                        field: None,
                    })?;
                if !current.accepted
                    || !fit(&self.manifest, &current.text, &[]).is_ok_and(|f| f.fits)
                {
                    return Err(reject(ErrorCode::NotAccepted));
                }
                if held_type
                    .as_ref()
                    .is_some_and(|held| *held != current.type_name)
                {
                    return Err(reject(ErrorCode::TypeChanged));
                }
                writer = Some((current.type_name.clone(), current.schema.clone()));
            }
            Kind::Delete => {
                let ok = match &held_type {
                    None => self.accepted_any(),
                    Some(held) => self.current.get(held).is_some_and(|c| c.accepted),
                };
                if !ok {
                    return Err(reject(ErrorCode::NotAccepted));
                }
            }
            _ => {
                if held.is_none() && !self.accepted_any() {
                    return Err(reject(ErrorCode::NotAccepted));
                }
            }
        }
        let newer = held.as_ref().is_none_or(|h| record.version > h.version);
        let value = match &writer {
            Some((type_name, writer)) if newer => {
                let reader = self
                    .readers
                    .get(type_name)
                    .map(|text| Schema::parse(text))
                    .transpose()
                    .map_err(reject_with)?;
                Some(
                    decode_record(writer, reader.as_ref(), &envelope.body, true)
                        .map_err(reject_with)?,
                )
            }
            // A DATA that is not newer is a duplicate or stale without being decoded;
            // the version rule settles it before it looks at the value.
            Some(_) => Some(Value::Null),
            None => None,
        };
        let applied = apply_record_message(
            held.as_ref(),
            self.values.get(&key).and_then(Option::as_ref),
            RecordMessage {
                kind: match kind {
                    Kind::Data => RecordKind::Data,
                    Kind::Delete => RecordKind::Delete,
                    _ => RecordKind::Withdraw,
                },
                version: record.version,
                type_name: writer.as_ref().map(|(name, _)| name.as_str()),
                value: value.as_ref(),
            },
            &RecordPolicy::default(),
            &ElementMerge::default(),
        )
        .map_err(reject_with)?;
        self.owed_acks.push(AckEntry {
            id: record.id.clone(),
            version: record.version,
            outcome: applied.outcome,
            receiver_version: applied.held.version,
            kept_fields: applied.kept_fields,
        });
        self.held.insert(key.clone(), applied.held);
        self.values.insert(key, applied.value);
        Ok(Received {
            outcome: Some(applied.outcome),
            ..Received::default()
        })
    }

    /// Sends the acknowledgements it owes: the entries, and the `ACK`.
    ///
    /// # Errors
    ///
    /// Only when the app fails to write the `ACK`.
    pub(crate) fn flush_acks(&mut self) -> Result<(Vec<AckEntry>, Vec<Vec<u8>>), Error> {
        let entries = std::mem::take(&mut self.owed_acks);
        if entries.is_empty() {
            return Ok((entries, Vec::new()));
        }
        let records: Vec<Json> = entries
            .iter()
            .map(|e| {
                json!({
                    "id": e.id,
                    "version": e.version,
                    "outcome": e.outcome.as_str(),
                    "receiver_version": e.receiver_version,
                    "kept_fields": e.kept_fields,
                })
            })
            .collect();
        let ack = self.send(
            "axt.Ack",
            Kind::Ack,
            &json!({"to": hex(&self.peer), "records": records}),
        )?;
        Ok((entries, vec![ack]))
    }

    /// Offers the types of `types`, each a description, a datum of `axt.Field`, with its
    /// count, under `offer_id`, the descriptions as given.
    ///
    /// # Errors
    ///
    /// `DESCRIPTION_INVALID` for a description of no object type, and `INVALID_MESSAGE`
    /// when the `OFFER` cannot be written.
    pub(crate) fn offer(
        &mut self,
        offer_id: &str,
        types: &[(Value, i64)],
    ) -> Result<Vec<u8>, Error> {
        let mut names = BTreeSet::new();
        for (description, _) in types {
            let name = object_name(description).ok_or_else(|| {
                Error::axt(
                    ErrorCode::DescriptionInvalid,
                    "the description is of no object type",
                )
            })?;
            names.insert(name.to_owned());
        }
        self.made_offers.insert(offer_id.to_owned());
        for name in &names {
            self.own_offers.insert(
                name.clone(),
                OwnOffer {
                    offer_id: offer_id.to_owned(),
                    answer: None,
                },
            );
        }
        self.offer_types.insert(offer_id.to_owned(), names);
        let schema = axt_schema("axt.Offer").ok_or_else(|| {
            Error::axt(ErrorCode::InvalidMessage, "the schema axt.Offer is missing")
        })?;
        let body = Value::Record(vec![
            ("to".into(), Value::Fixed(self.peer.to_vec())),
            ("offer_id".into(), Value::String(offer_id.to_owned())),
            (
                "types".into(),
                Value::Array(
                    types
                        .iter()
                        .map(|(description, count)| {
                            Value::Record(vec![
                                ("description".into(), description.clone()),
                                ("count".into(), Value::Long(*count)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        self.send_value(schema, Kind::Offer, &body)
    }

    /// Whether it has an accepted offer of `type_name`.
    pub(crate) fn accepted(&self, type_name: &str) -> bool {
        self.own_offers
            .get(type_name)
            .is_some_and(|own| own.answer.as_deref() == Some("ACCEPT"))
    }

    /// The outcome it holds for its record message `id` and `version`.
    pub(crate) fn outcome_of(&self, id: &str, version: i64) -> Option<Outcome> {
        record_key(id).and_then(|key| self.outcomes.get(&slot(&key, version)).copied())
    }

    /// What it holds of the other app's record `id`.
    pub(crate) fn record(&self, id: &str) -> Option<&HeldRecord> {
        record_key(id).and_then(|key| self.held.get(&key))
    }

    /// The codes of the `ERROR` messages about its own messages it has taken, in order.
    pub(crate) fn errors(&self) -> &[String] {
        &self.errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bricks::description_from_json;
    use crate::device_sets::fixtures::{
        TestKey, device_add, device_add_with, device_remove, tampered,
    };
    use crate::envelope::{decode_body, decode_message, encode_message};
    use crate::records::HeldState;

    const ID: &str = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80";
    const OFFER_ID: &str = "6f1c2b9e-3d4a-4e5f-8a7b-1c2d3e4f5a6b";

    /// A description of `name` with one required text `field`.
    fn describe(name: &str, field: &str) -> Json {
        json!({
            "name": "root",
            "doc": "A type.",
            "texts": {},
            "kind": {"axt.ObjectField": {
                "name": name,
                "version": 1,
                "fields": [{
                    "name": field,
                    "doc": "The text.",
                    "texts": {},
                    "required": true,
                    "kind": {"axt.StringField": {}},
                }],
            }},
        })
    }

    fn memo() -> Json {
        describe("org.example.Memo", "text")
    }

    fn schema_of(description: &Json) -> Schema {
        TypeDescription::from_json(description)
            .unwrap()
            .schema()
            .clone()
    }

    fn body(schema: &str, json: Json) -> Vec<u8> {
        let schema = axt_schema(schema).unwrap();
        schema
            .encode_single_object(&schema.datum_of_json(&json).unwrap())
            .unwrap()
    }

    fn manifest(name: &str, formats: &[i64], takes: Json, any_type: Json) -> Vec<u8> {
        body(
            "axt.Manifest",
            json!({
                "revision": 1,
                "app_name": name,
                "app_url": null,
                "formats": formats,
                "takes": takes,
                "any_type": any_type,
                "sends": null,
                "encryption_key": null,
                "relay": null,
            }),
        )
    }

    fn manifest_body(name: &str) -> Vec<u8> {
        manifest(
            name,
            &[1],
            json!([{
                "type": "org.example.Memo",
                "min_version": 1,
                "max_version": null,
                "purpose": "A Memo.",
                "purpose_translations": {},
            }]),
            Json::Null,
        )
    }

    fn signed(signer: &TestKey, kind: Kind, body: Vec<u8>, record: Option<(&str, i64)>) -> Vec<u8> {
        let mut message = encode_message(&Envelope {
            kind,
            sender: signer.public,
            record: record.map(|(id, version)| RecordRef {
                id: id.into(),
                version,
            }),
            body,
            signature: [0; 64],
        })
        .unwrap();
        let signature = ed25519::sign(
            &signer.seed,
            &signed_bytes_of_live_message(&message).unwrap(),
        );
        let end = message.len() - 64;
        message[end..].copy_from_slice(&signature);
        message
    }

    /// The kind and the body of a message the app wrote.
    fn decoded(message: &[u8]) -> (Kind, Value) {
        let envelope = decode_message(message).unwrap();
        (
            envelope.kind,
            decode_body(envelope.kind, &envelope.body).unwrap(),
        )
    }

    fn kind_of(message: &[u8]) -> Kind {
        decoded(message).0
    }

    /// The code of the one `ERROR` the app replies, or `None` for no reply.
    fn code(app: &mut LiveApp, message: &[u8]) -> Option<String> {
        let replies = app.receive(message).unwrap().replies;
        assert!(replies.len() <= 1);
        replies.first().map(|r| {
            let (kind, body) = decoded(r);
            assert_eq!(kind, Kind::Error);
            match body.field("code") {
                Some(Value::Enum { symbol, .. }) => symbol.clone(),
                other => panic!("no code: {other:?}"),
            }
        })
    }

    fn app_of(own: &TestKey, peer: &TestKey, takes: &[&str], readers: &[(&str, &str)]) -> LiveApp {
        LiveApp::open(
            SigningSeed::new(*own.seed.as_bytes()),
            &manifest_body("app"),
            readers
                .iter()
                .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
                .collect(),
            takes.iter().map(|t| (*t).to_owned()).collect(),
            peer.public,
        )
        .unwrap()
    }

    fn offer_of(from: &TestKey, to: &TestKey, offer_id: &str, types: Json) -> Vec<u8> {
        signed(
            from,
            Kind::Offer,
            body(
                "axt.Offer",
                json!({"to": hex(&to.public), "offer_id": offer_id, "types": types}),
            ),
            None,
        )
    }

    fn memo_data(from: &TestKey, version: i64) -> Vec<u8> {
        let text = Value::Record(vec![("text".into(), Value::String("x".into()))]);
        signed(
            from,
            Kind::Data,
            schema_of(&memo()).encode_single_object(&text).unwrap(),
            Some((ID, version)),
        )
    }

    fn keys() -> (TestKey, TestKey, TestKey) {
        (
            TestKey::named("live a"),
            TestKey::named("live b"),
            TestKey::named("live c"),
        )
    }

    #[test]
    fn a_receiver_manifest_offer_records_acks() {
        let (a, b, c) = keys();
        let mut app = app_of(&b, &a, &["org.example.Memo"], &[]);
        let offer = offer_of(
            &a,
            &b,
            OFFER_ID,
            json!([{"description": memo(), "count": 1}]),
        );
        assert!(
            app.receive(&offer).unwrap().replies.is_empty(),
            "before the manifest"
        );
        let manifest = signed(&a, Kind::Manifest, manifest_body("a"), None);
        assert!(app.receive(&manifest).unwrap().replies.is_empty());
        let answer = app.receive(&offer).unwrap();
        assert_eq!(answer.replies.len(), 1);
        assert_eq!(kind_of(&answer.replies[0]), Kind::Accept);
        let repeat = app.receive(&offer).unwrap();
        assert_eq!(kind_of(&repeat.replies[0]), Kind::Accept);
        let data = memo_data(&a, 1);
        assert_eq!(app.receive(&data).unwrap().outcome, Some(Outcome::Applied));
        assert_eq!(
            app.receive(&data).unwrap().outcome,
            Some(Outcome::Duplicate)
        );
        assert_eq!(app.record(ID).map(|h| h.version), Some(1));
        assert!(app.record("nope").is_none());
        let (entries, replies) = app.flush_acks().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(replies.len(), 1);
        assert_eq!(kind_of(&replies[0]), Kind::Ack);
        let (none, no_replies) = app.flush_acks().unwrap();
        assert!(none.is_empty() && no_replies.is_empty());
        let delete = signed(&a, Kind::Delete, Vec::new(), Some((ID, 2)));
        assert_eq!(
            app.receive(&delete).unwrap().outcome,
            Some(Outcome::Applied)
        );
        let withdraw = signed(
            &a,
            Kind::Withdraw,
            body("axt.Withdraw", json!({"to": hex(&b.public)})),
            Some((ID, 3)),
        );
        assert_eq!(
            app.receive(&withdraw).unwrap().outcome,
            Some(Outcome::Withdrawn)
        );
        assert_eq!(app.record(ID).map(|h| h.state), Some(HeldState::Withdrawn));
        let other_to = signed(
            &a,
            Kind::Withdraw,
            body("axt.Withdraw", json!({"to": hex(&c.public)})),
            Some((ID, 4)),
        );
        assert_eq!(app.receive(&other_to).unwrap(), Received::default());
        app.close_connection();
        assert!(
            app.receive(&data).unwrap().replies.is_empty(),
            "no manifest in the new connection"
        );
    }

    #[test]
    fn a_receiver_reports_what_it_cannot_process() {
        let (a, b, c) = keys();
        let reader = r#"{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"n","type":"int"}]}"#;
        let mut app = app_of(&b, &a, &[], &[("org.example.Memo", reader)]);
        assert_eq!(code(&mut app, &[0; 3]), None, "before any manifest");
        let bad = manifest("bad", &[2], json!([]), Json::Null);
        assert_eq!(
            code(&mut app, &signed(&a, Kind::Manifest, bad, None)).as_deref(),
            Some("MANIFEST_INVALID")
        );
        let good = signed(&a, Kind::Manifest, manifest_body("a"), None);
        assert_eq!(code(&mut app, &good), None);
        assert_eq!(code(&mut app, &[0; 3]).as_deref(), Some("INVALID_MESSAGE"));
        let data = memo_data(&a, 1);
        assert_eq!(
            code(&mut app, &tampered(data.clone())).as_deref(),
            Some("SIGNATURE_INVALID")
        );
        let mut other = data.clone();
        other[2..10].copy_from_slice(&[0; 8]);
        assert_eq!(
            code(&mut app, &other).as_deref(),
            Some("FORMAT_UNSUPPORTED")
        );
        assert_eq!(code(&mut app, &data).as_deref(), Some("SCHEMA_UNKNOWN"));
        let with_record = signed(&a, Kind::Manifest, manifest_body("a"), Some((ID, 1)));
        assert_eq!(
            code(&mut app, &with_record).as_deref(),
            Some("INVALID_MESSAGE")
        );
        let resync = signed(
            &a,
            Kind::Resync,
            body("axt.Resync", json!({"to": hex(&b.public)})),
            Some((ID, 1)),
        );
        assert_eq!(code(&mut app, &resync).as_deref(), Some("INVALID_MESSAGE"));
        let stranger = signed(&c, Kind::Data, Vec::new(), Some((ID, 1)));
        assert_eq!(code(&mut app, &stranger), None, "another sender");
        let entry =
            |description: Json, count: i64| json!({"description": description, "count": count});
        for (offer_id, types) in [
            ("x", json!([entry(memo(), 0)])),
            (OFFER_ID, json!([])),
            (OFFER_ID, json!([entry(memo(), -1)])),
            (
                OFFER_ID,
                json!([entry(
                    json!({"name": "root", "doc": "", "texts": {}, "kind": {"axt.StringField": {}}}),
                    0
                )]),
            ),
            (OFFER_ID, json!([entry(memo(), 0), entry(memo(), 0)])),
        ] {
            assert_eq!(
                code(&mut app, &offer_of(&a, &b, offer_id, types.clone())).as_deref(),
                Some("OFFER_INVALID"),
                "{types}"
            );
        }
        let declined = app
            .receive(&offer_of(
                &a,
                &b,
                OFFER_ID,
                json!([
                    entry(memo(), 0),
                    entry(describe("org.example.Other", "text"), 0),
                    entry(describe("org.example.Bad", "Bad"), 0),
                ]),
            ))
            .unwrap();
        assert_eq!(declined.replies.len(), 1);
        let (kind, decline) = decoded(&declined.replies[0]);
        assert_eq!(kind, Kind::Decline);
        let reasons: Vec<&str> = list(&decline, "types")
            .ok()
            .unwrap()
            .iter()
            .map(|t| symbol(t, "reason").ok().unwrap())
            .collect();
        assert_eq!(
            reasons,
            ["DOES_NOT_RESOLVE", "DOES_NOT_FIT", "DESCRIPTION_INVALID"]
        );
        assert_eq!(code(&mut app, &data).as_deref(), Some("NOT_ACCEPTED"));
        for (kind, body, record, expected) in [
            (Kind::Delete, vec![], (ID, 1), "NOT_ACCEPTED"),
            (Kind::Delete, vec![0], (ID, 1), "INVALID_MESSAGE"),
            (Kind::Delete, vec![], ("x", 1), "RECORD_ID_INVALID"),
            (Kind::Delete, vec![], (ID, 0), "VERSION_INVALID"),
            (Kind::Withdraw, vec![], (ID, 1), "INVALID_MESSAGE"),
            (
                Kind::Withdraw,
                super::tests::body("axt.Withdraw", json!({"to": hex(&b.public)})),
                (ID, 1),
                "NOT_ACCEPTED",
            ),
        ] {
            assert_eq!(
                code(&mut app, &signed(&a, kind, body, Some(record))).as_deref(),
                Some(expected),
                "{kind:?} {record:?}"
            );
        }
        let join = signed(
            &a,
            Kind::DeviceJoin,
            body(
                "axt.DeviceJoin",
                json!({"to": hex(&b.public), "proof": hex(&[0; 64])}),
            ),
            None,
        );
        assert_eq!(code(&mut app, &join), None);
        let reply = signed(&a, Kind::ProposalReply, Vec::new(), Some((ID, 1)));
        assert_eq!(code(&mut app, &reply), None);
    }

    #[test]
    fn a_sender_offers_answers_acks_and_errors() {
        let (a, b, c) = keys();
        let mut app = app_of(&a, &b, &["org.example.Memo"], &[]);
        let manifest = signed(&b, Kind::Manifest, manifest_body("b"), None);
        assert!(app.receive(&manifest).unwrap().replies.is_empty());
        let offer = app
            .offer(OFFER_ID, &[(description_from_json(&memo()).unwrap(), 1)])
            .unwrap();
        assert_eq!(kind_of(&offer), Kind::Offer);
        assert!(!app.accepted("org.example.Memo"));
        let receive = |app: &mut LiveApp, kind: Kind, schema: &str, json: Json| {
            app.receive(&signed(&b, kind, body(schema, json), None))
                .unwrap()
        };
        let accept = |to: &TestKey, offer_id: &str, name: &str| json!({"to": hex(&to.public), "offer_id": offer_id, "types": [name]});
        let other_offer = "7e8f9a0b-1c2d-4e3f-8a4b-5c6d7e8f9a0b";
        let got = receive(
            &mut app,
            Kind::Accept,
            "axt.Accept",
            accept(&a, other_offer, "org.example.Memo"),
        );
        assert!(got.replies.is_empty());
        let got = receive(
            &mut app,
            Kind::Accept,
            "axt.Accept",
            accept(&a, OFFER_ID, "org.example.Other"),
        );
        assert_eq!(
            symbol(&decoded(&got.replies[0]).1, "code").ok(),
            Some("INVALID_MESSAGE")
        );
        let got = receive(
            &mut app,
            Kind::Accept,
            "axt.Accept",
            accept(&c, OFFER_ID, "org.example.Memo"),
        );
        assert!(got.replies.is_empty());
        receive(
            &mut app,
            Kind::Accept,
            "axt.Accept",
            accept(&a, OFFER_ID, "org.example.Memo"),
        );
        receive(
            &mut app,
            Kind::Decline,
            "axt.Decline",
            json!({
                "to": hex(&a.public),
                "offer_id": OFFER_ID,
                "types": [{"type": "org.example.Memo", "reason": "NOT_WANTED"}],
            }),
        );
        assert!(app.accepted("org.example.Memo"));
        let entry = |outcome: &str, version: i64, receiver: i64, kept: &[&str]| {
            json!({
                "id": ID,
                "version": version,
                "outcome": outcome,
                "receiver_version": receiver,
                "kept_fields": kept,
            })
        };
        let ack = |app: &mut LiveApp, records: Json| {
            let got = receive(
                app,
                Kind::Ack,
                "axt.Ack",
                json!({"to": hex(&a.public), "records": records}),
            );
            got.replies
                .first()
                .map(|r| symbol(&decoded(r).1, "code").ok().unwrap().to_owned())
        };
        let mut bad_id = entry("APPLIED", 1, 1, &[]);
        bad_id["id"] = json!("x");
        for bad in [
            json!([]),
            json!([entry("STALE", 1, 1, &[])]),
            json!([entry("MERGED", 1, 1, &[])]),
            json!([entry("APPLIED", 1, 1, &["x"])]),
            json!([entry("APPLIED", 1, 1, &[]), entry("APPLIED", 1, 1, &[])]),
            json!([bad_id]),
            json!([entry("APPLIED", 0, 0, &[])]),
            json!([entry("MERGED", 1, 1, &["x", "x"])]),
        ] {
            assert_eq!(
                ack(&mut app, bad.clone()).as_deref(),
                Some("INVALID_MESSAGE"),
                "{bad}"
            );
        }
        assert_eq!(ack(&mut app, json!([entry("KEPT", 1, 1, &[])])), None);
        assert_eq!(ack(&mut app, json!([entry("APPLIED", 1, 1, &[])])), None);
        assert_eq!(app.outcome_of(ID, 1), Some(Outcome::Applied));
        assert_eq!(ack(&mut app, json!([entry("DUPLICATE", 2, 2, &[])])), None);
        assert_eq!(
            ack(&mut app, json!([entry("MERGED", 2, 2, &["text"])])),
            None
        );
        assert_eq!(app.outcome_of(ID, 2), Some(Outcome::Merged));
        assert_eq!(ack(&mut app, json!([entry("KEPT", 3, 3, &[])])), None);
        assert_eq!(ack(&mut app, json!([entry("WITHDRAWN", 3, 3, &[])])), None);
        assert_eq!(app.outcome_of(ID, 3), Some(Outcome::Withdrawn));
        assert_eq!(app.outcome_of("x", 1), None);
        let error = |to: &TestKey, id: &str, version: i64| {
            json!({
                "to": hex(&to.public),
                "code": "UNDECODABLE",
                "message_hash": hex(&[0; 32]),
                "record": {"id": id, "version": version},
                "fingerprint": null,
                "field": null,
                "detail": "",
            })
        };
        for (to, id, version) in [(&a, ID, 1), (&a, ID, 9), (&a, "x", 9), (&c, ID, 9)] {
            receive(&mut app, Kind::Error, "axt.Error", error(to, id, version));
        }
        assert_eq!(app.errors(), ["UNDECODABLE", "UNDECODABLE"]);
        app.receive(&signed(&b, Kind::Error, vec![0; 3], None))
            .unwrap();
        assert_eq!(app.errors().len(), 2);
    }

    #[test]
    fn a_chain_before_and_in_the_connection() {
        let (a, b, c) = keys();
        let mut app = app_of(&b, &a, &["org.example.Memo"], &[]);
        let rejected = device_add_with(&a, &c, Some([0; 64]), None);
        assert!(app.receive(&rejected).unwrap().replies.is_empty());
        let manifest = signed(&a, Kind::Manifest, manifest_body("a"), None);
        let got = app.receive(&manifest).unwrap();
        assert_eq!(got.replies.len(), 1);
        assert_eq!(
            symbol(&decoded(&got.replies[0]).1, "code").ok(),
            Some("DEVICE_REJECTED")
        );
        assert_eq!(
            code(&mut app, &rejected).as_deref(),
            Some("DEVICE_REJECTED")
        );
        assert!(app.receive(&device_add(&a, &c)).unwrap().replies.is_empty());
        let removal = app.receive(&device_remove(&c, &a)).unwrap();
        assert!(removal.close);
        assert!(app.receive(&manifest).unwrap().replies.is_empty());
    }

    #[test]
    fn records_under_accepted_offers_that_fail_later_steps() {
        let (a, b, _) = keys();
        let other = describe("org.example.Other", "other");
        let memo_text = TypeDescription::from_json(&memo())
            .unwrap()
            .schema_text()
            .to_owned();
        let any_type = json!({"purpose": "Anything.", "purpose_translations": {}});
        let mut app = LiveApp::open(
            SigningSeed::new(*b.seed.as_bytes()),
            &manifest("b", &[1], json!([]), any_type),
            BTreeMap::from([("org.example.Memo".to_owned(), memo_text)]),
            BTreeSet::from([
                "org.example.Memo".to_owned(),
                "org.example.Other".to_owned(),
            ]),
            a.public,
        )
        .unwrap();
        app.receive(&signed(&a, Kind::Manifest, manifest_body("a"), None))
            .unwrap();
        let offered = app
            .receive(&offer_of(
                &a,
                &b,
                OFFER_ID,
                json!([
                    {"description": memo(), "count": 0},
                    {"description": other.clone(), "count": 0},
                ]),
            ))
            .unwrap();
        assert_eq!(offered.replies.len(), 1);
        let (kind, accept) = decoded(&offered.replies[0]);
        assert_eq!(kind, Kind::Accept);
        assert_eq!(
            accept.field("types"),
            Some(&Value::Array(vec![
                Value::String("org.example.Memo".into()),
                Value::String("org.example.Other".into()),
            ]))
        );
        let data = |app: &mut LiveApp, bytes: Vec<u8>, version: i64| {
            code(app, &signed(&a, Kind::Data, bytes, Some((ID, version))))
        };
        assert_eq!(
            data(&mut app, vec![0; 3], 1).as_deref(),
            Some("INVALID_MESSAGE")
        );
        let text = Value::Record(vec![("text".into(), Value::String("x".into()))]);
        let good = schema_of(&memo()).encode_single_object(&text).unwrap();
        assert_eq!(
            data(&mut app, good[..good.len() - 1].to_vec(), 1).as_deref(),
            Some("UNDECODABLE")
        );
        assert_eq!(data(&mut app, good, 1), None);
        let value = Value::Record(vec![("other".into(), Value::String("x".into()))]);
        let other_body = schema_of(&other).encode_single_object(&value).unwrap();
        assert_eq!(
            data(&mut app, other_body, 2).as_deref(),
            Some("TYPE_CHANGED")
        );
    }

    #[test]
    fn a_decline_taken_before_an_accept() {
        let (a, b, _) = keys();
        let mut app = app_of(&a, &b, &["org.example.Memo"], &[]);
        app.receive(&signed(&b, Kind::Manifest, manifest_body("b"), None))
            .unwrap();
        app.offer(OFFER_ID, &[(description_from_json(&memo()).unwrap(), 0)])
            .unwrap();
        let decline = body(
            "axt.Decline",
            json!({
                "to": hex(&a.public),
                "offer_id": OFFER_ID,
                "types": [{"type": "org.example.Memo", "reason": "NOT_WANTED"}],
            }),
        );
        app.receive(&signed(&b, Kind::Decline, decline, None))
            .unwrap();
        let accept = body(
            "axt.Accept",
            json!({"to": hex(&a.public), "offer_id": OFFER_ID, "types": ["org.example.Memo"]}),
        );
        app.receive(&signed(&b, Kind::Accept, accept, None))
            .unwrap();
        assert!(!app.accepted("org.example.Memo"));
    }

    #[test]
    fn the_adapter_plays_a_session_and_refuses_bad_requests() {
        let (a, b, _) = keys();
        let ask = |input: Json| {
            crate::conformance::Adapter::default()
                .answer(&json!({"id": "s", "op": "session", "input": input}))
        };
        let app = json!({
            "seed": hex(b.seed.as_bytes()),
            "manifest": hex(&manifest_body("b")),
            "formats": [1],
            "readers": {},
            "user_takes": ["org.example.Memo"],
            "peer": hex(&a.public),
        });
        let manifest = hex(&signed(&a, Kind::Manifest, manifest_body("a"), None));
        let offer = hex(&offer_of(
            &a,
            &b,
            OFFER_ID,
            json!([{"description": memo(), "count": 0}]),
        ));
        let answer = ask(json!({
            "app": app,
            "steps": [
                {"receive": manifest},
                {"receive": offer},
                {"receive": hex(&memo_data(&a, 1))},
                {"offer": {"offer_id": OFFER_ID, "types": [{"description": memo(), "count": 0}]}},
                {"flush_acks": true},
                {"query": {"accepted": "org.example.Memo"}},
                {"query": {"outcome": {"id": ID, "version": 1}}},
                {"query": {"record": ID}},
                {"query": {"errors": true}},
                {"close": true},
            ],
        }));
        let steps = answer["output"]["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 10);
        assert_eq!(steps[2]["outcome"], json!("APPLIED"));
        assert_eq!(steps[4]["replies"].as_array().map(Vec::len), Some(1));
        assert_eq!(steps[5], json!({"accepted": false}));
        assert_eq!(steps[6], json!({"outcome": null}));
        assert_eq!(
            steps[7],
            json!({"record": {"version": 1, "state": "there"}})
        );
        assert_eq!(steps[8], json!({"errors": []}));
        assert_eq!(steps[9], json!({}));
        let mut no_takes = app.clone();
        no_takes["user_takes"] = json!(1);
        for bad in [
            json!({"app": no_takes, "steps": []}),
            json!({"app": app, "steps": 1}),
            json!({"app": app, "steps": [{}]}),
            json!({"app": app, "steps": [{"offer": {"offer_id": OFFER_ID, "types": 1}}]}),
        ] {
            assert!(ask(bad.clone())["failure"].is_string(), "{bad}");
        }
    }
}
