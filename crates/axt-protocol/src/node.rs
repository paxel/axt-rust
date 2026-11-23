//! The public face of the library: one installation of an app that speaks AXT, keeping
//! its AXT state in the app's store (`docs/adr/0001-the-public-api.md` and
//! `0002-axt-0-2-0.md` of `axt_protocol` for Dart).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use crate::container::write_container;
use crate::device_sets::{DeviceSetReceiver, KeptRecord, Key, KeyState, KnownSender, RecordState};
use crate::ed25519::{public_key_of, sign};
use crate::envelope::{Envelope, Kind, RecordRef, encode_message};
use crate::error::{Error, ErrorCode};
use crate::file_reader::{
    CheckedFile, FileReader, FileRecordResult, RecordResult, check_file, file_header_signed_bytes,
    read_file_records,
};
use crate::keys::{EncryptionSeed, SigningSeed};
use crate::links::without_links;
use crate::manifest::{check_manifest, fit};
use crate::records::{
    HeldRecord, HeldState, Outcome, RecordPolicy, checked_record_key, record_key,
};
use crate::relation_index::{HeldRelation, RelationResolver, target_sender};
use crate::schema::Schema;
use crate::schemas::{axt_schema, axt_schema_text};
use crate::signing::{short_fingerprint, signed_bytes_of_live_message};
use crate::type_description::TypeDescription;
use crate::value::{Value, hex};

/// The key-value storage of bytes that the app implements for the library.
///
/// The library owns the keys it uses and the format of their values. It runs every
/// received file and every written file in one [`Store::transaction`]; the app runs it
/// on the same connection as its own data, so that both are written together or not at
/// all.
pub trait Store {
    /// The error of the store's operations; the library passes it on as
    /// [`Error::Store`].
    type Error: std::error::Error + Send + Sync + 'static;

    /// The value of `key`, or `None`.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot be read.
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Sets `key` to `value`.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot be written.
    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), Self::Error>;

    /// Removes `key`; nothing happens for a key that is not there.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot be written.
    fn delete(&mut self, key: &str) -> Result<(), Self::Error>;

    /// The keys that begin with `prefix`, in any order.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot be read.
    fn list(&self, prefix: &str) -> Result<Vec<String>, Self::Error>;

    /// Runs `body` as one transaction: commits what it wrote when it returns `Ok`, and
    /// rolls it back when it returns `Err`.
    ///
    /// # Errors
    ///
    /// The error of `body`, or [`Error::Store`] (see [`Error::store`]) when the
    /// transaction cannot be begun or committed.
    fn transaction<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error>;
}

/// What the app gets for one received record that changed what it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordChange {
    /// The sender, by the name the library knows it by.
    pub sender: String,
    /// The record's id, as its sender wrote it.
    pub id: String,
    /// The record's type, or `None` for a tombstone of a record never seen.
    pub type_name: Option<String>,
    /// The record as the app now holds it, merged with its user's changes; `None` when
    /// the record is deleted or withdrawn.
    pub value: Option<Value>,
    /// [`Outcome::Applied`], [`Outcome::Merged`] or [`Outcome::Withdrawn`].
    pub outcome: Outcome,
}

/// A record of a sender, or of the app itself, by the sender's name as
/// [`RecordChange::sender`] gives it, or the app's own key as hexadecimal text, and the
/// record's id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordAddress {
    /// The sender's name.
    pub sender: String,
    /// The id, in lower case.
    pub id: String,
}

impl fmt::Display for RecordAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.sender, self.id)
    }
}

/// A relation that points at a record: the record that holds it, and the relation's id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    /// The record that holds the relation.
    pub holder: RecordAddress,
    /// The relation's id.
    pub relation: String,
}

/// A new record id: a UUID of version 7 (RFC 9562), from the system's clock and random
/// bytes.
///
/// # Errors
///
/// The error of the system when it gives no random bytes.
pub fn new_record_id() -> std::io::Result<String> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    let mut random = [0; 10];
    getrandom::fill(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(record_id_at(ms, random))
}

/// The UUID of version 7 of the Unix time `ms` in milliseconds and the bytes `random`.
fn record_id_at(ms: u64, random: [u8; 10]) -> String {
    let mut bytes: Vec<u8> = ms.to_be_bytes().into_iter().skip(2).chain(random).collect();
    if let Some(b) = bytes.get_mut(6) {
        *b = 0x70 | (*b & 0x0f);
    }
    if let Some(b) = bytes.get_mut(8) {
        *b = 0x80 | (*b & 0x3f);
    }
    let mut id = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        id.push_str(&hex(&[*b]));
    }
    id
}

/// A record of the app's own, as it hands it to the library to send.
#[derive(Debug, Clone)]
pub struct OutgoingRecord<'a> {
    /// The record's id, a UUID the app keeps beside its entity.
    pub id: String,
    /// The record's type, whose derived schema is the writer schema, and its value;
    /// `None` for a record its user deleted.
    pub record: Option<(&'a TypeDescription, Value)>,
    /// Whether its links go along: its relations to records not shared in the same file
    /// and to things outside AXT, and its extensions (`spec/shares.md`, section 19.1).
    pub with_links: bool,
}

impl<'a> OutgoingRecord<'a> {
    /// A record that is there, of `type_description`, with its `value`.
    #[must_use]
    pub fn new(id: impl Into<String>, type_description: &'a TypeDescription, value: Value) -> Self {
        Self {
            id: id.into(),
            record: Some((type_description, value)),
            with_links: false,
        }
    }

    /// A record its user deleted.
    #[must_use]
    pub fn deleted(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            record: None,
            with_links: false,
        }
    }

    /// The record with its links, for a share for the receiver that names it and lets its
    /// links go along.
    #[must_use]
    pub fn with_links(mut self) -> Self {
        self.with_links = true;
        self
    }
}

/// What [`AxtNode::inspect`] found in a file, before anything is applied.
#[derive(Debug, Clone)]
pub struct FilePreview {
    file: CheckedFile,
    /// The key in `axt.sender`, as hexadecimal text.
    pub sender: String,
    /// Its short fingerprint, for the user to compare.
    pub short_fingerprint: String,
    /// The app name of a valid `MANIFEST` in the file, or `None`.
    pub app_name: Option<String>,
    /// Whether the sender is no known sender, even after the file's chain.
    pub first_contact: bool,
    /// Whether the sender is a removed key, so that nothing is applied.
    pub sender_removed: bool,
    /// The number of `DATA` messages of each type that fit the app's manifest, by full
    /// name.
    pub fitting: BTreeMap<String, usize>,
}

/// What [`AxtNode::apply`] did with a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    /// Whether the sender was known or accepted, so that records were applied.
    pub accepted: bool,
    /// One entry for each record message of the file, in its order.
    pub records: Vec<FileRecordResult>,
}

/// The clock of the library: the time now.
pub type Clock = Box<dyn Fn() -> SystemTime + Send + Sync>;

/// What the app opens the library with, besides its store and its keys.
pub struct NodeConfig {
    /// The app's own manifest content: a value of `axt.Manifest` with every field but
    /// `revision`, which the library raises whenever the content changes.
    pub manifest: Value,
    /// The app's own types, by which it reads the records of others.
    pub readers: Vec<TypeDescription>,
    /// The app's policy for its user's changes.
    pub policy: RecordPolicy,
    /// The clock of the version stamps; the system's clock by default.
    pub clock: Clock,
}

impl NodeConfig {
    /// The configuration of an app with `manifest`, no readers, the default policy and
    /// the system's clock.
    #[must_use]
    pub fn new(manifest: Value) -> Self {
        Self {
            manifest,
            readers: Vec::new(),
            policy: RecordPolicy::default(),
            clock: Box::new(SystemTime::now),
        }
    }
}

/// One installation of an app that speaks AXT, on the app's store `S`.
///
/// It has no `Debug`, as it holds the app's private keys.
pub struct AxtNode<S: Store> {
    store: S,
    signing_seed: SigningSeed,
    #[expect(dead_code, reason = "opens the sealed messages of a later ticket")]
    encryption_seed: EncryptionSeed,
    public_key: Key,
    manifest: Value,
    readers: BTreeMap<String, TypeDescription>,
    policy: RecordPolicy,
    clock: Clock,
}

impl<S: Store> AxtNode<S> {
    /// Opens the library on the app's `store`, with the seed of the app's Ed25519 signing
    /// key and the private key of its X25519 encryption key, and its `config`: its own
    /// manifest content, its readers, its policy for its user's changes and its clock.
    ///
    /// The library never writes the seeds to the store.
    #[must_use]
    pub fn open(
        store: S,
        signing_seed: SigningSeed,
        encryption_seed: EncryptionSeed,
        config: NodeConfig,
    ) -> Self {
        let public_key = public_key_of(&signing_seed);
        Self {
            store,
            signing_seed,
            encryption_seed,
            public_key,
            manifest: config.manifest,
            readers: config
                .readers
                .into_iter()
                .map(|reader| (reader.name().to_owned(), reader))
                .collect(),
            policy: config.policy,
            clock: config.clock,
        }
    }

    /// The short fingerprint of the app's own key, for its settings.
    #[must_use]
    pub fn short_fingerprint_of_own_key(&self) -> String {
        short_fingerprint(&self.public_key)
    }

    /// Checks `file` as a whole and tells what it holds, applying nothing.
    ///
    /// # Errors
    ///
    /// `FILE_REJECTED` for a file rejected as a whole; [`Error::Store`] when the store
    /// fails or holds no AXT state the library can read.
    pub fn inspect(&self, file: &[u8]) -> Result<FilePreview, Error> {
        let checked = check_file(file)?;
        let mut receiver = load_receiver(&self.store)?;
        receiver.receive_chain(&checked.chain);
        let app_name = checked
            .manifest
            .as_ref()
            .and_then(|body| check_manifest(body, 1).ok())
            .and_then(|manifest| match manifest.field("app_name") {
                Some(Value::String(name)) => Some(name.clone()),
                _ => None,
            });
        let manifest = manifest_with_revision(&self.manifest, 1);
        let mut fitting = BTreeMap::new();
        for message in &checked.records {
            if message.envelope.kind != Kind::Data {
                continue;
            }
            let Some(writer) = checked.writer_of(message) else {
                continue;
            };
            if fit(&manifest, writer.schema_text(), &[]).is_ok_and(|f| f.fits) {
                let count: &mut usize = fitting.entry(writer.name().to_owned()).or_default();
                *count = count.saturating_add(1);
            }
        }
        let state = receiver.state_of(&checked.sender);
        Ok(FilePreview {
            sender: hex(&checked.sender),
            short_fingerprint: short_fingerprint(&checked.sender),
            app_name,
            first_contact: state == KeyState::Unknown,
            sender_removed: state == KeyState::Removed,
            fitting,
            file: checked,
        })
    }

    /// Applies the file of `preview`, in one transaction of the store.
    ///
    /// A first contact is applied only with `accept_sender`. `on_record` gets each record
    /// that changes what the app holds, inside the transaction, with the store for the
    /// app's own writes; `current_value` gives the app's current value of a received
    /// record by its sender's name and its id in lower case (while
    /// [`RecordChange::id`] is the id as the sender wrote it), or `None` for one its user
    /// deleted, by which the library finds its user's own changes.
    ///
    /// # Errors
    ///
    /// The error of `on_record` or `current_value`, or [`Error::Store`] when the store
    /// fails or holds no AXT state the library can read; the transaction is then rolled
    /// back.
    pub fn apply(
        &mut self,
        preview: &FilePreview,
        accept_sender: bool,
        mut on_record: impl FnMut(&mut S, RecordChange) -> Result<(), Error>,
        mut current_value: impl FnMut(&S, &str, &str) -> Result<Option<Value>, Error>,
    ) -> Result<FileResult, Error> {
        let Self {
            store,
            public_key,
            manifest,
            readers,
            policy,
            ..
        } = self;
        store.transaction(|store| {
            let file = &preview.file;
            let mut receiver = load_receiver(store)?;
            receiver.receive_chain(&file.chain);
            let key = file.sender;
            if receiver.state_of(&key) == KeyState::Unknown {
                if !accept_sender {
                    return Ok(FileResult {
                        accepted: false,
                        records: Vec::new(),
                    });
                }
                receiver.senders.push(KnownSender {
                    name: hex(&key),
                    current: BTreeSet::from([key]),
                    ..KnownSender::default()
                });
            }
            save_senders(store, &receiver)?;
            let Some(sender) = receiver.current_sender_of(&key).map(|s| s.name.clone()) else {
                return Ok(FileResult {
                    accepted: true,
                    records: file
                        .records
                        .iter()
                        .map(|message| {
                            let (id, version) = message.record();
                            FileRecordResult {
                                id: id.to_owned(),
                                version,
                                result: RecordResult::SenderRemoved,
                            }
                        })
                        .collect(),
                });
            };
            let mut held = HashMap::new();
            let mut current = HashMap::new();
            let mut ids = HashMap::new();
            for message in &file.records {
                let (id, _) = message.record();
                let Some(record) = record_key(id) else {
                    continue;
                };
                ids.insert(record.clone(), id.to_owned());
                if held.contains_key(&record) {
                    continue;
                }
                let Some(stored) = load_held(store, &sender, &record)? else {
                    continue;
                };
                let value = if stored.state == HeldState::There {
                    current_value(store, &sender, &record)?
                } else {
                    None
                };
                held.insert(record.clone(), stored);
                current.insert(record, value);
            }
            let manifest = manifest_with_revision(manifest, 1);
            let reader_texts: BTreeMap<String, String> = readers
                .iter()
                .map(|(name, t)| (name.clone(), t.schema_text().to_owned()))
                .collect();
            let own = BTreeSet::from([*public_key]);
            let reader = FileReader {
                manifest: &manifest,
                readers: &reader_texts,
                current: &own,
                removed: &BTreeSet::new(),
            };
            let results = read_file_records(file, reader, &mut held, &mut current, policy);
            for read in &results {
                let Some(applied) = &read.applied else {
                    continue;
                };
                let Some(record) = record_key(&read.result.id) else {
                    continue;
                };
                save_held(store, &sender, &record, &applied.held)?;
                let schema = decoded_schema(readers, file, applied.held.type_name.as_deref());
                index(store, &sender, &record, applied.value.as_ref(), schema)?;
                if matches!(
                    applied.outcome,
                    Outcome::Applied | Outcome::Merged | Outcome::Withdrawn
                ) {
                    on_record(
                        store,
                        RecordChange {
                            sender: sender.clone(),
                            id: ids.get(&record).cloned().unwrap_or(record),
                            type_name: applied.held.type_name.clone(),
                            value: applied.value.clone(),
                            outcome: applied.outcome,
                        },
                    )?;
                }
            }
            Ok(FileResult {
                accepted: true,
                records: results.into_iter().map(|read| read.result).collect(),
            })
        })
    }

    /// Writes an AXT file of `shared`, the app's records shared with `receiver` now, the
    /// key of an app of another user; or, with `receiver` `None`, an export of the
    /// records its user chose. The file is deflated.
    ///
    /// For a receiver, the file also holds the `WITHDRAW` of every record that was sent
    /// to it before and is no longer shared with it (`spec/shares.md`, sections 5.3 and
    /// 8.2). A record goes without its links (`spec/shares.md`, section 19.1) unless it is
    /// [`OutgoingRecord::with_links`], or `own_user` says that the receiver is an app of
    /// the app's own user, which gets every record whole.
    ///
    /// The version of a record is a state stamp (`spec/sync.md`, section 2.2), kept in the
    /// store, that rises when the record's content changes.
    ///
    /// # Errors
    ///
    /// `RECORD_ID_INVALID` for an id that is no UUID, `VALUE_INVALID` for a value that is
    /// no datum of its type, `MANIFEST_INVALID` for a manifest content that is no
    /// `axt.Manifest`, `VERSION_INVALID` when no state stamp is left, and
    /// [`Error::Store`] when the store fails, holds no AXT state the library can read, or
    /// the system gives no random bytes; the transaction is then rolled back.
    pub fn write_file(
        &mut self,
        shared: &[OutgoingRecord<'_>],
        receiver: Option<&[u8; 32]>,
        own_user: bool,
    ) -> Result<Vec<u8>, Error> {
        let Self {
            store,
            signing_seed,
            public_key,
            manifest,
            clock,
            ..
        } = self;
        let signer = Signer {
            seed: signing_seed,
            public_key: *public_key,
        };
        let now = || now_ms(clock());
        store.transaction(|store| {
            write_file(store, &signer, manifest, &now, shared, receiver, own_user)
        })
    }

    /// The app's own Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The app's store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The app's store, for the app's own writes beside the library's.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// The record that a relation of a record of `holder_sender` points at, with `target`
    /// the relation's `target` as the record's value holds it; `None` while it does not
    /// resolve (`spec/records.md`, section 10.2): for a target outside AXT, a key of no
    /// known sender or a refused one, or a record the app does not hold or holds as a
    /// tombstone.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] when the store fails or holds no AXT state the library can read.
    pub fn resolve(
        &self,
        holder_sender: &str,
        target: &Value,
    ) -> Result<Option<RecordAddress>, Error> {
        let target = match target {
            Value::Union { value, .. } => value,
            other => other,
        };
        let Some(Value::String(id)) = target.field("id") else {
            return Ok(None);
        };
        let Ok(sender) = target_sender(target) else {
            return Ok(None);
        };
        let (receiver, own, _) = load_resolver(&self.store, &self.public_key)?;
        let resolver = RelationResolver {
            receiver: &receiver,
            own: &own,
        };
        let resolution = resolver.resolve(&HeldRelation {
            id: String::new(),
            holder_sender: holder_sender.to_owned(),
            holder_id: String::new(),
            target_sender: sender,
            target_id: id.clone(),
        });
        Ok(
            match (resolution.sender, resolution.resolved, record_key(id)) {
                (Some(sender), true, Some(id)) => Some(RecordAddress { sender, id }),
                _ => None,
            },
        )
    }

    /// The relations of the records the app holds, of every sender and its own, that
    /// resolve to the record `id` of `sender` (`spec/records.md`, section 10.1), sorted
    /// by holder and relation.
    ///
    /// # Errors
    ///
    /// `RECORD_ID_INVALID` for an id that is no UUID; [`Error::Store`] when the store
    /// fails or holds no AXT state the library can read.
    pub fn linked_from(&self, sender: &str, id: &str) -> Result<Vec<Link>, Error> {
        let key = checked_record_key(id)?;
        let (receiver, own, held) = load_resolver(&self.store, &self.public_key)?;
        let resolver = RelationResolver {
            receiver: &receiver,
            own: &own,
        };
        let name = receiver.sender_named(sender);
        Ok(resolver
            .linked_from(&held)
            .into_iter()
            .filter(|linked| linked.sender == name && linked.id == key)
            .flat_map(|linked| linked.from)
            .map(|from| Link {
                holder: RecordAddress {
                    sender: from.sender,
                    id: from.id,
                },
                relation: from.relation,
            })
            .collect())
    }
}

/// A store that holds a value the library cannot read at `key`.
fn unreadable(key: &str) -> Error {
    Error::Store(format!("the store holds no AXT state the library reads at {key}").into())
}

/// The JSON at `key`, or `None`.
fn read_json<S: Store>(store: &S, key: &str) -> Result<Option<Json>, Error> {
    match store.read(key).map_err(Error::store)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| unreadable(key)),
    }
}

/// Every key that begins with `prefix`, with its JSON.
fn list_json<S: Store>(store: &S, prefix: &str) -> Result<Vec<(String, Json)>, Error> {
    let mut out = Vec::new();
    for key in store.list(prefix).map_err(Error::store)? {
        if let Some(json) = read_json(store, &key)? {
            out.push((key, json));
        }
    }
    Ok(out)
}

/// Sets `key` to `json`.
fn write_json<S: Store>(store: &mut S, key: &str, json: &Json) -> Result<(), Error> {
    store
        .write(key, json.to_string().as_bytes())
        .map_err(Error::store)
}

/// The bytes of hexadecimal digits.
fn key_bytes_of_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    let (pairs, rest) = digits.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair.as_slice())
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

/// A key in hexadecimal digits.
fn key_of_hex(text: &str) -> Option<Key> {
    key_bytes_of_hex(text)?.as_slice().try_into().ok()
}

fn keys_of(json: &Json, member: &str, at: &str) -> Result<std::collections::BTreeSet<Key>, Error> {
    json.get(member)
        .and_then(Json::as_array)
        .ok_or_else(|| unreadable(at))?
        .iter()
        .map(|k| {
            k.as_str()
                .and_then(key_of_hex)
                .ok_or_else(|| unreadable(at))
        })
        .collect()
}

/// The receiver's known senders and their joins, from the store (`sender/<name>` and
/// `joined`).
fn load_receiver<S: Store>(store: &S) -> Result<DeviceSetReceiver, Error> {
    let mut receiver = DeviceSetReceiver::default();
    for (key, json) in list_json(store, "sender/")? {
        let name = json
            .get("name")
            .and_then(Json::as_str)
            .ok_or_else(|| unreadable(&key))?;
        receiver.senders.push(KnownSender {
            name: name.to_owned(),
            current: keys_of(&json, "current", &key)?,
            removed: keys_of(&json, "removed", &key)?,
            records: BTreeMap::new(),
        });
    }
    if let Some(joined) = read_json(store, "joined")? {
        let joined = joined.as_object().ok_or_else(|| unreadable("joined"))?;
        for (name, stays) in joined {
            let stays = stays.as_str().ok_or_else(|| unreadable("joined"))?;
            receiver.joined_into.insert(name.clone(), stays.to_owned());
        }
    }
    Ok(receiver)
}

/// Saves the receiver's known senders and their joins.
fn save_senders<S: Store>(store: &mut S, receiver: &DeviceSetReceiver) -> Result<(), Error> {
    write_json(store, "joined", &json!(receiver.joined_into))?;
    for key in store.list("sender/").map_err(Error::store)? {
        store.delete(&key).map_err(Error::store)?;
    }
    let hexes =
        |keys: &std::collections::BTreeSet<Key>| keys.iter().map(|k| hex(k)).collect::<Vec<_>>();
    for sender in &receiver.senders {
        write_json(
            store,
            &format!("sender/{}", sender.name),
            &json!({
                "name": sender.name,
                "current": hexes(&sender.current),
                "removed": hexes(&sender.removed),
            }),
        )?;
    }
    Ok(())
}

/// Saves what the receiver holds of the record `id` (a record key) of `sender`, at
/// `record/<sender>/<id>`: its version, its state, its type and the value it last took,
/// in the lossless form of [`Value::to_stored`] as hexadecimal text.
fn save_held<S: Store>(
    store: &mut S,
    sender: &str,
    id: &str,
    held: &HeldRecord,
) -> Result<(), Error> {
    write_json(
        store,
        &format!("record/{sender}/{id}"),
        &json!({
            "version": held.version,
            "state": held.state.code(),
            "type": held.type_name,
            "taken": held.taken.as_ref().map(|taken| hex(&taken.to_stored())),
        }),
    )
}

/// What the receiver holds of the record `id` (a record key) of `sender`, or `None`.
fn load_held<S: Store>(store: &S, sender: &str, id: &str) -> Result<Option<HeldRecord>, Error> {
    let key = format!("record/{sender}/{id}");
    let Some(json) = read_json(store, &key)? else {
        return Ok(None);
    };
    let version = json
        .get("version")
        .and_then(Json::as_i64)
        .ok_or_else(|| unreadable(&key))?;
    let state = json
        .get("state")
        .and_then(Json::as_str)
        .and_then(HeldState::from_code)
        .ok_or_else(|| unreadable(&key))?;
    let type_name = match json.get("type") {
        None | Some(Json::Null) => None,
        Some(Json::String(name)) => Some(name.clone()),
        Some(_) => return Err(unreadable(&key)),
    };
    let taken = match json.get("taken") {
        None | Some(Json::Null) => None,
        Some(taken) => Some(
            taken
                .as_str()
                .and_then(key_bytes_of_hex)
                .and_then(|bytes| Value::from_stored(&bytes))
                .ok_or_else(|| unreadable(&key))?,
        ),
    };
    Ok(Some(HeldRecord {
        version,
        state,
        type_name,
        taken,
        kept_against: None,
    }))
}

/// Keeps the relations with a record target of the record `id` (a record key) of
/// `sender`, whose `value` has `schema`, at `relations/<sender>/<id>`; none for a record
/// that is gone. A record that stays, read with no schema here, keeps what is kept.
fn index<S: Store>(
    store: &mut S,
    sender: &str,
    id: &str,
    value: Option<&Value>,
    schema: Option<&Schema>,
) -> Result<(), Error> {
    let key = format!("relations/{sender}/{id}");
    let relations = match (value, schema) {
        (None, _) => Vec::new(),
        (Some(_), None) => return Ok(()),
        (Some(value), Some(schema)) => crate::relation_index::record_targets(schema, value),
    };
    if relations.is_empty() {
        return store.delete(&key).map_err(Error::store);
    }
    let relations: Vec<Json> = relations
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "sender": r.sender.map(|k| hex(&k)),
                "target": r.target,
            })
        })
        .collect();
    write_json(store, &key, &Json::Array(relations))
}

/// The schema a received record of the type `type_name` was decoded with: the reader's,
/// or the writer's in `file`.
fn decoded_schema<'a>(
    readers: &'a BTreeMap<String, TypeDescription>,
    file: &'a CheckedFile,
    type_name: Option<&str>,
) -> Option<&'a Schema> {
    let type_name = type_name?;
    if let Some(reader) = readers.get(type_name) {
        return Some(reader.schema());
    }
    file.schemas
        .values()
        .find(|writer| writer.name() == type_name)
        .map(TypeDescription::schema)
}

/// The app's manifest content with `revision`.
fn manifest_with_revision(manifest: &Value, revision: i64) -> Value {
    let mut fields = vec![("revision".to_owned(), Value::Long(revision))];
    if let Value::Record(given) = manifest {
        fields.extend(given.iter().filter(|(name, _)| name != "revision").cloned());
    }
    Value::Record(fields)
}

/// The SHA-256 of `value` in one form, whatever the order of its fields, after `prefix`.
fn digest_of(prefix: &[u8], value: &Value) -> String {
    hex(&Sha256::new()
        .chain_update(prefix)
        .chain_update(value.sorted().to_stored())
        .finalize())
}

/// `N` random bytes of the system.
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::store(std::io::Error::other(format!("no random bytes: {e}"))))?;
    Ok(bytes)
}

/// The milliseconds since the Unix epoch of `time`, negative before it.
fn now_ms(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_millis()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_millis())
            .unwrap_or(i64::MAX)
            .wrapping_neg(),
    }
}

/// The next state stamp after `highest` (`spec/sync.md`, section 2.2), with the clock
/// `now_ms` and `random`, below 32768; `None` when no stamp is left.
pub(crate) fn next_stamp(highest: i64, now_ms: i64, random: u16) -> Option<i64> {
    let clock = i128::from(now_ms).checked_mul(65536)?;
    let base = clock.max(i128::from(highest).checked_add(1)?);
    if base.checked_add(32767)? > i128::from(i64::MAX) {
        return None;
    }
    i64::try_from(base.checked_add(i128::from(random & 0x7fff))?).ok()
}

/// A new state stamp above the highest the store keeps, which it then keeps.
fn stamp<S: Store>(store: &mut S, now: &dyn Fn() -> i64) -> Result<i64, Error> {
    let highest = match read_json(store, "stamp")? {
        None => 0,
        Some(json) => json.as_i64().ok_or_else(|| unreadable("stamp"))?,
    };
    let random = u16::from_le_bytes(random::<2>()?);
    let stamp = next_stamp(highest, now(), random)
        .ok_or_else(|| Error::axt(ErrorCode::VersionInvalid, "no state stamp is left"))?;
    write_json(store, "stamp", &json!(stamp))?;
    Ok(stamp)
}

/// Keeps the `version` and the content `digest` of the app's own record `id`.
fn save_own<S: Store>(store: &mut S, id: &str, version: i64, digest: &str) -> Result<(), Error> {
    write_json(
        store,
        &format!("own/{id}"),
        &json!({"version": version, "digest": digest}),
    )
}

/// The version of the app's own record `id` with the content `digest`: the version it
/// has, or a new state stamp when the content changed.
fn version_of<S: Store>(
    store: &mut S,
    now: &dyn Fn() -> i64,
    id: &str,
    digest: &str,
) -> Result<i64, Error> {
    let key = format!("own/{id}");
    if let Some(json) = read_json(store, &key)?
        && json.get("digest").and_then(Json::as_str) == Some(digest)
    {
        return json
            .get("version")
            .and_then(Json::as_i64)
            .ok_or_else(|| unreadable(&key));
    }
    let version = stamp(store, now)?;
    save_own(store, id, version, digest)?;
    Ok(version)
}

/// The app's own key, to sign with.
struct Signer<'a> {
    seed: &'a SigningSeed,
    public_key: Key,
}

impl Signer<'_> {
    /// The datum of a message of `kind` of the app, signed: the envelope without the
    /// marker and the fingerprint of a live message.
    fn datum(
        &self,
        kind: Kind,
        record: Option<RecordRef>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let mut message = encode_message(&Envelope {
            kind,
            sender: self.public_key,
            record,
            body,
            signature: [0; 64],
        })?;
        let signed = signed_bytes_of_live_message(&message)
            .ok_or_else(|| Error::axt(ErrorCode::InvalidMessage, "a message too short"))?;
        let signature = sign(self.seed, &signed);
        if let Some((_, last)) = message.split_last_chunk_mut::<64>() {
            *last = signature;
        }
        Ok(message.get(10..).map(<[u8]>::to_vec).unwrap_or_default())
    }
}

/// The app's manifest with its revision, raised when the content changed since the
/// revision it last sent (`spec/manifest.md`, section 3.8).
fn revised_manifest<S: Store>(store: &mut S, manifest: &Value) -> Result<Value, Error> {
    let digest = digest_of(b"", manifest);
    let mut revision = 1;
    if let Some(json) = read_json(store, "manifest")? {
        revision = json
            .get("revision")
            .and_then(Json::as_i64)
            .ok_or_else(|| unreadable("manifest"))?;
        if json.get("digest").and_then(Json::as_str) != Some(digest.as_str()) {
            revision = revision.saturating_add(1);
        }
    }
    write_json(
        store,
        "manifest",
        &json!({"revision": revision, "digest": digest}),
    )?;
    Ok(manifest_with_revision(manifest, revision))
}

/// The body of `value`, a datum of the specification's schema `name`.
fn axt_body(name: &str, value: &Value, code: ErrorCode) -> Result<Vec<u8>, Error> {
    axt_schema(name)
        .ok_or_else(|| Error::axt(code, format!("the schema {name} is missing")))?
        .encode_single_object(value)
        .map_err(|e| Error::axt(code, e))
}

/// Writes the file of [`AxtNode::write_file`] in the transaction on `store`.
fn write_file<S: Store>(
    store: &mut S,
    signer: &Signer<'_>,
    manifest: &Value,
    now: &dyn Fn() -> i64,
    shared: &[OutgoingRecord<'_>],
    receiver: Option<&Key>,
    own_user: bool,
) -> Result<Vec<u8>, Error> {
    let own_name = hex(&signer.public_key);
    let shared_ids: HashSet<String> = shared
        .iter()
        .filter(|r| r.record.is_some())
        .map(|r| r.id.clone())
        .collect();
    let own_keys = BTreeSet::from([signer.public_key]);
    let mut datums = Vec::new();
    let mut types: Vec<&TypeDescription> = Vec::new();
    let body = axt_body(
        "axt.Manifest",
        &revised_manifest(store, manifest)?,
        ErrorCode::ManifestInvalid,
    )?;
    datums.push(signer.datum(Kind::Manifest, None, body)?);
    let to = receiver.map(|k| hex(k));
    let mut ids = HashSet::new();
    for record in shared {
        let id = checked_record_key(&record.id)?;
        ids.insert(id.clone());
        let (kind, body, digest) = match &record.record {
            None => (Kind::Delete, Vec::new(), hex(&Sha256::digest([]))),
            Some((type_description, value)) => {
                if types
                    .iter()
                    .all(|t| t.fingerprint() != type_description.fingerprint())
                {
                    types.push(type_description);
                }
                let schema = type_description.schema();
                let invalid = |e: String| Error::axt(ErrorCode::ValueInvalid, e);
                // The version follows the record whole, whatever goes along.
                let digest = digest_of(&type_description.fingerprint().0, value);
                // The whole record is encoded in every case, so that a value that is no
                // datum of its type fails, whatever goes along.
                let whole = schema.encode_single_object(value).map_err(invalid)?;
                let body = if record.with_links || own_user {
                    whole
                } else {
                    let without =
                        without_links(schema, value, &shared_ids, &own_keys).map_err(invalid)?;
                    schema.encode_single_object(&without).map_err(invalid)?
                };
                (Kind::Data, body, digest)
            }
        };
        let (value, schema) = match &record.record {
            Some((t, value)) => (Some(value), Some(t.schema())),
            None => (None, None),
        };
        index(store, &own_name, &id, value, schema)?;
        let mut version = version_of(store, now, &id, &digest)?;
        if let Some(to) = &to {
            let withdrawal = read_json(store, &format!("withdrawal/{to}/{id}"))?;
            if withdrawal
                .and_then(|w| w.as_i64())
                .is_some_and(|w| w >= version)
            {
                // Shared again: a version above the withdrawal (shares.md, section 6.2).
                version = stamp(store, now)?;
                save_own(store, &id, version, &digest)?;
            }
        }
        datums.push(signer.datum(
            kind,
            Some(RecordRef {
                id: record.id.clone(),
                version,
            }),
            body,
        )?);
        if let Some(to) = &to {
            // Sending the record again supersedes its last withdrawal.
            store
                .delete(&format!("withdrawal/{to}/{id}"))
                .map_err(Error::store)?;
            write_json(
                store,
                &format!("sent/{to}/{id}"),
                &json!({"kind": kind.symbol(), "id": record.id}),
            )?;
        }
    }
    if let (Some(to), Some(receiver)) = (&to, receiver) {
        let prefix = format!("sent/{to}/");
        for (key, sent) in list_json(store, &prefix)? {
            let id = key.strip_prefix(&prefix).unwrap_or_default().to_owned();
            if ids.contains(&id) {
                continue;
            }
            let sent_id = sent
                .get("id")
                .and_then(Json::as_str)
                .ok_or_else(|| unreadable(&key))?
                .to_owned();
            let withdrawal_key = format!("withdrawal/{to}/{id}");
            let withdrawal = read_json(store, &withdrawal_key)?;
            let version = if sent.get("kind").and_then(Json::as_str) == Some("DATA") {
                let version = stamp(store, now)?;
                write_json(store, &withdrawal_key, &json!(version))?;
                version
            } else if let Some(withdrawal) = withdrawal {
                withdrawal
                    .as_i64()
                    .ok_or_else(|| unreadable(&withdrawal_key))?
            } else {
                continue;
            };
            let body = axt_body(
                "axt.Withdraw",
                &Value::Record(vec![("to".into(), Value::Fixed(receiver.to_vec()))]),
                ErrorCode::InvalidMessage,
            )?;
            datums.push(signer.datum(
                Kind::Withdraw,
                Some(RecordRef {
                    id: sent_id.clone(),
                    version,
                }),
                body,
            )?);
            write_json(store, &key, &json!({"kind": "WITHDRAW", "id": sent_id}))?;
        }
    }
    signed_file(signer, &types, &datums)
}

/// The deflated file of `datums`, signed messages of `signer`, with the writer `types`
/// of its `DATA` in `axt.schemas`.
fn signed_file(
    signer: &Signer<'_>,
    types: &[&TypeDescription],
    datums: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let schemas_text = (!types.is_empty())
        .then(|| {
            let entries = types
                .iter()
                .map(|t| {
                    let schema: Json = serde_json::from_str(t.schema_text())
                        .map_err(|e| Error::axt(ErrorCode::DescriptionInvalid, e.to_string()))?;
                    Ok(json!({"description": t.to_json(), "schema": schema}))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok::<_, Error>(Json::Array(entries).to_string().into_bytes())
        })
        .transpose()?;
    let signature = sign(
        signer.seed,
        &file_header_signed_bytes(&signer.public_key, schemas_text.as_deref()),
    );
    let mut metadata: Vec<(&str, Vec<u8>)> = vec![(
        "avro.schema",
        axt_schema_text("axt.Envelope")
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
    )];
    if let Some(text) = schemas_text {
        metadata.push(("axt.schemas", text));
    }
    metadata.push(("axt.sender", hex(&signer.public_key).into_bytes()));
    metadata.push(("axt.signature", hex(&signature).into_bytes()));
    Ok(write_container(&metadata, datums, random::<16>()?, true))
}

/// The version and the state of a record from its JSON in the store.
fn kept_record(json: &Json, at: &str) -> Result<KeptRecord, Error> {
    let version = json
        .get("version")
        .and_then(Json::as_i64)
        .ok_or_else(|| unreadable(at))?;
    Ok(KeptRecord {
        version,
        state: if json.get("state").and_then(Json::as_str) == Some(HeldState::There.code()) {
            RecordState::There
        } else {
            RecordState::Tombstone
        },
    })
}

/// What resolving relations needs, from the store: the known senders with the records
/// held of them, the app's own set with its own records (`own/<id>`), named by its key as
/// hexadecimal text, and the relations the app holds.
fn load_resolver<S: Store>(
    store: &S,
    public_key: &Key,
) -> Result<(DeviceSetReceiver, KnownSender, Vec<HeldRelation>), Error> {
    let mut receiver = load_receiver(store)?;
    let own_name = hex(public_key);
    let mut own = KnownSender {
        name: own_name,
        current: std::collections::BTreeSet::from([*public_key]),
        ..KnownSender::default()
    };
    // An own record sent as a DELETE has the empty body.
    let deleted = hex(&Sha256::digest([]));
    for (key, json) in list_json(store, "own/")? {
        let id = key.strip_prefix("own/").unwrap_or_default();
        let version = json
            .get("version")
            .and_then(Json::as_i64)
            .ok_or_else(|| unreadable(&key))?;
        let state = if json.get("digest").and_then(Json::as_str) == Some(deleted.as_str()) {
            RecordState::Tombstone
        } else {
            RecordState::There
        };
        own.records
            .insert(id.to_owned(), KeptRecord { version, state });
    }
    for (key, json) in list_json(store, "record/")? {
        let Some((sender, id)) = key
            .strip_prefix("record/")
            .and_then(|rest| rest.rsplit_once('/'))
        else {
            continue;
        };
        let kept = kept_record(&json, &key)?;
        let name = receiver.sender_named(sender).to_owned();
        let Some(sender) = receiver.senders.iter_mut().find(|s| s.name == name) else {
            continue;
        };
        if sender
            .records
            .get(id)
            .is_none_or(|held| held.version < kept.version)
        {
            sender.records.insert(id.to_owned(), kept);
        }
    }
    let mut held = Vec::new();
    for (key, json) in list_json(store, "relations/")? {
        let Some((holder, holder_id)) = key
            .strip_prefix("relations/")
            .and_then(|rest| rest.rsplit_once('/'))
        else {
            continue;
        };
        for relation in json.as_array().ok_or_else(|| unreadable(&key))? {
            let text = |member: &str| {
                relation
                    .get(member)
                    .and_then(Json::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| unreadable(&key))
            };
            let target_sender = match relation.get("sender") {
                None | Some(Json::Null) => None,
                Some(sender) => Some(
                    sender
                        .as_str()
                        .and_then(key_of_hex)
                        .ok_or_else(|| unreadable(&key))?,
                ),
            };
            held.push(HeldRelation {
                id: text("id")?,
                holder_sender: holder.to_owned(),
                holder_id: holder_id.to_owned(),
                target_sender,
                target_id: text("target")?,
            });
        }
    }
    Ok((receiver, own, held))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::device_sets::fixtures::TestKey;
    use crate::error::ErrorCode;
    use crate::records::set_field;
    use crate::schemas::axt_schema_text;

    /// A store in memory whose transactions roll back on an error.
    #[derive(Debug, Default)]
    pub(crate) struct MemoryStore {
        pub(crate) data: BTreeMap<String, Vec<u8>>,
    }

    impl Store for MemoryStore {
        type Error = std::convert::Infallible;

        fn read(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.data.get(key).cloned())
        }

        fn write(&mut self, key: &str, value: &[u8]) -> Result<(), Self::Error> {
            self.data.insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &str) -> Result<(), Self::Error> {
            self.data.remove(key);
            Ok(())
        }

        fn list(&self, prefix: &str) -> Result<Vec<String>, Self::Error> {
            Ok(self
                .data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }

        fn transaction<T>(
            &mut self,
            body: impl FnOnce(&mut Self) -> Result<T, Error>,
        ) -> Result<T, Error> {
            let before = self.data.clone();
            let result = body(self);
            if result.is_err() {
                self.data = before;
            }
            result
        }
    }

    const R1: &str = "00000001-4e1a-4b0e-9c22-000000000001";
    const R2: &str = "00000002-4e1a-4b0e-9c22-000000000002";
    const R3: &str = "00000003-4e1a-4b0e-9c22-000000000003";
    const T1: &str = "00000001-5e55-4d0e-8a11-000000000001";
    const T2: &str = "00000002-5e55-4d0e-8a11-000000000002";
    const T3: &str = "00000003-5e55-4d0e-8a11-000000000003";

    fn node() -> AxtNode<MemoryStore> {
        AxtNode::open(
            MemoryStore::default(),
            TestKey::named("node a").seed,
            EncryptionSeed::new([3; 32]),
            NodeConfig::new(manifest("A", &[])),
        )
    }

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::Record(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect())
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn target(id: &str, sender: Option<Key>) -> Value {
        Value::Union {
            index: 0,
            branch: "axt.RelationRecordTarget".into(),
            value: Box::new(record(vec![
                ("id", s(id)),
                (
                    "sender",
                    sender.map_or(Value::Null, |k| Value::Fixed(k.to_vec())),
                ),
                ("type", s("")),
                ("text", s("")),
            ])),
        }
    }

    fn holder(links: Vec<(&str, Value)>) -> Value {
        record(vec![(
            "links",
            Value::Array(
                links
                    .into_iter()
                    .map(|(id, target)| {
                        record(vec![
                            ("id", s(id)),
                            ("kind", s("axt.related")),
                            ("target", target),
                            ("note", s("")),
                            ("start", Value::Null),
                            ("end", Value::Null),
                            ("attributes", Value::Map(BTreeMap::new())),
                        ])
                    })
                    .collect(),
            ),
        )])
    }

    fn holder_schema() -> Schema {
        Schema::parse(&format!(
            r#"{{"type":"record","name":"Holder","namespace":"org.example","fields":[
            {{"name":"links","type":{{"type":"array","items":{}}}}}]}}"#,
            axt_schema_text("axt.Relation").unwrap()
        ))
        .unwrap()
    }

    fn there(version: i64) -> HeldRecord {
        HeldRecord {
            version,
            state: HeldState::There,
            type_name: Some("org.example.Holder".into()),
            taken: None,
            kept_against: None,
        }
    }

    #[test]
    fn record_ids_are_uuids_of_version_7() {
        let id = record_id_at(1_795_219_200_000, [0xff; 10]);
        assert_eq!(id, "01a1fb67-1800-7fff-bfff-ffffffffffff");
        assert_eq!(record_key(&id).as_deref(), Some(id.as_str()));
        let id = new_record_id().unwrap();
        let bytes = id.as_bytes();
        assert_eq!(bytes.len(), 36);
        assert_eq!(bytes[14], b'7');
        assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(id, new_record_id().unwrap());
    }

    #[test]
    fn an_empty_store_resolves_nothing() {
        let node = node();
        assert_eq!(node.public_key(), TestKey::named("node a").public);
        assert_eq!(node.resolve("s", &target(T1, None)).unwrap(), None);
        assert_eq!(node.linked_from("s", T1).unwrap(), []);
        assert_eq!(
            node.linked_from("s", "no uuid").unwrap_err().code(),
            Some(ErrorCode::RecordIdInvalid)
        );
        let outside = record(vec![("uri", s("https://example.org")), ("text", s(""))]);
        assert_eq!(node.resolve("s", &outside).unwrap(), None);
    }

    #[test]
    fn relations_resolve_across_senders_joins_and_the_own_set() {
        let (a, b, c) = (
            TestKey::named("sender a").public,
            TestKey::named("sender b").public,
            TestKey::named("sender c").public,
        );
        let mut node = node();
        let own = hex(&node.public_key());
        let schema = holder_schema();
        let mut receiver = DeviceSetReceiver::default();
        for (name, key) in [("s", a), ("t", b), ("u", c)] {
            receiver.senders.push(KnownSender {
                name: name.into(),
                current: BTreeSet::from([key]),
                ..KnownSender::default()
            });
        }
        // u joined s: u's records and relations are now s's.
        receiver.joined_into.insert("u".into(), "s".into());
        receiver.senders.retain(|s| s.name != "u");
        if let Some(s) = receiver.senders.iter_mut().find(|s| s.name == "s") {
            s.current.insert(c);
        }
        let store = node.store_mut();
        save_senders(store, &receiver).unwrap();
        save_held(store, "s", T1, &there(1)).unwrap();
        let mut gone = there(2);
        gone.state = HeldState::Tombstone;
        save_held(store, "s", T2, &gone).unwrap();
        save_held(store, "t", T3, &there(1)).unwrap();
        // The holder on t points at s's T1 by the key of u, at s's tombstone T2, and at
        // the app's own record T3.
        index(
            store,
            "t",
            T3,
            Some(&holder(vec![
                (R1, target(T1, Some(c))),
                (R2, target(T2, Some(a))),
                (R3, target(T3, Some(node_key()))),
            ])),
            Some(&schema),
        )
        .unwrap();
        write_json(
            store,
            &format!("own/{T3}"),
            &json!({"version": 5, "digest": "00"}),
        )
        .unwrap();
        // The app's own record links to u's T1, by no sender: the holder's own.
        index(
            store,
            &own,
            T1,
            Some(&holder(vec![(R1, target(T1, None))])),
            Some(&schema),
        )
        .unwrap();
        save_held(store, "u", T1, &there(3)).unwrap();

        assert_eq!(
            node.resolve("t", &target(T1, Some(c))).unwrap(),
            Some(RecordAddress {
                sender: "s".into(),
                id: T1.into()
            })
        );
        assert_eq!(node.resolve("t", &target(T2, Some(a))).unwrap(), None);
        assert_eq!(
            node.resolve("u", &target(&T1.to_uppercase(), None))
                .unwrap()
                .map(|a| a.to_string()),
            Some(format!("s/{T1}"))
        );
        assert_eq!(
            node.linked_from("u", T1).unwrap(),
            [Link {
                holder: RecordAddress {
                    sender: "t".into(),
                    id: T3.into()
                },
                relation: R1.into(),
            }]
        );
        assert_eq!(
            node.linked_from(&own, T3).unwrap(),
            [Link {
                holder: RecordAddress {
                    sender: "t".into(),
                    id: T3.into()
                },
                relation: R3.into(),
            }]
        );
        // The own record's relation to T1 resolves to its own set, which has no T1.
        assert_eq!(node.resolve(&own, &target(T1, None)).unwrap(), None);

        // A record that is gone keeps no relations.
        index(node.store_mut(), "t", T3, None, Some(&schema)).unwrap();
        assert_eq!(node.linked_from("s", T1).unwrap(), []);
    }

    fn node_key() -> Key {
        TestKey::named("node a").public
    }

    #[test]
    fn a_store_that_holds_no_axt_state_fails() {
        let mut node = node();
        node.store_mut()
            .data
            .insert("sender/x".into(), b"not json".to_vec());
        assert!(matches!(
            node.resolve("s", &target(T1, None)),
            Err(Error::Store(_))
        ));
    }

    #[test]
    fn a_failed_transaction_rolls_the_store_back() {
        let mut store = MemoryStore::default();
        let result: Result<(), Error> = store.transaction(|store| {
            write_json(store, "stamp", &json!(1))?;
            Err(Error::axt(ErrorCode::FileRejected, "no"))
        });
        assert!(result.is_err());
        assert!(store.data.is_empty());
        store
            .transaction(|store| write_json(store, "stamp", &json!(1)))
            .unwrap();
        assert_eq!(store.data.len(), 1);
    }

    // The tests of `node_test.dart`.

    use std::cell::RefCell;

    use crate::device_sets::fixtures::signed_message;

    fn text_field(name: &str) -> Json {
        json!({"name": name, "doc": format!("The {name}."), "texts": {}, "required": true,
               "kind": {"axt.StringField": {}}})
    }

    fn object_type(name: &str, fields: Vec<Json>) -> TypeDescription {
        TypeDescription::from_json(&json!({
            "name": "t", "doc": "A type.", "texts": {},
            "kind": {"axt.ObjectField": {"name": name, "version": 1, "fields": fields}},
        }))
        .unwrap()
    }

    /// org.example.Memo, of two required texts.
    fn memo() -> TypeDescription {
        object_type(
            "org.example.Memo",
            vec![text_field("text"), text_field("note")],
        )
    }

    /// org.example.Blob, of required bytes.
    fn blob() -> TypeDescription {
        object_type(
            "org.example.Blob",
            vec![
                json!({"name": "data", "doc": "The data.", "texts": {}, "required": true,
                        "kind": {"axt.BytesField": {}}}),
            ],
        )
    }

    /// org.example.Note, a text with relations.
    fn note() -> TypeDescription {
        object_type(
            "org.example.Note",
            vec![
                text_field("text"),
                json!({"name": "links", "doc": "The links.", "texts": {},
                       "kind": {"axt.RelationField": {}}}),
            ],
        )
    }

    fn take(type_name: &str) -> Value {
        record(vec![
            ("type", s(type_name)),
            ("min_version", Value::Int(1)),
            ("max_version", Value::Null),
            ("purpose", s("A record becomes a note.")),
            ("purpose_translations", Value::Map(BTreeMap::new())),
        ])
    }

    /// A manifest content of `name` that takes `types`.
    fn manifest(name: &str, types: &[&str]) -> Value {
        record(vec![
            ("app_name", s(name)),
            ("app_url", Value::Null),
            ("formats", Value::Array(vec![Value::Int(1)])),
            (
                "takes",
                Value::Array(types.iter().map(|t| take(t)).collect()),
            ),
            ("any_type", Value::Null),
            ("sends", Value::Null),
            ("encryption_key", Value::Null),
            ("relay", Value::Null),
        ])
    }

    fn open(key: &str, manifest: Value, readers: Vec<TypeDescription>) -> AxtNode<MemoryStore> {
        let mut config = NodeConfig::new(manifest);
        config.readers = readers;
        AxtNode::open(
            MemoryStore::default(),
            TestKey::named(key).seed,
            EncryptionSeed::new([3; 32]),
            config,
        )
    }

    fn memo_value(text: &str, note: &str) -> Value {
        record(vec![("text", s(text)), ("note", s(note))])
    }

    /// What the app holds of received records, by id.
    type Held = RefCell<BTreeMap<String, Option<Value>>>;

    fn read(node: &mut AxtNode<MemoryStore>, file: &[u8], accept: bool, held: &Held) -> FileResult {
        let preview = node.inspect(file).unwrap();
        read_preview(node, &preview, accept, held).unwrap()
    }

    fn read_preview(
        node: &mut AxtNode<MemoryStore>,
        preview: &FilePreview,
        accept: bool,
        held: &Held,
    ) -> Result<FileResult, Error> {
        node.apply(
            preview,
            accept,
            |_, change| {
                held.borrow_mut().insert(change.id, change.value);
                Ok(())
            },
            |_, _, id| Ok(held.borrow().get(id).cloned().flatten()),
        )
    }

    fn results(result: &FileResult) -> Vec<&'static str> {
        result.records.iter().map(|r| r.result.as_str()).collect()
    }

    #[test]
    fn two_apps_exchange_records_through_files() {
        let memo = memo();
        let mut sender = open("node a", manifest("Sender", &["org.example.Memo"]), vec![]);
        let mut reader = open(
            "node b",
            manifest("Reader", &["org.example.Memo"]),
            vec![memo.clone()],
        );
        let b = TestKey::named("node b").public;
        assert_eq!(sender.short_fingerprint_of_own_key().len(), 29);
        let id = new_record_id().unwrap();
        let held = Held::default();
        let mut write = |records: Vec<OutgoingRecord<'_>>| {
            sender.write_file(&records, Some(&b), false).unwrap()
        };

        let file = write(vec![OutgoingRecord::new(&id, &memo, memo_value("vet", ""))]);
        let preview = reader.inspect(&file).unwrap();
        assert!(preview.first_contact);
        assert!(!preview.sender_removed);
        assert_eq!(preview.app_name.as_deref(), Some("Sender"));
        assert_eq!(preview.sender, hex(&TestKey::named("node a").public));
        assert_eq!(
            preview.fitting,
            BTreeMap::from([("org.example.Memo".to_owned(), 1)])
        );
        assert!(!read(&mut reader, &file, false, &held).accepted);
        assert!(held.borrow().is_empty());
        assert_eq!(results(&read(&mut reader, &file, true, &held)), ["APPLIED"]);
        assert_eq!(held.borrow()[&id], Some(memo_value("vet", "")));
        assert!(!reader.inspect(&file).unwrap().first_contact);
        assert_eq!(
            results(&read(&mut reader, &file, true, &held)),
            ["DUPLICATE"]
        );

        held.borrow_mut()
            .insert(id.clone(), Some(memo_value("vet", "mine")));
        let file = write(vec![OutgoingRecord::new(
            &id,
            &memo,
            memo_value("vet at 10", ""),
        )]);
        assert_eq!(results(&read(&mut reader, &file, true, &held)), ["MERGED"]);
        assert_eq!(held.borrow()[&id], Some(memo_value("vet at 10", "mine")));

        // The user discards the change; the withdrawal then removes the copy.
        held.borrow_mut()
            .insert(id.clone(), Some(memo_value("vet at 10", "")));
        let file = write(vec![]);
        assert_eq!(
            results(&read(&mut reader, &file, true, &held)),
            ["WITHDRAWN"]
        );
        assert_eq!(held.borrow()[&id], None);
        let file = write(vec![]);
        assert_eq!(
            results(&read(&mut reader, &file, true, &held)),
            ["DUPLICATE"]
        );

        let file = write(vec![OutgoingRecord::new(
            &id,
            &memo,
            memo_value("back", ""),
        )]);
        assert_eq!(results(&read(&mut reader, &file, true, &held)), ["APPLIED"]);
        let file = write(vec![OutgoingRecord::deleted(&id)]);
        assert_eq!(results(&read(&mut reader, &file, true, &held)), ["APPLIED"]);
        assert_eq!(held.borrow()[&id], None);
        let file = write(vec![]);
        assert!(read(&mut reader, &file, true, &held).records.is_empty());
    }

    #[test]
    fn an_export_has_no_withdrawals_and_a_record_that_does_not_fit() {
        let memo = memo();
        let mut sender = open("node a", manifest("Sender", &["org.example.Memo"]), vec![]);
        let mut reader = open("node b", manifest("Reader", &[]), vec![]);
        let id = new_record_id().unwrap();
        let file = sender
            .write_file(
                &[OutgoingRecord::new(id, &memo, memo_value("x", ""))],
                None,
                false,
            )
            .unwrap();
        let preview = reader.inspect(&file).unwrap();
        assert!(preview.fitting.is_empty());
        let result = read_preview(&mut reader, &preview, true, &Held::default()).unwrap();
        assert_eq!(results(&result), ["DOES_NOT_FIT"]);
        // An export leaves nothing that a receiver is owed.
        assert!(sender.store().list("sent/").unwrap().is_empty());
    }

    #[test]
    fn the_manifest_revision_rises_with_its_content() {
        let mut store = MemoryStore::default();
        let mut revision = |name: &str| {
            let mut node = AxtNode::open(
                std::mem::take(&mut store),
                TestKey::named("node a").seed,
                EncryptionSeed::new([3; 32]),
                NodeConfig::new(manifest(name, &[])),
            );
            node.write_file(&[], None, false).unwrap();
            store = std::mem::take(node.store_mut());
            read_json(&store, "manifest").unwrap().unwrap()["revision"]
                .as_i64()
                .unwrap()
        };
        assert_eq!(revision("One"), 1);
        assert_eq!(revision("One"), 1);
        assert_eq!(revision("Two"), 2);
    }

    #[test]
    fn a_removed_sender_applies_nothing() {
        let memo = memo();
        let (a, b) = (TestKey::named("node a"), TestKey::named("node b"));
        let mut reader = open("node b", manifest("Reader", &["org.example.Memo"]), vec![]);
        let mut sender = open("node a", manifest("Sender", &["org.example.Memo"]), vec![]);
        write_json(
            reader.store_mut(),
            "sender/s",
            &json!({"name": "s", "current": [hex(&b.public)], "removed": [hex(&a.public)]}),
        )
        .unwrap();
        let file = sender
            .write_file(
                &[OutgoingRecord::new(
                    new_record_id().unwrap(),
                    &memo,
                    memo_value("x", ""),
                )],
                None,
                false,
            )
            .unwrap();
        let preview = reader.inspect(&file).unwrap();
        assert!(preview.sender_removed);
        let result = read_preview(&mut reader, &preview, true, &Held::default()).unwrap();
        assert_eq!(results(&result), ["SENDER_REMOVED"]);
    }

    #[test]
    fn a_failure_in_on_record_rolls_the_store_back() {
        let memo = memo();
        let mut sender = open("node a", manifest("Sender", &["org.example.Memo"]), vec![]);
        let mut reader = open("node b", manifest("Reader", &["org.example.Memo"]), vec![]);
        let file = sender
            .write_file(
                &[OutgoingRecord::new(
                    new_record_id().unwrap(),
                    &memo,
                    memo_value("x", ""),
                )],
                None,
                false,
            )
            .unwrap();
        let preview = reader.inspect(&file).unwrap();
        let result = reader.apply(
            &preview,
            true,
            |store, _| {
                store.write("app/x", b"mine").unwrap();
                Err(Error::Store("app failed".into()))
            },
            |_, _, _| Ok(None),
        );
        assert!(matches!(result, Err(Error::Store(_))));
        assert!(reader.store().data.is_empty());
    }

    #[test]
    fn on_record_writes_the_app_s_own_data_in_the_same_transaction() {
        let memo = memo();
        let mut sender = open("node a", manifest("Sender", &["org.example.Memo"]), vec![]);
        let mut reader = open("node b", manifest("Reader", &["org.example.Memo"]), vec![]);
        let id = new_record_id().unwrap();
        let file = sender
            .write_file(
                &[OutgoingRecord::new(&id, &memo, memo_value("x", ""))],
                None,
                false,
            )
            .unwrap();
        let preview = reader.inspect(&file).unwrap();
        let result = reader
            .apply(
                &preview,
                true,
                |store, change| {
                    assert_eq!(change.type_name.as_deref(), Some("org.example.Memo"));
                    assert_eq!(change.outcome, Outcome::Applied);
                    store.write(&format!("app/{}", change.id), b"x").unwrap();
                    Ok(())
                },
                |_, _, _| Ok(None),
            )
            .unwrap();
        assert!(result.accepted);
        assert!(reader.store().data.contains_key(&format!("app/{id}")));
    }

    #[test]
    fn record_ids_and_stamps() {
        assert_eq!(next_stamp(0, 1, 5), Some(65536 + 5));
        assert_eq!(next_stamp(1 << 40, 1, 0), Some((1 << 40) + 1));
        assert_eq!(next_stamp(5, -1, 0), Some(6));
        assert_eq!(next_stamp(i64::MAX - 10, 0, 0), None);
        assert_eq!(next_stamp(0, i64::MAX, 0), None);
        assert_eq!(now_ms(UNIX_EPOCH + std::time::Duration::from_millis(7)), 7);
        assert_eq!(now_ms(UNIX_EPOCH - std::time::Duration::from_millis(7)), -7);
    }

    #[test]
    fn versions_are_state_stamps_of_the_clock_and_keep_rising_after_a_restore() {
        let memo = memo();
        let mut config = NodeConfig::new(manifest("S", &[]));
        config.clock = Box::new(|| UNIX_EPOCH + std::time::Duration::from_millis(1000));
        let mut node = AxtNode::open(
            MemoryStore::default(),
            TestKey::named("node a").seed,
            EncryptionSeed::new([3; 32]),
            config,
        );
        let id = new_record_id().unwrap();
        let version = |node: &mut AxtNode<MemoryStore>, text: &str| {
            let file = node
                .write_file(
                    &[OutgoingRecord::new(&id, &memo, memo_value(text, ""))],
                    None,
                    false,
                )
                .unwrap();
            let checked = check_file(&file).unwrap();
            checked.records[0].record().1
        };
        let first = version(&mut node, "one");
        assert!((1000 * 65536..1000 * 65536 + 32768).contains(&first));
        assert_eq!(version(&mut node, "one"), first);
        let second = version(&mut node, "two");
        assert!(second > first);
        // A restore of an older backup of the records keeps the stamp: the clock has not
        // moved, and the version still rises.
        node.store_mut().data.remove(&format!("own/{id}"));
        assert!(version(&mut node, "one") > second);
    }

    #[test]
    fn bytes_survive_the_store_and_an_unchanged_record_keeps_its_version() {
        let blob = blob();
        let mut sender = open("more a", manifest("S", &[]), vec![]);
        let mut any = manifest("R", &[]);
        set_field(
            &mut any,
            "any_type",
            record(vec![
                ("purpose", s("Anything.")),
                ("purpose_translations", Value::Map(BTreeMap::new())),
            ]),
        );
        let mut reader = open("more b", any, vec![]);
        let b = TestKey::named("more b").public;
        let held = Held::default();
        let record = OutgoingRecord::new(
            new_record_id().unwrap(),
            &blob,
            record(vec![("data", Value::Bytes(vec![1, 2]))]),
        );
        for (records, expected) in [
            (vec![record.clone()], "APPLIED"),
            (vec![record.clone()], "DUPLICATE"),
            (vec![], "WITHDRAWN"),
            (vec![record.clone()], "APPLIED"),
        ] {
            let file = sender.write_file(&records, Some(&b), false).unwrap();
            assert_eq!(results(&read(&mut reader, &file, true, &held)), [expected]);
        }
    }

    #[test]
    fn a_file_with_an_invalid_manifest_and_an_id_that_is_no_uuid() {
        let memo = memo();
        let mut bad = manifest("S", &[]);
        set_field(&mut bad, "formats", Value::Array(vec![Value::Int(2)]));
        let mut sender = open("more a", bad, vec![]);
        let reader = open("more b", manifest("R", &[]), vec![]);
        let file = sender.write_file(&[], None, false).unwrap();
        assert_eq!(reader.inspect(&file).unwrap().app_name, None);
        let failed = sender.write_file(
            &[OutgoingRecord::new("nope", &memo, memo_value("", ""))],
            None,
            false,
        );
        assert_eq!(failed.unwrap_err().code(), Some(ErrorCode::RecordIdInvalid));
        // A value that is no datum of its type.
        let failed = sender.write_file(
            &[OutgoingRecord::new(
                new_record_id().unwrap(),
                &memo,
                record(vec![("text", s(""))]),
            )],
            None,
            false,
        );
        assert_eq!(failed.unwrap_err().code(), Some(ErrorCode::ValueInvalid));
    }

    #[test]
    fn apply_skips_a_record_message_whose_id_is_no_uuid() {
        let memo = memo();
        let a = TestKey::named("more a");
        let mut reader = open("more b", manifest("R", &["org.example.Memo"]), vec![]);
        let signer = Signer {
            seed: &a.seed,
            public_key: a.public,
        };
        let body = memo
            .schema()
            .encode_single_object(&memo_value("x", ""))
            .unwrap();
        let data = |id: &str| {
            signer
                .datum(
                    Kind::Data,
                    Some(RecordRef {
                        id: id.into(),
                        version: 1,
                    }),
                    body.clone(),
                )
                .unwrap()
        };
        let file = signed_file(&signer, &[&memo], &[data("nope"), data(R1)]).unwrap();
        let result = read(&mut reader, &file, true, &Held::default());
        assert_eq!(results(&result), ["RECORD_ID_INVALID", "APPLIED"]);
        // A file that a message of another sender breaks is rejected as a whole.
        let other = signed_message(&TestKey::named("x"), Kind::Delete, vec![]);
        let file = signed_file(&signer, &[], &[other[10..].to_vec()]).unwrap();
        assert_eq!(
            reader.inspect(&file).unwrap_err().code(),
            Some(ErrorCode::FileRejected)
        );
    }

    fn relation(id: &str, target: Value) -> Value {
        record(vec![
            ("id", s(id)),
            ("kind", s("axt.related")),
            ("target", target),
            ("note", s("")),
            ("start", Value::Null),
            ("end", Value::Null),
            ("attributes", Value::Map(BTreeMap::new())),
        ])
    }

    fn outside() -> Value {
        Value::Union {
            index: 1,
            branch: "axt.RelationOutsideTarget".into(),
            value: Box::new(record(vec![
                ("uri", s("https://example.org")),
                ("text", s("")),
            ])),
        }
    }

    fn note_value(text: &str, links: Vec<Value>) -> Value {
        record(vec![("text", s(text)), ("links", Value::Array(links))])
    }

    fn address(sender: &str, id: &str) -> RecordAddress {
        RecordAddress {
            sender: sender.into(),
            id: id.into(),
        }
    }

    #[test]
    fn relations_resolve_across_senders_and_show_where_they_link_from() {
        let note = note();
        let (a, b) = (TestKey::named("relations a"), TestKey::named("relations b"));
        let mut sender = open("relations a", manifest("A", &["org.example.Note"]), vec![]);
        let mut reader = open(
            "relations b",
            manifest("B", &["org.example.Note"]),
            vec![note.clone()],
        );
        let (first, second, own) = (
            new_record_id().unwrap(),
            new_record_id().unwrap(),
            new_record_id().unwrap(),
        );
        let held = Held::default();
        let file = sender
            .write_file(
                &[
                    OutgoingRecord::new(&first, &note, note_value("first", vec![])),
                    OutgoingRecord::new(
                        &second,
                        &note,
                        note_value(
                            "second",
                            vec![relation(R1, target(&first, None)), relation(R2, outside())],
                        ),
                    ),
                ],
                Some(&b.public),
                false,
            )
            .unwrap();
        read(&mut reader, &file, true, &held);
        let name = hex(&a.public);
        assert_eq!(
            reader.resolve(&name, &target(&first, None)).unwrap(),
            Some(address(&name, &first))
        );
        assert_eq!(
            reader
                .resolve(&name, &target(&first, Some(b.public)))
                .unwrap(),
            None,
            "no record of its own of that id"
        );
        assert_eq!(reader.resolve(&name, &outside()).unwrap(), None);
        assert_eq!(
            reader.linked_from(&name, &first).unwrap(),
            [Link {
                holder: address(&name, &second),
                relation: R1.into()
            }]
        );

        // The reader's own record links the received one.
        reader
            .write_file(
                &[OutgoingRecord::new(
                    &own,
                    &note,
                    note_value("mine", vec![relation(R3, target(&first, Some(a.public)))]),
                )],
                Some(&a.public),
                false,
            )
            .unwrap();
        let mut expected = vec![
            Link {
                holder: address(&name, &second),
                relation: R1.into(),
            },
            Link {
                holder: address(&hex(&b.public), &own),
                relation: R3.into(),
            },
        ];
        expected.sort_by(|x, y| x.holder.cmp(&y.holder));
        let mut linked = reader.linked_from(&name, &first).unwrap();
        linked.sort_by(|x, y| x.holder.cmp(&y.holder));
        assert_eq!(linked, expected);
        assert_eq!(
            reader
                .resolve(&name, &target(&own, Some(b.public)))
                .unwrap(),
            Some(address(&hex(&b.public), &own))
        );

        // The sender deletes the second note: its relation is gone.
        let file = sender
            .write_file(
                &[
                    OutgoingRecord::new(&first, &note, note_value("first", vec![])),
                    OutgoingRecord::deleted(&second),
                ],
                Some(&b.public),
                false,
            )
            .unwrap();
        read(&mut reader, &file, true, &held);
        assert_eq!(
            reader.linked_from(&name, &first).unwrap(),
            [Link {
                holder: address(&hex(&b.public), &own),
                relation: R3.into()
            }]
        );
        // The reader deletes its own record: the link from it is gone too.
        reader
            .write_file(&[OutgoingRecord::deleted(&own)], Some(&a.public), false)
            .unwrap();
        assert_eq!(reader.linked_from(&name, &first).unwrap(), []);
        assert_eq!(
            reader
                .resolve(&hex(&b.public), &target(&own, None))
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_record_kept_against_a_withdrawal_keeps_its_relations() {
        let note = note();
        let (a, b) = (TestKey::named("relations a"), TestKey::named("relations b"));
        let mut sender = open("relations a", manifest("A", &["org.example.Note"]), vec![]);
        let mut reader = open("relations b", manifest("B", &["org.example.Note"]), vec![]);
        let (first, second) = (new_record_id().unwrap(), new_record_id().unwrap());
        let held = Held::default();
        let file = sender
            .write_file(
                &[
                    OutgoingRecord::new(&first, &note, note_value("first", vec![])),
                    OutgoingRecord::new(
                        &second,
                        &note,
                        note_value("second", vec![relation(R1, target(&first, None))]),
                    ),
                ],
                Some(&b.public),
                false,
            )
            .unwrap();
        read(&mut reader, &file, true, &held);
        for id in [&first, &second] {
            let mut mine = held.borrow()[id].clone().unwrap();
            set_field(&mut mine, "text", s("mine"));
            held.borrow_mut().insert(id.clone(), Some(mine));
        }
        // Withdrawals alone: the file holds no schema of the type.
        let file = sender.write_file(&[], Some(&b.public), false).unwrap();
        assert_eq!(
            results(&read(&mut reader, &file, true, &held)),
            ["KEPT", "KEPT"]
        );
        assert_eq!(
            reader.linked_from(&hex(&a.public), &first).unwrap(),
            [Link {
                holder: address(&hex(&a.public), &second),
                relation: R1.into()
            }]
        );
    }

    #[test]
    fn links_go_along_only_with_a_share_that_lets_them_or_to_the_own_user() {
        let note = note();
        let (a, b) = (TestKey::named("relations a"), TestKey::named("relations b"));
        let mut sender = open("relations a", manifest("A", &["org.example.Note"]), vec![]);
        let (first, second) = (new_record_id().unwrap(), new_record_id().unwrap());
        let links = vec![
            relation(R1, target(&first, None)),
            relation(R2, target(&new_record_id().unwrap(), Some(a.public))),
            relation(R3, outside()),
        ];
        let mut sent = |with_links: bool, own_user: bool| {
            let mut reader = open(
                "relations b",
                manifest("B", &["org.example.Note"]),
                vec![note.clone()],
            );
            let held = Held::default();
            let mut holder =
                OutgoingRecord::new(&second, &note, note_value("second", links.clone()));
            if with_links {
                holder = holder.with_links();
            }
            let file = sender
                .write_file(
                    &[
                        OutgoingRecord::new(&first, &note, note_value("first", vec![])),
                        holder,
                    ],
                    Some(&b.public),
                    own_user,
                )
                .unwrap();
            read(&mut reader, &file, true, &held);
            let value = held.borrow()[&second].clone().unwrap();
            match value.field("links") {
                Some(Value::Array(list)) => list
                    .iter()
                    .map(|r| match r.field("id") {
                        Some(Value::String(id)) => id.clone(),
                        _ => String::new(),
                    })
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            }
        };
        assert_eq!(sent(false, false), [R1]);
        assert_eq!(sent(true, false), [R1, R2, R3]);
        assert_eq!(sent(false, true), [R1, R2, R3]);
    }

    #[test]
    fn a_taken_value_survives_the_store_and_merges_on_the_next_file() {
        // A type of a long, a double, bytes and relations, read by a node opened again on
        // its store between the files.
        let kind = |name: &str, brick: &str| {
            json!({"name": name, "doc": "A field.", "texts": {}, "required": true,
                   "kind": {brick: {}}})
        };
        let rich = object_type(
            "org.example.Rich",
            vec![
                kind("count", "axt.LongField"),
                kind("share", "axt.DoubleField"),
                kind("data", "axt.BytesField"),
                json!({"name": "links", "doc": "The links.", "texts": {},
                       "kind": {"axt.RelationField": {}}}),
            ],
        );
        let (a, b) = (TestKey::named("rich a"), TestKey::named("rich b"));
        let mut sender = open("rich a", manifest("A", &["org.example.Rich"]), vec![]);
        let value = |count: i64, share: f64, links: Vec<Value>| {
            record(vec![
                ("count", Value::Long(count)),
                ("share", Value::Double(share)),
                ("data", Value::Bytes(vec![0, 255])),
                ("links", Value::Array(links)),
            ])
        };
        let id = new_record_id().unwrap();
        let link = relation(R1, target(&id, Some(a.public)));
        let held = Held::default();
        let file = sender
            .write_file(
                &[
                    OutgoingRecord::new(&id, &rich, value(1 << 40, 0.1, vec![link.clone()]))
                        .with_links(),
                ],
                Some(&b.public),
                false,
            )
            .unwrap();
        let mut reader = open("rich b", manifest("B", &["org.example.Rich"]), vec![]);
        assert_eq!(results(&read(&mut reader, &file, true, &held)), ["APPLIED"]);
        let taken = load_held(reader.store(), &hex(&a.public), &id)
            .unwrap()
            .unwrap()
            .taken;
        assert_eq!(taken, Some(value(1 << 40, 0.1, vec![link.clone()])));
        let store = std::mem::take(reader.store_mut());
        let mut config = NodeConfig::new(manifest("B", &["org.example.Rich"]));
        config.readers = vec![rich.clone()];
        let mut reader = AxtNode::open(
            store,
            TestKey::named("rich b").seed,
            EncryptionSeed::new([3; 32]),
            config,
        );
        // The user changes the share; the sender changes the count.
        let mut mine = held.borrow()[&id].clone().unwrap();
        set_field(&mut mine, "share", Value::Double(0.5));
        held.borrow_mut().insert(id.clone(), Some(mine));
        let file = sender
            .write_file(
                &[OutgoingRecord::new(&id, &rich, value(2, 0.1, vec![link.clone()])).with_links()],
                Some(&b.public),
                false,
            )
            .unwrap();
        assert_eq!(results(&read(&mut reader, &file, true, &held)), ["MERGED"]);
        assert_eq!(held.borrow()[&id], Some(value(2, 0.5, vec![link])));
        let kept = load_held(reader.store(), &hex(&a.public), &id)
            .unwrap()
            .unwrap();
        assert_eq!(kept.taken.unwrap().field("count"), Some(&Value::Long(2)));
    }

    #[test]
    fn a_shared_again_record_has_a_version_above_its_withdrawal() {
        let memo = memo();
        let b = TestKey::named("node b").public;
        let mut sender = open("node a", manifest("S", &[]), vec![]);
        let id = new_record_id().unwrap();
        let versions = |sender: &mut AxtNode<MemoryStore>, records: &[OutgoingRecord<'_>]| {
            let file = sender.write_file(records, Some(&b), false).unwrap();
            check_file(&file)
                .unwrap()
                .records
                .iter()
                .map(|m| (m.envelope.kind, m.record().1))
                .collect::<Vec<_>>()
        };
        let record = OutgoingRecord::new(&id, &memo, memo_value("x", ""));
        let [(Kind::Data, shared)] = versions(&mut sender, std::slice::from_ref(&record))[..]
        else {
            panic!("one DATA");
        };
        let [(Kind::Withdraw, withdrawn)] = versions(&mut sender, &[])[..] else {
            panic!("one WITHDRAW");
        };
        assert!(withdrawn > shared);
        // The withdrawal is sent again with its version until the record is shared again.
        assert_eq!(versions(&mut sender, &[]), [(Kind::Withdraw, withdrawn)]);
        let [(Kind::Data, again)] = versions(&mut sender, &[record])[..] else {
            panic!("one DATA");
        };
        assert!(again > withdrawn);
        // The record its user deletes goes as a DELETE, and no withdrawal follows it.
        let [(Kind::Delete, _)] = versions(&mut sender, &[OutgoingRecord::deleted(&id)])[..] else {
            panic!("one DELETE");
        };
        assert_eq!(versions(&mut sender, &[]), []);
    }

    #[test]
    fn relations_merge_per_element_from_the_schema() {
        let note = note();
        let b = TestKey::named("relations b");
        let mut sender = open("relations a", manifest("A", &["org.example.Note"]), vec![]);
        let mut reader = open(
            "relations b",
            manifest("B", &["org.example.Note"]),
            vec![note.clone()],
        );
        let id = new_record_id().unwrap();
        let held = Held::default();
        let theirs = relation(R1, outside());
        let file = sender
            .write_file(
                &[
                    OutgoingRecord::new(&id, &note, note_value("n", vec![theirs.clone()]))
                        .with_links(),
                ],
                Some(&b.public),
                false,
            )
            .unwrap();
        read(&mut reader, &file, true, &held);
        // The user adds a relation; the sender adds another.
        let mine = relation(R2, outside());
        held.borrow_mut().insert(
            id.clone(),
            Some(note_value("n", vec![theirs.clone(), mine.clone()])),
        );
        let added = relation(R3, outside());
        let file = sender
            .write_file(
                &[OutgoingRecord::new(
                    &id,
                    &note,
                    note_value("n", vec![theirs.clone(), added.clone()]),
                )
                .with_links()],
                Some(&b.public),
                false,
            )
            .unwrap();
        assert_eq!(results(&read(&mut reader, &file, true, &held)), ["MERGED"]);
        assert_eq!(
            held.borrow()[&id],
            Some(note_value("n", vec![theirs, added, mine]))
        );
    }
}
