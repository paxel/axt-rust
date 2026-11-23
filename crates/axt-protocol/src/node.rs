//! The public face of the library: one installation of an app that speaks AXT, keeping
//! its AXT state in the app's store (`docs/adr/0001-the-public-api.md` and
//! `0002-axt-0-2-0.md` of `axt_protocol` for Dart).

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use crate::device_sets::{DeviceSetReceiver, KeptRecord, Key, KnownSender, RecordState};
use crate::ed25519::public_key_of;
use crate::error::Error;
use crate::keys::{EncryptionSeed, SigningSeed};
use crate::records::{
    HeldRecord, HeldState, Outcome, RecordPolicy, checked_record_key, record_key,
};
use crate::relation_index::{HeldRelation, RelationResolver, target_sender};
use crate::schema::Schema;
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

/// One installation of an app that speaks AXT, on the app's store `S`.
///
/// It has no `Debug`, as it holds the app's private keys.
pub struct AxtNode<S: Store> {
    store: S,
    #[expect(dead_code, reason = "signs the files of axtrs-11")]
    signing_seed: SigningSeed,
    #[expect(dead_code, reason = "opens the sealed messages of a later ticket")]
    encryption_seed: EncryptionSeed,
    public_key: Key,
    #[expect(dead_code, reason = "reads the records of the files of axtrs-11")]
    readers: BTreeMap<String, TypeDescription>,
    #[expect(dead_code, reason = "applies the records of the files of axtrs-11")]
    policy: RecordPolicy,
}

impl<S: Store> AxtNode<S> {
    /// Opens the library on the app's `store`, with the seed of the app's Ed25519 signing
    /// key and the private key of its X25519 encryption key, the `readers`, its own types
    /// by which it reads the records of others, and its `policy` for its user's changes.
    ///
    /// The library never writes the seeds to the store.
    #[must_use]
    pub fn open(
        store: S,
        signing_seed: SigningSeed,
        encryption_seed: EncryptionSeed,
        readers: impl IntoIterator<Item = TypeDescription>,
        policy: RecordPolicy,
    ) -> Self {
        let public_key = public_key_of(&signing_seed);
        Self {
            store,
            signing_seed,
            encryption_seed,
            public_key,
            readers: readers
                .into_iter()
                .map(|reader| (reader.name().to_owned(), reader))
                .collect(),
            policy,
        }
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

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the files of axtrs-11 write the AXT state")
)]
fn write_json<S: Store>(store: &mut S, key: &str, json: &Json) -> Result<(), Error> {
    store
        .write(key, json.to_string().as_bytes())
        .map_err(Error::store)
}

/// A key in hexadecimal digits.
fn key_of_hex(text: &str) -> Option<Key> {
    let digits = text.as_bytes();
    let (pairs, rest) = digits.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let bytes: Vec<u8> = pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair.as_slice())
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect::<Option<_>>()?;
    bytes.as_slice().try_into().ok()
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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the files of axtrs-11 accept senders")
)]
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
/// `record/<sender>/<id>`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the files of axtrs-11 apply records")
)]
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
        }),
    )
}

/// Keeps the relations with a record target of the record `id` (a record key) of
/// `sender`, whose `value` has `schema`, at `relations/<sender>/<id>`; none for a record
/// that is gone.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the files of axtrs-11 index the records they apply and send"
    )
)]
fn index<S: Store>(
    store: &mut S,
    sender: &str,
    id: &str,
    value: Option<&Value>,
    schema: &Schema,
) -> Result<(), Error> {
    let key = format!("relations/{sender}/{id}");
    let relations = value.map_or_else(Vec::new, |value| {
        crate::relation_index::record_targets(schema, value)
    });
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
            [],
            RecordPolicy::default(),
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
            &schema,
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
            &schema,
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
        index(node.store_mut(), "t", T3, None, &schema).unwrap();
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
}
