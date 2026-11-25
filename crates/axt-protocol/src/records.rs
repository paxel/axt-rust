//! Records and their ids, and applying record messages: the version rule, tombstones,
//! the receiver's own changes and the outcomes (AXT `spec/records.md`, sections 2, 3 and
//! 5 to 7).

use std::collections::HashMap;

use crate::error::{Error, ErrorCode};
use crate::limits::{FIELDS_EXTENSIONS, FIELDS_RELATIONS};
use crate::schema::Schema;
use crate::value::Value;

/// The key of the record id `id`: the UUID in lower case; `None` for an id that is not a
/// UUID in text form, or the nil or the max UUID.
pub(crate) fn record_key(id: &str) -> Option<String> {
    let is_uuid = id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    let key = id.to_ascii_lowercase();
    (is_uuid
        && key != "00000000-0000-0000-0000-000000000000"
        && key != "ffffffff-ffff-ffff-ffff-ffffffffffff")
        .then_some(key)
}

/// The key of the record id `id`, or `RECORD_ID_INVALID` (section 2).
pub(crate) fn checked_record_key(id: &str) -> Result<String, Error> {
    record_key(id).ok_or_else(|| {
        Error::axt(
            ErrorCode::RecordIdInvalid,
            format!("{id} is no UUID, or the nil or the max UUID"),
        )
    })
}

/// What the receiver does when its user changed a received record (section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalChanges {
    /// Merges per field (section 6.1).
    #[default]
    PerField,
    /// Keeps the whole record as its user left it (section 6.2).
    WholeRecordKeep,
    /// Takes the whole record from the message (section 6.2).
    WholeRecordTake,
}

/// What the receiver does when a deletion or a withdrawal meets its user's changes
/// (section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeleteWithLocalChanges {
    /// Deletes the record all the same.
    Delete,
    /// Keeps the record as its user left it.
    #[default]
    Keep,
}

/// How a receiver treats its user's changes (section 6). The default merges per field
/// and keeps a record with changes of its user against a deletion or a withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecordPolicy {
    /// What the receiver does when its user changed a received record.
    pub local_changes: LocalChanges,
    /// What the receiver does when a `DELETE` meets its user's changes.
    pub delete_with_local_changes: DeleteWithLocalChanges,
    /// What the receiver does when a `WITHDRAW` meets its user's changes
    /// (`spec/shares.md`, section 4.3); `None` for the same as for a `DELETE`.
    pub withdraw_with_local_changes: Option<DeleteWithLocalChanges>,
}

impl RecordPolicy {
    /// What the receiver does when a `WITHDRAW` meets its user's changes.
    #[must_use]
    pub fn withdraw_policy(&self) -> DeleteWithLocalChanges {
        self.withdraw_with_local_changes
            .unwrap_or(self.delete_with_local_changes)
    }
}

/// The outcome of a record message (section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The message was taken as it came.
    Applied,
    /// The message was merged with the user's changes.
    Merged,
    /// The user's record was kept against the message.
    Kept,
    /// The message has the version the receiver holds.
    Duplicate,
    /// The message has a version below the one the receiver holds.
    Stale,
    /// The sender withdrew the record.
    Withdrawn,
}

impl Outcome {
    /// The outcome as the specification writes it, such as `APPLIED`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "APPLIED",
            Self::Merged => "MERGED",
            Self::Kept => "KEPT",
            Self::Duplicate => "DUPLICATE",
            Self::Stale => "STALE",
            Self::Withdrawn => "WITHDRAWN",
        }
    }
}

/// The kind of a record message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    Data,
    Delete,
    Withdraw,
}

/// The key by which the elements of a list merged per element are told apart
/// (`spec/sync.md`, section 25.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ElementKey {
    /// A relation, by its `id`, compared as 128-bit values.
    Id,
    /// An extension, by its `name`.
    Name,
}

/// What a receiver needs to merge lists per element (section 6.1): the top-level fields
/// that are such lists, and the schemas of the extension types it knows.
#[derive(Debug, Clone, Default)]
pub(crate) struct ElementMerge {
    /// The lists merged per element, by field name.
    pub(crate) lists: HashMap<String, ElementKey>,
    /// The writer schemas of extensions that the receiver holds, by fingerprint.
    pub(crate) writers: HashMap<[u8; 8], Schema>,
    /// The receiver's own schema of each extension type it knows, by full name.
    pub(crate) own: HashMap<String, Schema>,
}

/// The top-level fields of `schema` that are lists merged per element: the lists of
/// relations and of extensions.
pub(crate) fn element_lists_of(schema: &Schema) -> HashMap<String, ElementKey> {
    schema
        .record_lists()
        .into_iter()
        .filter_map(|(field, items)| match items.as_str() {
            "axt.Relation" => Some((field, ElementKey::Id)),
            "axt.Extension" => Some((field, ElementKey::Name)),
            _ => None,
        })
        .collect()
}

/// What a receiver merges per element in a record of `schema`, with the extension types
/// it knows: the `writers` it holds and its `readers`, its own schemas, by full name.
pub(crate) fn element_merge_of<'a>(
    schema: &Schema,
    writers: impl IntoIterator<Item = &'a Schema>,
    readers: HashMap<String, Schema>,
) -> ElementMerge {
    let mut writers: HashMap<[u8; 8], Schema> = writers
        .into_iter()
        .map(|s| (s.fingerprint().0, s.clone()))
        .collect();
    writers.extend(readers.values().map(|s| (s.fingerprint().0, s.clone())));
    ElementMerge {
        lists: element_lists_of(schema),
        writers,
        own: readers,
    }
}

/// What a receiver holds of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldState {
    There,
    Tombstone,
    Withdrawn,
    DeletedByUser,
}

impl HeldState {
    /// The state as the conformance vectors write it.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::There => "there",
            Self::Tombstone => "tombstone",
            Self::Withdrawn => "withdrawn",
            Self::DeletedByUser => "deleted_by_user",
        }
    }

    /// The state the vectors write as `code`.
    pub(crate) fn from_code(code: &str) -> Option<Self> {
        [
            Self::There,
            Self::Tombstone,
            Self::Withdrawn,
            Self::DeletedByUser,
        ]
        .into_iter()
        .find(|state| state.code() == code)
    }
}

/// What a receiver keeps of one record of one sender (section 5.1).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HeldRecord {
    /// The receiver's version: the highest version seen in a record message.
    pub(crate) version: i64,
    pub(crate) state: HeldState,
    /// The record's type, once a `DATA` has brought it.
    pub(crate) type_name: Option<String>,
    /// The value the receiver last took from the sender, for a record there.
    pub(crate) taken: Option<Value>,
    /// The kind of the message of the receiver's version that the receiver kept the
    /// record against, `DELETE` or `WITHDRAW`; `None` otherwise.
    pub(crate) kept_against: Option<RecordKind>,
}

impl HeldRecord {
    fn new(version: i64, state: HeldState, type_name: Option<String>) -> Self {
        Self {
            version,
            state,
            type_name,
            taken: None,
            kept_against: None,
        }
    }
}

/// The result of one record message.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Applied {
    pub(crate) outcome: Outcome,
    /// What the receiver holds now.
    pub(crate) held: HeldRecord,
    /// The record as the receiver now holds it, `None` unless it is there.
    pub(crate) value: Option<Value>,
    /// For `MERGED`: the fields whose values the receiver kept, sorted.
    pub(crate) kept_fields: Vec<String>,
}

impl Applied {
    fn new(outcome: Outcome, held: HeldRecord, value: Option<Value>) -> Self {
        Self {
            outcome,
            held,
            value,
            kept_fields: Vec::new(),
        }
    }
}

/// One record message as the receiver applies it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordMessage<'a> {
    pub(crate) kind: RecordKind,
    pub(crate) version: i64,
    /// The record's type, for a `DATA`.
    pub(crate) type_name: Option<&'a str>,
    /// The record, for a `DATA`.
    pub(crate) value: Option<&'a Value>,
}

/// Whether two values are equal, member by member; the fields of records compare by
/// name, whatever their order.
pub(crate) fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Record(x), Value::Record(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(name, v)| b.field(name).is_some_and(|w| same_value(v, w)))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, v)| y.get(key).is_some_and(|w| same_value(v, w)))
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(v, w)| same_value(v, w))
        }
        (
            Value::Union {
                index: i, value: v, ..
            },
            Value::Union {
                index: j, value: w, ..
            },
        ) => i == j && same_value(v, w),
        _ => a == b,
    }
}

/// The value of the field `name` of the record `value`, `null` where it has none.
fn field_or_null<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.field(name).unwrap_or(&Value::Null)
}

/// The fields of a record; none for another value.
fn fields_of(value: &Value) -> &[(String, Value)] {
    match value {
        Value::Record(fields) => fields,
        _ => &[],
    }
}

/// Sets the field `name` of the record `record` to `value`, adding it where it has none.
pub(crate) fn set_field(record: &mut Value, name: &str, value: Value) {
    if let Value::Record(fields) = record {
        match fields.iter_mut().find(|(n, _)| n == name) {
            Some((_, slot)) => *slot = value,
            None => fields.push((name.to_owned(), value)),
        }
    }
}

/// The fields of `current` that differ from `taken`: the user's own changes.
pub(crate) fn changed_fields(taken: &Value, current: &Value) -> Vec<String> {
    let mut names: Vec<&str> = Vec::new();
    for (name, _) in fields_of(taken).iter().chain(fields_of(current)) {
        if !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    names
        .into_iter()
        .filter(|name| !same_value(field_or_null(taken, name), field_or_null(current, name)))
        .map(str::to_owned)
        .collect()
}

/// Applies one record message to what the receiver holds of the record, `held` (`None`
/// for none), with `current`, the record as the receiver's user left it (`None` when the
/// user deleted it or it is not there). The id is checked by [`checked_record_key`].
///
/// # Errors
///
/// `VERSION_INVALID` for a version below 1 and `TYPE_CHANGED` for a `DATA` of another
/// type than the record's; `INVALID_MESSAGE` for a `DATA` without a value.
pub(crate) fn apply_record_message(
    held: Option<&HeldRecord>,
    current: Option<&Value>,
    message: RecordMessage<'_>,
    policy: &RecordPolicy,
    elements: &ElementMerge,
) -> Result<Applied, Error> {
    let RecordMessage {
        kind,
        version,
        type_name,
        value,
    } = message;
    if version < 1 {
        return Err(Error::axt(
            ErrorCode::VersionInvalid,
            format!("version {version} is below 1"),
        ));
    }
    if kind == RecordKind::Data
        && let Some(held_type) = held.and_then(|h| h.type_name.as_deref())
        && Some(held_type) != type_name
    {
        return Err(Error::axt(
            ErrorCode::TypeChanged,
            format!(
                "the record is a {held_type}, not a {}",
                type_name.unwrap_or("")
            ),
        ));
    }
    if kind == RecordKind::Data && value.is_none() {
        return Err(no_value());
    }
    let there = held.is_some_and(|h| h.state == HeldState::There);
    let shown = if there { current.cloned() } else { None };
    let Some(held) = held else {
        return Ok(first_message(message));
    };
    if version <= held.version {
        let outcome = if version == held.version {
            Outcome::Duplicate
        } else {
            Outcome::Stale
        };
        return Ok(Applied::new(outcome, held.clone(), shown));
    }
    let removed = if kind == RecordKind::Withdraw {
        Outcome::Withdrawn
    } else {
        Outcome::Applied
    };
    let tombstone = if kind == RecordKind::Withdraw {
        HeldState::Withdrawn
    } else {
        HeldState::Tombstone
    };
    // A record the user deleted stays deleted (section 6.3).
    if held.state == HeldState::DeletedByUser {
        let outcome = if kind == RecordKind::Data {
            Outcome::Kept
        } else {
            removed
        };
        let mut kept = HeldRecord::new(
            version,
            HeldState::DeletedByUser,
            held.type_name
                .clone()
                .or_else(|| type_name.map(str::to_owned)),
        );
        kept.taken.clone_from(&held.taken);
        return Ok(Applied::new(outcome, kept, None));
    }
    let changes = match (there, current, &held.taken) {
        (true, Some(current), Some(taken)) => changed_fields(taken, current),
        _ => Vec::new(),
    };
    if kind != RecordKind::Data {
        let keep = if kind == RecordKind::Withdraw {
            policy.withdraw_policy()
        } else {
            policy.delete_with_local_changes
        };
        if !changes.is_empty() && keep == DeleteWithLocalChanges::Keep {
            let mut kept = HeldRecord::new(version, HeldState::There, held.type_name.clone());
            kept.taken.clone_from(&held.taken);
            kept.kept_against = Some(kind);
            return Ok(Applied::new(Outcome::Kept, kept, current.cloned()));
        }
        return Ok(Applied::new(
            removed,
            HeldRecord::new(version, tombstone, held.type_name.clone()),
            None,
        ));
    }
    let Some(message_value) = value else {
        return Err(no_value());
    };
    let taken_now = |taken: &Value| {
        let mut record = HeldRecord::new(version, HeldState::There, type_name.map(str::to_owned));
        record.taken = Some(taken.clone());
        record
    };
    let (Some(current), Some(taken), false) = (current, &held.taken, changes.is_empty()) else {
        return Ok(Applied::new(
            Outcome::Applied,
            taken_now(message_value),
            Some(message_value.clone()),
        ));
    };
    match policy.local_changes {
        LocalChanges::WholeRecordTake => Ok(Applied::new(
            Outcome::Applied,
            taken_now(message_value),
            Some(message_value.clone()),
        )),
        LocalChanges::WholeRecordKeep => Ok(Applied::new(
            Outcome::Kept,
            taken_now(taken),
            Some(current.clone()),
        )),
        LocalChanges::PerField => {
            let mut merged = message_value.clone();
            let mut kept = Vec::new();
            for field in changes {
                let theirs = field_or_null(message_value, &field);
                let mine = match elements.lists.get(&field) {
                    None => field_or_null(current, &field).clone(),
                    Some(&key) => Value::Array(merge_elements(
                        key,
                        elements,
                        list_of(field_or_null(taken, &field)),
                        list_of(field_or_null(current, &field)),
                        list_of(theirs),
                    )),
                };
                if same_value(&mine, theirs) {
                    continue;
                }
                set_field(&mut merged, &field, mine);
                kept.push(field);
            }
            kept.sort();
            let outcome = if kept.is_empty() {
                Outcome::Applied
            } else {
                Outcome::Merged
            };
            let mut applied = Applied::new(outcome, taken_now(message_value), Some(merged));
            applied.kept_fields = kept;
            Ok(applied)
        }
    }
}

fn no_value() -> Error {
    Error::axt(ErrorCode::InvalidMessage, "a DATA without a value")
}

/// The first record message of a record the receiver holds nothing of.
fn first_message(message: RecordMessage<'_>) -> Applied {
    let type_name = message.type_name.map(str::to_owned);
    match (message.kind, message.value) {
        (RecordKind::Data, Some(value)) => {
            let mut held = HeldRecord::new(message.version, HeldState::There, type_name);
            held.taken = Some(value.clone());
            Applied::new(Outcome::Applied, held, Some(value.clone()))
        }
        (RecordKind::Withdraw, _) => Applied::new(
            Outcome::Withdrawn,
            HeldRecord::new(message.version, HeldState::Withdrawn, None),
            None,
        ),
        // A DELETE of an id never seen leaves a tombstone (section 5.2); a DATA without
        // a value is rejected before.
        _ => Applied::new(
            Outcome::Applied,
            HeldRecord::new(message.version, HeldState::Tombstone, None),
            None,
        ),
    }
}

/// The receiver's user takes after all the `DELETE` or the `WITHDRAW` of the receiver's
/// version that it kept the record against (`spec/protocol.md`, section 7.3); `None`
/// when the record is kept against neither.
#[cfg(any(test, feature = "conformance"))]
pub(crate) fn take_kept_removal(held: &HeldRecord) -> Option<Applied> {
    let withdraw = match held.kept_against? {
        RecordKind::Withdraw => true,
        RecordKind::Delete | RecordKind::Data => false,
    };
    let (outcome, state) = if withdraw {
        (Outcome::Withdrawn, HeldState::Withdrawn)
    } else {
        (Outcome::Applied, HeldState::Tombstone)
    };
    Some(Applied::new(
        outcome,
        HeldRecord::new(held.version, state, held.type_name.clone()),
        None,
    ))
}

/// The items of a list; none for another value.
fn list_of(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        _ => &[],
    }
}

/// The string of the field `name` of a record, or the empty string.
fn text<'a>(record: &'a Value, name: &str) -> &'a str {
    match record.field(name) {
        Some(Value::String(s)) => s,
        _ => "",
    }
}

/// The key of an element of a list merged per element.
fn element_key(key: ElementKey, element: &Value) -> String {
    match key {
        ElementKey::Id => {
            let id = text(element, "id");
            record_key(id).unwrap_or_else(|| id.to_owned())
        }
        ElementKey::Name => text(element, "name").to_owned(),
    }
}

/// The elements of `list` by key, in the order in which each key first appears; an
/// element whose key repeats replaces the earlier one.
fn keyed(key: ElementKey, list: &[Value]) -> Vec<(String, &Value)> {
    let mut out: Vec<(String, &Value)> = Vec::new();
    for element in list {
        let k = element_key(key, element);
        match out.iter_mut().find(|(seen, _)| *seen == k) {
            Some((_, slot)) => *slot = element,
            None => out.push((k, element)),
        }
    }
    out
}

fn lookup<'a>(list: &[(String, &'a Value)], key: &str) -> Option<&'a Value> {
    list.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
}

/// The list merged per element from `taken`, the list the receiver last took from the
/// sender, `user`, its user's list, and `message` (section 6.1): the message's elements
/// in its order, without those the user removed and with those the user changed, then
/// those the user added or changed that the message lacks, in the user's order.
fn merge_elements(
    key: ElementKey,
    elements: &ElementMerge,
    taken: &[Value],
    user: &[Value],
    message: &[Value],
) -> Vec<Value> {
    let before = keyed(key, taken);
    let mine = keyed(key, user);
    let changed: Vec<&str> = mine
        .iter()
        .filter(|(k, e)| lookup(&before, k).is_none_or(|b| !same_value(b, e)))
        .map(|(k, _)| k.as_str())
        .collect();
    let removed: Vec<&str> = before
        .iter()
        .filter(|(k, _)| lookup(&mine, k).is_none())
        .map(|(k, _)| k.as_str())
        .collect();
    let mut merged = Vec::new();
    let mut placed: Vec<String> = Vec::new();
    for element in message {
        let k = element_key(key, element);
        let is_removed = removed.contains(&k.as_str());
        let is_changed = changed.contains(&k.as_str());
        if !is_removed {
            match (is_changed, lookup(&before, &k), lookup(&mine, &k)) {
                (false, _, _) | (true, _, None) => merged.push(element.clone()),
                (true, Some(was), Some(users)) if key == ElementKey::Name => {
                    merged.push(merge_extension(elements, was, users, element));
                }
                (true, _, Some(users)) => merged.push(users.clone()),
            }
        }
        placed.push(k);
    }
    for (k, element) in &mine {
        if changed.contains(&k.as_str()) && !placed.contains(k) {
            merged.push((*element).clone());
        }
    }
    let max = match key {
        ElementKey::Id => FIELDS_RELATIONS,
        ElementKey::Name => FIELDS_EXTENSIONS,
    };
    merged.truncate(max);
    merged
}

/// The extension that the user changed, `user`, merged field by field with `message`
/// where the receiver knows the writer schemas of all three and has its own schema of
/// the type (`spec/fields.md`, section 12.4); the user's extension whole otherwise.
fn merge_extension(elements: &ElementMerge, taken: &Value, user: &Value, message: &Value) -> Value {
    let name = text(user, "name");
    let Some(own) = elements.own.get(name) else {
        return user.clone();
    };
    let decode = |extension: &Value| -> Option<Value> {
        let Some(Value::Bytes(data)) = extension.field("data") else {
            return None;
        };
        let (fingerprint, payload) = crate::avro::split_single_object(data)?;
        let writer = elements.writers.get(&fingerprint)?;
        let resolution = writer.resolution(own).ok()?;
        writer.decode_datum_as(&resolution, payload).ok()
    };
    let (Some(before), Some(mine), Some(theirs)) = (decode(taken), decode(user), decode(message))
    else {
        return user.clone();
    };
    let merged = Value::Record(
        fields_of(&theirs)
            .iter()
            .map(|(field, value)| {
                let users = field_or_null(&mine, field);
                let value = if same_value(users, field_or_null(&before, field)) {
                    value.clone()
                } else {
                    users.clone()
                };
                (field.clone(), value)
            })
            .collect(),
    );
    match own.encode_single_object(&merged) {
        Ok(data) => Value::Record(vec![
            ("name".to_owned(), Value::String(name.to_owned())),
            ("data".to_owned(), Value::Bytes(data)),
        ]),
        Err(_) => user.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_merged_per_element_come_from_the_schema() {
        let relation = crate::schemas::axt_schema_text("axt.Relation").unwrap();
        let extension = crate::schemas::axt_schema_text("axt.Extension").unwrap();
        let schema = Schema::parse(&format!(
            r#"{{"type":"record","name":"T","namespace":"org.example","fields":[
            {{"name":"links","type":{{"type":"array","items":{relation}}}}},
            {{"name":"more","type":{{"type":"array","items":"axt.Relation"}}}},
            {{"name":"extensions","type":{{"type":"array","items":{extension}}}}},
            {{"name":"items","type":{{"type":"array","items":"string"}}}},
            {{"name":"maybe","type":["null",{{"type":"array","items":"axt.Relation"}}]}}]}}"#
        ))
        .unwrap();
        assert_eq!(
            element_lists_of(&schema),
            HashMap::from([
                ("links".to_owned(), ElementKey::Id),
                ("more".to_owned(), ElementKey::Id),
                ("extensions".to_owned(), ElementKey::Name),
            ])
        );
        let readers = HashMap::from([("org.example.T".to_owned(), schema.clone())]);
        let other = Schema::parse(r#""string""#).unwrap();
        let merge = element_merge_of(&schema, [&other], readers);
        assert_eq!(merge.lists.len(), 3);
        assert_eq!(merge.writers.len(), 2);
        assert!(merge.own.contains_key("org.example.T"));
        assert!(element_lists_of(&other).is_empty());
    }

    const ID: &str = "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80";

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::Record(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect())
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn data_with(
        held: Option<&HeldRecord>,
        version: i64,
        value: &Value,
        current: Option<&Value>,
        policy: &RecordPolicy,
        type_name: &str,
    ) -> Result<Applied, Error> {
        apply_record_message(
            held,
            current,
            RecordMessage {
                kind: RecordKind::Data,
                version,
                type_name: Some(type_name),
                value: Some(value),
            },
            policy,
            &ElementMerge::default(),
        )
    }

    fn data(
        held: Option<&HeldRecord>,
        version: i64,
        value: &Value,
        current: Option<&Value>,
    ) -> Applied {
        data_with(
            held,
            version,
            value,
            current,
            &RecordPolicy::default(),
            "a.Memo",
        )
        .unwrap()
    }

    fn removal(
        held: Option<&HeldRecord>,
        version: i64,
        current: Option<&Value>,
        kind: RecordKind,
        policy: &RecordPolicy,
    ) -> Applied {
        apply_record_message(
            held,
            current,
            RecordMessage {
                kind,
                version,
                type_name: None,
                value: None,
            },
            policy,
            &ElementMerge::default(),
        )
        .unwrap()
    }

    #[test]
    fn a_record_key_is_a_uuid_in_lower_case() {
        assert_eq!(
            record_key("3E8A5B14-7c29-4d6e-a0f3-1b9d2c7e5a46").as_deref(),
            Some("3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46")
        );
        assert_eq!(checked_record_key(&ID.to_uppercase()).unwrap(), ID);
        for bad in [
            "",
            "vet",
            "3e8a5b147c294d6ea0f31b9d2c7e5a46",
            "3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a4g",
            "{3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a4}",
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        ] {
            assert_eq!(record_key(bad), None, "{bad}");
            assert_eq!(
                checked_record_key(bad).unwrap_err().code(),
                Some(ErrorCode::RecordIdInvalid)
            );
        }
    }

    #[test]
    fn values_compare_member_by_member() {
        let a = record(vec![(
            "a",
            Value::Array(vec![
                Value::Long(1),
                record(vec![("b", Value::Bytes(vec![2]))]),
            ]),
        )]);
        assert!(same_value(&a, &a.clone()));
        assert!(same_value(
            &record(vec![("x", Value::Long(1)), ("y", Value::Long(2))]),
            &record(vec![("y", Value::Long(2)), ("x", Value::Long(1))]),
        ));
        assert!(!same_value(
            &Value::Array(vec![Value::Long(1), Value::Long(2)]),
            &Value::Array(vec![Value::Long(1), Value::Long(3)])
        ));
        assert!(!same_value(
            &Value::Array(vec![Value::Long(1)]),
            &Value::Array(vec![Value::Long(1), Value::Long(2)])
        ));
        assert!(!same_value(
            &record(vec![("a", Value::Long(1))]),
            &record(vec![("b", Value::Long(1))])
        ));
        assert_eq!(
            changed_fields(
                &record(vec![("a", Value::Long(1)), ("b", Value::Long(2))]),
                &record(vec![
                    ("a", Value::Long(1)),
                    ("b", Value::Long(3)),
                    ("c", Value::Long(4))
                ]),
            ),
            ["b", "c"]
        );
    }

    #[test]
    fn the_version_rule() {
        let x = record(vec![("t", s("x"))]);
        let first = data(None, 2, &x, None);
        assert_eq!(first.outcome, Outcome::Applied);
        assert_eq!(
            data(Some(&first.held), 2, &x, first.value.as_ref()).outcome,
            Outcome::Duplicate
        );
        assert_eq!(
            data(
                Some(&first.held),
                1,
                &record(vec![("t", s("y"))]),
                first.value.as_ref()
            )
            .outcome,
            Outcome::Stale
        );
        let policy = RecordPolicy::default();
        let empty = record(vec![]);
        assert_eq!(
            data_with(None, 0, &empty, None, &policy, "a.Memo")
                .unwrap_err()
                .code(),
            Some(ErrorCode::VersionInvalid)
        );
        assert_eq!(
            data_with(Some(&first.held), 3, &empty, None, &policy, "a.Other")
                .unwrap_err()
                .code(),
            Some(ErrorCode::TypeChanged)
        );
    }

    #[test]
    fn per_field_keeps_the_changed_fields_that_differ() {
        let first = data(
            None,
            1,
            &record(vec![("t", s("a")), ("n", s("x")), ("o", Value::Long(1))]),
            None,
        );
        let user = record(vec![("t", s("a")), ("n", s("mine")), ("o", Value::Long(2))]);
        let merged = data(
            Some(&first.held),
            2,
            &record(vec![("t", s("b")), ("n", s("y")), ("o", Value::Long(2))]),
            Some(&user),
        );
        assert_eq!(merged.outcome, Outcome::Merged);
        assert_eq!(merged.kept_fields, ["n"]);
        assert_eq!(
            merged.value,
            Some(record(vec![
                ("t", s("b")),
                ("n", s("mine")),
                ("o", Value::Long(2))
            ]))
        );
        let same = data(
            Some(&first.held),
            2,
            &record(vec![("t", s("b")), ("n", s("mine")), ("o", Value::Long(2))]),
            Some(&user),
        );
        assert_eq!(same.outcome, Outcome::Applied);
    }

    #[test]
    fn whole_record_keep_and_take() {
        let first = data(None, 1, &record(vec![("t", s("a"))]), None);
        let mine = record(vec![("t", s("mine"))]);
        let theirs = record(vec![("t", s("b"))]);
        let keep = RecordPolicy {
            local_changes: LocalChanges::WholeRecordKeep,
            ..RecordPolicy::default()
        };
        let take = RecordPolicy {
            local_changes: LocalChanges::WholeRecordTake,
            ..RecordPolicy::default()
        };
        let kept = data_with(Some(&first.held), 2, &theirs, Some(&mine), &keep, "a.Memo").unwrap();
        assert_eq!(kept.outcome, Outcome::Kept);
        assert_eq!(kept.value.as_ref(), Some(&mine));
        assert_eq!(kept.held.version, 2);
        let taken = data_with(Some(&first.held), 2, &theirs, Some(&mine), &take, "a.Memo").unwrap();
        assert_eq!(taken.outcome, Outcome::Applied);
        assert_eq!(taken.value.as_ref(), Some(&theirs));
    }

    #[test]
    fn deletions_withdrawals_and_tombstones() {
        let keep = RecordPolicy::default();
        let first = data(None, 1, &record(vec![("t", s("a"))]), None);
        let deleted = removal(
            Some(&first.held),
            2,
            first.value.as_ref(),
            RecordKind::Delete,
            &keep,
        );
        assert_eq!(deleted.held.state, HeldState::Tombstone);
        assert_eq!(deleted.held.type_name.as_deref(), Some("a.Memo"));
        assert_eq!(
            data(Some(&deleted.held), 3, &record(vec![("t", s("c"))]), None).outcome,
            Outcome::Applied
        );
        let mine = record(vec![("t", s("mine"))]);
        let kept = removal(Some(&first.held), 2, Some(&mine), RecordKind::Delete, &keep);
        assert_eq!(kept.outcome, Outcome::Kept);
        assert_eq!(kept.held.state, HeldState::There);
        let taken = take_kept_removal(&kept.held).unwrap();
        assert_eq!(
            (taken.outcome, taken.held.state),
            (Outcome::Applied, HeldState::Tombstone)
        );
        assert_eq!(take_kept_removal(&first.held), None);
        let delete = RecordPolicy {
            delete_with_local_changes: DeleteWithLocalChanges::Delete,
            ..RecordPolicy::default()
        };
        assert_eq!(delete.withdraw_policy(), DeleteWithLocalChanges::Delete);
        let dropped = removal(
            Some(&first.held),
            2,
            Some(&mine),
            RecordKind::Delete,
            &delete,
        );
        assert_eq!(dropped.outcome, Outcome::Applied);
        let withdrawn = removal(None, 4, None, RecordKind::Withdraw, &keep);
        assert_eq!(withdrawn.outcome, Outcome::Withdrawn);
        assert_eq!(withdrawn.held.state, HeldState::Withdrawn);
        assert_eq!(HeldState::Withdrawn.code(), "withdrawn");
        assert_eq!(Outcome::Withdrawn.as_str(), "WITHDRAWN");
    }

    #[test]
    fn a_record_its_user_deleted_stays_deleted() {
        let policy = RecordPolicy::default();
        let gone = HeldRecord::new(1, HeldState::DeletedByUser, Some("a.Memo".into()));
        let data2 = data(Some(&gone), 2, &record(vec![("t", s("b"))]), None);
        assert_eq!(data2.outcome, Outcome::Kept);
        assert_eq!(data2.held.state, HeldState::DeletedByUser);
        assert_eq!(
            removal(Some(&gone), 3, None, RecordKind::Delete, &policy).outcome,
            Outcome::Applied
        );
        assert_eq!(
            removal(Some(&gone), 3, None, RecordKind::Withdraw, &policy).outcome,
            Outcome::Withdrawn
        );
    }

    fn cat() -> Schema {
        Schema::parse(
            r#"{"type":"record","name":"Cat","namespace":"org.example","fields":[
            {"name":"tasso","type":"string"},{"name":"fur","type":"string"}]}"#,
        )
        .unwrap()
    }

    fn extension(name: &str, data: Vec<u8>) -> Value {
        record(vec![("name", s(name)), ("data", Value::Bytes(data))])
    }

    fn ext(name: &str, tasso: &str, fur: &str) -> Value {
        let data = cat()
            .encode_single_object(&record(vec![("tasso", s(tasso)), ("fur", s(fur))]))
            .unwrap();
        extension(name, data)
    }

    fn unknown(name: &str, byte: u8) -> Value {
        let mut data = vec![0xc3, 0x01];
        data.extend([0; 8]);
        data.push(byte);
        extension(name, data)
    }

    fn merge(taken: Vec<Value>, user: Vec<Value>, message: Vec<Value>) -> Applied {
        let cat = cat();
        let elements = ElementMerge {
            lists: HashMap::from([("extensions".to_owned(), ElementKey::Name)]),
            writers: HashMap::from([(cat.fingerprint().0, cat.clone())]),
            own: HashMap::from([("org.example.Cat".to_owned(), cat)]),
        };
        let policy = RecordPolicy::default();
        let first = data(
            None,
            1,
            &record(vec![("extensions", Value::Array(taken))]),
            None,
        );
        apply_record_message(
            Some(&first.held),
            Some(&record(vec![("extensions", Value::Array(user))])),
            RecordMessage {
                kind: RecordKind::Data,
                version: 2,
                type_name: Some("a.Memo"),
                value: Some(&record(vec![("extensions", Value::Array(message))])),
            },
            &policy,
            &elements,
        )
        .unwrap()
    }

    fn extensions(applied: &Applied) -> Value {
        applied
            .value
            .as_ref()
            .unwrap()
            .field("extensions")
            .unwrap()
            .clone()
    }

    #[test]
    fn a_known_extension_type_merges_field_by_field() {
        let applied = merge(
            vec![ext("org.example.Cat", "1", "tabby")],
            vec![ext("org.example.Cat", "1", "black")],
            vec![ext("org.example.Cat", "2", "tabby")],
        );
        assert_eq!(applied.outcome, Outcome::Merged);
        assert_eq!(
            extensions(&applied),
            Value::Array(vec![ext("org.example.Cat", "2", "black")])
        );
    }

    #[test]
    fn an_unknown_extension_stays_whole_and_added_and_removed_stay() {
        let applied = merge(
            vec![unknown("org.example.A", 1), unknown("org.example.B", 1)],
            vec![unknown("org.example.A", 2), unknown("org.example.C", 1)],
            vec![
                unknown("org.example.B", 3),
                unknown("org.example.A", 3),
                unknown("org.example.D", 1),
            ],
        );
        assert_eq!(
            extensions(&applied),
            Value::Array(vec![
                unknown("org.example.A", 2),
                unknown("org.example.D", 1),
                unknown("org.example.C", 1),
            ])
        );
        assert_eq!(applied.kept_fields, ["extensions"]);
    }

    #[test]
    fn a_changed_extension_stays_when_the_message_drops_it() {
        let applied = merge(
            vec![unknown("org.example.A", 1)],
            vec![unknown("org.example.A", 2)],
            vec![],
        );
        assert_eq!(
            extensions(&applied),
            Value::Array(vec![unknown("org.example.A", 2)])
        );
    }

    #[test]
    fn an_extension_that_does_not_decode_stays_as_the_user_left_it() {
        let broken = extension("org.example.Cat", vec![0xc3, 0x01, 0]);
        let other = unknown("org.example.Cat", 2);
        let Value::Bytes(good) = ext("org.example.Cat", "", "")
            .field("data")
            .unwrap()
            .clone()
        else {
            panic!()
        };
        let mut trailing = good[..10].to_vec();
        trailing.push(0x7f);
        let bad = extension("org.example.Cat", trailing);
        for user in [broken, other, bad] {
            assert_eq!(
                extensions(&merge(
                    vec![ext("org.example.Cat", "", "")],
                    vec![user.clone()],
                    vec![ext("org.example.Cat", "1", "")],
                )),
                Value::Array(vec![user])
            );
        }
    }

    #[test]
    fn at_most_the_limit_of_elements() {
        let many = (0..=32)
            .map(|i| unknown(&format!("org.example.E{i}"), 1))
            .collect();
        let Value::Array(merged) = extensions(&merge(vec![], many, vec![])) else {
            panic!()
        };
        assert_eq!(merged.len(), 32);
    }

    #[test]
    fn relations_merge_per_element_by_their_id() {
        let relation = |id: &str, note: &str| {
            record(vec![
                ("id", s(id)),
                ("kind", s("axt.related")),
                (
                    "target",
                    record(vec![("uri", s("https://example.org")), ("text", s(""))]),
                ),
                ("note", s(note)),
            ])
        };
        let a = "3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46";
        let b = "1f2e3d4c-5b6a-4978-8a96-a5b4c3d2e1f0";
        let first = data(
            None,
            1,
            &record(vec![("links", Value::Array(vec![relation(a, "")]))]),
            None,
        );
        let elements = ElementMerge {
            lists: HashMap::from([("links".to_owned(), ElementKey::Id)]),
            ..ElementMerge::default()
        };
        let applied = apply_record_message(
            Some(&first.held),
            Some(&record(vec![(
                "links",
                Value::Array(vec![relation(a, ""), relation(b, "mine")]),
            )])),
            RecordMessage {
                kind: RecordKind::Data,
                version: 2,
                type_name: Some("a.Memo"),
                value: Some(&record(vec![(
                    "links",
                    Value::Array(vec![relation(a, "theirs")]),
                )])),
            },
            &RecordPolicy::default(),
            &elements,
        )
        .unwrap();
        assert_eq!(
            applied.value.unwrap().field("links").unwrap(),
            &Value::Array(vec![relation(a, "theirs"), relation(b, "mine")])
        );
        assert_eq!(applied.outcome, Outcome::Merged);
    }
}
