//! Relations across senders: which record a relation points at, and which relations
//! point at a record (AXT `spec/records.md`, section 10).

use std::cell::RefCell;

use crate::avro::Met;
use crate::device_sets::{DeviceSetReceiver, Key, KeyState, KnownSender, RecordState};
use crate::records::record_key;
use crate::schema::Schema;
use crate::value::Value;

/// A relation with a record target that a receiver holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldRelation {
    /// The relation's id.
    pub(crate) id: String,
    /// The name of the sender, or of the own set, of the record that holds it.
    pub(crate) holder_sender: String,
    /// The id of the record that holds it.
    pub(crate) holder_id: String,
    /// The key in the target's `sender`, or `None`.
    pub(crate) target_sender: Option<Key>,
    /// The target's id.
    pub(crate) target_id: String,
}

/// What a relation resolves to: the sender it names, `None` for a key of no known
/// sender, and whether the receiver holds the target record, not as a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolution {
    pub(crate) sender: Option<String>,
    pub(crate) resolved: bool,
}

/// A relation that points at a record: the record that holds it, and its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkFrom {
    pub(crate) sender: String,
    pub(crate) id: String,
    pub(crate) relation: String,
}

/// A record a relation points at, and the relations that point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkedFrom {
    pub(crate) sender: String,
    pub(crate) id: String,
    pub(crate) from: Vec<LinkFrom>,
}

/// Resolves relations as a receiver that knows the senders of `receiver` and its own
/// set `own` (section 10.2).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelationResolver<'a> {
    pub(crate) receiver: &'a DeviceSetReceiver,
    /// The receiver's own device set and its records.
    pub(crate) own: &'a KnownSender,
}

impl<'a> RelationResolver<'a> {
    /// The sender, or the own set, of the name `name` now.
    fn sender(&self, name: &str) -> Option<&'a KnownSender> {
        let current = self.receiver.sender_named(name);
        if current == self.own.name {
            return Some(self.own);
        }
        self.receiver.senders.iter().find(|s| s.name == current)
    }

    /// The sender that `relation` names, and whether it resolves.
    pub(crate) fn resolve(&self, relation: &HeldRelation) -> Resolution {
        let sender = match &relation.target_sender {
            None => self.sender(&relation.holder_sender),
            Some(key) if self.own.current.contains(key) || self.own.removed.contains(key) => {
                Some(self.own)
            }
            Some(key) if self.receiver.state_of(key) == KeyState::Refused => None,
            Some(key) => self.receiver.sender_of_key(key),
        };
        let Some(sender) = sender else {
            return Resolution {
                sender: None,
                resolved: false,
            };
        };
        let id = record_key(&relation.target_id);
        let resolved = id.as_ref().is_some_and(|id| {
            sender
                .records
                .iter()
                .find(|(key, _)| record_key(key).as_ref() == Some(id))
                .is_some_and(|(_, held)| held.state == RecordState::There)
        });
        Resolution {
            sender: Some(sender.name.clone()),
            resolved,
        }
    }

    /// The records to which at least one of `relations` resolves, with the relations,
    /// sorted by sender and id, their relations by holder and id.
    pub(crate) fn linked_from(&self, relations: &[HeldRelation]) -> Vec<LinkedFrom> {
        let mut out: Vec<LinkedFrom> = Vec::new();
        for relation in relations {
            let resolution = self.resolve(relation);
            let (Some(sender), true, Some(id)) = (
                resolution.sender,
                resolution.resolved,
                record_key(&relation.target_id),
            ) else {
                continue;
            };
            let from = LinkFrom {
                sender: self
                    .receiver
                    .sender_named(&relation.holder_sender)
                    .to_owned(),
                id: record_key(&relation.holder_id).unwrap_or_else(|| relation.holder_id.clone()),
                relation: relation.id.clone(),
            };
            match out.iter_mut().find(|l| l.sender == sender && l.id == id) {
                Some(linked) => linked.from.push(from),
                None => out.push(LinkedFrom {
                    sender,
                    id,
                    from: vec![from],
                }),
            }
        }
        out.sort_by(|a, b| (&a.sender, &a.id).cmp(&(&b.sender, &b.id)));
        for linked in &mut out {
            linked.from.sort_by(|a, b| {
                (&a.sender, &a.id, &a.relation).cmp(&(&b.sender, &b.id, &b.relation))
            });
        }
        out
    }
}

/// A relation with a record target as a record holds it: the relation's id, the key in
/// the target's `sender` or `None`, and the target's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordTarget {
    pub(crate) id: String,
    pub(crate) sender: Option<Key>,
    pub(crate) target: String,
}

/// The string of the field `name` of a record, or the empty string.
fn text<'a>(record: &'a Value, name: &str) -> &'a str {
    match record.field(name) {
        Some(Value::String(s)) => s,
        _ => "",
    }
}

/// The target of a relation, its branch's value where it is a union.
pub(crate) fn target_of(relation: &Value) -> &Value {
    match relation.field("target") {
        Some(Value::Union { value, .. }) => value,
        Some(other) => other,
        None => &Value::Null,
    }
}

/// The key in the `sender` of a record target: `Ok(None)` for `null`, `Err(())` for a
/// value that is no key of 32 bytes.
pub(crate) fn target_sender(target: &Value) -> Result<Option<Key>, ()> {
    match target.field("sender") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Fixed(bytes) | Value::Bytes(bytes)) => {
            bytes.as_slice().try_into().map(Some).map_err(|_| ())
        }
        Some(_) => Err(()),
    }
}

/// The relations with a record target in `value`, a record of `schema`, in the order of
/// the encoding.
pub(crate) fn record_targets(schema: &Schema, value: &Value) -> Vec<RecordTarget> {
    let found = RefCell::new(Vec::new());
    let rule = |met: Met<'_>, value: &Value, _: &str| match (met, value) {
        (Met::Items("axt.Relation"), Value::Array(list)) => {
            for relation in list {
                let target = target_of(relation);
                if target.field("id").is_none() {
                    continue;
                }
                // A sender that is no key cannot be resolved; a decoded record has none.
                let Ok(sender) = target_sender(target) else {
                    continue;
                };
                found.borrow_mut().push(RecordTarget {
                    id: text(relation, "id").to_owned(),
                    sender,
                    target: text(target, "id").to_owned(),
                });
            }
            Some(None)
        }
        _ => None,
    };
    // The walk only fails for a schema whose names do not resolve, which a parsed
    // schema always does.
    let _ = schema.first_problem(value, "", &rule);
    found.into_inner()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::device_sets::KeptRecord;
    use crate::schemas::axt_schema_text;

    const R1: &str = "00000001-4e1a-4b0e-9c22-000000000001";
    const R2: &str = "00000002-4e1a-4b0e-9c22-000000000002";
    const T1: &str = "00000001-5e55-4d0e-8a11-000000000001";
    const T2: &str = "00000002-5e55-4d0e-8a11-000000000002";
    const T3: &str = "00000003-5e55-4d0e-8a11-000000000003";

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::Record(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect())
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn record_target(id: &str, sender: Option<Key>) -> Value {
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

    fn outside_target() -> Value {
        Value::Union {
            index: 1,
            branch: "axt.RelationOutsideTarget".into(),
            value: Box::new(record(vec![
                ("uri", s("https://example.org")),
                ("text", s("")),
            ])),
        }
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

    #[test]
    fn relations_are_found_in_nested_records_lists_maps_and_unions() {
        let relation_schema = axt_schema_text("axt.Relation").unwrap();
        let schema = Schema::parse(&format!(
            r#"{{"type":"record","name":"Holder","namespace":"org.example","fields":[
            {{"name":"inner","type":["null",{{"type":"record","name":"Inner","fields":[
              {{"name":"links","type":{{"type":"array","items":{relation_schema}}}}}]}}]}},
            {{"name":"lists","type":{{"type":"array","items":"org.example.Inner"}}}},
            {{"name":"maps","type":{{"type":"map","values":{{"type":"array","items":"axt.Relation"}}}}}},
            {{"name":"none","type":["null","org.example.Inner"]}}]}}"#
        ))
        .unwrap();
        let mut sender = [0; 32];
        sender[0] = 0xab;
        let inner = |links: Vec<Value>| record(vec![("links", Value::Array(links))]);
        let value = record(vec![
            (
                "inner",
                inner(vec![
                    relation(R1, record_target(T1, None)),
                    relation(R2, outside_target()),
                ]),
            ),
            (
                "lists",
                Value::Array(vec![inner(vec![relation(
                    R2,
                    record_target(T2, Some(sender)),
                )])]),
            ),
            (
                "maps",
                Value::Map(BTreeMap::from([(
                    "a".to_owned(),
                    Value::Array(vec![relation(R1, record_target(T3, None))]),
                )])),
            ),
            ("none", Value::Null),
        ]);
        let target = |id: &str, sender: Option<Key>, target: &str| RecordTarget {
            id: id.into(),
            sender,
            target: target.into(),
        };
        assert_eq!(
            record_targets(&schema, &value),
            [
                target(R1, None, T1),
                target(R2, Some(sender), T2),
                target(R1, None, T3),
            ]
        );
    }

    fn kept() -> KeptRecord {
        KeptRecord {
            version: 1,
            state: RecordState::There,
        }
    }

    #[test]
    fn links_are_sorted_by_holder_then_by_relation() {
        let s = KnownSender {
            name: "s".into(),
            current: BTreeSet::from([[0xaa; 32]]),
            records: BTreeMap::from([(T1.to_owned(), kept()), (T2.to_owned(), kept())]),
            ..KnownSender::default()
        };
        let receiver = DeviceSetReceiver {
            senders: vec![s],
            ..DeviceSetReceiver::default()
        };
        let own = KnownSender {
            name: "me".into(),
            current: BTreeSet::from([[0xbb; 32]]),
            ..KnownSender::default()
        };
        let resolver = RelationResolver {
            receiver: &receiver,
            own: &own,
        };
        let held = |id: &str, holder: &str, target: &str| HeldRelation {
            id: id.into(),
            holder_sender: "s".into(),
            holder_id: holder.into(),
            target_sender: None,
            target_id: target.into(),
        };
        let linked = resolver.linked_from(&[held(R2, T3, T1), held(R1, T3, T1), held(R1, T2, T1)]);
        assert_eq!(linked.len(), 1);
        assert_eq!(
            (linked[0].sender.as_str(), linked[0].id.as_str()),
            ("s", T1)
        );
        let from = |id: &str, relation: &str| LinkFrom {
            sender: "s".into(),
            id: id.into(),
            relation: relation.into(),
        };
        assert_eq!(linked[0].from, [from(T2, R1), from(T3, R1), from(T3, R2)]);
        assert_eq!(
            resolver.resolve(&held(R1, T2, "no uuid")),
            Resolution {
                sender: Some("s".into()),
                resolved: false,
            }
        );
        // A key of the own set names the own records.
        let mut to_own = held(R1, T2, T1);
        to_own.target_sender = Some([0xbb; 32]);
        assert_eq!(
            resolver.resolve(&to_own),
            Resolution {
                sender: Some("me".into()),
                resolved: false,
            }
        );
    }
}
