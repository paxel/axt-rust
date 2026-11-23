//! The rules of relations and extensions that every receiver checks (AXT
//! `spec/fields.md`, sections 11.4 and 12.3).

use std::collections::HashSet;

use crate::limits::{
    FIELDS_EXTENSION_DATA, FIELDS_EXTENSION_NAME, FIELDS_EXTENSIONS,
    FIELDS_RELATION_ATTRIBUTE_NAME, FIELDS_RELATION_ATTRIBUTE_VALUE, FIELDS_RELATION_ATTRIBUTES,
    FIELDS_RELATION_NAME, FIELDS_RELATION_NOTE, FIELDS_RELATION_TEXT, FIELDS_RELATION_URI,
    FIELDS_RELATIONS,
};
use crate::records::record_key;
use crate::time_values::is_valid_time_value;
use crate::value::Value;

/// Whether `name` is an Avro name: an ASCII letter or `_`, then ASCII letters, digits
/// and `_`.
pub(crate) fn is_avro_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Whether `text` is a full name of Avro with a namespace, of at most `max` bytes.
fn is_full_name(text: &str, max: usize) -> bool {
    text.len() <= max && text.contains('.') && text.split('.').all(is_avro_name)
}

/// The string of the field `name` of a record, or the empty string.
fn text<'a>(record: &'a Value, name: &str) -> &'a str {
    match record.field(name) {
        Some(Value::String(s)) => s,
        _ => "",
    }
}

/// The path of the first value of the list of relations `list` at `path` that breaks a
/// rule, in the order of the encoding, or `None`.
pub(crate) fn relations_problem(list: &[Value], path: &str) -> Option<String> {
    if list.len() > FIELDS_RELATIONS {
        return Some(path.to_owned());
    }
    let mut ids = HashSet::new();
    for (i, relation) in list.iter().enumerate() {
        let at = format!("{path}[{i}]");
        if !record_key(text(relation, "id")).is_some_and(|key| ids.insert(key)) {
            return Some(format!("{at}.id"));
        }
        if let Some(found) = relation_problem(relation, &at) {
            return Some(found);
        }
    }
    None
}

fn relation_problem(relation: &Value, at: &str) -> Option<String> {
    if !is_full_name(text(relation, "kind"), FIELDS_RELATION_NAME) {
        return Some(format!("{at}.kind"));
    }
    let target = match relation.field("target") {
        Some(Value::Union { value, .. }) => value.as_ref(),
        Some(other) => other,
        None => &Value::Null,
    };
    if target.field("uri").is_some() {
        let uri = text(target, "uri").len();
        if !(1..=FIELDS_RELATION_URI).contains(&uri) {
            return Some(format!("{at}.target.uri"));
        }
    } else {
        if record_key(text(target, "id")).is_none() {
            return Some(format!("{at}.target.id"));
        }
        let kind = text(target, "type");
        if !kind.is_empty() && !is_full_name(kind, FIELDS_RELATION_NAME) {
            return Some(format!("{at}.target.type"));
        }
    }
    if text(target, "text").len() > FIELDS_RELATION_TEXT {
        return Some(format!("{at}.target.text"));
    }
    if text(relation, "note").len() > FIELDS_RELATION_NOTE {
        return Some(format!("{at}.note"));
    }
    for member in ["start", "end"] {
        if let Some(time @ Value::Record(_)) = relation.field(member)
            && !is_valid_time_value("axt.DateTime", time)
        {
            return Some(format!("{at}.{member}"));
        }
    }
    let attributes_break = match relation.field("attributes") {
        Some(Value::Map(attributes)) => {
            attributes.len() > FIELDS_RELATION_ATTRIBUTES
                || attributes.iter().any(|(name, value)| {
                    let value = match value {
                        Value::String(s) => s.len(),
                        _ => 0,
                    };
                    name.is_empty()
                        || name.len() > FIELDS_RELATION_ATTRIBUTE_NAME
                        || value > FIELDS_RELATION_ATTRIBUTE_VALUE
                })
        }
        _ => false,
    };
    attributes_break.then(|| format!("{at}.attributes"))
}

/// The path of the first value of the list of extensions `list` at `path` that breaks a
/// rule, in the order of the encoding, or `None`.
pub(crate) fn extensions_problem(list: &[Value], path: &str) -> Option<String> {
    if list.len() > FIELDS_EXTENSIONS {
        return Some(path.to_owned());
    }
    let mut names = HashSet::new();
    for (i, extension) in list.iter().enumerate() {
        let name = text(extension, "name");
        if !is_full_name(name, FIELDS_EXTENSION_NAME) || !names.insert(name) {
            return Some(format!("{path}[{i}].name"));
        }
        let data_keeps = match extension.field("data") {
            Some(Value::Bytes(data)) => {
                (10..=FIELDS_EXTENSION_DATA).contains(&data.len())
                    && data.starts_with(&[0xc3, 0x01])
            }
            _ => false,
        };
        if !data_keeps {
            return Some(format!("{path}[{i}].data"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::Record(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect())
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn relation(text: &str, note: &str, start: Value, attributes: &[(&str, &str)]) -> Value {
        record(vec![
            ("id", s("3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46")),
            ("kind", s("axt.related")),
            (
                "target",
                Value::Union {
                    index: 1,
                    branch: "axt.RelationOutsideTarget".into(),
                    value: Box::new(record(vec![
                        ("uri", s("https://example.org")),
                        ("text", s(text)),
                    ])),
                },
            ),
            ("note", s(note)),
            ("start", start),
            ("end", Value::Null),
            (
                "attributes",
                Value::Map(
                    attributes
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), s(v)))
                        .collect::<BTreeMap<_, _>>(),
                ),
            ),
        ])
    }

    #[test]
    fn a_relation_that_breaks_a_limit_is_named_by_its_member() {
        let ok = relation("", "", Value::Null, &[]);
        assert_eq!(relations_problem(std::slice::from_ref(&ok), "r"), None);
        assert_eq!(
            relations_problem(&[relation(&"x".repeat(257), "", Value::Null, &[])], "r").as_deref(),
            Some("r[0].target.text")
        );
        assert_eq!(
            relations_problem(&[relation("", &"x".repeat(4097), Value::Null, &[])], "r").as_deref(),
            Some("r[0].note")
        );
        let month_13 = record(vec![
            ("year", Value::Int(2026)),
            ("month", Value::Int(13)),
            ("day", Value::Int(1)),
            ("hour", Value::Int(0)),
            ("minute", Value::Int(0)),
            ("second", Value::Int(0)),
            ("millisecond", Value::Int(0)),
            ("zone", Value::Null),
            ("offset_seconds", Value::Null),
            ("instant_ms", Value::Null),
        ]);
        assert_eq!(
            relations_problem(&[relation("", "", month_13, &[])], "r").as_deref(),
            Some("r[0].start")
        );
        assert_eq!(
            relations_problem(&[relation("", "", Value::Null, &[("", "x")])], "r").as_deref(),
            Some("r[0].attributes")
        );
        assert_eq!(
            relations_problem(&[ok.clone(), ok.clone()], "r").as_deref(),
            Some("r[1].id")
        );
        assert_eq!(relations_problem(&vec![ok; 257], "r").as_deref(), Some("r"));
    }

    fn extension(name: &str, data: &[u8]) -> Value {
        record(vec![
            ("name", s(name)),
            ("data", Value::Bytes(data.to_vec())),
        ])
    }

    #[test]
    fn extensions_keep_their_rules() {
        let data = [0xc3, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            extensions_problem(&[extension("org.example.A", &data)], "e"),
            None
        );
        let many: Vec<Value> = (0..=32)
            .map(|i| extension(&format!("org.example.A{i}"), &data))
            .collect();
        assert_eq!(extensions_problem(&many, "e").as_deref(), Some("e"));
        assert_eq!(
            extensions_problem(&[extension("A", &data)], "e").as_deref(),
            Some("e[0].name")
        );
        assert_eq!(
            extensions_problem(
                &[
                    extension("org.example.A", &data),
                    extension("org.example.A", &data)
                ],
                "e"
            )
            .as_deref(),
            Some("e[1].name")
        );
        assert_eq!(
            extensions_problem(&[extension("org.example.A", &[0xc3, 0x01])], "e").as_deref(),
            Some("e[0].data")
        );
        let mut wrong = data;
        wrong[1] = 0;
        assert_eq!(
            extensions_problem(&[extension("org.example.A", &wrong)], "e").as_deref(),
            Some("e[0].data")
        );
    }
}
