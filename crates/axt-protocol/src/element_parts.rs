//! Proposals of single elements: element parts and parts within an extension (AXT
//! `spec/shares.md`, sections 19.3 and 20; `spec/sync.md`, sections 25.1, 25.2 and 25.9).

use std::collections::{BTreeSet, HashSet};

use crate::device_sets::Key;
use crate::error::{Error, ErrorCode};
use crate::links::{extensions_problem, relations_problem, shared_relations};
use crate::records::ElementKey;
use crate::schema::Schema;
use crate::value::Value;

/// The name of an entry that is a part: the list, the key text of the element, and for
/// a part within an extension the field's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartName {
    /// The list's field.
    pub(crate) list: String,
    /// The key text of the element.
    pub(crate) key: String,
    /// The field within the extension, for a part within an extension.
    pub(crate) field: Option<String>,
}

/// `name` as a part, or `None` for a top-level field.
///
/// # Errors
///
/// `INVALID_MESSAGE` for a name with a `/` that is no part.
pub(crate) fn part_name(name: &str) -> Result<Option<PartName>, Error> {
    let segments: Vec<&str> = name.split('/').collect();
    match segments.as_slice() {
        [_] => Ok(None),
        [list, key] | [list, key, _] if segments.iter().all(|s| !s.is_empty()) => {
            Ok(Some(PartName {
                list: (*list).to_owned(),
                key: (*key).to_owned(),
                field: segments.get(2).map(|f| (*f).to_owned()),
            }))
        }
        _ => Err(Error::axt(
            ErrorCode::InvalidMessage,
            format!("{name} is no part"),
        )),
    }
}

/// The string of the field `name` of a record, or the empty string.
fn text<'a>(record: &'a Value, name: &str) -> &'a str {
    match record.field(name) {
        Some(Value::String(s)) => s,
        _ => "",
    }
}

/// The key text of `element` of a list keyed by `key` (sync.md, section 25.1).
pub(crate) fn key_text(key: ElementKey, element: &Value) -> String {
    match key {
        ElementKey::Id => text(element, "id").to_lowercase(),
        ElementKey::Name => text(element, "name").to_owned(),
    }
}

/// The element of `list` whose key text is `text`, or `None`.
pub(crate) fn element_of<'a>(key: ElementKey, list: &'a [Value], text: &str) -> Option<&'a Value> {
    list.iter().find(|e| key_text(key, e) == text)
}

/// Whether `element` of a list keyed by `key` goes to a receiver whose shares leave out
/// the links (shares.md, section 19.1).
pub(crate) fn goes_without_links(
    key: ElementKey,
    element: &Value,
    shared: &HashSet<String>,
    own_keys: &BTreeSet<Key>,
) -> bool {
    key == ElementKey::Id
        && !shared_relations(std::slice::from_ref(element), shared, own_keys).is_empty()
}

/// The value of an element part under `items`: `None` for a removal mark, or the
/// element.
///
/// # Errors
///
/// `UNDECODABLE` for bytes that are neither.
pub(crate) fn decode_element_part(items: &Schema, bytes: &[u8]) -> Result<Option<Value>, Error> {
    let undecodable = |why: String| Error::axt(ErrorCode::Undecodable, why);
    match bytes.split_first() {
        Some((0, [])) => Ok(None),
        Some((2, rest)) => items.decode_datum(rest).map(Some).map_err(undecodable),
        _ => Err(undecodable("no union of an element".into())),
    }
}

/// The bytes of the element part of `element` under `items`: the removal mark for
/// `None`.
pub(crate) fn encode_element_part(
    items: &Schema,
    element: Option<&Value>,
) -> Result<Vec<u8>, String> {
    match element {
        None => Ok(vec![0]),
        Some(element) => {
            let mut out = vec![2];
            out.extend(items.encode_datum(element)?);
            Ok(out)
        }
    }
}

/// The path of the first value of `element`, the value of the element part `name` of a
/// list keyed by `key`, that breaks a rule of its type or whose key is not the key text
/// `text` of the name; `None` when it keeps them (shares.md, section 20.1, step 9).
pub(crate) fn element_problem(
    key: ElementKey,
    name: &str,
    text: &str,
    element: &Value,
) -> Option<String> {
    let list = std::slice::from_ref(element);
    let problem = match key {
        ElementKey::Id => relations_problem(list, ""),
        ElementKey::Name => extensions_problem(list, ""),
    };
    if let Some(problem) = problem {
        return Some(format!(
            "{name}{}",
            problem.strip_prefix("[0]").unwrap_or(&problem)
        ));
    }
    if key_text(key, element) != text {
        let member = match key {
            ElementKey::Id => "id",
            ElementKey::Name => "name",
        };
        return Some(format!("{name}.{member}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::Record(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect())
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn extension(name: &str, data: Vec<u8>) -> Value {
        record(vec![("name", s(name)), ("data", Value::Bytes(data))])
    }

    #[test]
    fn a_name_is_a_field_or_a_part() {
        assert_eq!(part_name("title").unwrap(), None);
        assert_eq!(
            part_name("relations/abc").unwrap(),
            Some(PartName {
                list: "relations".into(),
                key: "abc".into(),
                field: None,
            })
        );
        assert_eq!(
            part_name("extensions/a.B/f").unwrap().unwrap().field,
            Some("f".into())
        );
        for bad in ["a/", "/a", "a//b", "a/b/c/d"] {
            assert_eq!(
                part_name(bad).unwrap_err().code(),
                Some(ErrorCode::InvalidMessage)
            );
        }
    }

    #[test]
    fn the_key_text_of_an_element() {
        let relation = record(vec![("id", s("3E8A5B14-7C29-4D6E-A0F3-1B9D2C7E5A46"))]);
        assert_eq!(
            key_text(ElementKey::Id, &relation),
            "3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46"
        );
        let list = vec![extension("a.B", vec![]), extension("a.C", vec![])];
        assert_eq!(element_of(ElementKey::Name, &list, "a.C"), list.get(1));
        assert_eq!(element_of(ElementKey::Name, &list, "a.D"), None);
    }

    #[test]
    fn an_element_part_is_a_union_of_a_removal_and_the_element() {
        let items = Schema::parse(
            r#"{"type":"record","name":"E","fields":[{"name":"name","type":"string"}]}"#,
        )
        .unwrap();
        let element = record(vec![("name", s("x"))]);
        let bytes = encode_element_part(&items, Some(&element)).unwrap();
        assert_eq!(bytes, vec![2, 2, b'x']);
        assert_eq!(decode_element_part(&items, &bytes).unwrap(), Some(element));
        assert_eq!(encode_element_part(&items, None).unwrap(), vec![0]);
        assert_eq!(decode_element_part(&items, &[0]).unwrap(), None);
        for bad in [&[][..], &[0, 0], &[4]] {
            assert_eq!(
                decode_element_part(&items, bad).unwrap_err().code(),
                Some(ErrorCode::Undecodable)
            );
        }
    }

    #[test]
    fn an_element_whose_key_is_not_its_name_is_a_problem() {
        let name = "extensions/a.B";
        let good = extension("a.B", vec![0xc3, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(element_problem(ElementKey::Name, name, "a.B", &good), None);
        assert_eq!(
            element_problem(ElementKey::Name, name, "a.C", &good).as_deref(),
            Some("extensions/a.B.name")
        );
        let bad = extension("a.B", vec![1]);
        assert_eq!(
            element_problem(ElementKey::Name, name, "a.B", &bad).as_deref(),
            Some("extensions/a.B.data")
        );
    }
}
