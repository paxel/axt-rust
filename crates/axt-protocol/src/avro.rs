//! The Avro of the library: the crate `apache-avro`, behind the library's own types.
//!
//! Nothing of `apache-avro` leaves this module and [`crate::schema`]; values cross as
//! [`Value`], failures as their text.

use std::collections::{BTreeMap, HashMap, HashSet};

use apache_avro::Schema as AvroSchema;
use apache_avro::reader::datum::GenericDatumReader;
use apache_avro::schema::{NamesRef, ResolvedSchema, UnionSchema};
use apache_avro::types::Value as AvroValue;
use apache_avro::writer::datum::GenericDatumWriter;
use serde_json::Value as Json;

use crate::value::Value;

/// The two bytes that begin a single-object encoding.
const SINGLE_OBJECT_MARKER: [u8; 2] = [0xc3, 0x01];

/// `schema` without its `logicalType` attributes, which leaves its Parsing Canonical
/// Form, and so its fingerprint, as it is, and makes its values those of the underlying
/// types: a record id stays the text it was received as.
pub(crate) fn without_logical_types(schema: &Json) -> Json {
    match schema {
        Json::Object(members) => Json::Object(
            members
                .iter()
                .filter(|(name, _)| name.as_str() != "logicalType")
                .map(|(name, value)| (name.clone(), without_logical_types(value)))
                .collect(),
        ),
        Json::Array(items) => Json::Array(items.iter().map(without_logical_types).collect()),
        other => other.clone(),
    }
}

/// Parses the JSON text of a schema, without its logical types.
pub(crate) fn parse(text: &str) -> Result<AvroSchema, String> {
    let json: Json = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let raw = without_logical_types(&json);
    AvroSchema::parse(raw).map_err(|e| e.to_string())
}

/// The Parsing Canonical Form of a schema parsed by [`parse`] (Avro 1.12 specification,
/// "Parsing Canonical Form for Schemas").
///
/// Written here rather than taken from `apache-avro`, whose canonical form panics on a
/// custom attribute named `size`, `precision` or `scale` that is not a number.
pub(crate) fn canonical_form(schema: &AvroSchema) -> Result<String, String> {
    let mut out = String::new();
    write_canonical(schema, &mut HashSet::new(), &mut out)?;
    Ok(out)
}

/// A string as JSON.
fn quoted(text: &str) -> String {
    Json::String(text.to_owned()).to_string()
}

/// Writes the canonical form of `schema`; a named type already written is its full name.
fn write_canonical(
    schema: &AvroSchema,
    defined: &mut HashSet<String>,
    out: &mut String,
) -> Result<(), String> {
    // The start of a named type: its full name only, if it was written before.
    let mut named = |kind: &str, full_name: String, out: &mut String| {
        let first = defined.insert(full_name.clone());
        out.push_str(&if first {
            format!("{{\"name\":{},\"type\":\"{kind}\"", quoted(&full_name))
        } else {
            quoted(&full_name)
        });
        first
    };
    match schema {
        AvroSchema::Record(record) => {
            if named("record", record.name.fullname(None), out) {
                out.push_str(",\"fields\":[");
                for (i, field) in record.fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!("{{\"name\":{},\"type\":", quoted(&field.name)));
                    write_canonical(&field.schema, defined, out)?;
                    out.push('}');
                }
                out.push_str("]}");
            }
        }
        AvroSchema::Enum(e) => {
            if named("enum", e.name.fullname(None), out) {
                let symbols: Vec<String> = e.symbols.iter().map(|s| quoted(s)).collect();
                out.push_str(&format!(",\"symbols\":[{}]}}", symbols.join(",")));
            }
        }
        AvroSchema::Fixed(f) => {
            if named("fixed", f.name.fullname(None), out) {
                out.push_str(&format!(",\"size\":{}}}", f.size));
            }
        }
        AvroSchema::Ref { name } => out.push_str(&quoted(&name.fullname(None))),
        AvroSchema::Array(array) => {
            out.push_str("{\"type\":\"array\",\"items\":");
            write_canonical(&array.items, defined, out)?;
            out.push('}');
        }
        AvroSchema::Map(map) => {
            out.push_str("{\"type\":\"map\",\"values\":");
            write_canonical(&map.types, defined, out)?;
            out.push('}');
        }
        AvroSchema::Union(union) => {
            out.push('[');
            for (i, branch) in union.variants().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(branch, defined, out)?;
            }
            out.push(']');
        }
        AvroSchema::Null
        | AvroSchema::Boolean
        | AvroSchema::Int
        | AvroSchema::Long
        | AvroSchema::Float
        | AvroSchema::Double
        | AvroSchema::Bytes
        | AvroSchema::String => out.push_str(&quoted(&branch_name(schema))),
        // Logical types are removed before a schema is parsed.
        other => return Err(format!("an unexpected logical type {other:?}")),
    }
    Ok(())
}

/// Splits a single-object encoding into its fingerprint, the 8 bytes as written, and
/// its payload; `None` for bytes that do not begin with the marker and a fingerprint.
pub(crate) fn split_single_object(bytes: &[u8]) -> Option<([u8; 8], &[u8])> {
    let (head, payload) = bytes.split_at_checked(10)?;
    let (marker, fingerprint) = head.split_at_checked(2)?;
    if marker != SINGLE_OBJECT_MARKER {
        return None;
    }
    Some((fingerprint.try_into().ok()?, payload))
}

/// The single-object encoding of a payload under a fingerprint.
pub(crate) fn single_object(fingerprint: [u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(10));
    out.extend_from_slice(&SINGLE_OBJECT_MARKER);
    out.extend_from_slice(&fingerprint);
    out.extend_from_slice(payload);
    out
}

/// Decodes one datum of `schema` that fills `bytes` exactly.
pub(crate) fn decode(schema: &AvroSchema, bytes: &[u8]) -> Result<Value, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    let reader = GenericDatumReader::builder(schema)
        .build()
        .map_err(|e| e.to_string())?;
    let mut input = bytes;
    let value = reader.read_value(&mut input).map_err(|e| e.to_string())?;
    if !input.is_empty() {
        return Err(format!("{} bytes are left over", input.len()));
    }
    from_avro(value, schema, resolved.get_names())
}

/// Encodes `value` as one datum of `schema`.
pub(crate) fn encode(schema: &AvroSchema, value: &Value) -> Result<Vec<u8>, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    let value = to_avro(value, schema, resolved.get_names())?;
    let writer = GenericDatumWriter::builder(schema)
        .build()
        .map_err(|e| e.to_string())?;
    writer
        .write_value_to_vec(value)
        .map_err(|e| format!("the value does not fit the schema: {e}"))
}

/// The schema a reference names, or the schema itself.
fn resolve<'a>(schema: &'a AvroSchema, names: &NamesRef<'a>) -> Result<&'a AvroSchema, String> {
    match schema {
        AvroSchema::Ref { name } => names
            .get(name)
            .copied()
            .ok_or_else(|| format!("no type {}", name.fullname(None))),
        other => Ok(other),
    }
}

/// True for a union with two or more non-null branches, whose values name their branch.
fn names_its_branch(union: &UnionSchema) -> bool {
    union
        .variants()
        .iter()
        .filter(|s| !matches!(s, AvroSchema::Null))
        .count()
        >= 2
}

/// The name of a branch: the full name of a named type, otherwise the type's name.
fn branch_name(schema: &AvroSchema) -> String {
    match schema {
        AvroSchema::Record(r) => r.name.fullname(None),
        AvroSchema::Enum(e) => e.name.fullname(None),
        AvroSchema::Fixed(f) => f.name.fullname(None),
        AvroSchema::Ref { name } => name.fullname(None),
        AvroSchema::Null => "null".into(),
        AvroSchema::Boolean => "boolean".into(),
        AvroSchema::Int => "int".into(),
        AvroSchema::Long => "long".into(),
        AvroSchema::Float => "float".into(),
        AvroSchema::Double => "double".into(),
        AvroSchema::Bytes => "bytes".into(),
        AvroSchema::String => "string".into(),
        AvroSchema::Array(_) => "array".into(),
        AvroSchema::Map(_) => "map".into(),
        AvroSchema::Union(_) => "union".into(),
        // Logical types are removed before a schema is parsed.
        _ => "logical".into(),
    }
}

/// The library's value of a value that `apache-avro` decoded with `schema`.
fn from_avro(value: AvroValue, schema: &AvroSchema, names: &NamesRef) -> Result<Value, String> {
    let schema = resolve(schema, names)?;
    Ok(match (value, schema) {
        (AvroValue::Union(index, inner), AvroSchema::Union(union)) => {
            let branch = usize::try_from(index)
                .ok()
                .and_then(|i| union.variants().get(i))
                .ok_or_else(|| format!("no branch {index}"))?;
            let inner = from_avro(*inner, branch, names)?;
            if names_its_branch(union) {
                Value::Union {
                    index,
                    branch: branch_name(branch),
                    value: Box::new(inner),
                }
            } else {
                inner
            }
        }
        (AvroValue::Record(fields), AvroSchema::Record(record)) => Value::Record(
            fields
                .into_iter()
                .map(|(name, v)| {
                    let field = record
                        .lookup
                        .get(&name)
                        .and_then(|&i| record.fields.get(i))
                        .ok_or_else(|| format!("no field {name}"))?;
                    Ok((name, from_avro(v, &field.schema, names)?))
                })
                .collect::<Result<_, String>>()?,
        ),
        (AvroValue::Array(items), AvroSchema::Array(array)) => Value::Array(
            items
                .into_iter()
                .map(|v| from_avro(v, &array.items, names))
                .collect::<Result<_, String>>()?,
        ),
        (AvroValue::Map(entries), AvroSchema::Map(map)) => Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| Ok((k, from_avro(v, &map.types, names)?)))
                .collect::<Result<BTreeMap<_, _>, String>>()?,
        ),
        (AvroValue::Null, _) => Value::Null,
        (AvroValue::Boolean(b), _) => Value::Boolean(b),
        (AvroValue::Int(i), _) => Value::Int(i),
        (AvroValue::Long(l), _) => Value::Long(l),
        (AvroValue::Float(f), _) => Value::Float(f),
        (AvroValue::Double(d), _) => Value::Double(d),
        (AvroValue::Bytes(b), _) => Value::Bytes(b),
        (AvroValue::String(s), _) => Value::String(s),
        (AvroValue::Fixed(_, b), _) => Value::Fixed(b),
        (AvroValue::Enum(index, symbol), _) => Value::Enum { index, symbol },
        (other, _) => return Err(format!("an unexpected value {other:?}")),
    })
}

/// The value of `apache-avro` for `value` written with `schema`.
fn to_avro(value: &Value, schema: &AvroSchema, names: &NamesRef) -> Result<AvroValue, String> {
    let schema = resolve(schema, names)?;
    Ok(match (value, schema) {
        (
            Value::Union {
                index,
                value: inner,
                ..
            },
            AvroSchema::Union(union),
        ) => {
            let branch = usize::try_from(*index)
                .ok()
                .and_then(|i| union.variants().get(i))
                .ok_or_else(|| format!("no branch {index}"))?;
            AvroValue::Union(*index, Box::new(to_avro(inner, branch, names)?))
        }
        (_, AvroSchema::Union(union)) => {
            if names_its_branch(union) {
                return Err("a union of two or more non-null branches needs its branch".into());
            }
            // The union of null and one other type: the value picks the branch.
            let is_null = matches!(value, Value::Null);
            let (index, branch) = union
                .variants()
                .iter()
                .enumerate()
                .find(|(_, s)| matches!(s, AvroSchema::Null) == is_null)
                .ok_or("no branch for the value")?;
            let index = u32::try_from(index).map_err(|e| e.to_string())?;
            AvroValue::Union(index, Box::new(to_avro(value, branch, names)?))
        }
        (Value::Record(fields), AvroSchema::Record(record)) => AvroValue::Record(
            record
                .fields
                .iter()
                .map(|field| {
                    let v = fields
                        .iter()
                        .find(|(name, _)| *name == field.name)
                        .map(|(_, v)| v)
                        .ok_or_else(|| format!("no value for the field {}", field.name))?;
                    Ok((field.name.clone(), to_avro(v, &field.schema, names)?))
                })
                .collect::<Result<_, String>>()?,
        ),
        (Value::Array(items), AvroSchema::Array(array)) => AvroValue::Array(
            items
                .iter()
                .map(|v| to_avro(v, &array.items, names))
                .collect::<Result<_, String>>()?,
        ),
        (Value::Map(entries), AvroSchema::Map(map)) => AvroValue::Map(
            entries
                .iter()
                .map(|(k, v)| Ok((k.clone(), to_avro(v, &map.types, names)?)))
                .collect::<Result<HashMap<_, _>, String>>()?,
        ),
        (Value::Null, _) => AvroValue::Null,
        (Value::Boolean(b), _) => AvroValue::Boolean(*b),
        (Value::Int(i), _) => AvroValue::Int(*i),
        (Value::Long(l), _) => AvroValue::Long(*l),
        (Value::Float(f), _) => AvroValue::Float(*f),
        (Value::Double(d), _) => AvroValue::Double(*d),
        (Value::Bytes(b), _) => AvroValue::Bytes(b.clone()),
        (Value::String(s), _) => AvroValue::String(s.clone()),
        (Value::Fixed(b), _) => AvroValue::Fixed(b.len(), b.clone()),
        (Value::Enum { index, symbol }, _) => AvroValue::Enum(*index, symbol.clone()),
        (Value::Record(_) | Value::Array(_) | Value::Map(_) | Value::Union { .. }, _) => {
            return Err(format!(
                "the value does not fit the schema {}",
                branch_name(schema)
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(text: &str) -> AvroSchema {
        parse(text).unwrap()
    }

    #[test]
    fn logical_types_are_removed_everywhere() {
        let json: Json = serde_json::from_str(
            r#"{"type":"record","name":"R","fields":[{"name":"id","type":{"type":"string","logicalType":"uuid"}}]}"#,
        )
        .unwrap();
        assert!(
            !without_logical_types(&json)
                .to_string()
                .contains("logicalType")
        );
    }

    #[test]
    fn without_logical_types_drops_only_logical_type() {
        let json: Json = serde_json::from_str(
            r#"{"type":"string","logicalType":"uuid","x":[{"logicalType":"date","type":"int"}]}"#,
        )
        .unwrap();
        let expected: Json =
            serde_json::from_str(r#"{"type":"string","x":[{"type":"int"}]}"#).unwrap();
        assert_eq!(without_logical_types(&json), expected);
    }

    #[test]
    fn a_uuid_is_read_as_the_string_received() {
        let s = schema(r#"{"type":"string","logicalType":"uuid"}"#);
        let bytes = encode(&s, &Value::String("NOT-A-UUID".into())).unwrap();
        assert_eq!(
            decode(&s, &bytes).unwrap(),
            Value::String("NOT-A-UUID".into())
        );
    }

    #[test]
    fn bytes_left_over_are_rejected() {
        let s = schema(r#""long""#);
        assert_eq!(decode(&s, &[0x02]).unwrap(), Value::Long(1));
        assert!(decode(&s, &[0x02, 0x00]).is_err());
        assert!(decode(&s, &[]).is_err());
    }

    #[test]
    fn a_union_of_null_and_one_type_holds_the_value_of_its_branch() {
        let s = schema(r#"["null","string"]"#);
        assert_eq!(decode(&s, &[0x00]).unwrap(), Value::Null);
        assert_eq!(
            decode(&s, &[0x02, 0x02, b'a']).unwrap(),
            Value::String("a".into())
        );
        assert_eq!(
            encode(&s, &Value::String("a".into())).unwrap(),
            [0x02, 0x02, b'a']
        );
        assert_eq!(encode(&s, &Value::Null).unwrap(), [0x00]);
    }

    #[test]
    fn a_union_of_two_types_names_its_branch() {
        let s = schema(
            r#"[{"type":"record","name":"a.A","fields":[]},{"type":"record","name":"B","namespace":"b","fields":[{"name":"x","type":"int"}]}]"#,
        );
        let value = decode(&s, &[0x02, 0x04]).unwrap();
        assert_eq!(
            value,
            Value::Union {
                index: 1,
                branch: "b.B".into(),
                value: Box::new(Value::Record(vec![("x".into(), Value::Int(2))])),
            }
        );
        assert_eq!(encode(&s, &value).unwrap(), [0x02, 0x04]);
        assert!(encode(&s, &Value::Record(vec![])).is_err());
    }

    #[test]
    fn a_recursive_type_is_followed_through_its_name() {
        let s = schema(
            r#"{"type":"record","name":"N","fields":[{"name":"next","type":["null","N"]}]}"#,
        );
        let value = decode(&s, &[0x02, 0x00]).unwrap();
        assert_eq!(
            value,
            Value::Record(vec![(
                "next".into(),
                Value::Record(vec![("next".into(), Value::Null)])
            )])
        );
        assert_eq!(encode(&s, &value).unwrap(), [0x02, 0x00]);
    }

    #[test]
    fn the_single_object_header_is_split_from_its_payload() {
        let bytes = single_object([1, 2, 3, 4, 5, 6, 7, 8], &[9]);
        assert_eq!(bytes, [0xc3, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            split_single_object(&bytes),
            Some(([1, 2, 3, 4, 5, 6, 7, 8], &[9][..]))
        );
        assert_eq!(split_single_object(&bytes[..9]), None);
        assert_eq!(
            split_single_object(&[0xc3, 0x02, 0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
    }

    #[test]
    fn a_value_that_does_not_fit_is_not_encoded() {
        let s = schema(r#"{"type":"fixed","name":"K","size":32}"#);
        assert!(encode(&s, &Value::Fixed(vec![0; 31])).is_err());
        assert!(encode(&s, &Value::Fixed(vec![0; 32])).is_ok());
    }
}
