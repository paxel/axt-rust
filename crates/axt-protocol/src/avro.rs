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

mod resolve;

pub(crate) use resolve::Resolution;

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
    configure();
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
    write_canonical(schema, None, &mut HashSet::new(), &mut out)?;
    Ok(out)
}

/// The full name and the Parsing Canonical Form of every named type that `schema`
/// defines, each written on its own: a name it refers to that it did not define itself,
/// such as one defined earlier in `schema`, is written out in full.
pub(crate) fn named_forms(schema: &AvroSchema) -> Result<Vec<(String, String)>, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    collect_named(schema, resolved.get_names(), &mut out)?;
    Ok(out)
}

/// Adds the named types that `schema` defines to `out`, see [`named_forms`].
fn collect_named(
    schema: &AvroSchema,
    names: &NamesRef,
    out: &mut Vec<(String, String)>,
) -> Result<(), String> {
    let full_name = match schema {
        AvroSchema::Record(r) => Some(r.name.fullname(None)),
        AvroSchema::Enum(e) => Some(e.name.fullname(None)),
        AvroSchema::Fixed(f) => Some(f.name.fullname(None)),
        _ => None,
    };
    if let Some(full_name) = full_name {
        let mut form = String::new();
        write_canonical(schema, Some(names), &mut HashSet::new(), &mut form)?;
        out.push((full_name, form));
    }
    match schema {
        AvroSchema::Record(r) => r
            .fields
            .iter()
            .try_for_each(|f| collect_named(&f.schema, names, out)),
        AvroSchema::Array(a) => collect_named(&a.items, names, out),
        AvroSchema::Map(m) => collect_named(&m.types, names, out),
        AvroSchema::Union(u) => u
            .variants()
            .iter()
            .try_for_each(|b| collect_named(b, names, out)),
        _ => Ok(()),
    }
}

/// The full name and the aliases, in full, of a record schema; `None` for another schema.
pub(crate) fn record_names(schema: &AvroSchema) -> Option<(String, Vec<String>)> {
    match schema {
        AvroSchema::Record(r) => Some((
            r.name.fullname(None),
            r.aliases
                .iter()
                .flatten()
                .map(|a| a.fullname(None))
                .collect(),
        )),
        _ => None,
    }
}

/// The plan that reads data of `writer` as `reader` (Avro 1.12 schema resolution), or
/// why the two do not resolve.
pub(crate) fn resolution(writer: &AvroSchema, reader: &AvroSchema) -> Result<Resolution, String> {
    let writer_names = ResolvedSchema::try_from(writer).map_err(|e| e.to_string())?;
    let reader_names = ResolvedSchema::try_from(reader).map_err(|e| e.to_string())?;
    Resolution::new(
        writer,
        writer_names.get_names(),
        reader,
        reader_names.get_names(),
    )
}

/// Decodes one datum of `writer` that fills `bytes` exactly and reads it as the reader
/// schema of `resolution`.
pub(crate) fn decode_resolved(
    writer: &AvroSchema,
    resolution: &Resolution,
    bytes: &[u8],
) -> Result<Value, String> {
    resolution.apply(read_datum(writer, bytes)?)
}

/// A string as JSON.
fn quoted(text: &str) -> String {
    Json::String(text.to_owned()).to_string()
}

/// Writes the canonical form of `schema`; a named type already written is its full name.
///
/// With `names`, a reference to a type not yet written is written out in full.
fn write_canonical(
    schema: &AvroSchema,
    names: Option<&NamesRef>,
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
                    write_canonical(&field.schema, names, defined, out)?;
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
        AvroSchema::Ref { name } => match names.and_then(|n| n.get(name)) {
            Some(&target) if !defined.contains(&name.fullname(None)) => {
                write_canonical(target, names, defined, out)?;
            }
            _ => out.push_str(&quoted(&name.fullname(None))),
        },
        AvroSchema::Array(array) => {
            out.push_str("{\"type\":\"array\",\"items\":");
            write_canonical(&array.items, names, defined, out)?;
            out.push('}');
        }
        AvroSchema::Map(map) => {
            out.push_str("{\"type\":\"map\",\"values\":");
            write_canonical(&map.types, names, defined, out)?;
            out.push('}');
        }
        AvroSchema::Union(union) => {
            out.push('[');
            for (i, branch) in union.variants().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(branch, names, defined, out)?;
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

/// The deepest `apache-avro` recurses when it decodes a datum, for every schema of the
/// process. Its own default, 32, counts unions too and is below what a valid description
/// nests: `fields.depth` typed fields of about five Avro levels each, a field, its union
/// `kind`, an object, its array of fields and the next field. The limits of AXT, such as
/// `types.data_depth`, are checked on the decoded value; this one only keeps the
/// recursion within the stack.
const DECODE_RECURSION_LIMIT: usize = 512;

/// Sets the recursion limit of `apache-avro`, which takes it once per process, at its first
/// use; an app that set its own before keeps it. Every schema is parsed by [`parse`] first.
fn configure() {
    apache_avro::util::max_decode_recursion_depth(DECODE_RECURSION_LIMIT);
}

/// Decodes one datum of `schema` that fills `bytes` exactly.
pub(crate) fn decode(schema: &AvroSchema, bytes: &[u8]) -> Result<Value, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    from_avro(read_datum(schema, bytes)?, schema, resolved.get_names())
}

/// The value of `apache-avro` of one datum of `schema` that fills `bytes` exactly.
fn read_datum(schema: &AvroSchema, bytes: &[u8]) -> Result<AvroValue, String> {
    configure();
    let reader = GenericDatumReader::builder(schema)
        .build()
        .map_err(|e| e.to_string())?;
    let mut input = bytes;
    let value = reader.read_value(&mut input).map_err(|e| e.to_string())?;
    if !input.is_empty() {
        return Err(format!("{} bytes are left over", input.len()));
    }
    Ok(value)
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
pub(crate) fn branch_name(schema: &AvroSchema) -> String {
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

/// The datum of `schema` for `json`, a value in the form of `spec/conformance.md`,
/// section 3.3: bytes as lower-case hexadecimal, a union of `null` and one other type as
/// the value of its branch, another union as an object of one member named by its
/// branch. A record member that is absent takes the field's default; members that the
/// schema does not have are ignored.
pub(crate) fn from_json(schema: &AvroSchema, json: &Json) -> Result<Value, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    json_value(json, schema, resolved.get_names(), false)
}

/// The datum of `json` for `schema`; for a `default`, `json` is a default of the Avro
/// specification, whose bytes are a string of code points and whose union is of its
/// first branch.
fn json_value(
    json: &Json,
    schema: &AvroSchema,
    names: &NamesRef,
    default: bool,
) -> Result<Value, String> {
    let schema = resolve(schema, names)?;
    let not = |what: &str| format!("{json} is not {what}");
    Ok(match schema {
        AvroSchema::Null => match json {
            Json::Null => Value::Null,
            _ => return Err(not("null")),
        },
        AvroSchema::Boolean => Value::Boolean(json.as_bool().ok_or_else(|| not("a boolean"))?),
        AvroSchema::Int => Value::Int(
            json.as_i64()
                .and_then(|i| i32::try_from(i).ok())
                .ok_or_else(|| not("an int"))?,
        ),
        AvroSchema::Long => Value::Long(json.as_i64().ok_or_else(|| not("a long"))?),
        // A float of JSON is the nearest float to its number.
        AvroSchema::Float => Value::Float(json.as_f64().ok_or_else(|| not("a float"))? as f32),
        AvroSchema::Double => Value::Double(json.as_f64().ok_or_else(|| not("a double"))?),
        AvroSchema::Bytes => Value::Bytes(json_bytes(json, default)?),
        AvroSchema::Fixed(fixed) => {
            let bytes = json_bytes(json, default)?;
            if bytes.len() != fixed.size {
                return Err(not("of the size of the fixed"));
            }
            Value::Fixed(bytes)
        }
        AvroSchema::String => Value::String(json.as_str().ok_or_else(|| not("a string"))?.into()),
        AvroSchema::Enum(e) => {
            let symbol = json.as_str().ok_or_else(|| not("a symbol"))?;
            let index = e
                .symbols
                .iter()
                .position(|s| s == symbol)
                .and_then(|i| u32::try_from(i).ok())
                .ok_or_else(|| not("a symbol of the enum"))?;
            Value::Enum {
                index,
                symbol: symbol.into(),
            }
        }
        AvroSchema::Array(array) => Value::Array(
            json.as_array()
                .ok_or_else(|| not("an array"))?
                .iter()
                .map(|item| json_value(item, &array.items, names, default))
                .collect::<Result<_, String>>()?,
        ),
        AvroSchema::Map(map) => Value::Map(
            json.as_object()
                .ok_or_else(|| not("an object"))?
                .iter()
                .map(|(k, v)| Ok((k.clone(), json_value(v, &map.types, names, default)?)))
                .collect::<Result<BTreeMap<_, _>, String>>()?,
        ),
        AvroSchema::Record(record) => {
            let members = json.as_object().ok_or_else(|| not("an object"))?;
            Value::Record(
                record
                    .fields
                    .iter()
                    .map(|field| {
                        let value = match (members.get(&field.name), &field.default) {
                            (Some(member), _) => json_value(member, &field.schema, names, default)?,
                            (None, Some(d)) => json_value(d, &field.schema, names, true)?,
                            (None, None) => return Err(format!("no member {}", field.name)),
                        };
                        Ok((field.name.clone(), value))
                    })
                    .collect::<Result<_, String>>()?,
            )
        }
        AvroSchema::Union(union) => {
            let variants = union.variants();
            let (index, branch, inner) = if default {
                // A default is of the first branch.
                let branch = variants.first().ok_or("an empty union")?;
                (0, branch, json)
            } else if json.is_null() {
                let index = variants
                    .iter()
                    .position(|s| matches!(s, AvroSchema::Null))
                    .ok_or_else(|| not("a branch of the union"))?;
                (index, &AvroSchema::Null, json)
            } else if !names_its_branch(union) {
                variants
                    .iter()
                    .enumerate()
                    .find(|(_, s)| !matches!(s, AvroSchema::Null))
                    .map(|(i, s)| (i, s, json))
                    .ok_or_else(|| not("a branch of the union"))?
            } else {
                let members = json.as_object().ok_or_else(|| not("a branch"))?;
                let (name, inner) = match members.iter().next() {
                    Some(member) if members.len() == 1 => member,
                    _ => return Err(not("an object of one member, the branch")),
                };
                variants
                    .iter()
                    .enumerate()
                    .find(|(_, s)| branch_name(s) == *name)
                    .map(|(i, s)| (i, s, inner))
                    .ok_or_else(|| format!("no branch {name}"))?
            };
            let value = json_value(inner, branch, names, default)?;
            let index = u32::try_from(index).map_err(|e| e.to_string())?;
            if names_its_branch(union) {
                Value::Union {
                    index,
                    branch: branch_name(branch),
                    value: Box::new(value),
                }
            } else {
                value
            }
        }
        other => return Err(format!("an unexpected schema {other:?}")),
    })
}

/// Bytes in JSON: lower-case hexadecimal, or for a default a string of code points.
fn json_bytes(json: &Json, default: bool) -> Result<Vec<u8>, String> {
    let text = json
        .as_str()
        .ok_or_else(|| format!("{json} is not bytes"))?;
    if default {
        return text
            .chars()
            .map(|c| u8::try_from(u32::from(c)).map_err(|_| format!("{c} is not a byte")))
            .collect();
    }
    let digits = text.as_bytes();
    let bad = || format!("{json} is not lower-case hexadecimal");
    if !digits.len().is_multiple_of(2) {
        return Err(bad());
    }
    let (pairs, _) = digits.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[high, low]| {
            let digit = |d: u8| match d {
                b'0'..=b'9' | b'a'..=b'f' => char::from(d).to_digit(16),
                _ => None,
            };
            digit(high)
                .zip(digit(low))
                .and_then(|(h, l)| u8::try_from(h.checked_mul(16)?.checked_add(l)?).ok())
                .ok_or_else(bad)
        })
        .collect()
}

/// A named record type that a walk of a value meets.
pub(crate) enum Met<'a> {
    /// A value of the record type of this full name.
    Record(&'a str),
    /// An array whose items are of the record type of this full name.
    Items(&'a str),
}

/// What a rule of [`first_problem`] says of a spot: `None` to look inside it, or the
/// answer for it and everything inside it, the path of a problem or `None` for none.
pub(crate) type Verdict = Option<Option<String>>;

/// The path of the first problem in `value`, a datum of `schema` at `path`, in the order
/// of the encoding: `rule` judges each record and each array of records the walk meets.
pub(crate) fn first_problem(
    schema: &AvroSchema,
    value: &Value,
    path: &str,
    rule: &dyn Fn(Met<'_>, &Value, &str) -> Verdict,
) -> Result<Option<String>, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    walk(schema, value, path, resolved.get_names(), rule)
}

fn walk(
    schema: &AvroSchema,
    value: &Value,
    path: &str,
    names: &NamesRef,
    rule: &dyn Fn(Met<'_>, &Value, &str) -> Verdict,
) -> Result<Option<String>, String> {
    let schema = resolve(schema, names)?;
    match (schema, value) {
        (AvroSchema::Record(record), Value::Record(_)) => {
            if let Some(verdict) = rule(Met::Record(&record.name.fullname(None)), value, path) {
                return Ok(verdict);
            }
            for field in &record.fields {
                let Some(inner) = value.field(&field.name) else {
                    continue;
                };
                let at = if path.is_empty() {
                    field.name.clone()
                } else {
                    format!("{path}.{}", field.name)
                };
                if let Some(found) = walk(&field.schema, inner, &at, names, rule)? {
                    return Ok(Some(found));
                }
            }
        }
        (AvroSchema::Array(array), Value::Array(items)) => {
            if let AvroSchema::Record(record) = resolve(&array.items, names)?
                && let Some(verdict) = rule(Met::Items(&record.name.fullname(None)), value, path)
            {
                return Ok(verdict);
            }
            for (i, item) in items.iter().enumerate() {
                if let Some(found) = walk(&array.items, item, &format!("{path}[{i}]"), names, rule)?
                {
                    return Ok(Some(found));
                }
            }
        }
        (AvroSchema::Map(map), Value::Map(entries)) => {
            for (key, item) in entries {
                let at = format!("{path}[{}]", Json::String(key.clone()));
                if let Some(found) = walk(&map.types, item, &at, names, rule)? {
                    return Ok(Some(found));
                }
            }
        }
        (AvroSchema::Union(union), Value::Union { index, value, .. }) => {
            if let Some(branch) = usize::try_from(*index)
                .ok()
                .and_then(|i| union.variants().get(i))
            {
                return walk(branch, value, path, names, rule);
            }
        }
        (AvroSchema::Union(_), Value::Null) => {}
        (AvroSchema::Union(union), _) => {
            // The union of null and one other type holds the value of that type.
            if let Some(branch) = union
                .variants()
                .iter()
                .find(|s| !matches!(s, AvroSchema::Null))
            {
                return walk(branch, value, path, names, rule);
            }
        }
        _ => {}
    }
    Ok(None)
}

/// What replaces an array of records: given the full name of the items' record type and
/// the items, the new items, or `None` to look inside them.
pub(crate) type ListMap<'a> = dyn Fn(&str, &[Value]) -> Option<Vec<Value>> + 'a;

/// The top-level fields of `schema`, a record schema, that are arrays of records, each
/// with the full name of its items' record type; none for another schema.
pub(crate) fn record_lists(schema: &AvroSchema) -> Result<Vec<(String, String)>, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    let names = resolved.get_names();
    let AvroSchema::Record(record) = resolve(schema, names)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for field in &record.fields {
        if let AvroSchema::Array(array) = resolve(&field.schema, names)?
            && let AvroSchema::Record(items) = resolve(&array.items, names)?
        {
            out.push((field.name.clone(), items.name.fullname(None)));
        }
    }
    Ok(out)
}

/// `value`, a datum of `schema`, with every array of records that `map` replaces: `map`
/// gets the full name of the items' record type and the items, and gives the new items,
/// or `None` to look inside them; also nested in records, arrays, maps and unions.
pub(crate) fn map_record_lists(
    schema: &AvroSchema,
    value: &Value,
    map: &ListMap<'_>,
) -> Result<Value, String> {
    let resolved = ResolvedSchema::try_from(schema).map_err(|e| e.to_string())?;
    map_lists(schema, value, resolved.get_names(), map)
}

fn map_lists(
    schema: &AvroSchema,
    value: &Value,
    names: &NamesRef,
    map: &ListMap<'_>,
) -> Result<Value, String> {
    let schema = resolve(schema, names)?;
    Ok(match (schema, value) {
        (AvroSchema::Record(record), Value::Record(fields)) => Value::Record(
            fields
                .iter()
                .map(|(name, inner)| {
                    let inner = match record.fields.iter().find(|f| f.name == *name) {
                        Some(field) => map_lists(&field.schema, inner, names, map)?,
                        None => inner.clone(),
                    };
                    Ok((name.clone(), inner))
                })
                .collect::<Result<_, String>>()?,
        ),
        (AvroSchema::Array(array), Value::Array(items)) => {
            if let AvroSchema::Record(record) = resolve(&array.items, names)?
                && let Some(mapped) = map(&record.name.fullname(None), items)
            {
                return Ok(Value::Array(mapped));
            }
            Value::Array(
                items
                    .iter()
                    .map(|item| map_lists(&array.items, item, names, map))
                    .collect::<Result<_, String>>()?,
            )
        }
        (AvroSchema::Map(inner), Value::Map(entries)) => Value::Map(
            entries
                .iter()
                .map(|(key, item)| Ok((key.clone(), map_lists(&inner.types, item, names, map)?)))
                .collect::<Result<_, String>>()?,
        ),
        (
            AvroSchema::Union(union),
            Value::Union {
                index,
                branch,
                value: inner,
            },
        ) => {
            let schema = usize::try_from(*index)
                .ok()
                .and_then(|i| union.variants().get(i))
                .ok_or_else(|| format!("no branch {index}"))?;
            Value::Union {
                index: *index,
                branch: branch.clone(),
                value: Box::new(map_lists(schema, inner, names, map)?),
            }
        }
        (AvroSchema::Union(_), Value::Null) => Value::Null,
        (AvroSchema::Union(union), _) => {
            // The union of null and one other type holds the value of that type.
            match union
                .variants()
                .iter()
                .find(|s| !matches!(s, AvroSchema::Null))
            {
                Some(branch) => map_lists(branch, value, names, map)?,
                None => value.clone(),
            }
        }
        _ => value.clone(),
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
    fn the_json_form_takes_defaults_hexadecimal_and_named_branches() {
        let s = schema(
            r#"{"type":"record","name":"R","fields":[
                {"name":"b","type":"bytes"},
                {"name":"d","type":"bytes","default":"ÿ"},
                {"name":"o","type":["null","int"],"default":null},
                {"name":"k","type":[{"type":"record","name":"A","fields":[]},{"type":"record","name":"B","fields":[]}]}
            ]}"#,
        );
        let value = from_json(&s, &serde_json::json!({"b": "00ff", "k": {"B": {}}})).unwrap();
        assert_eq!(
            value,
            Value::Record(vec![
                ("b".into(), Value::Bytes(vec![0, 255])),
                ("d".into(), Value::Bytes(vec![255])),
                ("o".into(), Value::Null),
                (
                    "k".into(),
                    Value::Union {
                        index: 1,
                        branch: "B".into(),
                        value: Box::new(Value::Record(vec![])),
                    }
                ),
            ])
        );
        for bad in [
            serde_json::json!({"b": "FF", "k": {"B": {}}}),
            serde_json::json!({"b": "0", "k": {"B": {}}}),
            serde_json::json!({"b": "00", "k": {"C": {}}}),
            serde_json::json!({"b": "00", "k": {"A": {}, "B": {}}}),
            serde_json::json!({"k": {"B": {}}}),
            serde_json::json!({"b": "00", "o": "x", "k": {"B": {}}}),
        ] {
            assert!(from_json(&s, &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_walk_names_the_first_problem_by_its_path() {
        let s = schema(
            r#"{"type":"record","name":"R","fields":[
                {"name":"m","type":{"type":"map","values":{"type":"record","name":"T","fields":[{"name":"x","type":"int"}]}}},
                {"name":"l","type":["null",{"type":"array","items":"T"}]}
            ]}"#,
        );
        let t = |x| Value::Record(vec![("x".into(), Value::Int(x))]);
        let value = Value::Record(vec![
            (
                "m".into(),
                Value::Map(BTreeMap::from([("a\"".into(), t(1))])),
            ),
            ("l".into(), Value::Array(vec![t(1), t(2)])),
        ]);
        let rule = |met: Met<'_>, value: &Value, path: &str| match met {
            Met::Record("T") if value.field("x") == Some(&Value::Int(2)) => Some(Some(path.into())),
            _ => None,
        };
        assert_eq!(
            first_problem(&s, &value, "", &rule).unwrap(),
            Some("l[1]".into())
        );
        let items = |met: Met<'_>, _: &Value, path: &str| match met {
            Met::Items("T") => Some(Some(path.into())),
            Met::Record("T") => Some(Some(path.into())),
            _ => None,
        };
        assert_eq!(
            first_problem(&s, &value, "", &items).unwrap(),
            Some(r#"m["a\""]"#.into())
        );
    }

    #[test]
    fn a_value_that_does_not_fit_is_not_encoded() {
        let s = schema(r#"{"type":"fixed","name":"K","size":32}"#);
        assert!(encode(&s, &Value::Fixed(vec![0; 31])).is_err());
        assert!(encode(&s, &Value::Fixed(vec![0; 32])).is_ok());
    }
}
