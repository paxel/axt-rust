//! A decoded Avro value, the library's own (`spec/conformance.md`, section 3.3).

use std::collections::BTreeMap;
use std::fmt::Write;

use serde_json::{Value as Json, json};

/// One Avro datum, read without logical types: a value of a logical type is the value
/// of its underlying type, such as a `uuid` as its string as received.
///
/// A union of `null` and one other type holds the value of its branch, `Null` or the
/// other type's value, as no branch is in doubt. Only a union with two or more non-null
/// branches holds a [`Value::Union`], which names its branch.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `boolean`.
    Boolean(bool),
    /// `int`.
    Int(i32),
    /// `long`.
    Long(i64),
    /// `float`.
    Float(f32),
    /// `double`.
    Double(f64),
    /// `bytes`.
    Bytes(Vec<u8>),
    /// `string`.
    String(String),
    /// `fixed`: exactly as many bytes as its schema's size.
    Fixed(Vec<u8>),
    /// An enum: the position of its symbol in the schema and the symbol.
    Enum {
        /// The position of the symbol among the schema's symbols.
        index: u32,
        /// The symbol.
        symbol: String,
    },
    /// An array.
    Array(Vec<Value>),
    /// A map, by key.
    Map(BTreeMap<String, Value>),
    /// A record: its fields by name, in the order of the schema.
    Record(Vec<(String, Value)>),
    /// The value of a union with two or more non-null branches.
    Union {
        /// The position of the branch among the union's types.
        index: u32,
        /// The branch's full name for a named type, such as `axt.ObjectField`, or the
        /// type's name, such as `string` or `array`.
        branch: String,
        /// The branch's value.
        value: Box<Value>,
    },
}

impl Value {
    /// The value of the field `name` of a record; `None` for another value or a record
    /// without that field.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Value> {
        match self {
            Self::Record(fields) => fields.iter().find(|(n, _)| n == name).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value in JSON, in the form of `spec/conformance.md`, section 3.3: bytes as
    /// lower-case hexadecimal, and the value of a union with two or more non-null branches
    /// as an object of one member named by its branch, such as the `kind` of `axt.Field`
    /// (`spec/fields.md`, section 10.3), except for the targets of `axt.Relation`, whose
    /// branches have different fields and are written as the value of their branch.
    pub(crate) fn to_json(&self) -> Json {
        match self {
            Self::Null => Json::Null,
            Self::Boolean(b) => json!(b),
            Self::Int(i) => json!(i),
            Self::Long(l) => json!(l),
            // The shortest decimal that reads back to the float, not to its widening.
            Self::Float(f) => f
                .to_string()
                .parse::<f64>()
                .ok()
                .map_or(Json::Null, |d| json!(d)),
            Self::Double(d) => json!(d),
            Self::Bytes(b) | Self::Fixed(b) => json!(hex(b)),
            Self::String(s) => json!(s),
            Self::Enum { symbol, .. } => json!(symbol),
            Self::Array(items) => Json::Array(items.iter().map(Self::to_json).collect()),
            Self::Map(entries) => Json::Object(
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_json()))
                    .collect(),
            ),
            Self::Record(fields) => Json::Object(
                fields
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_json()))
                    .collect(),
            ),
            Self::Union { branch, value, .. }
                if branch == "axt.RelationRecordTarget"
                    || branch == "axt.RelationOutsideTarget" =>
            {
                value.to_json()
            }
            Self::Union { branch, value, .. } => json!({ branch.as_str(): value.to_json() }),
        }
    }
}

/// Bytes as lower-case hexadecimal digits.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a String cannot fail.
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The deepest a value that [`Value::from_stored`] reads nests.
const STORED_DEPTH: usize = 512;

impl Value {
    /// The value in the library's own lossless binary form, in which it keeps a value in
    /// the app's store: a tag for each kind of value, numbers in little-endian bytes,
    /// floating-point numbers by their bits, and lengths as 8 bytes.
    pub(crate) fn to_stored(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_stored(&mut out);
        out
    }

    fn write_stored(&self, out: &mut Vec<u8>) {
        let length = |out: &mut Vec<u8>, n: usize| {
            out.extend_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes());
        };
        let text = |out: &mut Vec<u8>, t: &str| {
            length(out, t.len());
            out.extend_from_slice(t.as_bytes());
        };
        match self {
            Self::Null => out.push(0),
            Self::Boolean(b) => out.extend([1, u8::from(*b)]),
            Self::Int(i) => {
                out.push(2);
                out.extend_from_slice(&i.to_le_bytes());
            }
            Self::Long(l) => {
                out.push(3);
                out.extend_from_slice(&l.to_le_bytes());
            }
            Self::Float(f) => {
                out.push(4);
                out.extend_from_slice(&f.to_bits().to_le_bytes());
            }
            Self::Double(d) => {
                out.push(5);
                out.extend_from_slice(&d.to_bits().to_le_bytes());
            }
            Self::Bytes(b) => {
                out.push(6);
                length(out, b.len());
                out.extend_from_slice(b);
            }
            Self::String(t) => {
                out.push(7);
                text(out, t);
            }
            Self::Fixed(b) => {
                out.push(8);
                length(out, b.len());
                out.extend_from_slice(b);
            }
            Self::Enum { index, symbol } => {
                out.push(9);
                out.extend_from_slice(&index.to_le_bytes());
                text(out, symbol);
            }
            Self::Array(items) => {
                out.push(10);
                length(out, items.len());
                for item in items {
                    item.write_stored(out);
                }
            }
            Self::Map(entries) => {
                out.push(11);
                length(out, entries.len());
                for (key, item) in entries {
                    text(out, key);
                    item.write_stored(out);
                }
            }
            Self::Record(fields) => {
                out.push(12);
                length(out, fields.len());
                for (name, item) in fields {
                    text(out, name);
                    item.write_stored(out);
                }
            }
            Self::Union {
                index,
                branch,
                value,
            } => {
                out.push(13);
                out.extend_from_slice(&index.to_le_bytes());
                text(out, branch);
                value.write_stored(out);
            }
        }
    }

    /// The value of bytes of [`Value::to_stored`]; `None` for bytes that are none.
    pub(crate) fn from_stored(bytes: &[u8]) -> Option<Self> {
        let mut input = bytes;
        let value = read_stored(&mut input, 0)?;
        input.is_empty().then_some(value)
    }

    /// The value with the fields of every record sorted by name: the same content in
    /// one form, whatever the order in which an app gives the fields.
    pub(crate) fn sorted(&self) -> Self {
        match self {
            Self::Record(fields) => {
                let mut fields: Vec<(String, Self)> = fields
                    .iter()
                    .map(|(n, v)| (n.clone(), v.sorted()))
                    .collect();
                fields.sort_by(|a, b| a.0.cmp(&b.0));
                Self::Record(fields)
            }
            Self::Array(items) => Self::Array(items.iter().map(Self::sorted).collect()),
            Self::Map(entries) => Self::Map(
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.sorted()))
                    .collect(),
            ),
            Self::Union {
                index,
                branch,
                value,
            } => Self::Union {
                index: *index,
                branch: branch.clone(),
                value: Box::new(value.sorted()),
            },
            other => other.clone(),
        }
    }
}

/// The next `N` bytes of `input`.
fn take<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
    let (head, rest) = input.split_first_chunk::<N>()?;
    *input = rest;
    Some(*head)
}

/// The next bytes after their length.
fn take_bytes(input: &mut &[u8]) -> Option<Vec<u8>> {
    let length = usize::try_from(u64::from_le_bytes(take(input)?)).ok()?;
    let (head, rest) = input.split_at_checked(length)?;
    *input = rest;
    Some(head.to_vec())
}

fn take_text(input: &mut &[u8]) -> Option<String> {
    String::from_utf8(take_bytes(input)?).ok()
}

/// A count of items, each of at least one byte, so that no count is above what is left.
fn take_count(input: &mut &[u8]) -> Option<usize> {
    let count = usize::try_from(u64::from_le_bytes(take(input)?)).ok()?;
    (count <= input.len()).then_some(count)
}

fn read_stored(input: &mut &[u8], depth: usize) -> Option<Value> {
    if depth > STORED_DEPTH {
        return None;
    }
    let inner = depth.saturating_add(1);
    let [tag] = take::<1>(input)?;
    Some(match tag {
        0 => Value::Null,
        1 => match take::<1>(input)? {
            [0] => Value::Boolean(false),
            [1] => Value::Boolean(true),
            _ => return None,
        },
        2 => Value::Int(i32::from_le_bytes(take(input)?)),
        3 => Value::Long(i64::from_le_bytes(take(input)?)),
        4 => Value::Float(f32::from_bits(u32::from_le_bytes(take(input)?))),
        5 => Value::Double(f64::from_bits(u64::from_le_bytes(take(input)?))),
        6 => Value::Bytes(take_bytes(input)?),
        7 => Value::String(take_text(input)?),
        8 => Value::Fixed(take_bytes(input)?),
        9 => Value::Enum {
            index: u32::from_le_bytes(take(input)?),
            symbol: take_text(input)?,
        },
        10 => {
            let count = take_count(input)?;
            Value::Array(
                (0..count)
                    .map(|_| read_stored(input, inner))
                    .collect::<Option<_>>()?,
            )
        }
        11 => {
            let count = take_count(input)?;
            Value::Map(
                (0..count)
                    .map(|_| Some((take_text(input)?, read_stored(input, inner)?)))
                    .collect::<Option<_>>()?,
            )
        }
        12 => {
            let count = take_count(input)?;
            Value::Record(
                (0..count)
                    .map(|_| Some((take_text(input)?, read_stored(input, inner)?)))
                    .collect::<Option<_>>()?,
            )
        }
        13 => Value::Union {
            index: u32::from_le_bytes(take(input)?),
            branch: take_text(input)?,
            value: Box::new(read_stored(input, inner)?),
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_gives_its_fields_by_name() {
        let record = Value::Record(vec![
            ("id".into(), Value::String("x".into())),
            ("version".into(), Value::Long(4)),
        ]);
        assert_eq!(record.field("version"), Some(&Value::Long(4)));
        assert_eq!(record.field("other"), None);
        assert_eq!(Value::Null.field("id"), None);
    }

    #[test]
    fn a_union_of_several_branches_is_written_under_the_branch_name() {
        let value = Value::Union {
            index: 1,
            branch: "axt.StringField".into(),
            value: Box::new(Value::Record(vec![(
                "multiline".into(),
                Value::Boolean(false),
            )])),
        };
        assert_eq!(
            value.to_json(),
            json!({"axt.StringField": {"multiline": false}})
        );
        assert_eq!(Value::Float(0.1).to_json(), json!(0.1));
        assert_eq!(Value::Bytes(vec![0, 255]).to_json(), json!("00ff"));
    }

    #[test]
    fn a_value_survives_its_stored_form() {
        let value = Value::Record(vec![
            ("n".into(), Value::Null),
            ("b".into(), Value::Boolean(true)),
            ("i".into(), Value::Int(-7)),
            ("l".into(), Value::Long(i64::MIN)),
            ("f".into(), Value::Float(f32::NAN)),
            ("d".into(), Value::Double(f64::NEG_INFINITY)),
            ("y".into(), Value::Bytes(vec![0, 255])),
            ("s".into(), Value::String("ä".into())),
            ("x".into(), Value::Fixed(vec![1; 32])),
            (
                "e".into(),
                Value::Enum {
                    index: 2,
                    symbol: "C".into(),
                },
            ),
            ("a".into(), Value::Array(vec![Value::Int(1), Value::Null])),
            (
                "m".into(),
                Value::Map(BTreeMap::from([("k".into(), Value::Long(1))])),
            ),
            (
                "u".into(),
                Value::Union {
                    index: 1,
                    branch: "axt.RelationOutsideTarget".into(),
                    value: Box::new(Value::Record(vec![])),
                },
            ),
        ]);
        let stored = value.to_stored();
        let back = Value::from_stored(&stored).unwrap();
        // NaN is not equal to itself; the stored form is the same bit for bit.
        assert_eq!(back.to_stored(), stored);
        assert_eq!(back.field("d"), Some(&Value::Double(f64::NEG_INFINITY)));
        assert_eq!(back.field("x"), value.field("x"));
        for end in 0..stored.len() {
            assert_eq!(Value::from_stored(&stored[..end]), None);
        }
        assert_eq!(
            Value::from_stored(&[stored.clone(), vec![0]].concat()),
            None
        );
        assert_eq!(Value::from_stored(&[14]), None);
        // A count above what is left.
        assert_eq!(
            Value::from_stored(&[10, 255, 255, 255, 255, 0, 0, 0, 0]),
            None
        );
        let deep = (0..600).fold(Value::Null, |v, _| Value::Array(vec![v]));
        assert_eq!(Value::from_stored(&deep.to_stored()), None);
    }

    #[test]
    fn sorted_values_have_their_fields_in_order_of_name() {
        let a = Value::Record(vec![
            ("b".into(), Value::Int(1)),
            (
                "a".into(),
                Value::Array(vec![Value::Record(vec![
                    ("y".into(), Value::Null),
                    ("x".into(), Value::Null),
                ])]),
            ),
        ]);
        let b = Value::Record(vec![
            (
                "a".into(),
                Value::Array(vec![Value::Record(vec![
                    ("x".into(), Value::Null),
                    ("y".into(), Value::Null),
                ])]),
            ),
            ("b".into(), Value::Int(1)),
        ]);
        assert_eq!(a.sorted(), b.sorted());
        assert_eq!(a.sorted(), b);
    }

    #[test]
    fn a_target_of_a_relation_is_written_as_its_value() {
        let value = Value::Union {
            index: 1,
            branch: "axt.RelationOutsideTarget".into(),
            value: Box::new(Value::Record(vec![(
                "uri".into(),
                Value::String("u".into()),
            )])),
        };
        assert_eq!(value.to_json(), json!({"uri": "u"}));
    }
}
