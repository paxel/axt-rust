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
