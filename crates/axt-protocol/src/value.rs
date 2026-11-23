//! A decoded Avro value, the library's own (`spec/conformance.md`, section 3.3).

use std::collections::BTreeMap;

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
}
