//! Reading a record of a type with its writer schema (AXT `spec/types.md`, sections 5 and
//! 5.7, and `spec/time.md`, section 8; `spec/fields.md`, sections 11.4 and 12.3).

use crate::avro::Met;
use crate::error::{Error, ErrorCode};
use crate::limits::{PROTOCOL_ERROR_FIELD, TYPES_DATA_DEPTH};
use crate::links::{extensions_problem, relations_problem};
use crate::schema::Schema;
use crate::time_values::{TIME_TYPES, is_valid_time_value};
use crate::value::Value;

/// Decodes `body`, a single-object encoding written with `writer`, with `writer` alone.
///
/// # Errors
///
/// `SCHEMA_UNKNOWN` when the body's fingerprint is not the writer schema's, `UNDECODABLE`
/// when the bytes are no value of the writer schema or nest deeper than
/// `types.data_depth`, and, with `check`, `VALUE_INVALID` for a time value, a relation or
/// an extension that is not valid.
pub(crate) fn decode_record(writer: &Schema, body: &[u8], check: bool) -> Result<Value, Error> {
    let (fingerprint, payload) = crate::avro::split_single_object(body)
        .ok_or_else(|| Error::axt(ErrorCode::Undecodable, "no single-object encoding"))?;
    if fingerprint != writer.fingerprint().0 {
        return Err(Error::axt(
            ErrorCode::SchemaUnknown,
            "the body's fingerprint is not the writer schema's",
        ));
    }
    let value = writer
        .decode_datum(payload)
        .map_err(|e| Error::axt(ErrorCode::Undecodable, e))?;
    if depth(&value) > TYPES_DATA_DEPTH {
        return Err(Error::axt(
            ErrorCode::Undecodable,
            format!("the record nests deeper than {TYPES_DATA_DEPTH}"),
        ));
    }
    if check {
        let found = writer
            .first_problem(&value, "", &rule)
            .map_err(|e| Error::axt(ErrorCode::Undecodable, e))?;
        if let Some(path) = found {
            return Err(value_invalid(&path, "breaks a rule"));
        }
    }
    Ok(value)
}

/// The rules of time values, relations and extensions that every receiver checks.
fn rule(met: Met<'_>, value: &Value, path: &str) -> Option<Option<String>> {
    match (met, value) {
        (Met::Record(name), _) if TIME_TYPES.contains(&name) => {
            Some((!is_valid_time_value(name, value)).then(|| path.to_owned()))
        }
        (Met::Items("axt.Relation"), Value::Array(list)) => Some(relations_problem(list, path)),
        (Met::Items("axt.Extension"), Value::Array(list)) => Some(extensions_problem(list, path)),
        _ => None,
    }
}

/// `VALUE_INVALID` for the value at `path`.
pub(crate) fn value_invalid(path: &str, why: &str) -> Error {
    Error::Axt {
        code: ErrorCode::ValueInvalid,
        message: format!("the value at \"{path}\" {why}"),
        field: field_path(path),
    }
}

/// `path` as the `field` of an error: `None` when it is above `protocol.error_field` bytes.
pub(crate) fn field_path(path: &str) -> Option<String> {
    (path.len() <= PROTOCOL_ERROR_FIELD).then(|| path.to_owned())
}

/// The data depth of `value` (types.md, section 5.7): records, arrays and maps each add
/// one.
fn depth(value: &Value) -> usize {
    let deepest = |values: &mut dyn Iterator<Item = &Value>| {
        values.map(depth).max().unwrap_or(0).saturating_add(1)
    };
    match value {
        Value::Record(fields) => deepest(&mut fields.iter().map(|(_, v)| v)),
        Value::Array(items) => deepest(&mut items.iter()),
        Value::Map(entries) => deepest(&mut entries.values()),
        Value::Union { value, .. } => depth(value),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_depth_counts_records_arrays_and_maps() {
        assert_eq!(depth(&Value::Int(1)), 0);
        let nested = Value::Record(vec![(
            "a".into(),
            Value::Array(vec![Value::Record(vec![])]),
        )]);
        assert_eq!(depth(&nested), 3);
    }

    #[test]
    fn a_field_path_above_the_limit_is_not_named() {
        assert_eq!(field_path("a.b").as_deref(), Some("a.b"));
        assert_eq!(field_path(&"a".repeat(1025)), None);
    }

    #[test]
    fn a_body_is_checked_against_its_writer() {
        let schema = Schema::parse(
            r#"{"type":"record","name":"R","fields":[{"name":"d","type":{"type":"record","name":"Duration","namespace":"axt","fields":[{"name":"months","type":"int"},{"name":"days","type":"int"},{"name":"millis","type":"long"}]}}]}"#,
        )
        .unwrap();
        let duration = |m| {
            Value::Record(vec![(
                "d".into(),
                Value::Record(vec![
                    ("months".into(), Value::Int(m)),
                    ("days".into(), Value::Int(-1)),
                    ("millis".into(), Value::Long(0)),
                ]),
            )])
        };
        let good = schema.encode_single_object(&duration(0)).unwrap();
        assert_eq!(decode_record(&schema, &good, true).unwrap(), duration(0));
        let bad = schema.encode_single_object(&duration(1)).unwrap();
        let e = decode_record(&schema, &bad, true).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::ValueInvalid));
        assert!(matches!(e, Error::Axt { field: Some(f), .. } if f == "d"));
        assert!(decode_record(&schema, &bad, false).is_ok());
        let other = Schema::parse("\"int\"").unwrap();
        let e = decode_record(&other, &good, true).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::SchemaUnknown));
        let e = decode_record(&schema, &good[..good.len() - 1], true).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::Undecodable));
    }
}
