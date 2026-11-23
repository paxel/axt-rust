//! Reading a record of a type with its writer schema and a reader schema (AXT
//! `spec/types.md`, sections 5 and 5.7, `spec/envelope.md`, section 6, and `spec/time.md`, section 8; `spec/fields.md`, sections 11.4 and 12.3).

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::avro::Met;
use crate::error::{Error, ErrorCode};
use crate::limits::{PROTOCOL_ERROR_FIELD, TYPES_DATA_DEPTH};
use crate::links::{extensions_problem, relations_problem};
use crate::schema::Schema;
use crate::schemas::axt_schema;
use crate::time_values::{TIME_TYPES, is_valid_time_value};
use crate::value::Value;

/// Decodes `body`, a single-object encoding written with `writer`, as `reader`, or as
/// `writer` when `reader` is `None` (types.md, section 5; envelope.md, section 6).
///
/// # Errors
///
/// `DOES_NOT_RESOLVE` when the schema the value is read as defines a named type of the
/// namespace `axt` that is not published as it stands, or when the schemas do not resolve;
/// `SCHEMA_UNKNOWN` when the body's fingerprint is not the writer schema's; `UNDECODABLE`
/// when the bytes are no value of the writer schema, the value has none of the reader
/// schema, or it nests deeper than `types.data_depth`; and, with `check`, `VALUE_INVALID`
/// for a time value, a relation or an extension that is not valid.
pub(crate) fn decode_record(
    writer: &Schema,
    reader: Option<&Schema>,
    body: &[u8],
    check: bool,
) -> Result<Value, Error> {
    // The value is read in the form of the reader: a writer may define the published
    // types without their defaulted fields (types.md, section 7.3), which resolution
    // fills in.
    check_axt_names(reader.unwrap_or(writer))?;
    if let Some(reader) = reader {
        check_type_names(writer, reader)?;
    }
    let (fingerprint, payload) = crate::avro::split_single_object(body)
        .ok_or_else(|| Error::axt(ErrorCode::Undecodable, "no single-object encoding"))?;
    if fingerprint != writer.fingerprint().0 {
        return Err(Error::axt(
            ErrorCode::SchemaUnknown,
            "the body's fingerprint is not the writer schema's",
        ));
    }
    let value = match reader {
        Some(reader) => {
            let resolution = writer
                .resolution(reader)
                .map_err(|e| Error::axt(ErrorCode::DoesNotResolve, e))?;
            // A value without one of the reader, such as a symbol the reader lacks while
            // its enum has no default, is undecodable, as with `axt_protocol` for Dart.
            writer.decode_datum_as(&resolution, payload)
        }
        None => writer.decode_datum(payload),
    }
    .map_err(|e| Error::axt(ErrorCode::Undecodable, e))?;
    if depth(&value) > TYPES_DATA_DEPTH {
        return Err(Error::axt(
            ErrorCode::Undecodable,
            format!("the record nests deeper than {TYPES_DATA_DEPTH}"),
        ));
    }
    if check {
        let found = reader
            .unwrap_or(writer)
            .first_problem(&value, "", &rule)
            .map_err(|e| Error::axt(ErrorCode::Undecodable, e))?;
        if let Some(path) = found {
            return Err(value_invalid(&path, "breaks a rule"));
        }
    }
    Ok(value)
}

/// Checks `value`, a decoded datum of `schema`, as [`decode_record`] does: its data depth,
/// counted from `depth_offset`, and its time values, relations and extensions, named from
/// `path`.
///
/// # Errors
///
/// `UNDECODABLE` for a value deeper than `types.data_depth`, and `VALUE_INVALID` for a
/// time value, a relation or an extension that is not valid.
#[cfg(feature = "conformance")]
pub(crate) fn check_value(
    schema: &Schema,
    value: &Value,
    path: &str,
    depth_offset: usize,
) -> Result<(), Error> {
    if depth(value).saturating_add(depth_offset) > TYPES_DATA_DEPTH {
        return Err(Error::axt(
            ErrorCode::Undecodable,
            format!("the value nests deeper than {TYPES_DATA_DEPTH}"),
        ));
    }
    let found = schema
        .first_problem(value, path, &rule)
        .map_err(|e| Error::axt(ErrorCode::Undecodable, e))?;
    match found {
        Some(path) => Err(value_invalid(&path, "breaks a rule")),
        None => Ok(()),
    }
}

/// The Parsing Canonical Form of each named type that a type may define in the namespace
/// `axt`: the time types, `axt.Relation` with its nested types and `axt.Extension`, by
/// full name.
static PUBLISHED: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    TIME_TYPES
        .iter()
        .chain(&["axt.Relation", "axt.Extension"])
        .filter_map(|name| axt_schema(name)?.named_forms().ok())
        .flatten()
        .collect()
});

/// `DOES_NOT_RESOLVE` when `schema` defines a named type in the namespace `axt` other
/// than one of [`PUBLISHED`] with its published Parsing Canonical Form (time.md, section
/// 3.1; fields.md, sections 11.6 and 12.5).
pub(crate) fn check_axt_names(schema: &Schema) -> Result<(), Error> {
    let forms = schema
        .named_forms()
        .map_err(|e| Error::axt(ErrorCode::DoesNotResolve, e))?;
    for (full_name, form) in forms {
        let in_axt = full_name
            .rsplit_once('.')
            .is_some_and(|(namespace, _)| namespace == "axt");
        if in_axt && PUBLISHED.get(&full_name) != Some(&form) {
            return Err(Error::axt(
                ErrorCode::DoesNotResolve,
                format!("{full_name} is reserved for the published types"),
            ));
        }
    }
    Ok(())
}

/// `DOES_NOT_RESOLVE` unless the full names of the two record schemas match or the
/// writer's is one of the reader's aliases (envelope.md, section 6); Avro itself compares
/// only the unqualified names.
fn check_type_names(writer: &Schema, reader: &Schema) -> Result<(), Error> {
    let (Some((writer_name, _)), Some((reader_name, aliases))) =
        (writer.record_names(), reader.record_names())
    else {
        return Ok(());
    };
    if writer_name != reader_name && !aliases.contains(&writer_name) {
        return Err(Error::axt(
            ErrorCode::DoesNotResolve,
            format!("{writer_name} is neither {reader_name} nor one of its aliases"),
        ));
    }
    Ok(())
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
        assert_eq!(
            decode_record(&schema, None, &good, true).unwrap(),
            duration(0)
        );
        let bad = schema.encode_single_object(&duration(1)).unwrap();
        let e = decode_record(&schema, None, &bad, true).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::ValueInvalid));
        assert!(matches!(e, Error::Axt { field: Some(f), .. } if f == "d"));
        assert!(decode_record(&schema, None, &bad, false).is_ok());
        let other = Schema::parse("\"int\"").unwrap();
        let e = decode_record(&other, None, &good, true).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::SchemaUnknown));
        let e = decode_record(&schema, None, &good[..good.len() - 1], true).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::Undecodable));
    }

    /// The memo of the Dart tests: a text, a due time and tags, with an optional field
    /// more that has a default.
    fn memo(name: &str, extra_field: Option<&str>, aliases: &[&str]) -> Schema {
        let date_time: serde_json::Value =
            serde_json::from_str(crate::schemas::axt_schema_text("axt.DateTime").unwrap()).unwrap();
        let mut fields = vec![
            serde_json::json!({"name": "text", "type": "string"}),
            serde_json::json!({"name": "due", "type": date_time}),
            serde_json::json!({"name": "tags", "type": {"type": "array", "items": "string"}}),
        ];
        if let Some(extra) = extra_field {
            fields.push(serde_json::json!({"name": extra, "type": "int", "default": 7}));
        }
        let mut schema = serde_json::json!({
            "type": "record", "name": name, "namespace": "org.example", "fields": fields,
        });
        if !aliases.is_empty() {
            schema["aliases"] = serde_json::json!(aliases);
        }
        Schema::parse(&schema.to_string()).unwrap()
    }

    fn good_memo(writer: &Schema) -> Vec<u8> {
        let due = writer
            .datum_of_json(&serde_json::json!({
                "text": "vet",
                "due": {"year": 2026, "month": 11, "day": 24, "hour": 10, "minute": 0,
                        "second": 0, "millisecond": 0, "zone": "Europe/Berlin",
                        "offset_seconds": 3600, "instant_ms": 1_795_510_800_000_i64},
                "tags": ["a"],
            }))
            .unwrap();
        writer.encode_single_object(&due).unwrap()
    }

    fn code(result: Result<Value, Error>) -> Option<ErrorCode> {
        result.unwrap_err().code()
    }

    #[test]
    fn resolves_against_a_reader_with_a_field_more() {
        let writer = memo("Memo", None, &[]);
        let good = good_memo(&writer);
        let reader = memo("Memo", Some("n"), &[]);
        let value = decode_record(&writer, Some(&reader), &good, true).unwrap();
        assert_eq!(value.field("n"), Some(&Value::Int(7)));
        assert_eq!(value.field("text"), Some(&Value::String("vet".into())));
    }

    #[test]
    fn takes_a_writer_named_by_an_alias_of_the_reader() {
        let writer = memo("Memo", None, &[]);
        let good = good_memo(&writer);
        for alias in ["Memo", "org.example.Memo"] {
            let reader = memo("Note", None, &[alias]);
            assert!(decode_record(&writer, Some(&reader), &good, true).is_ok());
        }
    }

    #[test]
    fn rejects_a_reader_of_another_name_without_an_alias() {
        let writer = memo("Memo", None, &[]);
        let good = good_memo(&writer);
        let reader = memo("Note", None, &[]);
        let result = decode_record(&writer, Some(&reader), &good, true);
        assert_eq!(code(result), Some(ErrorCode::DoesNotResolve));
    }

    #[test]
    fn rejects_schemas_that_do_not_resolve() {
        let writer = memo("Memo", None, &[]);
        let good = good_memo(&writer);
        let reader = Schema::parse(
            r#"{"type":"record","name":"Memo","namespace":"org.example","fields":[{"name":"missing","type":"int"}]}"#,
        )
        .unwrap();
        let result = decode_record(&writer, Some(&reader), &good, true);
        assert_eq!(code(result), Some(ErrorCode::DoesNotResolve));
        // The schemas are resolved before the bytes are read.
        let mut short = good.clone();
        short.truncate(12);
        let result = decode_record(&writer, Some(&reader), &short, true);
        assert_eq!(code(result), Some(ErrorCode::DoesNotResolve));
    }

    #[test]
    fn rejects_named_types_of_the_namespace_axt_but_the_published_ones() {
        let empty = |schema: &Schema| {
            let value = schema.datum_of_json(&serde_json::json!({"d": {}})).unwrap();
            schema.encode_single_object(&value).unwrap()
        };
        let other =
            Schema::parse(r#"{"type":"record","name":"Mine","namespace":"axt","fields":[]}"#)
                .unwrap();
        let result = decode_record(&other, None, &empty(&other), true);
        assert_eq!(code(result), Some(ErrorCode::DoesNotResolve));
        let changed = Schema::parse(
            r#"{"type":"record","name":"Host","fields":[{"name":"d","type":{"type":"record","name":"Date","namespace":"axt","fields":[]}}]}"#,
        )
        .unwrap();
        let result = decode_record(&changed, None, &empty(&changed), true);
        assert_eq!(code(result), Some(ErrorCode::DoesNotResolve));
        let enums = Schema::parse(
            r#"{"type":"record","name":"E","fields":[{"name":"e","type":{"type":"enum","name":"S","symbols":["A"]}},{"name":"f","type":{"type":"fixed","name":"F","size":1}},{"name":"g","type":"S"}]}"#,
        )
        .unwrap();
        let value = enums
            .datum_of_json(&serde_json::json!({"e": "A", "f": "00", "g": "A"}))
            .unwrap();
        let body = enums.encode_single_object(&value).unwrap();
        assert!(decode_record(&enums, None, &body, true).is_ok());
    }

    #[test]
    fn takes_a_published_type_defined_once_and_referred_to_by_name() {
        // axt.DateTime is defined at `a` and only named at `b`; each is checked as the
        // published type, with what it refers to written out.
        let date_time = crate::schemas::axt_schema_text("axt.DateTime").unwrap();
        let host = Schema::parse(&format!(
            r#"{{"type":"record","name":"Host","namespace":"org.example","fields":[{{"name":"a","type":{date_time}}},{{"name":"b","type":"axt.DateTime"}},{{"name":"x","type":{{"type":"array","items":{}}}}}]}}"#,
            crate::schemas::axt_schema_text("axt.Extension").unwrap()
        ))
        .unwrap();
        assert!(check_axt_names(&host).is_ok());
    }

    #[test]
    fn takes_axt_extension_as_published_and_checks_its_rules() {
        let host = Schema::parse(&format!(
            r#"{{"type":"record","name":"Host","namespace":"org.example","fields":[{{"name":"extensions","type":{{"type":"array","items":{}}}}}]}}"#,
            crate::schemas::axt_schema_text("axt.Extension").unwrap()
        ))
        .unwrap();
        let body = |data: &str| {
            let value = host
                .datum_of_json(&serde_json::json!({
                    "extensions": [{"name": "org.example.A", "data": data}],
                }))
                .unwrap();
            host.encode_single_object(&value).unwrap()
        };
        assert!(decode_record(&host, None, &body("c3010000000000000000"), true).is_ok());
        let e = decode_record(&host, None, &body("0000000000000000"), true).unwrap_err();
        assert!(
            matches!(&e, Error::Axt { field: Some(f), .. } if f == "extensions[0].data"),
            "{e:?}"
        );
    }
}
