//! Schema resolution (Avro 1.12 specification, "Schema Resolution"; AXT
//! `spec/envelope.md`, section 6): a plan, compiled once from a writer schema and a reader
//! schema, that turns a datum decoded with the writer schema into a value of the reader
//! schema.
//!
//! Written here rather than taken from `apache-avro`, whose resolution works on the
//! decoded value instead of the two schemas, so that a part of the schemas that does not
//! resolve goes unnoticed until a value takes it; it matches records neither by name nor by
//! alias, and picks a reader branch by the value rather than by its schema. The plan follows
//! the Dart `avro` package that `axt_protocol` for Dart reads with: the order in which a
//! reader branch is chosen, and the matching of named types, are those of its `resolve.dart`.

use std::collections::{BTreeMap, HashMap};

use apache_avro::Schema as AvroSchema;
use apache_avro::schema::{Alias, Name, NamesRef, RecordSchema, UnionSchema};
use apache_avro::types::Value as AvroValue;

use super::{branch_name, json_value, names_its_branch, resolve};
use crate::value::Value;

/// Where a plan step reads from: its position in [`Resolution::steps`].
type StepId = usize;

/// How a datum of the writer schema becomes one of the reader schema.
#[derive(Debug, Clone)]
enum Step {
    /// The value as it is: both schemas are the same primitive or fixed type.
    Same,
    /// A primitive promoted to the reader's type.
    Promote(Promotion),
    /// An enum: the reader's position and symbol for each writer position, `None` where
    /// the reader has neither the symbol nor a default.
    Enum(Vec<Option<(u32, String)>>),
    /// An array of the items' step.
    Array(StepId),
    /// A map of the values' step.
    Map(StepId),
    /// A record.
    Record(RecordStep),
    /// A writer union: the step of each writer branch, or why that branch does not resolve.
    WriterUnion(Vec<Result<StepId, String>>),
    /// The writer's value read as one branch of the reader's union.
    ReaderBranch {
        /// The step of the branch.
        step: StepId,
        /// The branch's position in the reader union.
        index: u32,
        /// The branch's name when the reader union names its branch, see [`Value::Union`].
        name: Option<String>,
    },
}

/// A promotion of the Avro specification.
#[derive(Debug, Clone, Copy)]
enum Promotion {
    Long,
    Float,
    Double,
    Bytes,
    String,
}

/// How a writer record becomes a reader record.
#[derive(Debug, Clone, Default)]
struct RecordStep {
    /// For each writer field, in the writer's order: the reader field it fills and how, or
    /// `None` to drop it.
    fields: Vec<Option<(String, StepId)>>,
    /// The reader fields the writer lacks, with their defaults.
    defaults: Vec<(String, Value)>,
    /// The reader's fields in the reader's order.
    order: Vec<String>,
}

/// The plan that reads data of a writer schema as a reader schema.
#[derive(Debug, Clone)]
pub(crate) struct Resolution {
    steps: Vec<Step>,
    root: StepId,
}

/// The primitive types each type promotes to.
fn promotion(from: &AvroSchema, to: &AvroSchema) -> Option<Promotion> {
    use AvroSchema as S;
    Some(match (from, to) {
        (S::Int, S::Long) => Promotion::Long,
        (S::Int | S::Long, S::Float) => Promotion::Float,
        (S::Int | S::Long | S::Float, S::Double) => Promotion::Double,
        (S::String, S::Bytes) => Promotion::Bytes,
        (S::Bytes, S::String) => Promotion::String,
        _ => return None,
    })
}

/// The type of a schema as its JSON names it: `record`, `enum`, `int`, ...
fn kind(schema: &AvroSchema) -> &'static str {
    match schema {
        AvroSchema::Record(_) => "record",
        AvroSchema::Enum(_) => "enum",
        AvroSchema::Fixed(_) => "fixed",
        AvroSchema::Ref { .. } => "ref",
        AvroSchema::Null => "null",
        AvroSchema::Boolean => "boolean",
        AvroSchema::Int => "int",
        AvroSchema::Long => "long",
        AvroSchema::Float => "float",
        AvroSchema::Double => "double",
        AvroSchema::Bytes => "bytes",
        AvroSchema::String => "string",
        AvroSchema::Array(_) => "array",
        AvroSchema::Map(_) => "map",
        AvroSchema::Union(_) => "union",
        // Logical types are removed before a schema is parsed.
        _ => "logical",
    }
}

/// The name and the aliases of a named type; `apache-avro` qualifies an alias with the
/// type's namespace.
fn named(schema: &AvroSchema) -> Option<(&Name, &[Alias])> {
    let (name, aliases) = match schema {
        AvroSchema::Record(r) => (&r.name, &r.aliases),
        AvroSchema::Enum(e) => (&e.name, &e.aliases),
        AvroSchema::Fixed(f) => (&f.name, &f.aliases),
        _ => return None,
    };
    Some((name, aliases.as_deref().unwrap_or_default()))
}

/// Whether a writer's named type matches a reader's: by its unqualified name, or by an
/// alias of the reader, in full or unqualified (Avro 1.12: named types match by their
/// unqualified names).
fn names_match(writer: &AvroSchema, reader: &AvroSchema) -> bool {
    let (Some((w, _)), Some((r, aliases))) = (named(writer), named(reader)) else {
        return false;
    };
    w.name() == r.name()
        || aliases
            .iter()
            .any(|a| a.fullname(None) == w.fullname(None) || a.name() == w.name())
}

/// Builds a [`Resolution`].
struct Resolver<'a> {
    writer_names: &'a NamesRef<'a>,
    reader_names: &'a NamesRef<'a>,
    steps: Vec<Step>,
    /// The record pairs planned so far, by the full names of writer and reader; a pair
    /// being planned resolves, so that a recursive type ends.
    records: HashMap<(String, String), StepId>,
}

impl<'a> Resolver<'a> {
    /// Adds a step.
    fn push(&mut self, step: Step) -> StepId {
        self.steps.push(step);
        self.steps.len().saturating_sub(1)
    }

    /// Whether the two schemas match at their top, as the specification defines it.
    fn matches(w: &AvroSchema, r: &AvroSchema) -> bool {
        use AvroSchema as S;
        match (w, r) {
            (S::Union(_), _) | (_, S::Union(_)) | (S::Array(_), S::Array(_)) => true,
            (S::Map(_), S::Map(_)) => true,
            (S::Enum(_), S::Enum(_)) | (S::Record(_), S::Record(_)) => names_match(w, r),
            (S::Fixed(a), S::Fixed(b)) => a.size == b.size && names_match(w, r),
            _ => kind(w) == kind(r) || promotion(w, r).is_some(),
        }
    }

    /// The step that reads data of `w` as `r`, or why the two do not resolve at `path`.
    fn plan(&mut self, w: &'a AvroSchema, r: &'a AvroSchema, path: &str) -> Result<StepId, String> {
        let w = resolve(w, self.writer_names)?;
        let r = resolve(r, self.reader_names)?;
        if let AvroSchema::Union(union) = w {
            let branches: Vec<Result<StepId, String>> = union
                .variants()
                .iter()
                .map(|b| self.plan(b, r, &format!("{path}<{}>", branch_name(b))))
                .collect();
            if branches.iter().all(Result::is_err) {
                return Err(format!(
                    "{path}: no branch of the writer union resolves against {}",
                    branch_name(r)
                ));
            }
            return Ok(self.push(Step::WriterUnion(branches)));
        }
        if let AvroSchema::Union(union) = r {
            let Some(i) = self.reader_branch(w, union, path) else {
                return Err(format!(
                    "{path}: no branch of the reader union matches {}",
                    branch_name(w)
                ));
            };
            let branch = union.variants().get(i).ok_or("no such branch")?;
            let step = self.plan(w, branch, path)?;
            let name = names_its_branch(union).then(|| branch_name(branch));
            let index = u32::try_from(i).map_err(|e| e.to_string())?;
            return Ok(self.push(Step::ReaderBranch { step, index, name }));
        }
        if !Self::matches(w, r) {
            return Err(format!(
                "{path}: {} does not resolve to {}",
                branch_name(w),
                branch_name(r)
            ));
        }
        use AvroSchema as S;
        let step = match (w, r) {
            (S::Array(a), S::Array(b)) => {
                Step::Array(self.plan(&a.items, &b.items, &format!("{path}[]"))?)
            }
            (S::Map(a), S::Map(b)) => {
                Step::Map(self.plan(&a.types, &b.types, &format!("{path}{{}}"))?)
            }
            (S::Enum(a), S::Enum(b)) => {
                let reader_symbol = |symbol: &str| {
                    b.symbols
                        .iter()
                        .position(|s| s == symbol)
                        .and_then(|i| Some((u32::try_from(i).ok()?, symbol.to_owned())))
                };
                Step::Enum(
                    a.symbols
                        .iter()
                        .map(|s| {
                            reader_symbol(s)
                                .or_else(|| b.default.as_deref().and_then(reader_symbol))
                        })
                        .collect(),
                )
            }
            (S::Record(a), S::Record(b)) => return self.record(a, b, path),
            _ => match promotion(w, r) {
                Some(p) => Step::Promote(p),
                None => Step::Same,
            },
        };
        Ok(self.push(step))
    }

    /// The reader branch that takes `w`, in the order of Apache Avro's Java implementation
    /// (`Resolver.firstMatchingBranch`) as the Dart `avro` package follows it: the same
    /// type, or the same full name for a named type; then the first record that resolves,
    /// preferring the same unqualified name; then a promotion; then any other match, such
    /// as a name found by alias.
    fn reader_branch(
        &mut self,
        w: &'a AvroSchema,
        r: &'a UnionSchema,
        path: &str,
    ) -> Option<usize> {
        let mut structure = None;
        for (i, b) in r.variants().iter().enumerate() {
            let Ok(b) = resolve(b, self.reader_names) else {
                continue;
            };
            if kind(b) != kind(w) {
                continue;
            }
            match (named(w), named(b)) {
                (Some((wn, _)), Some((bn, _))) => {
                    if wn.fullname(None) == bn.fullname(None) {
                        return Some(i);
                    }
                    if let (AvroSchema::Record(_), AvroSchema::Record(_)) = (w, b)
                        && self.resolves(w, b, path)
                        && (structure.is_none() || wn.name() == bn.name())
                    {
                        structure = Some(i);
                    }
                }
                (None, _) => return Some(i),
                (Some(_), None) => {}
            }
        }
        if structure.is_some() {
            return structure;
        }
        let resolved = |b: &'a AvroSchema| resolve(b, self.reader_names).ok();
        r.variants()
            .iter()
            .position(|b| resolved(b).is_some_and(|b| promotion(w, b).is_some()))
            .or_else(|| {
                r.variants()
                    .iter()
                    .position(|b| resolved(b).is_some_and(|b| Self::matches(w, b)))
            })
    }

    /// Whether `w` resolves to `r`; a failed record pair leaves no step behind.
    fn resolves(&mut self, w: &'a AvroSchema, r: &'a AvroSchema, path: &str) -> bool {
        self.plan(w, r, path).is_ok()
    }

    /// The step of a record pair, planned once.
    fn record(
        &mut self,
        w: &'a RecordSchema,
        r: &'a RecordSchema,
        path: &str,
    ) -> Result<StepId, String> {
        let key = (w.name.fullname(None), r.name.fullname(None));
        if let Some(&id) = self.records.get(&key) {
            return Ok(id);
        }
        let mark = self.steps.len();
        let id = self.push(Step::Record(RecordStep::default()));
        self.records.insert(key, id);
        match self.fill_record(w, r, path) {
            Ok(step) => {
                if let Some(slot) = self.steps.get_mut(id) {
                    *slot = Step::Record(step);
                }
                Ok(id)
            }
            Err(e) => {
                // A failed attempt, such as trying a union branch, must not leave a
                // half-built step that a later pair could refer to.
                self.steps.truncate(mark);
                self.records.retain(|_, &mut step| step < mark);
                Err(e)
            }
        }
    }

    /// The fields of a record pair: matched by name, then by an alias of the reader field.
    fn fill_record(
        &mut self,
        w: &'a RecordSchema,
        r: &'a RecordSchema,
        path: &str,
    ) -> Result<RecordStep, String> {
        let mut used: Vec<&str> = Vec::new();
        let mut fields = Vec::with_capacity(w.fields.len());
        for wf in &w.fields {
            let found = r
                .fields
                .iter()
                .find(|rf| rf.name == wf.name)
                .or_else(|| r.fields.iter().find(|rf| rf.aliases.contains(&wf.name)));
            match found {
                Some(rf) if !used.contains(&rf.name.as_str()) => {
                    used.push(&rf.name);
                    let step = self.plan(&wf.schema, &rf.schema, &format!("{path}.{}", rf.name))?;
                    fields.push(Some((rf.name.clone(), step)));
                }
                _ => fields.push(None),
            }
        }
        let mut defaults = Vec::new();
        for rf in &r.fields {
            if used.contains(&rf.name.as_str()) {
                continue;
            }
            let Some(default) = &rf.default else {
                return Err(format!(
                    "{path}.{}: the reader field has no default and the writer lacks it",
                    rf.name
                ));
            };
            let value = json_value(default, &rf.schema, self.reader_names, true)
                .map_err(|e| format!("{path}.{}: the default {e}", rf.name))?;
            defaults.push((rf.name.clone(), value));
        }
        Ok(RecordStep {
            fields,
            defaults,
            order: r.fields.iter().map(|f| f.name.clone()).collect(),
        })
    }
}

impl Resolution {
    /// The plan that reads data of `writer` as `reader`, or why the two do not resolve.
    pub(crate) fn new(
        writer: &AvroSchema,
        writer_names: &NamesRef,
        reader: &AvroSchema,
        reader_names: &NamesRef,
    ) -> Result<Self, String> {
        let mut resolver = Resolver {
            writer_names,
            reader_names,
            steps: Vec::new(),
            records: HashMap::new(),
        };
        let root = resolver.plan(writer, reader, "")?;
        Ok(Self {
            steps: resolver.steps,
            root,
        })
    }

    /// The reader's value of `value`, a datum that `apache-avro` decoded with the writer
    /// schema; the text says why the value has none, such as a symbol the reader lacks.
    pub(crate) fn apply(&self, value: AvroValue) -> Result<Value, String> {
        self.run(self.root, value)
    }

    fn run(&self, id: StepId, value: AvroValue) -> Result<Value, String> {
        let step = self.steps.get(id).ok_or("no such step")?;
        Ok(match (step, value) {
            (Step::Same, value) => scalar(value)?,
            (Step::Promote(p), value) => promote(*p, value)?,
            (Step::Enum(symbols), AvroValue::Enum(index, symbol)) => {
                let (index, symbol) = usize::try_from(index)
                    .ok()
                    .and_then(|i| symbols.get(i))
                    .ok_or_else(|| format!("{index} is not a symbol of the writer"))?
                    .clone()
                    .ok_or_else(|| {
                        format!("the symbol {symbol} is not the reader's, which has no default")
                    })?;
                Value::Enum { index, symbol }
            }
            (Step::Array(items), AvroValue::Array(values)) => Value::Array(
                values
                    .into_iter()
                    .map(|v| self.run(*items, v))
                    .collect::<Result<_, String>>()?,
            ),
            (Step::Map(values), AvroValue::Map(entries)) => Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| Ok((k, self.run(*values, v)?)))
                    .collect::<Result<BTreeMap<_, _>, String>>()?,
            ),
            (Step::Record(record), AvroValue::Record(values)) => {
                let mut out: HashMap<String, Value> = HashMap::new();
                for (field, (_, v)) in record.fields.iter().zip(values) {
                    if let Some((name, step)) = field {
                        out.insert(name.clone(), self.run(*step, v)?);
                    }
                }
                for (name, default) in &record.defaults {
                    out.insert(name.clone(), default.clone());
                }
                Value::Record(
                    record
                        .order
                        .iter()
                        .map(|name| {
                            let v = out.remove(name).ok_or_else(|| format!("no field {name}"))?;
                            Ok((name.clone(), v))
                        })
                        .collect::<Result<_, String>>()?,
                )
            }
            (Step::WriterUnion(branches), AvroValue::Union(index, inner)) => {
                let branch = usize::try_from(index)
                    .ok()
                    .and_then(|i| branches.get(i))
                    .ok_or_else(|| format!("the union has no branch {index}"))?;
                match branch {
                    Ok(step) => self.run(*step, *inner)?,
                    Err(why) => {
                        return Err(format!(
                            "the writer wrote a branch that does not resolve: {why}"
                        ));
                    }
                }
            }
            (Step::ReaderBranch { step, index, name }, value) => {
                let inner = self.run(*step, value)?;
                match name {
                    Some(branch) => Value::Union {
                        index: *index,
                        branch: branch.clone(),
                        value: Box::new(inner),
                    },
                    None => inner,
                }
            }
            (_, other) => return Err(format!("an unexpected value {other:?}")),
        })
    }
}

/// The library's value of a primitive or fixed value.
fn scalar(value: AvroValue) -> Result<Value, String> {
    Ok(match value {
        AvroValue::Null => Value::Null,
        AvroValue::Boolean(b) => Value::Boolean(b),
        AvroValue::Int(i) => Value::Int(i),
        AvroValue::Long(l) => Value::Long(l),
        AvroValue::Float(f) => Value::Float(f),
        AvroValue::Double(d) => Value::Double(d),
        AvroValue::Bytes(b) => Value::Bytes(b),
        AvroValue::String(s) => Value::String(s),
        AvroValue::Fixed(_, b) => Value::Fixed(b),
        other => return Err(format!("an unexpected value {other:?}")),
    })
}

/// A primitive value promoted to the reader's type.
fn promote(to: Promotion, value: AvroValue) -> Result<Value, String> {
    // The conversions to float and double are those of the Avro specification, which
    // allows the nearest value.
    Ok(match (to, value) {
        (Promotion::Long, AvroValue::Int(i)) => Value::Long(i64::from(i)),
        (Promotion::Float, AvroValue::Int(i)) => Value::Float(i as f32),
        (Promotion::Float, AvroValue::Long(l)) => Value::Float(l as f32),
        (Promotion::Double, AvroValue::Int(i)) => Value::Double(f64::from(i)),
        (Promotion::Double, AvroValue::Long(l)) => Value::Double(l as f64),
        (Promotion::Double, AvroValue::Float(f)) => Value::Double(f64::from(f)),
        (Promotion::Bytes, AvroValue::String(s)) => Value::Bytes(s.into_bytes()),
        (Promotion::String, AvroValue::Bytes(b)) => {
            Value::String(String::from_utf8(b).map_err(|_| "bytes that are not UTF-8 as a string")?)
        }
        (_, other) => return Err(format!("an unexpected value {other:?}")),
    })
}

#[cfg(test)]
mod tests {
    use super::super::{decode_resolved, encode, from_json, parse, resolution};
    use super::*;
    use serde_json::json;

    /// `json`, a value of `writer` in the JSON form of the conformance vectors, read as
    /// `reader`.
    fn read(writer: &str, reader: &str, json: serde_json::Value) -> Result<Value, String> {
        let (w, r) = (parse(writer).unwrap(), parse(reader).unwrap());
        let plan = resolution(&w, &r)?;
        let bytes = encode(&w, &from_json(&w, &json).unwrap()).unwrap();
        decode_resolved(&w, &plan, &bytes)
    }

    fn does_not_resolve(writer: &str, reader: &str) -> bool {
        resolution(&parse(writer).unwrap(), &parse(reader).unwrap()).is_err()
    }

    #[test]
    fn an_unknown_symbol_reads_as_the_default_or_has_no_value() {
        let writer = r#"{"type":"enum","name":"E","symbols":["A","B","C"]}"#;
        let with = r#"{"type":"enum","name":"E","symbols":["B","A"],"default":"B"}"#;
        assert_eq!(
            read(writer, with, json!("A")).unwrap(),
            Value::Enum {
                index: 1,
                symbol: "A".into()
            }
        );
        assert_eq!(
            read(writer, with, json!("C")).unwrap(),
            Value::Enum {
                index: 0,
                symbol: "B".into()
            }
        );
        let without = r#"{"type":"enum","name":"E","symbols":["A"]}"#;
        assert!(read(writer, without, json!("A")).is_ok());
        assert!(read(writer, without, json!("C")).is_err());
        assert!(does_not_resolve(
            writer,
            r#"{"type":"enum","name":"F","symbols":["A"]}"#
        ));
    }

    #[test]
    fn primitives_are_promoted() {
        assert_eq!(
            read("\"int\"", "\"long\"", json!(5)).unwrap(),
            Value::Long(5)
        );
        assert_eq!(
            read("\"int\"", "\"double\"", json!(5)).unwrap(),
            Value::Double(5.0)
        );
        assert_eq!(
            read("\"float\"", "\"double\"", json!(0.5)).unwrap(),
            Value::Double(0.5)
        );
        assert_eq!(
            read("\"string\"", "\"bytes\"", json!("ab")).unwrap(),
            Value::Bytes(b"ab".to_vec())
        );
        assert_eq!(
            read("\"bytes\"", "\"string\"", json!("6162")).unwrap(),
            Value::String("ab".into())
        );
        assert!(read("\"bytes\"", "\"string\"", json!("ff")).is_err());
        assert!(does_not_resolve("\"long\"", "\"int\""));
        assert!(does_not_resolve("\"double\"", "\"float\""));
    }

    #[test]
    fn a_reader_union_takes_the_branch_of_the_same_name_first() {
        let a = r#"{"type":"record","name":"x.A","fields":[{"name":"n","type":"int"}]}"#;
        let reader = r#"[{"type":"record","name":"y.A","fields":[{"name":"n","type":"int"}]},{"type":"record","name":"x.A","fields":[{"name":"n","type":"int"}]},"long"]"#;
        assert_eq!(
            read(a, reader, json!({"n": 1})).unwrap(),
            Value::Union {
                index: 1,
                branch: "x.A".into(),
                value: Box::new(Value::Record(vec![("n".into(), Value::Int(1))])),
            }
        );
        // A promotion comes after the same type, and a union of null and one type holds
        // the value of its branch.
        assert_eq!(
            read("\"int\"", r#"["null","long"]"#, json!(3)).unwrap(),
            Value::Long(3)
        );
        assert_eq!(
            read("\"null\"", r#"["null","long"]"#, json!(null)).unwrap(),
            Value::Null
        );
        assert!(does_not_resolve("\"string\"", r#"["null","long"]"#));
    }

    #[test]
    fn a_writer_branch_that_does_not_resolve_fails_only_when_written() {
        let writer = r#"["null","string"]"#;
        assert_eq!(
            read(writer, "\"string\"", json!("a")).unwrap(),
            Value::String("a".into())
        );
        assert!(read(writer, "\"string\"", json!(null)).is_err());
        assert!(does_not_resolve(r#"["null","int"]"#, "\"string\""));
    }

    #[test]
    fn a_part_that_no_value_takes_is_resolved_too() {
        let writer = r#"{"type":"record","name":"R","fields":[{"name":"l","type":{"type":"array","items":"string"}}]}"#;
        let reader = r#"{"type":"record","name":"R","fields":[{"name":"l","type":{"type":"array","items":"int"}}]}"#;
        assert!(does_not_resolve(writer, reader));
    }

    #[test]
    fn fields_match_by_name_or_alias_and_take_defaults() {
        let writer = r#"{"type":"record","name":"R","fields":[{"name":"a","type":"int"},{"name":"gone","type":"string"},{"name":"old","type":"int"}]}"#;
        let reader = r#"{"type":"record","name":"R","fields":[{"name":"new","aliases":["old"],"type":"int"},{"name":"d","type":{"type":"record","name":"D","fields":[{"name":"x","type":"int","default":1}]},"default":{}},{"name":"a","type":"long"},{"name":"b","type":"bytes","default":"ÿ"}]}"#;
        assert_eq!(
            read(writer, reader, json!({"a": 2, "gone": "x", "old": 3})).unwrap(),
            Value::Record(vec![
                ("new".into(), Value::Int(3)),
                ("d".into(), Value::Record(vec![("x".into(), Value::Int(1))])),
                ("a".into(), Value::Long(2)),
                ("b".into(), Value::Bytes(vec![0xff])),
            ])
        );
    }

    #[test]
    fn a_recursive_type_resolves_once() {
        let list = r#"{"type":"record","name":"L","fields":[{"name":"v","type":"int"},{"name":"next","type":["null","L"]}]}"#;
        let value = read(list, list, json!({"v": 1, "next": {"v": 2, "next": null}})).unwrap();
        assert_eq!(
            value,
            Value::Record(vec![
                ("v".into(), Value::Int(1)),
                (
                    "next".into(),
                    Value::Record(vec![
                        ("v".into(), Value::Int(2)),
                        ("next".into(), Value::Null),
                    ])
                ),
            ])
        );
    }
}
