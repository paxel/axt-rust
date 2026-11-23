//! Typed fields as Avro bricks: descriptions, their validity, the schema derived from them,
//! what a receiver shows of them, and the checks of their values (AXT `spec/fields.md`;
//! `spec/metadata.md`, sections 4 to 7).

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value as Json, json};

use crate::error::{Error, ErrorCode};
use crate::iregexp::IRegexp;
use crate::limits::{
    ENVELOPE_SCHEMA, ENVELOPE_SCHEMA_DEPTH, FIELDS_DEPTH, FIELDS_LONG_DEFAULT,
    MANIFEST_LANGUAGE_TAG, METADATA_EMOJI, METADATA_EXAMPLE, METADATA_GROUP_KEY, METADATA_HELP,
    METADATA_LABEL, METADATA_PLACEHOLDER, METADATA_TRANSLATIONS,
};
use crate::links::{extensions_problem, is_avro_name, relations_problem};
use crate::manifest::{is_language_tag, lookup};
use crate::schemas::{axt_schema, axt_schema_text};
use crate::time_values::is_valid_time_value;
use crate::value::Value;

// ---------------------------------------------------------------- the model

/// The texts of a field, a symbol or a group (`axt.FieldTexts`).
#[derive(Debug, Clone)]
pub(crate) struct Texts {
    label: String,
    label_translations: BTreeMap<String, String>,
    help: String,
    help_translations: BTreeMap<String, String>,
    emoji: String,
}

/// A typed field: a decoded `axt.Field`.
#[derive(Debug, Clone)]
pub(crate) struct Field {
    pub(crate) name: String,
    doc: String,
    pub(crate) texts: Texts,
    required: bool,
    order: Option<i64>,
    group: String,
    sensitive: bool,
    advanced: bool,
    /// The full name of the brick, such as `axt.EmailField`.
    brick: String,
    pub(crate) kind: Kind,
}

/// The `pattern` of a brick of text, compiled once.
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    /// The pattern; `None` when it is not an I-Regexp within its limits.
    compiled: Option<IRegexp>,
}

impl Pattern {
    fn new(pattern: &str) -> Self {
        Self {
            compiled: IRegexp::compile(pattern),
        }
    }
}

/// The members of a brick of text: `axt.StringField` and the semantic bricks.
#[derive(Debug, Clone)]
pub(crate) struct Text {
    default: Option<String>,
    min_length: Option<i64>,
    max_length: Option<i64>,
    pattern: Option<Pattern>,
    preferred_length: Option<i64>,
    placeholder: String,
    example: String,
}

/// The members of a brick of numbers.
#[derive(Debug, Clone)]
pub(crate) struct Numbers<T> {
    default: Option<T>,
    min: Option<T>,
    max: Option<T>,
    unit: String,
    placeholder: String,
    example: String,
}

/// A symbol of an enum.
#[derive(Debug, Clone)]
pub(crate) struct Symbol {
    symbol: String,
    texts: Texts,
}

/// An object: `axt.ObjectField`.
#[derive(Debug, Clone)]
pub(crate) struct Object {
    pub(crate) name: String,
    fields: Vec<Field>,
    groups: Vec<(String, Texts)>,
    version: Option<i64>,
    title: String,
}

/// The brick of a typed field, with its members.
#[derive(Debug, Clone)]
pub(crate) enum Kind {
    /// `axt.StringField` or a semantic brick.
    Text(Text),
    /// `axt.IntField` or `axt.LongField`.
    Integer(Numbers<i64>),
    /// `axt.DoubleField`.
    Double(Numbers<f64>),
    /// `axt.BooleanField`.
    Boolean { default: Option<bool> },
    /// `axt.BytesField`.
    Bytes {
        default: Option<Vec<u8>>,
        min_length: Option<i64>,
        max_length: Option<i64>,
    },
    /// `axt.EnumField`.
    Enum {
        name: String,
        symbols: Vec<Symbol>,
        fallback: String,
        default: Option<String>,
    },
    /// `axt.ListField`.
    List(Box<Field>),
    /// `axt.MapField`.
    Map(Box<Field>),
    /// `axt.ObjectField`.
    Object(Object),
    /// `axt.DateField`, `axt.TimeField`, `axt.DateTimeField` or `axt.DurationField`, by
    /// the full name of its time type.
    Time(&'static str),
    /// `axt.RelationField`.
    Relation,
    /// `axt.ExtensionField`.
    Extension,
}

/// The format of each semantic brick (fields.md, section 5).
const FORMATS: [(&str, &str); 13] = [
    ("axt.MarkdownField", "markdown"),
    ("axt.EmailField", "email"),
    ("axt.PhoneField", "phone"),
    ("axt.UrlField", "url"),
    ("axt.UriField", "uri"),
    ("axt.ColourField", "colour"),
    ("axt.IbanField", "iban"),
    ("axt.BicField", "bic"),
    ("axt.CountryField", "country"),
    ("axt.LanguageField", "language"),
    ("axt.CurrencyField", "currency"),
    ("axt.MediaTypeField", "media-type"),
    ("axt.UcumField", "ucum"),
];

/// The full names that a description may not give an object or an enum.
const RESERVED: [&str; 8] = [
    "axt.Date",
    "axt.Time",
    "axt.DateTime",
    "axt.Duration",
    "axt.Relation",
    "axt.RelationRecordTarget",
    "axt.RelationRecordTargetSender",
    "axt.RelationOutsideTarget",
];

/// A datum that is not one of `axt.Field`.
fn not_a_field(what: &str) -> Error {
    Error::axt(
        ErrorCode::DescriptionInvalid,
        format!("not a datum of axt.Field: {what}"),
    )
}

fn member<'a>(v: &'a Value, name: &str) -> Result<&'a Value, Error> {
    v.field(name).ok_or_else(|| not_a_field(name))
}

fn string(v: &Value, name: &str) -> Result<String, Error> {
    match member(v, name)? {
        Value::String(s) => Ok(s.clone()),
        _ => Err(not_a_field(name)),
    }
}

fn optional_string(v: &Value, name: &str) -> Result<Option<String>, Error> {
    match member(v, name)? {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        _ => Err(not_a_field(name)),
    }
}

fn optional_integer(v: &Value, name: &str) -> Result<Option<i64>, Error> {
    match member(v, name)? {
        Value::Null => Ok(None),
        Value::Int(i) => Ok(Some(i64::from(*i))),
        Value::Long(l) => Ok(Some(*l)),
        _ => Err(not_a_field(name)),
    }
}

fn optional_double(v: &Value, name: &str) -> Result<Option<f64>, Error> {
    match member(v, name)? {
        Value::Null => Ok(None),
        Value::Double(d) => Ok(Some(*d)),
        _ => Err(not_a_field(name)),
    }
}

fn flag(v: &Value, name: &str) -> Result<bool, Error> {
    match member(v, name)? {
        Value::Boolean(b) => Ok(*b),
        _ => Err(not_a_field(name)),
    }
}

fn list<'a>(v: &'a Value, name: &str) -> Result<&'a [Value], Error> {
    match member(v, name)? {
        Value::Array(items) => Ok(items),
        _ => Err(not_a_field(name)),
    }
}

fn strings(v: &Value, name: &str) -> Result<BTreeMap<String, String>, Error> {
    match member(v, name)? {
        Value::Map(entries) => entries
            .iter()
            .map(|(k, v)| match v {
                Value::String(s) => Ok((k.clone(), s.clone())),
                _ => Err(not_a_field(name)),
            })
            .collect(),
        _ => Err(not_a_field(name)),
    }
}

impl Texts {
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(Self {
            label: string(v, "label")?,
            label_translations: strings(v, "label_translations")?,
            help: string(v, "help")?,
            help_translations: strings(v, "help_translations")?,
            emoji: string(v, "emoji")?,
        })
    }
}

impl<T> Numbers<T> {
    fn from_value(
        b: &Value,
        number: fn(&Value, &str) -> Result<Option<T>, Error>,
    ) -> Result<Self, Error> {
        Ok(Self {
            default: number(b, "default")?,
            min: number(b, "min")?,
            max: number(b, "max")?,
            unit: string(b, "unit")?,
            placeholder: string(b, "placeholder")?,
            example: string(b, "example")?,
        })
    }
}

impl Object {
    fn from_value(b: &Value) -> Result<Self, Error> {
        Ok(Self {
            name: string(b, "name")?,
            fields: list(b, "fields")?
                .iter()
                .map(Field::from_value)
                .collect::<Result<_, _>>()?,
            groups: list(b, "groups")?
                .iter()
                .map(|g| Ok((string(g, "key")?, Texts::from_value(member(g, "texts")?)?)))
                .collect::<Result<_, Error>>()?,
            version: optional_integer(b, "version")?,
            title: string(b, "title")?,
        })
    }
}

impl Field {
    /// The typed field of `v`, a decoded datum of `axt.Field`.
    pub(crate) fn from_value(v: &Value) -> Result<Self, Error> {
        let Value::Union { branch, value, .. } = member(v, "kind")? else {
            return Err(not_a_field("kind"));
        };
        let b = value.as_ref();
        let kind = match branch.as_str() {
            "axt.StringField" => Kind::Text(Text {
                default: optional_string(b, "default")?,
                min_length: optional_integer(b, "min_length")?,
                max_length: optional_integer(b, "max_length")?,
                pattern: optional_string(b, "pattern")?.as_deref().map(Pattern::new),
                preferred_length: optional_integer(b, "preferred_length")?,
                placeholder: string(b, "placeholder")?,
                example: string(b, "example")?,
            }),
            semantic if FORMATS.iter().any(|(brick, _)| *brick == semantic) => Kind::Text(Text {
                default: optional_string(b, "default")?,
                min_length: optional_integer(b, "min_length")?,
                max_length: optional_integer(b, "max_length")?,
                pattern: None,
                preferred_length: optional_integer(b, "preferred_length")?,
                placeholder: string(b, "placeholder")?,
                example: string(b, "example")?,
            }),
            "axt.IntField" | "axt.LongField" => {
                Kind::Integer(Numbers::from_value(b, optional_integer)?)
            }
            "axt.DoubleField" => Kind::Double(Numbers::from_value(b, optional_double)?),
            "axt.BooleanField" => Kind::Boolean {
                default: match member(b, "default")? {
                    Value::Null => None,
                    Value::Boolean(d) => Some(*d),
                    _ => return Err(not_a_field("default")),
                },
            },
            "axt.BytesField" => Kind::Bytes {
                default: match member(b, "default")? {
                    Value::Null => None,
                    Value::Bytes(d) => Some(d.clone()),
                    _ => return Err(not_a_field("default")),
                },
                min_length: optional_integer(b, "min_length")?,
                max_length: optional_integer(b, "max_length")?,
            },
            "axt.EnumField" => Kind::Enum {
                name: string(b, "name")?,
                symbols: list(b, "symbols")?
                    .iter()
                    .map(|s| {
                        Ok(Symbol {
                            symbol: string(s, "symbol")?,
                            texts: Texts::from_value(member(s, "texts")?)?,
                        })
                    })
                    .collect::<Result<_, Error>>()?,
                fallback: string(b, "fallback")?,
                default: optional_string(b, "default")?,
            },
            "axt.ListField" => Kind::List(Box::new(Self::from_value(member(b, "items")?)?)),
            "axt.MapField" => Kind::Map(Box::new(Self::from_value(member(b, "values")?)?)),
            "axt.ObjectField" => Kind::Object(Object::from_value(b)?),
            "axt.DateField" => Kind::Time("axt.Date"),
            "axt.TimeField" => Kind::Time("axt.Time"),
            "axt.DateTimeField" => Kind::Time("axt.DateTime"),
            "axt.DurationField" => Kind::Time("axt.Duration"),
            "axt.RelationField" => Kind::Relation,
            "axt.ExtensionField" => Kind::Extension,
            other => return Err(not_a_field(other)),
        };
        Ok(Self {
            name: string(v, "name")?,
            doc: string(v, "doc")?,
            texts: Texts::from_value(member(v, "texts")?)?,
            required: flag(v, "required")?,
            order: optional_integer(v, "order")?,
            group: string(v, "group")?,
            sensitive: flag(v, "sensitive")?,
            advanced: flag(v, "advanced")?,
            brick: branch.clone(),
            kind,
        })
    }

    /// The format of a semantic brick, or `None`.
    fn format(&self) -> Option<&'static str> {
        FORMATS
            .iter()
            .find(|(brick, _)| *brick == self.brick)
            .map(|&(_, format)| format)
    }

    /// The brick's default, where it gives one, as a value of the field.
    fn default_value(&self) -> Option<Value> {
        match &self.kind {
            Kind::Text(t) => t.default.clone().map(Value::String),
            Kind::Integer(n) => n.default.map(Value::Long),
            Kind::Double(n) => n.default.map(Value::Double),
            Kind::Boolean { default } => default.map(Value::Boolean),
            Kind::Bytes { default, .. } => default.clone().map(Value::Bytes),
            Kind::Enum { default, .. } => default
                .clone()
                .map(|symbol| Value::Enum { index: 0, symbol }),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------- decoding

/// The schema `axt.Field`, embedded.
fn field_schema() -> Result<&'static crate::schema::Schema, Error> {
    axt_schema("axt.Field").ok_or_else(|| Error::axt(ErrorCode::DescriptionInvalid, "no axt.Field"))
}

/// Decodes a description from its Avro encoding, a datum of `axt.Field`.
///
/// # Errors
///
/// `UNDECODABLE` for bytes that are not a datum of `axt.Field`.
pub(crate) fn decode_description(bytes: &[u8]) -> Result<Value, Error> {
    field_schema()?
        .decode_datum(bytes)
        .map_err(|e| Error::axt(ErrorCode::Undecodable, e))
}

/// A description from its JSON form (fields.md, section 10.3).
///
/// # Errors
///
/// `DESCRIPTION_INVALID` for JSON that is not a datum of `axt.Field` in that form.
pub(crate) fn description_from_json(json: &Json) -> Result<Value, Error> {
    field_schema()?
        .datum_of_json(json)
        .map_err(|e| Error::axt(ErrorCode::DescriptionInvalid, e))
}

// ---------------------------------------------------------------- validity

fn invalid(path: &str, why: &str) -> Error {
    Error::Axt {
        code: ErrorCode::DescriptionInvalid,
        message: format!("{path}: {why}"),
        field: Some(path.to_owned()),
    }
}

/// Whether `text` is one line of at most `max` bytes.
fn one_line(text: &str, max: usize) -> bool {
    text.len() <= max
        && !text.chars().any(|c| {
            c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c) || c == '\u{2028}' || c == '\u{2029}'
        })
}

/// `[a-z][a-z0-9]*(_[a-z0-9]+)*`, or the same in upper case for `upper`.
fn is_snake(text: &str, upper: bool) -> bool {
    let letter = |b: u8| {
        if upper {
            b.is_ascii_uppercase()
        } else {
            b.is_ascii_lowercase()
        }
    };
    let mut bytes = text.bytes();
    bytes.next().is_some_and(letter)
        && text
            .bytes()
            .all(|b| letter(b) || b.is_ascii_digit() || b == b'_')
        && !text.contains("__")
        && !text.ends_with('_')
}

/// `[A-Z][A-Za-z0-9]*`.
fn is_upper_camel(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_uppercase()) && bytes.all(|b| b.is_ascii_alphanumeric())
}

/// Whether `emoji` is an emoji as metadata.md, section 4.3, has it.
fn is_emoji(emoji: &str) -> bool {
    let runes: Vec<char> = emoji.chars().collect();
    if runes.is_empty() || runes.len() > METADATA_EMOJI {
        return false;
    }
    let keycap = match runes.as_slice() {
        [first, '\u{20e3}'] | [first, '\u{fe0f}', '\u{20e3}'] => {
            *first == '#' || *first == '*' || first.is_ascii_digit()
        }
        _ => false,
    };
    runes.iter().enumerate().all(|(i, &r)| {
        let space = matches!(
            r,
            ' ' | '\u{a0}'
                | '\u{1680}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
        ) || ('\u{2000}'..='\u{200a}').contains(&r);
        let control = r < ' ' || ('\u{7f}'..='\u{9f}').contains(&r);
        !space && !control && (r >= '\u{80}' || (i == 0 && keycap))
    })
}

fn check_texts(texts: &Texts, path: &str) -> Result<(), Error> {
    if !one_line(&texts.label, METADATA_LABEL) {
        return Err(invalid(&format!("{path}.label"), "not one line"));
    }
    if !one_line(&texts.help, METADATA_HELP) {
        return Err(invalid(&format!("{path}.help"), "not one line"));
    }
    for (name, english, translations, max) in [
        (
            "label_translations",
            &texts.label,
            &texts.label_translations,
            METADATA_LABEL,
        ),
        (
            "help_translations",
            &texts.help,
            &texts.help_translations,
            METADATA_HELP,
        ),
    ] {
        if translations.is_empty() {
            continue;
        }
        let at = format!("{path}.{name}");
        if english.is_empty() {
            return Err(invalid(&at, "translations without an English text"));
        }
        if translations.len() > METADATA_TRANSLATIONS {
            return Err(invalid(&at, "too many"));
        }
        let mut seen = HashSet::new();
        for (key, value) in translations {
            let lower = key.to_lowercase();
            if key.encode_utf16().count() > MANIFEST_LANGUAGE_TAG
                || !is_language_tag(key)
                || lower == "en"
                || !seen.insert(lower)
                || value.is_empty()
                || !one_line(value, max)
            {
                return Err(invalid(&at, "a key or a text breaks its rules"));
            }
        }
    }
    if !texts.emoji.is_empty() && !is_emoji(&texts.emoji) {
        return Err(invalid(&format!("{path}.emoji"), "not an emoji"));
    }
    Ok(())
}

/// Checks that `root`, the typed field of `datum`, is a valid description (fields.md,
/// sections 3 to 6 and 9.1), and gives the text of its derived schema (section 9.3).
///
/// # Errors
///
/// `DESCRIPTION_INVALID`, whose `field` names the member that breaks a rule.
pub(crate) fn derive_schema(root: &Field, datum: &Value) -> Result<String, Error> {
    let Kind::Object(object) = &root.kind else {
        return Err(invalid("kind", "the root is not an object"));
    };
    if root.required
        || root.order.is_some()
        || !root.group.is_empty()
        || root.sensitive
        || root.advanced
    {
        return Err(invalid(
            "",
            "a root with required, an order, a group, sensitive or advanced",
        ));
    }
    if root.doc.trim().is_empty() {
        return Err(invalid("doc", "empty"));
    }
    check_texts(&root.texts, "texts")?;
    let name = &object.name;
    let parts: Vec<&str> = name.split('.').collect();
    let Some((last, namespace)) = parts.split_last() else {
        return Err(invalid("kind.name", "the root's name has no namespace"));
    };
    if namespace.is_empty() || !parts.iter().all(|p| is_avro_name(p)) || !is_upper_camel(last) {
        return Err(invalid("kind.name", "the root's name has no namespace"));
    }
    if object.version.is_none_or(|v| v < 1) {
        return Err(invalid("kind.version", "no version of at least 1"));
    }
    let namespace = namespace.join(".");
    let mut names = HashSet::from([name.clone()]);
    check_object(object, "kind", &namespace, &mut names, 1, true)?;
    let size = field_schema()?
        .encode_datum(datum)
        .map_err(|e| Error::axt(ErrorCode::DescriptionInvalid, e))?
        .len();
    let schema = derive_schema_json(root)?;
    let text = canonical_json(&schema);
    if size > ENVELOPE_SCHEMA || text.len() > ENVELOPE_SCHEMA {
        return Err(invalid(
            "",
            "a description or its derived schema of more than 256 KiB",
        ));
    }
    if json_depth(&schema) > ENVELOPE_SCHEMA_DEPTH {
        return Err(invalid("", "a derived schema nested deeper than 64"));
    }
    Ok(text)
}

/// The depth of `json`: objects and arrays each add one.
fn json_depth(json: &Json) -> usize {
    let deepest = |values: &mut dyn Iterator<Item = &Json>| {
        values.map(json_depth).max().unwrap_or(0).saturating_add(1)
    };
    match json {
        Json::Object(members) => deepest(&mut members.values()),
        Json::Array(items) => deepest(&mut items.iter()),
        _ => 0,
    }
}

fn check_object(
    object: &Object,
    path: &str,
    namespace: &str,
    names: &mut HashSet<String>,
    depth: usize,
    is_root: bool,
) -> Result<(), Error> {
    if !is_root {
        let at = format!("{path}.name");
        if object.name.contains('.') {
            return Err(invalid(&at, "a nested name with a namespace"));
        }
        if !is_upper_camel(&object.name) {
            return Err(invalid(&at, "not an Avro name in UpperCamelCase"));
        }
        let full = format!("{namespace}.{}", object.name);
        if RESERVED.contains(&full.as_str()) || !names.insert(full) {
            return Err(invalid(&at, "a full name that another object or enum has"));
        }
        if object.version.is_some() {
            return Err(invalid(
                &format!("{path}.version"),
                "a version in a nested object",
            ));
        }
    }
    if object.fields.is_empty() {
        return Err(invalid(&format!("{path}.fields"), "no field"));
    }
    let mut keys = HashSet::new();
    for (i, (key, texts)) in object.groups.iter().enumerate() {
        if !is_snake(key, false) || key.len() > METADATA_GROUP_KEY || !keys.insert(key.as_str()) {
            return Err(invalid(
                &format!("{path}.groups[{i}].key"),
                "not a group key, or a second time",
            ));
        }
        check_texts(texts, &format!("{path}.groups[{i}].texts"))?;
    }
    let mut field_names = HashSet::new();
    let mut used = HashSet::new();
    for (i, field) in object.fields.iter().enumerate() {
        let at = format!("{path}.fields[{i}]");
        if !is_snake(&field.name, false) {
            return Err(invalid(
                &format!("{at}.name"),
                "not a field name in snake_case",
            ));
        }
        if !field_names.insert(field.name.as_str()) {
            return Err(invalid(
                &format!("{at}.name"),
                "a second field of this name",
            ));
        }
        if !field.group.is_empty() {
            if !keys.contains(field.group.as_str()) {
                return Err(invalid(
                    &format!("{at}.group"),
                    "not a key of the object's groups",
                ));
            }
            used.insert(field.group.as_str());
        }
        check_field(field, &at, namespace, names, depth.saturating_add(1))?;
    }
    for (i, (key, _)) in object.groups.iter().enumerate() {
        if !used.contains(key.as_str()) {
            return Err(invalid(
                &format!("{path}.groups[{i}]"),
                "a group that no field names",
            ));
        }
    }
    if !object.title.is_empty()
        && !object
            .fields
            .iter()
            .any(|f| f.name == object.title && matches!(f.kind, Kind::Text(_)))
    {
        return Err(invalid(
            &format!("{path}.title"),
            "not the name of a field of text of the object",
        ));
    }
    Ok(())
}

/// Whether `example` is within `metadata.example` bytes, without a control character
/// other than LF.
fn example_keeps(example: &str) -> bool {
    example.len() <= METADATA_EXAMPLE
        && !example
            .chars()
            .any(|c| (c < ' ' && c != '\n') || ('\u{7f}'..='\u{9f}').contains(&c))
}

fn check_lengths(min: Option<i64>, max: Option<i64>, k: &str) -> Result<(), Error> {
    if min.is_some_and(|m| m < 0) {
        return Err(invalid(&format!("{k}.min_length"), "below 0"));
    }
    if max.is_some_and(|m| m < 0) {
        return Err(invalid(&format!("{k}.max_length"), "below 0"));
    }
    if let (Some(min), Some(max)) = (min, max)
        && min > max
    {
        return Err(invalid(
            &format!("{k}.min_length"),
            "larger than max_length",
        ));
    }
    Ok(())
}

fn check_placeholder(placeholder: &str, k: &str) -> Result<(), Error> {
    if one_line(placeholder, METADATA_PLACEHOLDER) {
        Ok(())
    } else {
        Err(invalid(
            &format!("{k}.placeholder"),
            "not one line of at most 256 bytes",
        ))
    }
}

fn check_example(example: &str, k: &str) -> Result<(), Error> {
    if example_keeps(example) {
        Ok(())
    } else {
        Err(invalid(
            &format!("{k}.example"),
            "more than 1,024 bytes, or a control character other than LF",
        ))
    }
}

/// Whether `code` has the syntax of a UCUM code: printable ASCII without a space.
fn is_ucum(code: &str) -> bool {
    !code.is_empty() && code.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Fails with `path` when `default` breaks a check of `field`.
fn check_default(field: &Field, default: Option<Value>, path: &str) -> Result<(), Error> {
    match default {
        Some(value) if check_value(field, &value, "", field.required).is_some() => {
            Err(invalid(path, "breaks a check of the field"))
        }
        _ => Ok(()),
    }
}

fn check_field(
    field: &Field,
    path: &str,
    namespace: &str,
    names: &mut HashSet<String>,
    depth: usize,
) -> Result<(), Error> {
    if depth > FIELDS_DEPTH {
        return Err(invalid("", "typed fields nested deeper than 64"));
    }
    if field.doc.trim().is_empty() {
        return Err(invalid(&format!("{path}.doc"), "empty"));
    }
    check_texts(&field.texts, &format!("{path}.texts"))?;
    let k = format!("{path}.kind");
    match &field.kind {
        Kind::Text(t) => {
            check_lengths(t.min_length, t.max_length, &k)?;
            if t.pattern.as_ref().is_some_and(|p| p.compiled.is_none()) {
                return Err(invalid(
                    &format!("{k}.pattern"),
                    "not an I-Regexp within its limits",
                ));
            }
            if let Some(preferred) = t.preferred_length
                && (preferred < 1 || t.max_length.is_some_and(|max| preferred > max))
            {
                return Err(invalid(
                    &format!("{k}.preferred_length"),
                    "below 1 or above max_length",
                ));
            }
            check_placeholder(&t.placeholder, &k)?;
            check_example(&t.example, &k)?;
            if !t.example.is_empty()
                && check_value(field, &Value::String(t.example.clone()), "", field.required)
                    .is_some()
            {
                return Err(invalid(
                    &format!("{k}.example"),
                    "breaks a check of the field",
                ));
            }
            check_default(field, field.default_value(), &format!("{k}.default"))?;
        }
        Kind::Integer(n) => {
            if let (Some(min), Some(max)) = (n.min, n.max)
                && min > max
            {
                return Err(invalid(&format!("{k}.min"), "larger than max"));
            }
            if field.brick == "axt.LongField"
                && n.default
                    .is_some_and(|d| d.unsigned_abs() > FIELDS_LONG_DEFAULT)
            {
                return Err(invalid(
                    &format!("{k}.default"),
                    "not a finite number, or a long above 2^53 in magnitude",
                ));
            }
            check_default(field, field.default_value(), &format!("{k}.default"))?;
            check_unit_and_hints(&n.unit, &n.placeholder, &n.example, &k)?;
        }
        Kind::Double(n) => {
            if n.min.is_some_and(|m| !m.is_finite()) {
                return Err(invalid(&format!("{k}.min"), "not a finite number"));
            }
            if n.max.is_some_and(|m| !m.is_finite()) {
                return Err(invalid(&format!("{k}.max"), "not a finite number"));
            }
            if let (Some(min), Some(max)) = (n.min, n.max)
                && min > max
            {
                return Err(invalid(&format!("{k}.min"), "larger than max"));
            }
            if n.default.is_some_and(|d| !d.is_finite()) {
                return Err(invalid(
                    &format!("{k}.default"),
                    "not a finite number, or a long above 2^53 in magnitude",
                ));
            }
            check_default(field, field.default_value(), &format!("{k}.default"))?;
            check_unit_and_hints(&n.unit, &n.placeholder, &n.example, &k)?;
        }
        Kind::Bytes {
            min_length,
            max_length,
            ..
        } => {
            check_lengths(*min_length, *max_length, &k)?;
            check_default(field, field.default_value(), &format!("{k}.default"))?;
        }
        Kind::Enum {
            name,
            symbols,
            fallback,
            default,
        } => {
            if !is_upper_camel(name) {
                return Err(invalid(
                    &format!("{k}.name"),
                    "not an Avro name in UpperCamelCase",
                ));
            }
            let full = format!("{namespace}.{name}");
            if RESERVED.contains(&full.as_str()) || !names.insert(full) {
                return Err(invalid(
                    &format!("{k}.name"),
                    "a full name that another object or enum has",
                ));
            }
            if symbols.is_empty() {
                return Err(invalid(&format!("{k}.symbols"), "no symbol"));
            }
            let mut seen = HashSet::new();
            for (i, s) in symbols.iter().enumerate() {
                if !is_snake(&s.symbol, true) || !seen.insert(s.symbol.as_str()) {
                    return Err(invalid(
                        &format!("{k}.symbols[{i}].symbol"),
                        "not a symbol in UPPER_SNAKE_CASE, or a second time",
                    ));
                }
                check_texts(&s.texts, &format!("{k}.symbols[{i}].texts"))?;
            }
            if !seen.contains(fallback.as_str()) {
                return Err(invalid(&format!("{k}.fallback"), "not one of the symbols"));
            }
            if default.as_ref().is_some_and(|d| !seen.contains(d.as_str())) {
                return Err(invalid(&format!("{k}.default"), "not one of the symbols"));
            }
        }
        Kind::List(item) | Kind::Map(item) => {
            let member = if matches!(field.kind, Kind::List(_)) {
                "items"
            } else {
                "values"
            };
            if item.name != field.name {
                return Err(invalid(
                    &format!("{k}.{member}.name"),
                    "not the name of its list or map",
                ));
            }
            if item.order.is_some() || !item.group.is_empty() || item.sensitive || item.advanced {
                return Err(invalid(
                    &format!("{k}.{member}"),
                    "an order, group, sensitive or advanced of its own",
                ));
            }
            check_field(
                item,
                &format!("{k}.{member}"),
                namespace,
                names,
                depth.saturating_add(1),
            )?;
        }
        Kind::Object(object) => check_object(object, &k, namespace, names, depth, false)?,
        Kind::Boolean { .. } | Kind::Time(_) | Kind::Relation | Kind::Extension => {}
    }
    Ok(())
}

fn check_unit_and_hints(
    unit: &str,
    placeholder: &str,
    example: &str,
    k: &str,
) -> Result<(), Error> {
    if !unit.is_empty() && !is_ucum(unit) {
        return Err(invalid(&format!("{k}.unit"), "not a UCUM code"));
    }
    check_placeholder(placeholder, k)?;
    check_example(example, k)
}

// ---------------------------------------------------------------- formats

/// A regular expression of the library's own; `None` only if it failed to compile, which a
/// test rules out.
fn compiled(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

/// The URI of RFC 3986, with the scheme as group 1 and the host as group 3.
static URI: LazyLock<Option<Regex>> = LazyLock::new(|| {
    let unreserved = r"A-Za-z0-9\-._~";
    let sub_delims = r"!$&'()*+,;=";
    let pchar = format!("(?:[{unreserved}{sub_delims}:@]|%[0-9A-Fa-f]{{2}})");
    compiled(&format!(
        concat!(
            r"\A([A-Za-z][A-Za-z0-9+.\-]*):",
            r"(?://((?:(?:[{u}{s}:]|%[0-9A-Fa-f]{{2}})*@)?",
            r"(\[[0-9A-Fa-f:.vV{u}{s}]*\]|(?:[{u}{s}]|%[0-9A-Fa-f]{{2}})*)",
            r"(?::[0-9]*)?)",
            r"(?:/{p}*)*",
            r"|/(?:{p}+(?:/{p}*)*)?",
            r"|{p}+(?:/{p}*)*",
            r"|)",
            r"(?:\?(?:{p}|[/?])*)?",
            r"(?:#(?:{p}|[/?])*)?\z",
        ),
        u = unreserved,
        s = sub_delims,
        p = pchar,
    ))
});

/// An atom of text of RFC 5322 with the code points of RFC 6532.
fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~-".contains(c) || c >= '\u{80}'
}

fn is_dot_atom(text: &str) -> bool {
    !text.is_empty()
        && text
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(is_atext))
}

fn is_email(v: &str) -> bool {
    match v.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            is_dot_atom(local) && is_dot_atom(domain) && local.len() <= 64 && v.len() <= 254
        }
        _ => false,
    }
}

fn is_url(v: &str) -> bool {
    URI.as_ref()
        .and_then(|uri| uri.captures(v))
        .is_some_and(|m| {
            let scheme = m.get(1).map(|s| s.as_str().to_ascii_lowercase());
            let host = m.get(3).map(|h| h.as_str());
            matches!(scheme.as_deref(), Some("http" | "https"))
                && host.is_some_and(|h| !h.is_empty())
        })
}

/// Whether `v` is the given number of ASCII upper-case letters and digits, as `kinds`
/// gives them: `b'A'` for a letter, `b'0'` for a digit, `b'*'` for either.
fn shaped(v: &str, kinds: &[u8]) -> bool {
    v.len() == kinds.len()
        && v.bytes().zip(kinds).all(|(b, &kind)| match kind {
            b'A' => b.is_ascii_uppercase(),
            b'0' => b.is_ascii_digit(),
            _ => b.is_ascii_uppercase() || b.is_ascii_digit(),
        })
}

fn is_iban(v: &str) -> bool {
    let Some((head, rest)) = v.split_at_checked(4) else {
        return false;
    };
    if !shaped(head, b"AA00")
        || !(11..=30).contains(&rest.len())
        || !rest
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return false;
    }
    let remainder = rest.bytes().chain(head.bytes()).try_fold(0u32, |acc, c| {
        // A letter counts as two digits, A as 10 to Z as 35.
        let value = u32::from(c);
        let (digits, scale) = if c.is_ascii_uppercase() {
            (value.checked_sub(55)?, 100)
        } else {
            (value.checked_sub(0x30)?, 10)
        };
        acc.checked_mul(scale)?.checked_add(digits)?.checked_rem(97)
    });
    remainder == Some(1)
}

fn is_phone(v: &str) -> bool {
    let Some(digits) = v.strip_prefix('+') else {
        return false;
    };
    (2..=15).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !digits.starts_with('0')
}

fn is_colour(v: &str) -> bool {
    v.strip_prefix('#')
        .is_some_and(|hex| hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_bic(v: &str) -> bool {
    shaped(v, b"AAAAAA**") || shaped(v, b"AAAAAA*****")
}

/// A restricted name of RFC 6838, section 4.2.
fn is_restricted_name(part: &str) -> bool {
    let mut bytes = part.bytes();
    part.len() <= 127
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
}

fn is_media_type(v: &str) -> bool {
    let parts: Vec<&str> = v.split('/').collect();
    parts.len() == 2 && parts.iter().all(|p| is_restricted_name(p))
}

/// Whether `v` has the format `format` of metadata.md, section 6.3.
fn has_format(format: &str, v: &str) -> bool {
    match format {
        "markdown" => true,
        "email" => is_email(v),
        "phone" => is_phone(v),
        "url" => is_url(v),
        "uri" => v.is_ascii() && URI.as_ref().is_some_and(|uri| uri.is_match(v)),
        "colour" => is_colour(v),
        "iban" => is_iban(v),
        "bic" => is_bic(v),
        "country" => shaped(v, b"AA"),
        "language" => v.encode_utf16().count() <= MANIFEST_LANGUAGE_TAG && is_language_tag(v),
        "currency" => shaped(v, b"AAA"),
        "media-type" => is_media_type(v),
        _ => is_ucum(v),
    }
}

// ---------------------------------------------------------------- checks

/// The path of the first value of `field` in `value` that breaks a check or a rule of time
/// values, relations and extensions, in the order of the encoding, or `None` (fields.md,
/// section 7). `required` is the field's own, or false for the root.
pub(crate) fn check_value(
    field: &Field,
    value: &Value,
    path: &str,
    required: bool,
) -> Option<String> {
    let empty = match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Bytes(b) => b.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Map(entries) => entries.is_empty(),
        _ => false,
    };
    if required && empty {
        return Some(path.to_owned());
    }
    let at = || Some(path.to_owned());
    match (&field.kind, value) {
        (_, Value::Null) => None,
        (Kind::Text(t), Value::String(text)) => {
            if !text.is_empty() && field.format().is_some_and(|f| !has_format(f, text)) {
                return at();
            }
            // A pattern that is not an I-Regexp is no check.
            if let Some(pattern) = t.pattern.as_ref().and_then(|p| p.compiled.as_ref())
                && !text.is_empty()
                && !pattern.has_match(text)
            {
                return at();
            }
            let length = i64::try_from(text.chars().count()).unwrap_or(i64::MAX);
            if t.min_length.is_some_and(|m| length < m) || t.max_length.is_some_and(|m| length > m)
            {
                return at();
            }
            None
        }
        (
            Kind::Bytes {
                min_length,
                max_length,
                ..
            },
            Value::Bytes(bytes),
        ) => {
            let length = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
            (min_length.is_some_and(|m| length < m) || max_length.is_some_and(|m| length > m))
                .then(|| path.to_owned())
        }
        (Kind::Integer(n), Value::Int(_) | Value::Long(_)) => {
            let v = match value {
                Value::Int(i) => i64::from(*i),
                Value::Long(l) => *l,
                _ => 0,
            };
            (n.min.is_some_and(|m| v < m) || n.max.is_some_and(|m| v > m)).then(|| path.to_owned())
        }
        (Kind::Double(n), Value::Double(v)) => {
            let breaks = |limit: Option<f64>, below: bool| {
                limit.is_some_and(|m| v.is_nan() || if below { *v < m } else { *v > m })
            };
            (breaks(n.min, true) || breaks(n.max, false)).then(|| path.to_owned())
        }
        (Kind::List(item), Value::Array(items)) => items
            .iter()
            .enumerate()
            .find_map(|(i, v)| check_value(item, v, &format!("{path}[{i}]"), item.required)),
        (Kind::Map(item), Value::Map(entries)) => entries.iter().find_map(|(key, v)| {
            let at = format!("{path}[{}]", Json::String(key.clone()));
            check_value(item, v, &at, item.required)
        }),
        (Kind::Time(name), _) => (!is_valid_time_value(name, value)).then(|| path.to_owned()),
        (Kind::Relation, Value::Array(list)) => relations_problem(list, path),
        (Kind::Extension, Value::Array(list)) => extensions_problem(list, path),
        (Kind::Object(object), Value::Record(_)) => object.fields.iter().find_map(|f| {
            let at = if path.is_empty() {
                f.name.clone()
            } else {
                format!("{path}.{}", f.name)
            };
            check_value(
                f,
                value.field(&f.name).unwrap_or(&Value::Null),
                &at,
                f.required,
            )
        }),
        _ => None,
    }
}

/// Decodes `body`, a record in single-object encoding of the type of `description`, and
/// checks its values (fields.md, section 7).
///
/// # Errors
///
/// The errors of [`crate::record_decoder::decode_record`], and `VALUE_INVALID` naming the
/// first value that breaks a check.
pub(crate) fn check_record(
    description: &crate::type_description::TypeDescription,
    body: &[u8],
) -> Result<Value, Error> {
    let value = crate::record_decoder::decode_record(description.schema(), None, body, false)?;
    match check_value(description.root(), &value, "", false) {
        Some(path) => Err(crate::record_decoder::value_invalid(
            &path,
            "breaks a check",
        )),
        None => Ok(value),
    }
}

// ---------------------------------------------------------------- derivation

/// The schema derived from `root` as JSON (fields.md, section 9.2).
pub(crate) fn derive_schema_json(root: &Field) -> Result<Json, Error> {
    let Kind::Object(object) = &root.kind else {
        return Err(invalid("kind", "the root is not an object"));
    };
    let mut defined = HashSet::from([object.name.clone()]);
    let (namespace, name) = object.name.rsplit_once('.').unwrap_or(("", &object.name));
    Ok(json!({
        "type": "record",
        "name": name,
        "namespace": namespace,
        "doc": root.doc,
        "axt.version": object.version,
        "fields": object
            .fields
            .iter()
            .map(|f| derived_field(f, &mut defined))
            .collect::<Result<Vec<_>, _>>()?,
    }))
}

fn derived_field(field: &Field, defined: &mut HashSet<String>) -> Result<Json, Error> {
    let t = derived_type(field, defined)?;
    let mut out = Map::new();
    out.insert("name".into(), json!(field.name));
    out.insert("doc".into(), json!(field.doc));
    match (&field.kind, field.default_value()) {
        (Kind::List(_) | Kind::Relation | Kind::Extension, _) => {
            out.insert("type".into(), t);
            out.insert("default".into(), json!([]));
        }
        (Kind::Map(_), _) => {
            out.insert("type".into(), t);
            out.insert("default".into(), json!({}));
        }
        (_, Some(default)) => {
            out.insert("type".into(), t);
            out.insert("default".into(), default_json(&default));
        }
        (_, None) if field.required => {
            out.insert("type".into(), t);
        }
        (_, None) => {
            out.insert("type".into(), json!(["null", t]));
            out.insert("default".into(), Json::Null);
        }
    }
    Ok(Json::Object(out))
}

/// A default as the Avro specification writes it: bytes as the string of their code
/// points.
fn default_json(default: &Value) -> Json {
    match default {
        Value::String(s) => json!(s),
        Value::Long(l) => json!(l),
        Value::Double(d) => json!(d),
        Value::Boolean(b) => json!(b),
        Value::Bytes(b) => json!(b.iter().map(|&byte| char::from(byte)).collect::<String>()),
        Value::Enum { symbol, .. } => json!(symbol),
        _ => Json::Null,
    }
}

fn derived_type(field: &Field, defined: &mut HashSet<String>) -> Result<Json, Error> {
    Ok(match &field.kind {
        Kind::Text(_) => json!("string"),
        Kind::Integer(_) if field.brick == "axt.IntField" => json!("int"),
        Kind::Integer(_) => json!("long"),
        Kind::Double(_) => json!("double"),
        Kind::Boolean { .. } => json!("boolean"),
        Kind::Bytes { .. } => json!("bytes"),
        Kind::Enum {
            name,
            symbols,
            fallback,
            ..
        } => json!({
            "type": "enum",
            "name": name,
            "doc": field.doc,
            "symbols": symbols.iter().map(|s| s.symbol.as_str()).collect::<Vec<_>>(),
            "default": fallback,
        }),
        Kind::List(item) => json!({"type": "array", "items": item_type(item, defined)?}),
        Kind::Map(item) => json!({"type": "map", "values": item_type(item, defined)?}),
        Kind::Object(object) => json!({
            "type": "record",
            "name": object.name,
            "doc": field.doc,
            "fields": object
                .fields
                .iter()
                .map(|f| derived_field(f, defined))
                .collect::<Result<Vec<_>, _>>()?,
        }),
        Kind::Time(name) => published(name, defined)?,
        Kind::Relation => json!({"type": "array", "items": published("axt.Relation", defined)?}),
        Kind::Extension => json!({"type": "array", "items": published("axt.Extension", defined)?}),
    })
}

/// The type of the items of a list or the values of a map.
fn item_type(item: &Field, defined: &mut HashSet<String>) -> Result<Json, Error> {
    let t = derived_type(item, defined)?;
    let nested = matches!(
        item.kind,
        Kind::List(_) | Kind::Map(_) | Kind::Relation | Kind::Extension
    );
    Ok(
        if nested || item.required || item.default_value().is_some() {
            t
        } else {
            json!(["null", t])
        },
    )
}

/// A published schema defined in place: its JSON, with every named type that is already
/// defined replaced by its full name, or its full name.
fn published(full_name: &str, defined: &mut HashSet<String>) -> Result<Json, Error> {
    if defined.contains(full_name) {
        return Ok(json!(full_name));
    }
    let text = axt_schema_text(full_name)
        .ok_or_else(|| Error::axt(ErrorCode::DescriptionInvalid, format!("no {full_name}")))?;
    let json: Json = serde_json::from_str(text)
        .map_err(|e| Error::axt(ErrorCode::DescriptionInvalid, e.to_string()))?;
    Ok(walk_published(&json, "axt", defined))
}

fn walk_published(json: &Json, namespace: &str, defined: &mut HashSet<String>) -> Json {
    const PRIMITIVES: [&str; 8] = [
        "null", "boolean", "int", "long", "float", "double", "bytes", "string",
    ];
    match json {
        Json::Object(members) => {
            let named = matches!(
                members.get("type").and_then(Json::as_str),
                Some("record" | "enum" | "fixed")
            );
            if !named {
                // The published schemas hold no named type inside an array or a map.
                return json.clone();
            }
            let ns = members
                .get("namespace")
                .and_then(Json::as_str)
                .unwrap_or(namespace)
                .to_owned();
            let name = members
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or_default();
            let full = if name.contains('.') {
                name.to_owned()
            } else {
                format!("{ns}.{name}")
            };
            if !defined.insert(full.clone()) {
                return json!(full);
            }
            Json::Object(
                members
                    .iter()
                    .map(|(key, value)| {
                        let value = match (key.as_str(), value) {
                            ("fields", Json::Array(fields)) => Json::Array(
                                fields
                                    .iter()
                                    .map(|f| match f {
                                        Json::Object(field) => Json::Object(
                                            field
                                                .iter()
                                                .map(|(k, v)| {
                                                    let v = if k == "type" {
                                                        walk_published(v, &ns, defined)
                                                    } else {
                                                        v.clone()
                                                    };
                                                    (k.clone(), v)
                                                })
                                                .collect(),
                                        ),
                                        other => other.clone(),
                                    })
                                    .collect(),
                            ),
                            _ => value.clone(),
                        };
                        (key.clone(), value)
                    })
                    .collect(),
            )
        }
        Json::Array(branches) => Json::Array(
            branches
                .iter()
                .map(|b| walk_published(b, namespace, defined))
                .collect(),
        ),
        Json::String(name) if !PRIMITIVES.contains(&name.as_str()) && !name.contains('.') => {
            json!(format!("{namespace}.{name}"))
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------- canonical JSON

/// JSON in the canonical form of RFC 8785: members sorted by their names in UTF-16 code
/// units, no white space, and every string and number written as ECMAScript writes it.
pub(crate) fn canonical_json(json: &Json) -> String {
    let mut out = String::new();
    write_canonical(json, &mut out);
    out
}

fn write_canonical(json: &Json, out: &mut String) {
    match json {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                out.push_str(&ecmascript_number(n.as_f64().unwrap_or_default()));
            }
        }
        Json::String(s) => write_string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Json::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                if let Some(value) = members.get(key) {
                    write_canonical(value, out);
                }
            }
            out.push('}');
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `v`, a finite number, as ECMAScript writes it (ECMA-262, Number::toString), from the
/// shortest digits that read back to it.
fn ecmascript_number(v: f64) -> String {
    if v == 0.0 {
        return "0".into();
    }
    if v < 0.0 {
        return format!("-{}", ecmascript_number(-v));
    }
    // Rust writes the shortest digits as d.ddde±x.
    let text = format!("{v:e}");
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let exponent: i64 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    let n = exponent.saturating_add(1);
    let zeros = |count: i64| "0".repeat(usize::try_from(count).unwrap_or(0));
    if k <= n && n <= 21 {
        return format!("{digits}{}", zeros(n.saturating_sub(k)));
    }
    if 0 < n && n <= 21 {
        let (whole, fraction) = digits
            .split_at_checked(usize::try_from(n).unwrap_or(0))
            .unwrap_or((digits, ""));
        return format!("{whole}.{fraction}");
    }
    if -6 < n && n <= 0 {
        return format!("0.{}{digits}", zeros(n.saturating_neg()));
    }
    let e = n.saturating_sub(1);
    let sign = if e < 0 { '-' } else { '+' };
    let (first, rest) = digits.split_at_checked(1).unwrap_or((digits, ""));
    let m = if rest.is_empty() {
        first.to_owned()
    } else {
        format!("{first}.{rest}")
    };
    format!("{m}e{sign}{}", e.unsigned_abs())
}

// ---------------------------------------------------------------- describe

fn shown_text(
    english: &str,
    translations: &BTreeMap<String, String>,
    languages: &[String],
) -> Json {
    let mut tags: Vec<&str> = translations.keys().map(String::as_str).collect();
    tags.push("en");
    let chosen = match lookup(languages, &tags) {
        None | Some("en") => english,
        Some(tag) => translations.get(tag).map_or(english, String::as_str),
    };
    if chosen.is_empty() {
        Json::Null
    } else {
        json!(chosen)
    }
}

fn shown(texts: &Texts, languages: &[String]) -> Map<String, Json> {
    let mut out = Map::new();
    out.insert(
        "label".into(),
        shown_text(&texts.label, &texts.label_translations, languages),
    );
    out.insert(
        "help".into(),
        shown_text(&texts.help, &texts.help_translations, languages),
    );
    out.insert(
        "emoji".into(),
        if texts.emoji.is_empty() {
            Json::Null
        } else {
            json!(texts.emoji)
        },
    );
    out
}

/// What a receiver shows of an object (metadata.md, sections 4 and 5).
pub(crate) fn describe_object(texts: &Texts, object: &Object, languages: &[String]) -> Json {
    let mut indexed: Vec<(usize, &Field)> = object.fields.iter().enumerate().collect();
    indexed.sort_by(|(ia, a), (ib, b)| match (a.order, b.order) {
        (Some(oa), Some(ob)) if oa != ob => oa.cmp(&ob),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        _ => ia.cmp(ib),
    });
    let mut ordered: Vec<&str> = Vec::new();
    let mut placed: HashSet<&str> = HashSet::new();
    for (_, f) in &indexed {
        if f.group.is_empty() {
            ordered.push(&f.name);
        } else if placed.insert(f.group.as_str()) {
            ordered.extend(
                indexed
                    .iter()
                    .filter(|(_, g)| g.group == f.group)
                    .map(|(_, g)| g.name.as_str()),
            );
        }
    }
    let groups: Map<String, Json> = object
        .groups
        .iter()
        .filter(|(key, _)| placed.contains(key.as_str()))
        .map(|(key, texts)| (key.clone(), Json::Object(shown(texts, languages))))
        .collect();
    let mut out = shown(texts, languages);
    out.insert("fields".into(), json!(ordered));
    out.insert("groups".into(), Json::Object(groups));
    Json::Object(out)
}

/// What a receiver shows of a typed field.
pub(crate) fn describe_field(field: &Field, languages: &[String]) -> Json {
    let mut out = shown(&field.texts, languages);
    out.insert("brick".into(), json!(field.brick));
    out.insert(
        "symbols".into(),
        match &field.kind {
            Kind::Enum { symbols, .. } => Json::Object(
                symbols
                    .iter()
                    .map(|s| (s.symbol.clone(), Json::Object(shown(&s.texts, languages))))
                    .collect(),
            ),
            _ => Json::Null,
        },
    );
    out.insert(
        "record".into(),
        match &field.kind {
            Kind::Object(object) => describe_object(&field.texts, object, languages),
            _ => Json::Null,
        },
    );
    out.insert(
        "items".into(),
        match &field.kind {
            Kind::List(item) | Kind::Map(item) => describe_field(item, languages),
            _ => Json::Null,
        },
    );
    Json::Object(out)
}

/// The typed field at `path`, the names from the root joined by `.`, going through the
/// items of lists and maps of objects.
pub(crate) fn field_at<'a>(root: &'a Field, path: &str) -> Option<&'a Field> {
    let mut current = root;
    for name in path.split('.') {
        while let Kind::List(item) | Kind::Map(item) = &current.kind {
            current = item;
        }
        let Kind::Object(object) = &current.kind else {
            return None;
        };
        current = object.fields.iter().find(|f| f.name == name)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(label: &str, labels: &[(&str, &str)], emoji: &str) -> Json {
        json!({
            "label": label,
            "label_translations": labels.iter().map(|(k, v)| ((*k).to_owned(), json!(v))).collect::<Map<_, _>>(),
            "emoji": emoji,
        })
    }

    fn field(name: &str, brick: &str, members: Json) -> Json {
        json!({"name": name, "doc": format!("The {name}."), "texts": {}, "kind": {brick: members}})
    }

    fn root(fields: Vec<Json>) -> Json {
        json!({
            "name": "root",
            "doc": "A type.",
            "texts": {},
            "kind": {"axt.ObjectField": {"name": "com.example.T", "version": 1, "fields": fields}},
        })
    }

    /// The typed field and the datum of a description in its JSON form.
    fn parse(json: &Json) -> (Field, Value) {
        let datum = description_from_json(json).unwrap();
        (Field::from_value(&datum).unwrap(), datum)
    }

    fn derive(json: &Json) -> Result<String, Error> {
        let (root, datum) = parse(json);
        derive_schema(&root, &datum)
    }

    fn invalid_at(json: &Json) -> Option<String> {
        match derive(json).unwrap_err() {
            Error::Axt {
                code: ErrorCode::DescriptionInvalid,
                field,
                ..
            } => field,
            other => panic!("{other}"),
        }
    }

    #[test]
    fn bytes_that_are_no_description_are_undecodable() {
        let e = decode_description(&[0xff]).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::Undecodable));
    }

    #[test]
    fn a_description_encodes_and_decodes_again() {
        let (_, datum) = parse(&root(vec![field("a", "axt.StringField", json!({}))]));
        let bytes = field_schema().unwrap().encode_datum(&datum).unwrap();
        assert_eq!(decode_description(&bytes).unwrap(), datum);
    }

    /// Runs `test` on a thread with a stack of 256 MiB: `apache-avro` recurses once per
    /// level of a datum, with large frames in a build without optimisations.
    fn with_a_large_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(test)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn typed_fields_nested_too_deep_are_decoded_and_not_valid() {
        with_a_large_stack(typed_fields_nested_too_deep);
    }

    #[test]
    fn objects_nested_five_deep_derive_on_a_default_stack() {
        // Without optimisations `apache-avro` takes about 40 KiB of stack per level of a
        // datum, so a default test thread holds only a few nested objects.
        let mut item = field("a", "axt.IntField", json!({}));
        for i in 0..5 {
            item = field(
                "a",
                "axt.ObjectField",
                json!({"name": format!("O{i}"), "fields": [item]}),
            );
        }
        let (_, datum) = parse(&root(vec![item]));
        let bytes = field_schema().unwrap().encode_datum(&datum).unwrap();
        let datum = decode_description(&bytes).unwrap();
        let root = Field::from_value(&datum).unwrap();
        assert!(derive_schema(&root, &datum).is_ok());
    }

    fn typed_fields_nested_too_deep() {
        for (depth, valid) in [(60, true), (61, false), (63, false), (100, false)] {
            let mut item = field("a", "axt.IntField", json!({}));
            for _ in 0..depth {
                item = field("a", "axt.ListField", json!({"items": item}));
            }
            let datum = description_from_json(&root(vec![item])).unwrap();
            let bytes = field_schema().unwrap().encode_datum(&datum).unwrap();
            let datum = decode_description(&bytes).unwrap();
            let root = Field::from_value(&datum).unwrap();
            let derived = derive_schema(&root, &datum);
            assert_eq!(derived.is_ok(), valid, "{depth}");
        }
    }

    #[test]
    fn a_description_nested_beyond_the_decoder_s_limit_is_undecodable() {
        with_a_large_stack(nested_beyond_the_decoder_s_limit);
    }

    fn nested_beyond_the_decoder_s_limit() {
        let encode = |json: &Json| {
            let (_, datum) = parse(json);
            field_schema().unwrap().encode_datum(&datum).unwrap()
        };
        // `kind` is the last member of a field, so a chain of lists is a repeated prefix.
        let inner = encode(&field("a", "axt.IntField", json!({})));
        let one = encode(&field(
            "a",
            "axt.ListField",
            json!({"items": field("a", "axt.IntField", json!({}))}),
        ));
        let prefix = &one[..one.len() - inner.len()];
        let mut bytes = prefix.repeat(5000);
        bytes.extend_from_slice(&inner);
        let e = decode_description(&bytes).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::Undecodable));
    }

    #[test]
    fn a_root_doc_of_white_space_only_is_empty() {
        let mut json = root(vec![field("a", "axt.StringField", json!({}))]);
        json["doc"] = json!(" ");
        assert_eq!(invalid_at(&json).as_deref(), Some("doc"));
    }

    #[test]
    fn a_keycap_is_an_emoji_a_digit_alone_is_not() {
        for emoji in ["#\u{20e3}", "1\u{fe0f}\u{20e3}", "🏥"] {
            let mut a = field("a", "axt.StringField", json!({}));
            a["texts"] = texts("", &[], emoji);
            assert!(derive(&root(vec![a])).is_ok(), "{emoji}");
        }
        for emoji in ["1", "a🏥", "🏥 "] {
            let mut a = field("a", "axt.StringField", json!({}));
            a["texts"] = texts("", &[], emoji);
            assert_eq!(
                invalid_at(&root(vec![a])).as_deref(),
                Some("kind.fields[0].texts.emoji")
            );
        }
    }

    #[test]
    fn more_translations_than_the_limit_break_the_rules() {
        let labels: Vec<(String, String)> = (0..=64)
            .map(|i| (format!("de-x-a{i:03}"), "A".to_owned()))
            .collect();
        let labels: Vec<(&str, &str)> = labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut a = field("a", "axt.StringField", json!({}));
        a["texts"] = texts("A", &labels, "");
        assert_eq!(
            invalid_at(&root(vec![a])).as_deref(),
            Some("kind.fields[0].texts.label_translations")
        );
        let mut b = field("a", "axt.StringField", json!({}));
        b["texts"] = texts("", &[("de", "A")], "");
        assert_eq!(
            invalid_at(&root(vec![b])).as_deref(),
            Some("kind.fields[0].texts.label_translations")
        );
    }

    #[test]
    fn rules_of_numbers_bytes_and_enums() {
        let cases = [
            (
                field("a", "axt.IntField", json!({"example": "1\t2"})),
                "kind.fields[0].kind.example",
            ),
            (
                field("a", "axt.IntField", json!({"min": 2, "max": 1})),
                "kind.fields[0].kind.min",
            ),
            (
                field(
                    "a",
                    "axt.LongField",
                    json!({"default": 9_007_199_254_740_993_i64}),
                ),
                "kind.fields[0].kind.default",
            ),
            (
                field(
                    "a",
                    "axt.BytesField",
                    json!({"default": "0000", "max_length": 1}),
                ),
                "kind.fields[0].kind.default",
            ),
            (
                field(
                    "a",
                    "axt.EnumField",
                    json!({"name": "T", "symbols": [{"symbol": "A", "texts": {}}], "fallback": "A"}),
                ),
                "kind.fields[0].kind.name",
            ),
            (
                field("a", "axt.StringField", json!({"pattern": "\\d"})),
                "kind.fields[0].kind.pattern",
            ),
            (
                field(
                    "a",
                    "axt.StringField",
                    json!({"pattern": "[0-9]+", "example": "x"}),
                ),
                "kind.fields[0].kind.example",
            ),
        ];
        for (f, path) in cases {
            assert_eq!(invalid_at(&root(vec![f])).as_deref(), Some(path));
        }
    }

    #[test]
    fn an_infinite_max_of_a_double_is_not_valid() {
        let (mut root, datum) = parse(&root(vec![field("a", "axt.DoubleField", json!({}))]));
        if let Kind::Object(object) = &mut root.kind
            && let Some(Kind::Double(n)) = object.fields.first_mut().map(|f| &mut f.kind)
        {
            n.max = Some(f64::INFINITY);
        }
        match derive_schema(&root, &datum).unwrap_err() {
            Error::Axt { field, .. } => {
                assert_eq!(field.as_deref(), Some("kind.fields[0].kind.max"))
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn the_root_needs_a_namespace_and_a_version() {
        let mut json = root(vec![field("a", "axt.StringField", json!({}))]);
        json["kind"]["axt.ObjectField"]["name"] = json!("T");
        assert_eq!(invalid_at(&json).as_deref(), Some("kind.name"));
        let mut json = root(vec![field("a", "axt.StringField", json!({}))]);
        json["kind"]["axt.ObjectField"]["version"] = json!(0);
        assert_eq!(invalid_at(&json).as_deref(), Some("kind.version"));
        let json = root(vec![
            field("a", "axt.StringField", json!({})),
            field("a", "axt.StringField", json!({})),
        ]);
        assert_eq!(invalid_at(&json).as_deref(), Some("kind.fields[1].name"));
    }

    #[test]
    fn the_derived_schema_has_the_forms_of_section_9_2() {
        let mut required = field("b", "axt.StringField", json!({}));
        required["required"] = json!(true);
        let text = derive(&root(vec![
            field("a", "axt.StringField", json!({"default": ""})),
            required,
            field("c", "axt.BytesField", json!({"default": "00ff"})),
            field("d", "axt.DoubleField", json!({"default": 2})),
            field(
                "e",
                "axt.ListField",
                json!({"items": field("e", "axt.IntField", json!({}))}),
            ),
            field("f", "axt.DateTimeField", json!({})),
            field("g", "axt.RelationField", json!({})),
        ]))
        .unwrap();
        let schema: Json = serde_json::from_str(&text).unwrap();
        let fields = &schema["fields"];
        assert_eq!(fields[0]["type"], json!("string"));
        assert_eq!(fields[0]["default"], json!(""));
        assert_eq!(fields[1].get("default"), None);
        assert_eq!(fields[2]["default"], json!("\u{0}\u{ff}"));
        assert!(text.contains(r#""default":2,"doc":"The d.""#));
        assert_eq!(
            fields[4]["type"],
            json!({"type": "array", "items": ["null", "int"]})
        );
        assert_eq!(fields[4]["default"], json!([]));
        assert_eq!(fields[5]["type"][1]["name"], json!("DateTime"));
        // The relation's start names the DateTime defined before it.
        assert_eq!(text.matches(r#""name":"DateTime""#).count(), 1);
        assert!(text.starts_with(r#"{"axt.version":1,"doc":"A type.","fields":["#));
        assert!(crate::schema::Schema::parse(&text).is_ok());
    }

    #[test]
    fn numbers_and_strings_are_written_as_ecmascript_writes_them() {
        let json = json!([
            123.456,
            1.5e-7,
            1e-6,
            1.23e22,
            5e-324,
            1e21,
            1e20,
            -0.0,
            2.0,
            "\u{8}\u{c}\r\n\u{1}"
        ]);
        assert_eq!(
            canonical_json(&json),
            r#"[123.456,1.5e-7,0.000001,1.23e+22,5e-324,1e+21,100000000000000000000,0,2,"\b\f\r\n\u0001"]"#
        );
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": {"é": 1, "z": 2}})),
            r#"{"a":{"z":2,"é":1},"b":1}"#
        );
    }

    #[test]
    fn formats_take_their_syntax() {
        for (format, good, bad) in [
            ("email", "mimi@example.org", "mimi@"),
            ("phone", "+4930123456", "+0301"),
            ("url", "https://example.org/a?b#c", "mailto:a@b"),
            ("uri", "mailto:a@b", "a b"),
            ("colour", "#00ffAA", "#00ffA"),
            ("iban", "DE89370400440532013000", "DE89370400440532013001"),
            ("bic", "DEUTDEFF500", "DEUTDEFF5"),
            ("country", "DE", "de"),
            ("language", "de-AT", "de_AT"),
            ("currency", "EUR", "EU"),
            ("media-type", "text/plain", "text/"),
            ("ucum", "mm[Hg]", "m m"),
        ] {
            assert!(has_format(format, good), "{format} {good}");
            assert!(!has_format(format, bad), "{format} {bad}");
        }
        assert!(URI.is_some());
    }

    #[test]
    fn fields_with_an_order_come_first_by_their_order() {
        let mut b = field("b", "axt.StringField", json!({}));
        b["order"] = json!(2);
        let mut c = field("c", "axt.StringField", json!({}));
        c["order"] = json!(1);
        let (root, _) = parse(&root(vec![
            field("a", "axt.StringField", json!({})),
            b,
            c,
            field("d", "axt.StringField", json!({})),
        ]));
        let Kind::Object(object) = &root.kind else {
            panic!()
        };
        let shown = describe_object(&root.texts, object, &["en".into()]);
        assert_eq!(shown["fields"], json!(["c", "b", "a", "d"]));
    }

    #[test]
    fn a_path_goes_through_lists_of_objects() {
        let item = field(
            "items",
            "axt.ObjectField",
            json!({"name": "Item", "fields": [field("code", "axt.StringField", json!({}))]}),
        );
        let (root, _) = parse(&root(vec![
            field("items", "axt.ListField", json!({"items": item})),
            field("name", "axt.StringField", json!({})),
        ]));
        assert_eq!(
            field_at(&root, "items.code").map(|f| f.name.as_str()),
            Some("code")
        );
        assert!(field_at(&root, "items.none").is_none());
        assert!(field_at(&root, "name.code").is_none());
    }

    #[test]
    fn a_value_is_named_by_the_first_check_it_breaks() {
        let mut name = field("name", "axt.StringField", json!({"max_length": 3}));
        name["required"] = json!(true);
        let (root, _) = parse(&root(vec![
            name,
            field(
                "tags",
                "axt.MapField",
                json!({"values": field("tags", "axt.EmailField", json!({}))}),
            ),
        ]));
        let record = |name: &str, tag: &str| {
            Value::Record(vec![
                ("name".into(), Value::String(name.into())),
                (
                    "tags".into(),
                    Value::Map(BTreeMap::from([("k".into(), Value::String(tag.into()))])),
                ),
            ])
        };
        assert_eq!(check_value(&root, &record("Mim", "a@b"), "", false), None);
        assert_eq!(
            check_value(&root, &record("", "a@b"), "", false).as_deref(),
            Some("name")
        );
        assert_eq!(
            check_value(&root, &record("Mimi", "a@b"), "", false).as_deref(),
            Some("name")
        );
        assert_eq!(
            check_value(&root, &record("Mim", "ab"), "", false).as_deref(),
            Some("tags[\"k\"]")
        );
        assert_eq!(check_value(&root, &record("Mim", ""), "", false), None);
    }
}
