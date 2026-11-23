//! The Rust source of the types of descriptions: the schema derived from each description,
//! read as Rust types, and the conversions of those types from and to `axt_protocol::Value`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use axt_protocol::TypeDescription;
use serde_json::{Map, Value as Json};

/// Why no source was generated.
#[derive(Debug)]
pub enum GenerateError {
    /// A description that is not valid (`DESCRIPTION_INVALID`), by the name it is known by.
    Description {
        /// The name the description is known by, such as its path.
        name: String,
        /// The library's rejection.
        error: axt_protocol::Error,
    },
    /// Where the generator stops: a schema it cannot write as Rust types, or two
    /// different types of one name.
    Generate(String),
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Description { name, error } => write!(f, "{name}: {error}"),
            Self::Generate(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for GenerateError {}

/// A primitive type of Avro other than `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prim {
    Boolean,
    Int,
    Long,
    Float,
    Double,
    Bytes,
    String,
}

impl Prim {
    fn of(name: &str) -> Option<Self> {
        Some(match name {
            "boolean" => Self::Boolean,
            "int" => Self::Int,
            "long" => Self::Long,
            "float" => Self::Float,
            "double" => Self::Double,
            "bytes" => Self::Bytes,
            "string" => Self::String,
            _ => return None,
        })
    }

    /// The type's Avro name, which is also the name of its helper and of its branch.
    const fn avro(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Int => "int",
            Self::Long => "long",
            Self::Float => "float",
            Self::Double => "double",
            Self::Bytes => "bytes",
            Self::String => "string",
        }
    }

    /// The variant of `Value` that holds it, also the name of its branch's variant.
    const fn variant(self) -> &'static str {
        match self {
            Self::Boolean => "Boolean",
            Self::Int => "Int",
            Self::Long => "Long",
            Self::Float => "Float",
            Self::Double => "Double",
            Self::Bytes => "Bytes",
            Self::String => "String",
        }
    }

    const fn rust(self) -> &'static str {
        match self {
            Self::Boolean => "bool",
            Self::Int => "i32",
            Self::Long => "i64",
            Self::Float => "f32",
            Self::Double => "f64",
            Self::Bytes => "Vec<u8>",
            Self::String => "String",
        }
    }

    /// What a value that is not of the type is not.
    const fn not(self) -> &'static str {
        match self {
            Self::Boolean => "not a boolean",
            Self::Int => "not an int",
            Self::Long => "not a long",
            Self::Float => "not a float",
            Self::Double => "not a double",
            Self::Bytes => "not bytes",
            Self::String => "not a string",
        }
    }
}

/// The type of a field as Rust holds it.
#[derive(Debug, Clone, PartialEq)]
enum Ty {
    Prim(Prim),
    /// A fixed of the full name `name`, held as an array of bytes.
    Fixed {
        name: String,
        size: usize,
    },
    /// A record, an enum or a union of two or more non-null branches, by its key.
    Named(String),
    Array(Box<Ty>),
    Map(Box<Ty>),
    /// A union of `null` and one other type.
    Option(Box<Ty>),
}

#[derive(Debug, Clone, PartialEq)]
struct FieldDef {
    name: String,
    doc: String,
    ty: Ty,
}

#[derive(Debug, Clone, PartialEq)]
struct BranchDef {
    /// The position of the branch among the union's types, `null` included.
    index: u32,
    /// The branch's name in a `Value::Union`.
    name: String,
    ty: Ty,
}

/// A type that becomes a Rust type, or a fixed, which does not.
#[derive(Debug, Clone, PartialEq)]
enum Def {
    Record {
        full: String,
        doc: String,
        fields: Vec<FieldDef>,
    },
    Enum {
        full: String,
        doc: String,
        symbols: Vec<String>,
    },
    /// The union of two or more non-null branches of the field `field` of the record
    /// `owner`.
    Union {
        owner: String,
        field: String,
        branches: Vec<BranchDef>,
    },
    Fixed {
        size: usize,
    },
}

/// The types of all descriptions, in the order they were first met.
#[derive(Default)]
struct Library {
    order: Vec<String>,
    defs: BTreeMap<String, Def>,
    /// The minified description of each root type, in the order of the descriptions.
    descriptions: BTreeMap<String, String>,
}

impl Library {
    /// Keeps the place of `key` in the order, before the types inside it.
    fn reserve(&mut self, key: &str) {
        if !self.defs.contains_key(key) && !self.order.iter().any(|k| k == key) {
            self.order.push(key.to_owned());
        }
    }

    fn define(&mut self, key: &str, def: Def) -> Result<(), String> {
        match self.defs.get(key) {
            Some(known) if *known != def => Err(format!("two different types are named {key}")),
            Some(_) => Ok(()),
            None => {
                self.defs.insert(key.to_owned(), def);
                Ok(())
            }
        }
    }
}

/// A named type as the schema being read knows it.
#[derive(Clone)]
enum Known {
    /// A record or an enum.
    Type,
    Fixed(usize),
    /// A record whose fields are being read.
    InProgress,
}

/// The reader of one schema into the library.
struct Reader<'a> {
    library: &'a mut Library,
    known: BTreeMap<String, Known>,
}

fn full_name(name: &str, namespace: &str) -> String {
    if name.contains('.') || namespace.is_empty() {
        name.to_owned()
    } else {
        format!("{namespace}.{name}")
    }
}

fn text<'j>(object: &'j Map<String, Json>, member: &str) -> Option<&'j str> {
    object.get(member).and_then(Json::as_str)
}

impl Reader<'_> {
    /// The type of `json`, met in the field `field` of the record `owner`, with
    /// `namespace` the enclosing one.
    fn ty(&mut self, json: &Json, namespace: &str, owner: &str, field: &str) -> Result<Ty, String> {
        match json {
            Json::String(name) => self.reference(name, namespace),
            Json::Array(branches) => self.union(branches, namespace, owner, field),
            Json::Object(object) => match text(object, "type") {
                Some("record" | "error") => self.record(object, namespace),
                Some("enum") => self.enumeration(object, namespace),
                Some("fixed") => self.fixed(object, namespace),
                Some("array") => {
                    let items = object.get("items").ok_or("an array without items")?;
                    Ok(Ty::Array(Box::new(
                        self.ty(items, namespace, owner, field)?,
                    )))
                }
                Some("map") => {
                    let values = object.get("values").ok_or("a map without values")?;
                    Ok(Ty::Map(Box::new(self.ty(values, namespace, owner, field)?)))
                }
                // A primitive type, possibly of a logical type, which Rust holds as the
                // underlying type.
                Some(name) => self.reference(name, namespace),
                None => Err(format!(
                    "a type without a name in the field {owner}.{field}"
                )),
            },
            other => Err(format!("{other} is not a type")),
        }
    }

    fn reference(&self, name: &str, namespace: &str) -> Result<Ty, String> {
        if let Some(prim) = Prim::of(name) {
            return Ok(Ty::Prim(prim));
        }
        if name == "null" {
            return Err("a null outside a union is not supported".into());
        }
        let full = full_name(name, namespace);
        match self.known.get(&full) {
            Some(Known::Type) => Ok(Ty::Named(full)),
            Some(Known::Fixed(size)) => Ok(Ty::Fixed {
                name: full,
                size: *size,
            }),
            Some(Known::InProgress) => Err(format!("the type {full} contains itself")),
            None => Err(format!("no type {full}")),
        }
    }

    /// The full name and the namespace of a named type.
    fn names(object: &Map<String, Json>, namespace: &str) -> Result<(String, String), String> {
        let name = text(object, "name").ok_or("a named type without a name")?;
        let own = text(object, "namespace").unwrap_or(namespace);
        let full = full_name(name, own);
        let space = full
            .rsplit_once('.')
            .map_or(String::new(), |(space, _)| space.to_owned());
        Ok((full, space))
    }

    fn record(&mut self, object: &Map<String, Json>, namespace: &str) -> Result<Ty, String> {
        let (full, space) = Self::names(object, namespace)?;
        self.known.insert(full.clone(), Known::InProgress);
        self.library.reserve(&full);
        let mut fields = Vec::new();
        for field in object
            .get("fields")
            .and_then(Json::as_array)
            .ok_or_else(|| format!("the record {full} has no fields"))?
        {
            let field = field
                .as_object()
                .ok_or_else(|| format!("a field of {full} is no object"))?;
            let name =
                text(field, "name").ok_or_else(|| format!("a field of {full} has no name"))?;
            let ty = field
                .get("type")
                .ok_or_else(|| format!("the field {full}.{name} has no type"))?;
            fields.push(FieldDef {
                name: name.to_owned(),
                doc: text(field, "doc").unwrap_or_default().to_owned(),
                ty: self.ty(ty, &space, &full, name)?,
            });
        }
        self.known.insert(full.clone(), Known::Type);
        let doc = text(object, "doc").unwrap_or_default().to_owned();
        self.library.define(
            &full,
            Def::Record {
                full: full.clone(),
                doc,
                fields,
            },
        )?;
        Ok(Ty::Named(full))
    }

    fn enumeration(&mut self, object: &Map<String, Json>, namespace: &str) -> Result<Ty, String> {
        let (full, _) = Self::names(object, namespace)?;
        let symbols = object
            .get("symbols")
            .and_then(Json::as_array)
            .ok_or_else(|| format!("the enum {full} has no symbols"))?
            .iter()
            .map(|s| s.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| format!("a symbol of {full} is no string"))?;
        self.known.insert(full.clone(), Known::Type);
        self.library.reserve(&full);
        let doc = text(object, "doc").unwrap_or_default().to_owned();
        self.library.define(
            &full,
            Def::Enum {
                full: full.clone(),
                doc,
                symbols,
            },
        )?;
        Ok(Ty::Named(full))
    }

    fn fixed(&mut self, object: &Map<String, Json>, namespace: &str) -> Result<Ty, String> {
        let (full, _) = Self::names(object, namespace)?;
        let size = object
            .get("size")
            .and_then(Json::as_u64)
            .and_then(|s| usize::try_from(s).ok())
            .ok_or_else(|| format!("the fixed {full} has no size"))?;
        self.known.insert(full.clone(), Known::Fixed(size));
        self.library.define(&full, Def::Fixed { size })?;
        Ok(Ty::Fixed { name: full, size })
    }

    fn union(
        &mut self,
        branches: &[Json],
        namespace: &str,
        owner: &str,
        field: &str,
    ) -> Result<Ty, String> {
        // A union that becomes an enum comes before the types defined in its branches.
        let key = format!("{owner}#{field}");
        if branches
            .iter()
            .filter(|b| b.as_str() != Some("null"))
            .count()
            >= 2
        {
            self.library.reserve(&key);
        }
        let mut nullable = false;
        let mut others = Vec::new();
        for (index, branch) in branches.iter().enumerate() {
            let index = u32::try_from(index).map_err(|e| e.to_string())?;
            if branch.as_str() == Some("null") {
                nullable = true;
                continue;
            }
            let ty = self.ty(branch, namespace, owner, field)?;
            let name = match &ty {
                Ty::Prim(prim) => prim.avro().to_owned(),
                Ty::Fixed { name, .. } | Ty::Named(name) => name.clone(),
                Ty::Array(_) => "array".into(),
                Ty::Map(_) => "map".into(),
                Ty::Option(_) => return Err(format!("a union inside a union in {owner}.{field}")),
            };
            others.push(BranchDef { index, name, ty });
        }
        let ty = match <[BranchDef; 1]>::try_from(others) {
            Ok([only]) => only.ty,
            Err(others) if others.is_empty() => {
                return Err(format!("a union of no type but null in {owner}.{field}"));
            }
            Err(others) => {
                self.library.define(
                    &key,
                    Def::Union {
                        owner: owner.to_owned(),
                        field: field.to_owned(),
                        branches: others,
                    },
                )?;
                Ty::Named(key)
            }
        };
        Ok(if nullable {
            Ty::Option(Box::new(ty))
        } else {
            ty
        })
    }
}

/// `name` with the first letter of each part between underscores in upper case and the
/// rest as it is, such as `PersonPhone` for `PersonPhone` and `OdometerUnit` for
/// `odometer_unit`.
fn camel(name: &str) -> String {
    name.split('_')
        .flat_map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|c| c.to_ascii_uppercase())
                .into_iter()
                .chain(chars)
        })
        .collect()
}

/// A symbol in the case of a Rust variant, such as `Kilometre` for `KILOMETRE`.
fn variant_of_symbol(symbol: &str) -> String {
    camel(&symbol.to_ascii_lowercase())
}

/// The Rust name of the type of the full name `full`: its name, with `Axt` before the
/// names of the namespace `axt`.
fn type_name(full: &str) -> String {
    let (namespace, name) = full.rsplit_once('.').unwrap_or(("", full));
    let prefix = if namespace == "axt" { "Axt" } else { "" };
    format!("{prefix}{}", camel(name))
}

fn simple_name(full: &str) -> &str {
    full.rsplit_once('.').map_or(full, |(_, name)| name)
}

/// Names that the generated source uses itself.
const TAKEN: [&str; 17] = [
    "Box",
    "BTreeMap",
    "Err",
    "Error",
    "ErrorCode",
    "From",
    "None",
    "Ok",
    "Option",
    "Result",
    "Self",
    "Some",
    "String",
    "TryFrom",
    "TypeDescription",
    "Value",
    "Vec",
];

const KEYWORDS: [&str; 51] = [
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate",
    "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl",
    "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "try", "type",
    "typeof", "unsafe", "unsized", "use", "virtual", "where", "while",
];

/// The identifier of the field `name`: the name, or the raw identifier of a keyword.
fn field_ident(name: &str) -> Result<String, String> {
    if matches!(name, "self" | "Self" | "super" | "crate" | "_") {
        return Err(format!("the field name {name} is not supported"));
    }
    Ok(if KEYWORDS.contains(&name) {
        format!("r#{name}")
    } else {
        name.to_owned()
    })
}

fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !KEYWORDS.contains(&name)
}

/// The doc comment of `doc`, at `indent`, with the characters that rustdoc would read as
/// links or HTML escaped.
fn doc_lines(out: &mut String, doc: &str, indent: &str) {
    for line in doc.lines() {
        let line = line.trim_end().chars().fold(String::new(), |mut text, c| {
            if matches!(c, '\\' | '[' | ']' | '<' | '>') {
                text.push('\\');
            }
            text.push(c);
            text
        });
        if line.is_empty() {
            out.push_str(&format!("{indent}///\n"));
        } else {
            out.push_str(&format!("{indent}/// {line}\n"));
        }
    }
}

/// JSON text without the white space outside its strings.
fn minified(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in json.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !c.is_whitespace() {
            out.push(c);
        }
    }
    out
}

/// `text` as a raw string literal of Rust.
fn raw_literal(text: &str) -> String {
    // One `#` more than the longest run of them after a quote in the text.
    let mut longest = 0_usize;
    let mut run: Option<usize> = None;
    for c in text.chars() {
        run = match (c, run) {
            ('"', _) => Some(0),
            ('#', Some(n)) => {
                let n = n.saturating_add(1);
                longest = longest.max(n);
                Some(n)
            }
            _ => None,
        };
    }
    let hashes = "#".repeat(longest.saturating_add(1));
    format!("r{hashes}\"{text}\"{hashes}")
}

/// The helpers the generated source may use, in the order they are written.
const HELPERS: [&str; 15] = [
    "invalid", "record", "field", "symbol", "branch", "boolean", "int", "long", "float", "double",
    "bytes", "string", "fixed", "array", "map",
];

/// The writer of the Rust source of the library.
struct Writer<'a> {
    library: &'a Library,
    used: BTreeSet<&'static str>,
    option: bool,
    btree_map: bool,
}

impl Writer<'_> {
    fn def(&self, key: &str) -> Result<&Def, String> {
        self.library
            .defs
            .get(key)
            .ok_or_else(|| format!("no type {key}"))
    }

    fn rust_name(&self, key: &str) -> Result<String, String> {
        Ok(match self.def(key)? {
            Def::Record { full, .. } | Def::Enum { full, .. } => type_name(full),
            Def::Union { owner, field, .. } => format!("{}{}", type_name(owner), camel(field)),
            Def::Fixed { .. } => return Err(format!("the fixed {key} is no Rust type")),
        })
    }

    fn rust_ty(&mut self, ty: &Ty) -> Result<String, String> {
        Ok(match ty {
            Ty::Prim(prim) => prim.rust().to_owned(),
            Ty::Fixed { size, .. } => format!("[u8; {size}]"),
            Ty::Named(key) => self.rust_name(key)?,
            Ty::Array(item) => format!("Vec<{}>", self.rust_ty(item)?),
            Ty::Map(item) => {
                self.btree_map = true;
                format!("BTreeMap<String, {}>", self.rust_ty(item)?)
            }
            Ty::Option(item) => format!("Option<{}>", self.rust_ty(item)?),
        })
    }

    /// Whether a value of `ty` holds a floating-point number, which has no `Eq`.
    fn has_float(&self, ty: &Ty) -> Result<bool, String> {
        Ok(match ty {
            Ty::Prim(prim) => matches!(prim, Prim::Float | Prim::Double),
            Ty::Fixed { .. } => false,
            Ty::Array(item) | Ty::Map(item) | Ty::Option(item) => self.has_float(item)?,
            Ty::Named(key) => match self.def(key)? {
                Def::Record { fields, .. } => {
                    let mut any = false;
                    for f in fields {
                        any = any || self.has_float(&f.ty)?;
                    }
                    any
                }
                Def::Union { branches, .. } => {
                    let mut any = false;
                    for b in branches {
                        any = any || self.has_float(&b.ty)?;
                    }
                    any
                }
                Def::Enum { .. } | Def::Fixed { .. } => false,
            },
        })
    }

    fn derives(&self, tys: &[&Ty]) -> Result<&'static str, String> {
        let mut float = false;
        for ty in tys {
            float = float || self.has_float(ty)?;
        }
        Ok(if float {
            "#[derive(Debug, Clone, PartialEq)]"
        } else {
            "#[derive(Debug, Clone, PartialEq, Eq, Hash)]"
        })
    }

    /// An expression of the `Value` of `expr`, a Rust value of `ty`.
    fn to_value(&self, ty: &Ty, expr: &str, depth: usize) -> String {
        let next = depth.saturating_add(1);
        match ty {
            Ty::Prim(prim) => format!("Value::{}({expr})", prim.variant()),
            Ty::Fixed { .. } => format!("Value::Fixed({expr}.to_vec())"),
            Ty::Named(_) => format!("Value::from({expr})"),
            Ty::Array(item) => format!(
                "Value::Array({expr}.into_iter().map({}).collect())",
                self.to_fn(item, depth)
            ),
            Ty::Map(item) => format!(
                "Value::Map({expr}.into_iter().map(|(k{depth}, x{depth})| (k{depth}, {})).collect())",
                self.to_value(item, &format!("x{depth}"), next)
            ),
            Ty::Option(item) => format!("{expr}.map_or(Value::Null, {})", self.to_fn(item, depth)),
        }
    }

    /// A function from a Rust value of `ty` to its `Value`.
    fn to_fn(&self, ty: &Ty, depth: usize) -> String {
        match ty {
            Ty::Prim(prim) => format!("Value::{}", prim.variant()),
            Ty::Named(_) => "Value::from".into(),
            _ => format!(
                "|x{depth}| {}",
                self.to_value(ty, &format!("x{depth}"), depth.saturating_add(1))
            ),
        }
    }

    /// An expression of the `Result` of the Rust value of `expr`, a `Value` of `ty` at
    /// `at`.
    fn of_value(&mut self, ty: &Ty, expr: &str, at: &str, depth: usize) -> Result<String, String> {
        Ok(match ty {
            Ty::Prim(prim) => {
                self.used.insert(prim.avro());
                format!("{}({expr}, {at:?})", prim.avro())
            }
            Ty::Fixed { size, .. } => {
                self.used.insert("fixed");
                format!("fixed::<{size}>({expr}, {at:?})")
            }
            Ty::Named(key) => format!("{}::try_from({expr})", self.rust_name(key)?),
            Ty::Array(item) => {
                self.used.insert("array");
                format!("array({expr}, {at:?}, {})", self.of_fn(item, at, depth)?)
            }
            Ty::Map(item) => {
                self.used.insert("map");
                self.btree_map = true;
                format!("map({expr}, {at:?}, {})", self.of_fn(item, at, depth)?)
            }
            Ty::Option(item) => {
                self.option = true;
                format!("option({expr}, {})", self.of_fn(item, at, depth)?)
            }
        })
    }

    /// A function from a `Value` of `ty` at `at` to the `Result` of its Rust value.
    fn of_fn(&mut self, ty: &Ty, at: &str, depth: usize) -> Result<String, String> {
        Ok(match ty {
            Ty::Named(key) => format!("{}::try_from", self.rust_name(key)?),
            _ => format!(
                "|x{depth}| {}",
                self.of_value(ty, &format!("x{depth}"), at, depth.saturating_add(1))?
            ),
        })
    }

    fn record(
        &mut self,
        out: &mut String,
        full: &str,
        doc: &str,
        fields: &[FieldDef],
    ) -> Result<(), String> {
        let name = type_name(full);
        let mut idents = BTreeSet::new();
        doc_lines(out, doc, "");
        let tys: Vec<&Ty> = fields.iter().map(|f| &f.ty).collect();
        out.push_str(self.derives(&tys)?);
        out.push_str(&format!("\npub struct {name} {{\n"));
        for f in fields {
            let ident = field_ident(&f.name)?;
            if !idents.insert(ident.clone()) {
                return Err(format!("two fields of {full} are both {ident} in Rust"));
            }
            doc_lines(out, &f.doc, "    ");
            out.push_str(&format!("    pub {ident}: {},\n", self.rust_ty(&f.ty)?));
        }
        out.push_str("}\n\n");
        if let Some(description) = self.library.descriptions.get(full) {
            out.push_str(&format!(
                "impl {name} {{\n    \
                 /// The description of the type in its JSON form (`spec/fields.md`, section\n    \
                 /// 10.3), from which its schema is derived.\n    \
                 pub const DESCRIPTION: &'static str = {};\n\n    \
                 /// The type's description, read from [`Self::DESCRIPTION`].\n    \
                 ///\n    \
                 /// # Errors\n    \
                 ///\n    \
                 /// `DESCRIPTION_INVALID` for a description that is not valid, which a generated\n    \
                 /// one is.\n    \
                 pub fn description() -> Result<TypeDescription, Error> {{\n        \
                 TypeDescription::from_json_text(Self::DESCRIPTION)\n    \
                 }}\n}}\n\n",
                raw_literal(description)
            ));
        }
        out.push_str(&format!(
            "impl From<{name}> for Value {{\n    fn from(value: {name}) -> Self {{\n        Value::Record(vec![\n"
        ));
        for f in fields {
            let expr = format!("value.{}", field_ident(&f.name)?);
            out.push_str(&format!(
                "            ({:?}.into(), {}),\n",
                f.name,
                self.to_value(&f.ty, &expr, 0)
            ));
        }
        out.push_str("        ])\n    }\n}\n\n");
        self.used.insert("record");
        out.push_str(&format!(
            "impl TryFrom<Value> for {name} {{\n    type Error = Error;\n\n    \
             fn try_from(value: Value) -> Result<Self, Error> {{\n"
        ));
        if fields.is_empty() {
            out.push_str(&format!(
                "        record(value, {full:?})?;\n        Ok(Self {{}})\n"
            ));
        } else {
            self.used.insert("field");
            out.push_str(&format!(
                "        let mut fields = record(value, {full:?})?;\n        Ok(Self {{\n"
            ));
            for f in fields {
                let at = format!("{full}.{}", f.name);
                let taken = format!("field(&mut fields, {:?}, {at:?})?", f.name);
                out.push_str(&format!(
                    "            {}: {}?,\n",
                    field_ident(&f.name)?,
                    self.of_value(&f.ty, &taken, &at, 0)?
                ));
            }
            out.push_str("        })\n");
        }
        out.push_str("    }\n}\n\n");
        Ok(())
    }

    fn enumeration(
        &mut self,
        out: &mut String,
        full: &str,
        doc: &str,
        symbols: &[String],
    ) -> Result<(), String> {
        let name = type_name(full);
        let mut variants = Vec::new();
        for symbol in symbols {
            let variant = variant_of_symbol(symbol);
            if !is_ident(&variant) || variant == "Self" {
                return Err(format!("the symbol {symbol} of {full} is no Rust variant"));
            }
            if variants.contains(&variant) {
                return Err(format!("two symbols of {full} are both {variant} in Rust"));
            }
            variants.push(variant);
        }
        doc_lines(out, doc, "");
        out.push_str(&format!(
            "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\npub enum {name} {{\n"
        ));
        for (variant, symbol) in variants.iter().zip(symbols) {
            out.push_str(&format!("    /// The symbol `{symbol}`.\n    {variant},\n"));
        }
        out.push_str(&format!(
            "}}\n\nimpl {name} {{\n    /// Every value, in the order of the symbols.\n    \
             pub const ALL: [Self; {}] = [{}];\n\n    \
             /// The Avro symbol of the value.\n    #[must_use]\n    \
             pub const fn symbol(self) -> &'static str {{\n        match self {{\n",
            variants.len(),
            variants
                .iter()
                .map(|v| format!("Self::{v}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        for (variant, symbol) in variants.iter().zip(symbols) {
            out.push_str(&format!("            Self::{variant} => {symbol:?},\n"));
        }
        out.push_str(
            "        }\n    }\n\n    \
             /// The value of the Avro symbol `symbol`; `None` for any other text.\n    \
             #[must_use]\n    \
             pub fn from_symbol(symbol: &str) -> Option<Self> {\n        match symbol {\n",
        );
        for (variant, symbol) in variants.iter().zip(symbols) {
            out.push_str(&format!(
                "            {symbol:?} => Some(Self::{variant}),\n"
            ));
        }
        out.push_str("            _ => None,\n        }\n    }\n}\n\n");
        self.used.insert("symbol");
        out.push_str(&format!(
            "impl From<{name}> for Value {{\n    fn from(value: {name}) -> Self {{\n        \
             Value::Enum {{\n            index: value as u32,\n            \
             symbol: value.symbol().into(),\n        }}\n    }}\n}}\n\n\
             impl TryFrom<Value> for {name} {{\n    type Error = Error;\n\n    \
             fn try_from(value: Value) -> Result<Self, Error> {{\n        \
             Self::from_symbol(&symbol(value, {full:?})?)\n            \
             .ok_or_else(|| invalid({full:?}, \"none of its symbols\"))\n    }}\n}}\n\n"
        ));
        Ok(())
    }

    fn union(
        &mut self,
        out: &mut String,
        key: &str,
        owner: &str,
        field: &str,
        branches: &[BranchDef],
    ) -> Result<(), String> {
        let name = self.rust_name(key)?;
        let at = format!("{owner}.{field}");
        let mut variants = Vec::new();
        for branch in branches {
            let variant = match &branch.ty {
                Ty::Prim(prim) => prim.variant().to_owned(),
                Ty::Fixed { name, .. } | Ty::Named(name) => camel(simple_name(name)),
                Ty::Array(_) => "Array".into(),
                Ty::Map(_) => "Map".into(),
                Ty::Option(_) => return Err(format!("a union inside a union in {at}")),
            };
            if variants.contains(&variant) || !is_ident(&variant) {
                return Err(format!(
                    "the branch {} of {at} is no Rust variant",
                    branch.name
                ));
            }
            variants.push(variant);
        }
        let tys: Vec<&Ty> = branches.iter().map(|b| &b.ty).collect();
        out.push_str(&format!(
            "/// A value of the union in the field `{field}` of [`{}`]: one variant per branch.\n{}\npub enum {name} {{\n",
            type_name(owner),
            self.derives(&tys)?
        ));
        for (variant, branch) in variants.iter().zip(branches) {
            out.push_str(&format!(
                "    /// The branch `{}`.\n    {variant}({}),\n",
                branch.name,
                self.rust_ty(&branch.ty)?
            ));
        }
        out.push_str(&format!(
            "}}\n\nimpl From<{name}> for Value {{\n    fn from(value: {name}) -> Self {{\n        match value {{\n"
        ));
        for (variant, branch) in variants.iter().zip(branches) {
            out.push_str(&format!(
                "            {name}::{variant}(x0) => Value::Union {{\n                \
                 index: {},\n                branch: {:?}.into(),\n                \
                 value: Box::new({}),\n            }},\n",
                branch.index,
                branch.name,
                self.to_value(&branch.ty, "x0", 1)
            ));
        }
        out.push_str("        }\n    }\n}\n\n");
        self.used.insert("branch");
        out.push_str(&format!(
            "impl TryFrom<Value> for {name} {{\n    type Error = Error;\n\n    \
             fn try_from(value: Value) -> Result<Self, Error> {{\n        \
             let (branch, value) = branch(value, {at:?})?;\n        match branch.as_str() {{\n"
        ));
        for (variant, branch) in variants.iter().zip(branches) {
            out.push_str(&format!(
                "            {:?} => Ok(Self::{variant}({}?)),\n",
                branch.name,
                self.of_value(&branch.ty, "value", &at, 0)?
            ));
        }
        out.push_str(&format!(
            "            _ => Err(invalid({at:?}, \"of no branch of the union\")),\n        }}\n    }}\n}}\n\n"
        ));
        Ok(())
    }

    fn helpers(&self, out: &mut String) {
        // Every conversion that fails says so through `invalid`.
        for helper in HELPERS {
            if helper != "invalid" && !self.used.contains(helper) {
                continue;
            }
            out.push_str(&match helper {
                "invalid" => "/// The error of a value that does not fit its type.\n\
                     fn invalid(at: &str, problem: &str) -> Error {\n    \
                     Error::axt(ErrorCode::ValueInvalid, format!(\"{at}: {problem}\"))\n}\n\n"
                    .to_owned(),
                "record" => "/// The fields of a record.\n\
                     fn record(value: Value, at: &str) -> Result<Vec<(String, Value)>, Error> {\n    \
                     match value {\n        Value::Record(fields) => Ok(fields),\n        \
                     _ => Err(invalid(at, \"not a record\")),\n    }\n}\n\n"
                    .to_owned(),
                "field" => "/// The value of the field `name` at `at`, taken out of `fields`.\n\
                     fn field(fields: &mut Vec<(String, Value)>, name: &str, at: &str) -> Result<Value, Error> {\n    \
                     let position = fields\n        .iter()\n        .position(|(n, _)| n == name)\n        \
                     .ok_or_else(|| invalid(at, \"missing\"))?;\n    \
                     Ok(fields.swap_remove(position).1)\n}\n\n"
                    .to_owned(),
                "symbol" => "/// The symbol of an enum.\n\
                     fn symbol(value: Value, at: &str) -> Result<String, Error> {\n    \
                     match value {\n        Value::Enum { symbol, .. } => Ok(symbol),\n        \
                     _ => Err(invalid(at, \"not an enum\")),\n    }\n}\n\n"
                    .to_owned(),
                "branch" => "/// The branch and the value of a union.\n\
                     fn branch(value: Value, at: &str) -> Result<(String, Value), Error> {\n    \
                     match value {\n        Value::Union { branch, value, .. } => Ok((branch, *value)),\n        \
                     _ => Err(invalid(at, \"not a union of two or more non-null branches\")),\n    }\n}\n\n"
                    .to_owned(),
                "fixed" => "/// The bytes of a fixed of `N` bytes.\n\
                     fn fixed<const N: usize>(value: Value, at: &str) -> Result<[u8; N], Error> {\n    \
                     match value {\n        \
                     Value::Fixed(bytes) => <[u8; N]>::try_from(bytes).map_err(|_| invalid(at, \"not of its size\")),\n        \
                     _ => Err(invalid(at, \"not a fixed\")),\n    }\n}\n\n"
                    .to_owned(),
                "array" => "/// The items of an array.\n\
                     fn array<T>(value: Value, at: &str, item: impl Fn(Value) -> Result<T, Error>) -> Result<Vec<T>, Error> {\n    \
                     match value {\n        Value::Array(items) => items.into_iter().map(item).collect(),\n        \
                     _ => Err(invalid(at, \"not an array\")),\n    }\n}\n\n"
                    .to_owned(),
                "map" => "/// The entries of a map.\n\
                     fn map<T>(value: Value, at: &str, item: impl Fn(Value) -> Result<T, Error>) -> Result<BTreeMap<String, T>, Error> {\n    \
                     match value {\n        \
                     Value::Map(entries) => entries.into_iter().map(|(key, v)| Ok((key, item(v)?))).collect(),\n        \
                     _ => Err(invalid(at, \"not a map\")),\n    }\n}\n\n"
                    .to_owned(),
                prim => {
                    let Some(prim) = Prim::of(prim) else {
                        continue;
                    };
                    format!(
                        "/// The value of a {}.\n\
                         fn {}(value: Value, at: &str) -> Result<{}, Error> {{\n    \
                         match value {{\n        Value::{}(v) => Ok(v),\n        \
                         _ => Err(invalid(at, {:?})),\n    }}\n}}\n\n",
                        prim.avro(),
                        prim.avro(),
                        prim.rust(),
                        prim.variant(),
                        prim.not()
                    )
                }
            });
        }
        if self.option {
            out.push_str(
                "/// The value of a union of null and one other type: `None` for null.\n\
                 fn option<T>(value: Value, item: impl FnOnce(Value) -> Result<T, Error>) -> Result<Option<T>, Error> {\n    \
                 match value {\n        Value::Null => Ok(None),\n        other => item(other).map(Some),\n    }\n}\n",
            );
        }
    }
}

/// The Rust source of the types of `descriptions`, their JSON texts by the names they
/// are known by, such as their paths: a struct for the type of each description and for
/// each record inside it, an enum for each enum and for each union of two or more
/// non-null branches, the types of the namespace `axt` named `Axt…`. The source is not
/// formatted.
///
/// # Errors
///
/// [`GenerateError::Description`] for a description that is not valid, and
/// [`GenerateError::Generate`] where the generator stops.
pub fn generate_from_descriptions(
    descriptions: &[(String, String)],
) -> Result<String, GenerateError> {
    let mut library = Library::default();
    let mut roots = Vec::new();
    for (name, text) in descriptions {
        let description =
            TypeDescription::from_json_text(text).map_err(|error| GenerateError::Description {
                name: name.clone(),
                error,
            })?;
        let schema: Json = serde_json::from_str(description.schema_text())
            .map_err(|e| GenerateError::Generate(format!("{name}: {e}")))?;
        let mut reader = Reader {
            library: &mut library,
            known: BTreeMap::new(),
        };
        reader
            .ty(&schema, "", "", "")
            .map_err(|e| GenerateError::Generate(format!("{name}: {e}")))?;
        let root = description.name().to_owned();
        let text = minified(text);
        match library.descriptions.get(&root) {
            Some(known) if *known != text => {
                return Err(GenerateError::Generate(format!(
                    "{name}: two different descriptions are of {root}"
                )));
            }
            Some(_) => {}
            None => {
                library.descriptions.insert(root.clone(), text);
            }
        }
        roots.push(name.clone());
    }
    write_library(&library, &roots).map_err(GenerateError::Generate)
}

fn write_library(library: &Library, names: &[String]) -> Result<String, String> {
    let mut writer = Writer {
        library,
        used: BTreeSet::new(),
        option: false,
        btree_map: false,
    };
    let mut rust_names = BTreeMap::new();
    for key in &library.order {
        if matches!(writer.def(key)?, Def::Fixed { .. }) {
            continue;
        }
        let rust = writer.rust_name(key)?;
        if !is_ident(&rust) || TAKEN.contains(&rust.as_str()) {
            return Err(format!("{key} cannot be named {rust} in Rust"));
        }
        if let Some(other) = rust_names.insert(rust.clone(), key.clone()) {
            return Err(format!("{other} and {key} are both named {rust} in Rust"));
        }
    }
    let mut body = String::new();
    for key in &library.order {
        match writer.def(key)?.clone() {
            Def::Record { full, doc, fields } => writer.record(&mut body, &full, &doc, &fields)?,
            Def::Enum { full, doc, symbols } => {
                writer.enumeration(&mut body, &full, &doc, &symbols)?;
            }
            Def::Union {
                owner,
                field,
                branches,
            } => writer.union(&mut body, key, &owner, &field, &branches)?,
            Def::Fixed { .. } => {}
        }
    }
    writer.helpers(&mut body);
    let mut out =
        String::from("// Generated by axt-protocol-generate. Do not edit.\n//\n// From:\n");
    for name in names {
        out.push_str(&format!("// - {name}\n"));
    }
    out.push('\n');
    if writer.btree_map {
        out.push_str("use std::collections::BTreeMap;\n\n");
    }
    out.push_str("use axt_protocol::{Error, ErrorCode, TypeDescription, Value};\n\n");
    out.push_str(body.trim_end());
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_literals() {
        assert_eq!(camel("odometer_unit"), "OdometerUnit");
        assert_eq!(camel("PersonPhone"), "PersonPhone");
        assert_eq!(variant_of_symbol("KILOMETRE"), "Kilometre");
        assert_eq!(variant_of_symbol("NOT_SET"), "NotSet");
        assert_eq!(type_name("axt.DateTime"), "AxtDateTime");
        assert_eq!(type_name("axt.example.v1.Pet"), "Pet");
        assert_eq!(type_name("Plain"), "Plain");
        assert_eq!(field_ident("type").unwrap(), "r#type");
        assert_eq!(field_ident("name").unwrap(), "name");
        assert!(field_ident("self").is_err());
        assert_eq!(
            minified("{ \"a b\" : [1, \"\\\" x\"] }\n"),
            "{\"a b\":[1,\"\\\" x\"]}"
        );
        assert_eq!(raw_literal("{}"), "r#\"{}\"#");
        let mut doc = String::new();
        doc_lines(&mut doc, "mm[Hg] <b>\n\nC:\\", "  ");
        assert_eq!(doc, "  /// mm\\[Hg\\] \\<b\\>\n  ///\n  /// C:\\\\\n");
        assert_eq!(raw_literal("\"#\"##"), "r###\"\"#\"##\"###");
    }
}
