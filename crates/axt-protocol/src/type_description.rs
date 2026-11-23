//! A type as an app gives it: its description, with the schema derived from it (AXT
//! `spec/fields.md`, sections 9 and 10).

use serde_json::Value as Json;

use crate::bricks::{self, Field, Kind};
use crate::error::{Error, ErrorCode};
use crate::schema::{Fingerprint, Schema};
use crate::value::Value;

/// A valid description of a type and the schema derived from it.
#[derive(Debug, Clone)]
pub struct TypeDescription {
    datum: Value,
    root: Field,
    schema_text: String,
    schema: Schema,
}

impl TypeDescription {
    /// The description in its JSON form (`spec/fields.md`, section 10.3): the datum of
    /// `axt.Field`, bytes as lower-case hexadecimal and the branch of each union `kind` as
    /// an object of one member named by the brick's full name.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::DescriptionInvalid`] for JSON that is not a description in that form,
    /// or a description that is not valid; for a rule of the description its `field`
    /// names the member that breaks it, such as `kind.fields[1].kind.symbols`.
    pub fn from_json(json: &Json) -> Result<Self, Error> {
        Self::from_datum(bricks::description_from_json(json)?)
    }

    /// The description of `datum`, a decoded datum of `axt.Field`.
    pub(crate) fn from_datum(datum: Value) -> Result<Self, Error> {
        let root = Field::from_value(&datum)?;
        let schema_text = bricks::derive_schema(&root, &datum)?;
        let schema = Schema::parse(&schema_text)
            .map_err(|e| Error::axt(ErrorCode::DescriptionInvalid, e.to_string()))?;
        Ok(Self {
            datum,
            root,
            schema_text,
            schema,
        })
    }

    /// The description, a decoded datum of `axt.Field`.
    #[must_use]
    pub fn datum(&self) -> &Value {
        &self.datum
    }

    /// The typed field at the root of the description.
    pub(crate) fn root(&self) -> &Field {
        &self.root
    }

    /// The text of the derived schema (`spec/fields.md`, section 9.3).
    #[must_use]
    pub fn schema_text(&self) -> &str {
        &self.schema_text
    }

    /// The derived schema.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The type's full name, such as `com.example.Vet`.
    #[must_use]
    pub fn name(&self) -> &str {
        match &self.root.kind {
            Kind::Object(object) => &object.name,
            // A valid description has an object at its root.
            _ => "",
        }
    }

    /// The fingerprint of the derived schema.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.schema.fingerprint()
    }

    /// The description in its JSON form.
    #[must_use]
    pub fn to_json(&self) -> Json {
        self.datum.to_json()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn json() -> Json {
        json!({
            "name": "root",
            "doc": "A type.",
            "texts": {"label": "Type", "label_translations": {"de": "Typ"}},
            "kind": {"axt.ObjectField": {
                "name": "com.example.T",
                "version": 1,
                "fields": [
                    {"name": "data", "doc": "The data.", "texts": {},
                     "kind": {"axt.BytesField": {"default": "00ff"}}},
                    {"name": "share", "doc": "The share.", "texts": {},
                     "kind": {"axt.DoubleField": {"default": 1}}},
                ],
            }},
        })
    }

    #[test]
    fn a_description_goes_to_its_json_form_and_back() {
        let t = TypeDescription::from_json(&json()).unwrap();
        assert_eq!(t.name(), "com.example.T");
        let again = TypeDescription::from_json(&t.to_json()).unwrap();
        assert_eq!(again.to_json(), t.to_json());
        assert_eq!(again.datum(), t.datum());
        let fields = &t.to_json()["kind"]["axt.ObjectField"]["fields"];
        assert_eq!(
            fields[0]["kind"]["axt.BytesField"]["default"],
            json!("00ff")
        );
        assert_eq!(fields[1]["kind"]["axt.DoubleField"]["default"], json!(1.0));
        assert_eq!(t.fingerprint(), t.schema().fingerprint());
        assert_eq!(
            Schema::parse(t.schema_text()).unwrap().canonical_form(),
            t.schema().canonical_form()
        );
    }

    #[test]
    fn json_that_is_not_the_form_is_not_a_valid_description() {
        let with = |name: &str, value: Json| {
            let mut j = json();
            j[name] = value;
            j
        };
        let mut no_doc = json();
        no_doc.as_object_mut().unwrap().remove("doc");
        let mut bad_hex = json();
        bad_hex["kind"]["axt.ObjectField"]["fields"][0]["kind"] =
            json!({"axt.BytesField": {"default": "FF"}});
        for bad in [
            json!("x"),
            no_doc,
            with("kind", json!({"axt.Nope": {}})),
            with(
                "kind",
                json!({"axt.ObjectField": {}, "axt.StringField": {}}),
            ),
            with("doc", json!(1)),
            with("order", json!("x")),
            bad_hex,
        ] {
            let e = TypeDescription::from_json(&bad).unwrap_err();
            assert_eq!(e.code(), Some(ErrorCode::DescriptionInvalid), "{bad}");
        }
        match TypeDescription::from_json(&with("doc", json!(""))).unwrap_err() {
            Error::Axt { field, .. } => assert_eq!(field.as_deref(), Some("doc")),
            other => panic!("{other}"),
        }
    }
}
