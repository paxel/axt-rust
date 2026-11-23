//! The limits of the specification that the library applies (AXT `types/axt/limits.json`).
//!
//! Each constant is the limit of the same name there, such as [`METADATA_LABEL`] for
//! `metadata.label`; a test compares them with the published file.

/// `envelope.schema`: the most bytes of a schema text, or of a description in its Avro
/// encoding.
pub(crate) const ENVELOPE_SCHEMA: usize = 262_144;
/// `envelope.schema_depth`: the deepest a schema nests as JSON.
pub(crate) const ENVELOPE_SCHEMA_DEPTH: usize = 64;
/// `types.data_depth`: the deepest a record nests.
pub(crate) const TYPES_DATA_DEPTH: usize = 32;
/// `time.zone`: the most bytes of a zone name.
pub(crate) const TIME_ZONE: usize = 64;
/// `metadata.label`: the most bytes of a label.
pub(crate) const METADATA_LABEL: usize = 256;
/// `metadata.help`: the most bytes of a help text.
pub(crate) const METADATA_HELP: usize = 1024;
/// `metadata.placeholder`: the most bytes of a placeholder.
pub(crate) const METADATA_PLACEHOLDER: usize = 256;
/// `metadata.example`: the most bytes of an example.
pub(crate) const METADATA_EXAMPLE: usize = 1024;
/// `metadata.translations`: the most translations of one text.
pub(crate) const METADATA_TRANSLATIONS: usize = 64;
/// `metadata.emoji`: the most code points of an emoji.
pub(crate) const METADATA_EMOJI: usize = 10;
/// `metadata.pattern`: the most bytes of a pattern.
pub(crate) const METADATA_PATTERN: usize = 1024;
/// `metadata.pattern_quantifier`: the largest number of a range quantifier.
pub(crate) const METADATA_PATTERN_QUANTIFIER: u32 = 1000;
/// `metadata.group_key`: the most bytes of a group key.
pub(crate) const METADATA_GROUP_KEY: usize = 64;
/// `manifest.language_tag`: the most characters of a language tag.
pub(crate) const MANIFEST_LANGUAGE_TAG: usize = 35;
/// `protocol.error_field`: the most bytes of the field path of an error.
pub(crate) const PROTOCOL_ERROR_FIELD: usize = 1024;
/// `fields.depth`: the deepest typed fields nest.
pub(crate) const FIELDS_DEPTH: usize = 64;
/// `fields.long_default`: the largest magnitude of a default of an `axt.LongField`.
pub(crate) const FIELDS_LONG_DEFAULT: u64 = 9_007_199_254_740_992;
/// `fields.relations`: the most relations of a list.
pub(crate) const FIELDS_RELATIONS: usize = 256;
/// `fields.relation_name`: the most bytes of a relation's kind or a target's type.
pub(crate) const FIELDS_RELATION_NAME: usize = 256;
/// `fields.relation_uri`: the most bytes of the URI of an outside target.
pub(crate) const FIELDS_RELATION_URI: usize = 2048;
/// `fields.relation_text`: the most bytes of the display text of a target.
pub(crate) const FIELDS_RELATION_TEXT: usize = 256;
/// `fields.relation_note`: the most bytes of the note of a relation.
pub(crate) const FIELDS_RELATION_NOTE: usize = 4096;
/// `fields.relation_attributes`: the most attributes of a relation.
pub(crate) const FIELDS_RELATION_ATTRIBUTES: usize = 32;
/// `fields.relation_attribute_name`: the most bytes of an attribute's name.
pub(crate) const FIELDS_RELATION_ATTRIBUTE_NAME: usize = 256;
/// `fields.relation_attribute_value`: the most bytes of an attribute's value.
pub(crate) const FIELDS_RELATION_ATTRIBUTE_VALUE: usize = 1024;
/// `fields.extensions`: the most extensions of a list.
pub(crate) const FIELDS_EXTENSIONS: usize = 32;
/// `fields.extension_name`: the most bytes of an extension's name.
pub(crate) const FIELDS_EXTENSION_NAME: usize = 256;
/// `fields.extension_data`: the most bytes of an extension's data.
pub(crate) const FIELDS_EXTENSION_DATA: usize = 65_536;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_are_those_published() {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/limits.json")).unwrap();
        let limit = |name: &str| json["limits"][name]["value"].as_u64().unwrap();
        for (name, value) in [
            ("envelope.schema", ENVELOPE_SCHEMA as u64),
            ("envelope.schema_depth", ENVELOPE_SCHEMA_DEPTH as u64),
            ("types.data_depth", TYPES_DATA_DEPTH as u64),
            ("time.zone", TIME_ZONE as u64),
            ("metadata.label", METADATA_LABEL as u64),
            ("metadata.help", METADATA_HELP as u64),
            ("metadata.placeholder", METADATA_PLACEHOLDER as u64),
            ("metadata.example", METADATA_EXAMPLE as u64),
            ("metadata.translations", METADATA_TRANSLATIONS as u64),
            ("metadata.emoji", METADATA_EMOJI as u64),
            ("metadata.pattern", METADATA_PATTERN as u64),
            (
                "metadata.pattern_quantifier",
                u64::from(METADATA_PATTERN_QUANTIFIER),
            ),
            ("metadata.group_key", METADATA_GROUP_KEY as u64),
            ("manifest.language_tag", MANIFEST_LANGUAGE_TAG as u64),
            ("protocol.error_field", PROTOCOL_ERROR_FIELD as u64),
            ("fields.depth", FIELDS_DEPTH as u64),
            ("fields.long_default", FIELDS_LONG_DEFAULT),
            ("fields.relations", FIELDS_RELATIONS as u64),
            ("fields.relation_name", FIELDS_RELATION_NAME as u64),
            ("fields.relation_uri", FIELDS_RELATION_URI as u64),
            ("fields.relation_text", FIELDS_RELATION_TEXT as u64),
            ("fields.relation_note", FIELDS_RELATION_NOTE as u64),
            (
                "fields.relation_attributes",
                FIELDS_RELATION_ATTRIBUTES as u64,
            ),
            (
                "fields.relation_attribute_name",
                FIELDS_RELATION_ATTRIBUTE_NAME as u64,
            ),
            (
                "fields.relation_attribute_value",
                FIELDS_RELATION_ATTRIBUTE_VALUE as u64,
            ),
            ("fields.extensions", FIELDS_EXTENSIONS as u64),
            ("fields.extension_name", FIELDS_EXTENSION_NAME as u64),
            ("fields.extension_data", FIELDS_EXTENSION_DATA as u64),
        ] {
            assert_eq!(limit(name), value, "{name}");
        }
    }
}
