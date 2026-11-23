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
/// `manifest.body`: the most bytes of the body of a `MANIFEST`, single-object header
/// included.
pub(crate) const MANIFEST_BODY: usize = 1_048_576;
/// `manifest.formats`: the most entries of `formats`.
pub(crate) const MANIFEST_FORMATS: usize = 16;
/// `manifest.takes`: the most entries of `takes`.
pub(crate) const MANIFEST_TAKES: usize = 256;
/// `manifest.sends`: the most entries of `sends`.
pub(crate) const MANIFEST_SENDS: usize = 256;
/// `manifest.full_name`: the most bytes of a full name in `takes` or `sends`.
pub(crate) const MANIFEST_FULL_NAME: usize = 512;
/// `manifest.app_name`: the most bytes of `app_name`.
pub(crate) const MANIFEST_APP_NAME: usize = 256;
/// `manifest.app_url`: the most bytes of `app_url`.
pub(crate) const MANIFEST_APP_URL: usize = 2048;
/// `manifest.purpose`: the most bytes of one purpose sentence.
pub(crate) const MANIFEST_PURPOSE: usize = 512;
/// `manifest.purpose_translations`: the most entries of one `purpose_translations`.
pub(crate) const MANIFEST_PURPOSE_TRANSLATIONS: usize = 64;
/// `manifest.language_tag`: the most characters of a language tag.
pub(crate) const MANIFEST_LANGUAGE_TAG: usize = 35;
/// `transports.relay_url`: the most bytes of the base URL of a relay.
pub(crate) const TRANSPORTS_RELAY_URL: usize = 256;
/// `protocol.error_field`: the most bytes of the field path of an error.
pub(crate) const PROTOCOL_ERROR_FIELD: usize = 1024;
/// `protocol.offer_types`: the most entries of `types` in one `OFFER`, `ACCEPT` or
/// `DECLINE`.
#[cfg(feature = "conformance")]
pub(crate) const PROTOCOL_OFFER_TYPES: usize = 256;
/// `protocol.ack_records`: the most entries of `records` in one `ACK`.
#[cfg(feature = "conformance")]
pub(crate) const PROTOCOL_ACK_RECORDS: usize = 4096;
/// `protocol.error_record_id`: the most bytes of the id of the reported message's record
/// up to which an `ERROR` carries `record`.
#[cfg(feature = "conformance")]
pub(crate) const PROTOCOL_ERROR_RECORD_ID: usize = 64;
/// `shares.proposal_fields`: the most entries of `fields` in one `PROPOSAL`.
#[cfg(feature = "conformance")]
pub(crate) const SHARES_PROPOSAL_FIELDS: usize = 4096;
/// `shares.proposal_field_name`: the most bytes of a field name in a `PROPOSAL`.
#[cfg(feature = "conformance")]
pub(crate) const SHARES_PROPOSAL_FIELD_NAME: usize = 512;
/// `shares.proposal_value_bytes`: the most value bytes of one `PROPOSAL`.
#[cfg(feature = "conformance")]
pub(crate) const SHARES_PROPOSAL_VALUE_BYTES: usize = 65_536;
/// `shares.open_value_bytes`: the most value bytes of the open proposals of one proposer.
#[cfg(feature = "conformance")]
pub(crate) const SHARES_OPEN_VALUE_BYTES: usize = 1_048_576;
/// `shares.open_per_record`: the most open proposals of one proposer for one record.
#[cfg(feature = "conformance")]
pub(crate) const SHARES_OPEN_PER_RECORD: usize = 16;
/// `shares.open`: the most open proposals of one proposer in all.
#[cfg(feature = "conformance")]
pub(crate) const SHARES_OPEN: usize = 256;
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
            ("manifest.body", MANIFEST_BODY as u64),
            ("manifest.formats", MANIFEST_FORMATS as u64),
            ("manifest.takes", MANIFEST_TAKES as u64),
            ("manifest.sends", MANIFEST_SENDS as u64),
            ("manifest.full_name", MANIFEST_FULL_NAME as u64),
            ("manifest.app_name", MANIFEST_APP_NAME as u64),
            ("manifest.app_url", MANIFEST_APP_URL as u64),
            ("manifest.purpose", MANIFEST_PURPOSE as u64),
            (
                "manifest.purpose_translations",
                MANIFEST_PURPOSE_TRANSLATIONS as u64,
            ),
            ("manifest.language_tag", MANIFEST_LANGUAGE_TAG as u64),
            ("transports.relay_url", TRANSPORTS_RELAY_URL as u64),
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

    #[cfg(feature = "conformance")]
    #[test]
    fn the_limits_of_the_live_session_are_those_published() {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/limits.json")).unwrap();
        let limit = |name: &str| json["limits"][name]["value"].as_u64().unwrap();
        assert_eq!(limit("protocol.offer_types"), PROTOCOL_OFFER_TYPES as u64);
        assert_eq!(limit("protocol.ack_records"), PROTOCOL_ACK_RECORDS as u64);
        assert_eq!(
            limit("protocol.error_record_id"),
            PROTOCOL_ERROR_RECORD_ID as u64
        );
        for (name, value) in [
            ("shares.proposal_fields", SHARES_PROPOSAL_FIELDS),
            ("shares.proposal_field_name", SHARES_PROPOSAL_FIELD_NAME),
            ("shares.proposal_value_bytes", SHARES_PROPOSAL_VALUE_BYTES),
            ("shares.open_value_bytes", SHARES_OPEN_VALUE_BYTES),
            ("shares.open_per_record", SHARES_OPEN_PER_RECORD),
            ("shares.open", SHARES_OPEN),
        ] {
            assert_eq!(limit(name), value as u64, "{name}");
        }
    }
}
