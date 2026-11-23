//! The schemas of the specification that the library reads and writes, as the AXT
//! 0.2.0 release publishes them in `types/axt/` (CC0 1.0).

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::schema::Schema;

/// The JSON text of each schema, by full name.
const TEXTS: [(&str, &str); 16] = [
    ("axt.Accept", include_str!("../schemas/Accept.avsc")),
    ("axt.Ack", include_str!("../schemas/Ack.avsc")),
    ("axt.Change", include_str!("../schemas/Change.avsc")),
    ("axt.Decline", include_str!("../schemas/Decline.avsc")),
    ("axt.DeviceAdd", include_str!("../schemas/DeviceAdd.avsc")),
    ("axt.DeviceJoin", include_str!("../schemas/DeviceJoin.avsc")),
    (
        "axt.DeviceRemove",
        include_str!("../schemas/DeviceRemove.avsc"),
    ),
    ("axt.Envelope", include_str!("../schemas/Envelope.avsc")),
    ("axt.Error", include_str!("../schemas/Error.avsc")),
    ("axt.Forward", include_str!("../schemas/Forward.avsc")),
    ("axt.Manifest", include_str!("../schemas/Manifest.avsc")),
    ("axt.Offer", include_str!("../schemas/Offer.avsc")),
    ("axt.Proposal", include_str!("../schemas/Proposal.avsc")),
    (
        "axt.ProposalReply",
        include_str!("../schemas/ProposalReply.avsc"),
    ),
    ("axt.Resync", include_str!("../schemas/Resync.avsc")),
    ("axt.Withdraw", include_str!("../schemas/Withdraw.avsc")),
];

/// The schemas, parsed once. Every text parses, as a test checks.
static SCHEMAS: LazyLock<HashMap<&'static str, Schema>> = LazyLock::new(|| {
    TEXTS
        .iter()
        .filter_map(|&(name, text)| Some((name, Schema::parse(text).ok()?)))
        .collect()
});

/// The JSON text of the specification's schema of `full_name`, such as `axt.Envelope`,
/// as the release publishes it; `None` for a name the library does not embed.
#[must_use]
pub fn axt_schema_text(full_name: &str) -> Option<&'static str> {
    TEXTS
        .iter()
        .find(|(name, _)| *name == full_name)
        .map(|&(_, text)| text)
}

/// The parsed schema of `full_name`, such as `axt.Envelope`; `None` for a name the
/// library does not embed.
#[must_use]
pub fn axt_schema(full_name: &str) -> Option<&'static Schema> {
    SCHEMAS.get(full_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_schema_parses_under_its_full_name() {
        for (name, text) in TEXTS {
            let schema = axt_schema(name).unwrap();
            let short = name.strip_prefix("axt.").unwrap();
            assert!(text.contains(&format!("\"name\": \"{short}\"")), "{name}");
            assert!(
                schema
                    .canonical_form()
                    .starts_with(&format!("{{\"name\":\"{name}\"")),
                "{name}"
            );
        }
        assert!(axt_schema("axt.Nothing").is_none());
        assert!(axt_schema_text("axt.Nothing").is_none());
    }

    #[test]
    fn the_envelope_has_the_published_fingerprint() {
        // The fingerprint every live message of format 1 begins with (envelope.md 3.1).
        let schema = axt_schema("axt.Envelope").unwrap();
        assert_eq!(schema.fingerprint().to_string(), "16306f71b9ce9ea8");
    }
}
