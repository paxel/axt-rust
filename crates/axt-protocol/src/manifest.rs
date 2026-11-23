//! The manifest: its validity and limits, which types fit it, and the language of the
//! purpose sentence (AXT `spec/manifest.md`, sections 3 to 5, and `spec/metadata.md`,
//! section 4.2).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value as Json;

use crate::envelope::{self, Kind};
use crate::error::{Error, ErrorCode};
use crate::limits::{
    MANIFEST_APP_NAME, MANIFEST_APP_URL, MANIFEST_BODY, MANIFEST_FORMATS, MANIFEST_FULL_NAME,
    MANIFEST_LANGUAGE_TAG, MANIFEST_PURPOSE, MANIFEST_PURPOSE_TRANSLATIONS, MANIFEST_SENDS,
    MANIFEST_TAKES, TRANSPORTS_RELAY_URL,
};
use crate::schema::Schema;
use crate::sealing;
use crate::value::Value;

/// The `langtag` form of RFC 5646, section 2.1; `None` only if it failed to compile, which
/// a test rules out.
static LANGTAG: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\A([A-Za-z]{2,3}(-[A-Za-z]{3}){0,3}|[A-Za-z]{4}|[A-Za-z]{5,8})",
        r"(-[A-Za-z]{4})?",
        r"(-([A-Za-z]{2}|[0-9]{3}))?",
        r"(-([A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*",
        r"(-[0-9A-WY-Za-wy-z](-[A-Za-z0-9]{2,8})+)*",
        r"(-[Xx](-[A-Za-z0-9]{1,8})+)?\z",
    ))
    .ok()
});

/// Whether `tag` is a language tag of RFC 5646 in the `langtag` form, of at most
/// `manifest.language_tag` characters.
pub(crate) fn is_language_tag(tag: &str) -> bool {
    tag.encode_utf16().count() <= MANIFEST_LANGUAGE_TAG
        && LANGTAG.as_ref().is_some_and(|r| r.is_match(tag))
}

/// The tag of `tags` that the Lookup of RFC 4647, section 3.4, chooses for the language
/// priority list `languages`, or `None`.
pub(crate) fn lookup<'a>(languages: &[String], tags: &[&'a str]) -> Option<&'a str> {
    let by_lower: HashMap<String, &str> = tags
        .iter()
        .map(|&tag| (tag.to_ascii_lowercase(), tag))
        .collect();
    for range in languages {
        if range == "*" {
            continue;
        }
        let mut candidate = range.to_ascii_lowercase();
        while !candidate.is_empty() {
            if let Some(&found) = by_lower.get(&candidate) {
                return Some(found);
            }
            let Some(mut cut) = candidate.rfind('-') else {
                break;
            };
            // A single-letter subtag goes with the one after it.
            if cut >= 2
                && cut
                    .checked_sub(2)
                    .and_then(|i| candidate.as_bytes().get(i))
                    .is_some_and(|&b| b == b'-')
            {
                cut = cut.saturating_sub(2);
            }
            candidate.truncate(cut);
        }
    }
    None
}

/// A rejection of the manifest.
fn invalid(why: impl Into<String>) -> Error {
    Error::axt(ErrorCode::ManifestInvalid, why)
}

/// Whether `text` is one line of plain text of 1 to `max` bytes: not empty, without
/// control characters and without the separators U+2028 and U+2029 (section 4).
fn is_one_line(text: Option<&Value>, max: usize) -> bool {
    let Some(Value::String(text)) = text else {
        return false;
    };
    !text.is_empty()
        && text.len() <= max
        && !text
            .chars()
            .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
}

/// Whether `name` is an Avro full name of up to `manifest.full_name` bytes.
fn is_full_name(name: &str) -> bool {
    name.len() <= MANIFEST_FULL_NAME
        && name.split('.').all(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Whether `url` is an absolute URL (RFC 3986) with the scheme `https` and a host, of up
/// to `max` bytes, without spaces or control characters; for a `base` URL, also without
/// user information, query or fragment, and with a path that ends with `/`.
fn is_https_url(url: Option<&Value>, max: usize, base: bool) -> bool {
    let Some(Value::String(url)) = url else {
        return false;
    };
    if url.len() > max || url.chars().any(|c| c <= ' ' || c.is_control()) {
        return false;
    }
    let Some((scheme, rest)) = url.split_once(':') else {
        return false;
    };
    let Some(rest) = rest.strip_prefix("//") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let Some((authority, tail)) = rest.split_at_checked(end) else {
        return false;
    };
    let (user_info, host_and_port) = authority.rsplit_once('@').unwrap_or(("", authority));
    let port_ok = |port: &str| port.chars().all(|c| c.is_ascii_digit());
    let host = if let Some(literal) = host_and_port.strip_prefix('[') {
        // An IP literal: its address in brackets, then an optional port.
        let Some((address, after)) = literal.split_once(']') else {
            return false;
        };
        if !after.strip_prefix(':').map_or(after.is_empty(), port_ok)
            || !address
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return false;
        }
        address
    } else {
        match host_and_port.rsplit_once(':') {
            Some((host, port)) if port_ok(port) => host,
            Some(_) => return false,
            None => host_and_port,
        }
    };
    if host.is_empty() {
        return false;
    }
    !base || (user_info.is_empty() && !tail.contains(['?', '#']) && tail.ends_with('/'))
}

/// The integer of a field of an integer type, or `None`.
fn integer(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Int(i)) => Some(i64::from(*i)),
        Some(Value::Long(l)) => Some(*l),
        _ => None,
    }
}

/// The entries of a field of an array type; none for another value.
fn items(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

/// The translations of a purpose sentence; none for another value.
fn translations(entry: &Value) -> Option<&BTreeMap<String, Value>> {
    match entry.field("purpose_translations") {
        Some(Value::Map(translations)) => Some(translations),
        _ => None,
    }
}

/// Checks the purpose sentence of `entry`, at `at`, and its translations (sections 3.6
/// and 4).
fn check_purpose(entry: &Value, at: &str) -> Result<(), Error> {
    if !is_one_line(entry.field("purpose"), MANIFEST_PURPOSE) {
        return Err(invalid(format!(
            "{at}.purpose is not one line of 1 to {MANIFEST_PURPOSE} bytes"
        )));
    }
    let Some(translations) = translations(entry) else {
        return Ok(());
    };
    if translations.len() > MANIFEST_PURPOSE_TRANSLATIONS {
        return Err(invalid(format!(
            "{at} has more than {MANIFEST_PURPOSE_TRANSLATIONS} translations"
        )));
    }
    let mut seen = HashSet::new();
    for (tag, sentence) in translations {
        if !is_language_tag(tag) {
            return Err(invalid(format!(
                "{at}: '{tag}' is not a language tag of RFC 5646 of up to \
                 {MANIFEST_LANGUAGE_TAG} characters"
            )));
        }
        let lower = tag.to_ascii_lowercase();
        if lower == "en" {
            return Err(invalid(format!(
                "{at}: the English sentence belongs in purpose, not under the tag '{tag}'"
            )));
        }
        if !seen.insert(lower) {
            return Err(invalid(format!("{at}: the tag '{tag}' appears twice")));
        }
        if !is_one_line(Some(sentence), MANIFEST_PURPOSE) {
            return Err(invalid(format!(
                "{at}: the {tag} sentence is not one line of 1 to {MANIFEST_PURPOSE} bytes"
            )));
        }
    }
    Ok(())
}

/// Checks the entries of `takes` or `sends`, the list `field` (section 4).
fn check_types(entries: &[Value], field: &str, max: usize) -> Result<(), Error> {
    if entries.len() > max {
        return Err(invalid(format!("{field} has more than {max} entries")));
    }
    let mut names = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let at = format!("{field}[{i}]");
        let name = match entry.field("type") {
            Some(Value::String(name)) if is_full_name(name) => name,
            _ => {
                return Err(invalid(format!(
                    "{at}.type is not an Avro full name of up to {MANIFEST_FULL_NAME} bytes"
                )));
            }
        };
        if !names.insert(name.as_str()) {
            return Err(invalid(format!("{at}.type {name} appears twice")));
        }
        let min = integer(entry.field("min_version")).unwrap_or(0);
        if min < 1 {
            return Err(invalid(format!("{at}.min_version is below 1")));
        }
        if integer(entry.field("max_version")).is_some_and(|max| max < min) {
            return Err(invalid(format!("{at}.max_version is below min_version")));
        }
        if field == "takes" {
            check_purpose(entry, &at)?;
        }
    }
    Ok(())
}

/// Decodes the body of a `MANIFEST` carried in an envelope of `envelope_format` and
/// checks that it is valid (section 4); the manifest is an `axt.Manifest` value.
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] for a body that is no `axt.Manifest`, and
/// [`ErrorCode::ManifestInvalid`] for one that is not valid.
pub(crate) fn check_manifest(body: &[u8], envelope_format: i64) -> Result<Value, Error> {
    if body.len() > MANIFEST_BODY {
        return Err(invalid(format!(
            "body of {} bytes, above {MANIFEST_BODY}",
            body.len()
        )));
    }
    let manifest = envelope::decode_body(Kind::Manifest, body)?;
    if integer(manifest.field("revision")).is_none_or(|r| r < 1) {
        return Err(invalid("revision is below 1"));
    }
    if !is_one_line(manifest.field("app_name"), MANIFEST_APP_NAME) {
        return Err(invalid(format!(
            "app_name is not one line of 1 to {MANIFEST_APP_NAME} bytes"
        )));
    }
    let app_url = manifest.field("app_url");
    if app_url.is_some_and(|u| *u != Value::Null) && !is_https_url(app_url, MANIFEST_APP_URL, false)
    {
        return Err(invalid(format!(
            "app_url is not an absolute https URL of up to {MANIFEST_APP_URL} bytes"
        )));
    }
    let formats: Vec<Option<i64>> = items(manifest.field("formats"))
        .iter()
        .map(|f| integer(Some(f)))
        .collect();
    let distinct: HashSet<_> = formats.iter().collect();
    if formats.is_empty()
        || formats.len() > MANIFEST_FORMATS
        || distinct.len() != formats.len()
        || formats.iter().any(|f| f.is_none_or(|f| f < 1))
    {
        return Err(invalid(format!(
            "formats is not 1 to {MANIFEST_FORMATS} distinct formats of at least 1"
        )));
    }
    if !formats.contains(&Some(envelope_format)) {
        return Err(invalid(
            "formats lacks the format of the envelope that carries the manifest",
        ));
    }
    check_types(items(manifest.field("takes")), "takes", MANIFEST_TAKES)?;
    if let Some(any_type) = manifest.field("any_type").filter(|a| **a != Value::Null) {
        check_purpose(any_type, "any_type")?;
    }
    if let Some(sends) = manifest.field("sends").filter(|s| **s != Value::Null) {
        check_types(items(Some(sends)), "sends", MANIFEST_SENDS)?;
    }
    let key = manifest
        .field("encryption_key")
        .filter(|k| **k != Value::Null);
    let relay = manifest.field("relay").filter(|r| **r != Value::Null);
    if key.is_some() != relay.is_some() {
        return Err(invalid(
            "relay and encryption_key are not both present or both null",
        ));
    }
    if let Some(key) = key {
        let small = match key {
            Value::Fixed(key) => sealing::is_small_order_encryption_key(key),
            _ => true,
        };
        if small {
            return Err(invalid("encryption_key is an X25519 key of small order"));
        }
    }
    if let Some(relay) = relay
        && !is_https_url(relay.field("url"), TRANSPORTS_RELAY_URL, true)
    {
        return Err(invalid(format!(
            "relay.url is not an absolute https base URL of up to {TRANSPORTS_RELAY_URL} bytes"
        )));
    }
    Ok(manifest)
}

/// The version of a writer schema: its `axt.version`, or 1 without one that is an
/// integer of at least 1 (section 3.4).
pub(crate) fn schema_version(schema: &Json) -> i64 {
    schema
        .get("axt.version")
        .and_then(Json::as_i64)
        .filter(|v| *v >= 1)
        .unwrap_or(1)
}

/// Whether a type fits a manifest, and the purpose sentence shown for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fit {
    /// Whether the manifest takes the type in the version of its schema.
    pub(crate) fits: bool,
    /// The purpose sentence in the user's language, or English; `None` when the type
    /// does not fit.
    pub(crate) purpose: Option<String>,
}

/// Whether the type of `schema_text` fits `manifest`, a valid manifest, and the purpose
/// sentence for a user with the language priority list `languages` (sections 3.6 and
/// 5.2).
///
/// # Errors
///
/// [`ErrorCode::DoesNotResolve`] for a text that is not an Avro schema.
pub(crate) fn fit(manifest: &Value, schema_text: &str, languages: &[String]) -> Result<Fit, Error> {
    let no_fit = Fit {
        fits: false,
        purpose: None,
    };
    let name = Schema::parse(schema_text)?.type_name();
    let version = serde_json::from_str::<Json>(schema_text)
        .map(|json| schema_version(&json))
        .unwrap_or(1);
    // A valid manifest names a type once; like the reference, the last entry counts.
    let take = items(manifest.field("takes"))
        .iter()
        .rfind(|t| matches!(t.field("type"), Some(Value::String(n)) if *n == name));
    let entry = if let Some(take) = take {
        let min = integer(take.field("min_version")).unwrap_or(1);
        let max = integer(take.field("max_version"));
        if version < min || max.is_some_and(|max| version > max) {
            return Ok(no_fit);
        }
        take
    } else {
        match manifest.field("any_type") {
            Some(any_type) if *any_type != Value::Null => any_type,
            _ => return Ok(no_fit),
        }
    };
    let translations = translations(entry);
    let mut tags: Vec<&str> = translations
        .into_iter()
        .flat_map(BTreeMap::keys)
        .map(String::as_str)
        .collect();
    tags.push("en");
    let chosen = lookup(languages, &tags)
        .filter(|tag| *tag != "en")
        .and_then(|tag| translations.and_then(|t| t.get(tag)));
    let purpose = match chosen.or_else(|| entry.field("purpose")) {
        Some(Value::String(purpose)) => Some(purpose.clone()),
        _ => None,
    };
    Ok(Fit {
        fits: true,
        purpose,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::schemas::axt_schema;
    use crate::value::hex;

    fn take(ty: &str) -> Json {
        json!({
            "type": ty,
            "min_version": 1,
            "max_version": null,
            "purpose": "A Pet becomes an animal.",
            "purpose_translations": {},
        })
    }

    fn manifest_of(changes: Json) -> Json {
        let mut manifest = json!({
            "revision": 1,
            "app_name": "cat-a-log",
            "app_url": null,
            "formats": [1],
            "takes": [take("axt.example.v1.Pet")],
            "any_type": null,
            "sends": null,
            "encryption_key": null,
            "relay": null,
        });
        for (name, value) in changes.as_object().unwrap() {
            manifest[name] = value.clone();
        }
        manifest
    }

    fn body_of(manifest: &Json) -> Vec<u8> {
        let schema = axt_schema("axt.Manifest").unwrap();
        schema
            .encode_single_object(&schema.datum_of_json(manifest).unwrap())
            .unwrap()
    }

    fn valid_key() -> String {
        hex(&x25519_dalek::x25519(
            [7; 32],
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }

    fn take_with(ty: &str, member: &str, value: Json) -> Json {
        let mut entry = take(ty);
        entry[member] = value;
        entry
    }

    #[test]
    fn a_valid_manifest_decodes() {
        let manifest = check_manifest(
            &body_of(&manifest_of(json!({
                "app_url": "https://example.org/app",
                "any_type": {
                    "purpose": "Any other type becomes a Note.",
                    "purpose_translations": {},
                },
                "sends": [{
                    "type": "axt.example.v1.Pet",
                    "min_version": 1,
                    "max_version": 1,
                    "proposals": false,
                }],
                "encryption_key": valid_key(),
                "relay": {"url": "https://relay.example.org/axt/", "mailbox": hex(&[0; 32])},
                "takes": [take_with(
                    "axt.example.v1.Pet",
                    "purpose_translations",
                    json!({"de": "Ein Tier.", "pt-BR": "Um animal."}),
                )],
            }))),
            1,
        )
        .unwrap();
        assert_eq!(
            manifest.field("app_name"),
            Some(&Value::String("cat-a-log".into()))
        );
    }

    #[test]
    fn every_rule_of_section_4_rejects() {
        let key = valid_key();
        let relay = |url: &str| json!({"url": url, "mailbox": hex(&[0; 32])});
        let send =
            json!({"type": "a.B", "min_version": 1, "max_version": null, "proposals": false});
        let many: serde_json::Map<String, Json> = (0..65)
            .map(|i| (format!("de-{}", 1000 + i), json!("x")))
            .collect();
        let cases = [
            json!({"revision": 0}),
            json!({"app_name": ""}),
            json!({"app_name": "two\nlines"}),
            json!({"app_name": "sep\u{2028}"}),
            json!({"app_name": "x".repeat(257)}),
            json!({"app_url": "http://example.org"}),
            json!({"app_url": "https://exa mple.org"}),
            json!({"app_url": "mailto:x"}),
            json!({"formats": []}),
            json!({"formats": [1, 1]}),
            json!({"formats": [0, 1]}),
            json!({"formats": [2]}),
            json!({"takes": [take("9bad")]}),
            json!({"takes": [take("a.B"), take("a.B")]}),
            json!({"takes": [take_with("a.B", "min_version", json!(0))]}),
            json!({"takes": [{
                "type": "a.B", "min_version": 2, "max_version": 1,
                "purpose": "x", "purpose_translations": {},
            }]}),
            json!({"takes": [take_with("a.B", "purpose", json!(""))]}),
            json!({"takes": [take_with("a.B", "purpose_translations", json!({"de_DE": "x"}))]}),
            json!({"takes": [take_with("a.B", "purpose_translations", json!({"EN": "x"}))]}),
            json!({"takes": [take_with("a.B", "purpose_translations", json!({"de": "x", "DE": "y"}))]}),
            json!({"takes": [take_with("a.B", "purpose_translations", json!({"de": ""}))]}),
            json!({"takes": [take_with("a.B", "purpose_translations", json!({"x-old": "x"}))]}),
            json!({"takes": [take_with("a.B", "purpose_translations", Json::Object(many))]}),
            json!({"takes": (0..257).map(|i| take(&format!("a.B{i}"))).collect::<Vec<_>>()}),
            json!({"any_type": {"purpose": "", "purpose_translations": {}}}),
            json!({"sends": [send.clone(), send]}),
            json!({"encryption_key": key}),
            json!({"encryption_key": hex(&[0; 32]), "relay": relay("https://r.org/")}),
            json!({"encryption_key": key, "relay": relay("https://r.org/x")}),
            json!({"encryption_key": key, "relay": relay("https://u@r.org/")}),
            json!({"encryption_key": key, "relay": relay("https://r.org/?q")}),
        ];
        for changes in cases {
            let result = check_manifest(&body_of(&manifest_of(changes.clone())), 1);
            assert_eq!(
                result.unwrap_err().code(),
                Some(ErrorCode::ManifestInvalid),
                "{changes}"
            );
        }
        let code = |body: &[u8]| check_manifest(body, 1).unwrap_err().code();
        assert_eq!(
            code(&vec![0; MANIFEST_BODY + 1]),
            Some(ErrorCode::ManifestInvalid)
        );
        assert_eq!(code(&[0; 3]), Some(ErrorCode::InvalidMessage));
    }

    #[test]
    fn https_urls_and_base_urls() {
        let url = |u: &str, base: bool| is_https_url(Some(&Value::String(u.into())), 256, base);
        for u in [
            "https://x.org",
            "HTTPS://x.org/a?b#c",
            "https://x:443",
            "https://[::1]/",
        ] {
            assert!(url(u, false), "{u}");
        }
        for u in [
            "https:x",
            "https://",
            "https://u@/",
            "https://x:abc/",
            "https://x.org/\u{7f}",
        ] {
            assert!(!url(u, false), "{u}");
        }
        assert!(url("https://relay.example.org/axt/", true));
        for u in [
            "https://r.org",
            "https://r.org/x",
            "https://r.org/#f",
            "https://r.org/?",
        ] {
            assert!(!url(u, true), "{u}");
        }
    }

    #[test]
    fn the_language_tag_pattern_compiles() {
        assert!(LANGTAG.is_some());
    }

    #[test]
    fn language_tags_have_the_langtag_form() {
        for tag in [
            "de",
            "de-AT",
            "zh-Hant-TW",
            "sl-rozaj-biske",
            "en-x-private",
        ] {
            assert!(is_language_tag(tag), "{tag}");
        }
        for tag in ["", "d", "de_AT", "de-", "toolongtag", "de-AT\n", "x-a001"] {
            assert!(!is_language_tag(tag), "{tag}");
        }
    }

    #[test]
    fn language_tags_of_the_reference_tests() {
        for tag in ["pt-BR", "de-CH-1901", "en-a-bbb-x-a", "es-419"] {
            assert!(is_language_tag(tag), "{tag}");
        }
        for tag in ["i-klingon", &"a".repeat(36)] {
            assert!(!is_language_tag(tag), "{tag}");
        }
    }

    fn fit_manifest() -> Value {
        let manifest = manifest_of(json!({
            "takes": [{
                "type": "axt.example.v1.Pet",
                "min_version": 2,
                "max_version": 3,
                "purpose": "A Pet becomes an animal.",
                "purpose_translations": {"de": "Ein Tier."},
            }],
            "any_type": {
                "purpose": "Any other type.",
                "purpose_translations": {"fr": "Tout autre."},
            },
        }));
        check_manifest(&body_of(&manifest), 1).unwrap()
    }

    fn schema(name: &str, version: Option<Json>) -> String {
        let mut schema = json!({
            "type": "record",
            "name": name,
            "namespace": "axt.example.v1",
            "fields": [],
        });
        if let Some(version) = version {
            schema["axt.version"] = version;
        }
        schema.to_string()
    }

    fn fits(manifest: &Value, schema: &str, languages: &[&str]) -> (bool, Option<String>) {
        let languages: Vec<String> = languages.iter().map(|l| (*l).to_owned()).collect();
        let result = fit(manifest, schema, &languages).unwrap();
        (result.fits, result.purpose)
    }

    #[test]
    fn a_type_in_takes_fits_in_its_range() {
        let m = fit_manifest();
        let yes = |p: &str| (true, Some(p.to_owned()));
        assert_eq!(
            fits(&m, &schema("Pet", Some(json!(2))), &["de-AT"]),
            yes("Ein Tier.")
        );
        assert_eq!(
            fits(&m, &schema("Pet", Some(json!(3))), &["en"]),
            yes("A Pet becomes an animal.")
        );
        assert_eq!(
            fits(&m, &schema("Pet", Some(json!(4))), &["de"]),
            (false, None)
        );
        assert_eq!(fits(&m, &schema("Pet", None), &["de"]), (false, None));
        assert_eq!(
            fits(&m, &schema("Pet", Some(json!("two"))), &["de"]),
            (false, None)
        );
    }

    #[test]
    fn any_other_type_fits_through_any_type_or_not_at_all() {
        let m = fit_manifest();
        assert_eq!(
            fits(&m, &schema("Note", Some(json!(1))), &["fr"]),
            (true, Some("Tout autre.".to_owned()))
        );
        let plain = check_manifest(&body_of(&manifest_of(json!({}))), 1).unwrap();
        assert_eq!(
            fits(&plain, &schema("Note", Some(json!(1))), &["fr"]),
            (false, None)
        );
        assert_eq!(
            fits(&m, "\"string\"", &[]),
            (true, Some("Any other type.".to_owned()))
        );
        let not_a_schema = fit(&m, "{", &[]).unwrap_err().code();
        assert_eq!(not_a_schema, Some(ErrorCode::DoesNotResolve));
    }

    #[test]
    fn the_version_of_a_schema() {
        assert_eq!(schema_version(&json!({"axt.version": 5})), 5);
        assert_eq!(schema_version(&json!({"axt.version": 0})), 1);
        assert_eq!(schema_version(&json!({"axt.version": 2.5})), 1);
        assert_eq!(schema_version(&json!({})), 1);
        assert_eq!(schema_version(&json!("string")), 1);
    }

    #[test]
    fn lookup_falls_back_by_cutting_subtags() {
        let languages = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let tags = ["de", "en", "fr-CH"];
        assert_eq!(lookup(&languages(&["de-AT", "en"]), &tags), Some("de"));
        assert_eq!(lookup(&languages(&["fr-ch"]), &tags), Some("fr-CH"));
        assert_eq!(lookup(&languages(&["fr", "*"]), &tags), None);
        assert_eq!(lookup(&languages(&["de-x-a-b"]), &tags), Some("de"));
        let tags = ["de", "pt-BR", "en", "zh-Hant"];
        assert_eq!(lookup(&languages(&["fr-CH", "fr"]), &tags), None);
        assert_eq!(lookup(&languages(&["*", "PT-br"]), &tags), Some("pt-BR"));
        assert_eq!(lookup(&languages(&["zh-Hant-x-a"]), &tags), Some("zh-Hant"));
    }
}
