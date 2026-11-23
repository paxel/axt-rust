//! Language tags and the choice of a translation (AXT `spec/manifest.md`, section 3, and
//! `spec/metadata.md`, section 4.2).

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::limits::MANIFEST_LANGUAGE_TAG;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn lookup_falls_back_by_cutting_subtags() {
        let languages = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let tags = ["de", "en", "fr-CH"];
        assert_eq!(lookup(&languages(&["de-AT", "en"]), &tags), Some("de"));
        assert_eq!(lookup(&languages(&["fr-ch"]), &tags), Some("fr-CH"));
        assert_eq!(lookup(&languages(&["fr", "*"]), &tags), None);
        assert_eq!(lookup(&languages(&["de-x-a-b"]), &tags), Some("de"));
    }
}
