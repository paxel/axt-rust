//! Records and their ids (AXT `spec/records.md`, section 2).

/// The key of the record id `id`: the UUID in lower case; `None` for an id that is not a
/// UUID in text form, or the nil or the max UUID.
pub(crate) fn record_key(id: &str) -> Option<String> {
    let is_uuid = id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    let key = id.to_ascii_lowercase();
    (is_uuid
        && key != "00000000-0000-0000-0000-000000000000"
        && key != "ffffffff-ffff-ffff-ffff-ffffffffffff")
        .then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_key_is_a_uuid_in_lower_case() {
        assert_eq!(
            record_key("3E8A5B14-7c29-4d6e-a0f3-1b9d2c7e5a46").as_deref(),
            Some("3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46")
        );
        for bad in [
            "",
            "3e8a5b147c294d6ea0f31b9d2c7e5a46",
            "3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a4g",
            "{3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a4}",
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        ] {
            assert_eq!(record_key(bad), None, "{bad}");
        }
    }
}
