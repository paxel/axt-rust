//! The validity of the time types `axt.Date`, `axt.Time`, `axt.DateTime` and
//! `axt.Duration` (AXT `spec/time.md`, sections 4 to 7.1). None of the rules needs a time
//! zone database.

use crate::value::Value;

/// The full names of the time types.
pub(crate) const TIME_TYPES: [&str; 4] = ["axt.Date", "axt.Time", "axt.DateTime", "axt.Duration"];

/// Whether `value`, a decoded record of the time type `full_name`, is valid; false for a
/// name that is not a time type.
pub(crate) fn is_valid_time_value(full_name: &str, value: &Value) -> bool {
    match full_name {
        "axt.Date" => valid_date(value),
        "axt.Time" => valid_time(value),
        "axt.DateTime" => valid_date_time(value),
        "axt.Duration" => valid_duration(value),
        _ => false,
    }
}

/// The integer of the field `name`; `None` for `null` or another value.
fn int(value: &Value, name: &str) -> Option<i64> {
    match value.field(name) {
        Some(Value::Int(i)) => Some(i64::from(*i)),
        Some(Value::Long(l)) => Some(*l),
        _ => None,
    }
}

/// Whether the field `name` is `null`.
fn is_null(value: &Value, name: &str) -> bool {
    matches!(value.field(name), Some(Value::Null))
}

/// Whether the field `name` is an integer from `low` to `high`.
fn within(value: &Value, name: &str, low: i64, high: i64) -> bool {
    int(value, name).is_some_and(|i| (low..=high).contains(&i))
}

fn is_leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// The days of `month` in `year`, or of a leap year when `year` is `None`.
pub(crate) fn days_in_month(year: Option<i64>, month: i64) -> i64 {
    match month {
        2 if year.is_none_or(is_leap) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn valid_date(v: &Value) -> bool {
    let (year, month, day) = (int(v, "year"), int(v, "month"), int(v, "day"));
    let given = |name, i: Option<i64>| i.is_some() || !is_null(v, name);
    let (has_year, has_month, has_day) = (
        given("year", year),
        given("month", month),
        given("day", day),
    );
    if !has_year && !has_month && !has_day {
        return false;
    }
    if !has_month && has_day {
        return false;
    }
    if has_year && !within(v, "year", 1, 9999) {
        return false;
    }
    if has_month && !within(v, "month", 1, 12) {
        return false;
    }
    match (has_day, month) {
        (true, Some(month)) => within(v, "day", 1, days_in_month(year, month)),
        (true, None) => false,
        (false, _) => true,
    }
}

fn valid_time(v: &Value) -> bool {
    within(v, "hour", 0, 23)
        && within(v, "minute", 0, 59)
        && within(v, "second", 0, 59)
        && within(v, "millisecond", 0, 999)
}

/// Whether `zone` has the syntax of a zone name (time.md, section 6.1).
fn is_zone_name(zone: &str) -> bool {
    zone.len() <= crate::limits::TIME_ZONE
        && zone.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
                && part != "."
                && part != ".."
                && !part.starts_with('-')
        })
}

/// The days from 1970-01-01 to `year`-`month`-`day` of the proleptic Gregorian calendar,
/// for a year from 1 to 9999.
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = y.div_euclid(400);
    let year_of_era = y.checked_sub(era.checked_mul(400)?)?;
    let shifted = if month > 2 {
        month.checked_sub(3)?
    } else {
        month.checked_add(9)?
    };
    let day_of_year = 153i64
        .checked_mul(shifted)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era.checked_div(4)?)?
        .checked_sub(year_of_era.checked_div(100)?)?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn valid_date_time(v: &Value) -> bool {
    let (Some(year), Some(month)) = (int(v, "year"), int(v, "month")) else {
        return false;
    };
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return false;
    }
    if !within(v, "day", 1, days_in_month(Some(year), month)) || !valid_time(v) {
        return false;
    }
    let zone = v.field("zone");
    let offset = int(v, "offset_seconds");
    let instant = int(v, "instant_ms");
    if is_null(v, "zone") && is_null(v, "offset_seconds") && is_null(v, "instant_ms") {
        return true;
    }
    let (Some(Value::String(zone)), Some(offset), Some(instant)) = (zone, offset, instant) else {
        return false;
    };
    if !is_zone_name(zone) || !(-64_800..=64_800).contains(&offset) {
        return false;
    }
    let part = |name| int(v, name).unwrap_or_default();
    let wall_clock = days_from_civil(year, month, part("day")).and_then(|days| {
        days.checked_mul(86_400_000)?
            .checked_add(part("hour").checked_mul(3_600_000)?)?
            .checked_add(part("minute").checked_mul(60_000)?)?
            .checked_add(part("second").checked_mul(1000)?)?
            .checked_add(part("millisecond"))?
            .checked_sub(offset.checked_mul(1000)?)
    });
    wall_clock == Some(instant)
}

fn valid_duration(v: &Value) -> bool {
    let (Some(months), Some(days), Some(millis)) =
        (int(v, "months"), int(v, "days"), int(v, "millis"))
    else {
        return false;
    };
    let parts = [months, days, millis];
    parts.iter().all(|&p| p >= 0) || parts.iter().all(|&p| p <= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fields: &[(&str, Value)]) -> Value {
        Value::Record(
            fields
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.clone()))
                .collect(),
        )
    }

    fn date(year: Option<i32>, month: Option<i32>, day: Option<i32>) -> Value {
        let v = |i: Option<i32>| i.map_or(Value::Null, Value::Int);
        record(&[("year", v(year)), ("month", v(month)), ("day", v(day))])
    }

    fn date_time(day: i32, zone: Option<&str>, offset: Option<i32>, instant: Option<i64>) -> Value {
        record(&[
            ("year", Value::Int(2026)),
            ("month", Value::Int(3)),
            ("day", Value::Int(day)),
            ("hour", Value::Int(10)),
            ("minute", Value::Int(0)),
            ("second", Value::Int(0)),
            ("millisecond", Value::Int(0)),
            (
                "zone",
                zone.map_or(Value::Null, |z| Value::String(z.into())),
            ),
            ("offset_seconds", offset.map_or(Value::Null, Value::Int)),
            ("instant_ms", instant.map_or(Value::Null, Value::Long)),
        ])
    }

    #[test]
    fn a_date_may_leave_out_parts_but_not_the_month_of_a_day() {
        assert!(is_valid_time_value(
            "axt.Date",
            &date(Some(2024), Some(2), Some(29))
        ));
        assert!(!is_valid_time_value(
            "axt.Date",
            &date(Some(2026), Some(2), Some(29))
        ));
        assert!(is_valid_time_value(
            "axt.Date",
            &date(None, Some(2), Some(29))
        ));
        assert!(!is_valid_time_value(
            "axt.Date",
            &date(Some(2026), None, Some(1))
        ));
        assert!(!is_valid_time_value("axt.Date", &date(None, None, None)));
        assert!(!is_valid_time_value("axt.Date", &date(Some(0), None, None)));
        assert!(!is_valid_time_value(
            "axt.Date",
            &date(None, Some(13), None)
        ));
    }

    #[test]
    fn a_date_time_with_a_zone_has_the_instant_of_its_offset() {
        // 2026-03-01T10:00 at +01:00 is 09:00 UTC.
        let instant = 1_772_355_600_000;
        assert!(is_valid_time_value(
            "axt.DateTime",
            &date_time(1, None, None, None)
        ));
        assert!(is_valid_time_value(
            "axt.DateTime",
            &date_time(1, Some("Europe/Berlin"), Some(3600), Some(instant))
        ));
        assert!(!is_valid_time_value(
            "axt.DateTime",
            &date_time(1, Some("Europe/Berlin"), Some(3600), Some(instant + 1))
        ));
        assert!(!is_valid_time_value(
            "axt.DateTime",
            &date_time(1, Some("Europe/Berlin"), None, Some(instant))
        ));
        assert!(!is_valid_time_value(
            "axt.DateTime",
            &date_time(1, Some("../x"), Some(3600), Some(instant))
        ));
        assert!(!is_valid_time_value(
            "axt.DateTime",
            &date_time(1, Some("Europe/Berlin"), Some(64_801), Some(instant))
        ));
        assert!(!is_valid_time_value(
            "axt.DateTime",
            &date_time(32, None, None, None)
        ));
    }

    #[test]
    fn a_date_keeps_the_leap_years_and_the_days_of_its_month() {
        let valid = |y, m, d| is_valid_time_value("axt.Date", &date(y, m, d));
        assert!(valid(Some(2026), Some(11), Some(24)));
        assert!(valid(Some(2027), Some(3), None));
        assert!(valid(Some(2019), None, None));
        assert!(valid(None, Some(5), Some(3)));
        assert!(!valid(Some(1900), Some(2), Some(29)));
        assert!(valid(Some(2000), Some(2), Some(29)));
        assert!(!valid(Some(0), Some(1), Some(1)));
        assert!(!valid(Some(2026), Some(4), Some(31)));
    }

    #[test]
    fn zone_names_keep_the_syntax_of_the_database() {
        assert!(is_zone_name("America/Argentina/Buenos_Aires"));
        assert!(is_zone_name("Etc/GMT+1"));
        assert!(is_zone_name("UTC"));
        assert!(!is_zone_name(""));
        assert!(!is_zone_name("Europe//Berlin"));
        assert!(!is_zone_name("."));
        assert!(!is_zone_name("-x"));
        assert!(!is_zone_name("Europe/Berlin "));
        assert!(!is_zone_name(&"a".repeat(65)));
    }

    #[test]
    fn days_from_civil_counts_from_1970_01_01() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 3, 1), Some(11017));
        assert_eq!(days_from_civil(1, 1, 1), Some(-719_162));
        assert_eq!(days_from_civil(1969, 12, 31), Some(-1));
    }

    #[test]
    fn a_time_and_a_duration_keep_their_ranges_and_sign() {
        let time = |h| {
            record(&[
                ("hour", Value::Int(h)),
                ("minute", Value::Int(0)),
                ("second", Value::Int(0)),
                ("millisecond", Value::Int(0)),
            ])
        };
        assert!(is_valid_time_value("axt.Time", &time(23)));
        assert!(!is_valid_time_value("axt.Time", &time(24)));
        let mut late = time(0);
        if let Value::Record(fields) = &mut late {
            fields[2].1 = Value::Int(60);
        }
        assert!(!is_valid_time_value("axt.Time", &late));
        let mut early = time(0);
        if let Value::Record(fields) = &mut early {
            fields[3].1 = Value::Int(-1);
        }
        assert!(!is_valid_time_value("axt.Time", &early));
        let duration = |m, d, ms| {
            record(&[
                ("months", Value::Int(m)),
                ("days", Value::Int(d)),
                ("millis", Value::Long(ms)),
            ])
        };
        assert!(is_valid_time_value("axt.Duration", &duration(-1, 0, -5)));
        assert!(is_valid_time_value("axt.Duration", &duration(1, 2, 3)));
        assert!(is_valid_time_value("axt.Duration", &duration(0, 0, 0)));
        assert!(!is_valid_time_value("axt.Duration", &duration(1, -1, 0)));
        assert!(!is_valid_time_value("axt.Other", &duration(1, 1, 1)));
    }
}
