//! Zone rules, and reading and adding to an `axt.DateTime` with them (AXT `spec/time.md`,
//! sections 6.3, 6.4 and 7.2).
//!
//! Only the conformance adapter reads a value with zone rules, so the module is behind the
//! feature `conformance`.

use jiff::Timestamp;
use jiff::tz::TimeZoneDatabase;

use crate::time_values::{days_from_civil, days_in_month};

/// The offsets of the zones of a time zone database.
pub(crate) trait ZoneRules {
    /// The offset in seconds of `zone` at `instant_ms`, or `None` when the rules do not know
    /// the zone.
    fn offset_at(&self, zone: &str, instant_ms: i64) -> Option<i64>;
}

/// The zone rules of the IANA time zone database that `jiff` bundles into the binary, so
/// every platform reads the same rules; neither the system's database nor `TZ` is read.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TzdbZoneRules;

impl ZoneRules for TzdbZoneRules {
    fn offset_at(&self, zone: &str, instant_ms: i64) -> Option<i64> {
        let time_zone = TimeZoneDatabase::bundled().get(zone).ok()?;
        // jiff finds a name without regard to case and knows `Etc/Unknown`, which the
        // database does not have; a zone is known only by its exact name.
        if time_zone.is_unknown() || time_zone.iana_name() != Some(zone) {
            return None;
        }
        // An instant beyond what jiff represents takes the offset at its nearest end, so a
        // known zone never reads as unknown.
        let instant = Timestamp::from_millisecond(instant_ms).unwrap_or(if instant_ms < 0 {
            Timestamp::MIN
        } else {
            Timestamp::MAX
        });
        Some(i64::from(time_zone.to_offset(instant).seconds()))
    }
}

const DAY_MS: i64 = 86_400_000;

/// The wall clock of an `axt.DateTime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WallClock {
    pub(crate) year: i64,
    pub(crate) month: i64,
    pub(crate) day: i64,
    pub(crate) hour: i64,
    pub(crate) minute: i64,
    pub(crate) second: i64,
    pub(crate) millisecond: i64,
}

/// The zone of an `axt.DateTime`, with the offset and the instant of its wall clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Zoned {
    pub(crate) zone: String,
    pub(crate) offset_seconds: i64,
    pub(crate) instant_ms: i64,
}

/// A value of `axt.DateTime`: a wall clock, floating or in a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DateTime {
    pub(crate) wall: WallClock,
    pub(crate) zoned: Option<Zoned>,
}

/// A value of `axt.Duration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Duration {
    pub(crate) months: i64,
    pub(crate) days: i64,
    pub(crate) millis: i64,
}

/// The anchor of a field: what a receiver keeps when its zone rules differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Anchor {
    Local,
    Instant,
}

/// The milliseconds from 1970-01-01T00:00 to `wall`, counted as if it were UTC.
pub(crate) fn wall_clock_ms(wall: &WallClock) -> Option<i64> {
    days_from_civil(wall.year, wall.month, wall.day)?
        .checked_mul(DAY_MS)?
        .checked_add(wall.hour.checked_mul(3_600_000)?)?
        .checked_add(wall.minute.checked_mul(60_000)?)?
        .checked_add(wall.second.checked_mul(1000)?)?
        .checked_add(wall.millisecond)
}

/// The wall clock of `ms` milliseconds from 1970-01-01T00:00.
pub(crate) fn wall_clock_of(ms: i64) -> Option<WallClock> {
    let rest = ms.rem_euclid(DAY_MS);
    let (year, month, day) = civil_from_days(ms.div_euclid(DAY_MS))?;
    Some(WallClock {
        year,
        month,
        day,
        hour: rest.checked_div(3_600_000)?,
        minute: rest.checked_div(60_000)?.checked_rem(60)?,
        second: rest.checked_div(1000)?.checked_rem(60)?,
        millisecond: rest.checked_rem(1000)?,
    })
}

/// The date `days` days after 1970-01-01 in the proleptic Gregorian calendar.
pub(crate) fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = day_of_era
        .checked_sub(day_of_era.checked_div(1460)?)?
        .checked_add(day_of_era.checked_div(36_524)?)?
        .checked_sub(day_of_era.checked_div(146_096)?)?
        .checked_div(365)?;
    let day_of_year = day_of_era.checked_sub(
        year_of_era
            .checked_mul(365)?
            .checked_add(year_of_era.checked_div(4)?)?
            .checked_sub(year_of_era.checked_div(100)?)?,
    )?;
    let mp = day_of_year
        .checked_mul(5)?
        .checked_add(2)?
        .checked_div(153)?;
    let day = day_of_year
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let month = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let year = year_of_era
        .checked_add(era.checked_mul(400)?)?
        .checked_add(i64::from(month <= 2))?;
    Some((year, month, day))
}

/// A zoned value with the wall clock of `wall_ms`, `offset` and the instant they give.
fn zoned(zone: &str, wall_ms: i64, offset: i64) -> Option<DateTime> {
    Some(DateTime {
        wall: wall_clock_of(wall_ms)?,
        zoned: Some(Zoned {
            zone: zone.to_owned(),
            offset_seconds: offset,
            instant_ms: wall_ms.checked_sub(offset.checked_mul(1000)?)?,
        }),
    })
}

/// Places the wall clock `wall_ms` in `zone`, which `rules` know, with `preferred` as the
/// preferred offset (section 6.3): the offset given if the wall clock occurs with it;
/// otherwise the one it occurs with; in an overlap the larger; in a gap the wall clock moved
/// later by the gap.
pub(crate) fn place_wall_clock(
    rules: &impl ZoneRules,
    zone: &str,
    wall_ms: i64,
    preferred: Option<i64>,
) -> Option<DateTime> {
    let offset_at = |instant: i64| rules.offset_at(zone, instant);
    let before = offset_at(wall_ms.checked_sub(DAY_MS)?)?;
    let after = offset_at(wall_ms.checked_add(DAY_MS)?)?;
    let mut occurs = Vec::new();
    for offset in [before, after] {
        let instant = wall_ms.checked_sub(offset.checked_mul(1000)?)?;
        if offset_at(instant) == Some(offset) && !occurs.contains(&offset) {
            occurs.push(offset);
        }
    }
    let Some(&largest) = occurs.iter().max() else {
        let gap = after.checked_sub(before)?.checked_mul(1000)?;
        return zoned(zone, wall_ms.checked_add(gap)?, after);
    };
    let offset = preferred.filter(|p| occurs.contains(p)).unwrap_or(largest);
    zoned(zone, wall_ms, offset)
}

/// `date_time` as a receiver with `rules` takes it for a field with `anchor` (section 6.4);
/// `None` only when the arithmetic leaves the range of `i64`.
pub(crate) fn resolve_date_time(
    rules: &impl ZoneRules,
    date_time: &DateTime,
    anchor: Anchor,
) -> Option<DateTime> {
    let Some(z) = &date_time.zoned else {
        return Some(date_time.clone());
    };
    let Some(offset) = rules.offset_at(&z.zone, z.instant_ms) else {
        return Some(date_time.clone());
    };
    if offset == z.offset_seconds {
        return Some(date_time.clone());
    }
    match anchor {
        Anchor::Local => place_wall_clock(rules, &z.zone, wall_clock_ms(&date_time.wall)?, None),
        Anchor::Instant => zoned(
            &z.zone,
            z.instant_ms.checked_add(offset.checked_mul(1000)?)?,
            offset,
        ),
    }
}

/// `date_time` plus `duration` (section 7.2); `None` when the result, or the date after the
/// months or the days, lies outside the years 1 to 9999.
pub(crate) fn add_duration(
    rules: &impl ZoneRules,
    date_time: &DateTime,
    duration: Duration,
) -> Option<DateTime> {
    let wall = &date_time.wall;
    let month_index = wall
        .year
        .checked_mul(12)?
        .checked_add(wall.month)?
        .checked_sub(1)?
        .checked_add(duration.months)?;
    let year = in_years(month_index.div_euclid(12))?;
    let month = month_index.rem_euclid(12).checked_add(1)?;
    let day = wall.day.min(days_in_month(Some(year), month));
    let time_of_day = wall_clock_ms(wall)?.rem_euclid(DAY_MS);
    let wall_ms = days_from_civil(year, month, day)?
        .checked_add(duration.days)?
        .checked_mul(DAY_MS)?
        .checked_add(time_of_day)?;
    in_years(wall_clock_of(wall_ms)?.year)?;
    let result = match &date_time.zoned {
        None => DateTime {
            wall: wall_clock_of(wall_ms.checked_add(duration.millis)?)?,
            zoned: None,
        },
        Some(z) => {
            let known = rules.offset_at(&z.zone, z.instant_ms).is_some();
            let placed = if duration.months == 0 && duration.days == 0 {
                date_time.clone()
            } else if known {
                place_wall_clock(rules, &z.zone, wall_ms, Some(z.offset_seconds))?
            } else {
                zoned(&z.zone, wall_ms, z.offset_seconds)?
            };
            let instant = placed.zoned?.instant_ms.checked_add(duration.millis)?;
            let offset = if known {
                rules.offset_at(&z.zone, instant)?
            } else {
                z.offset_seconds
            };
            zoned(
                &z.zone,
                instant.checked_add(offset.checked_mul(1000)?)?,
                offset,
            )?
        }
    };
    in_years(result.wall.year)?;
    Some(result)
}

/// `year` if it lies in the years 1 to 9999.
fn in_years(year: i64) -> Option<i64> {
    (1..=9999).contains(&year).then_some(year)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: TzdbZoneRules = TzdbZoneRules;

    fn wall(year: i64, month: i64, day: i64, hour: i64, minute: i64) -> WallClock {
        WallClock {
            year,
            month,
            day,
            hour,
            minute,
            second: 0,
            millisecond: 0,
        }
    }

    fn berlin(
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        minute: i64,
        offset: i64,
        instant: i64,
    ) -> DateTime {
        DateTime {
            wall: wall(year, month, day, hour, minute),
            zoned: Some(Zoned {
                zone: "Europe/Berlin".into(),
                offset_seconds: offset,
                instant_ms: instant,
            }),
        }
    }

    fn floating(year: i64, month: i64, day: i64, hour: i64) -> DateTime {
        DateTime {
            wall: wall(year, month, day, hour, 0),
            zoned: None,
        }
    }

    fn duration(months: i64, days: i64, millis: i64) -> Duration {
        Duration {
            months,
            days,
            millis,
        }
    }

    fn with_zone(mut date_time: DateTime, zone: &str) -> DateTime {
        if let Some(z) = &mut date_time.zoned {
            z.zone = zone.into();
        }
        date_time
    }

    #[test]
    fn the_rules_know_berlin_and_not_mars() {
        assert_eq!(
            RULES.offset_at("Europe/Berlin", 1_782_896_400_000),
            Some(7200)
        );
        assert_eq!(RULES.offset_at("Mars/Olympus_Mons", 0), None);
        assert_eq!(RULES.offset_at("UTC", 0), Some(0));
        assert_eq!(RULES.offset_at("Etc/UTC", 0), Some(0));
    }

    #[test]
    fn a_zone_is_known_only_by_its_exact_name() {
        assert_eq!(RULES.offset_at("europe/berlin", 0), None);
        assert_eq!(RULES.offset_at("Etc/Unknown", 0), None);
        assert_eq!(RULES.offset_at("US/Pacific", 0), Some(-28_800));
    }

    #[test]
    fn an_instant_beyond_jiff_takes_the_offset_at_its_end() {
        // 9999-12-31T23:59:59.999 UTC, and an instant far beyond it.
        assert_eq!(
            RULES.offset_at("Europe/Berlin", 253_402_300_799_999),
            Some(3600)
        );
        assert_eq!(RULES.offset_at("Europe/Berlin", i64::MAX), Some(3600));
        assert_eq!(RULES.offset_at("Europe/Berlin", i64::MIN), Some(3208));
    }

    #[test]
    fn civil_dates_and_wall_clocks_round_trip() {
        for ms in [
            0,
            -1,
            1_792_888_200_000,
            -62_135_596_800_000,
            253_402_300_799_999,
        ] {
            let w = wall_clock_of(ms).unwrap();
            assert_eq!(wall_clock_ms(&w), Some(ms), "{w:?}");
        }
        assert_eq!(civil_from_days(0), Some((1970, 1, 1)));
        assert_eq!(civil_from_days(-1), Some((1969, 12, 31)));
    }

    #[test]
    fn in_an_overlap_place_takes_the_preferred_offset_else_the_larger() {
        let w = wall_clock_ms(&wall(2026, 10, 25, 2, 30)).unwrap();
        let instant = |p: Option<DateTime>| p.unwrap().zoned.unwrap().instant_ms;
        assert_eq!(
            instant(place_wall_clock(&RULES, "Europe/Berlin", w, None)),
            1_792_888_200_000
        );
        assert_eq!(
            instant(place_wall_clock(&RULES, "Europe/Berlin", w, Some(3600))),
            1_792_891_800_000
        );
    }

    #[test]
    fn in_a_gap_place_moves_the_wall_clock_later_by_the_gap() {
        let w = wall_clock_ms(&wall(2027, 3, 28, 2, 30)).unwrap();
        let placed = place_wall_clock(&RULES, "Europe/Berlin", w, None).unwrap();
        assert_eq!((placed.wall.hour, placed.wall.minute), (3, 30));
        assert_eq!(placed.zoned.unwrap().offset_seconds, 7200);
    }

    #[test]
    fn resolve_keeps_a_floating_time_an_unknown_zone_and_a_value_that_agrees() {
        let summer = berlin(2026, 7, 1, 10, 0, 3600, 1_782_896_400_000);
        let f = floating(2026, 7, 1, 10);
        assert_eq!(resolve_date_time(&RULES, &f, Anchor::Local), Some(f));
        let mars = with_zone(summer.clone(), "Mars/Olympus_Mons");
        assert_eq!(
            resolve_date_time(&RULES, &mars, Anchor::Local),
            Some(mars.clone())
        );
        let agrees = berlin(2026, 7, 1, 10, 0, 7200, 1_782_892_800_000);
        assert_eq!(
            resolve_date_time(&RULES, &agrees, Anchor::Instant),
            Some(agrees.clone())
        );
    }

    #[test]
    fn resolve_local_keeps_the_wall_clock_instant_keeps_the_instant() {
        let summer = berlin(2026, 7, 1, 10, 0, 3600, 1_782_896_400_000);
        let local = resolve_date_time(&RULES, &summer, Anchor::Local).unwrap();
        assert_eq!(local.wall.hour, 10);
        assert_eq!(local.zoned.unwrap().instant_ms, 1_782_892_800_000);
        let instant = resolve_date_time(&RULES, &summer, Anchor::Instant).unwrap();
        assert_eq!(instant.wall.hour, 11);
        assert_eq!(instant.zoned.unwrap().instant_ms, 1_782_896_400_000);
    }

    #[test]
    fn months_clamp_the_day_and_floating_millis_move_the_wall_clock() {
        let add = |d: DateTime, by| add_duration(&RULES, &d, by).unwrap().wall;
        assert_eq!(add(floating(2027, 1, 31, 9), duration(1, 0, 0)).day, 28);
        assert_eq!(add(floating(2028, 1, 31, 9), duration(1, 0, 0)).day, 29);
        assert_eq!(
            add(floating(2026, 12, 31, 23), duration(0, 0, 3_600_000)).year,
            2027
        );
    }

    #[test]
    fn a_day_keeps_the_wall_clock_and_24_hours_keep_the_instant() {
        let october = berlin(2026, 10, 24, 10, 0, 7200, 1_792_828_800_000);
        let add = |by| add_duration(&RULES, &october, by).unwrap().wall.hour;
        assert_eq!(add(duration(0, 1, 0)), 10);
        assert_eq!(add(duration(0, 0, 86_400_000)), 9);
    }

    #[test]
    fn an_unknown_zone_keeps_its_offset() {
        let october = berlin(2026, 10, 24, 10, 0, 7200, 1_792_828_800_000);
        let mars = with_zone(october, "Mars/Olympus_Mons");
        let later = add_duration(&RULES, &mars, duration(0, 1, 1000)).unwrap();
        assert_eq!(later.wall.second, 1);
        let z = later.zoned.unwrap();
        assert_eq!(z.offset_seconds, 7200);
        assert_eq!(z.instant_ms, 1_792_828_800_000 + 86_400_000 + 1000);
    }

    #[test]
    fn a_sum_outside_the_years_1_to_9999_fails() {
        let add = |d: DateTime, by| add_duration(&RULES, &d, by);
        assert_eq!(add(floating(9999, 12, 1, 0), duration(1, 0, 0)), None);
        assert_eq!(add(floating(9999, 12, 31, 0), duration(0, 1, 0)), None);
        assert_eq!(
            add(floating(9999, 12, 31, 23), duration(0, 0, 3_600_000)),
            None
        );
        assert_eq!(add(floating(1, 1, 1, 0), duration(-1, 0, 0)), None);
    }

    #[test]
    fn a_berlin_value_in_the_year_9999_stays_known() {
        // 9999-12-31T22:00 at +01:00 is 21:00 UTC.
        let late = berlin(9999, 12, 31, 22, 0, 3600, 253_402_290_000_000);
        let sum = add_duration(&RULES, &late, duration(0, 0, 3_600_000)).unwrap();
        assert_eq!(sum.wall.hour, 23);
        assert_eq!(sum.zoned.unwrap().offset_seconds, 3600);
        let mut odd = late;
        if let Some(z) = &mut odd.zoned {
            z.offset_seconds = 0;
            z.instant_ms = 253_402_293_600_000;
        }
        let resolved = resolve_date_time(&RULES, &odd, Anchor::Instant).unwrap();
        assert_eq!(resolved.wall.hour, 23);
    }

    /// Rules with one fixed offset for every zone but `Nowhere`.
    struct Fixed(i64);

    impl ZoneRules for Fixed {
        fn offset_at(&self, zone: &str, _instant_ms: i64) -> Option<i64> {
            (zone != "Nowhere").then_some(self.0)
        }
    }

    #[test]
    fn other_rules_give_other_readings() {
        let summer = berlin(2026, 7, 1, 10, 0, 3600, 1_782_896_400_000);
        let local = resolve_date_time(&Fixed(0), &summer, Anchor::Local).unwrap();
        assert_eq!(local.wall.hour, 10);
        assert_eq!(local.zoned.unwrap().instant_ms, 1_782_900_000_000);
        let nowhere = with_zone(summer, "Nowhere");
        assert_eq!(
            resolve_date_time(&Fixed(0), &nowhere, Anchor::Instant),
            Some(nowhere.clone())
        );
    }
}
