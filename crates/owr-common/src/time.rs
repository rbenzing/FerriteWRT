//! Text forms of times: durations such as `12h` or `1h 30m`, and RFC 3339 timestamps in UTC.
//!
//! Replaces the `humantime` crate (declared unmaintained). Config files hold durations written
//! by [`format_duration`], so its output is exactly what `humantime` wrote (`1m 1s`, `1day 1h`,
//! `1month`, `3years 2months 18h`, ...), and [`parse_duration`] reads everything `humantime`
//! read in practice: a number (with an optional fraction that is a whole number of nanoseconds)
//! and a unit, repeated, with optional spaces: `90s`, `1h30m`, `1h 30m`, `1.5h`, `2weeks`.
//! Units are case sensitive: `ns`, `us`/`µs`, `ms`, `s`/`sec`/`second(s)`, `m`/`min`/`minute(s)`,
//! `h`/`hr`/`hour(s)`, `d`/`day(s)`, `w`/`week(s)`, `M`/`month(s)` (30.44 days) and `y`/`year(s)`
//! (365.25 days). Timestamps are `YYYY-MM-DDTHH:MM:SS[.fraction]Z` from 1970 to 9999.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NS_PER_SEC: u128 = 1_000_000_000;
const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_HOUR: u64 = 3_600;
const SECS_PER_DAY: u64 = 86_400;
/// A month is a twelfth of a year of 365.25 days: 30.44 days.
const SECS_PER_MONTH: u64 = 2_630_016;
const SECS_PER_YEAR: u64 = 31_557_600;
/// Most fraction digits read: more could not be a whole number of nanoseconds of any unit.
const MAX_FRACTION_DIGITS: usize = 18;

/// Why a duration string was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DurationError {
    #[error("value was empty")]
    Empty,
    #[error("expected a number at byte {0}")]
    ExpectedNumber(usize),
    #[error("a time unit is needed, for example 1s or 1ms")]
    UnitNeeded,
    #[error("unknown time unit {0:?}")]
    UnknownUnit(String),
    #[error("the value is too large")]
    TooLarge,
    #[error("a fraction must be a whole number of nanoseconds")]
    SubNanosecond,
}

/// Nanoseconds in one `unit`, `None` for an unknown unit.
fn unit_ns(unit: &str) -> Option<u128> {
    let secs = |s: u64| u128::from(s).checked_mul(NS_PER_SEC);
    match unit {
        "nsec" | "ns" => Some(1),
        "usec" | "us" | "µs" => Some(1_000),
        "msec" | "ms" => Some(1_000_000),
        "seconds" | "second" | "secs" | "sec" | "s" => secs(1),
        "minutes" | "minute" | "mins" | "min" | "m" => secs(SECS_PER_MINUTE),
        "hours" | "hour" | "hrs" | "hr" | "h" => secs(SECS_PER_HOUR),
        "days" | "day" | "d" => secs(SECS_PER_DAY),
        "weeks" | "week" | "w" => secs(7 * SECS_PER_DAY),
        "months" | "month" | "M" => secs(SECS_PER_MONTH),
        "years" | "year" | "y" => secs(SECS_PER_YEAR),
        _ => None,
    }
}

fn digits_value(digits: &str) -> Result<u128, DurationError> {
    digits.bytes().try_fold(0u128, |acc, b| {
        acc.checked_mul(10)
            .and_then(|v| v.checked_add(u128::from(b.wrapping_sub(b'0'))))
            .ok_or(DurationError::TooLarge)
    })
}

/// Parse a duration such as `12h`, `1h 30m`, `90s` or `250ms`.
pub fn parse_duration(input: &str) -> Result<Duration, DurationError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(DurationError::Empty);
    }
    let mut total: u128 = 0;
    let mut rest = s;
    let mut offset = 0usize;
    while !rest.is_empty() {
        let skipped = rest.len().saturating_sub(rest.trim_start().len());
        rest = rest.trim_start();
        offset = offset.saturating_add(skipped);
        if rest.is_empty() {
            break;
        }
        let int_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        if int_len == 0 {
            return Err(DurationError::ExpectedNumber(offset));
        }
        let (int_digits, after_int) = rest.split_at(int_len);
        let mut frac_digits = "";
        let mut after_number = after_int;
        if let Some(after_dot) = after_int.strip_prefix('.') {
            let frac_len = after_dot.bytes().take_while(u8::is_ascii_digit).count();
            if frac_len == 0 {
                return Err(DurationError::ExpectedNumber(
                    offset.saturating_add(int_len),
                ));
            }
            let (f, r) = after_dot.split_at(frac_len);
            frac_digits = f;
            after_number = r;
        }
        let after_space = after_number.trim_start();
        let unit_len = after_space
            .char_indices()
            .find(|(_, c)| !c.is_alphabetic())
            .map_or(after_space.len(), |(i, _)| i);
        if unit_len == 0 {
            // A bare zero needs no unit (`lease = "0"`), as it never did.
            if after_space.is_empty() && frac_digits.is_empty() && digits_value(int_digits)? == 0 {
                break;
            }
            return Err(if after_space.is_empty() {
                DurationError::UnitNeeded
            } else {
                DurationError::ExpectedNumber(
                    offset.saturating_add(rest.len().saturating_sub(after_space.len())),
                )
            });
        }
        let (unit, next) = after_space.split_at(unit_len);
        let per_unit = unit_ns(unit).ok_or_else(|| DurationError::UnknownUnit(unit.to_owned()))?;

        let whole = digits_value(int_digits)?
            .checked_mul(per_unit)
            .ok_or(DurationError::TooLarge)?;
        total = total.checked_add(whole).ok_or(DurationError::TooLarge)?;
        if !frac_digits.is_empty() {
            if frac_digits.len() > MAX_FRACTION_DIGITS {
                return Err(DurationError::SubNanosecond);
            }
            let scale = 10u128.pow(u32::try_from(frac_digits.len()).unwrap_or(0));
            let scaled = digits_value(frac_digits)?
                .checked_mul(per_unit)
                .ok_or(DurationError::TooLarge)?;
            if scaled.checked_rem(scale) != Some(0) {
                return Err(DurationError::SubNanosecond);
            }
            total = total
                .checked_add(scaled.checked_div(scale).unwrap_or(0))
                .ok_or(DurationError::TooLarge)?;
        }
        offset = offset.saturating_add(rest.len().saturating_sub(next.len()));
        rest = next;
    }
    let secs = total.checked_div(NS_PER_SEC).unwrap_or(0);
    let nanos = total.checked_rem(NS_PER_SEC).unwrap_or(0);
    Ok(Duration::new(
        u64::try_from(secs).map_err(|_| DurationError::TooLarge)?,
        u32::try_from(nanos).unwrap_or(0),
    ))
}

/// The canonical text of `d`: its largest units first, a space between them, `0s` for zero.
/// [`parse_duration`] reads it back exactly.
pub fn format_duration(d: Duration) -> String {
    let mut secs = d.as_secs();
    let nanos = d.subsec_nanos();
    if secs == 0 && nanos == 0 {
        return "0s".to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut take = |unit_secs: u64, singular: &str, plural: Option<&str>| {
        let n = secs.checked_div(unit_secs).unwrap_or(0);
        secs = secs.checked_rem(unit_secs).unwrap_or(secs);
        if n > 0 {
            parts.push(match plural {
                Some(p) if n > 1 => format!("{n}{p}"),
                _ => format!("{n}{singular}"),
            });
        }
    };
    take(SECS_PER_YEAR, "year", Some("years"));
    take(SECS_PER_MONTH, "month", Some("months"));
    take(SECS_PER_DAY, "day", Some("days"));
    take(SECS_PER_HOUR, "h", None);
    take(SECS_PER_MINUTE, "m", None);
    take(1, "s", None);
    for (unit_nanos, name) in [(1_000_000u32, "ms"), (1_000, "us"), (1, "ns")] {
        let n = nanos
            .checked_div(unit_nanos)
            .unwrap_or(0)
            .checked_rem(1_000)
            .unwrap_or(0);
        if n > 0 {
            parts.push(format!("{n}{name}"));
        }
    }
    parts.join(" ")
}

/// Why an RFC 3339 timestamp was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimestampError {
    #[error("timestamp format is invalid (expected YYYY-MM-DDTHH:MM:SSZ)")]
    Format,
    #[error("a numeric component of the timestamp is out of range")]
    Range,
}

/// Latest second [`format_rfc3339_seconds`] can write: 9999-12-31T23:59:59Z.
const MAX_UNIX_SECS: u64 = 253_402_300_799;

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's algorithm). Years are
/// 1970..=9999 here, so nothing below can overflow.
#[allow(clippy::arithmetic_side_effects)]
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date (year, month, day) of a day number since 1970-01-01 (inverse of
/// [`days_from_civil`]; at most 9999-12-31, so nothing below can overflow).
#[allow(clippy::arithmetic_side_effects)]
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// `t` as `YYYY-MM-DDTHH:MM:SSZ` (UTC, fractions dropped); times before 1970 or after the year
/// 9999 are written as the nearest bound.
pub fn format_rfc3339_seconds(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .min(MAX_UNIX_SECS);
    let days = secs.checked_div(SECS_PER_DAY).unwrap_or(0);
    let in_day = secs.checked_rem(SECS_PER_DAY).unwrap_or(0);
    let (year, month, day) = civil_from_days(days);
    let hour = in_day.checked_div(SECS_PER_HOUR).unwrap_or(0);
    let minute = in_day
        .checked_rem(SECS_PER_HOUR)
        .and_then(|r| r.checked_div(SECS_PER_MINUTE))
        .unwrap_or(0);
    let second = in_day.checked_rem(SECS_PER_MINUTE).unwrap_or(0);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction]Z`: UTC only, a capital `T` and `Z`, fixed-width fields,
/// a real calendar date, seconds 0..=59, from 1970 to 9999. Fractions beyond nanoseconds are cut.
pub fn parse_rfc3339(input: &str) -> Result<SystemTime, TimestampError> {
    let b = input.as_bytes();
    let field = |from: usize, len: usize| -> Result<u64, TimestampError> {
        let digits = b
            .get(from..from.saturating_add(len))
            .filter(|d| d.iter().all(u8::is_ascii_digit))
            .ok_or(TimestampError::Format)?;
        Ok(digits.iter().fold(0u64, |acc, d| {
            acc.saturating_mul(10)
                .saturating_add(u64::from(d.wrapping_sub(b'0')))
        }))
    };
    let sep = |at: usize, want: u8| {
        (b.get(at) == Some(&want))
            .then_some(())
            .ok_or(TimestampError::Format)
    };
    let (year, month, day) = (field(0, 4)?, field(5, 2)?, field(8, 2)?);
    sep(4, b'-')?;
    sep(7, b'-')?;
    sep(10, b'T')?;
    let (hour, minute, second) = (field(11, 2)?, field(14, 2)?, field(17, 2)?);
    sep(13, b':')?;
    sep(16, b':')?;
    let mut end = 19;
    let mut nanos = 0u32;
    if b.get(end) == Some(&b'.') {
        let digits = b
            .get(end.saturating_add(1)..)
            .map_or(0, |r| r.iter().take_while(|c| c.is_ascii_digit()).count());
        if digits == 0 {
            return Err(TimestampError::Format);
        }
        let used = digits.min(9);
        let frac = field(end.saturating_add(1), used)?;
        let pad = u32::try_from(9usize.saturating_sub(used)).unwrap_or(0);
        nanos = u32::try_from(frac.saturating_mul(10u64.pow(pad))).unwrap_or(0);
        end = end.saturating_add(1).saturating_add(digits);
    }
    sep(end, b'Z')?;
    if b.len() != end.saturating_add(1) {
        return Err(TimestampError::Format);
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return Err(TimestampError::Range),
    };
    if year < 1970 || day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return Err(TimestampError::Range);
    }
    let secs = days_from_civil(year, month, day)
        .saturating_mul(SECS_PER_DAY)
        .saturating_add(hour.saturating_mul(SECS_PER_HOUR))
        .saturating_add(minute.saturating_mul(SECS_PER_MINUTE))
        .saturating_add(second);
    UNIX_EPOCH
        .checked_add(Duration::new(secs, nanos))
        .ok_or(TimestampError::Range)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn d(secs: u64, nanos: u32) -> Duration {
        Duration::new(secs, nanos)
    }

    /// What `humantime::format_duration` wrote for these durations (kept as vectors when the
    /// crate was replaced), so existing config files read and write the same text.
    #[test]
    fn durations_are_written_as_humantime_did() {
        for (secs, nanos, text) in [
            (0, 0, "0s"),
            (1, 0, "1s"),
            (59, 0, "59s"),
            (60, 0, "1m"),
            (61, 0, "1m 1s"),
            (3_599, 0, "59m 59s"),
            (3_600, 0, "1h"),
            (3_661, 0, "1h 1m 1s"),
            (86_399, 0, "23h 59m 59s"),
            (86_400, 0, "1day"),
            (90_000, 0, "1day 1h"),
            (604_800, 0, "7days"),
            (2_629_999, 0, "30days 10h 33m 19s"),
            (2_630_016, 0, "1month"),
            (2_630_017, 0, "1month 1s"),
            (31_557_599, 0, "11months 30days 9h 50m 23s"),
            (31_557_600, 0, "1year"),
            (31_557_601, 0, "1year 1s"),
            (100_000_000, 0, "3years 2months 18h 39m 28s"),
            (1_000_000_000, 0, "31years 8months 7days 19h 17m 52s"),
            (4_294_967_295, 0, "136years 1month 5days 19h 54m 39s"),
            (0, 1, "1ns"),
            (0, 1_000, "1us"),
            (0, 1_000_000, "1ms"),
            (0, 500_000_000, "500ms"),
            (1, 500_000_000, "1s 500ms"),
            (3, 1, "3s 1ns"),
            (61, 250_000_000, "1m 1s 250ms"),
        ] {
            assert_eq!(format_duration(d(secs, nanos)), text, "{secs}s {nanos}ns");
            assert_eq!(parse_duration(text), Ok(d(secs, nanos)), "{text}");
        }
    }

    /// What `humantime::parse_duration` read.
    #[test]
    fn durations_are_read_as_humantime_did() {
        for (text, secs, nanos) in [
            ("0", 0, 0),
            ("0s", 0, 0),
            ("12h", 43_200, 0),
            ("30m", 1_800, 0),
            ("1h 30m", 5_400, 0),
            ("1h30m", 5_400, 0),
            ("90s", 90, 0),
            ("1d", 86_400, 0),
            ("1 d", 86_400, 0),
            ("1w", 604_800, 0),
            ("2weeks", 1_209_600, 0),
            ("1M", 2_630_016, 0),
            ("1y", 31_557_600, 0),
            ("100ms", 0, 100_000_000),
            ("5msec", 0, 5_000_000),
            ("7us", 0, 7_000),
            ("7µs", 0, 7_000),
            ("9usec", 0, 9_000),
            ("11ns", 0, 11),
            ("13nsec", 0, 13),
            ("1sec", 1, 0),
            ("2secs", 2, 0),
            ("1second", 1, 0),
            ("3seconds", 3, 0),
            ("1min", 60, 0),
            ("2mins", 120, 0),
            ("1minute", 60, 0),
            ("3minutes", 180, 0),
            ("1hr", 3_600, 0),
            ("2hrs", 7_200, 0),
            ("1hour", 3_600, 0),
            ("3hours", 10_800, 0),
            ("1h 1h", 7_200, 0),
            (" 1h", 3_600, 0),
            ("1h ", 3_600, 0),
            ("1.5h", 5_400, 0),
            ("1 h 30 m", 5_400, 0),
            ("0.5s", 0, 500_000_000),
            ("1s1s", 2, 0),
            ("01h", 3_600, 0),
            ("18446744073709551615s", u64::MAX, 0),
        ] {
            assert_eq!(parse_duration(text), Ok(d(secs, nanos)), "{text:?}");
        }
    }

    #[test]
    fn what_is_not_a_duration_is_refused() {
        assert_eq!(parse_duration(""), Err(DurationError::Empty));
        assert_eq!(parse_duration("  "), Err(DurationError::Empty));
        assert_eq!(parse_duration("1"), Err(DurationError::UnitNeeded));
        assert!(matches!(
            parse_duration("h"),
            Err(DurationError::ExpectedNumber(0))
        ));
        assert!(matches!(
            parse_duration("-1s"),
            Err(DurationError::ExpectedNumber(0))
        ));
        assert!(matches!(
            parse_duration("1h,30m"),
            Err(DurationError::ExpectedNumber(2))
        ));
        assert!(matches!(
            parse_duration("1h 30"),
            Err(DurationError::UnitNeeded)
        ));
        assert!(matches!(
            parse_duration("1.h"),
            Err(DurationError::ExpectedNumber(1))
        ));
        for unit in ["1x", "1H", "1S", "1e3s", "1hh", "1 hours30"] {
            assert!(
                matches!(
                    parse_duration(unit),
                    Err(DurationError::UnknownUnit(_) | DurationError::UnitNeeded)
                ),
                "{unit}"
            );
        }
        // too large for a Duration, and fractions below a nanosecond
        assert_eq!(
            parse_duration("18446744073709551616s"),
            Err(DurationError::TooLarge)
        );
        assert_eq!(
            parse_duration("5124095576030431d"),
            Err(DurationError::TooLarge)
        );
        assert_eq!(
            parse_duration("99999999999999999999999999999999999999999s"),
            Err(DurationError::TooLarge)
        );
        assert_eq!(parse_duration("0.1ns"), Err(DurationError::SubNanosecond));
        assert_eq!(
            parse_duration("1.0000000001s"),
            Err(DurationError::SubNanosecond)
        );
        assert_eq!(
            parse_duration("0.0000000000000000001s"),
            Err(DurationError::SubNanosecond)
        );
    }

    proptest! {
        #[test]
        fn every_duration_reads_back_as_written(secs in 0u64..=u64::MAX / 2, nanos in 0u32..1_000_000_000) {
            let dur = d(secs, nanos);
            prop_assert_eq!(parse_duration(&format_duration(dur)), Ok(dur));
        }

        #[test]
        fn parsing_never_panics(s in "\\PC{0,24}") {
            let _ = parse_duration(&s);
        }

        #[test]
        fn every_second_of_the_range_reads_back_as_written(secs in 0u64..=MAX_UNIX_SECS) {
            let t = UNIX_EPOCH + Duration::from_secs(secs);
            prop_assert_eq!(parse_rfc3339(&format_rfc3339_seconds(t)), Ok(t));
        }

        #[test]
        fn timestamp_parsing_never_panics(s in "\\PC{0,30}") {
            let _ = parse_rfc3339(&s);
        }
    }

    #[test]
    fn timestamps_are_written_as_humantime_did() {
        for (secs, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_582_934_400, "2020-02-29T00:00:00Z"),
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ] {
            let t = UNIX_EPOCH + Duration::from_secs(secs);
            assert_eq!(format_rfc3339_seconds(t), text);
            assert_eq!(parse_rfc3339(text), Ok(t));
        }
        // fractions are dropped, the far future is clamped
        assert_eq!(
            format_rfc3339_seconds(UNIX_EPOCH + d(1_700_000_000, 999_999_999)),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(
            format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(400_000_000_000)),
            "9999-12-31T23:59:59Z"
        );
    }

    #[test]
    fn timestamps_are_read_as_humantime_did() {
        let at = |secs: u64, nanos: u32| Ok(UNIX_EPOCH + d(secs, nanos));
        assert_eq!(parse_rfc3339("2026-11-23T21:02:49Z"), at(1_795_467_769, 0));
        assert_eq!(
            parse_rfc3339("2026-11-23T21:02:49.123Z"),
            at(1_795_467_769, 123_000_000)
        );
        assert_eq!(
            parse_rfc3339("2026-11-23T21:02:49.123456789Z"),
            at(1_795_467_769, 123_456_789)
        );
        assert_eq!(
            parse_rfc3339("2026-11-23T21:02:49.1234567891234Z"),
            at(1_795_467_769, 123_456_789)
        );
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), at(0, 0));
        assert_eq!(parse_rfc3339("2000-02-29T23:59:59Z"), at(951_868_799, 0));
        assert_eq!(
            parse_rfc3339("9999-12-31T23:59:59Z"),
            at(253_402_300_799, 0)
        );
    }

    #[test]
    fn what_is_not_a_timestamp_is_refused() {
        for bad in [
            "2026-11-23 21:02:49Z",
            "2026-11-23T21:02:49",
            "2026-11-23T21:02:49+01:00",
            "2026-11-23t21:02:49z",
            "10000-01-01T00:00:00Z",
            "2026-1-1T00:00:00Z",
            "2026-11-23T21:02Z",
            "",
            "x",
            "2026-11-23T21:02:49Zjunk",
            "2026-11-23T21:02:49.Z",
            "2026-11-23T21:02:49.12",
        ] {
            assert_eq!(parse_rfc3339(bad), Err(TimestampError::Format), "{bad:?}");
        }
        for bad in [
            "2100-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-11-23T24:00:00Z",
            "2026-11-23T23:60:00Z",
            "2026-11-23T23:59:60Z",
            "1969-12-31T23:59:59Z",
            "2026-04-31T00:00:00Z",
            "2026-11-00T00:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), Err(TimestampError::Range), "{bad:?}");
        }
        assert!(
            parse_rfc3339("2024-02-29T00:00:00Z").is_ok(),
            "2024 is a leap year"
        );
    }
}
