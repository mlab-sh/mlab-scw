//! The Scaleway side of the CLI: what to talk to, and how.

pub mod catalog;
pub mod client;
pub mod config;
pub mod identity;
pub mod locality;
pub mod secrets;
pub mod sweep;

pub use catalog::Severity;
pub use client::{esc, Client, Paging};
pub use config::Profile;
pub use locality::Scope;

/// Seconds since the epoch for an RFC 3339 timestamp, which is the one date
/// format the API uses: `2025-04-03T09:12:44.123456Z`.
///
/// Only the fixed-width prefix is read. Fractional seconds are ignored, and so
/// is a numeric offset — every date this API returns is UTC, and being an hour
/// wrong on a value only ever rendered as "3 years ago" is not worth a
/// date-time dependency.
pub fn epoch_of(rfc3339: &str) -> Option<i64> {
    let b = rfc3339.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |from: usize, to: usize| rfc3339.get(from..to)?.parse::<i64>().ok();
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Howard Hinnant's days_from_civil: shift the era so March starts the year,
/// which makes the leap day the last one and removes every special case.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since the epoch, now.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A time difference, in the coarsest unit that still says something.
///
/// `delta` is `now - then`, so a positive value is the past and a negative one
/// the future. Both directions matter here: an API key's age is a finding, and
/// so is how long is left before it expires.
///
/// Deliberately coarse. The question a date answers in an audit is "is this
/// older than anyone remembers" or "is this about to break", not "when exactly".
pub fn relative(delta: i64) -> String {
    let (n, suffix, prefix) = if delta < 0 {
        (-delta, "", "in ")
    } else {
        (delta, " ago", "")
    };
    let unit = match n {
        s if s < 90 => {
            return if delta < 0 {
                "in a moment".into()
            } else {
                "just now".into()
            }
        }
        s if s < 5_400 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3600),
        s if s < 5_184_000 => format!("{}d", s / 86_400),
        s if s < 63_072_000 => format!("{}mo", s / 2_592_000),
        s => format!("{}y", s / 31_536_000),
    };
    format!("{prefix}{unit}{suffix}")
}

/// An RFC 3339 timestamp with its distance from now appended, or the timestamp
/// untouched when it is not one. The shape every date in this CLI is printed in.
pub fn dated(rfc3339: &str) -> String {
    match epoch_of(rfc3339) {
        Some(epoch) => format!("{rfc3339}  ({})", relative(now() - epoch)),
        None => rfc3339.to_string(),
    }
}

/// A byte count as something a person can read. Binary units, because that is
/// what the API counts in.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_becomes_epoch_seconds() {
        assert_eq!(epoch_of("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_of("2025-09-29T12:20:39Z"), Some(1_759_148_439));
        assert_eq!(
            epoch_of("2025-09-29T12:20:39.123456Z"),
            Some(1_759_148_439),
            "fractional seconds are ignored, not fatal"
        );
    }

    #[test]
    fn the_march_shift_handles_leap_days_and_year_ends() {
        assert_eq!(epoch_of("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(epoch_of("2020-03-01T00:00:00Z"), Some(1_583_020_800));
        assert_eq!(epoch_of("2020-12-31T23:59:59Z"), Some(1_609_459_199));
    }

    #[test]
    fn anything_that_is_not_a_date_is_none_rather_than_zero() {
        assert_eq!(epoch_of(""), None);
        assert_eq!(epoch_of("never"), None);
        assert_eq!(epoch_of("2025-13-01T00:00:00Z"), None, "no month 13");
        assert_eq!(epoch_of("2025/09/29 12:20:39"), None);
    }

    #[test]
    fn relative_picks_the_coarsest_unit_that_still_says_something() {
        assert_eq!(relative(30), "just now");
        assert_eq!(relative(600), "10m ago");
        assert_eq!(relative(7_200), "2h ago");
        assert_eq!(relative(864_000), "10d ago");
        assert_eq!(relative(7_776_000), "3mo ago");
        assert_eq!(relative(94_608_000), "3y ago");
    }

    #[test]
    fn the_future_reads_forwards_rather_than_as_a_negative_past() {
        // An expiry is the whole reason this direction exists: "in 7d" is the
        // finding, "-604800s" and "in the future" are both useless.
        assert_eq!(relative(-604_800), "in 7d");
        assert_eq!(relative(-7_200), "in 2h");
        assert_eq!(relative(-31_536_000 * 2), "in 2y");
        assert_eq!(relative(-10), "in a moment");
    }

    #[test]
    fn dated_annotates_a_timestamp_and_leaves_anything_else_alone() {
        assert!(dated("2020-01-01T00:00:00Z").contains("ago"));
        assert_eq!(dated("never"), "never", "a word is not a date");
        assert_eq!(dated(""), "");
    }

    #[test]
    fn bytes_read_as_bytes_until_they_do_not() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(10 * 1024), "10.0 KiB");
        assert_eq!(bytes(107_374_182_400), "100.0 GiB");
    }
}
