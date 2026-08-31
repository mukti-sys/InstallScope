//! Wall-clock formatting shared by every backend.
//!
//! Lives in its own module rather than inside a backend because both the strace and aya recorders need
//! the same RFC3339 anchor, and a session's `wall_clock_utc` must be formatted identically regardless of
//! which recorder produced it — otherwise two recordings of the same install would not be comparable.
//!
//! No date crate. `Rules.md` §1 asks for a deliberately small dependency tree, and one timestamp format
//! does not justify pulling in a calendar library.

use std::time::{SystemTime, UNIX_EPOCH};

/// Formats an instant as RFC3339 UTC, to second precision.
///
/// Seconds are enough: this value exists only to anchor `ts_ns: 0`, and the authoritative ordering
/// within a recording comes from the nanosecond offsets themselves.
#[must_use]
pub fn rfc3339_utc(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let seconds_of_day = secs % 86_400;
    let (hour, minute, second) = (
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`. Public-domain algorithm.
#[must_use]
pub fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let shifted = days_since_epoch + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = u64::try_from(shifted - era * 146_097).unwrap_or(0);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = i64::try_from(year_of_era).unwrap_or(0) + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * month_prime + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    })
    .unwrap_or(1);
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Epoch seconds as a float, for anchoring strace's `-ttt` timestamps.
#[must_use]
pub fn epoch_secs_f64(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_719_245_678)),
            "2024-06-24T16:14:38Z"
        );
    }

    #[test]
    fn handles_leap_years_and_month_boundaries() {
        // 2024-02-29 exists; 2023-02-29 does not. Getting this wrong would misdate a recording by a day,
        // which matters when a receipt is disputed months later.
        let leap_day = UNIX_EPOCH + Duration::from_secs(1_709_164_800); // 2024-02-29T00:00:00Z
        assert_eq!(rfc3339_utc(leap_day), "2024-02-29T00:00:00Z");

        let new_year = UNIX_EPOCH + Duration::from_secs(1_704_067_199); // 2023-12-31T23:59:59Z
        assert_eq!(rfc3339_utc(new_year), "2023-12-31T23:59:59Z");
    }

    #[test]
    fn epoch_seconds_are_monotonic_with_time() {
        let earlier = epoch_secs_f64(UNIX_EPOCH + Duration::from_secs(100));
        let later = epoch_secs_f64(UNIX_EPOCH + Duration::from_secs(200));
        assert!(later > earlier);
        assert!((later - earlier - 100.0).abs() < 1e-6);
    }
}
