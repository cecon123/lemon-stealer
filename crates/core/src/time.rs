//! `ChromeTime`: a `chrono` wrapper with Go `time.Time` JSON parity.
//!
//! Go `time.Time` marshals as RFC3339Nano (trailing-zero fractional seconds trimmed),
//! and its zero value serializes as `"0001-01-01T00:00:00Z"` — `chrono`'s
//! `DateTime<Utc>` default would emit `"1970-01-01T00:00:00Z"`, so this wrapper is
//! required for output parity (PLAN.md R2: "chrono phải custom serialize cho khớp").

use std::fmt;

use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Offset from the Chromium epoch (1601-01-01 UTC) to the Unix epoch, matching
/// `base::Time::kTimeTToMicrosecondsOffset` in Chromium.
pub const CHROMIUM_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChromeTime(DateTime<Utc>);

fn is_zero(dt: DateTime<Utc>) -> bool {
    let d = dt.date_naive();
    let t = dt.time();
    d == NaiveDate::from_ymd_opt(1, 1, 1).expect("year 1 is in range")
        && t == NaiveTime::from_hms_opt(0, 0, 0).expect("valid midnight")
}

impl ChromeTime {
    /// The Go `time.Time{}` zero value: 0001-01-01T00:00:00 UTC.
    pub fn zero() -> Self {
        ChromeTime(chrono_zero())
    }

    /// The current UTC time (Go: `time.Now()` — used for `Dump.created_at`).
    pub fn now() -> Self {
        ChromeTime(Utc::now())
    }

    pub fn from_utc(dt: DateTime<Utc>) -> Self {
        ChromeTime(dt)
    }

    pub fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }

    /// Returns true when this is the zero time (Go: `time.Time.IsZero()`).
    pub fn is_zero(&self) -> bool {
        is_zero(self.0)
    }

    /// Converts a Chromium `base::Time` (µs since 1601 UTC) to UTC.
    ///
    /// Port of `browser/chromium/chromium.go: timeEpoch`: returns zero for
    /// non-positive input or out-of-range values (year outside 1..=9999, which
    /// Go's JSON encoder rejects).
    pub fn from_chromium_micros(epoch: i64) -> Self {
        if epoch <= 0 {
            return Self::zero();
        }
        match Utc
            .timestamp_opt(
                epoch
                    .saturating_sub(CHROMIUM_EPOCH_OFFSET_MICROS)
                    .div_euclid(1_000_000),
                (epoch
                    .saturating_sub(CHROMIUM_EPOCH_OFFSET_MICROS)
                    .rem_euclid(1_000_000)
                    * 1_000) as u32,
            )
            .single()
        {
            Some(t) if (1..=9999).contains(&t.year()) => ChromeTime(t),
            _ => Self::zero(),
        }
    }

    /// RFC3339Nano-formatted string with Go's quirks: trailing-zero fractional
    /// seconds trimmed, `Z` suffix for UTC, zero time as year 1.
    pub fn to_rfc3339_nano(&self) -> String {
        let dt = self.0;
        if is_zero(dt) {
            return "0001-01-01T00:00:00Z".to_string();
        }
        dt.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string()
    }
}

fn chrono_zero() -> DateTime<Utc> {
    Utc.from_utc_datetime(
        &NaiveDate::from_ymd_opt(1, 1, 1)
            .expect("year 1 is in range")
            .and_hms_opt(0, 0, 0)
            .expect("valid midnight"),
    )
}

impl Default for ChromeTime {
    /// Go `time.Time` zero value, NOT the Unix epoch.
    fn default() -> Self {
        Self::zero()
    }
}

impl From<DateTime<Utc>> for ChromeTime {
    fn from(dt: DateTime<Utc>) -> Self {
        ChromeTime(dt)
    }
}

impl fmt::Display for ChromeTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339_nano())
    }
}

impl Serialize for ChromeTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339_nano())
    }
}

impl<'de> Deserialize<'de> for ChromeTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&s)
            .map(|dt| ChromeTime(dt.with_timezone(&Utc)))
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    // Anchor: 2024-01-15T10:30:00Z as Chromium microseconds since 1601 UTC.
    const ANCHOR_UNIX_SECONDS: i64 = 1_705_314_600;
    const ANCHOR_CHROMIUM_MICROS: i64 = (ANCHOR_UNIX_SECONDS + 11_644_473_600) * 1_000_000;

    // Port of TestTimeEpoch_AnchorDate.
    #[test]
    fn time_epoch_anchor_date() {
        let got = ChromeTime::from_chromium_micros(ANCHOR_CHROMIUM_MICROS);
        let want = Utc.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap();
        assert_eq!(want, got.as_datetime());
        assert_eq!(ANCHOR_UNIX_SECONDS, got.as_datetime().timestamp());
    }

    // Port of TestTimeEpoch_ZeroReturnsZeroTime.
    #[test]
    fn time_epoch_zero_returns_zero() {
        assert!(ChromeTime::from_chromium_micros(0).is_zero());
    }

    // Port of TestTimeEpoch_NegativeReturnsZeroTime.
    #[test]
    fn time_epoch_negative_returns_zero() {
        assert!(ChromeTime::from_chromium_micros(-1).is_zero());
    }

    // Port of TestTimeEpoch_AlwaysUTC.
    #[test]
    fn time_epoch_always_utc() {
        let got = ChromeTime::from_chromium_micros(ANCHOR_CHROMIUM_MICROS);
        assert_eq!(Utc, got.as_datetime().timezone());
    }

    // Port of TestTimeEpoch_MicrosecondPrecisionPreserved.
    #[test]
    fn time_epoch_microsecond_precision_preserved() {
        let got = ChromeTime::from_chromium_micros(ANCHOR_CHROMIUM_MICROS + 123_456);
        assert_eq!(123_456_000, got.as_datetime().timestamp_subsec_nanos());
    }

    // Port of TestTimeEpoch_UnixEpochBoundary.
    #[test]
    fn time_epoch_unix_epoch_boundary() {
        let got = ChromeTime::from_chromium_micros(CHROMIUM_EPOCH_OFFSET_MICROS);
        assert_eq!(0, got.as_datetime().timestamp());
    }

    // Port of TestTimeEpoch_OutOfJSONRangeReturnsZero.
    #[test]
    fn time_epoch_out_of_range_returns_zero() {
        let got = ChromeTime::from_chromium_micros(1 << 62);
        assert!(got.is_zero());
        assert_eq!(
            r#""0001-01-01T00:00:00Z""#,
            serde_json::to_string(&got).unwrap()
        );
    }

    #[test]
    fn json_zero_time_matches_go() {
        assert_eq!(
            r#""0001-01-01T00:00:00Z""#,
            serde_json::to_string(&ChromeTime::zero()).unwrap()
        );
    }

    #[test]
    fn json_trims_trailing_zero_fraction() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap();
        assert_eq!(
            r#""2024-01-15T10:30:00Z""#,
            serde_json::to_string(&ChromeTime::from(dt)).unwrap()
        );
    }

    #[test]
    fn json_microsecond_fraction_kept() {
        let dt =
            Utc.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap() + Duration::microseconds(123_456);
        // Go RFC3339Nano with trailing zeros trimmed: ...30.123456Z
        assert_eq!(
            r#""2024-01-15T10:30:00.123456Z""#,
            serde_json::to_string(&ChromeTime::from(dt)).unwrap()
        );
    }

    #[test]
    fn round_trip_parse() {
        let t = ChromeTime::from_chromium_micros(ANCHOR_CHROMIUM_MICROS + 123_456);
        let s = serde_json::to_string(&t).unwrap();
        let back: ChromeTime = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn default_is_go_zero_not_unix_epoch() {
        assert_eq!(ChromeTime::zero(), ChromeTime::default());
        assert!(ChromeTime::default().is_zero());
    }
}
