//! The MongoDB store's clock: the same UTC text the SQLite store gets from
//! `strftime`, so a record reads the same whichever backend wrote it, and
//! the BSON instants the TTL indexes need.
//!
//! Two shapes are written: `YYYY-MM-DDTHH:MM:SS.mmmZ` for when something
//! happened (`created_at`, `occurred_at`, ...) and `YYYY-MM-DD HH:MM:SS` for
//! a cutoff (`expires_at`), which compares correctly as text.

use crate::error::{Error, Result};
use crate::provider::civil_from_days;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> Result<(i64, u32)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
    Ok((now.as_secs() as i64, now.subsec_millis()))
}

fn split(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    (year, month, day, rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

/// `YYYY-MM-DD HH:MM:SS` for a UNIX time.
pub(crate) fn seconds_at(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = split(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for a UNIX time.
fn iso_millis_at(secs: i64, millis: u32) -> String {
    let (y, mo, d, h, mi, s) = split(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Now, as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub(crate) fn now_iso_millis() -> Result<String> {
    let (secs, millis) = now_unix()?;
    Ok(iso_millis_at(secs, millis))
}

/// Now, as `YYYY-MM-DD HH:MM:SS`.
pub(crate) fn now_seconds() -> Result<String> {
    Ok(seconds_at(now_unix()?.0))
}

/// `delta` seconds from now, as `YYYY-MM-DD HH:MM:SS`. Refused when the
/// result cannot be written as a four-digit year, as SQLite refuses a TTL
/// `datetime()` cannot represent: a NULL expiry would mean "never".
pub(crate) fn seconds_after(delta: i64) -> Result<String> {
    let (now, _) = now_unix()?;
    let at = now.checked_add(delta).ok_or(Error::InvalidApiKeyRequest)?;
    let (year, ..) = split(at);
    if !(0..=9_999).contains(&year) {
        return Err(Error::InvalidApiKeyRequest);
    }
    Ok(seconds_at(at))
}

/// The UNIX time of a `YYYY-MM-DD HH:MM[:SS]` UTC cutoff, for a TTL index.
pub(crate) fn parse_seconds(text: &str) -> Option<i64> {
    let (date, time) = text.split_once(' ')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut time = time.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next().map_or(Some(0), |s| s.parse().ok())?;
    if time.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Howard Hinnant's days-from-civil (UTC, proleptic Gregorian), the
/// inverse of `provider::civil_from_days`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
#[path = "clock_tests.rs"]
mod tests;
