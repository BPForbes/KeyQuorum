//! What the relay saw each known key do, by hour, for the provider's console.
//!
//! One row per key, hour, route and outcome, counted in place: the table's
//! size follows the keys the provider issued, not the traffic. Only a bearer
//! that matches a stored key is recorded (an anonymous caller must not be able
//! to grow the table), and a refusal is recorded only when the key itself was
//! the reason (`revoked`, `expired`, a `scope` it does not hold). It is a usage
//! view, not evidence: it is not in the audit chain, and the scan drops rows
//! older than [`RETENTION_DAYS`].
//!
//! This module owns the `access_activity` table. It reads `api_keys` only to
//! learn a key's state; it never stores a bearer or a hash.

use super::api_key::hash_bearer;
use super::sql::{params, Sql};
use crate::error::Result;

/// How long hourly counts are kept.
pub const RETENTION_DAYS: i64 = 90;

/// The most hours a summary may span (the retention window).
pub const MAX_SUMMARY_HOURS: i64 = RETENTION_DAYS * 24;

/// Which part of the API a request was for. Coarse on purpose: the first path
/// segment, never an id, label or fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Inbox,
    Devices,
    Trees,
    Audit,
    Other,
}

impl Route {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Devices => "devices",
            Self::Trees => "trees",
            Self::Audit => "audit",
            Self::Other => "other",
        }
    }

    pub fn of_path(path: &str) -> Self {
        match path.trim_matches('/').split('/').next().unwrap_or("") {
            "inbox" => Self::Inbox,
            "devices" => Self::Devices,
            "trees" => Self::Trees,
            "audit" => Self::Audit,
            _ => Self::Other,
        }
    }
}

/// What a request meant for the key that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Revoked,
    Expired,
    Scope,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Scope => "scope",
        }
    }
}

/// The outcome for a key in the given state that was answered `status`, or
/// `None` when the request says nothing about the key (a revoked key on a route
/// that never asked for it, a server error).
pub(crate) fn classify(revoked: bool, expired: bool, status: u16) -> Option<Outcome> {
    let refused = matches!(status, 401 | 403);
    match (revoked, expired, refused) {
        (true, _, true) => Some(Outcome::Revoked),
        (false, true, true) => Some(Outcome::Expired),
        (false, false, true) => Some(Outcome::Scope),
        (false, false, false) if status < 500 => Some(Outcome::Ok),
        _ => None,
    }
}

/// Counts one request by the key `token` names, if it names one. `path` is the
/// request path and `status` the answer. A token that is malformed or unknown
/// records nothing.
pub fn record(conn: &dyn Sql, token: &str, path: &str, status: u16) -> Result<()> {
    let Ok(hash) = hash_bearer(token) else {
        return Ok(());
    };
    let key: Option<(i64, bool, bool)> = conn.query_opt(
        "SELECT id, revoked_at IS NOT NULL,
                expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')
         FROM api_keys WHERE key_hash = ?1",
        params![hash],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let Some((id, revoked, expired)) = key else {
        return Ok(());
    };
    let Some(outcome) = classify(revoked, expired, status) else {
        return Ok(());
    };
    conn.execute(
        "INSERT INTO access_activity (api_key_id, hour, route, outcome, count)
         VALUES (?1, strftime('%Y-%m-%dT%H:00:00Z', 'now'), ?2, ?3, 1)
         ON CONFLICT (api_key_id, hour, route, outcome) DO UPDATE SET count = count + 1",
        params![id, Route::of_path(path).as_str(), outcome.as_str()],
    )?;
    Ok(())
}

/// One key's requests over a window, by route and outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyActivity {
    pub api_key_id: i64,
    pub route: String,
    pub outcome: String,
    pub count: i64,
    /// The newest hour (UTC, `YYYY-MM-DDTHH:00:00Z`) with such a request.
    pub last_hour: String,
}

/// All requests, by hour and outcome, across every key in the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HourlyCount {
    pub hour: String,
    pub outcome: String,
    pub count: i64,
}

/// What the console shows: per key and per hour, over the last `hours`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub hours: i64,
    pub by_key: Vec<KeyActivity>,
    pub by_hour: Vec<HourlyCount>,
}

/// The window is `1..=MAX_SUMMARY_HOURS` hours; anything else is clamped.
pub fn summary(conn: &dyn Sql, hours: i64) -> Result<Summary> {
    let hours = hours.clamp(1, MAX_SUMMARY_HOURS);
    let since = format!("-{hours} hours");
    let by_key = conn.query_map(
        "SELECT api_key_id, route, outcome, SUM(count), MAX(hour)
         FROM access_activity
         WHERE hour >= strftime('%Y-%m-%dT%H:00:00Z', 'now', ?1)
         GROUP BY api_key_id, route, outcome
         ORDER BY api_key_id, route, outcome",
        params![&since],
        |row| {
            Ok(KeyActivity {
                api_key_id: row.get(0)?,
                route: row.get(1)?,
                outcome: row.get(2)?,
                count: row.get(3)?,
                last_hour: row.get(4)?,
            })
        },
    )?;
    let by_hour = conn.query_map(
        "SELECT hour, outcome, SUM(count)
         FROM access_activity
         WHERE hour >= strftime('%Y-%m-%dT%H:00:00Z', 'now', ?1)
         GROUP BY hour, outcome
         ORDER BY hour, outcome",
        params![&since],
        |row| {
            Ok(HourlyCount {
                hour: row.get(0)?,
                outcome: row.get(1)?,
                count: row.get(2)?,
            })
        },
    )?;
    Ok(Summary {
        hours,
        by_key,
        by_hour,
    })
}

/// Drops hourly counts past [`RETENTION_DAYS`]; how many rows.
pub fn purge_old(conn: &dyn Sql) -> Result<u64> {
    let removed = conn.execute(
        "DELETE FROM access_activity
         WHERE hour < strftime('%Y-%m-%dT%H:00:00Z', 'now', ?1)",
        params![format!("-{RETENTION_DAYS} days")],
    )?;
    Ok(removed as u64)
}

#[cfg(test)]
#[path = "activity/tests.rs"]
mod tests;
