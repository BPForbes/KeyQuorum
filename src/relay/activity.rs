//! What the relay saw each known key do, by hour, for the provider's console.
//!
//! One row per key, hour, route and outcome, counted in place: the table's
//! size follows the keys the provider issued, not the traffic. Each row sums
//! the requests, the time they took and the bytes each way, so the console can
//! show counts, errors, latency and volume. Only a bearer that matches a stored
//! key is recorded (an anonymous caller must not be able to grow the table), and
//! a refusal is recorded only when the key itself was the reason (`revoked`,
//! `expired`, a `scope` it does not hold). It is a usage view, not evidence: it
//! is not in the audit chain, the scan drops rows older than
//! [`RETENTION_DAYS`], and the durations are coarse (a Durable Object's clock
//! moves only when it waits). It never holds a bearer, a hash, a path past its
//! first segment, a body or an address.
//!
//! This module owns the `access_activity` table. It reads `api_keys` only to
//! learn a key's state.

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

    pub fn parse(text: &str) -> Option<Self> {
        [Self::Inbox, Self::Devices, Self::Trees, Self::Audit, Self::Other]
            .into_iter()
            .find(|route| route.as_str() == text)
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
    /// Answered below 400.
    Ok,
    /// Answered 400 to 499 other than a refusal of the key.
    ClientError,
    /// Answered 500 or more.
    ServerError,
    Revoked,
    Expired,
    /// The key is live but lacks the scope (or recipient) the route needs.
    Scope,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ClientError => "client_error",
            Self::ServerError => "server_error",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Scope => "scope",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Ok,
            Self::ClientError,
            Self::ServerError,
            Self::Revoked,
            Self::Expired,
            Self::Scope,
        ]
        .into_iter()
        .find(|outcome| outcome.as_str() == text)
    }

    /// Whether this is a refusal because of the key itself.
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::Revoked | Self::Expired | Self::Scope)
    }
}

/// The outcome for a key in the given state that was answered `status`, or
/// `None` when the request says nothing about the key (a revoked key on a
/// route that never asked for it).
pub(crate) fn classify(revoked: bool, expired: bool, status: u16) -> Option<Outcome> {
    let refused = matches!(status, 401 | 403);
    match (revoked, expired, refused) {
        (true, _, true) => Some(Outcome::Revoked),
        (false, true, true) => Some(Outcome::Expired),
        (false, false, true) => Some(Outcome::Scope),
        (false, false, false) => Some(match status {
            0..=399 => Outcome::Ok,
            400..=499 => Outcome::ClientError,
            _ => Outcome::ServerError,
        }),
        _ => None,
    }
}

/// What one request cost, as the object measured it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    pub millis: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Counts one request by the key `token` names, if it names one. `path` is the
/// request path and `status` the answer. A token that is malformed or unknown
/// records nothing.
pub fn record(conn: &dyn Sql, token: &str, path: &str, status: u16, cost: Cost) -> Result<()> {
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
    let millis = i64::from(cost.millis);
    let bytes_in = i64::try_from(cost.bytes_in).unwrap_or(i64::MAX);
    let bytes_out = i64::try_from(cost.bytes_out).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO access_activity
            (api_key_id, hour, route, outcome, count, ms_total, ms_max, bytes_in, bytes_out)
         VALUES (?1, strftime('%Y-%m-%dT%H:00:00Z', 'now'), ?2, ?3, 1, ?4, ?4, ?5, ?6)
         ON CONFLICT (api_key_id, hour, route, outcome) DO UPDATE SET
            count = count + 1,
            ms_total = ms_total + excluded.ms_total,
            ms_max = MAX(ms_max, excluded.ms_max),
            bytes_in = bytes_in + excluded.bytes_in,
            bytes_out = bytes_out + excluded.bytes_out",
        params![id, Route::of_path(path).as_str(), outcome.as_str(), millis, bytes_in, bytes_out],
    )?;
    Ok(())
}

/// What a summary covers. Every field narrows it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Filter {
    pub hours: i64,
    pub customer_id: Option<i64>,
    pub key_id: Option<i64>,
    pub route: Option<Route>,
    pub outcome: Option<Outcome>,
}

/// One key's requests over a window, by route and outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyActivity {
    pub api_key_id: i64,
    pub route: String,
    pub outcome: String,
    pub count: i64,
    pub ms_total: i64,
    pub ms_max: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    /// The newest hour (UTC, `YYYY-MM-DDTHH:00:00Z`) with such a request.
    pub last_hour: String,
}

/// All requests, by hour and outcome, across the keys in the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HourlyCount {
    pub hour: String,
    pub outcome: String,
    pub count: i64,
}

/// What the console shows: per key and per hour, over the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub hours: i64,
    pub by_key: Vec<KeyActivity>,
    pub by_hour: Vec<HourlyCount>,
}

const WHERE: &str = "hour >= strftime('%Y-%m-%dT%H:00:00Z', 'now', ?1)
   AND (?2 IS NULL OR api_key_id = ?2)
   AND (?3 IS NULL OR route = ?3)
   AND (?4 IS NULL OR outcome = ?4)
   AND (?5 IS NULL OR api_key_id IN (
        SELECT lk.api_key_id FROM licence_keys lk
        JOIN licences l ON l.id = lk.licence_id
        WHERE l.customer_id = ?5))";

/// The window is `1..=MAX_SUMMARY_HOURS` hours; anything else is clamped.
pub fn summary(conn: &dyn Sql, filter: &Filter) -> Result<Summary> {
    let hours = filter.hours.clamp(1, MAX_SUMMARY_HOURS);
    let since = format!("-{hours} hours");
    let route = filter.route.map(Route::as_str);
    let outcome = filter.outcome.map(Outcome::as_str);
    let by_key = conn.query_map(
        &format!(
            "SELECT api_key_id, route, outcome, SUM(count), SUM(ms_total), MAX(ms_max),
                    SUM(bytes_in), SUM(bytes_out), MAX(hour)
             FROM access_activity WHERE {WHERE}
             GROUP BY api_key_id, route, outcome
             ORDER BY api_key_id, route, outcome"
        ),
        params![&since, filter.key_id, route, outcome, filter.customer_id],
        |row| {
            Ok(KeyActivity {
                api_key_id: row.get(0)?,
                route: row.get(1)?,
                outcome: row.get(2)?,
                count: row.get(3)?,
                ms_total: row.get(4)?,
                ms_max: row.get(5)?,
                bytes_in: row.get(6)?,
                bytes_out: row.get(7)?,
                last_hour: row.get(8)?,
            })
        },
    )?;
    let by_hour = conn.query_map(
        &format!(
            "SELECT hour, outcome, SUM(count) FROM access_activity WHERE {WHERE}
             GROUP BY hour, outcome ORDER BY hour, outcome"
        ),
        params![&since, filter.key_id, route, outcome, filter.customer_id],
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
