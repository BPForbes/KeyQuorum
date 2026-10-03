//! The three short-lived caches in the personal store. All are non-secret,
//! all expire after the same flat [`TTL_MINUTES`], and none is ever an input
//! to an authorization decision: a signature, quorum, custody, approval or
//! trust outcome is always recomputed from the authoritative state. They only
//! skip repeated preflight work or fill an omitted parameter.
//!
//! Times are the strings `Env::now_utc` returns (`YYYY-MM-DD HH:MM:SS`), which
//! SQLite's `datetime()` reads directly, so the clock is the environment's
//! (a fixed one in tests and the lab).

use crate::error::Result;
use rusqlite::{params, Connection, OptionalExtension};

/// Every cache entry is fresh for this long.
pub const TTL_MINUTES: i64 = 15;

fn fresh_modifier() -> String {
    format!("-{TTL_MINUTES} minutes")
}

/// A recently used parameter and how many whole minutes ago it was used.
#[derive(Debug, PartialEq, Eq)]
pub struct Recent {
    pub value: String,
    pub age_minutes: i64,
}

/// Remember a parameter the user gave a command that succeeded.
pub fn remember(conn: &Connection, name: &str, value: &str, now: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO recent_params (name, value, used_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO UPDATE SET value = excluded.value, used_at = excluded.used_at",
        params![name, value, now],
    )?;
    Ok(())
}

/// The parameter if it was given less than [`TTL_MINUTES`] ago.
pub fn recall(conn: &Connection, name: &str, now: &str) -> Result<Option<Recent>> {
    Ok(conn
        .query_row(
            "SELECT value,
                    (CAST(strftime('%s', ?2) AS INTEGER) - CAST(strftime('%s', used_at) AS INTEGER)) / 60
             FROM recent_params
             WHERE name = ?1 AND datetime(used_at) > datetime(?2, ?3)",
            params![name, now, fresh_modifier()],
            |row| {
                Ok(Recent {
                    value: row.get(0)?,
                    age_minutes: row.get(1)?,
                })
            },
        )
        .optional()?)
}

/// A relay identity check that passed.
pub struct RelayTrust<'a> {
    pub relay_url: &'a str,
    pub cert_fingerprint: &'a str,
    pub krl_digest: &'a str,
    pub key_hash: &'a str,
    /// The certificate's own expiry (`YYYY-MM-DD HH:MM[:SS]`); the entry never
    /// outlives it.
    pub cert_not_after: &'a str,
}

/// Record a passed check. It is valid until the TTL or the certificate expiry,
/// whichever is first.
pub fn store_relay_trust(conn: &Connection, trust: &RelayTrust<'_>, now: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO relay_trust_cache
            (relay_url, cert_fingerprint, krl_digest, key_hash, verified_at, valid_until)
         VALUES (?1, ?2, ?3, ?4, ?5,
                 min(datetime(?5, ?6), datetime(?7)))
         ON CONFLICT(relay_url) DO UPDATE SET
            cert_fingerprint = excluded.cert_fingerprint,
            krl_digest = excluded.krl_digest,
            key_hash = excluded.key_hash,
            verified_at = excluded.verified_at,
            valid_until = excluded.valid_until",
        params![
            trust.relay_url,
            trust.cert_fingerprint,
            trust.krl_digest,
            trust.key_hash,
            now,
            format!("+{TTL_MINUTES} minutes"),
            trust.cert_not_after
        ],
    )?;
    Ok(())
}

/// Whether a still-valid check matches the revocation list and stored key
/// hash in force now. Any difference is a miss. The certificate fingerprint
/// is kept for display only: learning the one on offer now would take the
/// very challenge this entry replaces.
pub fn relay_trust_hit(
    conn: &Connection,
    relay_url: &str,
    krl_digest: &str,
    key_hash: &str,
    now: &str,
) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM relay_trust_cache
             WHERE relay_url = ?1 AND krl_digest = ?2
               AND key_hash = ?3 AND datetime(?4) < datetime(valid_until)",
            params![relay_url, krl_digest, key_hash, now],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub fn forget_relay_trust(conn: &Connection, relay_url: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM relay_trust_cache WHERE relay_url = ?1",
        [relay_url],
    )?;
    Ok(())
}

/// Record that a fact about `subject` held when it was read from something
/// that hashed to `fingerprint`.
pub fn store_verified(
    conn: &Connection,
    kind: &str,
    subject: &str,
    fingerprint: &str,
    now: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO verified_cache (kind, subject, fingerprint, verified_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(kind, subject) DO UPDATE SET
            fingerprint = excluded.fingerprint, verified_at = excluded.verified_at",
        params![kind, subject, fingerprint, now],
    )?;
    Ok(())
}

/// Whether the fact is still fresh and was read from the same fingerprint.
pub fn verified_hit(
    conn: &Connection,
    kind: &str,
    subject: &str,
    fingerprint: &str,
    now: &str,
) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM verified_cache
             WHERE kind = ?1 AND subject = ?2 AND fingerprint = ?3
               AND datetime(verified_at) > datetime(?4, ?5)",
            params![kind, subject, fingerprint, now, fresh_modifier()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Empty all three caches. The profile is not touched.
pub fn clear(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "DELETE FROM recent_params; DELETE FROM relay_trust_cache; DELETE FROM verified_cache;",
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "cache/tests.rs"]
mod tests;
