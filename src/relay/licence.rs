//! The provider's licence records: whom a key was licensed to, on what terms
//! and until when.
//!
//! A licence is bookkeeping the provider keeps in the relay's own database and
//! signs into each key it issues ([`statement`] is the text a sealed
//! `KeyIssue.licence` carries). It enforces nothing by itself: what stops a
//! client is a revoked or expired key, and [`void`] is how a licence ends them
//! together, in the store's one unit of work. The relay does not meter seats.
//!
//! This module owns the `licences` and `licence_keys` tables. It never holds a
//! bearer, a key hash or sealed bytes; `licence_keys` points at `api_keys` by
//! id.

use super::sql::{params, Row, Sql};
use crate::error::{Error, Result};

/// The longest client name, in characters.
pub const MAX_CLIENT_CHARS: usize = 200;
/// The longest free-form terms text, in UTF-8 bytes. The statement sealed into
/// a key also carries a header and must fit
/// [`crate::api_key_delivery::MAX_LICENCE_BYTES`].
pub const MAX_TERMS_BYTES: usize = 8 * 1024;
/// The longest reason recorded when a licence is voided, in characters.
pub const MAX_REASON_CHARS: usize = 500;

/// A licence as the provider recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Licence {
    pub id: i64,
    pub client: String,
    pub terms: String,
    pub created_at: String,
    /// UTC `YYYY-MM-DD HH:MM:SS`; `None` means it has no end.
    pub expires_at: Option<String>,
    pub voided_at: Option<String>,
    pub void_reason: Option<String>,
    /// Whether it is neither voided nor past its end, by the store's clock.
    pub active: bool,
}

/// A licence to record. `expires_at` is any date or date-time SQLite reads
/// (`2027-01-31`, `2027-01-31 12:00:00`, ISO 8601); it must be in the future.
#[derive(Clone, Debug)]
pub struct NewLicence {
    pub client: String,
    pub terms: String,
    pub expires_at: Option<String>,
}

const SELECT: &str = "SELECT id, client, terms, created_at, expires_at, voided_at, void_reason,
        voided_at IS NULL
          AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
 FROM licences";

fn row_to_licence(row: &Row) -> Result<Licence> {
    Ok(Licence {
        id: row.get(0)?,
        client: row.get(1)?,
        terms: row.get(2)?,
        created_at: row.get(3)?,
        expires_at: row.get(4)?,
        voided_at: row.get(5)?,
        void_reason: row.get(6)?,
        active: row.get(7)?,
    })
}

/// Control characters would reach the statement a client reads and the
/// operator's own screen.
fn plain(text: &str) -> bool {
    text.chars().all(|c| !c.is_control() || c == '\n')
}

/// Records a licence. The client name is 1 to [`MAX_CLIENT_CHARS`] characters
/// of plain text, the terms at most [`MAX_TERMS_BYTES`], and an end date, if
/// any, is normalised by SQLite and must be in the future.
pub fn create(conn: &dyn Sql, new: &NewLicence) -> Result<Licence> {
    let client = new.client.trim();
    let terms = new.terms.trim();
    if client.is_empty()
        || client.chars().count() > MAX_CLIENT_CHARS
        || !client.chars().all(|c| !c.is_control())
        || terms.len() > MAX_TERMS_BYTES
        || !plain(terms)
    {
        return Err(Error::InvalidLicence);
    }
    let expires_at = match new.expires_at.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(text) => {
            let normalised: Option<String> = conn.query_opt(
                "SELECT datetime(?1)
                 WHERE datetime(?1) IS NOT NULL AND datetime(?1) > datetime('now')",
                params![text],
                |row| row.get(0),
            )?;
            Some(normalised.ok_or(Error::InvalidLicence)?)
        }
    };
    conn.execute(
        "INSERT INTO licences (client, terms, expires_at) VALUES (?1, ?2, ?3)",
        params![client, terms, expires_at],
    )?;
    get(conn, conn.last_insert_rowid()?)
}

pub fn get(conn: &dyn Sql, id: i64) -> Result<Licence> {
    conn.query_opt(
        &format!("{SELECT} WHERE id = ?1"),
        params![id],
        row_to_licence,
    )?
    .ok_or(Error::LicenceNotFound)
}

/// Every licence, newest first.
pub fn list(conn: &dyn Sql) -> Result<Vec<Licence>> {
    conn.query_map(
        &format!("{SELECT} ORDER BY id DESC"),
        params![],
        row_to_licence,
    )
}

/// Records that key `api_key_id` was issued under licence `licence_id`.
pub fn link_key(conn: &dyn Sql, api_key_id: i64, licence_id: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO licence_keys (api_key_id, licence_id) VALUES (?1, ?2)",
        params![api_key_id, licence_id],
    )?;
    Ok(())
}

/// The licence key `api_key_id` was issued under, if any.
pub fn licence_of_key(conn: &dyn Sql, api_key_id: i64) -> Result<Option<i64>> {
    conn.query_opt(
        "SELECT licence_id FROM licence_keys WHERE api_key_id = ?1",
        params![api_key_id],
        |row| row.get(0),
    )
}

/// Every key issued under licence `licence_id`, oldest first.
pub fn keys_of(conn: &dyn Sql, licence_id: i64) -> Result<Vec<i64>> {
    conn.query_map(
        "SELECT api_key_id FROM licence_keys WHERE licence_id = ?1 ORDER BY api_key_id",
        params![licence_id],
        |row| row.get(0),
    )
}

/// Every (key, licence) pair, for the console's key list.
pub fn all_links(conn: &dyn Sql) -> Result<Vec<(i64, i64)>> {
    conn.query_map(
        "SELECT api_key_id, licence_id FROM licence_keys",
        params![],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
}

/// Marks licence `id` voided, once. Returns `true` when this call voided it,
/// `false` when it already was; the keys are the caller's to revoke in the
/// same unit of work.
pub fn mark_void(conn: &dyn Sql, id: i64, reason: Option<&str>) -> Result<bool> {
    let reason = reason.map(str::trim).filter(|text| !text.is_empty());
    if let Some(text) = reason {
        if text.chars().count() > MAX_REASON_CHARS || !text.chars().all(|c| !c.is_control()) {
            return Err(Error::InvalidLicence);
        }
    }
    let changed = conn.execute(
        "UPDATE licences
         SET voided_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), void_reason = ?2
         WHERE id = ?1 AND voided_at IS NULL",
        params![id, reason],
    )?;
    if changed == 1 {
        return Ok(true);
    }
    get(conn, id).map(|_| false)
}

/// Seconds from now until the licence ends, `None` when it has no end. Never
/// zero or negative: an ended licence is [`Error::LicenceNotActive`], as is a
/// voided one, so no key is issued under it.
pub fn seconds_remaining(conn: &dyn Sql, licence: &Licence) -> Result<Option<i64>> {
    if !get(conn, licence.id)?.active {
        return Err(Error::LicenceNotActive);
    }
    let Some(expires_at) = &licence.expires_at else {
        return Ok(None);
    };
    let seconds: i64 = conn.query_row(
        "SELECT CAST(strftime('%s', ?1) AS INTEGER) - CAST(strftime('%s', 'now') AS INTEGER)",
        params![expires_at],
        |row| row.get(0),
    )?;
    if seconds <= 0 {
        return Err(Error::LicenceNotActive);
    }
    Ok(Some(seconds))
}

/// The signed statement a key issued under `licence` carries: a plain-text
/// header the console renders from the record, then the operator's terms.
pub fn statement(licence: &Licence, scope: &str, issued_at: &str) -> String {
    let mut out = format!(
        "KeyQuorum licence {}\nLicensee: {}\nScope: {}\nIssued: {} UTC\nEnds: {}\n",
        licence.id,
        licence.client,
        scope,
        issued_at,
        licence
            .expires_at
            .as_deref()
            .map_or_else(|| "no fixed end".to_string(), |end| format!("{end} UTC")),
    );
    if !licence.terms.is_empty() {
        out.push('\n');
        out.push_str(&licence.terms);
        out.push('\n');
    }
    out
}

#[cfg(test)]
#[path = "licence/tests.rs"]
mod tests;
