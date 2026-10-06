//! A customer's licences, and the statements each one has carried.
//!
//! A licence is the provider's record of terms for one customer. Its statement
//! is signed into every key issued under it ([`statement`] is the text a
//! sealed `KeyIssue.licence` carries), and **statements are versioned and
//! immutable**: a renewal adds a version, it never rewrites one already
//! delivered. The licence enforces nothing by itself. What stops a client is a
//! revoked or expired key; a licence ends by its own end date or by [`void`],
//! which (in `issuance`) revokes the keys issued under it together. The relay
//! meters no seats and applies no feature policy.
//!
//! A key's end date is fixed when it is issued or replaced. Renewing a licence
//! changes its record and statement, not the keys already out: they end on the
//! date they were issued with, and replacing them (`issuance::rotate`) gives
//! each the licence's current end.
//!
//! This module owns the `licences`, `licence_versions` and `licence_keys`
//! tables. It never holds a bearer, a key hash or sealed bytes; links point at
//! `api_keys` by id.

use super::customer::Customer;
use super::sql::{params, Row, Sql};
use crate::error::{Error, Result};

/// The longest free-form terms text, in UTF-8 bytes. The statement sealed into
/// a key also carries a header and must fit
/// [`crate::api_key_delivery::MAX_LICENCE_BYTES`].
pub const MAX_TERMS_BYTES: usize = 8 * 1024;
/// The longest reason recorded when a licence is voided, in characters.
pub const MAX_REASON_CHARS: usize = 500;

/// A licence as the provider recorded it, with its latest statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Licence {
    pub id: i64,
    pub customer_id: i64,
    pub created_at: String,
    /// UTC `YYYY-MM-DD HH:MM:SS`; `None` means it has no end.
    pub expires_at: Option<String>,
    pub voided_at: Option<String>,
    pub void_reason: Option<String>,
    pub replaces_licence_id: Option<i64>,
    /// Whether it is neither voided nor past its end, by the store's clock.
    /// This is administrative status; what a key may do is the key's own state.
    pub active: bool,
    /// The number of the latest statement, and its text.
    pub version: i64,
    pub terms: String,
}

/// One statement a licence has carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub licence_id: i64,
    pub version: i64,
    pub terms: String,
    pub expires_at: Option<String>,
    pub issued_at: String,
}

/// A licence to record for a customer. `expires_at` is any date or date-time
/// SQLite reads (`2027-01-31`, `2027-01-31 12:00:00`, ISO 8601); it must be in
/// the future. `replaces` names a licence of the same customer this one
/// supersedes (recorded, not voided: see `issuance::issue`).
#[derive(Clone, Debug)]
pub struct NewLicence {
    pub terms: String,
    pub expires_at: Option<String>,
    pub replaces: Option<i64>,
}

/// Which licence and statement version a key was issued under, and the key it
/// replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLink {
    pub api_key_id: i64,
    pub licence_id: i64,
    pub licence_version: Option<i64>,
    pub replaces_key_id: Option<i64>,
}

const SELECT: &str = "SELECT l.id, l.customer_id, l.created_at, l.expires_at, l.voided_at,
        l.void_reason, l.replaces_licence_id,
        l.voided_at IS NULL
          AND (l.expires_at IS NULL OR datetime(l.expires_at) > datetime('now')),
        v.version, v.terms
 FROM licences l
 JOIN licence_versions v
   ON v.licence_id = l.id
  AND v.version = (SELECT MAX(version) FROM licence_versions WHERE licence_id = l.id)";

fn row_to_licence(row: &Row) -> Result<Licence> {
    Ok(Licence {
        id: row.get(0)?,
        customer_id: row.get(1)?,
        created_at: row.get(2)?,
        expires_at: row.get(3)?,
        voided_at: row.get(4)?,
        void_reason: row.get(5)?,
        replaces_licence_id: row.get(6)?,
        active: row.get(7)?,
        version: row.get(8)?,
        terms: row.get(9)?,
    })
}

/// Terms may carry line breaks but no other control character: they reach the
/// statement a client reads and the operator's own screen.
fn plain_terms(text: &str) -> bool {
    text.chars().all(|c| !c.is_control() || c == '\n')
}

/// An end date as SQLite normalises it, which must be in the future.
fn future_end(conn: &dyn Sql, text: &str) -> Result<String> {
    conn.query_opt(
        "SELECT datetime(?1)
         WHERE datetime(?1) IS NOT NULL AND datetime(?1) > datetime('now')",
        params![text],
        |row| row.get(0),
    )?
    .ok_or(Error::InvalidLicence)
}

fn checked_end(conn: &dyn Sql, end: Option<&str>) -> Result<Option<String>> {
    match end.map(str::trim) {
        None | Some("") => Ok(None),
        Some(text) => future_end(conn, text).map(Some),
    }
}

fn checked_terms(terms: &str) -> Result<&str> {
    let terms = terms.trim();
    if terms.len() > MAX_TERMS_BYTES || !plain_terms(terms) {
        return Err(Error::InvalidLicence);
    }
    Ok(terms)
}

/// Records a licence for customer `customer_id`, with statement version 1. The
/// terms are at most [`MAX_TERMS_BYTES`] of plain text and an end date, if
/// any, must be in the future. A licence it replaces must be the same
/// customer's.
pub fn create(conn: &dyn Sql, customer_id: i64, new: &NewLicence) -> Result<Licence> {
    let terms = checked_terms(&new.terms)?;
    let expires_at = checked_end(conn, new.expires_at.as_deref())?;
    if let Some(replaced) = new.replaces {
        let theirs: Option<i64> = conn.query_opt(
            "SELECT customer_id FROM licences WHERE id = ?1",
            params![replaced],
            |row| row.get(0),
        )?;
        match theirs {
            None => return Err(Error::LicenceNotFound),
            Some(owner) if owner != customer_id => return Err(Error::InvalidLicence),
            Some(_) => {}
        }
    }
    conn.execute(
        "INSERT INTO licences (customer_id, expires_at, replaces_licence_id)
         VALUES (?1, ?2, ?3)",
        params![customer_id, expires_at.as_deref(), new.replaces],
    )?;
    let id = conn.last_insert_rowid()?;
    conn.execute(
        "INSERT INTO licence_versions (licence_id, version, terms, expires_at)
         VALUES (?1, 1, ?2, ?3)",
        params![id, terms, expires_at.as_deref()],
    )?;
    get(conn, id)
}

/// Adds a statement version to an active licence: new terms, a new end date,
/// or both (a renewal or an amendment). The previous versions stay as they
/// were. Keys already issued are untouched (see the module documentation).
pub fn renew(
    conn: &dyn Sql,
    id: i64,
    terms: Option<&str>,
    expires_at: Option<&str>,
) -> Result<Licence> {
    let current = get(conn, id)?;
    if !current.active {
        return Err(Error::LicenceNotActive);
    }
    let terms = match terms {
        Some(text) => checked_terms(text)?.to_string(),
        None => current.terms.clone(),
    };
    let expires_at = match expires_at.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => Some(future_end(conn, text)?),
        None => current.expires_at.clone(),
    };
    if terms == current.terms && expires_at == current.expires_at {
        return Err(Error::InvalidLicence);
    }
    conn.execute(
        "INSERT INTO licence_versions (licence_id, version, terms, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![id, current.version + 1, terms.as_str(), expires_at.as_deref()],
    )?;
    conn.execute(
        "UPDATE licences SET expires_at = ?2 WHERE id = ?1",
        params![id, expires_at.as_deref()],
    )?;
    get(conn, id)
}

pub fn get(conn: &dyn Sql, id: i64) -> Result<Licence> {
    conn.query_opt(
        &format!("{SELECT} WHERE l.id = ?1"),
        params![id],
        row_to_licence,
    )?
    .ok_or(Error::LicenceNotFound)
}

/// A customer's licences, newest first.
pub fn list_for_customer(conn: &dyn Sql, customer_id: i64) -> Result<Vec<Licence>> {
    conn.query_map(
        &format!("{SELECT} WHERE l.customer_id = ?1 ORDER BY l.id DESC"),
        params![customer_id],
        row_to_licence,
    )
}

/// Every statement a licence has carried, oldest first.
pub fn versions(conn: &dyn Sql, licence_id: i64) -> Result<Vec<Version>> {
    conn.query_map(
        "SELECT licence_id, version, terms, expires_at, issued_at
         FROM licence_versions WHERE licence_id = ?1 ORDER BY version",
        params![licence_id],
        |row| {
            Ok(Version {
                licence_id: row.get(0)?,
                version: row.get(1)?,
                terms: row.get(2)?,
                expires_at: row.get(3)?,
                issued_at: row.get(4)?,
            })
        },
    )
}

/// Records that key `api_key_id` was issued under a licence, and the key it
/// replaced, if any.
pub fn link_key(conn: &dyn Sql, link: &KeyLink) -> Result<()> {
    conn.execute(
        "INSERT INTO licence_keys (api_key_id, licence_id, licence_version, replaces_key_id)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            link.api_key_id,
            link.licence_id,
            link.licence_version,
            link.replaces_key_id
        ],
    )?;
    Ok(())
}

fn row_to_link(row: &Row) -> Result<KeyLink> {
    Ok(KeyLink {
        api_key_id: row.get(0)?,
        licence_id: row.get(1)?,
        licence_version: row.get(2)?,
        replaces_key_id: row.get(3)?,
    })
}

/// The licence link of key `api_key_id`, if it has one.
pub fn link_of_key(conn: &dyn Sql, api_key_id: i64) -> Result<Option<KeyLink>> {
    conn.query_opt(
        "SELECT api_key_id, licence_id, licence_version, replaces_key_id
         FROM licence_keys WHERE api_key_id = ?1",
        params![api_key_id],
        row_to_link,
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

/// Every key link, for the console's key list.
pub fn all_links(conn: &dyn Sql) -> Result<Vec<KeyLink>> {
    conn.query_map(
        "SELECT api_key_id, licence_id, licence_version, replaces_key_id FROM licence_keys",
        params![],
        row_to_link,
    )
}

/// How many licences are active, voided and ended (neither voided nor active).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub active: i64,
    pub voided: i64,
    pub ended: i64,
}

pub fn counts(conn: &dyn Sql) -> Result<Counts> {
    conn.query_row(
        "SELECT
            COALESCE(SUM(voided_at IS NULL
                         AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))), 0),
            COALESCE(SUM(voided_at IS NOT NULL), 0),
            COALESCE(SUM(voided_at IS NULL
                         AND expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')), 0)
         FROM licences",
        params![],
        |row| {
            Ok(Counts {
                active: row.get(0)?,
                voided: row.get(1)?,
                ended: row.get(2)?,
            })
        },
    )
}

/// The customer a licence belongs to.
pub fn customer_of(conn: &dyn Sql, licence_id: i64) -> Result<Customer> {
    let id: i64 = conn
        .query_opt(
            "SELECT customer_id FROM licences WHERE id = ?1",
            params![licence_id],
            |row| row.get(0),
        )?
        .ok_or(Error::LicenceNotFound)?;
    super::customer::get(conn, id)
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
    let current = get(conn, licence.id)?;
    if !current.active {
        return Err(Error::LicenceNotActive);
    }
    let Some(expires_at) = &current.expires_at else {
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
/// header rendered from the record, then the operator's terms of this version.
pub fn statement(customer: &Customer, licence: &Licence, scope: &str, issued_at: &str) -> String {
    let mut out = format!(
        "KeyQuorum licence {} (statement {})\nLicensee: {}\nScope: {}\nIssued: {} UTC\nEnds: {}\n",
        licence.id,
        licence.version,
        customer.name,
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
