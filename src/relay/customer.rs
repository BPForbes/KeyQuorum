//! The provider's customers: the stable identity a licence and its keys hang
//! off.
//!
//! A customer is an id the provider assigns, with a name and an optional
//! reference of the provider's own (a contract or account number). Ownership
//! of a key is never inferred from a key's label, an address or a recipient
//! fingerprint: a push key has no fingerprint at all. It is a link from the key
//! to a licence (`licence_keys`) and from the licence to a customer, and a key
//! with no link is unassigned, never guessed.
//!
//! This module owns the `customers` table and the listing a console pages
//! through. It holds no bearer, key hash or sealed bytes, and the minimum
//! about a person: a name and a reference.

use super::sql::{params, Row, Sql};
use crate::error::{Error, Result};

/// The longest customer name, in characters.
pub const MAX_NAME_CHARS: usize = 200;
/// The longest reference, in characters.
pub const MAX_REFERENCE_CHARS: usize = 100;
/// The most rows a page returns.
pub const MAX_PAGE: i64 = 100;
/// The page size when none is asked for.
pub const DEFAULT_PAGE: i64 = 25;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Customer {
    pub id: i64,
    pub name: String,
    pub reference: Option<String>,
    pub created_at: String,
}

/// A customer to record.
#[derive(Clone, Debug)]
pub struct NewCustomer {
    pub name: String,
    pub reference: Option<String>,
}

/// Which customers a listing keeps, by whether they hold a licence in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenceFilter {
    All,
    /// At least one licence that is neither voided nor ended.
    WithActive,
    /// No licence in force.
    WithoutActive,
}

impl LicenceFilter {
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "all" => Ok(Self::All),
            "active" => Ok(Self::WithActive),
            "inactive" => Ok(Self::WithoutActive),
            _ => Err(Error::InvalidApiKeyRequest),
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::WithActive => "active",
            Self::WithoutActive => "inactive",
        }
    }
}

/// A customer with the counts a list row shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRow {
    pub customer: Customer,
    pub licences: i64,
    pub active_licences: i64,
    pub live_keys: i64,
    pub last_used_at: Option<String>,
}

/// A page of rows, newest first. `next_before` is the cursor for the next
/// (older) page, `None` at the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_before: Option<i64>,
}

fn row_to_customer(row: &Row) -> Result<Customer> {
    Ok(Customer {
        id: row.get(0)?,
        name: row.get(1)?,
        reference: row.get(2)?,
        created_at: row.get(3)?,
    })
}

fn plain(text: &str) -> bool {
    text.chars().all(|c| !c.is_control())
}

/// Records a customer. The name is 1 to [`MAX_NAME_CHARS`] characters of plain
/// text; a reference, if given, 1 to [`MAX_REFERENCE_CHARS`] and unique.
pub fn create(conn: &dyn Sql, new: &NewCustomer) -> Result<Customer> {
    let name = new.name.trim();
    let reference = new
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty());
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || !plain(name)
        || reference.is_some_and(|r| r.chars().count() > MAX_REFERENCE_CHARS || !plain(r))
    {
        return Err(Error::InvalidLicence);
    }
    if let Some(reference) = reference {
        let taken: Option<i64> = conn.query_opt(
            "SELECT id FROM customers WHERE reference = ?1",
            params![reference],
            |row| row.get(0),
        )?;
        if taken.is_some() {
            return Err(Error::InvalidLicence);
        }
    }
    conn.execute(
        "INSERT INTO customers (name, reference) VALUES (?1, ?2)",
        params![name, reference],
    )?;
    get(conn, conn.last_insert_rowid()?)
}

pub fn get(conn: &dyn Sql, id: i64) -> Result<Customer> {
    conn.query_opt(
        "SELECT id, name, reference, created_at FROM customers WHERE id = ?1",
        params![id],
        row_to_customer,
    )?
    .ok_or(Error::CustomerNotFound)
}

/// How many customers are recorded.
pub fn count(conn: &dyn Sql) -> Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM customers", params![], |row| row.get(0))
}

/// A `LIKE` pattern matching `term` anywhere, with the pattern characters in
/// `term` taken literally.
fn contains_pattern(term: &str) -> String {
    let mut out = String::from("%");
    for c in term.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// One page of customers, newest first, optionally filtered by a search term
/// (a substring of the name or reference) and by whether a licence is in
/// force. `before` is the cursor a previous page returned; `limit` is
/// clamped to `1..=MAX_PAGE`.
pub fn list(
    conn: &dyn Sql,
    search: Option<&str>,
    filter: LicenceFilter,
    before: Option<i64>,
    limit: Option<i64>,
) -> Result<Page<UserRow>> {
    let limit = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let pattern = search
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .map(|term| contains_pattern(&term.chars().take(MAX_NAME_CHARS).collect::<String>()));
    let mut rows = conn.query_map(
        "SELECT id, name, reference, created_at, licences, active_licences, live_keys, last_used_at
         FROM (
           SELECT c.id AS id, c.name AS name, c.reference AS reference, c.created_at AS created_at,
             (SELECT COUNT(*) FROM licences l WHERE l.customer_id = c.id) AS licences,
             (SELECT COUNT(*) FROM licences l
               WHERE l.customer_id = c.id AND l.voided_at IS NULL
                 AND (l.expires_at IS NULL OR datetime(l.expires_at) > datetime('now'))) AS active_licences,
             (SELECT COUNT(*) FROM licence_keys lk
               JOIN licences l ON l.id = lk.licence_id
               JOIN api_keys k ON k.id = lk.api_key_id
               WHERE l.customer_id = c.id AND k.revoked_at IS NULL
                 AND (k.expires_at IS NULL OR datetime(k.expires_at) > datetime('now'))) AS live_keys,
             (SELECT MAX(k.last_used_at) FROM licence_keys lk
               JOIN licences l ON l.id = lk.licence_id
               JOIN api_keys k ON k.id = lk.api_key_id
               WHERE l.customer_id = c.id) AS last_used_at
           FROM customers c
           WHERE (?1 IS NULL OR c.id < ?1)
             AND (?2 IS NULL OR c.name LIKE ?2 ESCAPE '\\' OR c.reference LIKE ?2 ESCAPE '\\')
         )
         WHERE (?3 = 'all'
                OR (?3 = 'active' AND active_licences > 0)
                OR (?3 = 'inactive' AND active_licences = 0))
         ORDER BY id DESC LIMIT ?4",
        params![before, pattern, filter.code(), limit + 1],
        |row| {
            Ok(UserRow {
                customer: Customer {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    reference: row.get(2)?,
                    created_at: row.get(3)?,
                },
                licences: row.get(4)?,
                active_licences: row.get(5)?,
                live_keys: row.get(6)?,
                last_used_at: row.get(7)?,
            })
        },
    )?;
    let next_before = if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        rows.last().map(|row| row.customer.id)
    } else {
        None
    };
    Ok(Page {
        items: rows,
        next_before,
    })
}

#[cfg(test)]
#[path = "customer/tests.rs"]
mod tests;
