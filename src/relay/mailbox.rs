//! Opaque envelope store. The only header field used for routing is the
//! recipient X25519 public key; the sealed payload is stored verbatim.

use crate::error::{Error, Result};
use crate::keys;
use crate::private_bridge;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

/// Default `GET /inbox` page when `limit` is omitted.
pub const DEFAULT_INBOX_PAGE: i64 = 100;
/// Hard cap on a single inbox read. Keep in sync with `Error::InvalidInboxPage`.
pub const MAX_INBOX_PAGE: i64 = 500;
/// Hard cap on the sealed bytes of one inbox read, so a page of letters at
/// `service::MAX_ENVELOPE_BYTES` each cannot outgrow the relay's memory or
/// the client's `relay::client::MAX_RESPONSE_BYTES` once encoded. A page that
/// stops here reports `next_after`, so the rest is read by the next pull. The
/// first letter is always returned, so no letter is ever unreadable.
pub const MAX_INBOX_PAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct StoredEnvelope {
    pub id: i64,
    pub recipient_fingerprint: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MailboxPage {
    pub envelopes: Vec<StoredEnvelope>,
    pub next_after: Option<i64>,
}

pub fn store(conn: &Connection, envelope: &[u8]) -> Result<(i64, String, bool)> {
    store_until(conn, envelope, None)
}

/// Store an opaque envelope, optionally with a UTC expiry
/// (`YYYY-MM-DD HH:MM:00`). The host scan and inbox pull drop expired rows.
pub fn store_until(
    conn: &Connection,
    envelope: &[u8],
    expires_at: Option<&str>,
) -> Result<(i64, String, bool)> {
    let (fingerprint, content_hash) = routing_of(envelope)?;

    conn.execute(
        "INSERT OR IGNORE INTO mailbox
            (recipient_fingerprint, envelope, content_hash, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![fingerprint, envelope, content_hash, expires_at],
    )?;

    if conn.changes() == 1 {
        Ok((conn.last_insert_rowid(), fingerprint, false))
    } else {
        let id: i64 = conn.query_row(
            "SELECT id FROM mailbox
             WHERE recipient_fingerprint = ?1 AND content_hash = ?2",
            params![fingerprint, content_hash],
            |row| row.get(0),
        )?;
        Ok((id, fingerprint, true))
    }
}

/// Where a bridge letter is filed (the recipient fingerprint from its outer
/// header) and what makes a repeat of it the same letter (its SHA-256).
/// Device letters (kinds 9 to 12) are refused: they have their own mailbox.
pub(crate) fn routing_of(envelope: &[u8]) -> Result<(String, String)> {
    let kind = crate::envelope::kind(envelope)?;
    if crate::envelope::is_device_workflow_kind(kind) {
        return Err(Error::InvalidBridgePackage);
    }
    let recipient_public_key = private_bridge::routing_public_key(envelope)?;
    let fingerprint = keys::fingerprint(&recipient_public_key);
    let content_hash = hex::encode(Sha256::digest(envelope));
    Ok((fingerprint, content_hash))
}

/// The page size a pull asked for: `DEFAULT_INBOX_PAGE` when omitted, else
/// 1 to `MAX_INBOX_PAGE`.
pub(crate) fn page_size(limit: Option<i64>) -> Result<i64> {
    match limit {
        None => Ok(DEFAULT_INBOX_PAGE),
        Some(n) if (1..=MAX_INBOX_PAGE).contains(&n) => Ok(n),
        Some(_) => Err(Error::InvalidInboxPage),
    }
}

/// Reads an inbox page from `rows` (in id order, each read from the store as
/// it is pulled) and stops as soon as the page is decided: at most `page`
/// rows and `MAX_INBOX_PAGE_BYTES` of sealed bytes (never fewer than one row).
/// The row that does not fit is read to learn that more remain and then
/// dropped, so a store holds the budget plus one letter, never every
/// candidate; `next_after` is the last row kept whenever any was left behind.
/// Both mailboxes and both backends use this, so the rule lives once.
pub(crate) fn bound_page<T, E>(
    rows: impl IntoIterator<Item = std::result::Result<T, E>>,
    page: i64,
    id_of: impl Fn(&T) -> i64,
    len_of: impl Fn(&T) -> usize,
) -> std::result::Result<(Vec<T>, Option<i64>), E> {
    let mut kept = Vec::new();
    let mut bytes = 0usize;
    let mut more = false;
    for row in rows {
        let row = row?;
        let next = bytes.saturating_add(len_of(&row));
        if kept.len() as i64 >= page || (!kept.is_empty() && next > MAX_INBOX_PAGE_BYTES) {
            more = true;
            break;
        }
        bytes = next;
        kept.push(row);
    }
    let next_after = if more { kept.last().map(id_of) } else { None };
    Ok((kept, next_after))
}

pub fn list_after(
    conn: &Connection,
    fingerprint: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<MailboxPage> {
    let page = page_size(limit)?;
    let after = after.unwrap_or(0);
    let fetch = page.saturating_add(1);
    purge_expired(conn)?;
    let mut stmt = conn.prepare(
        "SELECT id, recipient_fingerprint, envelope
         FROM mailbox
         WHERE recipient_fingerprint = ?1 AND id > ?2
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
         ORDER BY id ASC
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![fingerprint, after, fetch], |row| {
        Ok(StoredEnvelope {
            id: row.get(0)?,
            recipient_fingerprint: row.get(1)?,
            bytes: row.get(2)?,
        })
    })?;
    let (envelopes, next_after) = bound_page(rows, page, |item| item.id, |item| item.bytes.len())?;
    Ok(MailboxPage {
        envelopes,
        next_after,
    })
}

/// Deletes mailbox rows whose date-based TTL has passed. The sealed
/// envelope bytes live in this table, so the DELETE is what removes them
/// from disk (the SQLite file).
pub fn purge_expired(conn: &Connection) -> Result<u64> {
    conn.execute(
        "DELETE FROM mailbox
         WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        [],
    )?;
    Ok(conn.changes())
}

#[cfg(test)]
#[path = "mailbox/tests.rs"]
mod tests;
