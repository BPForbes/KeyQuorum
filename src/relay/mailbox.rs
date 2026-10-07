//! Opaque envelope store. The only header field used for routing is the
//! recipient X25519 public key; the sealed payload is stored verbatim.

use super::blob::{self, BlobRef};
use super::sql::{params, Row, Sql, Value};
use crate::error::{Error, Result};
use crate::keys;
use crate::private_bridge;
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
    /// The sealed letter, or, for a letter held in object storage, only its
    /// outer header (see [`super::blob`]).
    pub bytes: Vec<u8>,
    /// Where the rest is, for a held letter.
    pub blob: Option<BlobRef>,
}

/// What [`store_until_held`] did with a letter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub id: i64,
    pub recipient_fingerprint: String,
    /// The letter was already stored and ready.
    pub duplicate: bool,
    /// Set when the letter's bytes are still to be stored in object storage
    /// under this key, after which the row is marked ready.
    pub blob: Option<BlobRef>,
}

#[derive(Clone, Debug)]
pub struct MailboxPage {
    pub envelopes: Vec<StoredEnvelope>,
    pub next_after: Option<i64>,
}

pub fn store(conn: &dyn Sql, envelope: &[u8]) -> Result<(i64, String, bool)> {
    store_until(conn, envelope, None)
}

/// Store an opaque envelope, optionally with a UTC expiry
/// (`YYYY-MM-DD HH:MM:00`). The host scan and inbox pull drop expired rows.
pub fn store_until(
    conn: &dyn Sql,
    envelope: &[u8],
    expires_at: Option<&str>,
) -> Result<(i64, String, bool)> {
    let stored = store_until_held(conn, envelope, expires_at, None)?;
    Ok((stored.id, stored.recipient_fingerprint, stored.duplicate))
}

/// [`store_until`], holding the letter out of its row when it is at least
/// `hold_from` bytes: the row keeps only the outer header and is not ready
/// until the caller has stored the bytes ([`Stored::blob`], [`blob`]). A repeat
/// of a letter whose bytes were never confirmed asks for them again.
pub fn store_until_held(
    conn: &dyn Sql,
    envelope: &[u8],
    expires_at: Option<&str>,
    hold_from: Option<usize>,
) -> Result<Stored> {
    let (fingerprint, content_hash) = routing_of(envelope)?;
    let held = hold_from.is_some_and(|threshold| envelope.len() >= threshold);

    if held {
        conn.execute(
            "INSERT OR IGNORE INTO mailbox
                (recipient_fingerprint, envelope, content_hash, expires_at, blob_len, blob_ready)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![
                &fingerprint,
                blob::header_of(envelope),
                &content_hash,
                expires_at,
                envelope.len() as i64
            ],
        )?;
    } else {
        conn.execute(
            "INSERT OR IGNORE INTO mailbox
                (recipient_fingerprint, envelope, content_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![&fingerprint, envelope, &content_hash, expires_at],
        )?;
    }

    if conn.changes()? == 1 {
        return Ok(Stored {
            id: conn.last_insert_rowid()?,
            recipient_fingerprint: fingerprint,
            duplicate: false,
            blob: held.then(|| BlobRef {
                key: blob::key_of(MailTable::Inbox, &content_hash),
                len: envelope.len(),
            }),
        });
    }
    let (id, blob_len, ready): (i64, Option<i64>, i64) = conn.query_row(
        "SELECT id, blob_len, blob_ready FROM mailbox
         WHERE recipient_fingerprint = ?1 AND content_hash = ?2",
        params![&fingerprint, &content_hash],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let pending = blob_len.is_some() && ready == 0;
    Ok(Stored {
        id,
        recipient_fingerprint: fingerprint,
        duplicate: !pending,
        blob: if pending {
            blob::ref_from(MailTable::Inbox, &content_hash, blob_len)
        } else {
            None
        },
    })
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

/// The rule that decides an inbox page: at most `page` rows and
/// `MAX_INBOX_PAGE_BYTES` of sealed bytes (never fewer than one row). Rows
/// are offered in id order; the first one that does not fit decides the page,
/// so a reader holds the budget plus one letter, never every candidate.
pub(crate) struct PageBuilder<T> {
    kept: Vec<T>,
    bytes: usize,
    page: i64,
    more: bool,
}

impl<T> PageBuilder<T> {
    pub(crate) fn new(page: i64) -> Self {
        Self {
            kept: Vec::new(),
            bytes: 0,
            page,
            more: false,
        }
    }

    /// Offers the next row. `false` means the page is decided and the row was
    /// dropped (it only told the builder that more remain).
    pub(crate) fn offer(&mut self, row: T, len: usize) -> bool {
        let next = self.bytes.saturating_add(len);
        if self.kept.len() as i64 >= self.page
            || (!self.kept.is_empty() && next > MAX_INBOX_PAGE_BYTES)
        {
            self.more = true;
            return false;
        }
        self.bytes = next;
        self.kept.push(row);
        true
    }

    /// The rows kept, and `next_after` (the last row kept) whenever any was
    /// left behind.
    pub(crate) fn finish(self, id_of: impl Fn(&T) -> i64) -> (Vec<T>, Option<i64>) {
        let next_after = if self.more {
            self.kept.last().map(id_of)
        } else {
            None
        };
        (self.kept, next_after)
    }
}

/// Reads an inbox page from `rows` (in id order, each read from the store as
/// it is pulled) and stops as soon as the page is decided (see
/// [`PageBuilder`]). Both mailboxes and every backend decide a page through
/// that one builder, so the rule lives once.
#[cfg(test)]
pub(crate) fn bound_page<T, E>(
    rows: impl IntoIterator<Item = std::result::Result<T, E>>,
    page: i64,
    id_of: impl Fn(&T) -> i64,
    len_of: impl Fn(&T) -> usize,
) -> std::result::Result<(Vec<T>, Option<i64>), E> {
    let mut builder = PageBuilder::new(page);
    for row in rows {
        let row = row?;
        let len = len_of(&row);
        if !builder.offer(row, len) {
            break;
        }
    }
    Ok(builder.finish(id_of))
}

/// Runs `sql` (which must order by id and fetch one row more than `page`) and
/// decides the page as the rows stream in. Used by both mailboxes.
pub(crate) fn read_page<T>(
    conn: &dyn Sql,
    sql: &str,
    params: &[Value],
    page: i64,
    map: impl Fn(&Row) -> Result<T>,
    id_of: impl Fn(&T) -> i64,
    len_of: impl Fn(&T) -> usize,
) -> Result<(Vec<T>, Option<i64>)> {
    let mut builder = PageBuilder::new(page);
    conn.query_each(sql, params, &mut |row| {
        let item = map(row)?;
        let len = len_of(&item);
        Ok(builder.offer(item, len))
    })?;
    Ok(builder.finish(id_of))
}

pub fn list_after(
    conn: &dyn Sql,
    fingerprint: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<MailboxPage> {
    let page = page_size(limit)?;
    let after = after.unwrap_or(0);
    let fetch = page.saturating_add(1);
    purge_expired(conn)?;
    let (envelopes, next_after) = read_page(
        conn,
        "SELECT id, recipient_fingerprint, envelope, content_hash, blob_len
         FROM mailbox
         WHERE recipient_fingerprint = ?1 AND id > ?2 AND blob_ready = 1
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
         ORDER BY id ASC
         LIMIT ?3",
        params![fingerprint, after, fetch],
        page,
        |row| {
            let content_hash: String = row.get(3)?;
            Ok(StoredEnvelope {
                id: row.get(0)?,
                recipient_fingerprint: row.get(1)?,
                bytes: row.get(2)?,
                blob: blob::ref_from(MailTable::Inbox, &content_hash, row.get(4)?),
            })
        },
        |item| item.id,
        |item| item.blob.as_ref().map_or(item.bytes.len(), |held| held.len),
    )?;
    Ok(MailboxPage {
        envelopes,
        next_after,
    })
}

/// Deletes mailbox rows whose date-based TTL has passed. The sealed
/// envelope bytes live in this table, so the DELETE is what removes them
/// from disk (the SQLite file).
pub fn purge_expired(conn: &dyn Sql) -> Result<u64> {
    conn.execute(
        "DELETE FROM mailbox
         WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        params![],
    )?;
    conn.changes()
}

/// What the relay can say about a stored letter without opening it: where it
/// is filed, which kind its outer header names, how big it is and when it was
/// stored. Never the sealed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LetterSummary {
    pub id: i64,
    pub recipient_fingerprint: String,
    pub kind: Option<u8>,
    pub size: i64,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// How many letters are held and the newest `limit` (1 to 500) of them,
/// newest first. `table` is one of the two mailbox tables, never user input.
pub(crate) fn summaries_in(
    conn: &dyn Sql,
    table: MailTable,
    limit: i64,
) -> Result<(i64, Vec<LetterSummary>)> {
    let (name, column) = match table {
        MailTable::Inbox => ("mailbox", "envelope"),
        MailTable::Devices => ("device_mailbox", "package"),
    };
    let total: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {name}
             WHERE blob_ready = 1
               AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))"
        ),
        params![],
        |row| row.get(0),
    )?;
    let letters = conn.query_map(
        &format!(
            "SELECT id, recipient_fingerprint, substr({column}, 1, 6),
                    COALESCE(blob_len, length({column})), created_at, expires_at
             FROM {name}
             WHERE blob_ready = 1
               AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
             ORDER BY id DESC LIMIT ?1"
        ),
        params![limit.clamp(1, 500)],
        |row| {
            let prefix: Vec<u8> = row.get(2)?;
            Ok(LetterSummary {
                id: row.get(0)?,
                recipient_fingerprint: row.get(1)?,
                kind: crate::envelope::kind_of_prefix(&prefix),
                size: row.get(3)?,
                created_at: row.get(4)?,
                expires_at: row.get(5)?,
            })
        },
    )?;
    Ok((total, letters))
}

/// The two mailbox tables [`summaries_in`] can list, and a held letter's
/// object key is filed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailTable {
    Inbox,
    Devices,
}

/// The inbox's letters, summarised. See [`summaries_in`].
pub fn summaries(conn: &dyn Sql, limit: i64) -> Result<(i64, Vec<LetterSummary>)> {
    summaries_in(conn, MailTable::Inbox, limit)
}

#[cfg(test)]
#[path = "mailbox/tests.rs"]
mod tests;
