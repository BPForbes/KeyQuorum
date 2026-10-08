//! Sealed letters held in object storage (R2) instead of a table row.
//!
//! The relay never opens a letter, so where its bytes live is a question of
//! capacity, not of trust. This module owns the bookkeeping of a letter held
//! out of its row and nothing about the object store itself: the relay core
//! has no network and no clock, and the object store's API is asynchronous, so
//! the Durable Object's JavaScript does the transfers and this module says
//! what must be transferred and when it is safe.
//!
//! A held letter is a row whose `envelope`/`package` column holds only the
//! 42-byte outer header (so routing, kind and size still work) and whose
//! `blob_len` is the letter's true length. Its object key is
//! `inbox/<sha256>` or `device/<sha256>`, the hash being the same content hash
//! that makes delivery idempotent, so one letter is one immutable object.
//!
//! Accepting a held letter is two steps because a row and an object cannot
//! commit together:
//!
//! 1. The store authenticates, validates and inserts the row *not ready*
//!    (`blob_ready = 0`), and says which key to store the bytes under. Nothing
//!    has been written to the object store before the request was authorised,
//!    so an unauthorised request can never fill it.
//! 2. The caller stores the object, then [`mark_ready`]. If storing fails it
//!    calls [`abort`]. A row left not ready by a crash is dropped by
//!    [`drop_stale_pending`].
//!
//! A not-ready row is never listed, counted or offered, so a reader never meets
//! a letter whose object may not exist. Deleting a held row, by any path,
//! records its key in `blob_tombstones` (a trigger, so no path can forget);
//! [`tombstones`] hands out only keys no live row still names, and
//! [`tombstones_done`] forgets them once the object is deleted.

use super::mailbox::MailTable;
use super::sql::{params, Sql};
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// The length of a `KQPB`/`KQXB` outer header: magic, version, kind,
/// recipient public key and sealed length. All a held row keeps.
pub const HEADER_LEN: usize = 42;

/// Where a held letter's bytes go, and how many there are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub key: String,
    pub len: usize,
}

/// The object key of a letter with content hash `content_hash`.
pub fn key_of(table: MailTable, content_hash: &str) -> String {
    format!("{}/{content_hash}", prefix(table))
}

fn prefix(table: MailTable) -> &'static str {
    match table {
        MailTable::Inbox => "inbox",
        MailTable::Devices => "device",
    }
}

pub(crate) fn name_of(table: MailTable) -> &'static str {
    match table {
        MailTable::Inbox => "mailbox",
        MailTable::Devices => "device_mailbox",
    }
}

/// What a row holds in place of a letter held out of it.
pub(crate) fn header_of(letter: &[u8]) -> &[u8] {
    &letter[..letter.len().min(HEADER_LEN)]
}

/// The row is ready: its object is stored. Only a not-ready held row changes.
pub fn mark_ready(conn: &dyn Sql, table: MailTable, id: i64) -> Result<bool> {
    conn.execute(
        &format!(
            "UPDATE {} SET blob_ready = 1
             WHERE id = ?1 AND blob_len IS NOT NULL AND blob_ready = 0",
            name_of(table)
        ),
        params![id],
    )?;
    Ok(conn.changes()? == 1)
}

/// The object could not be stored: drop the not-ready row so the sender's
/// retry starts clean. A ready row is never touched.
pub fn abort(conn: &dyn Sql, table: MailTable, id: i64) -> Result<bool> {
    conn.execute(
        &format!(
            "DELETE FROM {} WHERE id = ?1 AND blob_len IS NOT NULL AND blob_ready = 0",
            name_of(table)
        ),
        params![id],
    )?;
    Ok(conn.changes()? == 1)
}

/// Drops held rows still not ready after `minutes`: a crash between the two
/// steps. Their keys are tombstoned like any other, so a half-stored object
/// is cleaned up too. Returns how many.
pub fn drop_stale_pending(conn: &dyn Sql, minutes: i64) -> Result<u64> {
    let modifier = format!("-{} minutes", minutes.clamp(1, 7 * 24 * 60));
    let mut dropped = 0;
    for table in [MailTable::Inbox, MailTable::Devices] {
        conn.execute(
            &format!(
                "DELETE FROM {} WHERE blob_len IS NOT NULL AND blob_ready = 0
                 AND datetime(created_at) <= datetime('now', ?1)",
                name_of(table)
            ),
            params![&modifier],
        )?;
        dropped += conn.changes()?;
    }
    Ok(dropped)
}

/// Keys of objects to delete: dropped, and named by no live row. At most
/// `limit` (1 to 1000), oldest first.
pub fn tombstones(conn: &dyn Sql, limit: i64) -> Result<Vec<String>> {
    conn.query_map(
        "SELECT blob_key FROM blob_tombstones t
         WHERE NOT EXISTS (SELECT 1 FROM mailbox m
                           WHERE m.blob_len IS NOT NULL AND 'inbox/' || m.content_hash = t.blob_key)
           AND NOT EXISTS (SELECT 1 FROM device_mailbox d
                           WHERE d.blob_len IS NOT NULL AND 'device/' || d.content_hash = t.blob_key)
         ORDER BY dropped_at ASC, blob_key ASC LIMIT ?1",
        params![limit.clamp(1, 1000)],
        |row| row.get(0),
    )
}

/// The objects at `keys` are deleted: forget their tombstones, except a key a
/// live row names again (the same letter stored anew meanwhile).
pub fn tombstones_done(conn: &dyn Sql, keys: &[String]) -> Result<u64> {
    let mut done = 0;
    for key in keys {
        conn.execute(
            "DELETE FROM blob_tombstones WHERE blob_key = ?1
               AND NOT EXISTS (SELECT 1 FROM mailbox m
                               WHERE m.blob_len IS NOT NULL AND 'inbox/' || m.content_hash = ?1)
               AND NOT EXISTS (SELECT 1 FROM device_mailbox d
                               WHERE d.blob_len IS NOT NULL AND 'device/' || d.content_hash = ?1)",
            params![key],
        )?;
        done += conn.changes()?;
    }
    Ok(done)
}

/// A held row's reference, from its columns, or `None` for an inline row.
pub(crate) fn ref_from(
    table: MailTable,
    content_hash: &str,
    blob_len: Option<i64>,
) -> Option<BlobRef> {
    blob_len.map(|len| BlobRef {
        key: key_of(table, content_hash),
        len: usize::try_from(len).unwrap_or(0),
    })
}

#[cfg(test)]
#[path = "blob/tests.rs"]
mod tests;
