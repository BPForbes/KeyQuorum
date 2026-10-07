//! Opaque store for device copy, move, and relocate letters.
//!
//! Routing uses the recipient X25519 public key in the outer `KQPB` header.
//! The sealed payload is stored verbatim. Raw `KQTX` and every non-device
//! kind are refused here so this table never becomes a second bridge inbox
//! and never holds an unsealed transfer package.

use super::blob::{self, BlobRef};
use super::mailbox::{MailTable, Stored};
use super::sql::{params, Sql};
use crate::envelope::{self, routing_public_key};
use crate::error::{Error, Result};
use crate::keys;
use sha2::{Digest, Sha256};

/// Same cap as the bridge inbox. A device letter is one sealed envelope.
pub const MAX_DEVICE_PACKAGE_BYTES: usize = 1024 * 1024;

/// Every device letter and acknowledgement expires this long after it is
/// first stored. Rows are never deleted on acknowledgement (letters carry no
/// correlation the relay can read), so this TTL is what bounds storage.
pub const DEVICE_PACKAGE_TTL_DAYS: i64 = 30;

#[derive(Clone, Debug)]
pub struct StoredDevicePackage {
    pub id: i64,
    pub recipient_fingerprint: String,
    /// The sealed letter, or only its outer header when it is held in object
    /// storage (see [`super::blob`]).
    pub bytes: Vec<u8>,
    /// Where the rest is, for a held letter.
    pub blob: Option<BlobRef>,
}

#[derive(Clone, Debug)]
pub struct DeviceMailPage {
    pub packages: Vec<StoredDevicePackage>,
    pub next_after: Option<i64>,
}

/// What this mailbox accepts: a sealed device letter (kinds 9 to 12) within
/// the size cap, never a raw `KQTX` or a bridge letter. Returns where it is
/// filed (the recipient fingerprint) and its content hash.
pub(crate) fn check_package(package: &[u8]) -> Result<(String, String)> {
    if package.len() > MAX_DEVICE_PACKAGE_BYTES {
        return Err(Error::BundleFieldTooLarge);
    }
    if package.starts_with(b"KQTX") {
        return Err(Error::InvalidBridgePackage);
    }
    let kind = envelope::kind(package)?;
    if !envelope::is_device_workflow_kind(kind) {
        return Err(Error::InvalidBridgePackage);
    }
    let recipient_public_key = routing_public_key(package)?;
    let fingerprint = keys::fingerprint(&recipient_public_key);
    let content_hash = hex::encode(Sha256::digest(package));
    Ok((fingerprint, content_hash))
}

pub fn store(conn: &dyn Sql, package: &[u8]) -> Result<(i64, String, bool)> {
    let stored = store_held(conn, package, None)?;
    Ok((stored.id, stored.recipient_fingerprint, stored.duplicate))
}

/// [`store`], holding the letter out of its row when it is at least
/// `hold_from` bytes. See [`super::mailbox::store_until_held`].
pub fn store_held(conn: &dyn Sql, package: &[u8], hold_from: Option<usize>) -> Result<Stored> {
    let (fingerprint, content_hash) = check_package(package)?;
    let held = hold_from.is_some_and(|threshold| package.len() >= threshold);

    purge_expired(conn)?;
    if held {
        conn.execute(
            "INSERT OR IGNORE INTO device_mailbox
                (recipient_fingerprint, package, content_hash, expires_at, blob_len, blob_ready)
             VALUES (?1, ?2, ?3, datetime('now', ?4), ?5, 0)",
            params![
                &fingerprint,
                blob::header_of(package),
                &content_hash,
                ttl_modifier(),
                package.len() as i64
            ],
        )?;
    } else {
        conn.execute(
            "INSERT OR IGNORE INTO device_mailbox
                (recipient_fingerprint, package, content_hash, expires_at)
             VALUES (?1, ?2, ?3, datetime('now', ?4))",
            params![&fingerprint, package, &content_hash, ttl_modifier()],
        )?;
    }

    if conn.changes()? == 1 {
        return Ok(Stored {
            id: conn.last_insert_rowid()?,
            recipient_fingerprint: fingerprint,
            duplicate: false,
            blob: held.then(|| BlobRef {
                key: blob::key_of(MailTable::Devices, &content_hash),
                len: package.len(),
            }),
        });
    }
    let (id, blob_len, ready): (i64, Option<i64>, i64) = conn.query_row(
        "SELECT id, blob_len, blob_ready FROM device_mailbox
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
            blob::ref_from(MailTable::Devices, &content_hash, blob_len)
        } else {
            None
        },
    })
}

pub fn list_after(
    conn: &dyn Sql,
    fingerprint: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<DeviceMailPage> {
    let page = super::mailbox::page_size(limit)?;
    let after = after.unwrap_or(0);
    let fetch = page.saturating_add(1);
    purge_expired(conn)?;
    let (packages, next_after) = super::mailbox::read_page(
        conn,
        "SELECT id, recipient_fingerprint, package, content_hash, blob_len
         FROM device_mailbox
         WHERE recipient_fingerprint = ?1 AND id > ?2 AND blob_ready = 1
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
         ORDER BY id ASC
         LIMIT ?3",
        params![fingerprint, after, fetch],
        page,
        |row| {
            let content_hash: String = row.get(3)?;
            Ok(StoredDevicePackage {
                id: row.get(0)?,
                recipient_fingerprint: row.get(1)?,
                bytes: row.get(2)?,
                blob: blob::ref_from(MailTable::Devices, &content_hash, row.get(4)?),
            })
        },
        |item| item.id,
        |item| item.blob.as_ref().map_or(item.bytes.len(), |held| held.len),
    )?;
    Ok(DeviceMailPage {
        packages,
        next_after,
    })
}

/// Deletes device letters whose TTL has passed. The sealed bytes live in
/// this table, so the DELETE is what removes them from the relay database.
pub fn purge_expired(conn: &dyn Sql) -> Result<u64> {
    conn.execute(
        "DELETE FROM device_mailbox
         WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        params![],
    )?;
    conn.changes()
}

/// The device mailbox's letters, summarised: the count and the newest
/// `limit`, newest first. See [`super::mailbox::summaries_in`].
pub fn summaries(conn: &dyn Sql, limit: i64) -> Result<(i64, Vec<super::mailbox::LetterSummary>)> {
    super::mailbox::summaries_in(conn, super::mailbox::MailTable::Devices, limit)
}

/// Rows stored before device retention have no `expires_at`. Give them the
/// same TTL, counted from when they were stored.
pub(crate) fn backfill_expiry(conn: &dyn Sql) -> Result<()> {
    conn.execute(
        "UPDATE device_mailbox
         SET expires_at = datetime(created_at, ?1)
         WHERE expires_at IS NULL",
        params![ttl_modifier()],
    )?;
    Ok(())
}

fn ttl_modifier() -> String {
    format!("+{DEVICE_PACKAGE_TTL_DAYS} days")
}

#[cfg(test)]
#[path = "device_mail/tests.rs"]
mod tests;
