//! Opaque store for device copy, move, and relocate letters.
//!
//! Routing uses the recipient X25519 public key in the outer `KQPB` header.
//! The sealed payload is stored verbatim. Raw `KQTX` and every non-device
//! kind are refused here so this table never becomes a second bridge inbox
//! and never holds an unsealed transfer package.

use super::mailbox::{DEFAULT_INBOX_PAGE, MAX_INBOX_PAGE};
use crate::envelope::{self, routing_public_key};
use crate::error::{Error, Result};
use crate::keys;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

/// Same cap as the bridge inbox. A device letter is one sealed envelope.
pub const MAX_DEVICE_PACKAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct StoredDevicePackage {
    pub id: i64,
    pub recipient_fingerprint: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DeviceMailPage {
    pub packages: Vec<StoredDevicePackage>,
    pub next_after: Option<i64>,
}

pub fn store(conn: &Connection, package: &[u8]) -> Result<(i64, String, bool)> {
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

    conn.execute(
        "INSERT OR IGNORE INTO device_mailbox
            (recipient_fingerprint, package, content_hash)
         VALUES (?1, ?2, ?3)",
        params![fingerprint, package, content_hash],
    )?;

    if conn.changes() == 1 {
        Ok((conn.last_insert_rowid(), fingerprint, false))
    } else {
        let id: i64 = conn.query_row(
            "SELECT id FROM device_mailbox
             WHERE recipient_fingerprint = ?1 AND content_hash = ?2",
            params![fingerprint, content_hash],
            |row| row.get(0),
        )?;
        Ok((id, fingerprint, true))
    }
}

pub fn list_after(
    conn: &Connection,
    fingerprint: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<DeviceMailPage> {
    let page = match limit {
        None => DEFAULT_INBOX_PAGE,
        Some(n) if (1..=MAX_INBOX_PAGE).contains(&n) => n,
        Some(_) => return Err(Error::InvalidInboxPage),
    };
    let after = after.unwrap_or(0);
    let fetch = page.saturating_add(1);
    let mut stmt = conn.prepare(
        "SELECT id, recipient_fingerprint, package
         FROM device_mailbox
         WHERE recipient_fingerprint = ?1 AND id > ?2
         ORDER BY id ASC
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![fingerprint, after, fetch], |row| {
        Ok(StoredDevicePackage {
            id: row.get(0)?,
            recipient_fingerprint: row.get(1)?,
            bytes: row.get(2)?,
        })
    })?;
    let mut packages = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let next_after = if packages.len() > page as usize {
        packages.pop();
        packages.last().map(|item| item.id)
    } else {
        None
    };
    Ok(DeviceMailPage {
        packages,
        next_after,
    })
}

#[cfg(test)]
#[path = "device_mail/tests.rs"]
mod tests;
