//! Hardware-key-quorum file protection: encrypts a file under a random
//! data key, then splits that key via `key_tree::split` so unlocking the
//! file means reconstructing that key's tree — a flat "M-of-N hardware
//! keys" quorum is just the simplest possible tree shape.

use crate::authority::{self, UnlockGrant};
use crate::crypto::{self, NONCE_LEN};
use crate::device;
use crate::error::{Error, Result};
use crate::key_tree::{self, NodeSpec, TreeSummary};
use crate::storage::{NativeStorage, Storage};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

pub struct FileStatus {
    pub id: i64,
    pub name: String,
    pub encrypted_path: String,
    pub created_at: String,
    /// UTC cutoff (`YYYY-MM-DD HH:MM:00`) after which the file is treated
    /// as expired. `None` if the file never expires.
    pub expires_at: Option<String>,
    pub tree: TreeSummary,
}

/// Encrypts `source_path` under a fresh random data key and splits that
/// key per `tree_spec`. The ciphertext is written first, outside any
/// database transaction (mirroring `locked_files::lock_file`'s reasoning:
/// `create_new` fails atomically if `encrypted_path` is already in use,
/// and this keeps the write lock held only for the DB work that follows).
/// The key-tree build and the `files` row insert happen in one
/// transaction, so a failure partway through never leaves a `files` row
/// pointing at an incomplete tree, or vice versa; on any failure the
/// just-written ciphertext file is removed too.
pub fn lock_file(
    conn: &mut Connection,
    source_path: &Path,
    encrypted_path: &Path,
    name: Option<&str>,
    tree_spec: &NodeSpec,
) -> Result<i64> {
    key_tree::validate(conn, tree_spec)?;
    let plaintext = fs::read(source_path)?;
    let name = name.map(str::to_owned).unwrap_or_else(|| {
        source_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    lock_bytes_in(
        &mut NativeStorage,
        conn,
        &plaintext,
        encrypted_path,
        &name,
        tree_spec,
    )
}

/// [`lock_file`] for plaintext already in memory, writing the ciphertext
/// through `storage`. The browser lab locks its seeded files this way.
pub fn lock_bytes_in(
    storage: &mut dyn Storage,
    conn: &mut Connection,
    plaintext: &[u8],
    encrypted_path: &Path,
    name: &str,
    tree_spec: &NodeSpec,
) -> Result<i64> {
    lock_bytes_until_in(
        storage,
        conn,
        plaintext,
        encrypted_path,
        name,
        tree_spec,
        None,
    )
}

/// [`lock_bytes_in`], plus a UTC expiry (`YYYY-MM-DD HH:MM:00`; parse one
/// with `locked_files::parse_expires_utc`). After that instant,
/// [`complete_unlock_in`] deletes the ciphertext and the `files` row
/// instead of decrypting — same TTL convention as
/// `locked_files::lock_file_until`, kept as a separate table because a
/// quorum-protected file's expiry sits next to its key tree, not a KDF salt.
pub fn lock_bytes_until_in(
    storage: &mut dyn Storage,
    conn: &mut Connection,
    plaintext: &[u8],
    encrypted_path: &Path,
    name: &str,
    tree_spec: &NodeSpec,
    expires_at: Option<&str>,
) -> Result<i64> {
    key_tree::validate(conn, tree_spec)?;
    let encrypted_path_str = encrypted_path.to_str().ok_or(Error::InvalidPath)?;

    let data_key = crypto::random_key();
    let nonce = crypto::random_nonce();
    let ciphertext = crypto::encrypt(&data_key, &nonce, plaintext);

    storage.write_new(encrypted_path, &ciphertext)?;

    let result = (|| -> Result<i64> {
        let tx = conn.transaction()?;
        let key_id = key_tree::build_tree(&tx, name, &data_key[..], tree_spec)?;
        tx.execute(
            "INSERT INTO files (name, encrypted_path, key_id, nonce, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, encrypted_path_str, key_id, nonce.to_vec(), expires_at],
        )?;
        let file_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(file_id)
    })();

    // Everything that can fail — starting the transaction, building the
    // key tree, the insert, the commit — lives inside the closure above
    // and flows through this one `result`, so the just-written ciphertext
    // is always cleaned up on any failure, including one that happens
    // before a transaction ever opens (e.g. `conn` already has one active).
    if result.is_err() {
        let _ = storage.delete(encrypted_path);
    }
    result
}

/// Set (or clear, with `None`) a quorum-protected file's date-based TTL.
/// Does not check the value is in the future; callers wanting that call
/// `locked_files::require_future_expires_utc` first.
pub fn set_expires_at(conn: &Connection, file_id: i64, expires_at: Option<&str>) -> Result<()> {
    conn.query_row(
        "SELECT id FROM files WHERE id = ?1",
        params![file_id],
        |_| Ok(()),
    )?;
    conn.execute(
        "UPDATE files SET expires_at = ?1 WHERE id = ?2",
        params![expires_at, file_id],
    )?;
    Ok(())
}

/// Whether this file's TTL has passed, without deleting anything — for
/// display, so a file listing can show "expired" before anyone attempts to
/// open it. `false` for a file with no expiry.
pub fn is_expired(conn: &Connection, file_id: i64) -> Result<bool> {
    conn.query_row(
        "SELECT expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')
         FROM files WHERE id = ?1",
        params![file_id],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// If this file's date-based TTL has passed, delete the ciphertext and the
/// `files` row (which cascades its `unlock_events`). No-op when the file
/// has no expiry, is still live, or was already purged.
pub fn purge_if_expired_in(
    storage: &mut dyn Storage,
    conn: &Connection,
    file_id: i64,
) -> Result<()> {
    let row: Option<(String, bool)> = conn
        .query_row(
            "SELECT encrypted_path,
                    expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')
             FROM files WHERE id = ?1",
            params![file_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((encrypted_path, expired)) = row else {
        return Ok(());
    };
    if !expired {
        return Ok(());
    }
    let _ = storage.delete(Path::new(&encrypted_path));
    conn.execute("DELETE FROM files WHERE id = ?1", params![file_id])?;
    Err(Error::FileExpired)
}

/// [`purge_if_expired_in`] against the native filesystem.
pub fn purge_if_expired(conn: &Connection, file_id: i64) -> Result<()> {
    purge_if_expired_in(&mut NativeStorage, conn, file_id)
}

/// Deletes every quorum-protected file whose date-based TTL has passed.
pub fn purge_expired_in(storage: &mut dyn Storage, conn: &Connection) -> Result<u64> {
    let mut stmt = conn.prepare(
        "SELECT id, encrypted_path FROM files
         WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')",
    )?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<(i64, String)>>>()?;
    drop(stmt);
    let mut purged = 0u64;
    for (file_id, encrypted_path) in rows {
        let _ = storage.delete(Path::new(&encrypted_path));
        conn.execute("DELETE FROM files WHERE id = ?1", params![file_id])?;
        purged += 1;
    }
    Ok(purged)
}

/// [`purge_expired_in`] against the native filesystem.
pub fn purge_expired(conn: &Connection) -> Result<u64> {
    purge_expired_in(&mut NativeStorage, conn)
}

pub fn status(conn: &Connection, file_id: i64) -> Result<FileStatus> {
    let (name, encrypted_path, key_id, created_at, expires_at): (
        String,
        String,
        i64,
        String,
        Option<String>,
    ) = conn.query_row(
        "SELECT name, encrypted_path, key_id, created_at, expires_at FROM files WHERE id = ?1",
        params![file_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let tree = key_tree::describe(conn, key_id)?;

    Ok(FileStatus {
        id: file_id,
        name,
        encrypted_path,
        created_at,
        expires_at,
        tree,
    })
}

/// `raw_shares` maps a leaf `key_nodes.id` to its already-unwrapped raw
/// share bytes — see `key_tree`'s module doc comment for why obtaining
/// them is the caller's responsibility. A key file with no placement is
/// one device; slots that share a container are not.
pub fn unlock_file(
    conn: &Connection,
    file_id: i64,
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    unlock_file_with_approval(conn, file_id, raw_shares, &[])
}

/// Same as [`unlock_file`], plus parent signatures when the tree's
/// `unlock_approval` policy asks for them.
pub fn unlock_file_with_approval(
    conn: &Connection,
    file_id: i64,
    raw_shares: &HashMap<i64, Vec<u8>>,
    grants: &[UnlockGrant],
) -> Result<Vec<u8>> {
    // Same as `locked_files::unlock_file`: the TTL is checked before any
    // share is even looked at, so an expired file is destroyed on the
    // first unlock *attempt* — including one whose shares never reconstruct
    // — rather than only on a full, successful quorum (which the purge
    // embedded in `complete_unlock_in` alone would require, since a failed
    // `reconstruct_presented` below returns before ever reaching it).
    purge_if_expired(conn, file_id)?;
    let key_id: i64 = conn.query_row(
        "SELECT key_id FROM files WHERE id = ?1",
        params![file_id],
        |row| row.get(0),
    )?;
    let presented = match key_tree::reconstruct_presented(conn, key_id, raw_shares) {
        Ok(presented) => presented,
        Err(err) => {
            let _ = record_unlock_failure(conn, file_id, &err);
            return Err(err);
        }
    };
    complete_unlock(conn, file_id, presented, grants)
}

/// Write the same failed `unlock_events` row the unlock path writes when
/// reconstruction fails before [`complete_unlock`] runs.
pub fn record_unlock_failure(conn: &Connection, file_id: i64, err: &Error) -> Result<()> {
    conn.execute(
        "INSERT INTO unlock_events (file_id, success, keys_presented) VALUES (?1, 0, ?2)",
        params![file_id, format!("failed: {err}")],
    )?;
    Ok(())
}

/// Decrypt with an already reconstructed secret and write one audit row.
/// Callers that fail while building approval grants record that failure
/// themselves so the secret is not reconstructed a second time.
pub fn complete_unlock(
    conn: &Connection,
    file_id: i64,
    presented: key_tree::PresentedReconstruction,
    grants: &[UnlockGrant],
) -> Result<Vec<u8>> {
    complete_unlock_in(&mut NativeStorage, conn, file_id, presented, grants)
}

/// [`complete_unlock`], reading the ciphertext through `storage` — and, if
/// the file's TTL has passed, deleting it through `storage` instead of
/// decrypting (see [`purge_if_expired_in`]).
pub fn complete_unlock_in(
    storage: &mut dyn Storage,
    conn: &Connection,
    file_id: i64,
    presented: key_tree::PresentedReconstruction,
    grants: &[UnlockGrant],
) -> Result<Vec<u8>> {
    let audit_devices = device::format_presentation(&presented.devices);
    let secret = Zeroizing::new(presented.secret);
    let result = decrypt_presented(
        storage,
        conn,
        file_id,
        secret.as_slice(),
        &presented.leaves,
        &presented.devices,
        grants,
    );
    let keys_presented = match &result {
        Ok(_) => audit_devices,
        Err(err) => format!("failed: {err}"),
    };
    let _ = conn.execute(
        "INSERT INTO unlock_events (file_id, success, keys_presented) VALUES (?1, ?2, ?3)",
        params![file_id, result.is_ok() as i64, keys_presented],
    );
    result
}

fn decrypt_presented(
    storage: &mut dyn Storage,
    conn: &Connection,
    file_id: i64,
    secret: &[u8],
    leaves: &[device::UsedLeaf],
    devices: &[device::PresentedDevice],
    grants: &[UnlockGrant],
) -> Result<Vec<u8>> {
    purge_if_expired_in(storage, conn, file_id)?;
    let (encrypted_path, key_id, nonce): (String, i64, Vec<u8>) = conn.query_row(
        "SELECT encrypted_path, key_id, nonce FROM files WHERE id = ?1",
        params![file_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    authority::require_unlock_approval(conn, key_id, file_id, leaves, devices, grants)?;
    let data_key: Zeroizing<[u8; crypto::KEY_LEN]> =
        Zeroizing::new(secret.try_into().map_err(|_| Error::QuorumNotMet)?);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::IntegrityCheckFailed)?;
    let ciphertext = storage.read(Path::new(&encrypted_path))?;
    crypto::decrypt(&data_key, &nonce, &ciphertext).map_err(|_| Error::IntegrityCheckFailed)
}

#[cfg(test)]
#[path = "quorum/tests.rs"]
mod tests;
