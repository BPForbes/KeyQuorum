//! Sealed backups of the relay's database (`docs/operator/r2-backups.md`).
//!
//! A backup is a logical dump of every table, cut into chunks, each sealed to
//! the operator's backup key (an X25519 public key; the private half stays with
//! the operator, offline) and listed in a manifest that the relay signs with its
//! own key. Cloudflare, R2 and the relay itself can therefore write a backup and
//! never read one: the customer names, licence terms, key hashes and the audit
//! chain inside are readable only by whoever holds the backup key, and the
//! operator can prove each backup came from the relay and is whole.
//!
//! The relay core has no network and no clock, so it builds a snapshot whole and
//! synchronously ([`snapshot`], one Durable Object turn: nothing else runs
//! between the first row and the last, so the snapshot is consistent) and the
//! Durable Object's JavaScript uploads the pieces, the manifest last. That bounds
//! what a backup can be: the snapshot lives in memory, so [`snapshot`] refuses a
//! database over `max_bytes` ([`Error::BackupTooLarge`]) and the object reports it
//! rather than run out of its 128 MB. Letters held in object storage are not in a
//! backup, only their rows (which name the objects); they are transient mail.
//!
//! Restoring ([`restore`]) is offline, into an empty relay database, and checks
//! everything before it trusts anything: the manifest opens with the backup key,
//! its signature verifies under the key a root-signed, unrevoked certificate
//! names, every chunk matches its SHA-256, and afterwards the audit chains are
//! re-walked. Rows that held a letter out in object storage are not restored
//! (their objects are not in the backup), and are counted.

use super::audit;
use super::service::ProviderIdentity;
use super::sql::{params, Sql, Value};
use crate::envelope::{self, EXPORT_BUNDLE};
use crate::error::{Error, Result};
use crate::export::{BUNDLE_TYPE_BACKUP_CHUNK, BUNDLE_TYPE_BACKUP_MANIFEST};
use crate::{provider, signing};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// The format of the manifest body and of a chunk's plaintext.
const VERSION: u32 = 1;
/// A chunk's plaintext is cut near this size.
pub const CHUNK_TARGET_BYTES: usize = 4 * 1024 * 1024;
/// Rows read from a table at a time.
const READ_ROWS: i64 = 200;
/// A sealed object is never larger than this, so a manifest or chunk read back
/// from a bucket is bounded.
pub const MAX_OBJECT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct ChunkRef {
    seq: u32,
    object: String,
    sha256: String,
    bytes: u64,
    rows: u64,
}

#[derive(Serialize, Deserialize)]
struct TableEntry {
    name: String,
    columns: Vec<String>,
    rows: u64,
    chunks: Vec<ChunkRef>,
}

#[derive(Serialize, Deserialize)]
struct Body {
    version: u32,
    backup_id: String,
    taken_at: String,
    relay_serial: String,
    tables: Vec<TableEntry>,
}

/// What the manifest carries: the body as signed (kept as the exact text, so
/// nothing depends on how JSON is re-serialised), the signature, and the
/// certificate that names the signing key.
#[derive(Serialize, Deserialize)]
struct SignedManifest {
    body_json: String,
    signature: String,
    certificate: String,
}

/// A backup, built and sealed, ready to be stored: the chunks, then the
/// manifest.
pub struct Snapshot {
    /// `YYYYMMDDHHMMSSmmm-xxxxxxxx`, so backups sort by time.
    pub backup_id: String,
    /// `(object name, sealed bytes)` for each chunk, in order.
    pub objects: Vec<(String, Vec<u8>)>,
    pub manifest_name: String,
    pub manifest: Vec<u8>,
    pub tables: usize,
    pub rows: u64,
}

/// What a backup says of itself, after the manifest checks.
#[derive(Debug, PartialEq, Eq)]
pub struct Inspected {
    pub backup_id: String,
    pub taken_at: String,
    /// Each table and how many rows it held.
    pub tables: Vec<(String, u64)>,
}

/// What a restore did.
#[derive(Debug, PartialEq, Eq)]
pub struct Restored {
    pub backup_id: String,
    pub taken_at: String,
    pub tables: usize,
    pub rows: u64,
    /// Rows that held a letter out in object storage, not restored.
    pub held_skipped: u64,
    /// Every audit chain still holds and every anchor in it verifies.
    pub audit_intact: bool,
}

fn identifier_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn id_of(taken_at: &str, serial: &str) -> String {
    let digits: String = taken_at.chars().filter(char::is_ascii_digit).collect();
    let mut hasher = Sha256::new();
    hasher.update(taken_at.as_bytes());
    hasher.update(serial.as_bytes());
    format!("{digits}-{}", hex::encode(&hasher.finalize()[..4]))
}

fn cell(value: &Value) -> Result<Json> {
    Ok(match value {
        Value::Null => Json::Null,
        Value::Integer(n) => json!(n),
        Value::Real(n) => serde_json::Number::from_f64(*n)
            .map(Json::Number)
            .ok_or(Error::InvalidBackup)?,
        Value::Text(text) => Json::String(text.clone()),
        Value::Blob(bytes) => json!({ "b": STANDARD.encode(bytes) }),
    })
}

fn value(cell: &Json) -> Result<Value> {
    Ok(match cell {
        Json::Null => Value::Null,
        Json::Number(n) => match n.as_i64() {
            Some(i) => Value::Integer(i),
            None => Value::Real(n.as_f64().ok_or(Error::InvalidBackup)?),
        },
        Json::String(text) => Value::Text(text.clone()),
        Json::Object(map) if map.len() == 1 => {
            let encoded = map
                .get("b")
                .and_then(Json::as_str)
                .ok_or(Error::InvalidBackup)?;
            Value::Blob(STANDARD.decode(encoded).map_err(|_| Error::InvalidBackup)?)
        }
        _ => return Err(Error::InvalidBackup),
    })
}

fn seal_chunk(
    recipient: &[u8; 32],
    table: &str,
    columns: &[String],
    rows: &[Json],
) -> Result<(Vec<u8>, u64)> {
    let plaintext = serde_json::to_vec(&json!({
        "v": VERSION, "table": table, "columns": columns, "rows": rows,
    }))
    .map_err(|_| Error::InvalidBackup)?;
    Ok((
        envelope::seal(
            EXPORT_BUNDLE,
            BUNDLE_TYPE_BACKUP_CHUNK,
            recipient,
            &plaintext,
        )?,
        rows.len() as u64,
    ))
}

/// A sealed, relay-signed snapshot of every table in `conn`, sealed to
/// `recipient` (the operator's backup public key). `taken_at` is the current
/// UTC time as text (`YYYY-MM-DD HH:MM:SS.mmm`); the core reads no clock.
/// Refuses, with [`Error::BackupTooLarge`], a database whose plaintext would
/// exceed `max_bytes`, before holding more than that in memory.
pub fn snapshot(
    conn: &dyn Sql,
    identity: &ProviderIdentity,
    recipient: &[u8; 32],
    taken_at: &str,
    max_bytes: usize,
) -> Result<Snapshot> {
    if taken_at.len() > 40
        || !taken_at
            .bytes()
            .all(|b| b.is_ascii_digit() || b" :-.".contains(&b))
    {
        return Err(Error::InvalidBackup);
    }
    let certificate = provider::parse_certificate(&identity.certificate)?;
    let backup_id = id_of(taken_at, &certificate.serial);
    let table_names = conn.query_map(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        params![],
        |row| row.get::<String>(0),
    )?;

    let mut spent = 0usize;
    let mut objects = Vec::new();
    let mut entries = Vec::new();
    let mut total_rows = 0u64;
    for table in &table_names {
        if !identifier_ok(table) {
            return Err(Error::InvalidBackup);
        }
        let columns = conn.query_map(
            "SELECT name FROM pragma_table_info(?1) ORDER BY cid",
            params![table],
            |row| row.get::<String>(0),
        )?;
        if columns.is_empty() || !columns.iter().all(|column| identifier_ok(column)) {
            return Err(Error::InvalidBackup);
        }
        let select = format!(
            "SELECT rowid, {} FROM \"{table}\" WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
            columns
                .iter()
                .map(|column| format!("\"{column}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut chunks = Vec::new();
        let mut table_rows = 0u64;
        let mut pending: Vec<Json> = Vec::new();
        let mut pending_bytes = 0usize;
        let mut after = 0i64;
        loop {
            let page = conn.query_map(&select, params![after, READ_ROWS], |row| {
                let rowid: i64 = row.get(0)?;
                let mut cells = Vec::with_capacity(columns.len());
                for index in 0..columns.len() {
                    cells.push(cell(&row.get::<Value>(index + 1)?)?);
                }
                Ok((rowid, Json::Array(cells)))
            })?;
            let last = page.last().map(|(rowid, _)| *rowid);
            let full = page.len() as i64 == READ_ROWS;
            for (_, row) in page {
                let size = row.to_string().len();
                spent = spent.saturating_add(size);
                if spent > max_bytes {
                    return Err(Error::BackupTooLarge);
                }
                pending_bytes += size;
                pending.push(row);
                table_rows += 1;
                if pending_bytes >= CHUNK_TARGET_BYTES {
                    chunks.push(flush(
                        recipient,
                        table,
                        &columns,
                        &mut pending,
                        &mut pending_bytes,
                        &mut objects,
                        &backup_id,
                    )?);
                }
            }
            match (full, last) {
                (true, Some(rowid)) => after = rowid,
                _ => break,
            }
        }
        if !pending.is_empty() || chunks.is_empty() {
            chunks.push(flush(
                recipient,
                table,
                &columns,
                &mut pending,
                &mut pending_bytes,
                &mut objects,
                &backup_id,
            )?);
        }
        total_rows += table_rows;
        entries.push(TableEntry {
            name: table.clone(),
            columns,
            rows: table_rows,
            chunks,
        });
    }

    let body = Body {
        version: VERSION,
        backup_id: backup_id.clone(),
        taken_at: taken_at.to_string(),
        relay_serial: certificate.serial,
        tables: entries,
    };
    let body_json = serde_json::to_string(&body).map_err(|_| Error::InvalidBackup)?;
    let signature = signing::sign(
        &identity.relay_private_key,
        &signing::relay_backup_manifest_preimage(body_json.as_bytes()),
    );
    let payload = serde_json::to_vec(&SignedManifest {
        body_json,
        signature: hex::encode(signature),
        certificate: STANDARD.encode(&identity.certificate),
    })
    .map_err(|_| Error::InvalidBackup)?;
    let manifest = envelope::seal(
        EXPORT_BUNDLE,
        BUNDLE_TYPE_BACKUP_MANIFEST,
        recipient,
        &payload,
    )?;
    Ok(Snapshot {
        backup_id,
        tables: table_names.len(),
        rows: total_rows,
        objects,
        manifest_name: "manifest.kqbk".to_string(),
        manifest,
    })
}

/// Seals the pending rows as the next chunk of `objects` and returns its entry.
fn flush(
    recipient: &[u8; 32],
    table: &str,
    columns: &[String],
    pending: &mut Vec<Json>,
    pending_bytes: &mut usize,
    objects: &mut Vec<(String, Vec<u8>)>,
    backup_id: &str,
) -> Result<ChunkRef> {
    let (sealed, rows) = seal_chunk(recipient, table, columns, pending)?;
    if sealed.len() > MAX_OBJECT_BYTES {
        return Err(Error::BackupTooLarge);
    }
    let seq = objects.len() as u32 + 1;
    let object = format!("chunk-{seq:06}.kqbk");
    let reference = ChunkRef {
        seq,
        object: object.clone(),
        sha256: hex::encode(Sha256::digest(&sealed)),
        bytes: sealed.len() as u64,
        rows,
    };
    let _ = backup_id;
    objects.push((object, sealed));
    pending.clear();
    *pending_bytes = 0;
    Ok(reference)
}

/// The manifest, opened with the backup key and verified: sealed to this key,
/// signed by the key a `root`-signed, unrevoked certificate names (valid when
/// the backup was taken, which the manifest itself states), and well formed.
fn open_manifest(
    manifest: &[u8],
    secret: &[u8; 32],
    root: &[u8; 32],
    revoked: &HashSet<String>,
) -> Result<Body> {
    if manifest.len() > MAX_OBJECT_BYTES {
        return Err(Error::InvalidBackup);
    }
    let (kind, _, payload) =
        envelope::open_as(EXPORT_BUNDLE, manifest, secret).map_err(|_| Error::InvalidBackup)?;
    if kind != BUNDLE_TYPE_BACKUP_MANIFEST {
        return Err(Error::InvalidBackup);
    }
    let signed: SignedManifest =
        serde_json::from_slice(&payload).map_err(|_| Error::InvalidBackup)?;
    let body: Body = serde_json::from_str(&signed.body_json).map_err(|_| Error::InvalidBackup)?;
    if body.version != VERSION {
        return Err(Error::InvalidBackup);
    }
    let certificate = STANDARD
        .decode(&signed.certificate)
        .map_err(|_| Error::InvalidBackup)?;
    let verified = provider::verify_certificate(root, &certificate, &body.taken_at, revoked)
        .map_err(|_| Error::InvalidBackup)?;
    if verified.serial != body.relay_serial {
        return Err(Error::InvalidBackup);
    }
    let signature: [u8; 64] = hex::decode(&signed.signature)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::InvalidBackup)?;
    signing::verify_signature(
        &verified.relay_public_key,
        &signing::relay_backup_manifest_preimage(signed.body_json.as_bytes()),
        &signature,
    )
    .map_err(|_| Error::InvalidBackup)?;
    Ok(body)
}

/// A backup's date, id and table list, after the same checks as [`restore`]
/// but without opening a chunk or touching a database: what `backup inspect`
/// shows.
pub fn inspect(
    manifest: &[u8],
    secret: &[u8; 32],
    root: &[u8; 32],
    revoked: &HashSet<String>,
) -> Result<Inspected> {
    let body = open_manifest(manifest, secret, root, revoked)?;
    Ok(Inspected {
        backup_id: body.backup_id,
        taken_at: body.taken_at,
        tables: body.tables.into_iter().map(|t| (t.name, t.rows)).collect(),
    })
}

/// Restores a backup into `target`, an empty relay database of the same shape
/// (`relay::open` made it). `read_object` returns the bytes of a chunk by name.
/// Nothing is written until the manifest and the target have been checked;
/// each chunk is checked against the manifest as it is read, inside one
/// transaction, so a bad chunk leaves the target empty.
pub fn restore(
    target: &dyn Sql,
    manifest: &[u8],
    read_object: &mut dyn FnMut(&str) -> Result<Vec<u8>>,
    secret: &[u8; 32],
    root: &[u8; 32],
    revoked: &HashSet<String>,
) -> Result<Restored> {
    let body = open_manifest(manifest, secret, root, revoked)?;

    // The target: same tables, same columns, and empty.
    let existing = target.query_map(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        params![],
        |row| row.get::<String>(0),
    )?;
    let named: Vec<&str> = body.tables.iter().map(|t| t.name.as_str()).collect();
    if existing.iter().map(String::as_str).collect::<Vec<_>>() != named {
        return Err(Error::BackupTargetNotEmpty);
    }
    for entry in &body.tables {
        if !identifier_ok(&entry.name) || !entry.columns.iter().all(|c| identifier_ok(c)) {
            return Err(Error::InvalidBackup);
        }
        let columns = target.query_map(
            "SELECT name FROM pragma_table_info(?1) ORDER BY cid",
            params![&entry.name],
            |row| row.get::<String>(0),
        )?;
        if columns != entry.columns {
            return Err(Error::BackupTargetNotEmpty);
        }
        let held: i64 = target.query_row(
            &format!("SELECT COUNT(*) FROM \"{}\"", entry.name),
            params![],
            |row| row.get(0),
        )?;
        if held != 0 {
            return Err(Error::BackupTargetNotEmpty);
        }
    }

    let mut rows_restored = 0u64;
    let mut held_skipped = 0u64;
    target.with_transaction(|| {
        target.execute_batch("PRAGMA defer_foreign_keys = ON")?;
        for entry in &body.tables {
            let blob_len_at = entry.columns.iter().position(|c| c == "blob_len");
            let columns = entry
                .columns
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let slots = (1..=entry.columns.len())
                .map(|n| format!("?{n}"))
                .collect::<Vec<_>>()
                .join(", ");
            let insert = format!(
                "INSERT INTO \"{}\" ({columns}) VALUES ({slots})",
                entry.name
            );
            let mut table_rows = 0u64;
            for chunk in &entry.chunks {
                let sealed = read_object(&chunk.object)?;
                if sealed.len() > MAX_OBJECT_BYTES
                    || sealed.len() as u64 != chunk.bytes
                    || hex::encode(Sha256::digest(&sealed)) != chunk.sha256
                {
                    return Err(Error::InvalidBackup);
                }
                let (kind, _, plaintext) = envelope::open_as(EXPORT_BUNDLE, &sealed, secret)
                    .map_err(|_| Error::InvalidBackup)?;
                if kind != BUNDLE_TYPE_BACKUP_CHUNK {
                    return Err(Error::InvalidBackup);
                }
                let parsed: Json =
                    serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidBackup)?;
                let rows = parsed
                    .get("rows")
                    .and_then(Json::as_array)
                    .ok_or(Error::InvalidBackup)?;
                let same_shape = parsed.get("table").and_then(Json::as_str)
                    == Some(entry.name.as_str())
                    && parsed.get("columns") == Some(&json!(entry.columns))
                    && rows.len() as u64 == chunk.rows;
                if !same_shape {
                    return Err(Error::InvalidBackup);
                }
                for row in rows {
                    let cells = row.as_array().ok_or(Error::InvalidBackup)?;
                    if cells.len() != entry.columns.len() {
                        return Err(Error::InvalidBackup);
                    }
                    let values = cells.iter().map(value).collect::<Result<Vec<_>>>()?;
                    table_rows += 1;
                    if blob_len_at.is_some_and(|at| values[at] != Value::Null) {
                        held_skipped += 1;
                        continue;
                    }
                    target.execute(&insert, &values)?;
                    rows_restored += 1;
                }
            }
            if table_rows != entry.rows {
                return Err(Error::InvalidBackup);
            }
        }
        Ok(())
    })?;

    let reports = audit::verify(target, root, revoked, None)?;
    Ok(Restored {
        backup_id: body.backup_id,
        taken_at: body.taken_at,
        tables: body.tables.len(),
        rows: rows_restored,
        held_skipped,
        audit_intact: reports.iter().all(audit::TableReport::is_intact),
    })
}

/// A file name a backup may name: plain, so a manifest can never point a
/// restore at a path outside the directory it was downloaded to.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::open(path)?, MAX_OBJECT_BYTES as u64 + 1),
        &mut bytes,
    )?;
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(Error::InvalidBackup);
    }
    Ok(bytes)
}

/// What `host backup inspect` says: the backup in `dir` (its `manifest.kqbk`
/// as downloaded from the bucket), verified as [`restore`] would, with nothing
/// opened beyond the manifest and nothing written.
pub fn inspect_dir(
    dir: &std::path::Path,
    secret: &[u8; 32],
    root: &[u8; 32],
    revoked: &HashSet<String>,
) -> Result<Inspected> {
    inspect(
        &read_bounded(&dir.join("manifest.kqbk"))?,
        secret,
        root,
        revoked,
    )
}

/// Restores the backup in `dir` (the objects as downloaded from the bucket:
/// `manifest.kqbk` and its chunk files) into a new relay database at `out`,
/// which must not exist. A restore that fails leaves no database behind.
pub fn restore_dir(
    dir: &std::path::Path,
    out: &std::path::Path,
    secret: &[u8; 32],
    root: &[u8; 32],
    revoked: &HashSet<String>,
) -> Result<Restored> {
    if out.exists() {
        return Err(Error::BackupTargetNotEmpty);
    }
    let manifest = read_bounded(&dir.join("manifest.kqbk"))?;
    // Checked before a database is made, so a wrong key or a forged manifest
    // creates nothing.
    open_manifest(&manifest, secret, root, revoked)?;
    let path = out.to_str().ok_or(Error::InvalidBackup)?;
    let conn = super::open(path)?;
    let result = restore(
        &conn,
        &manifest,
        &mut |name| {
            if !plain_name(name) {
                return Err(Error::InvalidBackup);
            }
            read_bounded(&dir.join(name))
        },
        secret,
        root,
        revoked,
    );
    drop(conn);
    if result.is_err() {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }
    result
}

#[cfg(test)]
#[path = "backup/tests.rs"]
mod tests;
