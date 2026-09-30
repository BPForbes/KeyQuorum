//! A rebuildable SQLite index over tracked files.
//!
//! The `.kqtf` container is the authority; these tables (`tracked_files`,
//! `tracked_revisions`, `tracked_history_index`) only make files and their
//! events listable. Nothing here decides trust or holds payload bytes, and
//! every function can be re-run from the containers to restore the rows.
//!
//! The rows are metadata, not payload, but metadata is not harmless: file
//! names, scopes, labels, authors and event times can reveal who did what.
//! Treat the store that holds them as sensitive (`db::open` keeps it
//! owner-only).

use super::container::TrackedFile;
use crate::error::Result;
use rusqlite::{params, Connection};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedFile {
    pub file_id: [u8; 16],
    pub logical_name: String,
    pub scope_root: Option<String>,
    pub history_root: [u8; 32],
    pub head_count: usize,
    pub event_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEvent {
    pub sequence: u64,
    pub event_type: String,
    pub outcome: String,
    pub revision_id: Option<[u8; 32]>,
    pub actor_label: Option<String>,
    pub occurred_at: String,
}

fn array<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    let mut out = [0u8; N];
    let n = bytes.len().min(N);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Replace whatever is indexed for this file with what the container says,
/// in one transaction. The container should already be verified (decoding
/// does that).
pub fn record(conn: &Connection, file: &TrackedFile) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    record_in(&tx, file)?;
    tx.commit()?;
    Ok(())
}

/// The work of [`record`] inside a transaction the caller owns, so several
/// files can be replaced as one unit.
fn record_in(tx: &Connection, file: &TrackedFile) -> Result<()> {
    tx.execute(
        "DELETE FROM tracked_files WHERE file_id = ?1",
        params![file.file_id.to_vec()],
    )?;
    let heads = file.graph().heads();
    tx.execute(
        "INSERT INTO tracked_files
             (file_id, logical_name, scope_root, history_root, head_count, event_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            file.file_id.to_vec(),
            file.logical_name,
            file.policy().map(|policy| policy.scope_root.clone()),
            file.history_root().to_vec(),
            heads.len() as i64,
            file.events().len() as i64,
        ],
    )?;
    for (ordinal, stored) in file.revisions().iter().enumerate() {
        let revision = &stored.revision;
        let parents: Vec<u8> = revision
            .parent_revision_ids
            .iter()
            .flatten()
            .copied()
            .collect();
        tx.execute(
            "INSERT INTO tracked_revisions
                 (revision_id, file_id, ordinal, parent_ids, generated_label,
                  user_label, author_label, created_at, is_head)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                revision.revision_id.to_vec(),
                file.file_id.to_vec(),
                ordinal as i64,
                parents,
                revision.generated_label,
                revision.user_label,
                revision.author_hcp_label,
                revision.created_at_utc,
                i64::from(heads.contains(&revision.revision_id)),
            ],
        )?;
    }
    for event in file.events() {
        tx.execute(
            "INSERT INTO tracked_history_index
                 (file_id, sequence, event_type, outcome, revision_id, actor_label, occurred_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                file.file_id.to_vec(),
                event.sequence as i64,
                format!("{:?}", event.event_type),
                format!("{:?}", event.outcome),
                event.revision_id.map(|id| id.to_vec()),
                event.actor_label,
                event.occurred_at,
            ],
        )?;
    }
    Ok(())
}

/// Drop one file from the index.
pub fn forget(conn: &Connection, file_id: &[u8; 16]) -> Result<()> {
    conn.execute(
        "DELETE FROM tracked_files WHERE file_id = ?1",
        params![file_id.to_vec()],
    )?;
    Ok(())
}

/// Empty the index, then index `files`: the state after a rebuild from
/// scratch. It is one transaction, so if any file fails the previous index
/// is left exactly as it was.
pub fn rebuild(conn: &Connection, files: &[TrackedFile]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM tracked_files", [])?;
    for file in files {
        record_in(&tx, file)?;
    }
    tx.commit()?;
    Ok(())
}

pub fn list(conn: &Connection) -> Result<Vec<IndexedFile>> {
    let mut statement = conn.prepare(
        "SELECT file_id, logical_name, scope_root, history_root, head_count, event_count
         FROM tracked_files ORDER BY logical_name, file_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(IndexedFile {
            file_id: array(row.get(0)?),
            logical_name: row.get(1)?,
            scope_root: row.get(2)?,
            history_root: array(row.get(3)?),
            head_count: row.get::<_, i64>(4)? as usize,
            event_count: row.get::<_, i64>(5)? as usize,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn events(conn: &Connection, file_id: &[u8; 16]) -> Result<Vec<IndexedEvent>> {
    let mut statement = conn.prepare(
        "SELECT sequence, event_type, outcome, revision_id, actor_label, occurred_at
         FROM tracked_history_index WHERE file_id = ?1 ORDER BY sequence",
    )?;
    let rows = statement.query_map(params![file_id.to_vec()], |row| {
        Ok(IndexedEvent {
            sequence: row.get::<_, i64>(0)? as u64,
            event_type: row.get(1)?,
            outcome: row.get(2)?,
            revision_id: row.get::<_, Option<Vec<u8>>>(3)?.map(array),
            actor_label: row.get(4)?,
            occurred_at: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}
