//! Ties a quorum-protected file to a tracked `.kqtf` and appends what
//! happened at the gate to that file's history. The gates themselves
//! (`quorum`, `locked_files`) know nothing about this: the CLI calls in
//! here after a gate has already answered, and nothing here can change
//! that answer. A failure to record is reported and otherwise ignored, so
//! history is an account of the gate, never a condition of it. Only the
//! outcome and the labels that were presented are recorded, never shares,
//! passwords, PINs or plaintext.

use super::env::{errln, outln};
use super::file_cmd::{index_after, load, save, utc_instant};
use super::usage;
use crate::error::{Error, Result};
use crate::file_history::{EventDetails, HistoryEventType, HistoryOutcome, NewEvent, TrackedFile};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Gate {
    Quorum,
}

impl Gate {
    fn name(self) -> &'static str {
        match self {
            Gate::Quorum => "quorum",
        }
    }

    fn table(self) -> &'static str {
        match self {
            Gate::Quorum => "files",
        }
    }

    fn unlock_event(self) -> HistoryEventType {
        match self {
            Gate::Quorum => HistoryEventType::QuorumUnlockAttempted,
        }
    }
}

fn gate_row_exists(conn: &Connection, gate: Gate, id: i64) -> Result<bool> {
    Ok(gate_ref(conn, gate, id)?.is_some())
}

/// What makes this row this file: its ciphertext path and creation time.
/// The integer id alone can be handed out again after a purge, so a link
/// remembers this and a reused id is never mistaken for the old file.
fn gate_ref(conn: &Connection, gate: Gate, id: i64) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT encrypted_path || '|' || created_at FROM {} WHERE id = ?1",
                gate.table()
            ),
            params![id],
            |row| row.get(0),
        )
        .optional()?)
}

fn info(kind: HistoryEventType, outcome: HistoryOutcome, details: EventDetails) -> NewEvent {
    NewEvent {
        revision_id: None,
        occurred_at: String::new(),
        actor_identity: None,
        actor_label: None,
        topology_generation: None,
        event_type: kind,
        outcome,
        details,
    }
}

pub(super) fn link(conn: &Connection, kqtf: &Path, gate: Gate, id: i64) -> Result<()> {
    let Some(reference) = gate_ref(conn, gate, id)? else {
        return Err(usage(&format!(
            "no {} file {id} in this store",
            gate.name()
        )));
    };
    let mut file = load(kqtf)?;
    let path = kqtf.to_string_lossy().into_owned();
    let existing: Option<(String, String)> = conn
        .query_row(
            "SELECT kqtf_path, gate_ref FROM tracked_gate_links
             WHERE tracked_file_id = ?1 AND gate = ?2 AND gate_file_id = ?3",
            params![file.file_id.as_slice(), gate.name(), id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match existing {
        Some((old, old_ref)) if old_ref == reference => {
            if old == path {
                outln!("Already linked.");
            } else {
                // The same tracked file at another path (a copy, or a move):
                // events go to the path named last.
                conn.execute(
                    "UPDATE tracked_gate_links SET kqtf_path = ?4
                     WHERE tracked_file_id = ?1 AND gate = ?2 AND gate_file_id = ?3",
                    params![file.file_id.as_slice(), gate.name(), id, path],
                )?;
                outln!("Already linked; now recording to {path} (was {old}).");
            }
            return Ok(());
        }
        // A retired link that a reused id has since replaced.
        Some(_) => {
            conn.execute(
                "DELETE FROM tracked_gate_links
                 WHERE tracked_file_id = ?1 AND gate = ?2 AND gate_file_id = ?3",
                params![file.file_id.as_slice(), gate.name(), id],
            )?;
        }
        None => {}
    }
    conn.execute(
        "INSERT INTO tracked_gate_links (tracked_file_id, gate, gate_file_id, gate_ref, kqtf_path)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![file.file_id.as_slice(), gate.name(), id, reference, path],
    )?;
    // The link and its first event stand or fall together: if the container
    // cannot be written, the link is taken back so a failed command leaves
    // nothing behind.
    let written = (|| -> Result<()> {
        let details = EventDetails::new()
            .with("gate", gate.name())
            .with("gate_file", &id.to_string());
        append(
            &mut file,
            info(HistoryEventType::GateLinked, HistoryOutcome::Info, details),
        )?;
        save(kqtf, &file)
    })();
    if let Err(error) = written {
        let _ = conn.execute(
            "DELETE FROM tracked_gate_links
             WHERE tracked_file_id = ?1 AND gate = ?2 AND gate_file_id = ?3",
            params![file.file_id.as_slice(), gate.name(), id],
        );
        return Err(error);
    }
    index_after(conn, &file);
    outln!("Linked {} file {id} to {}.", gate.name(), file.logical_name);
    Ok(())
}

pub(super) fn unlink(conn: &Connection, kqtf: &Path, gate: Gate, id: i64) -> Result<()> {
    let file = load(kqtf)?;
    let removed = conn.execute(
        "DELETE FROM tracked_gate_links
         WHERE tracked_file_id = ?1 AND gate = ?2 AND gate_file_id = ?3",
        params![file.file_id.as_slice(), gate.name(), id],
    )?;
    if removed == 0 {
        return Err(usage("that file is not linked"));
    }
    outln!("Unlinked {} file {id}.", gate.name());
    Ok(())
}

fn append(file: &mut TrackedFile, mut event: NewEvent) -> Result<()> {
    event.occurred_at = utc_instant()?;
    file.append(event)?;
    Ok(())
}

/// The containers to write to: each link whose gate row is either gone (a
/// tombstone) or is still the very file that was linked. A link whose id now
/// names a different file is stale and is skipped.
fn links(conn: &Connection, gate: Gate, id: i64) -> Result<Vec<(Vec<u8>, String)>> {
    let current = gate_ref(conn, gate, id)?;
    let mut stmt = conn.prepare(
        "SELECT tracked_file_id, kqtf_path, gate_ref FROM tracked_gate_links
         WHERE gate = ?1 AND gate_file_id = ?2",
    )?;
    let rows = stmt
        .query_map(params![gate.name(), id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get::<_, String>(2)?))
        })?
        .collect::<rusqlite::Result<Vec<(Vec<u8>, String, String)>>>()?;
    Ok(rows
        .into_iter()
        .filter(|(_, _, reference)| current.as_ref().is_none_or(|now| now == reference))
        .map(|(tracked, path, _)| (tracked, path))
        .collect())
}

/// Append `events` to every container linked to this gate file. Never
/// fails: the gate has already decided. The container must still be the
/// tracked file that was linked, so a replacement at the same path is not
/// written to.
fn record(conn: &Connection, gate: Gate, id: i64, events: Vec<NewEvent>) {
    let targets = match links(conn, gate, id) {
        Ok(targets) => targets,
        Err(error) => {
            errln!("Warning: could not look up {} links: {error}", gate.name());
            return;
        }
    };
    for (tracked, path) in targets {
        let result = (|| -> Result<()> {
            let mut file = load(Path::new(&path))?;
            if file.file_id.as_slice() != tracked.as_slice() {
                return Err(usage("the file at that path is a different tracked file"));
            }
            for event in &events {
                append(&mut file, event.clone())?;
            }
            save(Path::new(&path), &file)?;
            index_after(conn, &file);
            Ok(())
        })();
        if let Err(error) = result {
            errln!(
                "Warning: could not record the {} event in {path}: {error}",
                gate.name()
            );
        }
    }
}

fn gate_details(gate: Gate, id: i64) -> EventDetails {
    EventDetails::new()
        .with("gate", gate.name())
        .with("gate_file", &id.to_string())
}

/// After an unlock attempt at the gate: one event per attempt, with the
/// labels that were presented when it succeeded.
pub(super) fn record_unlock(
    gate: Gate,
    conn: &Connection,
    id: i64,
    failure: Option<&Error>,
    presented: &[String],
) {
    if matches!(failure, Some(Error::FileExpired)) {
        return record_expiry(gate, conn, id);
    }
    let mut details = gate_details(gate, id);
    let kind = match failure {
        None => {
            details = details.with("result", "success");
            if !presented.is_empty() {
                details = details.with("presented", &presented.join(","));
            }
            HistoryOutcome::Success
        }
        Some(error) => {
            details = details.with("result", &failure_text(error));
            HistoryOutcome::Failure
        }
    };
    record(
        conn,
        gate,
        id,
        vec![info(gate.unlock_event(), kind, details)],
    );
}

/// The gate's refusal as history records it. Storage errors carry text from
/// the operating system or the database, which history has no business
/// keeping, so they are named, not quoted.
fn failure_text(error: &Error) -> String {
    match error {
        Error::Io(_) | Error::Db(_) => "failed: storage error".to_string(),
        other => format!("failed: {other}"),
    }
}

/// The gate destroyed an expired file on this attempt.
pub(super) fn record_expiry(gate: Gate, conn: &Connection, id: i64) {
    let d = || gate_details(gate, id);
    record(
        conn,
        gate,
        id,
        vec![
            info(HistoryEventType::FileExpired, HistoryOutcome::Info, d()),
            info(
                HistoryEventType::ContentDestroyed,
                HistoryOutcome::Success,
                d(),
            ),
            info(
                HistoryEventType::ExpiredAccessAttempt,
                HistoryOutcome::Denied,
                d(),
            ),
        ],
    );
}

/// Before an attempt: a linked gate file that no longer exists was
/// destroyed earlier, so this is an access attempt on an expired file.
pub(super) fn note_if_gone(gate: Gate, conn: &Connection, id: i64) {
    if gate_row_exists(conn, gate, id).unwrap_or(true) {
        return;
    }
    record(
        conn,
        gate,
        id,
        vec![info(
            HistoryEventType::ExpiredAccessAttempt,
            HistoryOutcome::Denied,
            gate_details(gate, id),
        )],
    );
}
