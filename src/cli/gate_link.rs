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
    Ok(conn
        .query_row(
            &format!("SELECT 1 FROM {} WHERE id = ?1", gate.table()),
            params![id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
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
    if !gate_row_exists(conn, gate, id)? {
        return Err(usage(&format!(
            "no {} file {id} in this store",
            gate.name()
        )));
    }
    let mut file = load(kqtf)?;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO tracked_gate_links (tracked_file_id, gate, gate_file_id, kqtf_path)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            file.file_id.as_slice(),
            gate.name(),
            id,
            kqtf.to_string_lossy()
        ],
    )?;
    if inserted == 0 {
        outln!("Already linked.");
        return Ok(());
    }
    let details = EventDetails::new()
        .with("gate", gate.name())
        .with("gate_file", &id.to_string());
    append(
        &mut file,
        info(HistoryEventType::GateLinked, HistoryOutcome::Info, details),
    )?;
    save(kqtf, &file)?;
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

fn links(conn: &Connection, gate: Gate, id: i64) -> Vec<String> {
    let query = || -> rusqlite::Result<Vec<String>> {
        let mut stmt = conn.prepare(
            "SELECT kqtf_path FROM tracked_gate_links WHERE gate = ?1 AND gate_file_id = ?2",
        )?;
        let rows = stmt.query_map(params![gate.name(), id], |row| row.get(0))?;
        rows.collect()
    };
    query().unwrap_or_default()
}

/// Append `events` to every container linked to this gate file. Never
/// fails: the gate has already decided.
fn record(conn: &Connection, gate: Gate, id: i64, events: Vec<NewEvent>) {
    for path in links(conn, gate, id) {
        let result = (|| -> Result<()> {
            let mut file = load(Path::new(&path))?;
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
            details = details.with("result", &format!("failed: {error}"));
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
