//! Each ring's timeline: when every letter took a slot, left it, or was turned
//! away, kept as history events chained exactly as a tracked file's are
//! (`file_history`), so the timeline is a `KQHS` history snapshot. Each event
//! carries its time (the store's clock, whole seconds UTC) and the hash of
//! everything before it, so a time cannot be changed later without breaking
//! the chain. A snapshot written out (`outbox history --snapshot`) and checked
//! later (`--check`) shows the timeline still passes through it.
//!
//! One timeline per ring: each person's outbox, and each store's inbox per
//! relay. Its id is derived from which ring it is, and its chain starts from
//! that id's genesis hash, like a file's. Events hold ids, labels, slots,
//! kinds and rule names only: never a letter, its hash, or anything sealed in
//! it (`file_history::SAFE_DETAIL_KEYS`).

use crate::error::{Error, Result};
use crate::file_history::{
    genesis_hash, EventDetails, HistoryEvent, HistoryEventType, HistoryOutcome, HistorySnapshot,
    NewEvent,
};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

const ID_DOMAIN: &[u8] = b"KQ-RING-HISTORY-v1";

/// Which ring a timeline belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timeline<'a> {
    /// A person's outbox, by their label.
    Outbox(&'a str),
    /// A store's inbox for one relay, by its URL.
    Inbox(&'a str),
}

impl Timeline<'_> {
    fn kind(self) -> &'static str {
        match self {
            Self::Outbox(_) => "outbox",
            Self::Inbox(_) => "inbox",
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Outbox(owner) => owner,
            Self::Inbox(url) => url,
        }
    }

    /// The timeline's id: the `file_id` of its snapshot.
    pub fn id(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(ID_DOMAIN);
        hasher.update(self.kind().as_bytes());
        hasher.update([0]);
        hasher.update(self.name().as_bytes());
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }
}

/// Append one event to the timeline, in the caller's transaction when there is
/// one, so it lands together with the slot change it records.
pub fn record(
    conn: &Connection,
    timeline: Timeline,
    event_type: HistoryEventType,
    outcome: HistoryOutcome,
    actor: Option<&str>,
    details: EventDetails,
) -> Result<()> {
    let id = timeline.id();
    crate::db::with_immediate_transaction(conn, || {
        conn.execute(
            "INSERT OR IGNORE INTO ring_histories (history_id, ring_kind, ring_key, head_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                &id[..],
                timeline.kind(),
                timeline.name(),
                &genesis_hash(&id)[..]
            ],
        )?;
        let (count, head, at): (i64, Vec<u8>, String) = conn.query_row(
            "SELECT event_count, head_hash, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             FROM ring_histories WHERE history_id = ?1",
            params![&id[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let head: [u8; 32] = head.try_into().map_err(|_| Error::IntegrityCheckFailed)?;
        let sequence = u64::try_from(count).map_err(|_| Error::IntegrityCheckFailed)?;
        let event = HistoryEvent::chained(
            id,
            sequence,
            head,
            NewEvent {
                revision_id: None,
                occurred_at: at,
                actor_identity: None,
                actor_label: actor.map(str::to_string),
                topology_generation: None,
                event_type,
                outcome,
                details,
            },
        )?;
        conn.execute(
            "INSERT INTO ring_events (history_id, sequence, event) VALUES (?1, ?2, ?3)",
            params![&id[..], count, event.to_bytes()?],
        )?;
        conn.execute(
            "UPDATE ring_histories SET event_count = ?2, head_hash = ?3 WHERE history_id = ?1",
            params![&id[..], count + 1, &event.event_hash[..]],
        )?;
        Ok(())
    })
}

/// The whole timeline as a `KQHS` snapshot, its chain verified and matching
/// the head the store recorded. A timeline nothing was recorded on is empty.
pub fn snapshot(conn: &Connection, timeline: Timeline) -> Result<HistorySnapshot> {
    let id = timeline.id();
    let mut stmt =
        conn.prepare("SELECT event FROM ring_events WHERE history_id = ?1 ORDER BY sequence")?;
    let events = stmt
        .query_map(params![&id[..]], |row| row.get::<_, Vec<u8>>(0))?
        .map(|bytes| HistoryEvent::from_bytes(&bytes?))
        .collect::<Result<Vec<_>>>()?;
    let snapshot =
        HistorySnapshot::from_events(id, events).map_err(|_| Error::IntegrityCheckFailed)?;
    let head: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT event_count, head_hash FROM ring_histories WHERE history_id = ?1",
            params![&id[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();
    let consistent = match head {
        Some((count, head)) => {
            usize::try_from(count).ok() == Some(snapshot.events.len())
                && head == snapshot.history_root
        }
        None => snapshot.events.is_empty(),
    };
    if !consistent {
        return Err(Error::IntegrityCheckFailed);
    }
    Ok(snapshot)
}

#[cfg(test)]
#[path = "history/tests.rs"]
mod tests;
