//! The letters `keyquorum inbox` has pulled: which ones, of what kind, and
//! whether this store has handled them, and the inbox ring that holds the
//! unopened ones. The sealed bytes live in the inbox directory; the ring keeps
//! each held letter's hash, and a delivered letter's slot is released and its
//! file deleted (`inbox open`, `inbox drop`).

use crate::error::{Error, Result};
use crate::ring;
use rusqlite::{params, Connection, OptionalExtension};

/// Unopened letters an inbox holds per relay before a pull stops.
pub const RING_CAPACITY: u32 = 256;

const TABLE: ring::Table = ring::Table {
    rings: "inbox_rings",
    slots: "inbox_slots",
    key: "relay_url",
    content: None,
};

/// A letter the inbox ring holds.
pub struct HeldLetter {
    pub content_hash: String,
}

/// Whether this store already knows the letter, handled or not.
pub fn is_known(conn: &Connection, relay_url: &str, letter_id: i64) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM inbox_letters WHERE relay_url = ?1 AND letter_id = ?2",
            params![relay_url, letter_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Whether the inbox ring has a free slot for another letter.
pub fn has_room(conn: &Connection, relay_url: &str) -> Result<bool> {
    Ok(ring::load(conn, &TABLE, relay_url)?.is_none_or(|ring| !ring.is_full()))
}

/// Take a new pulled letter into the inbox ring and record it as pending,
/// together. Refused when the ring is full.
pub fn hold(
    conn: &Connection,
    relay_url: &str,
    letter_id: i64,
    kind: u8,
    content_hash: &str,
) -> Result<()> {
    crate::db::with_immediate_transaction(conn, || {
        let ring = ring::ensure(conn, &TABLE, relay_url, RING_CAPACITY)?;
        if ring.is_full() {
            return Err(Error::OutboxFull);
        }
        conn.execute(
            "INSERT INTO inbox_slots (relay_url, slot_index, letter_id, envelope_kind, content_hash)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![relay_url, ring.write_index, letter_id, kind, content_hash],
        )?;
        ring::advance_write(conn, &TABLE, relay_url)?;
        record(conn, relay_url, letter_id, kind)
    })
}

/// The held letter's slot, if the ring holds it. A letter pulled before the
/// inbox ring existed has none.
pub fn held(conn: &Connection, relay_url: &str, letter_id: i64) -> Result<Option<HeldLetter>> {
    Ok(conn
        .query_row(
            "SELECT content_hash FROM inbox_slots WHERE relay_url = ?1 AND letter_id = ?2",
            params![relay_url, letter_id],
            |row| {
                Ok(HeldLetter {
                    content_hash: row.get(0)?,
                })
            },
        )
        .optional()?)
}

/// Mark the letter handled and release its slot, together.
pub fn deliver(conn: &Connection, relay_url: &str, letter_id: i64) -> Result<()> {
    crate::db::with_immediate_transaction(conn, || {
        mark_handled(conn, relay_url, letter_id)?;
        let index: Option<u32> = conn
            .query_row(
                "SELECT slot_index FROM inbox_slots WHERE relay_url = ?1 AND letter_id = ?2",
                params![relay_url, letter_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(index) = index {
            ring::release(conn, &TABLE, relay_url, index)?;
        }
        Ok(())
    })
}

/// Letters held unopened, and how many the ring can hold.
pub fn usage(conn: &Connection, relay_url: &str) -> Result<(u32, u32)> {
    let held: u32 = conn.query_row(
        "SELECT count(*) FROM inbox_slots WHERE relay_url = ?1",
        params![relay_url],
        |row| row.get(0),
    )?;
    let capacity = ring::load(conn, &TABLE, relay_url)?.map_or(RING_CAPACITY, |r| r.capacity);
    Ok((held, capacity))
}

pub const PENDING: &str = "pending";
pub const HANDLED: &str = "handled";

pub struct Letter {
    pub id: i64,
    pub kind: u8,
    pub status: String,
}

/// The newest letter id pulled from this relay, where the next pull resumes.
pub fn cursor(conn: &Connection, relay_url: &str) -> Result<Option<i64>> {
    Ok(conn.query_row(
        "SELECT max(letter_id) FROM inbox_letters WHERE relay_url = ?1",
        [relay_url],
        |row| row.get(0),
    )?)
}

/// Record a pulled letter. A letter already known keeps its status.
pub fn record(conn: &Connection, relay_url: &str, letter_id: i64, kind: u8) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO inbox_letters (relay_url, letter_id, kind) VALUES (?1, ?2, ?3)",
        params![relay_url, letter_id, kind],
    )?;
    Ok(())
}

pub fn mark_handled(conn: &Connection, relay_url: &str, letter_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE inbox_letters SET status = 'handled' WHERE relay_url = ?1 AND letter_id = ?2",
        params![relay_url, letter_id],
    )?;
    Ok(())
}

pub fn list(conn: &Connection, relay_url: &str) -> Result<Vec<Letter>> {
    let mut stmt = conn.prepare(
        "SELECT letter_id, kind, status FROM inbox_letters
         WHERE relay_url = ?1 ORDER BY letter_id",
    )?;
    let rows = stmt.query_map([relay_url], |row| {
        Ok(Letter {
            id: row.get(0)?,
            kind: row.get(1)?,
            status: row.get(2)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
