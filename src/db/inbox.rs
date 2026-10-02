//! The letters `keyquorum inbox` has pulled: which ones, of what kind, and
//! whether this store has handled them. The sealed bytes live in the inbox
//! directory; this only remembers the cursor and the status.

use crate::error::Result;
use rusqlite::{params, Connection};

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
