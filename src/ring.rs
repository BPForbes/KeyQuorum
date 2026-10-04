//! The pointer arithmetic of a bounded ring of slots kept in SQLite, shared by
//! each person's outbox (`outbox`) and each store's inbox (`db::inbox`).
//!
//! A ring has a capacity, a read pointer, a write pointer and a span
//! (`size`): the slots from the read pointer up to the write pointer. A new
//! item takes the slot at the write pointer, and a full ring takes none: it
//! never overwrites a held item. A slot is released by wiping and deleting
//! its row; the read pointer then moves past every released slot at the head.
//! The outbox releases only its head, so its span is exactly what it holds.
//! The inbox releases a letter whenever it is opened, so a released slot is
//! reused only once every slot before it has been released too.
//!
//! Table and column names here are this module's constants, never input.

use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) mod history;

/// Where one kind of ring lives.
pub(crate) struct Table {
    pub rings: &'static str,
    pub slots: &'static str,
    /// The column naming whose ring it is, in both tables.
    pub key: &'static str,
    /// A column holding the item itself, overwritten before the row is
    /// deleted. `None` when the item lives elsewhere.
    pub content: Option<&'static str>,
}

/// A ring's pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pointers {
    pub capacity: u32,
    pub read_index: u32,
    pub write_index: u32,
    /// Slots from the read pointer up to the write pointer.
    pub size: u32,
}

impl Pointers {
    pub fn is_full(&self) -> bool {
        self.size >= self.capacity
    }
}

pub(crate) fn load(conn: &Connection, table: &Table, key: &str) -> Result<Option<Pointers>> {
    conn.query_row(
        &format!(
            "SELECT capacity, read_index, write_index, size FROM {} WHERE {} = ?1",
            table.rings, table.key
        ),
        params![key],
        |row| {
            Ok(Pointers {
                capacity: row.get(0)?,
                read_index: row.get(1)?,
                write_index: row.get(2)?,
                size: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Error::from)
}

/// The ring for `key`, created with `capacity` slots the first time.
pub(crate) fn ensure(
    conn: &Connection,
    table: &Table,
    key: &str,
    capacity: u32,
) -> Result<Pointers> {
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {} ({}, capacity) VALUES (?1, ?2)",
            table.rings, table.key
        ),
        params![key, capacity],
    )?;
    load(conn, table, key)?.ok_or(Error::IntegrityCheckFailed)
}

/// Count the slot at the write pointer as taken. The caller has just
/// inserted its row at `Pointers::write_index`.
pub(crate) fn advance_write(conn: &Connection, table: &Table, key: &str) -> Result<()> {
    conn.execute(
        &format!(
            "UPDATE {} SET write_index = (write_index + 1) % capacity, size = size + 1
             WHERE {} = ?1",
            table.rings, table.key
        ),
        params![key],
    )?;
    Ok(())
}

/// Wipe and delete the slot at `index`, then move the read pointer past every
/// released slot at the head.
pub(crate) fn release(conn: &Connection, table: &Table, key: &str, index: u32) -> Result<()> {
    if let Some(content) = table.content {
        // Overwrite before deleting, with secure_delete on, so the bytes do
        // not linger in the freed page.
        conn.pragma_update(None, "secure_delete", true)?;
        conn.execute(
            &format!(
                "UPDATE {} SET {content} = zeroblob(length({content}))
                 WHERE {} = ?1 AND slot_index = ?2",
                table.slots, table.key
            ),
            params![key, index],
        )?;
    }
    conn.execute(
        &format!(
            "DELETE FROM {} WHERE {} = ?1 AND slot_index = ?2",
            table.slots, table.key
        ),
        params![key, index],
    )?;
    let Some(mut ring) = load(conn, table, key)? else {
        return Ok(());
    };
    while ring.size > 0 && !held(conn, table, key, ring.read_index)? {
        ring.read_index = (ring.read_index + 1) % ring.capacity;
        ring.size -= 1;
    }
    conn.execute(
        &format!(
            "UPDATE {} SET read_index = ?2, size = ?3 WHERE {} = ?1",
            table.rings, table.key
        ),
        params![key, ring.read_index, ring.size],
    )?;
    Ok(())
}

fn held(conn: &Connection, table: &Table, key: &str, index: u32) -> Result<bool> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT 1 FROM {} WHERE {} = ?1 AND slot_index = ?2",
                table.slots, table.key
            ),
            params![key, index],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Change the number of slots. Only an empty ring is resized, so no held item
/// is moved or lost; `false` when it is not empty.
pub(crate) fn resize(conn: &Connection, table: &Table, key: &str, capacity: u32) -> Result<bool> {
    let ring = ensure(conn, table, key, capacity)?;
    if ring.size != 0 {
        return Ok(false);
    }
    conn.execute(
        &format!(
            "UPDATE {} SET capacity = ?1, read_index = 0, write_index = 0 WHERE {} = ?2",
            table.rings, table.key
        ),
        params![capacity, key],
    )?;
    Ok(true)
}

#[cfg(test)]
#[path = "ring/tests.rs"]
mod tests;
