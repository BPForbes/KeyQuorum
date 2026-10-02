//! The profile: non-secret defaults a command falls back on when a flag is
//! omitted. It is pointers only. Identity lives in the device container and
//! slot token, relay auth in `relay_credentials`; the profile just says
//! "use these by default". It never holds a passphrase, key, or bearer.

use crate::error::Result;
use rusqlite::{params, Connection, OptionalExtension};

pub const DEFAULT_LABEL: &str = "default_label";
pub const DEFAULT_SLOT_LABEL: &str = "default_slot_label";
pub const DEFAULT_CONTAINER: &str = "default_container";
pub const DEFAULT_RELAY_URL: &str = "default_relay_url";
pub const CACHE_ENABLED: &str = "cache_enabled";

pub fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM profile WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

pub fn set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO profile (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn clear(conn: &Connection, key: &str) -> Result<()> {
    conn.execute("DELETE FROM profile WHERE key = ?1", [key])?;
    Ok(())
}

pub fn clear_all(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM profile", [])?;
    Ok(())
}

/// Every stored default, in key order.
pub fn all(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare("SELECT key, value FROM profile ORDER BY key")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Whether caching is on. It is unless the profile says `off`.
pub fn cache_enabled(conn: &Connection) -> Result<bool> {
    Ok(get(conn, CACHE_ENABLED)?.as_deref() != Some("off"))
}
