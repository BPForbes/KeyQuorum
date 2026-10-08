//! The package generation counter (issue #106): the number a relay puts in
//! every setup manifest it signs, one stream per recipient and device, so a
//! client can tell a newer package from an older one and refuse to go back.
//!
//! A generation is taken from this counter, in its own unit of work, before
//! the package is built; a package that is then not delivered leaves a gap,
//! which is harmless (the client only ever compares, never counts). It is
//! never reused and never decreases, and the native host and the console take
//! it the same way. This module owns the `package_generations` table.

use super::sql::{params, Sql};
use crate::error::Result;

/// The next generation for the stream `(recipient, device)`, starting at 1.
/// `device` is the hex device id, or empty for a package bound to no device.
pub fn next(conn: &dyn Sql, recipient: &[u8; 32], device: Option<&[u8; 16]>) -> Result<u64> {
    let recipient = hex::encode(recipient);
    let device = device.map(hex::encode).unwrap_or_default();
    let mut taken = 0u64;
    conn.transaction(&mut || {
        conn.execute(
            "INSERT INTO package_generations (recipient, device_id, generation)
             VALUES (?1, ?2, 1)
             ON CONFLICT (recipient, device_id) DO UPDATE SET generation = generation + 1",
            params![recipient.as_str(), device.as_str()],
        )?;
        taken = conn.query_row(
            "SELECT generation FROM package_generations WHERE recipient = ?1 AND device_id = ?2",
            params![recipient.as_str(), device.as_str()],
            |row| row.get::<i64>(0),
        )? as u64;
        Ok(())
    })?;
    Ok(taken)
}
