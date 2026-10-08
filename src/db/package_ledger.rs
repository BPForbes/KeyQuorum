//! The package install ledger (issue #106): what `keyquorum setup` has
//! installed from which `.kqpkg`, and the highest package generation accepted
//! for each stream, so an interrupted setup can be finished, a completed one
//! is not run twice, and an older package can never replace what a newer one
//! installed.
//!
//! A **stream** is `(provider id, recipient, device id, slot label)`: the
//! provider id comes from the package's root-verified certificate and stays the
//! same across certificate renewals and relay URL changes, so neither resets
//! the baseline. The recipient and device are the slot's own; the slot label
//! and the selected container are the approved target.
//!
//! [`decide`] is the one place the six acceptance cases live; [`begin`] runs it
//! again and reserves the generation (and the stream's one pending slot) in the
//! same immediate transaction, before the package's first change. Steps are
//! marked done one at a time after their effect was verified ([`mark_step`]),
//! and a package is marked complete only after the final-state check
//! ([`complete`]). SQLite makes each of these writes atomic; it does not make a
//! file or a relay request atomic with them, which is why each step is
//! idempotent and verified before it is marked.
//!
//! Limits: a store restored from an older copy, or erased, loses its baseline;
//! the ledger cannot detect that. It holds ids, hashes and labels only, never a
//! bearer, key, passphrase or plaintext.

use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// Where a package is installed and for whom: the stream and the container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub provider_id: String,
    /// Hex of the recipient's X25519 public key.
    pub recipient: String,
    /// Hex of the container's device id.
    pub device_id: String,
    pub slot_label: String,
    /// The container path the package was approved for.
    pub container: String,
}

/// A package about to be installed, as the ledger sees it.
#[derive(Clone, Debug)]
pub struct Incoming {
    /// Hex of the package id.
    pub package_id: String,
    /// Hex SHA-256 of the complete signed package bytes.
    pub package_sha256: String,
    /// `client_setup` or `client_update`.
    pub purpose: &'static str,
    /// Hex of the relay key that signed it.
    pub issuer: String,
    pub target: Target,
    /// The signed generation from its setup manifest; `None` for a package
    /// with no manifest, which may not replace anything.
    pub generation: Option<u64>,
    /// Hex SHA-256 of the licence text the keys carry, when they carry one.
    pub licence_sha256: Option<String>,
}

/// What to do with an incoming package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// A new package: install it from the first step.
    Install,
    /// The same package, started earlier and not finished: these steps are
    /// done (their effects are checked again before the rest run).
    Resume { steps_done: Vec<String> },
    /// The same package, already complete: nothing to do.
    AlreadyInstalled,
}

/// One package's record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub package_id: String,
    pub package_sha256: String,
    pub purpose: String,
    pub target: Target,
    pub generation: Option<u64>,
    pub steps_done: Vec<String>,
    pub state: String,
}

/// A ledger refusal, reported as a refused package.
fn refused(reason: impl Into<String>) -> Error {
    Error::KqpkgRefused(reason.into())
}

/// One `package_installs` row as a [`Record`].
fn record_of(row: &rusqlite::Row) -> rusqlite::Result<Record> {
    let steps: String = row.get(10)?;
    Ok(Record {
        package_id: row.get(0)?,
        package_sha256: row.get(1)?,
        purpose: row.get(2)?,
        target: Target {
            provider_id: row.get(3)?,
            recipient: row.get(4)?,
            device_id: row.get(5)?,
            slot_label: row.get(6)?,
            container: row.get(7)?,
        },
        generation: row.get::<_, Option<i64>>(8)?.map(|g| g as u64),
        state: row.get(9)?,
        steps_done: steps
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

const SELECT: &str = "SELECT package_id, package_sha256, purpose, provider_id, recipient, \
     device_id, slot_label, container, generation, state, steps_done FROM package_installs";

/// The record of package `package_id`, if setup ever started it.
pub fn record(conn: &Connection, package_id: &str) -> Result<Option<Record>> {
    Ok(conn
        .query_row(
            &format!("{SELECT} WHERE package_id = ?1"),
            params![package_id],
            record_of,
        )
        .optional()?)
}

/// The package still pending in `target`'s stream, if one is.
pub fn pending_in_stream(conn: &Connection, target: &Target) -> Result<Option<Record>> {
    Ok(conn
        .query_row(
            &format!(
                "{SELECT} WHERE provider_id = ?1 AND recipient = ?2 AND device_id = ?3
                 AND slot_label = ?4 AND state = 'pending'"
            ),
            params![
                target.provider_id,
                target.recipient,
                target.device_id,
                target.slot_label
            ],
            record_of,
        )
        .optional()?)
}

/// The highest generation accepted in `target`'s stream, if any.
pub fn baseline(conn: &Connection, target: &Target) -> Result<Option<u64>> {
    Ok(conn
        .query_row(
            "SELECT generation FROM package_baselines WHERE provider_id = ?1 AND recipient = ?2
             AND device_id = ?3 AND slot_label = ?4",
            params![
                target.provider_id,
                target.recipient,
                target.device_id,
                target.slot_label
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|g| g as u64))
}

/// Whether a package update in `target`'s stream replaced the key with this
/// hash; such a key is never installed again.
pub fn is_retired(conn: &Connection, target: &Target, key_hash: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM package_retired_keys WHERE provider_id = ?1 AND recipient = ?2
             AND device_id = ?3 AND slot_label = ?4 AND key_hash = ?5",
            params![
                target.provider_id,
                target.recipient,
                target.device_id,
                target.slot_label,
                key_hash
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// The six acceptance cases, in order:
///
/// 1. the same id with different bytes is refused;
/// 2. the same package for another target is refused;
/// 3. the same package, pending, resumes unless a newer accepted package has
///    since raised the baseline past it (or it was abandoned);
/// 4. the same package, complete, is reported installed and not run again;
/// 5. a different package whose generation is at or below the baseline is
///    refused as stale;
/// 6. a newer package is accepted only when no other package is pending in
///    its stream.
pub fn decide(conn: &Connection, incoming: &Incoming) -> Result<Decision> {
    decide_in_batch(conn, incoming, &[])
}

/// [`decide`] for a package checked with others before any is applied
/// (`setup A.kqpkg B.kqpkg`): a package of the stream left pending earlier
/// does not block it when that package is one of `batch`, which runs it
/// first. Every other rule is the same, and each package is decided again
/// with [`decide`] (through [`begin`]) just before it is applied.
pub fn decide_in_batch(
    conn: &Connection,
    incoming: &Incoming,
    batch: &[String],
) -> Result<Decision> {
    if let Some(existing) = record(conn, &incoming.package_id)? {
        if existing.package_sha256 != incoming.package_sha256 {
            return Err(refused(format!(
                "package {} was installed from different bytes; this file is not that package",
                incoming.package_id
            )));
        }
        if existing.target != incoming.target {
            return Err(refused(format!(
                "package {} was approved for {} on {}; it is not installed anywhere else",
                incoming.package_id, existing.target.slot_label, existing.target.container
            )));
        }
        return match existing.state.as_str() {
            "complete" => Ok(Decision::AlreadyInstalled),
            "failed" => Err(refused(format!(
                "package {} was abandoned; ask your provider for a new package",
                incoming.package_id
            ))),
            _ => {
                let superseded = match (baseline(conn, &incoming.target)?, existing.generation) {
                    (Some(base), Some(own)) => base > own,
                    _ => false,
                };
                if superseded {
                    return Err(refused(format!(
                        "package {} was superseded by a newer package before it finished; \
                         abandon it with `setup --abandon {}`",
                        incoming.package_id, incoming.package_id
                    )));
                }
                Ok(Decision::Resume {
                    steps_done: existing.steps_done,
                })
            }
        };
    }
    if let (Some(generation), Some(base)) = (incoming.generation, baseline(conn, &incoming.target)?)
    {
        if generation <= base {
            return Err(refused(format!(
                "package generation {generation} is not newer than {base}, the newest this slot \
                 accepted from the provider; an older package cannot replace newer credentials"
            )));
        }
    }
    if let Some(pending) = pending_in_stream(conn, &incoming.target)?
        .filter(|pending| !batch.contains(&pending.package_id))
    {
        return Err(refused(format!(
            "package {} is still being installed for this slot; finish it by running setup with \
             it again, or abandon it with `setup --abandon {}`",
            pending.package_id, pending.package_id
        )));
    }
    Ok(Decision::Install)
}

/// Decides again and, for a new package, records it pending and raises the
/// stream's baseline to its generation, in one immediate transaction, before
/// the package's first change. Two setups racing for one stream cannot both
/// pass: the second finds the first pending (and the unique index stops it if
/// not). Returns the decision it acted on.
pub fn begin(conn: &Connection, incoming: &Incoming) -> Result<Decision> {
    super::with_immediate_transaction(conn, || {
        let decision = decide(conn, incoming)?;
        if decision != Decision::Install {
            return Ok(decision);
        }
        let t = &incoming.target;
        conn.execute(
            "INSERT INTO package_installs (package_id, package_sha256, purpose, issuer,
                provider_id, recipient, device_id, slot_label, container, generation,
                licence_sha256, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending')",
            params![
                incoming.package_id,
                incoming.package_sha256,
                incoming.purpose,
                incoming.issuer,
                t.provider_id,
                t.recipient,
                t.device_id,
                t.slot_label,
                t.container,
                incoming.generation.map(|g| g as i64),
                incoming.licence_sha256,
            ],
        )?;
        if let Some(generation) = incoming.generation {
            conn.execute(
                "INSERT INTO package_baselines (provider_id, recipient, device_id, slot_label,
                    generation)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (provider_id, recipient, device_id, slot_label)
                 DO UPDATE SET generation = MAX(generation, excluded.generation)",
                params![
                    t.provider_id,
                    t.recipient,
                    t.device_id,
                    t.slot_label,
                    generation as i64
                ],
            )?;
        }
        Ok(Decision::Install)
    })
}

/// Marks step `step` of pending package `package_id` done. Called only after
/// the step's effect was verified.
pub fn mark_step(conn: &Connection, package_id: &str, step: &str) -> Result<()> {
    super::with_immediate_transaction(conn, || {
        let Some(existing) = record(conn, package_id)? else {
            return Err(refused(format!(
                "package {package_id} is not being installed"
            )));
        };
        if existing.state != "pending" {
            return Err(refused(format!("package {package_id} is not pending")));
        }
        if existing.steps_done.iter().any(|done| done == step) {
            return Ok(());
        }
        let mut steps = existing.steps_done;
        steps.push(step.to_string());
        conn.execute(
            "UPDATE package_installs SET steps_done = ?2,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE package_id = ?1",
            params![package_id, steps.join(",")],
        )?;
        Ok(())
    })
}

/// Records that a package update replaced the key with hash `key_hash` in
/// `target`'s stream, before the replacement is stored.
pub fn retire_key(conn: &Connection, target: &Target, key_hash: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO package_retired_keys (provider_id, recipient, device_id,
            slot_label, key_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            target.provider_id,
            target.recipient,
            target.device_id,
            target.slot_label,
            key_hash
        ],
    )?;
    Ok(())
}

/// Marks pending package `package_id` complete, after its final state was
/// verified.
pub fn complete(conn: &Connection, package_id: &str) -> Result<()> {
    let changed = conn.execute(
        "UPDATE package_installs SET state = 'complete',
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE package_id = ?1 AND state = 'pending'",
        params![package_id],
    )?;
    if changed != 1 {
        return Err(refused(format!("package {package_id} is not pending")));
    }
    Ok(())
}

/// Abandons pending package `package_id` (the explicit reconciliation a stuck
/// install needs before another package can proceed in its stream). The
/// baseline it raised stays: abandoning never lets an older package in. What it
/// already installed stays installed.
pub fn abandon(conn: &Connection, package_id: &str) -> Result<Record> {
    super::with_immediate_transaction(conn, || {
        let Some(existing) = record(conn, package_id)? else {
            return Err(refused(format!(
                "no package {package_id} was ever started here"
            )));
        };
        if existing.state != "pending" {
            return Err(refused(format!(
                "package {package_id} is {}, not pending",
                existing.state
            )));
        }
        conn.execute(
            "UPDATE package_installs SET state = 'failed',
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE package_id = ?1",
            params![package_id],
        )?;
        Ok(existing)
    })
}

#[cfg(test)]
#[path = "package_ledger/tests.rs"]
mod tests;
