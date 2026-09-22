//! Online mailbox for opaque `.kqpb` envelopes, plus the canonical
//! *public* split-tree topology.
//!
//! The relay never unseals envelopes and never holds wrapped shares or
//! private keys. Full public-tree context is stored as JSON documents.
//! Pushing envelopes merges the sender's public topology into those
//! documents; pull returns a sliced copy for the recipient fingerprint
//! that a personal SQLite store translates.

mod api_key;
mod client;
mod device_directory;
mod device_mail;
mod mailbox;
mod org_tree;
#[cfg(feature = "provider")]
mod server;

pub use api_key::{
    authenticate, authenticate_licensee, authorize_licensee_or_bootstrap,
    bootstrap_licensee_if_empty, check_hash, check_token, create as create_api_key, hash_bearer,
    list as list_api_keys, record_provider_auth_event, revoke as revoke_api_key,
    rotate as rotate_api_key, ApiKeyInfo, ApiKeyScope, AuthedKey, CreatedApiKey, CreatedLicensee,
    KeyCheck, NewApiKey,
};
pub use client::{
    authenticate_provider, check_key, check_key_hash, fetch_tree_context, get_device, publish_tree,
    pull as pull_inbox, pull_device_packages, push as push_inbox, push_device_package,
    push_with_trees as push_inbox_with_trees, push_with_trees_until as push_inbox_with_trees_until,
    put_device, validate_relay_url, DevicePackageList, DevicePackagePush, InboxAccepted,
    InboxEnvelope, InboxList, InboxPush, KeyCheckRequest, KeyCheckResponse,
    ProviderIdentityRequest, ProviderIdentityResponse,
};
pub use device_directory::{
    get as get_device_descriptor, put as put_device_descriptor,
    sign_descriptor as sign_device_descriptor, DeviceDescriptor, DeviceSlotDescriptor,
};
pub use device_mail::{
    list_after as list_device_packages, purge_expired as purge_expired_device_packages,
    store as store_device_package, DeviceMailPage, StoredDevicePackage, DEVICE_PACKAGE_TTL_DAYS,
};
pub use mailbox::{
    list_after, purge_expired as purge_expired_envelopes, store, store_until, MailboxPage,
    StoredEnvelope, DEFAULT_INBOX_PAGE, MAX_INBOX_PAGE,
};
pub use org_tree::{
    context_for_fingerprint, contexts_for_fingerprint, get_public_tree, list_public_trees,
    merge_public_tree, put_public_tree, slices_for_fingerprint,
};
#[cfg(feature = "provider")]
pub use server::{router, AppState, ProviderIdentity, MAX_ENVELOPE_BYTES};

use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::time::Duration;

const SCHEMA: &str = include_str!("schema.sql");

const ORGANIZATION_TABLES: [&str; 4] = [
    "hardware_keys",
    "private_bridges",
    "credentials",
    "key_nodes",
];

/// Opens (creating if needed) the relay's own SQLite database and applies
/// the mailbox + public-tree schema. This is not a personal organization
/// database and must not receive wrapped shares or private keys.
///
/// An existing organization store is refused before any relay tables are
/// created, so a `--db` mix-up cannot merge the two schemas.
pub fn open(path: &str) -> Result<Connection> {
    let path_ref = Path::new(path);
    if path_ref.is_file() {
        let meta = std::fs::metadata(path_ref)?;
        if meta.len() > 0 {
            let probe = Connection::open(path)?;
            if looks_like_organization_database(&probe)? {
                return Err(Error::OrganizationDatabase);
            }
        }
    }
    let conn = Connection::open(path)?;
    init(&conn)?;
    Ok(conn)
}

fn looks_like_organization_database(conn: &Connection) -> Result<bool> {
    for table in ORGANIZATION_TABLES {
        let found: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if found > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Opens an in-memory relay database. Intended for tests.
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    init(&conn)?;
    Ok(conn)
}

fn init(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.execute_batch(SCHEMA)?;
    migrate(conn)
}

fn table_sql(conn: &Connection, table: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        rusqlite::params![table],
        |row| row.get(0),
    )
    .optional()
    .map_err(Error::from)
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.iter().any(|name| name == column))
}

/// `CREATE TABLE IF NOT EXISTS` never adds columns to an already-created
/// table. Mailboxes from before envelope TTL need `expires_at`, and device
/// letters stored before device retention get the same TTL from `created_at`.
fn migrate(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "mailbox", "expires_at")? {
        conn.execute("ALTER TABLE mailbox ADD COLUMN expires_at TEXT", [])?;
    }
    if table_sql(conn, "device_mailbox")?.is_some() {
        if !table_has_column(conn, "device_mailbox", "expires_at")? {
            conn.execute("ALTER TABLE device_mailbox ADD COLUMN expires_at TEXT", [])?;
        }
        device_mail::backfill_expiry(conn)?;
    }
    widen_api_key_scopes(conn)
}

/// `CREATE TABLE IF NOT EXISTS` does not widen a CHECK already stored in
/// `sqlite_master`. Mailboxes created before device scopes need that check
/// rebuilt or `device.push` / `device.pull` inserts fail.
fn widen_api_key_scopes(conn: &Connection) -> Result<()> {
    let Some(sql) = table_sql(conn, "api_keys")? else {
        return Ok(());
    };
    if sql.contains("'device.push'") {
        return Ok(());
    }
    conn.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE api_keys_new (
            id                      INTEGER PRIMARY KEY,
            key_hash                TEXT NOT NULL UNIQUE,
            scope                   TEXT NOT NULL CHECK (scope IN (
                'inbox.push', 'inbox.pull', 'admin', 'device.push', 'device.pull'
            )),
            recipient_fingerprint   TEXT,
            label                   TEXT,
            created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            expires_at              TEXT,
            revoked_at              TEXT,
            last_used_at            TEXT,
            CHECK (
                (scope IN ('inbox.pull', 'device.pull') AND recipient_fingerprint IS NOT NULL)
                OR (scope NOT IN ('inbox.pull', 'device.pull') AND recipient_fingerprint IS NULL)
            )
         );
         INSERT INTO api_keys_new
            (id, key_hash, scope, recipient_fingerprint, label, created_at, expires_at,
             revoked_at, last_used_at)
            SELECT id, key_hash, scope, recipient_fingerprint, label, created_at, expires_at,
                   revoked_at, last_used_at
            FROM api_keys;
         DROP TABLE api_keys;
         ALTER TABLE api_keys_new RENAME TO api_keys;
         COMMIT;",
    )?;
    Ok(())
}

#[cfg(test)]
mod test_helpers;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
