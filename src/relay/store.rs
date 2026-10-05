//! The relay's persistence boundary.
//!
//! Everything a relay keeps (API-key hashes and their audit trail, opaque
//! mailbox letters, the canonical public trees, device descriptors and
//! device letters, audit anchors, whom a sealed key was issued to) is
//! reached through [`RelayStore`]. The route handlers (`service.rs`), the
//! HTTP server, the host `keys` commands and the browser lab all speak to
//! this trait, never to a database handle, so the same relay can run on the
//! owner-only SQLite file it always had ([`SqliteRelayStore`]) or, with the
//! `mongodb` feature, on a shared MongoDB deployment (`relay::mongo`) where
//! several relay processes serve one mailbox.
//!
//! The boundary is drawn at the relay's units of work, not at rows: a
//! method is one thing the relay does atomically (push a letter together
//! with the trees it carries, rotate a key together with its sealed
//! replacement, its grace period, its delivery record and its audit event).
//! A backend that cannot do a method atomically must not implement it.
//! This is the relay's persistence only: a personal or organization store
//! stays the SQLite file on the person's own drive and never passes through
//! here.
//!
//! Whatever the backend, the store never holds a raw bearer (only
//! `hex(SHA-256(raw))`), never unseals a letter, and never holds a wrapped
//! share, a private key or the provider root.

use super::api_key::{
    self, ApiKeyEvent, ApiKeyInfo, ApiKeyScope, AuthedKey, CreatedApiKey, CreatedLicensee,
    KeyCheck, NewApiKey, OldKey,
};
use super::audit::{self, Checkpoint, TableReport};
use super::device_directory::{self, DeviceDescriptor};
use super::device_mail::{self, DeviceMailPage};
use super::key_delivery::{self, Delivered, Recipient};
use super::mailbox::{self, MailboxPage};
use super::org_tree;
use super::service::ProviderIdentity;
use crate::error::Result;
use crate::key_tree::PublicTree;
use rusqlite::Connection;
use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard};

/// A letter the store accepted: its id, the recipient fingerprint it is
/// filed under, and whether it was already there (delivery is idempotent
/// by recipient and content hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredLetter {
    pub id: i64,
    pub recipient_fingerprint: String,
    pub duplicate: bool,
}

impl From<(i64, String, bool)> for StoredLetter {
    fn from((id, recipient_fingerprint, duplicate): (i64, String, bool)) -> Self {
        Self {
            id,
            recipient_fingerprint,
            duplicate,
        }
    }
}

/// A privileged provider-auth attempt as `provider_auth_events` records it
/// (`record_provider_auth_event`). Never a key, bearer or challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAuthEvent<'a> {
    pub operation: &'a str,
    pub provider_id: Option<&'a str>,
    pub network_id: Option<&'a str>,
    pub hardware_fingerprints: Option<&'a str>,
    pub success: bool,
}

/// Where the relay keeps its state. See the module documentation.
///
/// Every method is one atomic unit of work. Methods take `&self` and the
/// trait is `Send + Sync`, so one store is shared by every request handler
/// and the scan loop; a backend serializes inside (the SQLite store holds
/// one connection behind a mutex, MongoDB runs transactions on the server).
pub trait RelayStore: Send + Sync {
    /// The backend, for the operator's log line at startup.
    fn backend(&self) -> &'static str;

    /// A round trip to the backend, for a readiness check. Says nothing about
    /// the provider identity.
    fn ping(&self) -> Result<()>;

    // --- API keys --------------------------------------------------------

    /// Mint a key: the bearer is returned once and only its hash is stored,
    /// with a `created` audit event in the same unit of work.
    fn mint_key(&self, new: &NewApiKey) -> Result<CreatedApiKey>;
    fn list_keys(&self) -> Result<Vec<ApiKeyInfo>>;
    fn key_info(&self, id: i64) -> Result<ApiKeyInfo>;
    /// Revoke key `id` and record who did it. Revoking an already revoked
    /// key succeeds and records nothing.
    fn revoke_key_by(&self, id: i64, actor: &str) -> Result<()>;
    /// Replace key `id` with a new key of the same scope and binding, ending
    /// the old one as `old` says, with a `rotated` event, atomically.
    fn rotate_key_with(&self, id: i64, old: OldKey) -> Result<CreatedApiKey>;
    /// Whether a live `inbox.pull` key is bound to `fingerprint`.
    fn has_live_pull_key(&self, fingerprint: &str) -> Result<bool>;
    /// Atomic lookup: stamps last-used only when the key is live, unexpired
    /// and of the required scope.
    fn authenticate(&self, token: &str, required: ApiKeyScope) -> Result<AuthedKey>;
    /// Authenticate a live key of any scope and stamp its use.
    fn authenticate_any(&self, token: &str) -> Result<AuthedKey>;
    /// `POST /keycheck` by token: no scope required, no use recorded.
    fn check_token(&self, token: &str) -> Result<KeyCheck>;
    /// `POST /keycheck` by stored hash.
    fn check_hash(&self, key_hash: &str) -> Result<KeyCheck>;
    /// The lifecycle audit trail, oldest first; with `key`, only the events
    /// that pertain to that key.
    fn key_events(&self, key: Option<i64>) -> Result<Vec<ApiKeyEvent>>;
    /// Authenticate a supplied operator lock, or mint the issuer when none
    /// exists. A supplied key is never ignored in favour of a bootstrap.
    fn authorize_licensee_or_bootstrap(
        &self,
        supplied: Option<&str>,
    ) -> Result<Option<CreatedLicensee>>;
    /// Confirms the caller holds the operator lock.
    fn authenticate_licensee(&self, token: &str) -> Result<()>;
    /// Record a privileged provider-auth attempt, chained into the audit trail.
    fn record_provider_auth_event(&self, event: &ProviderAuthEvent<'_>) -> Result<()>;

    // --- Mailbox ---------------------------------------------------------

    /// `POST /inbox`: merge the public trees the sender attached and store
    /// the opaque letter, atomically. `expires_at` is a UTC cutoff
    /// (`YYYY-MM-DD HH:MM:00`) that must be in the future.
    fn inbox_push(
        &self,
        trees: &[PublicTree],
        envelope: &[u8],
        expires_at: Option<&str>,
    ) -> Result<StoredLetter>;
    /// A page of unexpired letters for `fingerprint` after id `after`.
    fn list_envelopes_after(
        &self,
        fingerprint: &str,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<MailboxPage>;
    /// Delete expired letters; returns how many.
    fn purge_expired_envelopes(&self) -> Result<u64>;

    // --- Public trees ----------------------------------------------------

    /// Replace a canonical public tree (admin).
    fn put_public_tree(&self, tree: &PublicTree) -> Result<PublicTree>;
    /// Merge a sender's public topology into the stored document.
    fn merge_public_tree(&self, tree: &PublicTree) -> Result<PublicTree>;
    fn get_public_tree(&self, label: &str) -> Result<PublicTree>;
    fn list_public_trees(&self) -> Result<Vec<PublicTree>>;

    // --- Devices ---------------------------------------------------------

    /// Store a sealed device letter (kinds 9 to 12 only), with the device TTL.
    fn store_device_package(&self, package: &[u8]) -> Result<StoredLetter>;
    fn list_device_packages_after(
        &self,
        fingerprint: &str,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<DeviceMailPage>;
    fn purge_expired_device_packages(&self) -> Result<u64>;
    /// Store a signed public device descriptor; a known device may not
    /// change its verify key.
    fn put_device_descriptor(&self, descriptor: &DeviceDescriptor) -> Result<DeviceDescriptor>;
    fn get_device_descriptor(&self, device_id: &str) -> Result<Option<DeviceDescriptor>>;

    // --- Audit -----------------------------------------------------------

    /// Sign each audit table's chain head with the relay key unless the
    /// newest anchor already covers it; how many anchors were written.
    fn anchor_audit(&self, identity: &ProviderIdentity, signed_at: &str) -> Result<usize>;
    /// A signed checkpoint of every audit table, for the operator to keep
    /// off the relay.
    fn audit_checkpoint(&self, identity: &ProviderIdentity, taken_at: &str) -> Result<Checkpoint>;
    /// Re-walk every chain and check every anchor (and the checkpoint, if
    /// given) against the provider root.
    fn verify_audit(
        &self,
        root_public_key: &[u8; 32],
        revoked: &HashSet<String>,
        checkpoint: Option<&Checkpoint>,
    ) -> Result<Vec<TableReport>>;

    // --- Sealed key delivery (issue #86) ---------------------------------

    /// Whom key `id` was sealed to, if it ever was.
    fn delivery_recipient_for(&self, id: i64) -> Result<Option<Recipient>>;
    /// Mint a key and hand it to `write` as a sealed `.kqkey` bundle, in one
    /// unit of work: on an error the key does not exist.
    fn mint_key_as_bundle(
        &self,
        identity: &ProviderIdentity,
        new: &NewApiKey,
        recipient: &Recipient,
        write: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Delivered>;
    /// Rotate key `id` and store the sealed replacement in this relay's own
    /// mailbox, the old key staying usable for `grace_seconds`, atomically.
    fn rotate_key_as_letter(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        recipient: Option<Recipient>,
        grace_seconds: i64,
    ) -> Result<Delivered>;
    /// Rotate key `id`, revoking it at once, and hand the replacement to
    /// `write` as a sealed bundle, atomically.
    fn rotate_key_as_bundle(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        recipient: Option<Recipient>,
        write: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Delivered>;
}

/// The relay's original backend: one owner-only SQLite file, one connection,
/// serialized behind a mutex. Every method delegates to the module that
/// owns the table, so this store is exactly the relay as it was before the
/// boundary existed; it remains the reference backend and the one the
/// tests, the browser lab and a single-node deployment use.
pub struct SqliteRelayStore {
    conn: Mutex<Connection>,
}

impl SqliteRelayStore {
    /// Open (creating if needed) the relay database at `path`; see
    /// [`super::open`] for what it refuses.
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self::from_connection(super::open(path)?))
    }

    /// An in-memory relay database. Intended for tests and the lab.
    pub fn open_in_memory() -> Result<Self> {
        Ok(Self::from_connection(super::open_in_memory()?))
    }

    /// Wrap an already opened relay connection.
    pub fn from_connection(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// The connection itself, for callers that still speak SQL to the relay
    /// database (the lab's clock, tests that inspect rows). A poisoned lock
    /// is taken over: the data is SQLite's, not the panicking thread's.
    pub fn connection(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.connection();
        f(&conn)
    }
}

impl RelayStore for SqliteRelayStore {
    fn backend(&self) -> &'static str {
        "sqlite"
    }

    fn ping(&self) -> Result<()> {
        self.with(|conn| {
            conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?;
            Ok(())
        })
    }

    fn mint_key(&self, new: &NewApiKey) -> Result<CreatedApiKey> {
        self.with(|conn| api_key::create(conn, new))
    }

    fn list_keys(&self) -> Result<Vec<ApiKeyInfo>> {
        self.with(api_key::list)
    }

    fn key_info(&self, id: i64) -> Result<ApiKeyInfo> {
        self.with(|conn| api_key::info(conn, id))
    }

    fn revoke_key_by(&self, id: i64, actor: &str) -> Result<()> {
        self.with(|conn| api_key::revoke_by(conn, id, actor))
    }

    fn rotate_key_with(&self, id: i64, old: OldKey) -> Result<CreatedApiKey> {
        self.with(|conn| api_key::rotate_with(conn, id, old))
    }

    fn has_live_pull_key(&self, fingerprint: &str) -> Result<bool> {
        self.with(|conn| api_key::has_live_pull_key(conn, fingerprint))
    }

    fn authenticate(&self, token: &str, required: ApiKeyScope) -> Result<AuthedKey> {
        self.with(|conn| api_key::authenticate(conn, token, required))
    }

    fn authenticate_any(&self, token: &str) -> Result<AuthedKey> {
        self.with(|conn| api_key::authenticate_any(conn, token))
    }

    fn check_token(&self, token: &str) -> Result<KeyCheck> {
        self.with(|conn| api_key::check_token(conn, token))
    }

    fn check_hash(&self, key_hash: &str) -> Result<KeyCheck> {
        self.with(|conn| api_key::check_hash(conn, key_hash))
    }

    fn key_events(&self, key: Option<i64>) -> Result<Vec<ApiKeyEvent>> {
        self.with(|conn| match key {
            Some(id) => api_key::events_for_key(conn, id),
            None => api_key::events(conn),
        })
    }

    fn authorize_licensee_or_bootstrap(
        &self,
        supplied: Option<&str>,
    ) -> Result<Option<CreatedLicensee>> {
        self.with(|conn| api_key::authorize_licensee_or_bootstrap(conn, supplied))
    }

    fn authenticate_licensee(&self, token: &str) -> Result<()> {
        self.with(|conn| api_key::authenticate_licensee(conn, token))
    }

    fn record_provider_auth_event(&self, event: &ProviderAuthEvent<'_>) -> Result<()> {
        self.with(|conn| {
            api_key::record_provider_auth_event(
                conn,
                event.operation,
                event.provider_id,
                event.network_id,
                event.hardware_fingerprints,
                event.success,
            )
        })
    }

    fn inbox_push(
        &self,
        trees: &[PublicTree],
        envelope: &[u8],
        expires_at: Option<&str>,
    ) -> Result<StoredLetter> {
        self.with(|conn| {
            crate::db::with_immediate_transaction(conn, || {
                if let Some(expires_at) = expires_at {
                    crate::locked_files::require_future_expires_utc(conn, expires_at)?;
                }
                for tree in trees {
                    org_tree::merge_public_tree(conn, tree)?;
                }
                mailbox::store_until(conn, envelope, expires_at).map(StoredLetter::from)
            })
        })
    }

    fn list_envelopes_after(
        &self,
        fingerprint: &str,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<MailboxPage> {
        self.with(|conn| mailbox::list_after(conn, fingerprint, after, limit))
    }

    fn purge_expired_envelopes(&self) -> Result<u64> {
        self.with(mailbox::purge_expired)
    }

    fn put_public_tree(&self, tree: &PublicTree) -> Result<PublicTree> {
        self.with(|conn| org_tree::put_public_tree(conn, tree))
    }

    fn merge_public_tree(&self, tree: &PublicTree) -> Result<PublicTree> {
        self.with(|conn| org_tree::merge_public_tree(conn, tree))
    }

    fn get_public_tree(&self, label: &str) -> Result<PublicTree> {
        self.with(|conn| org_tree::get_public_tree(conn, label))
    }

    fn list_public_trees(&self) -> Result<Vec<PublicTree>> {
        self.with(org_tree::list_public_trees)
    }

    fn store_device_package(&self, package: &[u8]) -> Result<StoredLetter> {
        self.with(|conn| device_mail::store(conn, package).map(StoredLetter::from))
    }

    fn list_device_packages_after(
        &self,
        fingerprint: &str,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<DeviceMailPage> {
        self.with(|conn| device_mail::list_after(conn, fingerprint, after, limit))
    }

    fn purge_expired_device_packages(&self) -> Result<u64> {
        self.with(device_mail::purge_expired)
    }

    fn put_device_descriptor(&self, descriptor: &DeviceDescriptor) -> Result<DeviceDescriptor> {
        self.with(|conn| device_directory::put(conn, descriptor))
    }

    fn get_device_descriptor(&self, device_id: &str) -> Result<Option<DeviceDescriptor>> {
        self.with(|conn| device_directory::get(conn, device_id))
    }

    fn anchor_audit(&self, identity: &ProviderIdentity, signed_at: &str) -> Result<usize> {
        self.with(|conn| audit::anchor(conn, identity, signed_at))
    }

    fn audit_checkpoint(&self, identity: &ProviderIdentity, taken_at: &str) -> Result<Checkpoint> {
        self.with(|conn| audit::checkpoint(conn, identity, taken_at))
    }

    fn verify_audit(
        &self,
        root_public_key: &[u8; 32],
        revoked: &HashSet<String>,
        checkpoint: Option<&Checkpoint>,
    ) -> Result<Vec<TableReport>> {
        self.with(|conn| audit::verify(conn, root_public_key, revoked, checkpoint))
    }

    fn delivery_recipient_for(&self, id: i64) -> Result<Option<Recipient>> {
        self.with(|conn| key_delivery::recipient_for(conn, id))
    }

    fn mint_key_as_bundle(
        &self,
        identity: &ProviderIdentity,
        new: &NewApiKey,
        recipient: &Recipient,
        write: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Delivered> {
        self.with(|conn| {
            key_delivery::create_as_bundle(conn, identity, new, recipient, |bytes| write(bytes))
        })
    }

    fn rotate_key_as_letter(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        recipient: Option<Recipient>,
        grace_seconds: i64,
    ) -> Result<Delivered> {
        self.with(|conn| {
            key_delivery::rotate_as_letter(conn, identity, id, recipient, grace_seconds)
        })
    }

    fn rotate_key_as_bundle(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        recipient: Option<Recipient>,
        write: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Delivered> {
        self.with(|conn| {
            key_delivery::rotate_as_bundle(conn, identity, id, recipient, |bytes| write(bytes))
        })
    }
}

#[cfg(test)]
#[path = "store/conformance.rs"]
pub(crate) mod conformance;

#[cfg(test)]
#[path = "store/tests.rs"]
mod tests;
