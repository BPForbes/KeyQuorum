//! The relay's persistence boundary.
//!
//! Everything a relay keeps (API-key hashes and their audit trail, opaque
//! mailbox letters, the canonical public trees, device descriptors and
//! device letters, audit anchors, whom a sealed key was issued to) is
//! reached through [`RelayStore`]. The route handlers (`service.rs`), the
//! HTTP server, the host `keys` commands and the browser lab all speak to
//! this trait, never to a database handle, so the same relay can run on the
//! owner-only SQLite file it always had ([`SqliteRelayStore`]) or on another
//! backend that keeps each unit of work atomic.
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

use super::activity::{self, Cost, Filter as ActivityFilter, Summary as ActivitySummary};
use super::api_key::{
    self, ApiKeyEvent, ApiKeyInfo, ApiKeyScope, AuthedKey, CreatedApiKey, CreatedLicensee,
    KeyCheck, NewApiKey, OldKey, ProviderAuthRecord,
};
use super::audit::{self, Checkpoint, TableReport};
use super::customer::{self, Customer, LicenceFilter, NewCustomer, Page, UserRow};
use super::device_directory::{self, DeviceDescriptor};
use super::device_mail::{self, DeviceMailPage};
use super::issuance::{self, Issuance, Issued, RotateVia, Rotated, Voided};
use super::key_delivery::{self, Delivered, DeliveryRecord, Recipient};
use super::licence::{self, KeyLink, Licence, Version};
use super::mailbox::{self, LetterSummary, MailboxPage};
use super::operator_log::{self, Note, OperatorAction};
use super::org_tree::{self, TreeSummary};
use super::service::ProviderIdentity;
use super::sql::{params, Sql};
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
/// one connection behind a mutex).
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

    // --- The provider's operator console ---------------------------------
    //
    // Each changing method is one atomic unit of work: the records, the keys,
    // their delivery records and links, and the operation record (`note`)
    // commit together or not at all, and the sealed bundles come back only once
    // they have.

    /// Whether the operator lock exists yet.
    fn operator_lock_exists(&self) -> Result<bool>;
    /// The ids of keys past their own expiry, by the store's clock.
    fn expired_key_ids(&self) -> Result<HashSet<i64>>;
    /// Stage a new operator lock, shown once and not yet the lock (see
    /// `api_key::stage_licensee`).
    fn stage_operator_lock(&self) -> Result<CreatedLicensee>;
    /// Whether a staged lock is waiting to be confirmed.
    fn operator_lock_pending(&self) -> Result<bool>;
    /// Promote the staged lock to the lock when `token` is it.
    fn confirm_operator_lock(&self, token: &str) -> Result<()>;

    /// Record a customer.
    fn create_customer(&self, new: &NewCustomer, note: Option<&Note<'_>>) -> Result<Customer>;
    fn get_customer(&self, id: i64) -> Result<Customer>;
    /// A page of customers with their counts (see `customer::list`).
    fn list_customers(
        &self,
        search: Option<&str>,
        filter: LicenceFilter,
        before: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Page<UserRow>>;
    fn customer_count(&self) -> Result<i64>;
    fn get_licence(&self, id: i64) -> Result<Licence>;
    /// A customer's licences, newest first.
    fn licences_of(&self, customer_id: i64) -> Result<Vec<Licence>>;
    /// The statements a licence has carried, oldest first.
    fn licence_versions(&self, licence_id: i64) -> Result<Vec<Version>>;
    /// How many licences are active, voided and ended.
    fn licence_counts(&self) -> Result<licence::Counts>;
    /// Every key link.
    fn key_links(&self) -> Result<Vec<KeyLink>>;
    /// Record a licence for an existing customer, with no keys.
    fn create_licence(
        &self,
        customer_id: i64,
        new: &licence::NewLicence,
        note: Option<&Note<'_>>,
    ) -> Result<(Licence, Option<Voided>)>;
    /// Issue a licence's keys as sealed bundles (see [`issuance::issue`]).
    fn issue_licensed_bundles(
        &self,
        identity: &ProviderIdentity,
        request: &Issuance,
        note: Option<&Note<'_>>,
    ) -> Result<Issued>;
    /// Replace key `id` under its licence (see [`issuance::rotate`]).
    fn rotate_licensed_key(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        via: RotateVia,
        note: Option<&Note<'_>>,
    ) -> Result<Rotated>;
    /// Void licence `id` and revoke the keys issued under it.
    fn void_licence(
        &self,
        id: i64,
        reason: Option<&str>,
        note: Option<&Note<'_>>,
    ) -> Result<Voided>;
    /// Add a statement version to an active licence.
    fn renew_licence(
        &self,
        id: i64,
        terms: Option<&str>,
        expires_at: Option<&str>,
        note: Option<&Note<'_>>,
    ) -> Result<Licence>;
    /// Revoke one key, with its operation record.
    fn revoke_key_noted(&self, id: i64, note: Option<&Note<'_>>) -> Result<()>;
    /// Assign an unassigned key to a licence.
    fn assign_key(&self, key_id: i64, licence_id: i64, note: Option<&Note<'_>>) -> Result<()>;
    /// Whom each issued key was sealed to (never the sealed bytes).
    fn delivery_records(&self) -> Result<Vec<DeliveryRecord>>;
    /// Count one request by the key `token` names, if it names a stored key.
    fn record_access(&self, token: &str, path: &str, status: u16, cost: Cost) -> Result<()>;
    /// What known keys did over a window, narrowed by the filter.
    fn access_summary(&self, filter: &ActivityFilter) -> Result<ActivitySummary>;
    /// Drop hourly counts past their retention; how many rows.
    fn purge_old_activity(&self) -> Result<u64>;
    /// Record an attempt that changed nothing, by the identity Access verified.
    fn record_operator_action(
        &self,
        operator: &str,
        action: &str,
        subject: Option<&str>,
        success: bool,
    ) -> Result<()>;
    /// The change recorded under an operation id, if it was made.
    fn find_operation(&self, operation_id: &str) -> Result<Option<OperatorAction>>;
    /// The newest `limit` operator actions, older than `before`, newest first.
    fn operator_actions(&self, limit: i64, before: Option<i64>) -> Result<Vec<OperatorAction>>;
    /// The newest `limit` privileged-auth attempts, newest first.
    fn provider_auth_events(&self, limit: i64) -> Result<Vec<ProviderAuthRecord>>;
    /// The inbox's letters without opening them: count and newest `limit`.
    fn inbox_letters(&self, limit: i64) -> Result<(i64, Vec<LetterSummary>)>;
    /// The device mailbox's letters without opening them.
    fn device_letters(&self, limit: i64) -> Result<(i64, Vec<LetterSummary>)>;
    /// The stored public trees by label, generation and update time.
    fn tree_summaries(&self) -> Result<Vec<TreeSummary>>;
}

/// The relay over any SQLite executor ([`Sql`]): one executor, serialized
/// behind a mutex, every method delegating to the module that owns the table
/// (all of them take `&dyn Sql`, none a connection). It is the one
/// implementation of [`RelayStore`], so a backend that is SQLite underneath
/// re-rolls no rule: it supplies an executor, and `relay::store::conformance`
/// runs over it.
///
/// [`SqliteRelayStore`] is this over a `rusqlite` connection, the original
/// owner-only SQLite file, and stays the reference backend and the one the
/// tests, the browser lab and the native host use. The Cloudflare backend
/// (planned) is this over a Durable Object's SQL API, whose executor opens
/// no `BEGIN` of its own (a transaction is `transactionSync`).
pub struct SqlRelayStore<S> {
    sql: Mutex<S>,
    backend: &'static str,
}

/// The relay's original backend: [`SqlRelayStore`] over a SQLite file or an
/// in-memory database.
pub type SqliteRelayStore = SqlRelayStore<Connection>;

impl<S: Sql> SqlRelayStore<S> {
    /// A store over `sql`, reporting itself as `backend`.
    pub fn new(sql: S, backend: &'static str) -> Self {
        Self {
            sql: Mutex::new(sql),
            backend,
        }
    }

    /// The executor, under the store's lock. A poisoned lock is taken over:
    /// the data is SQLite's, not the panicking thread's.
    fn executor(&self) -> MutexGuard<'_, S> {
        self.sql
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn with<T>(&self, f: impl FnOnce(&dyn Sql) -> Result<T>) -> Result<T> {
        let sql = self.executor();
        f(&*sql)
    }
}

impl SqlRelayStore<Connection> {
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
        Self::new(conn, "sqlite")
    }

    /// The connection itself, for callers that still speak SQL to the relay
    /// database (the lab's clock, tests that inspect rows).
    pub fn connection(&self) -> MutexGuard<'_, Connection> {
        self.executor()
    }
}

impl<S: Sql + Send> RelayStore for SqlRelayStore<S> {
    fn backend(&self) -> &'static str {
        self.backend
    }

    fn ping(&self) -> Result<()> {
        self.with(|conn| {
            conn.query_row("SELECT 1", params![], |row| row.get::<i64>(0))?;
            Ok(())
        })
    }

    fn mint_key(&self, new: &NewApiKey) -> Result<CreatedApiKey> {
        self.with(|conn| api_key::create(conn, new))
    }

    fn list_keys(&self) -> Result<Vec<ApiKeyInfo>> {
        self.with(|conn| api_key::list(conn))
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
            conn.with_transaction(|| {
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
        self.with(|conn| mailbox::purge_expired(conn))
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
        self.with(|conn| org_tree::list_public_trees(conn))
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
        self.with(|conn| device_mail::purge_expired(conn))
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

    fn operator_lock_exists(&self) -> Result<bool> {
        self.with(|conn| api_key::licensee_exists(conn))
    }

    fn expired_key_ids(&self) -> Result<HashSet<i64>> {
        self.with(|conn| api_key::expired_ids(conn))
    }

    fn stage_operator_lock(&self) -> Result<CreatedLicensee> {
        self.with(|conn| api_key::stage_licensee(conn))
    }

    fn operator_lock_pending(&self) -> Result<bool> {
        self.with(|conn| api_key::licensee_pending_exists(conn))
    }

    fn confirm_operator_lock(&self, token: &str) -> Result<()> {
        self.with(|conn| api_key::confirm_licensee(conn, token))
    }

    fn create_customer(&self, new: &NewCustomer, note: Option<&Note<'_>>) -> Result<Customer> {
        self.with(|conn| issuance::create_customer(conn, new, note))
    }

    fn get_customer(&self, id: i64) -> Result<Customer> {
        self.with(|conn| customer::get(conn, id))
    }

    fn list_customers(
        &self,
        search: Option<&str>,
        filter: LicenceFilter,
        before: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Page<UserRow>> {
        self.with(|conn| customer::list(conn, search, filter, before, limit))
    }

    fn customer_count(&self) -> Result<i64> {
        self.with(|conn| customer::count(conn))
    }

    fn get_licence(&self, id: i64) -> Result<Licence> {
        self.with(|conn| licence::get(conn, id))
    }

    fn licences_of(&self, customer_id: i64) -> Result<Vec<Licence>> {
        self.with(|conn| licence::list_for_customer(conn, customer_id))
    }

    fn licence_versions(&self, licence_id: i64) -> Result<Vec<Version>> {
        self.with(|conn| licence::versions(conn, licence_id))
    }

    fn licence_counts(&self) -> Result<licence::Counts> {
        self.with(|conn| licence::counts(conn))
    }

    fn key_links(&self) -> Result<Vec<KeyLink>> {
        self.with(|conn| licence::all_links(conn))
    }

    fn create_licence(
        &self,
        customer_id: i64,
        new: &licence::NewLicence,
        note: Option<&Note<'_>>,
    ) -> Result<(Licence, Option<Voided>)> {
        self.with(|conn| issuance::create_licence(conn, customer_id, new, note))
    }

    fn issue_licensed_bundles(
        &self,
        identity: &ProviderIdentity,
        request: &Issuance,
        note: Option<&Note<'_>>,
    ) -> Result<Issued> {
        self.with(|conn| issuance::issue(conn, identity, request, note))
    }

    fn rotate_licensed_key(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        via: RotateVia,
        note: Option<&Note<'_>>,
    ) -> Result<Rotated> {
        self.with(|conn| issuance::rotate(conn, identity, id, via, note))
    }

    fn void_licence(
        &self,
        id: i64,
        reason: Option<&str>,
        note: Option<&Note<'_>>,
    ) -> Result<Voided> {
        self.with(|conn| issuance::void_licence(conn, id, reason, note))
    }

    fn renew_licence(
        &self,
        id: i64,
        terms: Option<&str>,
        expires_at: Option<&str>,
        note: Option<&Note<'_>>,
    ) -> Result<Licence> {
        self.with(|conn| issuance::renew_licence(conn, id, terms, expires_at, note))
    }

    fn revoke_key_noted(&self, id: i64, note: Option<&Note<'_>>) -> Result<()> {
        self.with(|conn| issuance::revoke_key(conn, id, note))
    }

    fn assign_key(&self, key_id: i64, licence_id: i64, note: Option<&Note<'_>>) -> Result<()> {
        self.with(|conn| issuance::assign_key(conn, key_id, licence_id, note))
    }

    fn delivery_records(&self) -> Result<Vec<DeliveryRecord>> {
        self.with(|conn| key_delivery::records(conn))
    }

    fn record_access(&self, token: &str, path: &str, status: u16, cost: Cost) -> Result<()> {
        self.with(|conn| activity::record(conn, token, path, status, cost))
    }

    fn access_summary(&self, filter: &ActivityFilter) -> Result<ActivitySummary> {
        self.with(|conn| activity::summary(conn, filter))
    }

    fn purge_old_activity(&self) -> Result<u64> {
        self.with(|conn| activity::purge_old(conn))
    }

    fn record_operator_action(
        &self,
        operator: &str,
        action: &str,
        subject: Option<&str>,
        success: bool,
    ) -> Result<()> {
        self.with(|conn| operator_log::record(conn, operator, action, subject, success))
    }

    fn find_operation(&self, operation_id: &str) -> Result<Option<OperatorAction>> {
        self.with(|conn| operator_log::find_operation(conn, operation_id))
    }

    fn operator_actions(&self, limit: i64, before: Option<i64>) -> Result<Vec<OperatorAction>> {
        self.with(|conn| operator_log::recent(conn, limit, before))
    }

    fn provider_auth_events(&self, limit: i64) -> Result<Vec<ProviderAuthRecord>> {
        self.with(|conn| api_key::provider_auth_events(conn, limit))
    }

    fn inbox_letters(&self, limit: i64) -> Result<(i64, Vec<LetterSummary>)> {
        self.with(|conn| mailbox::summaries(conn, limit))
    }

    fn device_letters(&self, limit: i64) -> Result<(i64, Vec<LetterSummary>)> {
        self.with(|conn| super::device_mail::summaries(conn, limit))
    }

    fn tree_summaries(&self) -> Result<Vec<TreeSummary>> {
        self.with(|conn| org_tree::summaries(conn))
    }
}

#[cfg(test)]
#[path = "store/conformance.rs"]
pub(crate) mod conformance;

#[cfg(test)]
#[path = "store/tests.rs"]
mod tests;
