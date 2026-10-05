//! The hosted relay's store: one MongoDB deployment shared by every relay
//! replica (`MongoRelayStore`, feature `mongodb`).
//!
//! It implements [`RelayStore`] with the same rules as the SQLite store and
//! reuses the same code wherever a rule lives in one place (the audit chain
//! arithmetic in `relay::audit`, letter routing in `relay::mailbox` and
//! `relay::device_mail`, tree merging in `relay::org_tree`, descriptor
//! checks in `relay::device_directory`, the sealed key-delivery flow in
//! `relay::key_delivery`). What is MongoDB's own is below: documents,
//! indexes, id allocation, and the transactions that keep each unit of work
//! atomic when several replicas write at once.
//!
//! The SQLite relay serializes every write through one connection. Here
//! the server does: a unit of work that writes is a multi-document
//! transaction (snapshot read concern, majority write concern) and is
//! retried from the start when the server reports a write conflict, so two
//! replicas appending to the same audit chain, pushing the same letter, or
//! rotating the same key cannot both commit against the same previous
//! state. The audit chains keep an explicit head document
//! (`audit_heads`) that is advanced by compare-and-set: a row is chained
//! onto the head the transaction read, and the commit fails unless that is
//! still the head. Ids come from `counters`, allocated inside the same
//! transaction, so a letter's id is in commit order and a client paging
//! with `after` never skips one.
//!
//! Like every relay store this one holds API-key hashes, never bearers;
//! opaque sealed letters, never their contents; public trees and public
//! device descriptors; the audit trail and its anchors; and whom a sealed
//! key was issued to. A personal or organization store never lives here.

use super::api_key::{
    self, ApiKeyEvent, ApiKeyInfo, ApiKeyScope, AuthedKey, CreatedApiKey, CreatedLicensee,
    KeyCheck, NewApiKey, OldKey, HOST_ACTOR,
};
use super::audit::{self, AnchorRow, AuditTable, Checkpoint, TableReport};
use super::device_directory::{self, DeviceDescriptor};
use super::device_mail::{self, DeviceMailPage, StoredDevicePackage, DEVICE_PACKAGE_TTL_DAYS};
use super::key_delivery::{self, Delivered, DeliveryOps, Recipient, Via};
use super::mailbox::{self, MailboxPage, StoredEnvelope};
use super::org_tree;
use super::service::ProviderIdentity;
use super::store::{ProviderAuthEvent, RelayStore, StoredLetter};
use crate::db::relay_credential::normalize_url;
use crate::error::{Error, Result};
use crate::key_tree::PublicTree;
use mongodb::bson::{doc, spec::BinarySubtype, Binary, Bson, DateTime, Document};
use mongodb::error::{TRANSIENT_TRANSACTION_ERROR, UNKNOWN_TRANSACTION_COMMIT_RESULT};
use mongodb::options::{ClientOptions, IndexOptions, ReadConcern, ReturnDocument, WriteConcern};
use mongodb::sync::{Client, ClientSession, Collection, Database};
use mongodb::IndexModel;
use std::collections::HashSet;
use std::time::{Duration, Instant};

mod clock;

/// The layout version this build writes (`schema_meta`). A newer deployment
/// is refused rather than misread; an older one is migrated on open.
pub const SCHEMA_VERSION: i64 = 1;

/// How long a unit of work keeps being retried after write conflicts
/// before the request fails.
const TRANSACTION_DEADLINE: Duration = Duration::from_secs(30);

/// Documents the server sends a mailbox page's cursor at a time, so the
/// driver never buffers more than a few letters ahead of the byte budget.
const PAGE_BATCH: u32 = 4;

/// How long `open` waits to find a server before giving up.
const SERVER_SELECTION_TIMEOUT: Duration = Duration::from_secs(10);

const API_KEYS: &str = "api_keys";
const API_KEY_EVENTS: &str = "api_key_events";
const PROVIDER_AUTH_EVENTS: &str = "provider_auth_events";
const AUDIT_HEADS: &str = "audit_heads";
const AUDIT_ANCHORS: &str = "audit_anchors";
const COUNTERS: &str = "counters";
const MAILBOX: &str = "mailbox";
const DEVICE_MAILBOX: &str = "device_mailbox";
const DEVICE_DIRECTORY: &str = "device_directory";
const PUBLIC_TREES: &str = "public_trees";
const OPERATOR_ISSUER: &str = "operator_issuer";
const API_KEY_DELIVERIES: &str = "api_key_deliveries";
const SCHEMA_META: &str = "schema_meta";

/// Every collection this store owns, in the order the runbook lists them.
pub const COLLECTIONS: [&str; 13] = [
    API_KEYS,
    API_KEY_EVENTS,
    PROVIDER_AUTH_EVENTS,
    AUDIT_HEADS,
    AUDIT_ANCHORS,
    COUNTERS,
    MAILBOX,
    DEVICE_MAILBOX,
    DEVICE_DIRECTORY,
    PUBLIC_TREES,
    OPERATOR_ISSUER,
    API_KEY_DELIVERIES,
    SCHEMA_META,
];

/// Collections a personal or organization store would have. A database
/// holding one is not a relay database, whatever its name.
const ORGANIZATION_COLLECTIONS: [&str; 4] = [
    "hardware_keys",
    "private_bridges",
    "credentials",
    "key_nodes",
];

/// A relay store on a MongoDB replica set. Cheap to clone; every clone
/// shares the driver's connection pool.
#[derive(Clone)]
pub struct MongoRelayStore {
    client: Client,
    db: Database,
}

/// Where the hosted relay keeps its state, as the operator configures it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MongoSettings {
    /// The database name within the deployment (`keyquorum` by default).
    pub database: String,
}

impl Default for MongoSettings {
    fn default() -> Self {
        Self {
            database: "keyquorum".to_string(),
        }
    }
}

fn store_err(err: mongodb::error::Error) -> Error {
    if err.contains_label(TRANSIENT_TRANSACTION_ERROR) || is_duplicate_key(&err) {
        Error::StoreConflict
    } else {
        Error::Store(err.to_string())
    }
}

/// `E11000`: an insert hit a unique index.
fn is_duplicate_key(err: &mongodb::error::Error) -> bool {
    use mongodb::error::{ErrorKind, WriteFailure};
    match err.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(write)) => write.code == 11_000,
        ErrorKind::Command(command) => command.code == 11_000,
        ErrorKind::BulkWrite(bulk) => bulk.write_errors.values().any(|write| write.code == 11_000),
        _ => false,
    }
}

fn bson_err(err: mongodb::bson::error::Error) -> Error {
    Error::Store(format!("malformed relay document: {err}"))
}

fn binary(bytes: &[u8]) -> Binary {
    Binary {
        subtype: BinarySubtype::Generic,
        bytes: bytes.to_vec(),
    }
}

fn opt_str(value: Option<&str>) -> Bson {
    value.map_or(Bson::Null, |s| Bson::String(s.to_string()))
}

fn get_opt_str(doc: &Document, key: &str) -> Result<Option<String>> {
    match doc.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Error::Store(format!(
            "relay document field {key} is not text"
        ))),
    }
}

fn get_opt_i64(doc: &Document, key: &str) -> Result<Option<i64>> {
    match doc.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::Int64(n)) => Ok(Some(*n)),
        Some(Bson::Int32(n)) => Ok(Some(i64::from(*n))),
        Some(_) => Err(Error::Store(format!(
            "relay document field {key} is not an integer"
        ))),
    }
}

fn get_i64(doc: &Document, key: &str) -> Result<i64> {
    get_opt_i64(doc, key)?.ok_or_else(|| Error::Store(format!("relay document lacks {key}")))
}

fn get_str(doc: &Document, key: &str) -> Result<String> {
    get_opt_str(doc, key)?.ok_or_else(|| Error::Store(format!("relay document lacks {key}")))
}

fn get_bytes(doc: &Document, key: &str) -> Result<Vec<u8>> {
    doc.get_binary_generic(key).cloned().map_err(bson_err)
}

/// The BSON instant of a `YYYY-MM-DD HH:MM[:SS]` cutoff, for the TTL index
/// that removes a letter the moment it expires even between scans.
fn purge_at(expires_at: &str) -> Bson {
    match clock::parse_seconds(expires_at) {
        Some(secs) => Bson::DateTime(DateTime::from_millis(secs.saturating_mul(1_000))),
        None => Bson::Null,
    }
}

/// One session on the deployment, with or without a transaction open. Every
/// operation runs through one of these so that reads inside a transaction
/// see its snapshot and writes join it.
pub(crate) struct Tx<'a> {
    session: &'a mut ClientSession,
    db: &'a Database,
    /// Cleared once the unit of work has had an effect outside the store
    /// (a bundle handed to the caller): a conflict after that is reported,
    /// never retried, since a retry would mint a different key.
    retryable: bool,
}

impl Tx<'_> {
    fn coll(&self, name: &str) -> Collection<Document> {
        self.db.collection::<Document>(name)
    }

    fn find_one(&mut self, name: &str, filter: Document) -> Result<Option<Document>> {
        self.coll(name)
            .find_one(filter)
            .session(&mut *self.session)
            .run()
            .map_err(store_err)
    }

    fn find_all(
        &mut self,
        name: &str,
        filter: Document,
        sort: Document,
        limit: Option<i64>,
    ) -> Result<Vec<Document>> {
        let coll = self.coll(name);
        let mut find = coll.find(filter).sort(sort);
        if let Some(limit) = limit {
            find = find.limit(limit);
        }
        let mut cursor = find.session(&mut *self.session).run().map_err(store_err)?;
        cursor
            .iter(&mut *self.session)
            .map(|doc| doc.map_err(store_err))
            .collect()
    }

    fn insert_one(&mut self, name: &str, document: Document) -> Result<()> {
        self.coll(name)
            .insert_one(document)
            .session(&mut *self.session)
            .run()
            .map(|_| ())
            .map_err(store_err)
    }

    /// `$set` on the one document matching `filter`; whether one matched.
    fn update_one(&mut self, name: &str, filter: Document, set: Document) -> Result<bool> {
        let result = self
            .coll(name)
            .update_one(filter, doc! { "$set": set })
            .session(&mut *self.session)
            .run()
            .map_err(store_err)?;
        Ok(result.matched_count == 1)
    }

    fn upsert_one(&mut self, name: &str, filter: Document, set: Document) -> Result<()> {
        self.coll(name)
            .update_one(filter, doc! { "$set": set })
            .upsert(true)
            .session(&mut *self.session)
            .run()
            .map(|_| ())
            .map_err(store_err)
    }

    fn delete_many(&mut self, name: &str, filter: Document) -> Result<u64> {
        self.coll(name)
            .delete_many(filter)
            .session(&mut *self.session)
            .run()
            .map(|result| result.deleted_count)
            .map_err(store_err)
    }

    /// The next id for `counter`, allocated in this session (so, inside a
    /// transaction, in commit order).
    fn next_id(&mut self, counter: &str) -> Result<i64> {
        let updated = self
            .coll(COUNTERS)
            .find_one_and_update(doc! { "_id": counter }, doc! { "$inc": { "next": 1i64 } })
            .upsert(true)
            .return_document(ReturnDocument::After)
            .session(&mut *self.session)
            .run()
            .map_err(store_err)?
            .ok_or_else(|| Error::Store(format!("counter {counter} did not return")))?;
        get_i64(&updated, "next")
    }

    /// From here on a conflict is an error, not a retry.
    fn no_retry(&mut self) {
        self.retryable = false;
    }
}

impl MongoRelayStore {
    /// Connect to the deployment `uri` names and use its database
    /// `settings.database`, creating the collections and indexes the relay
    /// needs. The URI may carry credentials; it is never logged.
    pub fn open(uri: &str, settings: &MongoSettings) -> Result<Self> {
        let mut options = ClientOptions::parse(uri).run().map_err(store_err)?;
        options.app_name = Some("keyquorum-relay".to_string());
        options.server_selection_timeout = Some(SERVER_SELECTION_TIMEOUT);
        if options.connect_timeout.is_none() {
            options.connect_timeout = Some(SERVER_SELECTION_TIMEOUT);
        }
        let client = Client::with_options(options).map_err(store_err)?;
        let db = client.database(&settings.database);
        let store = Self { client, db };
        store.refuse_organization_database()?;
        store.ensure_schema()?;
        Ok(store)
    }

    /// The database name this store writes to.
    pub fn database_name(&self) -> &str {
        self.db.name()
    }

    /// Drop the whole database. For tests that made their own.
    pub fn drop_database(&self) -> Result<()> {
        self.db.drop().run().map_err(store_err)
    }

    fn refuse_organization_database(&self) -> Result<()> {
        let names = self.db.list_collection_names().run().map_err(store_err)?;
        if names
            .iter()
            .any(|name| ORGANIZATION_COLLECTIONS.contains(&name.as_str()))
        {
            return Err(Error::OrganizationDatabase);
        }
        Ok(())
    }

    /// Indexes are idempotent to create; the schema version is checked so
    /// an older build never writes into a layout it does not know.
    fn ensure_schema(&self) -> Result<()> {
        let meta = self.db.collection::<Document>(SCHEMA_META);
        // The recorded layout version is read, and a newer one refused,
        // before anything is written: a build rolled back onto a newer
        // database must leave it exactly as it found it, not first apply its
        // own (older) index set to it.
        let recorded = meta
            .find_one(doc! { "_id": "schema" })
            .run()
            .map_err(store_err)?;
        if let Some(existing) = &recorded {
            let version = get_i64(existing, "version")?;
            if version > SCHEMA_VERSION {
                return Err(Error::Store(format!(
                    "relay database schema is version {version}, newer than this build's {SCHEMA_VERSION}"
                )));
            }
        }
        let unique = || IndexOptions::builder().unique(true).build();
        let ttl = || {
            IndexOptions::builder()
                .expire_after(Duration::from_secs(0))
                .build()
        };
        let index = |keys: Document, options: Option<IndexOptions>| {
            let mut model = IndexModel::builder().keys(keys).build();
            model.options = options;
            model
        };
        let plans: [(&str, Vec<IndexModel>); 6] = [
            (
                API_KEYS,
                vec![
                    index(doc! { "key_hash": 1 }, Some(unique())),
                    index(
                        doc! { "scope": 1, "recipient_fingerprint": 1, "revoked_at": 1 },
                        None,
                    ),
                ],
            ),
            (
                API_KEY_EVENTS,
                vec![
                    index(doc! { "api_key_id": 1, "_id": 1 }, None),
                    index(doc! { "related_key_id": 1 }, None),
                    index(doc! { "actor": 1 }, None),
                ],
            ),
            (
                AUDIT_ANCHORS,
                vec![
                    index(doc! { "table_name": 1, "row_count": 1 }, Some(unique())),
                    index(doc! { "table_name": 1, "_id": 1 }, None),
                ],
            ),
            (
                MAILBOX,
                vec![
                    index(
                        doc! { "recipient_fingerprint": 1, "content_hash": 1 },
                        Some(unique()),
                    ),
                    index(doc! { "recipient_fingerprint": 1, "_id": 1 }, None),
                    index(doc! { "purge_at": 1 }, Some(ttl())),
                ],
            ),
            (
                DEVICE_MAILBOX,
                vec![
                    index(
                        doc! { "recipient_fingerprint": 1, "content_hash": 1 },
                        Some(unique()),
                    ),
                    index(doc! { "recipient_fingerprint": 1, "_id": 1 }, None),
                    index(doc! { "purge_at": 1 }, Some(ttl())),
                ],
            ),
            (
                PROVIDER_AUTH_EVENTS,
                vec![index(doc! { "operation": 1, "_id": 1 }, None)],
            ),
        ];
        for (name, models) in plans {
            self.db
                .collection::<Document>(name)
                .create_indexes(models)
                .run()
                .map_err(store_err)?;
        }
        match recorded {
            Some(existing) => {
                let version = get_i64(&existing, "version")?;
                if version < SCHEMA_VERSION {
                    // No older layout exists yet; a later version adds its
                    // migration here and then records the new version.
                    meta.update_one(
                        doc! { "_id": "schema" },
                        doc! { "$set": { "version": SCHEMA_VERSION, "updated_at": clock::now_iso_millis()? } },
                    )
                    .run()
                    .map_err(store_err)?;
                }
            }
            None => {
                let result = meta
                    .insert_one(doc! {
                        "_id": "schema",
                        "version": SCHEMA_VERSION,
                        "created_at": clock::now_iso_millis()?,
                    })
                    .run();
                match result {
                    Ok(_) => {}
                    Err(err) if is_duplicate_key(&err) => {}
                    Err(err) => return Err(store_err(err)),
                }
            }
        }
        Ok(())
    }

    /// Run `f` in a session with no transaction: reads see majority-committed
    /// data and single-document writes are atomic on their own.
    fn with_session<T>(&self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let mut session = self.client.start_session().run().map_err(store_err)?;
        let mut tx = Tx {
            session: &mut session,
            db: &self.db,
            retryable: false,
        };
        f(&mut tx)
    }

    /// Run `f` as one transaction, retried from the start on a write
    /// conflict until it commits or [`TRANSACTION_DEADLINE`] passes. `f`
    /// must be repeatable: it is called again on each retry.
    fn transaction<T>(&self, mut f: impl FnMut(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let mut session = self.client.start_session().run().map_err(store_err)?;
        let deadline = Instant::now() + TRANSACTION_DEADLINE;
        loop {
            session
                .start_transaction()
                .read_concern(ReadConcern::snapshot())
                .write_concern(WriteConcern::majority())
                .run()
                .map_err(store_err)?;
            let (outcome, retryable) = {
                let mut tx = Tx {
                    session: &mut session,
                    db: &self.db,
                    retryable: true,
                };
                let outcome = f(&mut tx);
                (outcome, tx.retryable)
            };
            let value = match outcome {
                Ok(value) => value,
                Err(Error::StoreConflict) if retryable && Instant::now() < deadline => {
                    let _ = session.abort_transaction().run();
                    continue;
                }
                Err(err) => {
                    let _ = session.abort_transaction().run();
                    return Err(err);
                }
            };
            loop {
                match session.commit_transaction().run() {
                    Ok(()) => return Ok(value),
                    Err(err) if err.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) => {
                        if Instant::now() >= deadline {
                            // The commit may have applied: say so, rather
                            // than report a failure the caller would undo.
                            tracing::warn!("relay store commit outcome unknown: {err}");
                            return Err(Error::StoreCommitUnknown);
                        }
                        continue;
                    }
                    Err(err)
                        if err.contains_label(TRANSIENT_TRANSACTION_ERROR)
                            && retryable
                            && Instant::now() < deadline =>
                    {
                        break;
                    }
                    Err(err) => return Err(store_err(err)),
                }
            }
        }
    }
}

// --- API keys ----------------------------------------------------------

fn info_from(doc: &Document) -> Result<ApiKeyInfo> {
    Ok(ApiKeyInfo {
        id: get_i64(doc, "_id")?,
        scope: get_str(doc, "scope")?,
        recipient_fingerprint: get_opt_str(doc, "recipient_fingerprint")?,
        label: get_opt_str(doc, "label")?,
        created_at: get_str(doc, "created_at")?,
        expires_at: get_opt_str(doc, "expires_at")?,
        revoked_at: get_opt_str(doc, "revoked_at")?,
        last_used_at: get_opt_str(doc, "last_used_at")?,
    })
}

fn key_info(tx: &mut Tx<'_>, id: i64) -> Result<ApiKeyInfo> {
    let doc = tx
        .find_one(API_KEYS, doc! { "_id": id })?
        .ok_or(Error::ApiKeyNotFound)?;
    info_from(&doc)
}

/// The filter for a key that is live now (not revoked, not past its expiry).
fn live_filter(now_seconds: &str) -> Document {
    doc! {
        "revoked_at": Bson::Null,
        "$or": [
            { "expires_at": Bson::Null },
            { "expires_at": { "$gt": now_seconds } },
        ],
    }
}

fn insert_key(
    tx: &mut Tx<'_>,
    new: &NewApiKey,
    expires_at: Option<String>,
) -> Result<CreatedApiKey> {
    let fingerprint = match (
        new.scope.binds_recipient(),
        new.recipient_fingerprint.as_deref(),
    ) {
        (true, Some(fp)) => Some(api_key::normalize_fingerprint(fp)?),
        (true, None) => return Err(Error::InvalidApiKeyRequest),
        (false, Some(_)) => return Err(Error::InvalidApiKeyRequest),
        (false, None) => None,
    };
    let expires_at = match (expires_at, new.ttl_seconds) {
        (Some(copied), _) => Some(copied),
        (None, Some(0)) => return Err(Error::InvalidApiKeyRequest),
        (None, Some(ttl)) => Some(clock::seconds_after(ttl)?),
        (None, None) => None,
    };
    let (token, token_hash) = api_key::generate_bearer();
    let id = tx.next_id(API_KEYS)?;
    let created_at = clock::now_iso_millis()?;
    tx.insert_one(
        API_KEYS,
        doc! {
            "_id": id,
            "key_hash": &token_hash,
            "scope": new.scope.as_str(),
            "recipient_fingerprint": opt_str(fingerprint.as_deref()),
            "label": opt_str(new.label.as_deref()),
            "created_at": &created_at,
            "expires_at": opt_str(expires_at.as_deref()),
            "revoked_at": Bson::Null,
            "last_used_at": Bson::Null,
        },
    )?;
    Ok(CreatedApiKey {
        info: ApiKeyInfo {
            id,
            scope: new.scope.as_str().to_string(),
            recipient_fingerprint: fingerprint,
            label: new.label.clone(),
            created_at,
            expires_at,
            revoked_at: None,
            last_used_at: None,
        },
        token,
    })
}

fn record_key_event(
    tx: &mut Tx<'_>,
    key_id: i64,
    event: &str,
    actor: &str,
    related_key_id: Option<i64>,
) -> Result<()> {
    let occurred_at = clock::now_iso_millis()?;
    let fields = vec![
        Some(key_id.to_string()),
        Some(event.to_string()),
        Some(actor.to_string()),
        related_key_id.map(|id| id.to_string()),
        Some(occurred_at.clone()),
    ];
    let document = doc! {
        "api_key_id": key_id,
        "event": event,
        "actor": actor,
        "related_key_id": related_key_id.map_or(Bson::Null, Bson::Int64),
        "occurred_at": occurred_at,
    };
    append_audit(tx, AuditTable::ApiKeyEvents, fields, document)
}

fn create_key(tx: &mut Tx<'_>, new: &NewApiKey) -> Result<CreatedApiKey> {
    let created = insert_key(tx, new, None)?;
    record_key_event(tx, created.info.id, "created", HOST_ACTOR, None)?;
    Ok(created)
}

/// Revoke key `id` unless already revoked; whether this call revoked it.
fn revoke_key(tx: &mut Tx<'_>, id: i64, actor: &str) -> Result<()> {
    let revoked = tx.update_one(
        API_KEYS,
        doc! { "_id": id, "revoked_at": Bson::Null },
        doc! { "revoked_at": clock::now_iso_millis()? },
    )?;
    if revoked {
        return record_key_event(tx, id, "revoked", actor, None);
    }
    if tx.find_one(API_KEYS, doc! { "_id": id })?.is_some() {
        Ok(())
    } else {
        Err(Error::ApiKeyNotFound)
    }
}

fn rotate_key(tx: &mut Tx<'_>, id: i64, old: OldKey) -> Result<CreatedApiKey> {
    let info = key_info(tx, id)?;
    if info.revoked_at.is_some() {
        return Err(Error::ApiKeyRevoked);
    }
    let scope = ApiKeyScope::parse(&info.scope)?;
    let created = insert_key(
        tx,
        &NewApiKey {
            scope,
            recipient_fingerprint: info.recipient_fingerprint.clone(),
            label: info.label.clone(),
            ttl_seconds: None,
        },
        info.expires_at.clone(),
    )?;
    match old {
        OldKey::RevokeNow => revoke_key(tx, id, HOST_ACTOR)?,
        OldKey::ExpireAfter(seconds) => {
            if seconds <= 0 {
                return Err(Error::InvalidApiKeyRequest);
            }
            let until = clock::seconds_after(seconds)?;
            let expires_at = match &info.expires_at {
                Some(existing) if existing.as_str() <= until.as_str() => existing.clone(),
                _ => until,
            };
            tx.update_one(
                API_KEYS,
                doc! { "_id": id },
                doc! { "expires_at": expires_at },
            )?;
        }
    }
    record_key_event(tx, created.info.id, "rotated", HOST_ACTOR, Some(id))?;
    Ok(created)
}

fn has_live_pull_key(tx: &mut Tx<'_>, fingerprint: &str) -> Result<bool> {
    let fingerprint = api_key::normalize_fingerprint(fingerprint)?;
    let mut filter = live_filter(&clock::now_seconds()?);
    filter.insert("scope", ApiKeyScope::InboxPull.as_str());
    filter.insert("recipient_fingerprint", fingerprint);
    Ok(tx.find_one(API_KEYS, filter)?.is_some())
}

fn event_from(doc: &Document) -> Result<ApiKeyEvent> {
    Ok(ApiKeyEvent {
        id: get_i64(doc, "_id")?,
        key_id: get_i64(doc, "api_key_id")?,
        event: get_str(doc, "event")?,
        actor: get_str(doc, "actor")?,
        related_key_id: get_opt_i64(doc, "related_key_id")?,
        occurred_at: get_str(doc, "occurred_at")?,
        entry_hash: get_opt_str(doc, "entry_hash")?.unwrap_or_default(),
    })
}

// --- Audit chain -------------------------------------------------------

/// Append one row to `table`'s chain: hashed onto the head this
/// transaction read, inserted with the next id, and the head advanced by
/// compare-and-set. If another replica advanced the head first, the insert
/// collides on `_id` or the compare-and-set matches nothing, and the whole
/// unit of work is retried from the start.
fn append_audit(
    tx: &mut Tx<'_>,
    table: AuditTable,
    fields: Vec<Option<String>>,
    mut document: Document,
) -> Result<()> {
    let head = tx.find_one(AUDIT_HEADS, doc! { "_id": table.name() })?;
    let (count, prev) = match &head {
        None => (0i64, audit::GENESIS),
        Some(head) => (
            get_i64(head, "row_count")?,
            audit::decode_hash(&get_str(head, "head_hash")?).ok_or(Error::IntegrityCheckFailed)?,
        ),
    };
    let id = count + 1;
    let hash = audit::entry_hash(table, &prev, &fields)?;
    let head_hash = hex::encode(hash);
    document.insert("_id", id);
    document.insert("prev_hash", hex::encode(prev));
    document.insert("entry_hash", &head_hash);
    tx.insert_one(table.name(), document)?;
    if head.is_none() {
        tx.insert_one(
            AUDIT_HEADS,
            doc! { "_id": table.name(), "row_count": id, "head_hash": head_hash },
        )?;
    } else if !tx.update_one(
        AUDIT_HEADS,
        doc! { "_id": table.name(), "row_count": count },
        doc! { "row_count": id, "head_hash": head_hash },
    )? {
        return Err(Error::StoreConflict);
    }
    Ok(())
}

/// A table's chain head as `audit_heads` records it; `None` for an empty
/// table.
fn audit_head(tx: &mut Tx<'_>, table: AuditTable) -> Result<Option<(u64, [u8; 32])>> {
    match tx.find_one(AUDIT_HEADS, doc! { "_id": table.name() })? {
        None => Ok(None),
        Some(head) => {
            let count = u64::try_from(get_i64(&head, "row_count")?)
                .map_err(|_| Error::IntegrityCheckFailed)?;
            let hash = audit::decode_hash(&get_str(&head, "head_hash")?)
                .ok_or(Error::IntegrityCheckFailed)?;
            Ok(Some((count, hash)))
        }
    }
}

/// Every row of `table` in chain order, in the shape `relay::audit` hashes.
fn audit_rows(tx: &mut Tx<'_>, table: AuditTable) -> Result<Vec<audit::Row>> {
    let docs = tx.find_all(table.name(), doc! {}, doc! { "_id": 1 }, None)?;
    docs.iter()
        .map(|doc| {
            let fields = match table {
                AuditTable::ApiKeyEvents => vec![
                    get_opt_i64(doc, "api_key_id")?.map(|n| n.to_string()),
                    get_opt_str(doc, "event")?,
                    get_opt_str(doc, "actor")?,
                    get_opt_i64(doc, "related_key_id")?.map(|n| n.to_string()),
                    get_opt_str(doc, "occurred_at")?,
                ],
                AuditTable::ProviderAuthEvents => vec![
                    get_opt_str(doc, "operation")?,
                    get_opt_str(doc, "provider_id")?,
                    get_opt_str(doc, "network_id")?,
                    get_opt_str(doc, "hardware_fingerprints")?,
                    match doc.get("success") {
                        Some(Bson::Boolean(true)) => Some("1".to_string()),
                        Some(Bson::Boolean(false)) => Some("0".to_string()),
                        _ => None,
                    },
                    get_opt_str(doc, "attempted_at")?,
                ],
            };
            Ok(audit::Row {
                id: get_i64(doc, "_id")?,
                fields,
                prev_hash: get_opt_str(doc, "prev_hash")?,
                entry_hash: get_opt_str(doc, "entry_hash")?,
            })
        })
        .collect()
}

// --- Mailboxes ---------------------------------------------------------

/// File a letter under `fingerprint` in `collection`, unless the same
/// letter is already there. Runs inside the caller's transaction.
fn file_letter(
    tx: &mut Tx<'_>,
    collection: &str,
    payload_field: &str,
    fingerprint: &str,
    content_hash: &str,
    bytes: &[u8],
    expires_at: Option<&str>,
) -> Result<StoredLetter> {
    let existing = tx.find_one(
        collection,
        doc! { "recipient_fingerprint": fingerprint, "content_hash": content_hash },
    )?;
    if let Some(existing) = existing {
        return Ok(StoredLetter {
            id: get_i64(&existing, "_id")?,
            recipient_fingerprint: fingerprint.to_string(),
            duplicate: true,
        });
    }
    let id = tx.next_id(collection)?;
    tx.insert_one(
        collection,
        doc! {
            "_id": id,
            "recipient_fingerprint": fingerprint,
            payload_field: binary(bytes),
            "content_hash": content_hash,
            "created_at": clock::now_iso_millis()?,
            "expires_at": opt_str(expires_at),
            "purge_at": expires_at.map_or(Bson::Null, purge_at),
        },
    )?;
    Ok(StoredLetter {
        id,
        recipient_fingerprint: fingerprint.to_string(),
        duplicate: false,
    })
}

/// One stored letter of either mailbox, as a page lists it.
struct Letter {
    id: i64,
    recipient_fingerprint: String,
    bytes: Vec<u8>,
}

/// Unexpired letters for `fingerprint` after `after`, one page plus one to
/// know whether there is a next page. Expired letters are purged first, as
/// the SQLite store does.
fn page_letters(
    tx: &mut Tx<'_>,
    collection: &str,
    payload_field: &str,
    fingerprint: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<(Vec<Letter>, Option<i64>)> {
    let page = mailbox::page_size(limit)?;
    purge_letters(tx, collection)?;
    let filter = doc! {
        "recipient_fingerprint": fingerprint,
        "_id": { "$gt": after.unwrap_or(0) },
        "$or": [
            { "expires_at": Bson::Null },
            { "expires_at": { "$gt": clock::now_seconds()? } },
        ],
    };
    // Stream the cursor a few documents a batch and stop at the page's byte
    // budget, so the relay holds the budget plus one letter, not every
    // candidate document (`Tx::find_all` would collect them all first).
    let coll = tx.coll(collection);
    let mut cursor = coll
        .find(filter)
        .sort(doc! { "_id": 1 })
        .limit(page.saturating_add(1))
        .batch_size(PAGE_BATCH)
        .session(&mut *tx.session)
        .run()
        .map_err(store_err)?;
    let rows = cursor.iter(&mut *tx.session).map(|doc| {
        let doc = doc.map_err(store_err)?;
        Ok(Letter {
            id: get_i64(&doc, "_id")?,
            recipient_fingerprint: get_str(&doc, "recipient_fingerprint")?,
            bytes: get_bytes(&doc, payload_field)?,
        })
    });
    mailbox::bound_page(rows, page, |letter| letter.id, |letter| letter.bytes.len())
}

fn purge_letters(tx: &mut Tx<'_>, collection: &str) -> Result<u64> {
    tx.delete_many(collection, doc! { "purge_at": { "$lte": DateTime::now() } })
}

// --- Public trees ------------------------------------------------------

fn get_tree(tx: &mut Tx<'_>, label: &str) -> Result<PublicTree> {
    let doc = tx
        .find_one(PUBLIC_TREES, doc! { "_id": label })?
        .ok_or(Error::TreeNotFound)?;
    org_tree::parse_document(&get_str(&doc, "document")?)
}

fn persist_tree(tx: &mut Tx<'_>, snapshot: &PublicTree) -> Result<PublicTree> {
    let existing = tx.find_one(PUBLIC_TREES, doc! { "_id": &snapshot.label })?;
    let generation = match existing {
        Some(doc) => get_i64(&doc, "generation")?.saturating_add(1),
        None => 1,
    };
    let mut stored = snapshot.clone();
    stored.generation = u32::try_from(generation).unwrap_or(u32::MAX);
    let document = serde_json::to_string(&stored).map_err(|_| Error::InvalidTreeSpec)?;
    tx.upsert_one(
        PUBLIC_TREES,
        doc! { "_id": &stored.label },
        doc! {
            "generation": generation,
            "document": document,
            "updated_at": clock::now_iso_millis()?,
        },
    )?;
    Ok(stored)
}

fn merge_tree(tx: &mut Tx<'_>, snapshot: &PublicTree) -> Result<PublicTree> {
    org_tree::validate_public_tree(snapshot)?;
    let merged = match get_tree(tx, &snapshot.label) {
        Ok(existing) => org_tree::merge_into_existing(&existing, snapshot)?,
        Err(Error::TreeNotFound) => snapshot.clone(),
        Err(err) => return Err(err),
    };
    persist_tree(tx, &merged)
}

// --- Sealed key delivery -----------------------------------------------

impl DeliveryOps for Tx<'_> {
    fn key_info(&mut self, id: i64) -> Result<ApiKeyInfo> {
        key_info(self, id)
    }

    fn has_live_pull_key(&mut self, fingerprint: &str) -> Result<bool> {
        has_live_pull_key(self, fingerprint)
    }

    fn recipient_for(&mut self, id: i64) -> Result<Option<Recipient>> {
        let Some(doc) = self.find_one(API_KEY_DELIVERIES, doc! { "_id": id })? else {
            return Ok(None);
        };
        let device_id = match doc.get("device_id") {
            None | Some(Bson::Null) => None,
            Some(Bson::Binary(bytes)) => Some(
                bytes
                    .bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidDevice)?,
            ),
            Some(_) => return Err(Error::InvalidDevice),
        };
        Ok(Some(Recipient {
            public_key: get_bytes(&doc, "recipient_public_key")?
                .try_into()
                .map_err(|_| Error::InvalidPublicKey)?,
            relay_url: get_str(&doc, "relay_url")?,
            device_id,
            licence: get_opt_str(&doc, "licence")?,
        }))
    }

    fn create_key(&mut self, new: &NewApiKey) -> Result<CreatedApiKey> {
        create_key(self, new)
    }

    fn rotate_key(&mut self, id: i64, old: OldKey) -> Result<CreatedApiKey> {
        rotate_key(self, id, old)
    }

    fn store_letter(&mut self, letter: &[u8], until: Option<&str>) -> Result<(i64, String, bool)> {
        let (fingerprint, content_hash) = mailbox::routing_of(letter)?;
        let stored = file_letter(
            self,
            MAILBOX,
            "envelope",
            &fingerprint,
            &content_hash,
            letter,
            until,
        )?;
        Ok((stored.id, stored.recipient_fingerprint, stored.duplicate))
    }

    fn record_delivery(&mut self, key_id: i64, recipient: &Recipient, via: &Via) -> Result<()> {
        let (kind, letter_id, sha256) = match via {
            Via::Bundle { sha256 } => ("bundle", None, Some(sha256.as_str())),
            Via::Letter { id, .. } => ("letter", Some(*id), None),
        };
        self.insert_one(
            API_KEY_DELIVERIES,
            doc! {
                "_id": key_id,
                "recipient_public_key": binary(&recipient.public_key),
                "relay_url": normalize_url(&recipient.relay_url),
                "device_id": recipient.device_id.as_ref().map_or(Bson::Null, |id| Bson::Binary(binary(id))),
                "licence": opt_str(recipient.licence.as_deref()),
                "via": kind,
                "letter_id": letter_id.map_or(Bson::Null, Bson::Int64),
                "bundle_sha256": opt_str(sha256),
                "created_at": clock::now_iso_millis()?,
            },
        )
    }

    fn now_seconds(&mut self) -> Result<String> {
        clock::now_seconds()
    }
}

// --- The store ---------------------------------------------------------

impl RelayStore for MongoRelayStore {
    fn backend(&self) -> &'static str {
        "mongodb"
    }

    fn ping(&self) -> Result<()> {
        self.db
            .run_command(doc! { "ping": 1 })
            .run()
            .map(|_| ())
            .map_err(store_err)
    }

    fn mint_key(&self, new: &NewApiKey) -> Result<CreatedApiKey> {
        self.transaction(|tx| create_key(tx, new))
    }

    fn list_keys(&self) -> Result<Vec<ApiKeyInfo>> {
        self.with_session(|tx| {
            tx.find_all(API_KEYS, doc! {}, doc! { "_id": 1 }, None)?
                .iter()
                .map(info_from)
                .collect()
        })
    }

    fn key_info(&self, id: i64) -> Result<ApiKeyInfo> {
        self.with_session(|tx| key_info(tx, id))
    }

    fn revoke_key_by(&self, id: i64, actor: &str) -> Result<()> {
        self.transaction(|tx| revoke_key(tx, id, actor))
    }

    fn rotate_key_with(&self, id: i64, old: OldKey) -> Result<CreatedApiKey> {
        self.transaction(|tx| rotate_key(tx, id, old))
    }

    fn has_live_pull_key(&self, fingerprint: &str) -> Result<bool> {
        self.with_session(|tx| has_live_pull_key(tx, fingerprint))
    }

    fn authenticate(&self, token: &str, required: ApiKeyScope) -> Result<AuthedKey> {
        let token_hash = api_key::hash_bearer(token)?;
        let now = clock::now_seconds()?;
        let mut live = live_filter(&now);
        live.insert("key_hash", &token_hash);
        live.insert("scope", required.as_str());
        let claimed = self
            .db
            .collection::<Document>(API_KEYS)
            .find_one_and_update(
                live,
                doc! { "$set": { "last_used_at": clock::now_iso_millis()? } },
            )
            .return_document(ReturnDocument::After)
            .run()
            .map_err(store_err)?;
        if let Some(key) = claimed {
            return Ok(AuthedKey {
                id: get_i64(&key, "_id")?,
                scope: required,
                recipient_fingerprint: get_opt_str(&key, "recipient_fingerprint")?,
            });
        }
        let Some(key) =
            self.with_session(|tx| tx.find_one(API_KEYS, doc! { "key_hash": &token_hash }))?
        else {
            return Err(Error::InvalidApiKey);
        };
        if get_opt_str(&key, "revoked_at")?.is_some() {
            Err(Error::ApiKeyRevoked)
        } else if get_opt_str(&key, "expires_at")?.is_some_and(|expires| expires <= now) {
            Err(Error::ApiKeyExpired)
        } else if get_str(&key, "scope")? != required.as_str() {
            Err(Error::ApiKeyScopeDenied)
        } else {
            Err(Error::InvalidApiKey)
        }
    }

    fn authenticate_any(&self, token: &str) -> Result<AuthedKey> {
        let token_hash = api_key::hash_bearer(token)?;
        let scope = self
            .with_session(|tx| tx.find_one(API_KEYS, doc! { "key_hash": &token_hash }))?
            .ok_or(Error::InvalidApiKey)
            .and_then(|key| get_str(&key, "scope"))?;
        self.authenticate(token, ApiKeyScope::parse(&scope)?)
    }

    fn check_token(&self, token: &str) -> Result<KeyCheck> {
        match api_key::hash_bearer(token) {
            Ok(hash) => self.check_hash(&hash),
            Err(_) => Ok(KeyCheck::invalid()),
        }
    }

    fn check_hash(&self, key_hash: &str) -> Result<KeyCheck> {
        if key_hash.len() != 64 || !key_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(KeyCheck::invalid());
        }
        let key_hash = key_hash.to_ascii_lowercase();
        let Some(key) =
            self.with_session(|tx| tx.find_one(API_KEYS, doc! { "key_hash": key_hash }))?
        else {
            return Ok(KeyCheck::invalid());
        };
        let now = clock::now_seconds()?;
        let revoked = get_opt_str(&key, "revoked_at")?.is_some();
        let expired = get_opt_str(&key, "expires_at")?.is_some_and(|expires| expires <= now);
        if revoked || expired {
            return Ok(KeyCheck::invalid());
        }
        Ok(KeyCheck {
            valid: true,
            id: Some(get_i64(&key, "_id")?),
            scope: Some(get_str(&key, "scope")?),
            label: get_opt_str(&key, "label")?,
            recipient_fingerprint: get_opt_str(&key, "recipient_fingerprint")?,
        })
    }

    fn key_events(&self, key: Option<i64>) -> Result<Vec<ApiKeyEvent>> {
        let filter = match key {
            None => doc! {},
            Some(id) => doc! {
                "$or": [
                    { "api_key_id": id },
                    { "related_key_id": id },
                    { "actor": api_key::admin_actor(id) },
                ],
            },
        };
        self.with_session(|tx| {
            tx.find_all(API_KEY_EVENTS, filter.clone(), doc! { "_id": 1 }, None)?
                .iter()
                .map(event_from)
                .collect()
        })
    }

    fn authorize_licensee_or_bootstrap(
        &self,
        supplied: Option<&str>,
    ) -> Result<Option<CreatedLicensee>> {
        if let Some(key) = supplied {
            if key.is_empty() {
                return Err(Error::InvalidLicenseeKey);
            }
            self.authenticate_licensee(key)?;
            return Ok(None);
        }
        if self
            .with_session(|tx| tx.find_one(OPERATOR_ISSUER, doc! { "_id": 1 }))?
            .is_some()
        {
            return Ok(None);
        }
        let (token, token_hash) = api_key::generate_prefixed_bearer(api_key::LICENSEE_PREFIX);
        let inserted = self
            .db
            .collection::<Document>(OPERATOR_ISSUER)
            .insert_one(doc! {
                "_id": 1,
                "key_hash": token_hash,
                "created_at": clock::now_iso_millis()?,
            })
            .run();
        match inserted {
            Ok(_) => Ok(Some(CreatedLicensee { token })),
            // Another host command minted it first: this one minted nothing.
            Err(err) if is_duplicate_key(&err) => Ok(None),
            Err(err) => Err(store_err(err)),
        }
    }

    fn authenticate_licensee(&self, token: &str) -> Result<()> {
        let token_hash = api_key::hash_prefixed(token, api_key::LICENSEE_PREFIX)
            .map_err(|_| Error::InvalidLicenseeKey)?;
        let found = self.with_session(|tx| {
            tx.find_one(OPERATOR_ISSUER, doc! { "_id": 1, "key_hash": token_hash })
        })?;
        match found {
            Some(_) => Ok(()),
            None => Err(Error::InvalidLicenseeKey),
        }
    }

    fn record_provider_auth_event(&self, event: &ProviderAuthEvent<'_>) -> Result<()> {
        self.transaction(|tx| {
            let attempted_at = clock::now_iso_millis()?;
            let fields = vec![
                Some(event.operation.to_string()),
                event.provider_id.map(str::to_string),
                event.network_id.map(str::to_string),
                event.hardware_fingerprints.map(str::to_string),
                Some(if event.success { "1" } else { "0" }.to_string()),
                Some(attempted_at.clone()),
            ];
            let document = doc! {
                "operation": event.operation,
                "provider_id": opt_str(event.provider_id),
                "network_id": opt_str(event.network_id),
                "hardware_fingerprints": opt_str(event.hardware_fingerprints),
                "success": event.success,
                "attempted_at": attempted_at,
            };
            append_audit(tx, AuditTable::ProviderAuthEvents, fields, document)
        })
    }

    fn inbox_push(
        &self,
        trees: &[PublicTree],
        envelope: &[u8],
        expires_at: Option<&str>,
    ) -> Result<StoredLetter> {
        let (fingerprint, content_hash) = mailbox::routing_of(envelope)?;
        self.transaction(|tx| {
            if let Some(expires_at) = expires_at {
                if expires_at <= clock::now_seconds()?.as_str() {
                    return Err(Error::ExpiresAtInPast);
                }
            }
            for tree in trees {
                merge_tree(tx, tree)?;
            }
            file_letter(
                tx,
                MAILBOX,
                "envelope",
                &fingerprint,
                &content_hash,
                envelope,
                expires_at,
            )
        })
    }

    fn list_envelopes_after(
        &self,
        fingerprint: &str,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<MailboxPage> {
        self.with_session(|tx| {
            let (letters, next_after) =
                page_letters(tx, MAILBOX, "envelope", fingerprint, after, limit)?;
            Ok(MailboxPage {
                envelopes: letters
                    .into_iter()
                    .map(|letter| StoredEnvelope {
                        id: letter.id,
                        recipient_fingerprint: letter.recipient_fingerprint,
                        bytes: letter.bytes,
                    })
                    .collect(),
                next_after,
            })
        })
    }

    fn purge_expired_envelopes(&self) -> Result<u64> {
        self.with_session(|tx| purge_letters(tx, MAILBOX))
    }

    fn put_public_tree(&self, tree: &PublicTree) -> Result<PublicTree> {
        org_tree::validate_public_tree(tree)?;
        self.transaction(|tx| persist_tree(tx, tree))
    }

    fn merge_public_tree(&self, tree: &PublicTree) -> Result<PublicTree> {
        org_tree::validate_public_tree(tree)?;
        self.transaction(|tx| merge_tree(tx, tree))
    }

    fn get_public_tree(&self, label: &str) -> Result<PublicTree> {
        self.with_session(|tx| get_tree(tx, label))
    }

    fn list_public_trees(&self) -> Result<Vec<PublicTree>> {
        self.with_session(|tx| {
            tx.find_all(PUBLIC_TREES, doc! {}, doc! { "_id": 1 }, None)?
                .iter()
                .map(|doc| org_tree::parse_document(&get_str(doc, "document")?))
                .collect()
        })
    }

    fn store_device_package(&self, package: &[u8]) -> Result<StoredLetter> {
        let (fingerprint, content_hash) = device_mail::check_package(package)?;
        let expires_at = clock::seconds_after(DEVICE_PACKAGE_TTL_DAYS * 86_400)?;
        self.with_session(|tx| purge_letters(tx, DEVICE_MAILBOX))?;
        self.transaction(|tx| {
            file_letter(
                tx,
                DEVICE_MAILBOX,
                "package",
                &fingerprint,
                &content_hash,
                package,
                Some(&expires_at),
            )
        })
    }

    fn list_device_packages_after(
        &self,
        fingerprint: &str,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<DeviceMailPage> {
        self.with_session(|tx| {
            let (letters, next_after) =
                page_letters(tx, DEVICE_MAILBOX, "package", fingerprint, after, limit)?;
            Ok(DeviceMailPage {
                packages: letters
                    .into_iter()
                    .map(|letter| StoredDevicePackage {
                        id: letter.id,
                        recipient_fingerprint: letter.recipient_fingerprint,
                        bytes: letter.bytes,
                    })
                    .collect(),
                next_after,
            })
        })
    }

    fn purge_expired_device_packages(&self) -> Result<u64> {
        self.with_session(|tx| purge_letters(tx, DEVICE_MAILBOX))
    }

    fn put_device_descriptor(&self, descriptor: &DeviceDescriptor) -> Result<DeviceDescriptor> {
        let mut stored = descriptor.clone();
        device_directory::normalize_fields(&mut stored)?;
        device_directory::verify_descriptor(&stored)?;
        let document = serde_json::to_string(&stored).map_err(|_| Error::InvalidDevice)?;
        self.transaction(|tx| {
            if let Some(existing) =
                tx.find_one(DEVICE_DIRECTORY, doc! { "_id": &stored.device_id })?
            {
                if get_str(&existing, "verify_key")? != stored.verify_key {
                    return Err(Error::InvalidDevice);
                }
            }
            tx.upsert_one(
                DEVICE_DIRECTORY,
                doc! { "_id": &stored.device_id },
                doc! {
                    "verify_key": &stored.verify_key,
                    "document": &document,
                    "updated_at": clock::now_iso_millis()?,
                },
            )?;
            Ok(stored.clone())
        })
    }

    fn get_device_descriptor(&self, device_id: &str) -> Result<Option<DeviceDescriptor>> {
        let device_id = device_directory::normalize_device_id(device_id)?;
        let Some(doc) =
            self.with_session(|tx| tx.find_one(DEVICE_DIRECTORY, doc! { "_id": device_id }))?
        else {
            return Ok(None);
        };
        let descriptor: DeviceDescriptor =
            serde_json::from_str(&get_str(&doc, "document")?).map_err(|_| Error::InvalidDevice)?;
        device_directory::verify_descriptor(&descriptor)?;
        Ok(Some(descriptor))
    }

    fn anchor_audit(&self, identity: &ProviderIdentity, signed_at: &str) -> Result<usize> {
        let mut written = 0;
        for table in AuditTable::ALL {
            let Some((count, head_hash)) = self.with_session(|tx| audit_head(tx, table))? else {
                continue;
            };
            // Covered when an anchor already vouches for this head or a later
            // one. Looked up by row count, never by insertion order: a slow
            // replica can insert a stale anchor after a newer one, and that
            // stale anchor must not hide the newer coverage.
            let covered = self.with_session(|tx| {
                tx.find_one(
                    AUDIT_ANCHORS,
                    doc! { "table_name": table.name(), "row_count": { "$gte": count as i64 } },
                )
            })?;
            if covered.is_some() {
                continue;
            }
            let signature = audit::sign_anchor(identity, table, count, &head_hash, signed_at)?;
            let id = self.with_session(|tx| tx.next_id(AUDIT_ANCHORS))?;
            let inserted = self
                .db
                .collection::<Document>(AUDIT_ANCHORS)
                .insert_one(doc! {
                    "_id": id,
                    "table_name": table.name(),
                    "row_count": count as i64,
                    "head_hash": hex::encode(head_hash),
                    "signed_at": signed_at,
                    "certificate": binary(&identity.certificate),
                    "signature": binary(&signature),
                })
                .run();
            match inserted {
                Ok(_) => written += 1,
                // Another replica anchored this same head first.
                Err(err) if is_duplicate_key(&err) => {}
                Err(err) => return Err(store_err(err)),
            }
        }
        Ok(written)
    }

    fn audit_checkpoint(&self, identity: &ProviderIdentity, taken_at: &str) -> Result<Checkpoint> {
        let mut heads = Vec::new();
        for table in AuditTable::ALL {
            let (count, hash) = self
                .with_session(|tx| audit_head(tx, table))?
                .unwrap_or((0, audit::GENESIS));
            heads.push((table.name(), count, hash));
        }
        audit::sign_checkpoint(&heads, identity, taken_at)
    }

    fn verify_audit(
        &self,
        root_public_key: &[u8; 32],
        revoked: &HashSet<String>,
        checkpoint: Option<&Checkpoint>,
    ) -> Result<Vec<TableReport>> {
        if checkpoint.is_some_and(|c| !c.is_signed_by_trusted_relay(root_public_key, revoked)) {
            return Err(Error::IntegrityCheckFailed);
        }
        let mut reports = Vec::new();
        for table in AuditTable::ALL {
            // One snapshot per table: an append and its anchor that commit
            // while this runs are either both seen or both missed, never an
            // anchor for a row the walk did not read.
            let (rows, anchors) = self.transaction(|tx| {
                let rows = audit_rows(tx, table)?;
                let anchors = tx
                    .find_all(
                        AUDIT_ANCHORS,
                        doc! { "table_name": table.name() },
                        doc! { "_id": 1 },
                        None,
                    )?
                    .iter()
                    .map(|doc| {
                        Ok(AnchorRow {
                            row_count: get_i64(doc, "row_count")?,
                            head_hash: get_str(doc, "head_hash")?,
                            signed_at: get_str(doc, "signed_at")?,
                            certificate: get_bytes(doc, "certificate")?,
                            signature: get_bytes(doc, "signature")?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok((rows, anchors))
            })?;
            reports.push(audit::verify_table(
                table,
                &rows,
                &anchors,
                root_public_key,
                revoked,
                checkpoint,
            )?);
        }
        Ok(reports)
    }

    fn delivery_recipient_for(&self, id: i64) -> Result<Option<Recipient>> {
        self.with_session(|tx| tx.recipient_for(id))
    }

    fn mint_key_as_bundle(
        &self,
        identity: &ProviderIdentity,
        new: &NewApiKey,
        recipient: &Recipient,
        write: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Delivered> {
        self.transaction(|tx| {
            // Handing the bundle out is the point of no return for a retry:
            // a retried unit of work would mint a different key than the
            // one in the file.
            let wrote = std::cell::Cell::new(false);
            let delivered =
                key_delivery::create_as_bundle_with(tx, identity, new, recipient, &mut |bytes| {
                    wrote.set(true);
                    write(bytes)
                });
            if wrote.get() {
                tx.no_retry();
            }
            delivered
        })
    }

    fn rotate_key_as_letter(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        recipient: Option<Recipient>,
        grace_seconds: i64,
    ) -> Result<Delivered> {
        self.transaction(|tx| {
            key_delivery::rotate_as_letter_with(tx, identity, id, recipient.clone(), grace_seconds)
        })
    }

    fn rotate_key_as_bundle(
        &self,
        identity: &ProviderIdentity,
        id: i64,
        recipient: Option<Recipient>,
        write: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Delivered> {
        self.transaction(|tx| {
            let wrote = std::cell::Cell::new(false);
            let delivered = key_delivery::rotate_as_bundle_with(
                tx,
                identity,
                id,
                recipient.clone(),
                &mut |bytes| {
                    wrote.set(true);
                    write(bytes)
                },
            );
            if wrote.get() {
                tx.no_retry();
            }
            delivered
        })
    }
}

#[cfg(test)]
#[path = "mongo/tests.rs"]
mod tests;
