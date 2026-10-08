//! The relay core as a WebAssembly module for a Cloudflare Durable Object.
//!
//! The public Worker (`workers/`) authenticates nothing itself: it checks the
//! request's size, method and host, then hands it to the one SQLite-backed
//! Durable Object, which owns a [`RelayCore`]. A `RelayCore` is
//! [`SqlRelayStore`] over [`do_sql::DoSql`] and
//! [`service::dispatch`](crate::relay::service::dispatch): the same routes, key
//! scopes, audit chain and idempotent letter filing every other backend runs,
//! with nothing re-rolled here. This file only maps a fetch request to a
//! [`RelayHttpRequest`] and the answer back, and runs the Durable Object's
//! housekeeping (purge, audit anchor) when its alarm fires.
//!
//! Time is never read here: the wasm target has no `SystemTime`, so the Worker
//! passes the current UTC time in as text.
//!
//! The relay's private key and `provider.kqcert` arrive as bytes from Worker
//! secrets. The provider-root key and the `kql_` operator lock never do: no
//! route of [`RelayCore::handle`] mints or rotates a key. The provider's own
//! console reaches [`RelayCore::operate`] only through the admin Worker's
//! binding to the Durable Object, and the operator lock arrives with each
//! request that changes something and is never kept.

mod do_sql;

use crate::relay::activity::Cost;
use crate::relay::operator;
use crate::relay::service::{self, ProviderIdentity};
use crate::relay::sql::Sql;
use crate::relay::store::{RelayStore, SqlRelayStore};
use crate::relay::RelayHttpRequest;
use do_sql::{DoSql, SqlAdapter};
use url::Url;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The largest request body the core accepts. The Worker enforces the same
/// cap before it reads the body; this is the second line.
pub const MAX_REQUEST_BODY: usize = 2 * 1024 * 1024;

/// The largest body of `POST /inbox` as raw bytes: a letter of up to
/// [`service::MAX_LARGE_LETTER_BYTES`] plus slack. Only that one route takes a
/// body this large, and only as raw bytes: a JSON body (trees, expiry) stays at
/// [`MAX_REQUEST_BODY`], so a big letter cannot ride with a big JSON document
/// through the core's memory.
pub const MAX_LARGE_REQUEST_BODY: usize = service::MAX_LARGE_LETTER_BYTES + 64 * 1024;

/// Why a request was turned away before routing, as an HTTP status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused(pub u16);

/// A fetch request as the relay's router takes it: the method and content
/// type become the router's literals (it matches on `&'static str`), and a
/// method it has no route for, an unparseable URL or an oversized body is
/// refused here.
pub(crate) fn map_request(
    method: &str,
    url: &str,
    bearer: Option<String>,
    content_type: Option<&str>,
    body: Vec<u8>,
    holds_letters: bool,
) -> Result<RelayHttpRequest, Refused> {
    let method = match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        _ => return Err(Refused(405)),
    };
    let url = Url::parse(url).map_err(|_| Refused(400))?;
    let raw = !content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    });
    let limit =
        if holds_letters && method == "POST" && raw && url.path().trim_end_matches('/') == "/inbox"
        {
            MAX_LARGE_REQUEST_BODY
        } else {
            MAX_REQUEST_BODY
        };
    if body.len() > limit {
        return Err(Refused(413));
    }
    let content_type = content_type.map(|value| {
        let essence = value.split(';').next().unwrap_or("").trim();
        if essence.eq_ignore_ascii_case("application/json") {
            "application/json"
        } else {
            "application/octet-stream"
        }
    });
    Ok(RelayHttpRequest {
        method,
        url,
        bearer: bearer.filter(|token| !token.is_empty()).map(Zeroizing::new),
        content_type,
        body,
    })
}

/// The relay's answer to one request.
#[wasm_bindgen]
pub struct RelayResponse {
    status: u16,
    body: Vec<u8>,
}

#[wasm_bindgen]
impl RelayResponse {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
}

/// The relay inside one Durable Object.
#[wasm_bindgen]
pub struct RelayCore {
    store: SqlRelayStore<DoSql>,
    identity: Option<ProviderIdentity>,
    /// The provider root the Worker pins (`PROVIDER_ROOT`), see
    /// [`operator::Context::pinned_root`].
    pinned_root: Option<[u8; 32]>,
    /// A backup being uploaded: built whole by [`RelayCore::backup_begin`], read
    /// out piece by piece, dropped by [`RelayCore::backup_end`].
    backup: std::cell::RefCell<Option<crate::relay::backup::Snapshot>>,
}

fn mail_table(name: &str) -> Result<crate::relay::MailTable, JsError> {
    match name {
        "inbox" => Ok(crate::relay::MailTable::Inbox),
        "device" => Ok(crate::relay::MailTable::Devices),
        _ => Err(JsError::new("unknown mailbox")),
    }
}

fn js_error(error: impl std::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

#[wasm_bindgen]
impl RelayCore {
    /// Opens the relay over `adapter` (see `workers/src/sql-adapter.js`),
    /// creating its tables if they are not there. `certificate` and
    /// `relay_private_key` are the Worker secrets; without both the relay
    /// answers every route but `POST /provider-identity` as usual and that one
    /// with its own refusal, so an official client will not trust it.
    /// `pinned_root` is the provider root public key the Worker's
    /// `PROVIDER_ROOT` variable names, which the console's identity check
    /// runs against; the relay itself verifies nothing against it.
    #[wasm_bindgen(constructor)]
    pub fn new(
        adapter: SqlAdapter,
        certificate: Option<Vec<u8>>,
        relay_private_key: Option<Vec<u8>>,
        pinned_root: Option<Vec<u8>>,
    ) -> Result<RelayCore, JsError> {
        let pinned_root = match pinned_root {
            Some(root) if !root.is_empty() => Some(
                root.as_slice()
                    .try_into()
                    .map_err(|_| JsError::new("the pinned provider root is not 32 bytes"))?,
            ),
            _ => None,
        };
        let identity = match (certificate, relay_private_key) {
            (Some(certificate), Some(key)) if !certificate.is_empty() => {
                let key = Zeroizing::new(key);
                let key: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| JsError::new("the relay private key is not 32 bytes"))?;
                Some(ProviderIdentity {
                    certificate,
                    relay_private_key: Zeroizing::new(key),
                })
            }
            _ => None,
        };
        let sql = DoSql::new(adapter);
        sql.execute_batch(crate::relay::SCHEMA).map_err(js_error)?;
        crate::relay::mailbox::ensure_blob_columns(&sql).map_err(js_error)?;
        sql.execute_batch("PRAGMA foreign_keys = ON")
            .map_err(js_error)?;
        Ok(Self {
            store: SqlRelayStore::new(sql, "durable-object"),
            identity,
            pinned_root,
            backup: std::cell::RefCell::new(None),
        })
    }

    /// Answers one request. `now` is the current UTC time as
    /// `YYYY-MM-DD HH:MM:SS.mmm`, used only to sign the audit anchor after a
    /// revocation.
    pub fn handle(
        &self,
        method: &str,
        url: &str,
        bearer: Option<String>,
        content_type: Option<String>,
        body: Vec<u8>,
        now: &str,
    ) -> RelayResponse {
        let request = match map_request(
            method,
            url,
            bearer,
            content_type.as_deref(),
            body,
            self.store.holds_letters(),
        ) {
            Ok(request) => request,
            Err(Refused(status)) => {
                return RelayResponse {
                    status,
                    body: Vec::new(),
                }
            }
        };
        let response = service::dispatch(&self.store, self.identity.as_ref(), &request);
        if response.status == 204
            && request.method == "POST"
            && request.url.path().ends_with("/revoke")
        {
            // Vouch for the revocation at once, as the native host does.
            if let Some(identity) = &self.identity {
                let _ = self.store.anchor_audit(identity, now);
            }
        }
        RelayResponse {
            status: response.status,
            body: response.body,
        }
    }

    /// Answers one request of the provider's console (`relay::operator`). Only
    /// the admin Worker calls this, through its binding to the Durable Object;
    /// the public Worker never does. `operator` is the identity Cloudflare
    /// Access verified. `lock` is the operator lock when this request changes
    /// something; it is checked against its stored hash and dropped, never
    /// kept. `now` is the current UTC time as `YYYY-MM-DD HH:MM:SS.mmm`.
    pub fn operate(
        &self,
        request: Vec<u8>,
        operator: &str,
        lock: Option<String>,
        now: &str,
    ) -> RelayResponse {
        let lock = lock.map(Zeroizing::new);
        let context = operator::Context {
            operator,
            lock: lock.as_deref().map(String::as_str),
            pinned_root: self.pinned_root.as_ref(),
        };
        let reply = operator::operate(&self.store, self.identity.as_ref(), &request, &context, now);
        if reply.changed {
            // Vouch for the change at once, as the native host does.
            if let Some(identity) = &self.identity {
                let _ = self.store.anchor_audit(identity, now);
            }
        }
        RelayResponse {
            status: reply.status,
            body: reply.body,
        }
    }

    /// Counts one request for the provider's console: what a known key did, how
    /// long it took (as the object measured it, coarse) and the bytes each way.
    /// The object calls this after it has the answer, with the bearer it read;
    /// a bearer that names no stored key records nothing, and a failure to
    /// count never changes the answer (the caller ignores it).
    pub fn record_access(
        &self,
        token: &str,
        url: &str,
        status: u16,
        millis: u32,
        bytes_in: f64,
        bytes_out: f64,
    ) -> Result<(), JsError> {
        let path = Url::parse(url).map_err(js_error)?.path().to_string();
        self.store
            .record_access(
                token,
                &path,
                status,
                Cost {
                    millis,
                    bytes_in: bytes_in as u64,
                    bytes_out: bytes_out as u64,
                },
            )
            .map_err(js_error)
    }

    /// From now on, hold letters of at least `bytes` out of their rows: the
    /// caller (the Durable Object, with an R2 bucket bound) stores each one's
    /// bytes in the bucket and then calls [`Self::blob_ready`], or
    /// [`Self::blob_abort`] if it cannot. Never called when no bucket is bound,
    /// so without one nothing is held out. `bytes` is at least 4096.
    pub fn hold_letters_from(&mut self, bytes: u32) {
        self.store.set_blob_threshold(bytes.max(4096) as usize);
    }

    /// The bytes of held letter `id` of `table` (`"inbox"` or `"device"`) are
    /// stored: make it ready. False when there was nothing to make ready.
    pub fn blob_ready(&self, table: &str, id: f64) -> Result<bool, JsError> {
        self.store
            .blob_ready(mail_table(table)?, id as i64)
            .map_err(js_error)
    }

    /// The bytes could not be stored: drop the not-ready row, so the sender's
    /// retry starts clean. A ready row is never dropped.
    pub fn blob_abort(&self, table: &str, id: f64) -> Result<bool, JsError> {
        self.store
            .blob_abort(mail_table(table)?, id as i64)
            .map_err(js_error)
    }

    /// Keys of objects to delete from the bucket, as a JSON array of strings:
    /// dropped, and named by no live row. At most `limit`.
    pub fn blob_tombstones(&self, limit: u32) -> Result<String, JsError> {
        let keys = self
            .store
            .blob_tombstones(i64::from(limit))
            .map_err(js_error)?;
        serde_json::to_string(&keys).map_err(js_error)
    }

    /// The objects named by `keys` (a JSON array of strings) are deleted:
    /// forget their tombstones. Returns how many were forgotten.
    pub fn blob_tombstones_done(&self, keys: &str) -> Result<u32, JsError> {
        let keys: Vec<String> = serde_json::from_str(keys).map_err(js_error)?;
        if keys.len() > 1000 {
            return Err(JsError::new("too many keys"));
        }
        let done = self.store.blob_tombstones_done(&keys).map_err(js_error)?;
        Ok(u32::try_from(done).unwrap_or(u32::MAX))
    }

    /// Builds a sealed, relay-signed snapshot of the whole database for the
    /// operator's backup key (`recipient`, 64 hex characters, an X25519 public
    /// key), in one synchronous turn so it is consistent, and holds it for the
    /// caller to read out and upload. Returns its plan as JSON: the backup id and
    /// the name and size of each chunk and of the manifest. Refuses a database
    /// whose plaintext would exceed `max_bytes`, and a relay without an identity
    /// to sign with. Replaces any snapshot not yet ended.
    pub fn backup_begin(
        &self,
        recipient: &str,
        now: &str,
        max_bytes: u32,
    ) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("the relay has no identity to sign a backup with"))?;
        let recipient: [u8; 32] = hex::decode(recipient.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| JsError::new("the backup recipient is not a 32-byte hex key"))?;
        *self.backup.borrow_mut() = None;
        let snapshot = self
            .store
            .backup_snapshot(identity, &recipient, now, max_bytes as usize)
            .map_err(js_error)?;
        let plan = serde_json::json!({
            "id": snapshot.backup_id,
            "tables": snapshot.tables,
            "rows": snapshot.rows,
            "objects": snapshot.objects.iter()
                .map(|(name, bytes)| serde_json::json!({ "name": name, "bytes": bytes.len() }))
                .collect::<Vec<_>>(),
            "manifest": { "name": snapshot.manifest_name, "bytes": snapshot.manifest.len() },
        });
        *self.backup.borrow_mut() = Some(snapshot);
        serde_json::to_string(&plan).map_err(js_error)
    }

    /// The sealed bytes of chunk `index` of the snapshot [`Self::backup_begin`] built.
    pub fn backup_object(&self, index: u32) -> Result<Vec<u8>, JsError> {
        let held = self.backup.borrow();
        let snapshot = held
            .as_ref()
            .ok_or_else(|| JsError::new("no backup is in progress"))?;
        snapshot
            .objects
            .get(index as usize)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| JsError::new("no such backup chunk"))
    }

    /// The sealed, signed manifest of the snapshot. Upload it last.
    pub fn backup_manifest(&self) -> Result<Vec<u8>, JsError> {
        self.backup
            .borrow()
            .as_ref()
            .map(|snapshot| snapshot.manifest.clone())
            .ok_or_else(|| JsError::new("no backup is in progress"))
    }

    /// Drops the snapshot, whatever happened to its upload.
    pub fn backup_end(&self) {
        *self.backup.borrow_mut() = None;
    }

    /// Whether the store answers (the readiness probe).
    pub fn ready(&self) -> bool {
        self.store.ping().is_ok()
    }

    /// The Durable Object's alarm: drop expired letters, then sign the audit
    /// chain heads. Returns how many rows were purged.
    pub fn scan(&self, now: &str) -> Result<u32, JsError> {
        let purged = self.store.purge_expired_envelopes().map_err(js_error)?
            + self
                .store
                .purge_expired_device_packages()
                .map_err(js_error)?;
        let purged = purged + self.store.purge_old_activity().map_err(js_error)?;
        // A held letter whose bytes were never confirmed (a crash between the
        // two steps) is dropped after an hour and its key tombstoned.
        let purged = purged + self.store.blob_drop_stale(60).map_err(js_error)?;
        if let Some(identity) = &self.identity {
            self.store.anchor_audit(identity, now).map_err(js_error)?;
        }
        Ok(u32::try_from(purged).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
