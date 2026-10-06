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
//! secrets. The provider-root key and the `kql_` operator lock never do; no
//! route here mints or rotates a key.

mod do_sql;

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
) -> Result<RelayHttpRequest, Refused> {
    let method = match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        _ => return Err(Refused(405)),
    };
    if body.len() > MAX_REQUEST_BODY {
        return Err(Refused(413));
    }
    let url = Url::parse(url).map_err(|_| Refused(400))?;
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
    #[wasm_bindgen(constructor)]
    pub fn new(
        adapter: SqlAdapter,
        certificate: Option<Vec<u8>>,
        relay_private_key: Option<Vec<u8>>,
    ) -> Result<RelayCore, JsError> {
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
        sql.execute_batch("PRAGMA foreign_keys = ON")
            .map_err(js_error)?;
        Ok(Self {
            store: SqlRelayStore::new(sql, "durable-object"),
            identity,
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
        let request = match map_request(method, url, bearer, content_type.as_deref(), body) {
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
        if let Some(identity) = &self.identity {
            self.store.anchor_audit(identity, now).map_err(js_error)?;
        }
        Ok(u32::try_from(purged).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
