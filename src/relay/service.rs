//! What each relay route does, independent of how the request arrived.
//!
//! The provider-only axum server (`server.rs`) adapts HTTP to these
//! functions, and [`dispatch`] routes an already-parsed request to them in
//! process. That second path is how the browser lab runs a relay without a
//! listener: the same authentication, scopes, fingerprint binding, and
//! opaque-envelope storage, reached through the CLI's relay client. Nothing
//! here serves sockets, mints API keys, or issues certificates; those stay
//! behind the `provider` feature. Handlers never unseal envelopes.

use super::api_key::{self, ApiKeyInfo, ApiKeyScope, AuthedKey};
use super::client::{
    DevicePackageList, DevicePackagePush, ErrorBody, InboxAccepted, InboxEnvelope, InboxList,
    InboxPush, KeyCheckRequest, KeyCheckResponse, ProviderIdentityRequest,
    ProviderIdentityResponse, RelayHttpRequest, RelayHttpResponse,
};
use super::device_directory::{self, DeviceDescriptor};
use super::device_mail;
use super::mailbox;
use super::org_tree;
use crate::error::{Error, Result};
use crate::key_tree::PublicTree;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Live provider identity presented on `POST /provider-identity`.
pub struct ProviderIdentity {
    pub certificate: Vec<u8>,
    pub relay_private_key: Zeroizing<[u8; 32]>,
}

/// An error as the relay reports it: an HTTP status and a message that is
/// safe to show the caller.
pub struct HttpError {
    pub status: u16,
    pub message: String,
}

impl HttpError {
    pub fn unauthorized() -> Self {
        Self {
            status: 401,
            message: "unauthorized".to_string(),
        }
    }

    pub fn internal() -> Self {
        Self {
            status: 500,
            message: "internal error".to_string(),
        }
    }
}

impl From<Error> for HttpError {
    fn from(err: Error) -> Self {
        match err {
            // Denials are logged for monitoring by reason only: never the
            // bearer, its hash or the request body.
            Error::InvalidApiKey | Error::ApiKeyExpired | Error::ApiKeyRevoked => {
                #[cfg(feature = "provider")]
                tracing::warn!(reason = %err, "relay authentication denied");
                Self::unauthorized()
            }
            Error::ApiKeyScopeDenied => {
                #[cfg(feature = "provider")]
                tracing::warn!(reason = %err, "relay scope denied");
                Self {
                    status: 403,
                    message: "forbidden".to_string(),
                }
            }
            Error::InvalidApiKeyRequest
            | Error::InvalidInboxPage
            | Error::InvalidBridgePackage
            | Error::InvalidPublicKey
            | Error::SignatureVerificationFailed
            | Error::InvalidTreeSpec
            | Error::DuplicateNodeLabel
            | Error::InvalidBridge
            | Error::InvalidProviderChallenge
            | Error::InvalidExpiresAt
            | Error::ExpiresAtInPast
            | Error::WrongKeyType
            | Error::InvalidDevice
            | Error::InvalidSlot => Self {
                status: 400,
                message: err.to_string(),
            },
            Error::ApiKeyNotFound
            | Error::TreeNotFound
            | Error::NodeNotFound
            | Error::DeviceNotFound => Self {
                status: 404,
                message: err.to_string(),
            },
            Error::ProviderIdentityMissing => Self {
                status: 503,
                message: err.to_string(),
            },
            Error::BundleFieldTooLarge => Self {
                status: 413,
                message: err.to_string(),
            },
            _other => {
                #[cfg(feature = "provider")]
                tracing::error!("relay internal error: {_other}");
                Self::internal()
            }
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ApiKeyView {
    pub id: i64,
    pub scope: String,
    pub recipient_fingerprint: Option<String>,
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

impl From<ApiKeyInfo> for ApiKeyView {
    fn from(info: ApiKeyInfo) -> Self {
        Self {
            id: info.id,
            scope: info.scope,
            recipient_fingerprint: info.recipient_fingerprint,
            label: info.label,
            created_at: info.created_at,
            expires_at: info.expires_at,
            revoked_at: info.revoked_at,
            last_used_at: info.last_used_at,
        }
    }
}

/// One API-key lifecycle event as `GET /audit/api-keys` returns it.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ApiKeyEventView {
    pub id: i64,
    pub api_key_id: i64,
    pub event: String,
    pub actor: String,
    pub related_key_id: Option<i64>,
    pub occurred_at: String,
    /// This row's link in the relay's signed audit chain.
    pub entry_hash: String,
}

impl From<api_key::ApiKeyEvent> for ApiKeyEventView {
    fn from(event: api_key::ApiKeyEvent) -> Self {
        Self {
            id: event.id,
            api_key_id: event.api_key_id,
            event: event.event,
            actor: event.actor,
            related_key_id: event.related_key_id,
            occurred_at: event.occurred_at,
            entry_hash: event.entry_hash,
        }
    }
}

/// `GET /audit/api-keys` (any live key): the lifecycle events that pertain
/// to the caller. An admin key sees every event; any other key only those
/// about itself, so no key holder learns about another's.
pub fn audit_events(conn: &Connection, token: &str) -> Result<Vec<ApiKeyEventView>> {
    let auth = api_key::authenticate_any(conn, token)?;
    Ok(api_key::events_visible_to(conn, &auth)?
        .into_iter()
        .map(ApiKeyEventView::from)
        .collect())
}

/// `POST /provider-identity`: the certificate plus a signature over the
/// caller's challenge.
pub fn provider_identity(
    identity: Option<&ProviderIdentity>,
    body: &ProviderIdentityRequest,
) -> Result<ProviderIdentityResponse> {
    let identity = identity.ok_or(Error::ProviderIdentityMissing)?;
    let challenge = STANDARD
        .decode(body.challenge.as_bytes())
        .map_err(|_| Error::InvalidProviderChallenge)?;
    let signature = crate::provider::sign_challenge(&identity.relay_private_key, &challenge)?;
    Ok(ProviderIdentityResponse {
        certificate: STANDARD.encode(&identity.certificate),
        signature: STANDARD.encode(signature),
    })
}

/// `POST /keycheck`: whether a token or a stored hash is live. Exactly one
/// of the two must be given.
pub fn keycheck(conn: &Connection, body: &KeyCheckRequest) -> Result<KeyCheckResponse> {
    let token = body.token.as_deref().filter(|s| !s.is_empty());
    let key_hash = body.key_hash.as_deref().filter(|s| !s.is_empty());
    let check = match (token, key_hash) {
        (Some(token), None) => api_key::check_token(conn, token)?,
        (None, Some(key_hash)) => api_key::check_hash(conn, key_hash)?,
        _ => return Err(Error::InvalidApiKeyRequest),
    };
    Ok(KeyCheckResponse {
        valid: check.valid,
        id: check.id,
        scope: check.scope,
        label: check.label,
        recipient_fingerprint: check.recipient_fingerprint,
    })
}

pub struct ParsedInbox {
    pub envelope: Vec<u8>,
    pub trees: Vec<PublicTree>,
    pub expires_at: Option<String>,
}

/// An inbox upload is raw `.kqpb` bytes, or JSON ([`InboxPush`]) that may
/// also carry public trees and an expiry.
pub fn parse_inbox(is_json: bool, body: &[u8]) -> Result<ParsedInbox> {
    if !is_json {
        return Ok(ParsedInbox {
            envelope: body.to_vec(),
            trees: Vec::new(),
            expires_at: None,
        });
    }
    let push: InboxPush = serde_json::from_slice(body).map_err(|_| Error::InvalidBridgePackage)?;
    let expires_at = match push.expires_at {
        Some(raw) => Some(crate::locked_files::parse_expires_utc(&raw)?),
        None => None,
    };
    let envelope = STANDARD
        .decode(push.bytes.as_bytes())
        .map_err(|_| Error::InvalidBridgePackage)?;
    Ok(ParsedInbox {
        envelope,
        trees: push.trees,
        expires_at,
    })
}

/// `POST /inbox` (`inbox.push`). Returns the stored id and whether the
/// envelope was already there.
pub fn inbox_push(
    conn: &Connection,
    token: &str,
    parsed: &ParsedInbox,
) -> Result<(InboxAccepted, bool)> {
    if parsed.envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::BundleFieldTooLarge);
    }
    api_key::authenticate(conn, token, ApiKeyScope::InboxPush)?;
    let (id, fingerprint, duplicate) = crate::db::with_immediate_transaction(conn, || {
        if let Some(expires_at) = parsed.expires_at.as_deref() {
            crate::locked_files::require_future_expires_utc(conn, expires_at)?;
        }
        for tree in &parsed.trees {
            org_tree::merge_public_tree(conn, tree)?;
        }
        mailbox::store_until(conn, &parsed.envelope, parsed.expires_at.as_deref())
    })?;
    Ok((
        InboxAccepted {
            id,
            recipient_fingerprint: fingerprint,
        },
        duplicate,
    ))
}

/// `GET /inbox` (`inbox.pull`), bound to the key's recipient fingerprint.
pub fn inbox_pull(
    conn: &Connection,
    token: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<InboxList> {
    let auth = api_key::authenticate(conn, token, ApiKeyScope::InboxPull)?;
    let fingerprint = auth.recipient_fingerprint.ok_or(Error::ApiKeyScopeDenied)?;
    let page = mailbox::list_after(conn, &fingerprint, after, limit)?;
    let trees = org_tree::slices_for_fingerprint(conn, &fingerprint)?;
    Ok(InboxList {
        envelopes: page
            .envelopes
            .into_iter()
            .map(|item| InboxEnvelope {
                id: item.id,
                recipient_fingerprint: item.recipient_fingerprint,
                bytes: STANDARD.encode(&item.bytes),
            })
            .collect(),
        trees,
        next_after: page.next_after,
    })
}

/// `GET /api-keys` (admin): keys without their bearers.
pub fn list_keys(conn: &Connection, token: &str) -> Result<Vec<ApiKeyView>> {
    api_key::authenticate(conn, token, ApiKeyScope::Admin)?;
    Ok(api_key::list(conn)?
        .into_iter()
        .map(ApiKeyView::from)
        .collect())
}

/// `POST /api-keys/{id}/revoke` (admin).
/// Recorded in `api_key_events` with the admin key that revoked it.
pub fn revoke_key(conn: &Connection, token: &str, id: i64) -> Result<()> {
    let admin = api_key::authenticate(conn, token, ApiKeyScope::Admin)?;
    api_key::revoke_by(conn, id, &api_key::admin_actor(admin.id))
}

/// `PUT /trees` (admin): replace a canonical public tree.
pub fn put_tree(conn: &Connection, token: &str, tree: &PublicTree) -> Result<PublicTree> {
    api_key::authenticate(conn, token, ApiKeyScope::Admin)?;
    org_tree::put_public_tree(conn, tree)
}

/// `GET /trees/{label}/context` (`inbox.pull`): the slice visible to the
/// key's fingerprint.
pub fn tree_context(conn: &Connection, token: &str, label: &str) -> Result<PublicTree> {
    let auth = api_key::authenticate(conn, token, ApiKeyScope::InboxPull)?;
    let fingerprint = auth.recipient_fingerprint.ok_or(Error::ApiKeyScopeDenied)?;
    org_tree::context_for_fingerprint(conn, label, &fingerprint)
}

fn authenticate_device_read(conn: &Connection, token: &str) -> Result<AuthedKey> {
    match api_key::authenticate(conn, token, ApiKeyScope::DevicePull) {
        Err(Error::ApiKeyScopeDenied) => {
            api_key::authenticate(conn, token, ApiKeyScope::DevicePush)
        }
        other => other,
    }
}

/// A device upload is raw letter bytes, or JSON ([`DevicePackagePush`]).
pub fn parse_device_package(is_json: bool, body: &[u8]) -> Result<Vec<u8>> {
    if !is_json {
        return Ok(body.to_vec());
    }
    let push: DevicePackagePush =
        serde_json::from_slice(body).map_err(|_| Error::InvalidBridgePackage)?;
    STANDARD
        .decode(push.bytes.as_bytes())
        .map_err(|_| Error::InvalidBridgePackage)
}

/// `POST /devices/packages` (`device.push`).
pub fn device_push(
    conn: &Connection,
    token: &str,
    package: &[u8],
) -> Result<(InboxAccepted, bool)> {
    if package.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::BundleFieldTooLarge);
    }
    api_key::authenticate(conn, token, ApiKeyScope::DevicePush)?;
    let (id, fingerprint, duplicate) = device_mail::store(conn, package)?;
    Ok((
        InboxAccepted {
            id,
            recipient_fingerprint: fingerprint,
        },
        duplicate,
    ))
}

/// `GET /devices/packages` (`device.pull`), bound to the key's fingerprint.
pub fn device_pull(
    conn: &Connection,
    token: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<DevicePackageList> {
    let auth = api_key::authenticate(conn, token, ApiKeyScope::DevicePull)?;
    let fingerprint = auth.recipient_fingerprint.ok_or(Error::ApiKeyScopeDenied)?;
    let page = device_mail::list_after(conn, &fingerprint, after, limit)?;
    Ok(DevicePackageList {
        packages: page
            .packages
            .into_iter()
            .map(|item| InboxEnvelope {
                id: item.id,
                recipient_fingerprint: item.recipient_fingerprint,
                bytes: STANDARD.encode(&item.bytes),
            })
            .collect(),
        next_after: page.next_after,
    })
}

/// `PUT /devices` (`device.push`): store a signed public descriptor.
pub fn put_device(
    conn: &Connection,
    token: &str,
    descriptor: &DeviceDescriptor,
) -> Result<DeviceDescriptor> {
    api_key::authenticate(conn, token, ApiKeyScope::DevicePush)?;
    device_directory::put(conn, descriptor)
}

/// `GET /devices/{device_id}` (`device.pull` or `device.push`).
pub fn get_device(conn: &Connection, token: &str, device_id: &str) -> Result<DeviceDescriptor> {
    authenticate_device_read(conn, token)?;
    device_directory::require(conn, device_id)
}

/// Route one request to the handler above, the way the HTTP router does,
/// and render its result the way the HTTP server would. `GET /health` and
/// the documentation routes are HTTP-only and not served here.
pub fn dispatch(
    conn: &Connection,
    identity: Option<&ProviderIdentity>,
    request: &RelayHttpRequest,
) -> RelayHttpResponse {
    match route(conn, identity, request) {
        Ok(response) => response,
        Err(err) => {
            let err = HttpError::from(err);
            json_response(err.status, &ErrorBody { error: err.message })
        }
    }
}

fn route(
    conn: &Connection,
    identity: Option<&ProviderIdentity>,
    request: &RelayHttpRequest,
) -> Result<RelayHttpResponse> {
    let path = request.url.path();
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let query = |name: &str| -> Result<Option<i64>> {
        match request.url.query_pairs().find(|(key, _)| key == name) {
            Some((_, value)) => value.parse().map(Some).map_err(|_| Error::InvalidInboxPage),
            None => Ok(None),
        }
    };
    let token = || request.bearer.clone().ok_or(Error::InvalidApiKey);
    let is_json = request.content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .map(str::trim)
            .is_some_and(|mime| mime.eq_ignore_ascii_case("application/json"))
    });
    match (request.method, segments.as_slice()) {
        ("POST", ["provider-identity"]) => {
            let body: ProviderIdentityRequest = parse_json(&request.body)?;
            Ok(json_response(200, &provider_identity(identity, &body)?))
        }
        ("POST", ["keycheck"]) => {
            let body: KeyCheckRequest = parse_json(&request.body)?;
            Ok(json_response(200, &keycheck(conn, &body)?))
        }
        ("POST", ["inbox"]) => {
            let parsed = parse_inbox(is_json, &request.body)?;
            let (accepted, duplicate) = inbox_push(conn, &token()?, &parsed)?;
            Ok(json_response(if duplicate { 200 } else { 201 }, &accepted))
        }
        ("GET", ["inbox"]) => Ok(json_response(
            200,
            &inbox_pull(conn, &token()?, query("after")?, query("limit")?)?,
        )),
        ("GET", ["api-keys"]) => Ok(json_response(200, &list_keys(conn, &token()?)?)),
        ("GET", ["audit", "api-keys"]) => Ok(json_response(200, &audit_events(conn, &token()?)?)),
        ("POST", ["api-keys", id, "revoke"]) => {
            let id = id.parse().map_err(|_| Error::ApiKeyNotFound)?;
            revoke_key(conn, &token()?, id)?;
            Ok(RelayHttpResponse {
                status: 204,
                body: Vec::new(),
            })
        }
        ("PUT", ["trees"]) => {
            let tree: PublicTree = parse_json(&request.body)?;
            Ok(json_response(200, &put_tree(conn, &token()?, &tree)?))
        }
        ("GET", ["trees", label, "context"]) => {
            let label = percent_decode(label)?;
            Ok(json_response(200, &tree_context(conn, &token()?, &label)?))
        }
        ("POST", ["devices", "packages"]) => {
            let package = parse_device_package(is_json, &request.body)?;
            let (accepted, duplicate) = device_push(conn, &token()?, &package)?;
            Ok(json_response(if duplicate { 200 } else { 201 }, &accepted))
        }
        ("GET", ["devices", "packages"]) => Ok(json_response(
            200,
            &device_pull(conn, &token()?, query("after")?, query("limit")?)?,
        )),
        ("PUT", ["devices"]) => {
            let descriptor: DeviceDescriptor = parse_json(&request.body)?;
            Ok(json_response(
                200,
                &put_device(conn, &token()?, &descriptor)?,
            ))
        }
        ("GET", ["devices", device_id]) => {
            Ok(json_response(200, &get_device(conn, &token()?, device_id)?))
        }
        _ => Ok(json_response(
            404,
            &ErrorBody {
                error: "not found".to_string(),
            },
        )),
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| Error::InvalidApiKeyRequest)
}

fn json_response<T: Serialize>(status: u16, value: &T) -> RelayHttpResponse {
    match serde_json::to_vec(value) {
        Ok(body) => RelayHttpResponse { status, body },
        Err(_) => RelayHttpResponse {
            status: 500,
            body: br#"{"error":"internal error"}"#.to_vec(),
        },
    }
}

fn percent_decode(segment: &str) -> Result<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = segment.get(i + 1..i + 3).ok_or(Error::TreeNotFound)?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::TreeNotFound)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::TreeNotFound)
}

#[cfg(test)]
#[path = "service/tests.rs"]
mod tests;
