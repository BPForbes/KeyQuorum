//! Axum router for the mailbox relay. Handlers never unseal envelopes.

use super::api_key::ApiKeyEvent;
use super::client::{
    DevicePackageList, DevicePackagePush, ErrorBody, InboxAccepted, InboxEnvelope, InboxList,
    InboxPush, KeyCheckRequest, KeyCheckResponse, ProviderIdentityRequest,
    ProviderIdentityResponse,
};
use super::device_directory::{DeviceDescriptor, DeviceSlotDescriptor};
use super::service::{self, ApiKeyView, HttpError, ProviderIdentity, MAX_ENVELOPE_BYTES};
use crate::error::Error;
use crate::key_tree::{PublicEdge, PublicNode, PublicTree};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    identity: Option<Arc<ProviderIdentity>>,
    rate_limit: Option<Arc<RateLimiter>>,
}

impl AppState {
    pub fn new(conn: Connection) -> Self {
        Self {
            db: Arc::new(Mutex::new(conn)),
            identity: None,
            rate_limit: None,
        }
    }

    pub fn with_identity(conn: Connection, identity: ProviderIdentity) -> Self {
        Self {
            db: Arc::new(Mutex::new(conn)),
            identity: Some(Arc::new(identity)),
            rate_limit: None,
        }
    }

    /// Limit each client to `per_minute` requests (0 turns the limit off).
    /// With `trust_forwarded`, the client is the address the TLS proxy put
    /// last in `X-Forwarded-For`; otherwise the connection's peer address.
    pub fn with_rate_limit(mut self, per_minute: u32, trust_forwarded: bool) -> Self {
        self.rate_limit =
            (per_minute > 0).then(|| Arc::new(RateLimiter::new(per_minute, trust_forwarded)));
        self
    }

    pub fn identity(&self) -> Option<Arc<ProviderIdentity>> {
        self.identity.clone()
    }
}

/// The caller's bearer, zeroed when the request is done with it.
struct ApiToken(Zeroizing<String>);

impl<S> FromRequestParts<S> for ApiToken
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        token_from_headers(&parts.headers).map(ApiToken)
    }
}

fn token_from_headers(headers: &HeaderMap) -> Result<Zeroizing<String>, ApiError> {
    if let Some(value) = headers.get(AUTHORIZATION) {
        let s = value.to_str().map_err(|_| ApiError::unauthorized())?;
        if let Some(token) = s.strip_prefix("Bearer ") {
            if !token.is_empty() {
                return Ok(Zeroizing::new(token.to_string()));
            }
        }
    }
    if let Some(value) = headers.get("x-api-key") {
        let s = value.to_str().map_err(|_| ApiError::unauthorized())?;
        if !s.is_empty() {
            return Ok(Zeroizing::new(s.to_string()));
        }
    }
    Err(ApiError::unauthorized())
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized() -> Self {
        HttpError::unauthorized().into()
    }

    fn internal() -> Self {
        HttpError::internal().into()
    }
}

impl From<HttpError> for ApiError {
    fn from(err: HttpError) -> Self {
        Self {
            status: StatusCode::from_u16(err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            message: err.message,
        }
    }
}

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        HttpError::from(err).into()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

async fn with_conn<T, F>(state: &AppState, f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> crate::error::Result<T> + Send + 'static,
{
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&conn)
    })
    .await
    .map_err(|_| ApiError::internal())
    .and_then(|result| result.map_err(ApiError::from))
}

#[derive(Serialize, ToSchema)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Deserialize, IntoParams)]
struct InboxQuery {
    after: Option<i64>,
    /// Page size, 1–500. Defaults to 100 when omitted.
    limit: Option<i64>,
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("API key")
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        post_keycheck,
        post_inbox,
        get_inbox,
        list_keys,
        revoke_key,
        get_audit_events,
        put_tree,
        get_tree_context,
        post_provider_identity,
        post_device_package,
        get_device_packages,
        put_device,
        get_device
    ),
    components(
        schemas(
            HealthResponse,
            KeyCheckRequest,
            KeyCheckResponse,
            InboxAccepted,
            InboxEnvelope,
            InboxList,
            InboxPush,
            DevicePackagePush,
            DevicePackageList,
            DeviceDescriptor,
            DeviceSlotDescriptor,
            ErrorBody,
            ApiKeyView,
            ApiKeyEvent,
            PublicTree,
            PublicNode,
            PublicEdge,
            ProviderIdentityRequest,
            ProviderIdentityResponse
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "inbox", description = "Opaque .kqpb envelope mailbox"),
        (name = "api-keys", description = "List and revoke API keys"),
        (name = "audit", description = "API-key lifecycle events, scoped to the caller"),
        (name = "trees", description = "Canonical public split-tree topology"),
        (name = "provider", description = "KeyQuorum-signed relay identity"),
        (name = "devices", description = "Sealed device copy, move, and relocate letters")
    )
)]
struct ApiDoc;

#[utoipa::path(
    get,
    path = "/health",
    tag = "inbox",
    responses((status = 200, description = "Relay is up", body = HealthResponse))
)]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[utoipa::path(
    post,
    path = "/provider-identity",
    tag = "provider",
    request_body = ProviderIdentityRequest,
    responses(
        (status = 200, description = "Certificate plus signature over the challenge", body = ProviderIdentityResponse),
        (status = 400, description = "Challenge is not 32 bytes", body = ErrorBody),
        (status = 503, description = "Host has no provider identity", body = ErrorBody)
    )
)]
async fn post_provider_identity(
    State(state): State<AppState>,
    Json(body): Json<ProviderIdentityRequest>,
) -> Result<Json<ProviderIdentityResponse>, ApiError> {
    Ok(Json(service::provider_identity(
        state.identity.as_deref(),
        &body,
    )?))
}

#[utoipa::path(
    post,
    path = "/keycheck",
    tag = "api-keys",
    request_body = KeyCheckRequest,
    responses(
        (status = 200, description = "Whether the token or stored hash is live", body = KeyCheckResponse),
        (status = 400, description = "Provide exactly one of token or key_hash", body = ErrorBody)
    )
)]
async fn post_keycheck(
    State(state): State<AppState>,
    Json(body): Json<KeyCheckRequest>,
) -> Result<Json<KeyCheckResponse>, ApiError> {
    let check = with_conn(&state, move |conn| service::keycheck(conn, &body)).await?;
    Ok(Json(check))
}

#[utoipa::path(
    post,
    path = "/inbox",
    tag = "inbox",
    request_body(content = InboxPush, content_type = "application/json"),
    responses(
        (status = 201, description = "Envelope stored; attached trees merge into canonical public context", body = InboxAccepted),
        (status = 200, description = "Envelope already stored", body = InboxAccepted),
        (status = 400, description = "Malformed envelope or tree", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 413, description = "Envelope too large", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn post_inbox(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<InboxAccepted>), ApiError> {
    let parsed = service::parse_inbox(is_json(&headers), &body)?;
    let (accepted, duplicate) = with_conn(&state, move |conn| {
        service::inbox_push(conn, &token, &parsed)
    })
    .await?;
    Ok((created_or_ok(duplicate), Json(accepted)))
}

/// `Content-Type: application/json` (parameters ignored), the one switch
/// the upload routes take between raw bytes and a JSON body.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .map(str::trim)
                .is_some_and(|mime| mime.eq_ignore_ascii_case("application/json"))
        })
}

fn created_or_ok(duplicate: bool) -> StatusCode {
    if duplicate {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    }
}

#[utoipa::path(
    get,
    path = "/inbox",
    tag = "inbox",
    params(InboxQuery),
    responses(
        (status = 200, description = "Envelopes and public-tree slices for this pull key", body = InboxList),
        (status = 400, description = "Invalid page size", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn get_inbox(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Query(query): Query<InboxQuery>,
) -> Result<Json<InboxList>, ApiError> {
    let (after, limit) = (query.after, query.limit);
    let list = with_conn(&state, move |conn| {
        service::inbox_pull(conn, &token, after, limit)
    })
    .await?;
    Ok(Json(list))
}

#[utoipa::path(
    get,
    path = "/api-keys",
    tag = "api-keys",
    responses(
        (status = 200, description = "API keys without bearers", body = [ApiKeyView]),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn list_keys(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
) -> Result<Json<Vec<ApiKeyView>>, ApiError> {
    let keys = with_conn(&state, move |conn| service::list_keys(conn, &token)).await?;
    Ok(Json(keys))
}

#[utoipa::path(
    post,
    path = "/api-keys/{id}/revoke",
    tag = "api-keys",
    params(("id" = i64, Path, description = "API key id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown key", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn revoke_key(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let identity = state.identity();
    with_conn(&state, move |conn| {
        service::revoke_key(conn, &token, id)?;
        // Sign the new chain head at once, so the revocation is vouched
        // for before the next scan.
        if let Some(identity) = identity {
            if let Err(err) = anchor_now(conn, &identity) {
                tracing::warn!("audit anchor after revocation failed: {err}");
            }
        }
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Anchor the audit chains with this relay's key at the current time.
pub fn anchor_now(conn: &Connection, identity: &ProviderIdentity) -> crate::error::Result<usize> {
    let now = crate::provider::system_now_utc_millis()?;
    super::audit::anchor(conn, identity, &now)
}

#[utoipa::path(
    get,
    path = "/audit/api-keys",
    tag = "audit",
    responses(
        (status = 200, description = "Events about the caller's own key (every event for an admin key)", body = [ApiKeyEvent]),
        (status = 401, description = "Unauthorized", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn get_audit_events(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
) -> Result<Json<Vec<ApiKeyEvent>>, ApiError> {
    let events = with_conn(&state, move |conn| service::audit_events(conn, &token)).await?;
    Ok(Json(events))
}

#[utoipa::path(
    put,
    path = "/trees",
    tag = "trees",
    request_body = PublicTree,
    responses(
        (status = 200, description = "Public tree replaced", body = PublicTree),
        (status = 400, description = "Malformed tree", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn put_tree(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Json(tree): Json<PublicTree>,
) -> Result<Json<PublicTree>, ApiError> {
    let stored = with_conn(&state, move |conn| service::put_tree(conn, &token, &tree)).await?;
    Ok(Json(stored))
}

#[utoipa::path(
    get,
    path = "/trees/{label}/context",
    tag = "trees",
    params(("label" = String, Path, description = "keys.label of the published tree")),
    responses(
        (status = 200, description = "Visible public-tree slice for this pull key", body = PublicTree),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown tree or fingerprint", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn get_tree_context(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Path(label): Path<String>,
) -> Result<Json<PublicTree>, ApiError> {
    let slice = with_conn(&state, move |conn| {
        service::tree_context(conn, &token, &label)
    })
    .await?;
    Ok(Json(slice))
}

#[utoipa::path(
    post,
    path = "/devices/packages",
    tag = "devices",
    request_body(content = DevicePackagePush, content_type = "application/json"),
    responses(
        (status = 201, description = "Device letter stored", body = InboxAccepted),
        (status = 200, description = "Device letter already stored", body = InboxAccepted),
        (status = 400, description = "Not a sealed device letter", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 413, description = "Letter too large", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn post_device_package(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<InboxAccepted>), ApiError> {
    let package = service::parse_device_package(is_json(&headers), &body)?;
    let (accepted, duplicate) = with_conn(&state, move |conn| {
        service::device_push(conn, &token, &package)
    })
    .await?;
    Ok((created_or_ok(duplicate), Json(accepted)))
}

#[utoipa::path(
    get,
    path = "/devices/packages",
    tag = "devices",
    params(InboxQuery),
    responses(
        (status = 200, description = "Device letters for this pull key", body = DevicePackageList),
        (status = 400, description = "Invalid page size", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn get_device_packages(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Query(query): Query<InboxQuery>,
) -> Result<Json<DevicePackageList>, ApiError> {
    let (after, limit) = (query.after, query.limit);
    let list = with_conn(&state, move |conn| {
        service::device_pull(conn, &token, after, limit)
    })
    .await?;
    Ok(Json(list))
}

#[utoipa::path(
    put,
    path = "/devices",
    tag = "devices",
    request_body = DeviceDescriptor,
    responses(
        (status = 200, description = "Public device descriptor stored", body = DeviceDescriptor),
        (status = 400, description = "Descriptor is unsigned or malformed", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn put_device(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Json(descriptor): Json<DeviceDescriptor>,
) -> Result<Json<DeviceDescriptor>, ApiError> {
    let stored = with_conn(&state, move |conn| {
        service::put_device(conn, &token, &descriptor)
    })
    .await?;
    Ok(Json(stored))
}

#[utoipa::path(
    get,
    path = "/devices/{device_id}",
    tag = "devices",
    params(("device_id" = String, Path, description = "Hex device id")),
    responses(
        (status = 200, description = "Public device descriptor", body = DeviceDescriptor),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown device", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn get_device(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceDescriptor>, ApiError> {
    let descriptor = with_conn(&state, move |conn| {
        service::get_device(conn, &token, &device_id)
    })
    .await?;
    Ok(Json(descriptor))
}

/// Most clients the rate limiter tracks at once. Past this, expired windows
/// are dropped, and if every tracked client is still active, new clients
/// share one overflow bucket, so memory stays bounded under a flood of
/// distinct addresses.
pub const MAX_RATE_LIMITED_CLIENTS: usize = 65_536;

const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Who a request is counted against. An IPv6 client is its /64 network, the
/// smallest block one subscriber is normally given, so one host cycling
/// through its own addresses is still one client. Requests with no peer
/// address and new clients past [`MAX_RATE_LIMITED_CLIENTS`] each have
/// their own bucket, so neither crowds out the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ClientKey {
    V4(Ipv4Addr),
    V6Network(u64),
    UnknownPeer,
    Overflow,
}

impl ClientKey {
    fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => Self::V6Network((v6.to_bits() >> 64) as u64),
        }
    }
}

impl std::fmt::Display for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(ip) => write!(f, "{ip}"),
            Self::V6Network(network) => {
                write!(f, "{}/64", Ipv6Addr::from_bits(u128::from(*network) << 64))
            }
            Self::UnknownPeer => f.write_str("unknown peer"),
            Self::Overflow => f.write_str("overflow"),
        }
    }
}

/// A fixed one-minute window per client (see [`ClientKey`]).
pub struct RateLimiter {
    per_minute: u32,
    trust_forwarded: bool,
    clients: Mutex<HashMap<ClientKey, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32, trust_forwarded: bool) -> Self {
        Self {
            per_minute,
            trust_forwarded,
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// `Ok` to serve a request from `client`, or how long until it may retry.
    pub fn check(&self, client: IpAddr, now: Instant) -> std::result::Result<(), Duration> {
        self.check_key(ClientKey::of(client), now)
    }

    fn check_key(&self, client: ClientKey, now: Instant) -> std::result::Result<(), Duration> {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !clients.contains_key(&client) && clients.len() >= MAX_RATE_LIMITED_CLIENTS {
            clients.retain(|_, (start, _)| now.duration_since(*start) < RATE_WINDOW);
        }
        // The unknown-peer bucket is one fixed entry, never displaced by
        // the overflow it is kept apart from.
        let key = if client == ClientKey::UnknownPeer
            || clients.contains_key(&client)
            || clients.len() < MAX_RATE_LIMITED_CLIENTS
        {
            client
        } else {
            ClientKey::Overflow
        };
        let entry = clients.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= RATE_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_minute {
            return Err(RATE_WINDOW.saturating_sub(now.duration_since(entry.0)));
        }
        entry.1 += 1;
        Ok(())
    }

    fn client(&self, request: &Request) -> ClientKey {
        if self.trust_forwarded {
            // The proxy appends the address it saw, so only the last entry
            // is the proxy's word; earlier ones are whatever the client sent.
            let forwarded = request
                .headers()
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .next_back()
                .and_then(|last| last.trim().parse::<IpAddr>().ok());
            if let Some(ip) = forwarded {
                return ClientKey::of(ip);
            }
        }
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(ClientKey::UnknownPeer, |info| ClientKey::of(info.0.ip()))
    }
}

async fn rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let client = limiter.client(&request);
    match limiter.check_key(client, Instant::now()) {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            tracing::warn!(%client, "relay rate limit exceeded");
            let mut response = ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "rate limit exceeded".to_string(),
            }
            .into_response();
            let seconds = retry_after.as_secs().max(1).to_string();
            if let Ok(value) = HeaderValue::from_str(&seconds) {
                response.headers_mut().insert(RETRY_AFTER, value);
            }
            response
        }
    }
}

/// Longest a request may take, body included, before the relay answers
/// `408 Request Timeout`, so a slow or stalled client cannot hold a
/// connection and the database lock indefinitely.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The relay serves plain HTTP. That is only acceptable on loopback, or
/// when the operator states that a TLS-terminating proxy sits in front of
/// it (`--behind-tls-proxy`); official clients refuse plain HTTP to any
/// other host, and a bearer must never cross a network in the clear.
pub fn check_bind(addr: &SocketAddr, behind_tls_proxy: bool) -> crate::error::Result<()> {
    if addr.ip().is_loopback() || behind_tls_proxy {
        return Ok(());
    }
    Err(Error::RelayRequest(format!(
        "refusing to serve plain HTTP on non-loopback address {addr}: bind to loopback, \
         or pass --behind-tls-proxy when a TLS-terminating proxy forwards to this address"
    )))
}

pub fn router(state: AppState) -> Router {
    let limiter = state.rate_limit.clone();
    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(health))
        .route("/keycheck", post(post_keycheck))
        .route("/provider-identity", post(post_provider_identity))
        .route("/inbox", post(post_inbox).get(get_inbox))
        .route("/api-keys", get(list_keys))
        .route("/api-keys/{id}/revoke", post(revoke_key))
        .route("/audit/api-keys", get(get_audit_events))
        .route("/trees", put(put_tree))
        .route("/trees/{label}/context", get(get_tree_context))
        .route(
            "/devices/packages",
            post(post_device_package).get(get_device_packages),
        )
        .route("/devices", put(put_device))
        .route("/devices/{device_id}", get(get_device))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES.saturating_mul(2)))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(state);
    // Outermost after tracing, so a refused request costs no database work
    // and still shows up in the trace.
    let app = match limiter {
        Some(limiter) => app.layer(middleware::from_fn_with_state(limiter, rate_limit)),
        None => app,
    };
    app.layer(TraceLayer::new_for_http())
}

#[cfg(test)]
mod tests;
