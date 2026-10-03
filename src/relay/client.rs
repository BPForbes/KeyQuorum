//! HTTP JSON wire types and a synchronous client for the relay. Requests go
//! through a [`RelayTransport`]: `ureq` over HTTPS natively, or an
//! in-process relay in the browser lab.

use super::device_directory::DeviceDescriptor;
use crate::error::{Error, Result};
use crate::key_tree::PublicTree;
use crate::provider::{self, Certificate};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::OnceLock;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
use url::Url;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxAccepted {
    pub id: i64,
    pub recipient_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxEnvelope {
    pub id: i64,
    pub recipient_fingerprint: String,
    /// Standard base64 of the exact `.kqpb` bytes.
    pub bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxList {
    pub envelopes: Vec<InboxEnvelope>,
    /// Visible public-tree slices for this pull key's fingerprint.
    /// Empty when nothing is published or this fingerprint is not in a tree.
    #[serde(default)]
    pub trees: Vec<PublicTree>,
    /// Id to pass as `after` for the next page. Absent when this page is complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<i64>,
}

/// JSON inbox upload: opaque envelope plus optional public trees.
/// Sending trees merges into the relay's canonical documents for those labels.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxPush {
    /// Standard base64 of the exact `.kqpb` bytes.
    pub bytes: String,
    /// Public trees to merge. Omit or empty to leave server context unchanged.
    /// Nodes the sender does not hold stay on the relay.
    #[serde(default)]
    pub trees: Vec<PublicTree>,
    /// UTC expiry as `YYYY-MM-DD HH:MM:00`. After this instant the host
    /// scan and inbox pull delete the envelope so it cannot be fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

/// Body for the unauthenticated `POST /keycheck` route.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct KeyCheckRequest {
    /// Raw `kq_…` bearer. Used by `loadkey` and `--api-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// `hex(SHA-256(raw))` stored on the personal instance after a valid load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hash: Option<String>,
}

/// Whether the key is live on the service. Invalid keys are not distinguished
/// (unknown, expired, and revoked all return `valid: false`).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct KeyCheckResponse {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_fingerprint: Option<String>,
}

/// Unauthenticated `POST /provider-identity` challenge.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProviderIdentityRequest {
    /// Standard base64 of a 32-byte random challenge.
    pub challenge: String,
}

/// JSON upload of one sealed device letter.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct DevicePackagePush {
    /// Standard base64 of the exact `KQPB` bytes.
    pub bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct DevicePackageList {
    pub packages: Vec<InboxEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<i64>,
}

/// Certificate bytes plus the relay signature over the challenge.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProviderIdentityResponse {
    /// Standard base64 of the `provider.kqcert` bytes.
    pub certificate: String,
    /// Standard base64 of the 64-byte Ed25519 signature.
    pub signature: String,
}

/// HTTPS is always accepted. HTTP is only allowed for loopback hosts so a
/// bearer is never sent in the clear to a remote relay.
pub fn validate_relay_url(url: &str) -> Result<()> {
    parse_relay_url(url).map(|_| ())
}

/// Parse once with the WHATWG parser, then validate that parsed host.
/// Callers must reuse the returned `Url` (whose serialization is canonical)
/// for the request so a string-level host check cannot disagree with the
/// connect target.
fn parse_relay_url(raw: &str) -> Result<Url> {
    let raw = raw.trim();
    if raw.contains('\\') {
        return Err(Error::RelayRequest(
            "relay URL must not contain backslashes".into(),
        ));
    }
    let parsed = Url::parse(raw).map_err(|_| {
        Error::RelayRequest("relay URL must use https, or http only to a loopback host".into())
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::RelayRequest(
            "relay URL must not include userinfo".into(),
        ));
    }
    if parsed.host().is_none() {
        return Err(Error::RelayRequest("relay URL is missing a host".into()));
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if is_loopback_url(&parsed) => Ok(parsed),
        "http" => Err(Error::RelayRequest(
            "HTTP relay URLs are only allowed for loopback hosts".into(),
        )),
        _ => Err(Error::RelayRequest(
            "relay URL must use https, or http only to a loopback host".into(),
        )),
    }
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn relay_request_url(base: &str, path: &str) -> Result<Url> {
    let mut parsed = parse_relay_url(base)?;
    let joined = format!("{}{path}", parsed.path().trim_end_matches('/'));
    parsed.set_path(&joined);
    Ok(parsed)
}

/// One relay request, already validated and addressed. The transport only
/// has to deliver it.
pub struct RelayHttpRequest {
    pub method: &'static str,
    pub url: Url,
    /// Sent as `Authorization: Bearer …`; zeroed when the request is dropped.
    pub bearer: Option<zeroize::Zeroizing<String>>,
    pub content_type: Option<&'static str>,
    pub body: Vec<u8>,
}

/// The relay's answer: status code and raw body.
pub struct RelayHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// How relay requests travel. [`UreqTransport`] is HTTPS to a hosted
/// relay; the browser lab delivers them to an in-process relay instead
/// (`relay::service::dispatch`). Every client function below takes one, so
/// the request shapes, bearer handling, and provider check are the same
/// either way.
pub trait RelayTransport {
    fn send(&self, request: RelayHttpRequest) -> Result<RelayHttpResponse>;
}

/// HTTPS (or loopback HTTP) through `ureq`, with bounded timeouts and no
/// redirects.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct UreqTransport;

#[cfg(not(target_arch = "wasm32"))]
impl RelayTransport for UreqTransport {
    fn send(&self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        let mut req = ureq::http::Request::builder()
            .method(request.method)
            .uri(request.url.as_str());
        if let Some(bearer) = &request.bearer {
            req = req.header("Authorization", format!("Bearer {}", bearer.as_str()));
        }
        if let Some(content_type) = request.content_type {
            req = req.header("Content-Type", content_type);
        }
        let result = if request.method == "GET" {
            req.body(())
                .map_err(|e| Error::RelayRequest(e.to_string()))
                .and_then(|req| {
                    http_agent()
                        .run(req)
                        .map_err(|e| Error::RelayRequest(e.to_string()))
                })
        } else {
            req.body(request.body)
                .map_err(|e| Error::RelayRequest(e.to_string()))
                .and_then(|req| {
                    http_agent()
                        .run(req)
                        .map_err(|e| Error::RelayRequest(e.to_string()))
                })
        };
        let resp = result?;
        let status = resp.status().as_u16();
        let body = read_bounded(resp.into_body().into_reader(), MAX_RESPONSE_BYTES)?;
        Ok(RelayHttpResponse { status, body })
    }
}

/// Largest relay response the client reads: a full inbox page of envelopes
/// fits, and an untrusted or compromised relay cannot exhaust memory by
/// streaming more (the provider check itself runs over this transport).
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

/// Reads at most `limit` bytes and refuses a longer body instead of
/// truncating it silently.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) fn read_bounded(reader: impl std::io::Read, limit: u64) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut reader.take(limit.saturating_add(1)), &mut body)
        .map_err(|e| Error::RelayRequest(e.to_string()))?;
    if body.len() as u64 > limit {
        return Err(Error::RelayRequest(format!(
            "relay response exceeds {limit} bytes"
        )));
    }
    Ok(body)
}

/// Longest piece of a relay's error body quoted in an error message.
const MAX_ERROR_TEXT_CHARS: usize = 512;

/// A relay's error body as safe terminal text: control characters (escape
/// sequences included) dropped and the length capped, since the relay is
/// on the other side of a network boundary.
pub(crate) fn relay_error_text(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut out: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_TEXT_CHARS)
        .collect();
    if text
        .chars()
        .filter(|c| !c.is_control())
        .nth(MAX_ERROR_TEXT_CHARS)
        .is_some()
    {
        out.push('…');
    }
    out
}

/// Status codes come back as responses, not errors, so the caller sees the
/// relay's body; no redirects are followed, and no proxy is taken from the
/// environment.
#[cfg(not(target_arch = "wasm32"))]
fn http_agent_config() -> ureq::config::ConfigBuilder<ureq::typestate::AgentScope> {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_send_request(Some(Duration::from_secs(20)))
        .timeout_send_body(Some(Duration::from_secs(20)))
        .timeout_recv_response(Some(Duration::from_secs(20)))
        .timeout_recv_body(Some(Duration::from_secs(20)))
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .http_status_as_error(false)
        .proxy(None)
}

#[cfg(not(target_arch = "wasm32"))]
fn http_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| ureq::Agent::new_with_config(http_agent_config().build()))
}

fn request(
    method: &'static str,
    url: Url,
    bearer: Option<&str>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
) -> RelayHttpRequest {
    RelayHttpRequest {
        method,
        url,
        bearer: bearer.map(|b| zeroize::Zeroizing::new(b.to_owned())),
        content_type,
        body,
    }
}

fn json_body<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| Error::RelayRequest(e.to_string()))
}

fn read_json<T: serde::de::DeserializeOwned>(response: RelayHttpResponse) -> Result<T> {
    if !(200..300).contains(&response.status) {
        let body = relay_error_text(&response.body);
        return Err(Error::RelayRequest(format!(
            "HTTP {}: {body}",
            response.status
        )));
    }
    serde_json::from_slice(&response.body).map_err(|e| Error::RelayRequest(e.to_string()))
}

fn page_query(url: &mut Url, after: Option<i64>, limit: Option<i64>) {
    let mut params = Vec::new();
    if let Some(after) = after {
        params.push(format!("after={after}"));
    }
    if let Some(limit) = limit {
        params.push(format!("limit={limit}"));
    }
    if !params.is_empty() {
        url.set_query(Some(&params.join("&")));
    }
}

/// Upload one opaque `.kqpb` envelope (no tree update).
pub fn push(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    envelope: &[u8],
) -> Result<InboxAccepted> {
    let url = relay_request_url(base_url, "/inbox")?;
    read_json(transport.send(request(
        "POST",
        url,
        Some(api_key),
        Some("application/octet-stream"),
        envelope.to_vec(),
    ))?)
}

/// Upload an envelope and merge the sender's public-tree documents.
pub fn push_with_trees(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    envelope: &[u8],
    trees: &[PublicTree],
) -> Result<InboxAccepted> {
    push_with_trees_until(transport, base_url, api_key, envelope, trees, None)
}

/// Like [`push_with_trees`], and stamps a UTC envelope expiry the host scan
/// will delete after.
pub fn push_with_trees_until(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    envelope: &[u8],
    trees: &[PublicTree],
    expires_at: Option<&str>,
) -> Result<InboxAccepted> {
    let body = InboxPush {
        bytes: base64::engine::general_purpose::STANDARD.encode(envelope),
        trees: trees.to_vec(),
        expires_at: expires_at.map(str::to_owned),
    };
    let url = relay_request_url(base_url, "/inbox")?;
    read_json(transport.send(request(
        "POST",
        url,
        Some(api_key),
        Some("application/json"),
        json_body(&body)?,
    ))?)
}

/// Fetch one page of envelopes for the pull key's bound fingerprint.
pub fn pull(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<InboxList> {
    let mut url = relay_request_url(base_url, "/inbox")?;
    page_query(&mut url, after, limit);
    read_json(transport.send(request("GET", url, Some(api_key), None, Vec::new()))?)
}

/// Ask the relay whether a bearer is live. No `Authorization` header.
pub fn check_key(
    transport: &dyn RelayTransport,
    base_url: &str,
    token: &str,
) -> Result<KeyCheckResponse> {
    post_keycheck(
        transport,
        base_url,
        &KeyCheckRequest {
            token: Some(token.to_string()),
            key_hash: None,
        },
    )
}

/// Revalidate a hash stored on the personal instance. No `Authorization` header.
pub fn check_key_hash(
    transport: &dyn RelayTransport,
    base_url: &str,
    key_hash: &str,
) -> Result<KeyCheckResponse> {
    post_keycheck(
        transport,
        base_url,
        &KeyCheckRequest {
            token: None,
            key_hash: Some(key_hash.to_string()),
        },
    )
}

fn post_keycheck(
    transport: &dyn RelayTransport,
    base_url: &str,
    body: &KeyCheckRequest,
) -> Result<KeyCheckResponse> {
    let url = relay_request_url(base_url, "/keycheck")?;
    read_json(transport.send(request(
        "POST",
        url,
        None,
        Some("application/json"),
        json_body(body)?,
    ))?)
}

/// Challenge the relay for a KeyQuorum-signed provider certificate and a
/// signature over a fresh nonce. Official clients call this *before*
/// sending a bearer so a modified host cannot skip authorization.
pub fn authenticate_provider(
    transport: &dyn RelayTransport,
    base_url: &str,
    root_public_key: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<Certificate> {
    let challenge = provider::random_challenge();
    let body = ProviderIdentityRequest {
        challenge: base64::engine::general_purpose::STANDARD.encode(challenge),
    };
    let url = relay_request_url(base_url, "/provider-identity")?;
    let response = transport.send(request(
        "POST",
        url,
        None,
        Some("application/json"),
        json_body(&body)?,
    ))?;
    let response: ProviderIdentityResponse = match response.status {
        200..=299 => serde_json::from_slice(&response.body).map_err(|_| Error::UntrustedRelay)?,
        503 => return Err(Error::UntrustedRelay),
        400 => return Err(Error::InvalidProviderChallenge),
        code => {
            let body = relay_error_text(&response.body);
            return Err(Error::RelayRequest(format!("HTTP {code}: {body}")));
        }
    };
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(response.certificate.as_bytes())
        .map_err(|_| Error::UntrustedRelay)?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(response.signature.as_bytes())
        .map_err(|_| Error::UntrustedRelay)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Error::UntrustedRelay)?;
    let cert = provider::verify_certificate(root_public_key, &cert_bytes, now_utc, revoked)?;
    provider::verify_challenge(&cert, &challenge, &signature)?;
    Ok(cert)
}

/// Replace the relay's canonical public tree (admin scope).
pub fn publish_tree(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    tree: &PublicTree,
) -> Result<PublicTree> {
    let url = relay_request_url(base_url, "/trees")?;
    read_json(transport.send(request(
        "PUT",
        url,
        Some(api_key),
        Some("application/json"),
        json_body(tree)?,
    ))?)
}

/// Fetch the public-tree slice for this pull key's bound fingerprint.
pub fn fetch_tree_context(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    label: &str,
) -> Result<PublicTree> {
    let path = format!("/trees/{}/context", urlencoding_label(label));
    let url = relay_request_url(base_url, &path)?;
    read_json(transport.send(request("GET", url, Some(api_key), None, Vec::new()))?)
}

/// Upload one sealed device letter (`device.push`).
pub fn push_device_package(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    package: &[u8],
) -> Result<InboxAccepted> {
    let url = relay_request_url(base_url, "/devices/packages")?;
    read_json(transport.send(request(
        "POST",
        url,
        Some(api_key),
        Some("application/octet-stream"),
        package.to_vec(),
    ))?)
}

/// Fetch one page of device letters for this pull key's fingerprint.
pub fn pull_device_packages(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<DevicePackageList> {
    let mut url = relay_request_url(base_url, "/devices/packages")?;
    page_query(&mut url, after, limit);
    read_json(transport.send(request("GET", url, Some(api_key), None, Vec::new()))?)
}

/// Publish this device's public descriptor (`device.push`).
pub fn put_device(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    descriptor: &DeviceDescriptor,
) -> Result<DeviceDescriptor> {
    let url = relay_request_url(base_url, "/devices")?;
    read_json(transport.send(request(
        "PUT",
        url,
        Some(api_key),
        Some("application/json"),
        json_body(descriptor)?,
    ))?)
}

/// Read a published public descriptor. `device.push` and `device.pull` both work.
pub fn get_device(
    transport: &dyn RelayTransport,
    base_url: &str,
    api_key: &str,
    device_id: &str,
) -> Result<DeviceDescriptor> {
    let path = format!("/devices/{device_id}");
    let url = relay_request_url(base_url, &path)?;
    read_json(transport.send(request("GET", url, Some(api_key), None, Vec::new()))?)
}

fn urlencoding_label(label: &str) -> String {
    let mut out = String::new();
    for b in label.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
