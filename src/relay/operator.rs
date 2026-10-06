//! The provider's console API: what the operator sees of the relay and the
//! licences and keys the operator issues, voids and replaces.
//!
//! Only the provider's own people reach this. The admin Worker (behind
//! Cloudflare Access) is its only caller, through its binding to the Durable
//! Object; no route on the public Worker leads here, and a client of the
//! provider never sees it. Every request is JSON (`{"op": "...", ...}`) and
//! every answer is JSON.
//!
//! **Reading** (`overview`, `keys`, `licences`, `activity`, `events`,
//! `letters`, `trees`, `checkpoint`) needs only the identity Access verified.
//! **Changing anything** (`issue`, `rotate`, `void_key`, `void_licence`) also
//! needs the operator lock (`kql_…`), presented with that one request: it is
//! checked against the hash the relay holds and is never stored, logged or
//! echoed, and a refused one is recorded. `bootstrap` creates the lock once,
//! on an empty relay, and shows it once; `rotate_lock` replaces it (with the
//! current one in hand) and shows the new one once.
//!
//! What the console can show is what the relay holds: key lifecycle and
//! audit events, which key did what and when, blocked attempts by a known key,
//! the letters in the mailboxes by kind, size and time (never their contents,
//! which are sealed to their recipients), and the public trees' labels and
//! generations. File contents and tracked-file histories are inside sealed
//! letters and are not visible here by design.
//!
//! This module is orchestration: the rules live in [`issuance`],
//! [`licence`], [`key_delivery`], [`activity`] and [`api_key`], and the clock
//! is the store's. Replies carry no bearer and no key hash; an issue returns
//! bundles sealed to the client and nothing else.

use super::activity::MAX_SUMMARY_HOURS;
use super::api_key::{ApiKeyInfo, ApiKeyScope};
use super::issuance::{Issuance, LicenceRef, CLIENT_SCOPES};
use super::licence::{Licence, NewLicence};
use super::store::{ProviderAuthEvent, RelayStore};
use super::ProviderIdentity;
use crate::api_key_delivery::DEVICE_ID_LEN;
use crate::envelope;
use crate::error::Error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

/// The largest console request, in bytes.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// How many rows a feed returns.
const FEED_LIMIT: i64 = 200;

/// Who is asking and what they hold, for one request.
pub struct Context<'a> {
    /// The identity Cloudflare Access verified (an email address).
    pub operator: &'a str,
    /// The operator lock, if this request presents one.
    pub lock: Option<&'a str>,
}

/// An answer: an HTTP status and a JSON body.
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    /// Whether the relay's state changed, so the caller can sign the audit
    /// chain at once.
    pub changed: bool,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Overview {},
    Keys {},
    Licences {},
    Activity {
        hours: Option<i64>,
    },
    Events {},
    Letters {},
    Trees {},
    Checkpoint {},
    Bootstrap {},
    RotateLock {},
    Issue {
        licence_id: Option<i64>,
        client: Option<String>,
        terms: Option<String>,
        expires_at: Option<String>,
        scopes: Vec<String>,
        recipient_public_key: String,
        relay_url: String,
        device_id: Option<String>,
    },
    Rotate {
        key_id: i64,
    },
    VoidKey {
        key_id: i64,
    },
    VoidLicence {
        licence_id: i64,
        reason: Option<String>,
    },
}

fn reply(status: u16, body: Value) -> Reply {
    Reply {
        status,
        body: serde_json::to_vec(&body).unwrap_or_default(),
        changed: false,
    }
}

fn refuse(status: u16, code: &str, message: &str) -> Reply {
    reply(status, json!({ "error": message, "code": code }))
}

/// A failure as the operator is told of it: the relay's own message where it
/// is a statement about the request, a fixed one where it could be a store's.
fn failure(error: &Error) -> Reply {
    match error {
        Error::InvalidLicence
        | Error::InvalidApiKeyRequest
        | Error::InvalidPublicKey
        | Error::InvalidDevice => refuse(400, "invalid", &error.to_string()),
        Error::RelayRequest(_) => refuse(400, "invalid", "the relay URL is not valid"),
        Error::LicenceNotFound | Error::ApiKeyNotFound => {
            refuse(404, "not_found", &error.to_string())
        }
        Error::LicenceNotActive | Error::ApiKeyRevoked | Error::DeliveryRecipientMissing => {
            refuse(409, "conflict", &error.to_string())
        }
        Error::StoreCommitUnknown => refuse(
            500,
            "commit_unknown",
            "the relay could not confirm the write; check the keys list before retrying",
        ),
        _ => refuse(500, "internal", "internal error"),
    }
}

/// Answers one console request. `body` is the JSON request, `ctx` who is
/// asking. `identity` is the relay's own (needed to seal and to sign).
pub fn operate(
    store: &dyn RelayStore,
    identity: Option<&ProviderIdentity>,
    body: &[u8],
    ctx: &Context<'_>,
    now: &str,
) -> Reply {
    if ctx.operator.trim().is_empty() {
        return refuse(401, "no_operator", "no verified operator identity");
    }
    if body.len() > MAX_REQUEST_BYTES {
        return refuse(413, "too_large", "request too large");
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return refuse(400, "invalid", "unrecognised request");
    };
    let Ok(request) = serde_json::from_value::<Request>(value.clone()) else {
        return refuse(400, "invalid", "unrecognised request");
    };
    // `deny_unknown_fields` does not reach an operation with no fields of its
    // own, so those are held to `{"op": ...}` and nothing more.
    let bare = matches!(
        request,
        Request::Overview {}
            | Request::Keys {}
            | Request::Licences {}
            | Request::Events {}
            | Request::Letters {}
            | Request::Trees {}
            | Request::Checkpoint {}
            | Request::Bootstrap {}
            | Request::RotateLock {}
    );
    if bare && value.as_object().is_none_or(|fields| fields.len() != 1) {
        return refuse(400, "invalid", "unrecognised request");
    }
    match run(store, identity, request, ctx, now) {
        Ok(reply) => reply,
        Err(reply) => reply,
    }
}

type Outcome = Result<Reply, Reply>;

fn seen<T>(result: crate::error::Result<T>) -> Result<T, Reply> {
    result.map_err(|e| failure(&e))
}

fn ok(body: Value) -> Outcome {
    Ok(reply(200, body))
}

fn changed(body: Value) -> Outcome {
    let mut answer = reply(200, body);
    answer.changed = true;
    Ok(answer)
}

fn run(
    store: &dyn RelayStore,
    identity: Option<&ProviderIdentity>,
    request: Request,
    ctx: &Context<'_>,
    now: &str,
) -> Outcome {
    match request {
        Request::Overview {} => overview(store, identity.is_some()),
        Request::Keys {} => {
            let view = key_views(store).map_err(|e| failure(&e))?;
            ok(json!({ "keys": view }))
        }
        Request::Licences {} => {
            let licences = seen(store.list_licences())?;
            let links = seen(store.licence_links())?;
            let infos: HashMap<i64, ApiKeyInfo> = seen(store.list_keys())?
                .into_iter()
                .map(|info| (info.id, info))
                .collect();
            let views: Vec<Value> = licences
                .iter()
                .map(|licence| {
                    let keys: Vec<i64> = links
                        .iter()
                        .filter(|(_, l)| *l == licence.id)
                        .map(|(k, _)| *k)
                        .collect();
                    let live = keys
                        .iter()
                        .filter(|k| infos.get(k).is_some_and(|i| i.revoked_at.is_none()))
                        .count();
                    let mut view = licence_view(licence);
                    view["keys"] = json!(keys);
                    view["live_keys"] = json!(live);
                    view
                })
                .collect();
            ok(json!({ "licences": views }))
        }
        Request::Activity { hours } => activity(store, hours.unwrap_or(24)),
        Request::Events {} => {
            let mut key_events = seen(store.key_events(None))?;
            key_events.reverse();
            key_events.truncate(FEED_LIMIT as usize);
            let events: Vec<Value> = key_events
                .iter()
                .map(|e| {
                    json!({ "id": e.id, "key_id": e.key_id, "event": e.event,
                            "actor": e.actor, "related_key_id": e.related_key_id,
                            "occurred_at": e.occurred_at, "entry_hash": e.entry_hash })
                })
                .collect();
            let actions: Vec<Value> = seen(store.operator_actions(FEED_LIMIT))?
                .iter()
                .map(|a| {
                    json!({ "id": a.id, "operator": a.operator, "action": a.action,
                            "subject": a.subject, "success": a.success,
                            "occurred_at": a.occurred_at })
                })
                .collect();
            let auth: Vec<Value> = seen(store.provider_auth_events(FEED_LIMIT))?
                .iter()
                .map(|a| {
                    json!({ "id": a.id, "operation": a.operation, "success": a.success,
                            "attempted_at": a.attempted_at, "entry_hash": a.entry_hash })
                })
                .collect();
            ok(json!({ "key_events": events, "operator_actions": actions, "auth_events": auth }))
        }
        Request::Letters {} => letters(store),
        Request::Trees {} => {
            let trees: Vec<Value> = seen(store.tree_summaries())?
                .iter()
                .map(|t| {
                    json!({ "label": t.label, "generation": t.generation,
                            "updated_at": t.updated_at })
                })
                .collect();
            ok(json!({ "trees": trees }))
        }
        Request::Checkpoint {} => {
            let identity = identity
                .ok_or_else(|| refuse(503, "no_identity", "the relay has no identity configured"))?;
            let checkpoint = seen(store.audit_checkpoint(identity, now))?;
            let bytes = seen(checkpoint.encode())?;
            ok(json!({
                "filename": format!("keyquorum-audit-checkpoint-{}.json", slug(now)),
                "content_base64": STANDARD.encode(bytes),
            }))
        }
        Request::Bootstrap {} => bootstrap(store, identity, ctx),
        Request::RotateLock {} => {
            need_identity(identity)?;
            gate(store, ctx, "rotate_lock", "operator lock")?;
            let rotated = store.rotate_operator_lock();
            audited(store, ctx, "rotate_lock", "operator lock", rotated.is_ok());
            let created = seen(rotated)?;
            changed(json!({ "operator_lock": created.token.as_str() }))
        }
        Request::Issue {
            licence_id,
            client,
            terms,
            expires_at,
            scopes,
            recipient_public_key,
            relay_url,
            device_id,
        } => {
            let subject = licence_id
                .map(|id| format!("licence {id}"))
                .or_else(|| client.clone())
                .unwrap_or_default();
            let identity = need_identity(identity)?;
            let request = build_issuance(
                licence_id,
                client,
                terms,
                expires_at,
                &scopes,
                &recipient_public_key,
                relay_url,
                device_id.as_deref(),
            )
            .map_err(|e| failure(&e))?;
            gate(store, ctx, "issue", &subject)?;
            let issued = store.issue_licensed_bundles(identity, &request);
            audited(store, ctx, "issue", &subject, issued.is_ok());
            let issued = seen(issued)?;
            let bundles: Vec<Value> = issued
                .bundles
                .iter()
                .map(|b| bundle_view(&issued.licence, b))
                .collect();
            changed(json!({ "licence": licence_view(&issued.licence), "bundles": bundles }))
        }
        Request::Rotate { key_id } => {
            let identity = need_identity(identity)?;
            let subject = format!("key {key_id}");
            gate(store, ctx, "rotate", &subject)?;
            let rotated = store.rotate_licensed_key(identity, key_id);
            audited(store, ctx, "rotate", &subject, rotated.is_ok());
            let rotated = seen(rotated)?;
            let link = seen(store.licence_links())?
                .into_iter()
                .find(|(key, _)| *key == rotated.info.id);
            let licences = seen(store.list_licences())?;
            let licence = link.and_then(|(_, id)| licences.into_iter().find(|l| l.id == id));
            changed(json!({
                "replaced_key_id": key_id,
                "bundle": match &licence {
                    Some(licence) => bundle_view(licence, &rotated),
                    None => bundle_view_bare(&rotated),
                },
            }))
        }
        Request::VoidKey { key_id } => {
            let subject = format!("key {key_id}");
            gate(store, ctx, "void_key", &subject)?;
            let result = store.revoke_key_by(key_id, super::api_key::HOST_ACTOR);
            audited(store, ctx, "void_key", &subject, result.is_ok());
            seen(result)?;
            changed(json!({ "key_id": key_id, "revoked": true }))
        }
        Request::VoidLicence {
            licence_id,
            reason,
        } => {
            let subject = format!("licence {licence_id}");
            gate(store, ctx, "void_licence", &subject)?;
            let result = store.void_licence(licence_id, reason.as_deref());
            audited(store, ctx, "void_licence", &subject, result.is_ok());
            let voided = seen(result)?;
            changed(json!({
                "licence_id": licence_id,
                "newly_voided": voided.newly_voided,
                "revoked_keys": voided.revoked_keys,
            }))
        }
    }
}

fn need_identity(identity: Option<&ProviderIdentity>) -> Result<&ProviderIdentity, Reply> {
    identity.ok_or_else(|| refuse(503, "no_identity", "the relay has no identity configured"))
}

/// The operator lock check for a request that changes something. A missing
/// lock is a prompt for the page; a wrong one is recorded as a refused
/// attempt, in the audit chain and under the operator's name.
fn gate(
    store: &dyn RelayStore,
    ctx: &Context<'_>,
    action: &str,
    subject: &str,
) -> Result<(), Reply> {
    let exists = store.operator_lock_exists().map_err(|e| failure(&e))?;
    if !exists {
        return Err(refuse(
            409,
            "no_lock",
            "the operator lock has not been created yet; create it first",
        ));
    }
    let Some(lock) = ctx.lock.filter(|lock| !lock.is_empty()) else {
        return Err(refuse(
            401,
            "lock_required",
            "this action needs the operator lock",
        ));
    };
    let operation = format!("console.{action}");
    let authorised = store.authenticate_licensee(lock).is_ok();
    let _ = store.record_provider_auth_event(&ProviderAuthEvent {
        operation: &operation,
        provider_id: None,
        network_id: None,
        hardware_fingerprints: None,
        success: authorised,
    });
    if !authorised {
        let _ = store.record_operator_action(ctx.operator, action, Some(subject), false);
        return Err(refuse(401, "lock_refused", "the operator lock was refused"));
    }
    Ok(())
}

fn audited(store: &dyn RelayStore, ctx: &Context<'_>, action: &str, subject: &str, success: bool) {
    let _ = store.record_operator_action(ctx.operator, action, Some(subject), success);
}

fn bootstrap(
    store: &dyn RelayStore,
    identity: Option<&ProviderIdentity>,
    ctx: &Context<'_>,
) -> Outcome {
    // As on the native host, the lock is created only on a relay that holds a
    // signed identity.
    need_identity(identity)?;
    let created = store
        .authorize_licensee_or_bootstrap(None)
        .map_err(|e| failure(&e))?;
    let Some(created) = created else {
        return Err(refuse(
            409,
            "lock_exists",
            "the operator lock already exists and cannot be shown again",
        ));
    };
    let _ = store.record_provider_auth_event(&ProviderAuthEvent {
        operation: "console.bootstrap",
        provider_id: None,
        network_id: None,
        hardware_fingerprints: None,
        success: true,
    });
    audited(store, ctx, "bootstrap", "operator lock", true);
    changed(json!({ "operator_lock": created.token.as_str() }))
}

#[allow(clippy::too_many_arguments)]
fn build_issuance(
    licence_id: Option<i64>,
    client: Option<String>,
    terms: Option<String>,
    expires_at: Option<String>,
    scopes: &[String],
    recipient_public_key: &str,
    relay_url: String,
    device_id: Option<&str>,
) -> crate::error::Result<Issuance> {
    let licence = match (licence_id, client) {
        (Some(id), None) if terms.is_none() && expires_at.is_none() => LicenceRef::Existing(id),
        (None, Some(client)) => LicenceRef::New(NewLicence {
            client,
            terms: terms.unwrap_or_default(),
            expires_at,
        }),
        _ => return Err(Error::InvalidLicence),
    };
    let scopes = scopes
        .iter()
        .map(|s| ApiKeyScope::parse(s))
        .collect::<crate::error::Result<Vec<_>>>()?;
    let key: [u8; 32] = hex::decode(recipient_public_key.trim())
        .map_err(|_| Error::InvalidPublicKey)?
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    let device_id = device_id
        .filter(|text| !text.trim().is_empty())
        .map(|text| -> crate::error::Result<[u8; DEVICE_ID_LEN]> {
            hex::decode(text.trim())
                .map_err(|_| Error::InvalidDevice)?
                .try_into()
                .map_err(|_| Error::InvalidDevice)
        })
        .transpose()?;
    Ok(Issuance {
        licence,
        scopes,
        recipient_public_key: key,
        relay_url,
        device_id,
    })
}

fn licence_view(licence: &Licence) -> Value {
    let status = if licence.voided_at.is_some() {
        "voided"
    } else if licence.active {
        "active"
    } else {
        "ended"
    };
    json!({
        "id": licence.id, "client": licence.client, "terms": licence.terms,
        "created_at": licence.created_at, "expires_at": licence.expires_at,
        "voided_at": licence.voided_at, "void_reason": licence.void_reason,
        "status": status,
    })
}

fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
        if out.len() >= 40 {
            break;
        }
    }
    out.trim_end_matches('-').to_string()
}

fn bundle_view(licence: &Licence, issued: &super::issuance::IssuedBundle) -> Value {
    let mut view = bundle_view_bare(issued);
    view["filename"] = json!(format!(
        "{}-{}-{}.kqkey",
        slug(&licence.client),
        issued.info.scope.replace('.', "-"),
        issued.info.id
    ));
    view
}

fn bundle_view_bare(issued: &super::issuance::IssuedBundle) -> Value {
    json!({
        "key_id": issued.info.id,
        "scope": issued.info.scope,
        "expires_at": issued.info.expires_at,
        "recipient_fingerprint": issued.recipient_fingerprint,
        "filename": format!("key-{}.kqkey", issued.info.id),
        "bundle_base64": STANDARD.encode(&issued.bundle),
    })
}

/// Every key with its state, licence and delivery, for the keys page and for
/// the other views that name a client.
fn key_views(store: &dyn RelayStore) -> crate::error::Result<Vec<Value>> {
    let infos = store.list_keys()?;
    let expired = store.expired_key_ids()?;
    let links: HashMap<i64, i64> = store.licence_links()?.into_iter().collect();
    let licences: HashMap<i64, Licence> = store
        .list_licences()?
        .into_iter()
        .map(|l| (l.id, l))
        .collect();
    let deliveries: HashMap<i64, _> = store
        .delivery_records()?
        .into_iter()
        .map(|d| (d.api_key_id, d))
        .collect();
    Ok(infos
        .iter()
        .rev()
        .map(|info| {
            let state = if info.revoked_at.is_some() {
                "revoked"
            } else if expired.contains(&info.id) {
                "expired"
            } else {
                "live"
            };
            let licence = links.get(&info.id).and_then(|id| licences.get(id));
            let delivery = deliveries.get(&info.id);
            json!({
                "id": info.id, "scope": info.scope, "label": info.label,
                "bound_fingerprint": info.recipient_fingerprint,
                "created_at": info.created_at, "expires_at": info.expires_at,
                "revoked_at": info.revoked_at, "last_used_at": info.last_used_at,
                "state": state,
                "licence_id": licence.map(|l| l.id),
                "client": licence.map(|l| l.client.clone()),
                "licence_status": licence.map(|l| licence_view(l)["status"].clone()),
                "delivery": delivery.map(|d| json!({
                    "recipient_fingerprint": d.recipient_fingerprint,
                    "relay_url": d.relay_url, "device_bound": d.device_bound,
                    "via": d.via, "issued_at": d.created_at,
                })),
            })
        })
        .collect())
}

fn overview(store: &dyn RelayStore, identity_configured: bool) -> Outcome {
    let fail = |e: Error| failure(&e);
    let infos = store.list_keys().map_err(fail)?;
    let expired = store.expired_key_ids().map_err(fail)?;
    let licences = store.list_licences().map_err(fail)?;
    let (inbox_total, _) = store.inbox_letters(1).map_err(fail)?;
    let (device_total, _) = store.device_letters(1).map_err(fail)?;
    let trees = store.tree_summaries().map_err(fail)?;
    let summary = store.access_summary(24).map_err(fail)?;
    let revoked = infos.iter().filter(|i| i.revoked_at.is_some()).count();
    let expired_live = infos
        .iter()
        .filter(|i| i.revoked_at.is_none() && expired.contains(&i.id))
        .count();
    let (mut served, mut blocked) = (0i64, 0i64);
    for hour in &summary.by_hour {
        if hour.outcome == "ok" {
            served += hour.count;
        } else {
            blocked += hour.count;
        }
    }
    let voided = licences.iter().filter(|l| l.voided_at.is_some()).count();
    let active = licences.iter().filter(|l| l.active).count();
    ok(json!({
        "operator_lock": store.operator_lock_exists().map_err(fail)?,
        "identity_configured": identity_configured,
        "keys": { "live": infos.len() - revoked - expired_live, "revoked": revoked,
                  "expired": expired_live },
        "licences": { "active": active, "voided": voided,
                      "ended": licences.len() - active - voided },
        "letters": { "inbox": inbox_total, "devices": device_total },
        "trees": trees.len(),
        "last_24h": { "served": served, "blocked": blocked },
        "client_scopes": CLIENT_SCOPES.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    }))
}

fn activity(store: &dyn RelayStore, hours: i64) -> Outcome {
    let fail = |e: Error| failure(&e);
    let summary = store
        .access_summary(hours.clamp(1, MAX_SUMMARY_HOURS))
        .map_err(fail)?;
    let keys = key_views(store).map_err(fail)?;
    let by_id: HashMap<i64, &Value> = keys
        .iter()
        .filter_map(|k| Some((k["id"].as_i64()?, k)))
        .collect();
    let by_key: Vec<Value> = summary
        .by_key
        .iter()
        .map(|a| {
            let key = by_id.get(&a.api_key_id);
            json!({
                "key_id": a.api_key_id, "scope": key.map(|k| k["scope"].clone()),
                "client": key.map(|k| k["client"].clone()),
                "route": a.route, "outcome": a.outcome, "count": a.count,
                "last_hour": a.last_hour,
            })
        })
        .collect();
    // One row per client: what its keys did, and when one last did anything.
    let mut clients: HashMap<String, Value> = HashMap::new();
    for key in &keys {
        let name = key["client"].as_str().unwrap_or("(no licence)").to_string();
        let row = clients.entry(name.clone()).or_insert_with(|| {
            json!({ "client": name, "keys": 0, "live_keys": 0, "last_used_at": null,
                    "ok": 0, "revoked": 0, "expired": 0, "scope": 0 })
        });
        row["keys"] = json!(row["keys"].as_i64().unwrap_or(0) + 1);
        if key["state"] == "live" {
            row["live_keys"] = json!(row["live_keys"].as_i64().unwrap_or(0) + 1);
        }
        let used = key["last_used_at"].as_str();
        if used > row["last_used_at"].as_str() {
            row["last_used_at"] = json!(used);
        }
    }
    for a in &summary.by_key {
        let name = by_id
            .get(&a.api_key_id)
            .and_then(|k| k["client"].as_str())
            .unwrap_or("(no licence)")
            .to_string();
        if let Some(row) = clients.get_mut(&name) {
            row[a.outcome.as_str()] = json!(row[a.outcome.as_str()].as_i64().unwrap_or(0) + a.count);
        }
    }
    let mut clients: Vec<Value> = clients.into_values().collect();
    clients.sort_by(|a, b| a["client"].as_str().cmp(&b["client"].as_str()));
    let by_hour: Vec<Value> = summary
        .by_hour
        .iter()
        .map(|h| json!({ "hour": h.hour, "outcome": h.outcome, "count": h.count }))
        .collect();
    ok(json!({
        "hours": summary.hours, "clients": clients, "by_key": by_key, "by_hour": by_hour,
    }))
}

fn kind_name(kind: Option<u8>) -> &'static str {
    match kind {
        Some(envelope::KIND_INVITE) => "bridge invite",
        Some(envelope::KIND_ROTATE) => "bridge rotation",
        Some(envelope::KIND_DESTROY) => "bridge destroy",
        Some(envelope::KIND_SUPERVISOR) => "supervisor",
        Some(envelope::KIND_KEY_REISSUE) => "key reissue",
        Some(envelope::KIND_TREE_UPDATE) => "tree update",
        Some(envelope::KIND_TREE_PROPOSAL) => "tree proposal",
        Some(envelope::KIND_COUNTERSIGNED_TREE) => "countersigned tree",
        Some(envelope::KIND_DEVICE_TRANSFER) => "device transfer",
        Some(envelope::KIND_DEVICE_TRANSFER_ACK) => "device transfer ack",
        Some(envelope::KIND_DEVICE_RELOCATE) => "device relocate",
        Some(envelope::KIND_DEVICE_RELOCATE_ACK) => "device relocate ack",
        Some(envelope::KIND_FILE_DELIVERY) => "file delivery",
        Some(envelope::KIND_FILE_DELIVERY_ACK) => "file delivery answer",
        Some(envelope::KIND_FILE_HISTORY) => "tracked file",
        Some(envelope::KIND_FILE_HISTORY_ACK) => "tracked file answer",
        Some(envelope::KIND_FILE_HISTORY_SNAPSHOT) => "history snapshot",
        Some(envelope::KIND_FILE_REQUEST) => "file request",
        Some(envelope::KIND_FILE_REQUEST_ANSWER) => "file request answer",
        Some(envelope::KIND_API_KEY_ISSUE) => "api key issue",
        _ => "unknown",
    }
}

fn letters(store: &dyn RelayStore) -> Outcome {
    let fail = |e: Error| failure(&e);
    // Name the client a letter is for, by the key bound to its recipient.
    let keys = key_views(store).map_err(fail)?;
    let mut owners: HashMap<String, String> = HashMap::new();
    for key in &keys {
        if let (Some(fp), Some(client)) = (key["bound_fingerprint"].as_str(), key["client"].as_str())
        {
            owners.insert(fp.to_string(), client.to_string());
        }
    }
    let view = |letters: Vec<super::LetterSummary>| -> Vec<Value> {
        letters
            .into_iter()
            .map(|l| {
                json!({
                    "id": l.id,
                    "recipient_fingerprint": l.recipient_fingerprint,
                    "client": owners.get(&l.recipient_fingerprint),
                    "kind": l.kind, "kind_name": kind_name(l.kind), "size": l.size,
                    "stored_at": l.created_at, "expires_at": l.expires_at,
                })
            })
            .collect()
    };
    let (inbox_total, inbox) = store.inbox_letters(FEED_LIMIT).map_err(fail)?;
    let (device_total, devices) = store.device_letters(FEED_LIMIT).map_err(fail)?;
    ok(json!({
        "inbox": { "total": inbox_total, "newest": view(inbox) },
        "devices": { "total": device_total, "newest": view(devices) },
    }))
}

#[cfg(test)]
#[path = "operator/tests.rs"]
mod tests;
