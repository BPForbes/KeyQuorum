//! The provider's console API: what the operator sees of the relay and the
//! customers, licences and keys the operator manages.
//!
//! Only the provider's own people reach this. The admin Worker (behind
//! Cloudflare Access) is its only caller, through its private binding to the
//! Durable Object; no route on the public Worker leads here, and a client of
//! the provider never sees it. Every request is JSON (`{"op": "...", ...}`) and
//! every answer is JSON.
//!
//! **Reading** (`overview`, `users`, `user`, `keys`, `activity`, `audit`,
//! `letters`, `trees`, `checkpoint`, `status`) needs only the identity Access
//! verified. **Changing anything** (`create_customer`, `create_licence`, `issue`,
//! `renew_licence`, `void_licence`, `rotate`, `void_key`, `assign_key`) also
//! needs the operator lock (`kql_…`), presented with that one request, and an
//! operation id. The lock is checked against the hash the relay holds and is
//! never stored, logged or echoed; a refused one is recorded. The operation id
//! is the recovery contract: it is written in the same unit of work as the
//! change, so a lost response is reconciled by sending the same id again, which
//! is told the change is done and what ids it made, and never makes it twice.
//! Sealed bundles are not retained: a lost download is replaced by replacing
//! the key.
//!
//! The lock itself is made in two steps, so a lost response cannot lock the
//! provider out: `bootstrap` (on a relay with no lock) or `rotate_lock` (with
//! the current one) stages a new lock and shows it once, and `confirm_lock`,
//! presenting it back, makes it the lock. Until then the previous lock (or
//! none) stands.
//!
//! What the console can show is what the relay holds: customers, licences and
//! their statement versions, keys and what they did, blocked attempts by a
//! known key, the letters in the mailboxes by kind, size and time (never their
//! contents, which are sealed to their recipients), and the public trees'
//! labels and generations. File contents and tracked-file histories are inside
//! sealed letters and are not visible here by design.
//!
//! This module is orchestration: the rules live in [`issuance`], [`customer`],
//! [`licence`], [`key_delivery`], [`activity`] and [`api_key`], and the clock is
//! the store's. Replies carry no bearer and no key hash; an issue returns
//! bundles sealed to the client and nothing else.

use super::activity::{self, Filter, Outcome, Route, MAX_SUMMARY_HOURS};
use super::api_key::{ApiKeyInfo, ApiKeyScope};
use super::customer::{Customer, LicenceFilter, NewCustomer};
use super::issuance::{
    CustomerRef, Issuance, LicenceRef, RotateVia, CLIENT_SCOPES, MAX_GRACE_SECONDS,
};
use super::licence::{KeyLink, Licence, NewLicence};
use super::operator_log::{valid_operation_id, Note, OperatorAction};
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

/// How many rows a feed returns by default, and at most.
const FEED_DEFAULT: i64 = 50;
const FEED_MAX: i64 = 200;

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
    Status {},
    Users {
        search: Option<String>,
        status: Option<String>,
        before: Option<i64>,
        limit: Option<i64>,
    },
    User {
        id: i64,
    },
    Keys {
        customer_id: Option<i64>,
        state: Option<String>,
        assignment: Option<String>,
        before: Option<i64>,
        limit: Option<i64>,
    },
    Activity {
        hours: Option<i64>,
        customer_id: Option<i64>,
        key_id: Option<i64>,
        route: Option<String>,
        outcome: Option<String>,
    },
    Audit {
        feed: String,
        before: Option<i64>,
        limit: Option<i64>,
    },
    Letters {},
    Trees {},
    Checkpoint {},
    Bootstrap {},
    RotateLock {},
    ConfirmLock {},
    CreateCustomer {
        operation_id: Option<String>,
        name: String,
        reference: Option<String>,
    },
    Issue {
        operation_id: Option<String>,
        customer_id: Option<i64>,
        name: Option<String>,
        reference: Option<String>,
        licence_id: Option<i64>,
        terms: Option<String>,
        expires_at: Option<String>,
        replaces_licence_id: Option<i64>,
        scopes: Vec<String>,
        recipient_public_key: String,
        relay_url: String,
        device_id: Option<String>,
    },
    CreateLicence {
        operation_id: Option<String>,
        customer_id: i64,
        terms: Option<String>,
        expires_at: Option<String>,
        replaces_licence_id: Option<i64>,
    },
    RenewLicence {
        operation_id: Option<String>,
        licence_id: i64,
        terms: Option<String>,
        expires_at: Option<String>,
    },
    VoidLicence {
        operation_id: Option<String>,
        licence_id: i64,
        reason: Option<String>,
    },
    Rotate {
        operation_id: Option<String>,
        key_id: i64,
        via: Option<String>,
        grace_seconds: Option<i64>,
    },
    VoidKey {
        operation_id: Option<String>,
        key_id: i64,
    },
    AssignKey {
        operation_id: Option<String>,
        key_id: i64,
        licence_id: i64,
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

/// A failure as the operator is told of it: the relay's own wording where it
/// is a statement about the request, a fixed one where it could be a store's.
fn failure(error: &Error) -> Reply {
    match error {
        Error::InvalidLicence
        | Error::InvalidApiKeyRequest
        | Error::InvalidPublicKey
        | Error::InvalidDevice => refuse(400, "invalid", &error.to_string()),
        Error::RelayRequest(_) => refuse(400, "invalid", "the relay URL is not valid"),
        Error::LicenceNotFound | Error::CustomerNotFound | Error::ApiKeyNotFound => {
            refuse(404, "not_found", &error.to_string())
        }
        Error::LicenceNotActive
        | Error::ApiKeyRevoked
        | Error::DeliveryRecipientMissing
        | Error::DeliveryNotCollectable
        | Error::KeyNotAssigned => refuse(409, "conflict", &error.to_string()),
        Error::StoreCommitUnknown => refuse(
            500,
            "commit_unknown",
            "the relay could not confirm the write; send the same operation id again to find out",
        ),
        _ => refuse(500, "internal", "internal error"),
    }
}

fn seen<T>(result: crate::error::Result<T>) -> Result<T, Reply> {
    result.map_err(|e| failure(&e))
}

type Outcome2 = Result<Reply, Reply>;

fn ok(body: Value) -> Outcome2 {
    Ok(reply(200, body))
}

fn changed(body: Value) -> Outcome2 {
    let mut answer = reply(200, body);
    answer.changed = true;
    Ok(answer)
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
            | Request::Status {}
            | Request::Letters {}
            | Request::Trees {}
            | Request::Checkpoint {}
            | Request::Bootstrap {}
            | Request::RotateLock {}
            | Request::ConfirmLock {}
    );
    if bare && value.as_object().is_none_or(|fields| fields.len() != 1) {
        return refuse(400, "invalid", "unrecognised request");
    }
    match run(store, identity, request, ctx, now) {
        Ok(reply) => reply,
        Err(reply) => reply,
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
    if !seen(store.operator_lock_exists())? {
        return Err(if seen(store.operator_lock_pending())? {
            refuse(
                409,
                "lock_unconfirmed",
                "the operator lock was created but not confirmed; enter it on the Overview page to confirm it",
            )
        } else {
            refuse(
                409,
                "no_lock",
                "the operator lock has not been created yet; create it first",
            )
        });
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

/// A change to the relay, from the lock check to its record. The operation id
/// is required and must be new: a repeat of one that went through is answered
/// with what it made, never done again. `run` makes the change and writes the
/// note inside its own transaction.
fn change<T>(
    store: &dyn RelayStore,
    ctx: &Context<'_>,
    action: &str,
    subject: &str,
    operation_id: Option<&str>,
    run: impl FnOnce(&Note<'_>) -> crate::error::Result<T>,
) -> Result<T, Reply> {
    let Some(operation_id) = operation_id.filter(|id| valid_operation_id(id)) else {
        return Err(refuse(
            400,
            "operation_id_required",
            "send an operation id (8 to 64 letters, digits, - or _) so a lost response can be reconciled",
        ));
    };
    gate(store, ctx, action, subject)?;
    if let Some(done) = seen(store.find_operation(operation_id))? {
        return Err(already_done(&done));
    }
    let note = Note {
        operation_id: Some(operation_id),
        operator: ctx.operator,
        action,
        subject,
    };
    match run(&note) {
        Ok(value) => Ok(value),
        Err(error) => {
            let _ = store.record_operator_action(ctx.operator, action, Some(subject), false);
            Err(failure(&error))
        }
    }
}

/// The answer to an operation id that already went through.
fn already_done(done: &OperatorAction) -> Reply {
    let result: Value = done
        .result
        .as_deref()
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null);
    reply(
        409,
        json!({
            "error": "this operation was already done; it was not repeated. Sealed files are not kept: replace a key to get a new one",
            "code": "already_done",
            "operation": {
                "operation_id": done.operation_id,
                "action": done.action,
                "operator": done.operator,
                "occurred_at": done.occurred_at,
                "result": result,
            },
        }),
    )
}

fn run(
    store: &dyn RelayStore,
    identity: Option<&ProviderIdentity>,
    request: Request,
    ctx: &Context<'_>,
    now: &str,
) -> Outcome2 {
    match request {
        Request::Overview {} => overview(store, identity.is_some()),
        Request::Status {} => status(store, identity),
        Request::Users {
            search,
            status,
            before,
            limit,
        } => users(store, search.as_deref(), status.as_deref(), before, limit),
        Request::User { id } => user(store, id),
        Request::Keys {
            customer_id,
            state,
            assignment,
            before,
            limit,
        } => keys_page(
            store,
            customer_id,
            state.as_deref(),
            assignment.as_deref(),
            before,
            limit,
        ),
        Request::Activity {
            hours,
            customer_id,
            key_id,
            route,
            outcome,
        } => activity_view(
            store,
            hours.unwrap_or(24),
            customer_id,
            key_id,
            route.as_deref(),
            outcome.as_deref(),
        ),
        Request::Audit {
            feed,
            before,
            limit,
        } => audit(store, &feed, before, limit),
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
            let identity = need_identity(identity)?;
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
            let staged = store.stage_operator_lock();
            let _ = store.record_operator_action(
                ctx.operator,
                "rotate_lock",
                Some("operator lock"),
                staged.is_ok(),
            );
            let created = seen(staged)?;
            changed(json!({ "operator_lock": created.token.as_str(), "pending": true }))
        }
        Request::ConfirmLock {} => confirm_lock(store, ctx),
        Request::CreateCustomer {
            operation_id,
            name,
            reference,
        } => {
            let new = NewCustomer { name, reference };
            let made = change(store, ctx, "create_customer", &new.name.clone(), operation_id.as_deref(), |note| {
                store.create_customer(&new, Some(note))
            })?;
            changed(json!({ "customer": customer_view(&made) }))
        }
        Request::Issue {
            operation_id,
            customer_id,
            name,
            reference,
            licence_id,
            terms,
            expires_at,
            replaces_licence_id,
            scopes,
            recipient_public_key,
            relay_url,
            device_id,
        } => {
            let subject = match (customer_id, &name) {
                (Some(id), _) => format!("customer {id}"),
                (None, Some(name)) => name.clone(),
                (None, None) => String::new(),
            };
            let identity = need_identity(identity)?;
            let request = build_issuance(
                customer_id,
                name,
                reference,
                licence_id,
                terms,
                expires_at,
                replaces_licence_id,
                &scopes,
                &recipient_public_key,
                relay_url,
                device_id.as_deref(),
            )
            .map_err(|e| failure(&e))?;
            let issued = change(store, ctx, "issue", &subject, operation_id.as_deref(), |note| {
                store.issue_licensed_bundles(identity, &request, Some(note))
            })?;
            let bundles: Vec<Value> = issued
                .bundles
                .iter()
                .map(|b| bundle_view(&issued.customer, &b.info, &b.recipient_fingerprint, &b.bundle))
                .collect();
            changed(json!({
                "customer": customer_view(&issued.customer),
                "licence": licence_summary(&issued.licence),
                "bundles": bundles,
                "voided_licence_id": issued.voided.as_ref().map(|v| v.licence_id),
            }))
        }
        Request::CreateLicence {
            operation_id,
            customer_id,
            terms,
            expires_at,
            replaces_licence_id,
        } => {
            let subject = format!("customer {customer_id}");
            let new = NewLicence {
                terms: terms.unwrap_or_default(),
                expires_at,
                replaces: replaces_licence_id,
            };
            let (made, voided) = change(store, ctx, "create_licence", &subject, operation_id.as_deref(), |note| {
                store.create_licence(customer_id, &new, Some(note))
            })?;
            changed(json!({
                "licence": licence_summary(&made),
                "voided_licence_id": voided.as_ref().map(|v| v.licence_id),
            }))
        }
        Request::RenewLicence {
            operation_id,
            licence_id,
            terms,
            expires_at,
        } => {
            let subject = format!("licence {licence_id}");
            let renewed = change(store, ctx, "renew_licence", &subject, operation_id.as_deref(), |note| {
                store.renew_licence(licence_id, terms.as_deref(), expires_at.as_deref(), Some(note))
            })?;
            changed(json!({
                "licence": licence_summary(&renewed),
                "note": "Keys already issued keep the end they were issued with. Replace them to give each the new end and the new statement.",
            }))
        }
        Request::VoidLicence {
            operation_id,
            licence_id,
            reason,
        } => {
            let subject = format!("licence {licence_id}");
            let voided = change(store, ctx, "void_licence", &subject, operation_id.as_deref(), |note| {
                store.void_licence(licence_id, reason.as_deref(), Some(note))
            })?;
            changed(json!({
                "licence_id": licence_id,
                "newly_voided": voided.newly_voided,
                "revoked_keys": voided.revoked_keys,
            }))
        }
        Request::Rotate {
            operation_id,
            key_id,
            via,
            grace_seconds,
        } => {
            let identity = need_identity(identity)?;
            let via = match (via.as_deref().unwrap_or("bundle"), grace_seconds) {
                ("bundle", None) => RotateVia::Bundle,
                ("letter", grace) => RotateVia::Letter {
                    grace_seconds: grace.unwrap_or(86_400),
                },
                _ => return Err(failure(&Error::InvalidApiKeyRequest)),
            };
            let subject = format!("key {key_id}");
            let rotated = change(store, ctx, "rotate", &subject, operation_id.as_deref(), |note| {
                store.rotate_licensed_key(identity, key_id, via, Some(note))
            })?;
            let customer = licence_customer(store, rotated.licence_id);
            let mut out = json!({
                "replaced_key_id": key_id,
                "key_id": rotated.info.id,
                "licence_id": rotated.licence_id,
                "delivery": if rotated.bundle.is_some() { "bundle" } else { "letter" },
            });
            if let Some(bundle) = &rotated.bundle {
                out["bundle"] = match &customer {
                    Some(customer) => {
                        bundle_view(customer, &rotated.info, &rotated.recipient_fingerprint, bundle)
                    }
                    None => json!({ "key_id": rotated.info.id }),
                };
            }
            if let Some((letter_id, until)) = &rotated.letter {
                out["letter"] = json!({
                    "letter_id": letter_id,
                    "old_key_ends": until,
                    "note": "The old key stays usable until then so the customer can collect the sealed letter with the next `keyquorum inbox open`.",
                });
            }
            changed(out)
        }
        Request::VoidKey { operation_id, key_id } => {
            let subject = format!("key {key_id}");
            change(store, ctx, "void_key", &subject, operation_id.as_deref(), |note| {
                store.revoke_key_noted(key_id, Some(note))
            })?;
            changed(json!({ "key_id": key_id, "revoked": true }))
        }
        Request::AssignKey {
            operation_id,
            key_id,
            licence_id,
        } => {
            let subject = format!("key {key_id}");
            change(store, ctx, "assign_key", &subject, operation_id.as_deref(), |note| {
                store.assign_key(key_id, licence_id, Some(note))
            })?;
            changed(json!({ "key_id": key_id, "licence_id": licence_id }))
        }
    }
}

fn licence_customer(store: &dyn RelayStore, licence_id: i64) -> Option<Customer> {
    let licence = store.get_licence(licence_id).ok()?;
    store.get_customer(licence.customer_id).ok()
}

fn confirm_lock(store: &dyn RelayStore, ctx: &Context<'_>) -> Outcome2 {
    let Some(lock) = ctx.lock.filter(|lock| !lock.is_empty()) else {
        return Err(refuse(
            401,
            "lock_required",
            "enter the new operator lock to confirm it",
        ));
    };
    let confirmed = store.confirm_operator_lock(lock);
    let _ = store.record_provider_auth_event(&ProviderAuthEvent {
        operation: "console.confirm_lock",
        provider_id: None,
        network_id: None,
        hardware_fingerprints: None,
        success: confirmed.is_ok(),
    });
    let _ = store.record_operator_action(
        ctx.operator,
        "confirm_lock",
        Some("operator lock"),
        confirmed.is_ok(),
    );
    match confirmed {
        Ok(()) => changed(json!({ "confirmed": true })),
        Err(Error::InvalidLicenseeKey) => Err(refuse(
            401,
            "lock_refused",
            "that is not the new operator lock, or none is waiting to be confirmed",
        )),
        Err(error) => Err(failure(&error)),
    }
}

fn bootstrap(
    store: &dyn RelayStore,
    identity: Option<&ProviderIdentity>,
    ctx: &Context<'_>,
) -> Outcome2 {
    // As on the native host, the lock is made only on a relay that holds a
    // signed identity, and only by an operator who asks for it here.
    need_identity(identity)?;
    if seen(store.operator_lock_exists())? {
        return Err(refuse(
            409,
            "lock_exists",
            "the operator lock already exists; replace it with the current one instead",
        ));
    }
    let staged = seen(store.stage_operator_lock())?;
    let _ = store.record_provider_auth_event(&ProviderAuthEvent {
        operation: "console.bootstrap",
        provider_id: None,
        network_id: None,
        hardware_fingerprints: None,
        success: true,
    });
    let _ = store.record_operator_action(ctx.operator, "bootstrap", Some("operator lock"), true);
    changed(json!({ "operator_lock": staged.token.as_str(), "pending": true }))
}

#[allow(clippy::too_many_arguments)]
fn build_issuance(
    customer_id: Option<i64>,
    name: Option<String>,
    reference: Option<String>,
    licence_id: Option<i64>,
    terms: Option<String>,
    expires_at: Option<String>,
    replaces_licence_id: Option<i64>,
    scopes: &[String],
    recipient_public_key: &str,
    relay_url: String,
    device_id: Option<&str>,
) -> crate::error::Result<Issuance> {
    let customer = match (customer_id, name) {
        (Some(id), None) if reference.is_none() => CustomerRef::Existing(id),
        (None, Some(name)) => CustomerRef::New(NewCustomer { name, reference }),
        _ => return Err(Error::InvalidLicence),
    };
    let licence = match licence_id {
        Some(id) if terms.is_none() && expires_at.is_none() && replaces_licence_id.is_none() => {
            LicenceRef::Existing(id)
        }
        Some(_) => return Err(Error::InvalidLicence),
        None => LicenceRef::New(NewLicence {
            terms: terms.unwrap_or_default(),
            expires_at,
            replaces: replaces_licence_id,
        }),
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
        customer,
        licence,
        scopes,
        recipient_public_key: key,
        relay_url,
        device_id,
    })
}

fn customer_view(customer: &Customer) -> Value {
    json!({
        "id": customer.id, "name": customer.name, "reference": customer.reference,
        "created_at": customer.created_at,
    })
}

fn licence_status(licence: &Licence) -> &'static str {
    if licence.voided_at.is_some() {
        "voided"
    } else if licence.active {
        "active"
    } else {
        "ended"
    }
}

fn licence_summary(licence: &Licence) -> Value {
    json!({
        "id": licence.id, "customer_id": licence.customer_id,
        "status": licence_status(licence), "created_at": licence.created_at,
        "expires_at": licence.expires_at, "voided_at": licence.voided_at,
        "void_reason": licence.void_reason,
        "replaces_licence_id": licence.replaces_licence_id,
        "version": licence.version, "terms": licence.terms,
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

fn bundle_view(customer: &Customer, info: &ApiKeyInfo, fingerprint: &str, bundle: &[u8]) -> Value {
    json!({
        "key_id": info.id,
        "scope": info.scope,
        "expires_at": info.expires_at,
        "recipient_fingerprint": fingerprint,
        "filename": format!("{}-{}-{}.kqkey", slug(&customer.name), info.scope.replace('.', "-"), info.id),
        "bundle_base64": STANDARD.encode(bundle),
    })
}

/// Everything the key views need, read once.
struct Directory {
    infos: Vec<ApiKeyInfo>,
    expired: std::collections::HashSet<i64>,
    links: HashMap<i64, KeyLink>,
    licences: HashMap<i64, Licence>,
    customers: HashMap<i64, Customer>,
    deliveries: HashMap<i64, super::key_delivery::DeliveryRecord>,
}

fn directory(store: &dyn RelayStore) -> crate::error::Result<Directory> {
    let infos = store.list_keys()?;
    let expired = store.expired_key_ids()?;
    let links: HashMap<i64, KeyLink> = store
        .key_links()?
        .into_iter()
        .map(|l| (l.api_key_id, l))
        .collect();
    let mut licences = HashMap::new();
    let mut customers = HashMap::new();
    for link in links.values() {
        if let std::collections::hash_map::Entry::Vacant(slot) = licences.entry(link.licence_id) {
            let licence = store.get_licence(link.licence_id)?;
            if let std::collections::hash_map::Entry::Vacant(c) = customers.entry(licence.customer_id) {
                c.insert(store.get_customer(licence.customer_id)?);
            }
            slot.insert(licence);
        }
    }
    let deliveries = store
        .delivery_records()?
        .into_iter()
        .map(|d| (d.api_key_id, d))
        .collect();
    Ok(Directory {
        infos,
        expired,
        links,
        licences,
        customers,
        deliveries,
    })
}

impl Directory {
    fn state(&self, info: &ApiKeyInfo) -> &'static str {
        if info.revoked_at.is_some() {
            "revoked"
        } else if self.expired.contains(&info.id) {
            "expired"
        } else {
            "live"
        }
    }

    fn customer_of(&self, key_id: i64) -> Option<&Customer> {
        let link = self.links.get(&key_id)?;
        let licence = self.licences.get(&link.licence_id)?;
        self.customers.get(&licence.customer_id)
    }

    fn view(&self, info: &ApiKeyInfo) -> Value {
        let link = self.links.get(&info.id);
        let licence = link.and_then(|l| self.licences.get(&l.licence_id));
        let customer = self.customer_of(info.id);
        let delivery = self.deliveries.get(&info.id);
        json!({
            "id": info.id, "scope": info.scope, "label": info.label,
            "bound_fingerprint": info.recipient_fingerprint,
            "created_at": info.created_at, "expires_at": info.expires_at,
            "revoked_at": info.revoked_at, "last_used_at": info.last_used_at,
            "state": self.state(info),
            "assigned": link.is_some(),
            "customer_id": customer.map(|c| c.id),
            "customer": customer.map(|c| c.name.clone()),
            "licence_id": link.map(|l| l.licence_id),
            "licence_version": link.and_then(|l| l.licence_version),
            "licence_status": licence.map(licence_status),
            "replaces_key_id": link.and_then(|l| l.replaces_key_id),
            "delivery": delivery.map(|d| json!({
                "recipient_fingerprint": d.recipient_fingerprint,
                "relay_url": d.relay_url, "device_bound": d.device_bound,
                "via": d.via, "issued_at": d.created_at,
            })),
        })
    }
}

fn page_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(FEED_DEFAULT).clamp(1, FEED_MAX)
}

fn users(
    store: &dyn RelayStore,
    search: Option<&str>,
    status: Option<&str>,
    before: Option<i64>,
    limit: Option<i64>,
) -> Outcome2 {
    let filter = match status {
        None => LicenceFilter::All,
        Some(text) => seen(LicenceFilter::parse(text))?,
    };
    let page = seen(store.list_customers(search, filter, before, limit))?;
    let rows: Vec<Value> = page
        .items
        .iter()
        .map(|row| {
            let mut view = customer_view(&row.customer);
            view["licences"] = json!(row.licences);
            view["active_licences"] = json!(row.active_licences);
            view["live_keys"] = json!(row.live_keys);
            view["last_used_at"] = json!(row.last_used_at);
            view
        })
        .collect();
    ok(json!({ "users": rows, "next_before": page.next_before }))
}

fn user(store: &dyn RelayStore, id: i64) -> Outcome2 {
    let customer = seen(store.get_customer(id))?;
    let directory = seen(directory(store))?;
    let licences = seen(store.licences_of(id))?;
    let mut views = Vec::new();
    for licence in &licences {
        let versions: Vec<Value> = seen(store.licence_versions(licence.id))?
            .iter()
            .map(|v| {
                json!({ "version": v.version, "terms": v.terms, "expires_at": v.expires_at,
                        "issued_at": v.issued_at })
            })
            .collect();
        let key_ids: Vec<i64> = directory
            .links
            .values()
            .filter(|l| l.licence_id == licence.id)
            .map(|l| l.api_key_id)
            .collect();
        let live = directory
            .infos
            .iter()
            .filter(|i| key_ids.contains(&i.id) && directory.state(i) == "live")
            .count();
        let mut view = licence_summary(licence);
        view["versions"] = json!(versions);
        view["key_ids"] = json!(key_ids);
        view["live_keys"] = json!(live);
        views.push(view);
    }
    let keys: Vec<Value> = directory
        .infos
        .iter()
        .rev()
        .filter(|info| directory.customer_of(info.id).is_some_and(|c| c.id == id))
        .map(|info| directory.view(info))
        .collect();
    ok(json!({ "customer": customer_view(&customer), "licences": views, "keys": keys }))
}

fn keys_page(
    store: &dyn RelayStore,
    customer_id: Option<i64>,
    state: Option<&str>,
    assignment: Option<&str>,
    before: Option<i64>,
    limit: Option<i64>,
) -> Outcome2 {
    if !matches!(state, None | Some("all" | "live" | "revoked" | "expired"))
        || !matches!(assignment, None | Some("all" | "unassigned"))
    {
        return Err(failure(&Error::InvalidApiKeyRequest));
    }
    let directory = seen(directory(store))?;
    let limit = page_limit(limit) as usize;
    let mut rows: Vec<&ApiKeyInfo> = directory
        .infos
        .iter()
        .rev()
        .filter(|info| before.is_none_or(|b| info.id < b))
        .filter(|info| match state {
            None | Some("all") => true,
            Some(wanted) => directory.state(info) == wanted,
        })
        .filter(|info| match customer_id {
            None => true,
            Some(id) => directory.customer_of(info.id).is_some_and(|c| c.id == id),
        })
        .filter(|info| assignment != Some("unassigned") || !directory.links.contains_key(&info.id))
        .take(limit + 1)
        .collect();
    let next_before = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|info| info.id)
    } else {
        None
    };
    let keys: Vec<Value> = rows.iter().map(|info| directory.view(info)).collect();
    ok(json!({ "keys": keys, "next_before": next_before }))
}

fn overview(store: &dyn RelayStore, identity_configured: bool) -> Outcome2 {
    let infos = seen(store.list_keys())?;
    let expired = seen(store.expired_key_ids())?;
    let links = seen(store.key_links())?;
    let licences = seen(store.licence_counts())?;
    let (inbox_total, _) = seen(store.inbox_letters(1))?;
    let (device_total, _) = seen(store.device_letters(1))?;
    let trees = seen(store.tree_summaries())?;
    let summary = seen(store.access_summary(&Filter {
        hours: 24,
        ..Filter::default()
    }))?;
    let revoked = infos.iter().filter(|i| i.revoked_at.is_some()).count();
    let expired_live = infos
        .iter()
        .filter(|i| i.revoked_at.is_none() && expired.contains(&i.id))
        .count();
    let (mut served, mut blocked) = (0i64, 0i64);
    for hour in &summary.by_hour {
        if Outcome::parse(&hour.outcome).is_some_and(Outcome::is_blocked) {
            blocked += hour.count;
        } else if hour.outcome == "ok" {
            served += hour.count;
        }
    }
    let assigned = links.len();
    ok(json!({
        "operator_lock": seen(store.operator_lock_exists())?,
        "operator_lock_pending": seen(store.operator_lock_pending())?,
        "identity_configured": identity_configured,
        "customers": seen(store.customer_count())?,
        "keys": { "live": infos.len() - revoked - expired_live, "revoked": revoked,
                  "expired": expired_live, "unassigned": infos.len().saturating_sub(assigned) },
        "licences": { "active": licences.active, "voided": licences.voided,
                      "ended": licences.ended },
        "letters": { "inbox": inbox_total, "devices": device_total },
        "trees": trees.len(),
        "last_24h": { "served": served, "blocked": blocked },
        "client_scopes": CLIENT_SCOPES.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "max_grace_seconds": MAX_GRACE_SECONDS,
    }))
}

/// What the relay core knows of itself. The Durable Object adds what only it
/// can see (storage use, the alarm, overload, the deployment).
fn status(store: &dyn RelayStore, identity: Option<&ProviderIdentity>) -> Outcome2 {
    let identity_view = match identity {
        None => json!({ "configured": false }),
        Some(identity) => match crate::provider::parse_certificate(&identity.certificate) {
            Ok(cert) => json!({
                "configured": true, "provider_id": cert.provider_id, "serial": cert.serial,
                "issued_at": cert.issued_at, "expires_at": cert.expires_at,
            }),
            Err(_) => json!({ "configured": true, "certificate_readable": false }),
        },
    };
    ok(json!({
        "identity": identity_view,
        "operator_lock": {
            "exists": seen(store.operator_lock_exists())?,
            "pending": seen(store.operator_lock_pending())?,
        },
        "ready": store.ping().is_ok(),
        "counts": {
            "customers": seen(store.customer_count())?,
            "keys": seen(store.list_keys())?.len(),
        },
    }))
}

fn activity_view(
    store: &dyn RelayStore,
    hours: i64,
    customer_id: Option<i64>,
    key_id: Option<i64>,
    route: Option<&str>,
    outcome: Option<&str>,
) -> Outcome2 {
    let route = match route {
        None | Some("") => None,
        Some(text) => Some(Route::parse(text).ok_or_else(|| failure(&Error::InvalidApiKeyRequest))?),
    };
    let outcome = match outcome {
        None | Some("") => None,
        Some(text) => Some(Outcome::parse(text).ok_or_else(|| failure(&Error::InvalidApiKeyRequest))?),
    };
    let summary = seen(store.access_summary(&Filter {
        hours: hours.clamp(1, MAX_SUMMARY_HOURS),
        customer_id,
        key_id,
        route,
        outcome,
    }))?;
    let directory = seen(directory(store))?;

    let mut total = Totals::default();
    let mut by_user: HashMap<Option<i64>, (String, Totals)> = HashMap::new();
    let mut last_used: HashMap<Option<i64>, Option<String>> = HashMap::new();
    for info in &directory.infos {
        let customer = directory.customer_of(info.id).map(|c| c.id);
        let entry = last_used.entry(customer).or_insert(None);
        if info.last_used_at > *entry {
            *entry = info.last_used_at.clone();
        }
    }
    let by_key: Vec<Value> = summary
        .by_key
        .iter()
        .map(|a| {
            let customer = directory.customer_of(a.api_key_id);
            total.add(a);
            let slot = by_user
                .entry(customer.map(|c| c.id))
                .or_insert_with(|| {
                    (
                        customer.map_or_else(|| "(unassigned keys)".to_string(), |c| c.name.clone()),
                        Totals::default(),
                    )
                });
            slot.1.add(a);
            let key = directory.infos.iter().find(|i| i.id == a.api_key_id);
            json!({
                "key_id": a.api_key_id, "scope": key.map(|k| k.scope.clone()),
                "customer_id": customer.map(|c| c.id), "customer": customer.map(|c| c.name.clone()),
                "route": a.route, "outcome": a.outcome, "count": a.count,
                "avg_ms": if a.count > 0 { a.ms_total / a.count } else { 0 },
                "max_ms": a.ms_max, "bytes_in": a.bytes_in, "bytes_out": a.bytes_out,
                "last_hour": a.last_hour,
            })
        })
        .collect();
    let mut users: Vec<Value> = by_user
        .into_iter()
        .map(|(id, (name, t))| {
            let mut view = t.view();
            view["customer_id"] = json!(id);
            view["customer"] = json!(name);
            view["last_used_at"] = json!(last_used.get(&id).cloned().flatten());
            view
        })
        .collect();
    users.sort_by(|a, b| a["customer"].as_str().cmp(&b["customer"].as_str()));
    let by_hour: Vec<Value> = summary
        .by_hour
        .iter()
        .map(|h| json!({ "hour": h.hour, "outcome": h.outcome, "count": h.count }))
        .collect();
    ok(json!({
        "hours": summary.hours,
        "totals": total.view(),
        "users": users, "by_key": by_key, "by_hour": by_hour,
        "note": "Counts are of requests the relay admitted to its core from keys it knows, by hour. Requests the public Worker refused before the relay (wrong host or route, too large, rate limited) and anything a client does on its own machine are not seen here. Durations are coarse.",
    }))
}

#[derive(Default)]
struct Totals {
    requests: i64,
    ok: i64,
    client_error: i64,
    server_error: i64,
    blocked: i64,
    ms_total: i64,
    ms_max: i64,
    bytes_in: i64,
    bytes_out: i64,
}

impl Totals {
    fn add(&mut self, a: &activity::KeyActivity) {
        self.requests += a.count;
        match Outcome::parse(&a.outcome) {
            Some(Outcome::Ok) => self.ok += a.count,
            Some(Outcome::ClientError) => self.client_error += a.count,
            Some(Outcome::ServerError) => self.server_error += a.count,
            Some(o) if o.is_blocked() => self.blocked += a.count,
            _ => {}
        }
        self.ms_total += a.ms_total;
        self.ms_max = self.ms_max.max(a.ms_max);
        self.bytes_in += a.bytes_in;
        self.bytes_out += a.bytes_out;
    }

    fn view(&self) -> Value {
        json!({
            "requests": self.requests, "ok": self.ok, "client_error": self.client_error,
            "server_error": self.server_error, "blocked": self.blocked,
            "avg_ms": if self.requests > 0 { self.ms_total / self.requests } else { 0 },
            "max_ms": self.ms_max, "bytes_in": self.bytes_in, "bytes_out": self.bytes_out,
        })
    }
}

fn audit(store: &dyn RelayStore, feed: &str, before: Option<i64>, limit: Option<i64>) -> Outcome2 {
    let limit = page_limit(limit);
    match feed {
        "keys" => {
            let mut events = seen(store.key_events(None))?;
            events.reverse();
            let mut rows: Vec<_> = events
                .into_iter()
                .filter(|e| before.is_none_or(|b| e.id < b))
                .take(limit as usize + 1)
                .collect();
            let next_before = if rows.len() as i64 > limit {
                rows.truncate(limit as usize);
                rows.last().map(|e| e.id)
            } else {
                None
            };
            let events: Vec<Value> = rows
                .iter()
                .map(|e| {
                    json!({ "id": e.id, "key_id": e.key_id, "event": e.event,
                            "actor": e.actor, "related_key_id": e.related_key_id,
                            "occurred_at": e.occurred_at, "entry_hash": e.entry_hash })
                })
                .collect();
            ok(json!({ "feed": "keys", "rows": events, "next_before": next_before }))
        }
        "actions" => {
            let mut rows = seen(store.operator_actions(limit + 1, before))?;
            let next_before = if rows.len() as i64 > limit {
                rows.truncate(limit as usize);
                rows.last().map(|a| a.id)
            } else {
                None
            };
            let actions: Vec<Value> = rows
                .iter()
                .map(|a| {
                    json!({ "id": a.id, "operator": a.operator, "action": a.action,
                            "subject": a.subject, "success": a.success,
                            "occurred_at": a.occurred_at, "operation_id": a.operation_id })
                })
                .collect();
            ok(json!({ "feed": "actions", "rows": actions, "next_before": next_before }))
        }
        "auth" => {
            let rows: Vec<Value> = seen(store.provider_auth_events(limit))?
                .iter()
                .filter(|a| before.is_none_or(|b| a.id < b))
                .map(|a| {
                    json!({ "id": a.id, "operation": a.operation, "success": a.success,
                            "attempted_at": a.attempted_at, "entry_hash": a.entry_hash })
                })
                .collect();
            ok(json!({ "feed": "auth", "rows": rows, "next_before": null }))
        }
        _ => Err(failure(&Error::InvalidApiKeyRequest)),
    }
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

fn letters(store: &dyn RelayStore) -> Outcome2 {
    // Name the customer a letter is for, by the key bound to its recipient.
    let directory = seen(directory(store))?;
    let mut owners: HashMap<String, String> = HashMap::new();
    for info in &directory.infos {
        if let (Some(fp), Some(customer)) = (&info.recipient_fingerprint, directory.customer_of(info.id)) {
            owners.insert(fp.clone(), customer.name.clone());
        }
    }
    let view = |letters: Vec<super::LetterSummary>| -> Vec<Value> {
        letters
            .into_iter()
            .map(|l| {
                json!({
                    "id": l.id,
                    "recipient_fingerprint": l.recipient_fingerprint,
                    "customer": owners.get(&l.recipient_fingerprint),
                    "kind": l.kind, "kind_name": kind_name(l.kind), "size": l.size,
                    "stored_at": l.created_at, "expires_at": l.expires_at,
                })
            })
            .collect()
    };
    let (inbox_total, inbox) = seen(store.inbox_letters(FEED_MAX))?;
    let (device_total, devices) = seen(store.device_letters(FEED_MAX))?;
    ok(json!({
        "inbox": { "total": inbox_total, "newest": view(inbox) },
        "devices": { "total": device_total, "newest": view(devices) },
    }))
}

#[cfg(test)]
#[path = "operator/tests.rs"]
mod tests;
