//! The provider's licensing flows, each one atomic: issue a licence's keys as
//! sealed bundles, replace a key, renew or void a licence, assign a key.
//!
//! Each runs inside one unit of work of the store, composing the modules that
//! own the tables: [`customer`], [`licence`] (the records), [`key_delivery`]
//! (mint a key and seal it to its customer), [`api_key`] (revoke, expiry) and
//! [`operator_log`] (the record of who did it, with the operation id the
//! console sent). Nothing here re-decides a rule they own. A flow either
//! commits whole, its operation record included, or not at all, and the sealed
//! bundles are handed back only once it has: no file is written inside the
//! transaction, so a failure leaves nothing to clean up, and a lost response is
//! recovered by the operation id (sealed bytes are not retained, so a lost
//! download is replaced by replacing the key).
//!
//! The scopes a licence may carry are the four a customer uses
//! (`inbox.push`, `inbox.pull`, `device.push`, `device.pull`). The `admin`
//! scope is the operator's own HTTP key and is never issued to a client.
//!
//! A key belongs to a customer only through its link to a licence. A key with
//! no link is unassigned and is changed only by voiding it or by assigning it
//! ([`assign_key`]), never by guessing.

use super::api_key::{self, ApiKeyInfo, ApiKeyScope, NewApiKey, HOST_ACTOR};
use super::customer::{self, Customer, NewCustomer};
use super::key_delivery::{self, Recipient, Via};
use super::licence::{self, KeyLink, Licence, NewLicence};
use super::operator_log::Note;
use super::sql::{params, Sql};
use super::ProviderIdentity;
use crate::api_key_delivery::{DEVICE_ID_LEN, MAX_LICENCE_BYTES};
use crate::error::{Error, Result};
use crate::keys;
use serde_json::json;

/// The scopes a client's licence may carry.
pub const CLIENT_SCOPES: [ApiKeyScope; 4] = [
    ApiKeyScope::InboxPush,
    ApiKeyScope::InboxPull,
    ApiKeyScope::DevicePush,
    ApiKeyScope::DevicePull,
];

/// The longest a replaced key may stay usable so its holder can collect the
/// letter that carries its replacement (a week).
pub const MAX_GRACE_SECONDS: i64 = 7 * 86_400;

/// Whose licence the keys are issued under.
#[derive(Clone, Debug)]
pub enum CustomerRef {
    /// Record this customer first, in the same unit of work.
    New(NewCustomer),
    Existing(i64),
}

/// Which licence the keys are issued under.
#[derive(Clone, Debug)]
pub enum LicenceRef {
    /// Record this licence first, in the same unit of work.
    New(NewLicence),
    /// An existing licence of the customer, which must be active.
    Existing(i64),
}

/// What to issue.
#[derive(Clone, Debug)]
pub struct Issuance {
    pub customer: CustomerRef,
    pub licence: LicenceRef,
    /// One key, and one bundle, per scope; at least one, none repeated.
    pub scopes: Vec<ApiKeyScope>,
    /// The client's X25519 public key: every bundle is sealed to it.
    pub recipient_public_key: [u8; 32],
    /// The relay URL the client loads the keys for.
    pub relay_url: String,
    /// Bind the keys to one device container, if the client asked.
    pub device_id: Option<[u8; DEVICE_ID_LEN]>,
}

/// One issued key and the bundle that carries it. The bundle is sealed to the
/// client; the bearer inside is never returned any other way.
#[derive(Clone, Debug)]
pub struct IssuedBundle {
    pub info: ApiKeyInfo,
    pub recipient_fingerprint: String,
    pub bundle: Vec<u8>,
}

/// The result of [`issue`].
#[derive(Clone, Debug)]
pub struct Issued {
    pub customer: Customer,
    pub licence: Licence,
    pub bundles: Vec<IssuedBundle>,
    /// The licence this one replaced, voided in the same unit of work.
    pub voided: Option<Voided>,
}

/// How a replacement reaches its customer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotateVia {
    /// A sealed `.kqkey` bundle; the old key is revoked at once.
    Bundle,
    /// A sealed letter in the customer's own mailbox; the old key stays usable
    /// for `grace_seconds` (1 to [`MAX_GRACE_SECONDS`]) so it can be collected,
    /// and only when the customer can collect it.
    Letter { grace_seconds: i64 },
}

/// The result of [`rotate`].
#[derive(Clone, Debug)]
pub struct Rotated {
    pub replaced_key_id: i64,
    pub licence_id: i64,
    pub info: ApiKeyInfo,
    pub recipient_fingerprint: String,
    /// The sealed bundle, for [`RotateVia::Bundle`].
    pub bundle: Option<Vec<u8>>,
    /// The mailbox letter's id and the time the old key ends, for
    /// [`RotateVia::Letter`].
    pub letter: Option<(i64, Option<String>)>,
}

/// The result of [`void_licence`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Voided {
    pub licence_id: i64,
    /// Whether this call voided the licence (false: it already was).
    pub newly_voided: bool,
    /// The keys this call revoked (live ones only), oldest first.
    pub revoked_keys: Vec<i64>,
}

fn now(conn: &dyn Sql) -> Result<String> {
    conn.query_row(
        "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now')",
        params![],
        |row| row.get(0),
    )
}

/// The statement a key under `licence` carries, refused if it would not fit
/// the sealed issue.
fn statement_for(
    conn: &dyn Sql,
    customer: &Customer,
    licence: &Licence,
    scope: &str,
) -> Result<String> {
    let text = licence::statement(customer, licence, scope, &now(conn)?);
    if text.len() > MAX_LICENCE_BYTES {
        return Err(Error::InvalidLicence);
    }
    Ok(text)
}

fn validate(request: &Issuance) -> Result<()> {
    if request.scopes.is_empty() || request.scopes.iter().any(|s| !CLIENT_SCOPES.contains(s)) {
        return Err(Error::InvalidApiKeyRequest);
    }
    let mut seen = request.scopes.clone();
    seen.sort_by_key(|scope| scope.as_str());
    seen.dedup();
    if seen.len() != request.scopes.len() {
        return Err(Error::InvalidApiKeyRequest);
    }
    if crate::envelope::is_weak_x25519_public_key(&request.recipient_public_key) {
        return Err(Error::InvalidPublicKey);
    }
    super::validate_relay_url(&request.relay_url)?;
    // A new customer can only be given a new licence.
    if matches!(request.customer, CustomerRef::New(_))
        && matches!(request.licence, LicenceRef::Existing(_))
    {
        return Err(Error::InvalidLicence);
    }
    Ok(())
}

fn done(note: Option<&Note<'_>>, conn: &dyn Sql, result: serde_json::Value) -> Result<()> {
    match note {
        Some(note) => note.record_done(conn, &result.to_string()),
        None => Ok(()),
    }
}

/// Records a customer, atomically with its operation record.
pub fn create_customer(
    conn: &dyn Sql,
    new: &NewCustomer,
    note: Option<&Note<'_>>,
) -> Result<Customer> {
    conn.with_transaction(|| {
        let made = customer::create(conn, new)?;
        done(note, conn, json!({ "customer_id": made.id }))?;
        Ok(made)
    })
}

/// Records a licence for an existing customer, with no keys, atomically with
/// its operation record. A licence recorded as replacing another voids it, with
/// its keys, in the same unit of work.
pub fn create_licence(
    conn: &dyn Sql,
    customer_id: i64,
    new: &NewLicence,
    note: Option<&Note<'_>>,
) -> Result<(Licence, Option<Voided>)> {
    conn.with_transaction(|| {
        customer::get(conn, customer_id)?;
        let made = licence::create(conn, customer_id, new)?;
        let voided = match made.replaces_licence_id {
            Some(old) => Some(void_inner(conn, old, Some("replaced by a new licence"))?),
            None => None,
        };
        done(
            note,
            conn,
            json!({
                "customer_id": customer_id,
                "licence_id": made.id,
                "voided_licence_id": voided.as_ref().map(|v| v.licence_id),
            }),
        )?;
        Ok((made, voided))
    })
}

/// Issues the licence's keys as sealed bundles, atomically: the customer and
/// licence (when new), one key per scope, each key's delivery record and its
/// link to the licence, a replaced licence's voiding if one is named, and the
/// operation record commit together or not at all. The keys end when the
/// licence does.
pub fn issue(
    conn: &dyn Sql,
    identity: &ProviderIdentity,
    request: &Issuance,
    note: Option<&Note<'_>>,
) -> Result<Issued> {
    validate(request)?;
    conn.with_transaction(|| {
        let customer = match &request.customer {
            CustomerRef::New(new) => customer::create(conn, new)?,
            CustomerRef::Existing(id) => customer::get(conn, *id)?,
        };
        let licence = match &request.licence {
            LicenceRef::New(new) => licence::create(conn, customer.id, new)?,
            LicenceRef::Existing(id) => {
                let found = licence::get(conn, *id)?;
                if found.customer_id != customer.id {
                    return Err(Error::InvalidLicence);
                }
                found
            }
        };
        let ttl = licence::seconds_remaining(conn, &licence)?;
        let mut bundles = Vec::with_capacity(request.scopes.len());
        for &scope in &request.scopes {
            let recipient = Recipient {
                public_key: request.recipient_public_key,
                relay_url: request.relay_url.clone(),
                device_id: request.device_id,
                licence: Some(statement_for(conn, &customer, &licence, scope.as_str())?),
            };
            let new = NewApiKey {
                scope,
                recipient_fingerprint: None,
                label: Some(customer.name.clone()),
                ttl_seconds: ttl,
            };
            let mut sealed = None;
            let delivered = key_delivery::create_as_bundle(conn, identity, &new, &recipient, |b| {
                sealed = Some(b.to_vec());
                Ok(())
            })?;
            licence::link_key(
                conn,
                &KeyLink {
                    api_key_id: delivered.info.id,
                    licence_id: licence.id,
                    licence_version: Some(licence.version),
                    replaces_key_id: None,
                },
            )?;
            bundles.push(IssuedBundle {
                info: delivered.info,
                recipient_fingerprint: delivered.recipient_fingerprint,
                bundle: sealed.ok_or(Error::IntegrityCheckFailed)?,
            });
        }
        // A licence recorded as replacing another voids it, with its keys, in
        // this same unit of work; keys added later to an existing licence
        // never do.
        let voided = match (&request.licence, licence.replaces_licence_id) {
            (LicenceRef::New(_), Some(old)) => {
                Some(void_inner(conn, old, Some("replaced by a new licence"))?)
            }
            _ => None,
        };
        done(
            note,
            conn,
            json!({
                "customer_id": customer.id,
                "licence_id": licence.id,
                "key_ids": bundles.iter().map(|b| b.info.id).collect::<Vec<_>>(),
                "voided_licence_id": voided.as_ref().map(|v| v.licence_id),
            }),
        )?;
        Ok(Issued {
            customer,
            licence,
            bundles,
            voided,
        })
    })
}

/// Replaces key `id` with a new one under the same licence and the same
/// recipient, sealed with the licence's current statement and ending when the
/// licence does. The key must be assigned to a licence, and the licence active.
/// A bundle revokes the old key at once; a letter leaves it usable for the
/// grace period and is refused unless the customer can collect it.
pub fn rotate(
    conn: &dyn Sql,
    identity: &ProviderIdentity,
    id: i64,
    via: RotateVia,
    note: Option<&Note<'_>>,
) -> Result<Rotated> {
    if let RotateVia::Letter { grace_seconds } = via {
        if !(1..=MAX_GRACE_SECONDS).contains(&grace_seconds) {
            return Err(Error::InvalidApiKeyRequest);
        }
    }
    conn.with_transaction(|| {
        let link = licence::link_of_key(conn, id)?.ok_or(Error::KeyNotAssigned)?;
        let licence = licence::get(conn, link.licence_id)?;
        let customer = customer::get(conn, licence.customer_id)?;
        licence::seconds_remaining(conn, &licence)?;
        let info = api_key::info(conn, id)?;
        // The recorded recipient, with the licence's current statement.
        let recorded = key_delivery::recipient_for(conn, id)?.ok_or(Error::DeliveryRecipientMissing)?;
        let recipient = Recipient {
            licence: Some(statement_for(conn, &customer, &licence, &info.scope)?),
            ..recorded
        };

        let mut sealed = None;
        let delivered = match via {
            RotateVia::Bundle => key_delivery::rotate_as_bundle(conn, identity, id, Some(recipient), |b| {
                sealed = Some(b.to_vec());
                Ok(())
            })?,
            RotateVia::Letter { grace_seconds } => {
                key_delivery::rotate_as_letter(conn, identity, id, Some(recipient), grace_seconds)?
            }
        };
        // The replacement ends with the licence as it stands now.
        api_key::set_expiry(conn, delivered.info.id, licence.expires_at.as_deref())?;
        licence::link_key(
            conn,
            &KeyLink {
                api_key_id: delivered.info.id,
                licence_id: licence.id,
                licence_version: Some(licence.version),
                replaces_key_id: Some(id),
            },
        )?;
        let letter = match &delivered.via {
            Via::Letter { id, until } => Some((*id, until.clone())),
            Via::Bundle { .. } => None,
        };
        done(
            note,
            conn,
            json!({
                "replaced_key_id": id,
                "key_id": delivered.info.id,
                "licence_id": licence.id,
                "letter_id": letter.as_ref().map(|(letter_id, _)| letter_id),
            }),
        )?;
        Ok(Rotated {
            replaced_key_id: id,
            licence_id: licence.id,
            info: api_key::info(conn, delivered.info.id)?,
            recipient_fingerprint: delivered.recipient_fingerprint,
            bundle: sealed,
            letter,
        })
    })
}

fn void_inner(conn: &dyn Sql, id: i64, reason: Option<&str>) -> Result<Voided> {
    let newly_voided = licence::mark_void(conn, id, reason)?;
    let mut revoked_keys = Vec::new();
    for key in licence::keys_of(conn, id)? {
        if api_key::info(conn, key)?.revoked_at.is_none() {
            api_key::revoke_by(conn, key, HOST_ACTOR)?;
            revoked_keys.push(key);
        }
    }
    Ok(Voided {
        licence_id: id,
        newly_voided,
        revoked_keys,
    })
}

/// Voids licence `id` and revokes every live key issued under it, atomically.
/// Voiding twice is not an error; it revokes any key still live.
pub fn void_licence(
    conn: &dyn Sql,
    id: i64,
    reason: Option<&str>,
    note: Option<&Note<'_>>,
) -> Result<Voided> {
    conn.with_transaction(|| {
        let voided = void_inner(conn, id, reason)?;
        done(
            note,
            conn,
            json!({ "licence_id": id, "revoked_keys": voided.revoked_keys }),
        )?;
        Ok(voided)
    })
}

/// Revokes one key, atomically with its operation record. Revoking a revoked
/// key succeeds and records nothing more in the key's lifecycle.
pub fn revoke_key(conn: &dyn Sql, id: i64, note: Option<&Note<'_>>) -> Result<()> {
    conn.with_transaction(|| {
        api_key::revoke_by(conn, id, HOST_ACTOR)?;
        done(note, conn, json!({ "key_id": id }))
    })
}

/// Adds a statement version to an active licence (a renewal or amendment),
/// atomically with its operation record. Keys already issued keep the end they
/// were issued with; replacing them gives each the licence's new end.
pub fn renew_licence(
    conn: &dyn Sql,
    id: i64,
    terms: Option<&str>,
    expires_at: Option<&str>,
    note: Option<&Note<'_>>,
) -> Result<Licence> {
    conn.with_transaction(|| {
        let renewed = licence::renew(conn, id, terms, expires_at)?;
        done(
            note,
            conn,
            json!({ "licence_id": id, "version": renewed.version }),
        )?;
        Ok(renewed)
    })
}

/// Assigns an unassigned key to a licence, atomically with its operation
/// record. Only a customer scope, and only once: a link is never rewritten.
pub fn assign_key(
    conn: &dyn Sql,
    key_id: i64,
    licence_id: i64,
    note: Option<&Note<'_>>,
) -> Result<()> {
    conn.with_transaction(|| {
        let info = api_key::info(conn, key_id)?;
        let scope = ApiKeyScope::parse(&info.scope)?;
        if !CLIENT_SCOPES.contains(&scope) || licence::link_of_key(conn, key_id)?.is_some() {
            return Err(Error::InvalidApiKeyRequest);
        }
        licence::get(conn, licence_id)?;
        licence::link_key(
            conn,
            &KeyLink {
                api_key_id: key_id,
                licence_id,
                licence_version: None,
                replaces_key_id: None,
            },
        )?;
        done(
            note,
            conn,
            json!({ "key_id": key_id, "licence_id": licence_id }),
        )
    })
}

/// The fingerprint a client's public key goes by, as the console shows it.
pub fn fingerprint_of(public_key: &[u8; 32]) -> String {
    keys::fingerprint(public_key)
}

#[cfg(test)]
#[path = "issuance/tests.rs"]
mod tests;
