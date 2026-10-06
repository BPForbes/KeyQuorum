//! The provider's licensing flows, each one atomic: issue a licence's keys as
//! sealed bundles, replace a key, void a licence.
//!
//! Each runs inside one unit of work of the store, composing the modules that
//! own the tables: [`licence`] (the records), [`key_delivery`] (mint a key and
//! seal it to its customer), [`api_key`] (revoke). Nothing here re-decides a
//! rule they own. A flow either commits whole or not at all, and the sealed
//! bundles are handed back only once it has: no file is written inside the
//! transaction, so a failure leaves nothing to clean up.
//!
//! The scopes a licence may carry are the four a customer uses
//! (`inbox.push`, `inbox.pull`, `device.push`, `device.pull`). The `admin`
//! scope is the operator's own HTTP key and is never issued to a client.

use super::api_key::{self, ApiKeyInfo, ApiKeyScope, NewApiKey, HOST_ACTOR};
use super::key_delivery::{self, Recipient};
use super::licence::{self, Licence, NewLicence};
use super::sql::{params, Sql};
use super::ProviderIdentity;
use crate::api_key_delivery::{DEVICE_ID_LEN, MAX_LICENCE_BYTES};
use crate::error::{Error, Result};
use crate::keys;

/// The scopes a client's licence may carry.
pub const CLIENT_SCOPES: [ApiKeyScope; 4] = [
    ApiKeyScope::InboxPush,
    ApiKeyScope::InboxPull,
    ApiKeyScope::DevicePush,
    ApiKeyScope::DevicePull,
];

/// Which licence the keys are issued under.
#[derive(Clone, Debug)]
pub enum LicenceRef {
    /// Record this licence first, in the same unit of work.
    New(NewLicence),
    /// An existing licence, which must be active.
    Existing(i64),
}

/// What to issue.
#[derive(Clone, Debug)]
pub struct Issuance {
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
    pub licence: Licence,
    pub bundles: Vec<IssuedBundle>,
}

/// The result of [`void`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Voided {
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
fn statement_for(conn: &dyn Sql, licence: &Licence, scope: ApiKeyScope) -> Result<String> {
    let text = licence::statement(licence, scope.as_str(), &now(conn)?);
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
    super::validate_relay_url(&request.relay_url)
}

/// Issues the licence's keys as sealed bundles, atomically: the licence (when
/// new), one key per scope, each key's delivery record and its link to the
/// licence commit together or not at all. The keys expire when the licence
/// does.
pub fn issue(conn: &dyn Sql, identity: &ProviderIdentity, request: &Issuance) -> Result<Issued> {
    validate(request)?;
    conn.with_transaction(|| {
        let licence = match &request.licence {
            LicenceRef::New(new) => licence::create(conn, new)?,
            LicenceRef::Existing(id) => licence::get(conn, *id)?,
        };
        let ttl = licence::seconds_remaining(conn, &licence)?;
        let mut bundles = Vec::with_capacity(request.scopes.len());
        for &scope in &request.scopes {
            let recipient = Recipient {
                public_key: request.recipient_public_key,
                relay_url: request.relay_url.clone(),
                device_id: request.device_id,
                licence: Some(statement_for(conn, &licence, scope)?),
            };
            let new = NewApiKey {
                scope,
                recipient_fingerprint: None,
                label: Some(licence.client.clone()),
                ttl_seconds: ttl,
            };
            let mut sealed = None;
            let delivered = key_delivery::create_as_bundle(conn, identity, &new, &recipient, |b| {
                sealed = Some(b.to_vec());
                Ok(())
            })?;
            licence::link_key(conn, delivered.info.id, licence.id)?;
            bundles.push(IssuedBundle {
                info: delivered.info,
                recipient_fingerprint: delivered.recipient_fingerprint,
                bundle: sealed.ok_or(Error::IntegrityCheckFailed)?,
            });
        }
        Ok(Issued { licence, bundles })
    })
}

/// Replaces key `id` with a new one under the same licence, sealed to the same
/// recipient as before; the old key is revoked at once. The licence must still
/// be active, and the key must have been issued by [`issue`] (it must have a
/// recorded recipient).
pub fn rotate(conn: &dyn Sql, identity: &ProviderIdentity, id: i64) -> Result<IssuedBundle> {
    conn.with_transaction(|| {
        let licence_id = licence::licence_of_key(conn, id)?;
        let licence = licence_id.map(|l| licence::get(conn, l)).transpose()?;
        if let Some(licence) = &licence {
            licence::seconds_remaining(conn, licence)?;
        }
        let mut sealed = None;
        let delivered = key_delivery::rotate_as_bundle(conn, identity, id, None, |b| {
            sealed = Some(b.to_vec());
            Ok(())
        })?;
        if let Some(licence) = licence {
            licence::link_key(conn, delivered.info.id, licence.id)?;
        }
        Ok(IssuedBundle {
            info: delivered.info,
            recipient_fingerprint: delivered.recipient_fingerprint,
            bundle: sealed.ok_or(Error::IntegrityCheckFailed)?,
        })
    })
}

/// Voids licence `id` and revokes every live key issued under it, atomically.
/// Voiding twice is not an error; it revokes any key still live.
pub fn void(conn: &dyn Sql, id: i64, reason: Option<&str>) -> Result<Voided> {
    conn.with_transaction(|| {
        let newly_voided = licence::mark_void(conn, id, reason)?;
        let mut revoked_keys = Vec::new();
        for key in licence::keys_of(conn, id)? {
            if api_key::info(conn, key)?.revoked_at.is_none() {
                api_key::revoke_by(conn, key, HOST_ACTOR)?;
                revoked_keys.push(key);
            }
        }
        Ok(Voided {
            newly_voided,
            revoked_keys,
        })
    })
}

/// The fingerprint a client's public key goes by, as the console shows it.
pub fn fingerprint_of(public_key: &[u8; 32]) -> String {
    keys::fingerprint(public_key)
}

#[cfg(test)]
#[path = "issuance/tests.rs"]
mod tests;
