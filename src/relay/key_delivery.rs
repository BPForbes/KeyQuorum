//! Issuing a customer API key sealed to its customer, on the host.
//!
//! `host keys create --recipient-key` and `host keys rotate` call in here
//! instead of printing a bearer. The key is minted and the sealed issue
//! produced in one immediate transaction: for a first key a `.kqkey`
//! bundle is handed to `write` while the transaction is open, so a write
//! that fails leaves no key behind, and a commit that fails tells the
//! caller to remove the file it wrote; for a rotation the letter is stored
//! in this relay's own mailbox in the same transaction, addressed to the
//! recipient's fingerprint like any pushed letter, so the key change and
//! its delivery commit together or not at all.
//!
//! The key a mailbox letter replaces is not revoked at once: it keeps
//! working for a grace period ([`DEFAULT_GRACE_SECONDS`], `--grace-seconds`)
//! so its holder can still pull the letter, then expires; the letter
//! expires with it, and `keys revoke` ends both sooner. A bundle replaces
//! the old key at once, as `rotate` always did.
//!
//! A letter is only worth sending if the customer can collect it. Only an
//! `inbox.pull` key bound to the recipient reads that mailbox, so
//! [`rotate_as_letter`] refuses a key of any other scope unless such a key
//! is live for the same recipient ([`Error::DeliveryNotCollectable`]), before
//! it changes anything; the way out for the rest is [`rotate_as_bundle`].
//!
//! A bundle is a file, and a file is outside the database transaction:
//! the write happens while it is open and a failure the process survives
//! removes it, but a crash between the write and the commit can leave a
//! bundle for a key that was never created. That bundle opens nothing (the
//! relay never stored the key), and since files are never overwritten the
//! operator removes it before retrying. The mailbox letter has no such gap:
//! it commits with the key.
//!
//! Whom a key was sealed to is kept in `api_key_deliveries`, so a rotation
//! needs no `--recipient-key` again. That table never holds a bearer, a
//! hash of one, or the sealed bytes: a bundle is named by its SHA-256 and a
//! letter by its mailbox id.

use super::api_key::{self, ApiKeyInfo, ApiKeyScope, CreatedApiKey, NewApiKey, OldKey};
use super::{mailbox, ProviderIdentity};
use crate::api_key_delivery::{self, KeyIssue, DEVICE_ID_LEN};
use crate::db::relay_credential::normalize_url;
use crate::error::{Error, Result};
use crate::keys;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// How long the key a letter replaces stays usable to collect the letter.
pub const DEFAULT_GRACE_SECONDS: i64 = 86_400;

/// Whom a key is sealed to, and what its issue says about this relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// The customer's X25519 encryption public key.
    pub public_key: [u8; 32],
    /// The URL the customer loads the key for.
    pub relay_url: String,
    /// The container the key may be loaded from, if bound to one.
    pub device_id: Option<[u8; DEVICE_ID_LEN]>,
    /// A licence statement to carry inside the sealed issue.
    pub licence: Option<String>,
}

/// How a sealed issue left the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    /// A `.kqkey` file, named by its digest.
    Bundle { sha256: String },
    /// A mailbox letter, by its id; usable until `until` (UTC), when the key
    /// it replaces expires.
    Letter { id: i64, until: Option<String> },
}

/// What an issue left behind on the host. Never the bearer.
#[derive(Clone, Debug)]
pub struct Delivered {
    pub info: ApiKeyInfo,
    pub recipient_fingerprint: String,
    pub via: Via,
}

/// The recipient recorded for key `id`, if it was ever sealed to one.
pub fn recipient_for(conn: &Connection, id: i64) -> Result<Option<Recipient>> {
    conn.query_row(
        "SELECT recipient_public_key, relay_url, device_id, licence
         FROM api_key_deliveries WHERE api_key_id = ?1",
        params![id],
        |row| {
            let public_key: Vec<u8> = row.get(0)?;
            let device_id: Option<Vec<u8>> = row.get(2)?;
            Ok((public_key, row.get::<_, String>(1)?, device_id, row.get(3)?))
        },
    )
    .optional()?
    .map(|(public_key, relay_url, device_id, licence)| {
        Ok(Recipient {
            public_key: public_key.try_into().map_err(|_| Error::InvalidPublicKey)?,
            relay_url,
            device_id: device_id
                .map(|id| id.try_into().map_err(|_| Error::InvalidDevice))
                .transpose()?,
            licence,
        })
    })
    .transpose()
}

/// What a sealed issue needs from the store it runs in, inside the one unit
/// of work that mints or rotates the key. The SQLite store implements it
/// over its open transaction ([`SqliteOps`]) and any other backend over its
/// own, so the flow that decides whom a key is sealed to, whether a letter
/// can be collected, and what is recorded is written once, here.
pub(crate) trait DeliveryOps {
    fn key_info(&mut self, id: i64) -> Result<ApiKeyInfo>;
    fn has_live_pull_key(&mut self, fingerprint: &str) -> Result<bool>;
    fn recipient_for(&mut self, id: i64) -> Result<Option<Recipient>>;
    fn create_key(&mut self, new: &NewApiKey) -> Result<CreatedApiKey>;
    fn rotate_key(&mut self, id: i64, old: OldKey) -> Result<CreatedApiKey>;
    /// Store a letter in this relay's own mailbox, expiring at `until`.
    fn store_letter(&mut self, letter: &[u8], until: Option<&str>) -> Result<(i64, String, bool)>;
    fn record_delivery(&mut self, key_id: i64, recipient: &Recipient, via: &Via) -> Result<()>;
    /// The store's clock, as `YYYY-MM-DD HH:MM:SS` UTC.
    fn now_seconds(&mut self) -> Result<String>;
}

/// [`DeliveryOps`] over the relay's SQLite connection, already inside a
/// transaction.
pub(crate) struct SqliteOps<'a>(pub &'a Connection);

impl DeliveryOps for SqliteOps<'_> {
    fn key_info(&mut self, id: i64) -> Result<ApiKeyInfo> {
        api_key::info(self.0, id)
    }

    fn has_live_pull_key(&mut self, fingerprint: &str) -> Result<bool> {
        api_key::has_live_pull_key(self.0, fingerprint)
    }

    fn recipient_for(&mut self, id: i64) -> Result<Option<Recipient>> {
        recipient_for(self.0, id)
    }

    fn create_key(&mut self, new: &NewApiKey) -> Result<CreatedApiKey> {
        api_key::create(self.0, new)
    }

    fn rotate_key(&mut self, id: i64, old: OldKey) -> Result<CreatedApiKey> {
        api_key::rotate_with(self.0, id, old)
    }

    fn store_letter(&mut self, letter: &[u8], until: Option<&str>) -> Result<(i64, String, bool)> {
        mailbox::store_until(self.0, letter, until)
    }

    fn record_delivery(&mut self, key_id: i64, recipient: &Recipient, via: &Via) -> Result<()> {
        let (kind, letter_id, sha256) = match via {
            Via::Bundle { sha256 } => ("bundle", None, Some(sha256.as_str())),
            Via::Letter { id, .. } => ("letter", Some(*id), None),
        };
        self.0.execute(
            "INSERT INTO api_key_deliveries
                (api_key_id, recipient_public_key, relay_url, device_id, licence,
                 via, letter_id, bundle_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                key_id,
                &recipient.public_key[..],
                normalize_url(&recipient.relay_url),
                recipient.device_id.as_ref().map(|id| &id[..]),
                recipient.licence,
                kind,
                letter_id,
                sha256,
            ],
        )?;
        Ok(())
    }

    fn now_seconds(&mut self) -> Result<String> {
        Ok(self
            .0
            .query_row("SELECT strftime('%Y-%m-%d %H:%M:%S', 'now')", [], |row| {
                row.get(0)
            })?)
    }
}

/// Mint a new key and hand it to `write` as a sealed `.kqkey` bundle, in
/// one transaction. `new.recipient_fingerprint` may be left out for a
/// scope that binds one: it is the recipient key's fingerprint; given, it
/// must match. On an error the key does not exist; if `write` had already
/// succeeded the caller removes what it wrote.
pub fn create_as_bundle(
    conn: &Connection,
    identity: &ProviderIdentity,
    new: &NewApiKey,
    recipient: &Recipient,
    write: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<Delivered> {
    let mut write = Some(write);
    crate::db::with_immediate_transaction(conn, || {
        create_as_bundle_with(
            &mut SqliteOps(conn),
            identity,
            new,
            recipient,
            &mut |bytes| write.take().ok_or(Error::IntegrityCheckFailed)?(bytes),
        )
    })
}

/// [`create_as_bundle`] over any store's [`DeliveryOps`], inside its unit
/// of work.
pub(crate) fn create_as_bundle_with(
    ops: &mut impl DeliveryOps,
    identity: &ProviderIdentity,
    new: &NewApiKey,
    recipient: &Recipient,
    write: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<Delivered> {
    let fingerprint = keys::fingerprint(&recipient.public_key);
    let mut new = new.clone();
    if new.scope.binds_recipient() {
        match &new.recipient_fingerprint {
            None => new.recipient_fingerprint = Some(fingerprint.clone()),
            Some(given) if given.eq_ignore_ascii_case(&fingerprint) => {}
            Some(_) => return Err(Error::InvalidApiKeyRequest),
        }
    }
    let created = ops.create_key(&new)?;
    deliver_bundle(ops, identity, created, recipient, write)
}

/// Rotate key `id` and store the replacement in this relay's mailbox as a
/// sealed letter for the recipient recorded for `id` (or `recipient`), in
/// one transaction. The old key stays usable for `grace_seconds` to collect
/// it, and the letter expires with it.
pub fn rotate_as_letter(
    conn: &Connection,
    identity: &ProviderIdentity,
    id: i64,
    recipient: Option<Recipient>,
    grace_seconds: i64,
) -> Result<Delivered> {
    crate::db::with_immediate_transaction(conn, || {
        rotate_as_letter_with(&mut SqliteOps(conn), identity, id, recipient, grace_seconds)
    })
}

/// [`rotate_as_letter`] over any store's [`DeliveryOps`].
pub(crate) fn rotate_as_letter_with(
    ops: &mut impl DeliveryOps,
    identity: &ProviderIdentity,
    id: i64,
    recipient: Option<Recipient>,
    grace_seconds: i64,
) -> Result<Delivered> {
    let recipient = resolve_recipient(ops, id, recipient)?;
    let collectable = ops.key_info(id)?.scope == ApiKeyScope::InboxPull.as_str()
        || ops.has_live_pull_key(&keys::fingerprint(&recipient.public_key))?;
    if !collectable {
        return Err(Error::DeliveryNotCollectable);
    }
    let created = ops.rotate_key(id, OldKey::ExpireAfter(grace_seconds))?;
    let until = ops.key_info(id)?.expires_at;
    let issue = issue_for(ops, identity, &created, &recipient)?;
    let letter = api_key_delivery::seal_letter(identity, &recipient.public_key, &issue)?;
    let (letter_id, fingerprint, _) = ops.store_letter(&letter, until.as_deref())?;
    let via = Via::Letter {
        id: letter_id,
        until,
    };
    ops.record_delivery(created.info.id, &recipient, &via)?;
    Ok(Delivered {
        info: created.info,
        recipient_fingerprint: fingerprint,
        via,
    })
}

/// Rotate key `id`, revoking it at once, and hand the replacement to
/// `write` as a sealed `.kqkey` bundle, in one transaction.
pub fn rotate_as_bundle(
    conn: &Connection,
    identity: &ProviderIdentity,
    id: i64,
    recipient: Option<Recipient>,
    write: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<Delivered> {
    let mut write = Some(write);
    crate::db::with_immediate_transaction(conn, || {
        rotate_as_bundle_with(
            &mut SqliteOps(conn),
            identity,
            id,
            recipient,
            &mut |bytes| write.take().ok_or(Error::IntegrityCheckFailed)?(bytes),
        )
    })
}

/// [`rotate_as_bundle`] over any store's [`DeliveryOps`].
pub(crate) fn rotate_as_bundle_with(
    ops: &mut impl DeliveryOps,
    identity: &ProviderIdentity,
    id: i64,
    recipient: Option<Recipient>,
    write: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<Delivered> {
    let recipient = resolve_recipient(ops, id, recipient)?;
    let created = ops.rotate_key(id, OldKey::RevokeNow)?;
    deliver_bundle(ops, identity, created, &recipient, write)
}

/// The recipient given now, else the one recorded for `id`. A key bound to
/// a fingerprint is sealed only to the key with that fingerprint.
fn resolve_recipient(
    ops: &mut impl DeliveryOps,
    id: i64,
    given: Option<Recipient>,
) -> Result<Recipient> {
    let recipient = match given {
        Some(recipient) => recipient,
        None => ops
            .recipient_for(id)?
            .ok_or(Error::DeliveryRecipientMissing)?,
    };
    let info = ops.key_info(id)?;
    if let Some(bound) = &info.recipient_fingerprint {
        if !bound.eq_ignore_ascii_case(&keys::fingerprint(&recipient.public_key)) {
            return Err(Error::InvalidApiKeyRequest);
        }
    }
    Ok(recipient)
}

fn deliver_bundle(
    ops: &mut impl DeliveryOps,
    identity: &ProviderIdentity,
    created: CreatedApiKey,
    recipient: &Recipient,
    write: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<Delivered> {
    let issue = issue_for(ops, identity, &created, recipient)?;
    let bundle = api_key_delivery::seal_bundle(identity, &recipient.public_key, &issue)?;
    write(&bundle)?;
    let via = Via::Bundle {
        sha256: hex::encode(Sha256::digest(&bundle)),
    };
    ops.record_delivery(created.info.id, recipient, &via)?;
    Ok(Delivered {
        info: created.info,
        recipient_fingerprint: keys::fingerprint(&recipient.public_key),
        via,
    })
}

fn issue_for(
    ops: &mut impl DeliveryOps,
    identity: &ProviderIdentity,
    created: &CreatedApiKey,
    recipient: &Recipient,
) -> Result<KeyIssue> {
    Ok(KeyIssue {
        relay_url: normalize_url(&recipient.relay_url),
        key_id: created.info.id,
        scope: created.info.scope.clone(),
        token: created.token.clone(),
        issued_at: ops.now_seconds()?,
        expires_at: created.info.expires_at.clone(),
        device_id: recipient.device_id,
        certificate: identity.certificate.clone(),
        licence: recipient.licence.clone(),
    })
}

#[cfg(test)]
#[path = "key_delivery/tests.rs"]
mod tests;
