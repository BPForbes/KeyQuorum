//! The setup manifest of a `.kqpkg` (`KQXB` type 6, issue #104): the ordered,
//! typed steps `keyquorum setup` runs to unfold a package, link its parts and
//! make them work.
//!
//! These are not commands in any shell sense. There is no text to run, no
//! script, no path and no URL: each step is one of a closed set of operations
//! (below), each mapped to a handler this crate already has, and every step that
//! touches a package part names it by the SHA-256 of its bytes. An operation this
//! version does not know fails the whole package before anything is written
//! (`deny_unknown_fields`, a closed tag), and adding one is a code change that
//! is reviewed, not something a package can ask for.
//!
//! The manifest is sealed to the one recipient (only their slot opens it, so a
//! preview needs the local passphrase), signed by the relay over a
//! domain-separated preimage with the certificate that names the signing key
//! (so it authenticates on its own, not only through the package around it), and
//! bound to one package, one recipient, optionally one device, and an expiry. A
//! manifest lifted into another package, opened by another person, or aimed at
//! another drive is refused ([`Body::check_against`]). Recipient sealing alone
//! authenticates no one; the signature does.

use crate::envelope::{self, EXPORT_BUNDLE};
use crate::error::{Error, Result};
use crate::export::BUNDLE_TYPE_SETUP_MANIFEST;
use crate::package::{ComponentKind, Package};
use crate::relay::ProviderIdentity;
use crate::{provider, signing};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// The manifest format. A reader refuses any other: version 1, which carried
/// no generation, is refused rather than read as generation zero (issue #106).
pub const VERSION: u32 = 2;
/// The most steps one manifest holds.
pub const MAX_OPERATIONS: usize = 32;
/// A sealed manifest is never larger than this.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// One step. A closed set: an unknown `op`, or an unknown field, is an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// The drive's container, the slot, its registered keys and their binding
    /// exist: `setup`'s identity steps, each skipped when already done. It never
    /// replaces an identity.
    EnsureIdentity {
        id: String,
        #[serde(default)]
        needs: Vec<String>,
    },
    /// Place the relay certificate (the package part with this SHA-256) beside
    /// the container as `provider.kqcert`: identical bytes are kept, different
    /// bytes are refused.
    InstallCertificate {
        id: String,
        #[serde(default)]
        needs: Vec<String>,
        component: String,
    },
    /// Open the sealed key (the part with this SHA-256) with the slot and store
    /// it through the one path `loadkey --bundle` uses, after the relay proves
    /// itself and before any bearer is sent.
    InstallKey {
        id: String,
        #[serde(default)]
        needs: Vec<String>,
        component: String,
    },
    /// Make the relay the key (the part with this SHA-256) was issued for the
    /// stored default (`keyquorum use`).
    UseRelay {
        id: String,
        #[serde(default)]
        needs: Vec<String>,
        key: String,
    },
}

impl Operation {
    pub fn id(&self) -> &str {
        match self {
            Self::EnsureIdentity { id, .. }
            | Self::InstallCertificate { id, .. }
            | Self::InstallKey { id, .. }
            | Self::UseRelay { id, .. } => id,
        }
    }

    pub fn needs(&self) -> &[String] {
        match self {
            Self::EnsureIdentity { needs, .. }
            | Self::InstallCertificate { needs, .. }
            | Self::InstallKey { needs, .. }
            | Self::UseRelay { needs, .. } => needs,
        }
    }

    /// The package part this step names, by SHA-256.
    pub fn component(&self) -> Option<&str> {
        match self {
            Self::EnsureIdentity { .. } => None,
            Self::InstallCertificate { component, .. } | Self::InstallKey { component, .. } => {
                Some(component)
            }
            Self::UseRelay { key, .. } => Some(key),
        }
    }

    /// What the step does, for the preview. Never a secret.
    pub fn describe(&self) -> String {
        match self {
            Self::EnsureIdentity { .. } => {
                "set up the drive identity if it is missing (container, slot, keys, binding)".into()
            }
            Self::InstallCertificate { .. } => {
                "place the relay certificate beside the container".into()
            }
            Self::InstallKey { .. } => {
                "open a sealed key and store it after the relay proves itself".into()
            }
            Self::UseRelay { .. } => "make that relay the default".into(),
        }
    }
}

/// What the manifest says and the relay signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub version: u32,
    /// Hex of the enclosing package's id.
    pub package_id: String,
    /// `client_setup` or `client_update`, as the package's purpose.
    pub purpose: String,
    /// Hex of the recipient's X25519 public key.
    pub recipient: String,
    /// Hex of the one device container this is for, when bound to one.
    pub device_id: Option<String>,
    /// Unix seconds, never later than the package's own end.
    pub expires_at: u64,
    /// The relay's generation for this recipient and device (issue #106):
    /// required, at least 1, and compared by the client with the highest it
    /// has accepted for the same stream, so an older package cannot replace
    /// newer credentials. There is no default: a manifest without it fails.
    pub package_generation: u64,
    /// SHA-256 (hex) of the package's relay certificate, so the manifest is
    /// bound to the certificate it travels with as well as to its signer.
    pub certificate_sha256: String,
    pub operations: Vec<Operation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    body_json: String,
    signature: String,
    certificate: String,
}

/// A manifest that opened and verified.
#[derive(Debug)]
pub struct Opened {
    pub body: Body,
    /// The relay key that signed it, from a root-verified certificate.
    pub relay_public_key: [u8; 32],
}

pub fn hash_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn step_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// The steps a relay-issued client package carries: the identity, the
/// certificate, each key, then the default relay (the first key's).
pub fn standard_operations(certificate_hash: &str, key_hashes: &[String]) -> Vec<Operation> {
    let mut operations = vec![
        Operation::EnsureIdentity {
            id: "identity".into(),
            needs: vec![],
        },
        Operation::InstallCertificate {
            id: "certificate".into(),
            needs: vec!["identity".into()],
            component: certificate_hash.to_string(),
        },
    ];
    for (index, hash) in key_hashes.iter().enumerate() {
        operations.push(Operation::InstallKey {
            id: format!("key-{}", index + 1),
            needs: vec!["certificate".into()],
            component: hash.clone(),
        });
    }
    if let Some(first) = key_hashes.first() {
        operations.push(Operation::UseRelay {
            id: "relay".into(),
            needs: vec!["key-1".into()],
            key: first.clone(),
        });
    }
    operations
}

impl Body {
    /// The manifest's own shape, before it is held against a package: version,
    /// field forms, a bounded list, unique step ids, every dependency naming an
    /// *earlier* step (so the order is the dependency order and no cycle can
    /// exist), one identity step first, the certificate before any key, and a
    /// default-relay step only for a key that is installed.
    pub fn validate(&self) -> Result<()> {
        let bad = Error::InvalidSetupManifest;
        if self.version != VERSION
            || !is_hex(&self.package_id, 32)
            || !is_hex(&self.recipient, 64)
            || !matches!(self.purpose.as_str(), "client_setup" | "client_update")
            || self.device_id.as_deref().is_some_and(|d| !is_hex(d, 32))
            || self.package_generation == 0
            || !is_hex(&self.certificate_sha256, 64)
            || self.operations.is_empty()
            || self.operations.len() > MAX_OPERATIONS
        {
            return Err(bad);
        }
        let mut seen: HashMap<&str, usize> = HashMap::new();
        let mut certificate_step = None;
        let mut key_steps: HashMap<&str, &str> = HashMap::new();
        for (index, operation) in self.operations.iter().enumerate() {
            let id = operation.id();
            if !step_id_ok(id) || seen.insert(id, index).is_some() {
                return Err(Error::InvalidSetupManifest);
            }
            for need in operation.needs() {
                match seen.get(need.as_str()) {
                    Some(at) if *at < index => {}
                    _ => return Err(Error::InvalidSetupManifest),
                }
            }
            if operation.component().is_some_and(|hash| !is_hex(hash, 64)) {
                return Err(Error::InvalidSetupManifest);
            }
            let first = index == 0;
            match operation {
                Operation::EnsureIdentity { needs, .. } => {
                    if !first || !needs.is_empty() {
                        return Err(Error::InvalidSetupManifest);
                    }
                }
                Operation::InstallCertificate { needs, .. } => {
                    if first
                        || certificate_step.is_some()
                        || !needs.iter().any(|n| n == self.operations[0].id())
                    {
                        return Err(Error::InvalidSetupManifest);
                    }
                    certificate_step = Some(id);
                }
                Operation::InstallKey {
                    needs, component, ..
                } => {
                    let after_certificate =
                        certificate_step.is_some_and(|c| needs.iter().any(|n| n == c));
                    if !after_certificate || key_steps.insert(component, id).is_some() {
                        return Err(Error::InvalidSetupManifest);
                    }
                }
                Operation::UseRelay { needs, key, .. } => {
                    let installed = key_steps.get(key.as_str()).copied();
                    if !installed.is_some_and(|step| needs.iter().any(|n| n == step)) {
                        return Err(Error::InvalidSetupManifest);
                    }
                }
            }
        }
        if !matches!(self.operations[0], Operation::EnsureIdentity { .. }) {
            return Err(Error::InvalidSetupManifest);
        }
        if self
            .operations
            .iter()
            .filter(|o| matches!(o, Operation::UseRelay { .. }))
            .count()
            > 1
        {
            return Err(Error::InvalidSetupManifest);
        }
        Ok(())
    }

    /// Holds the manifest against the package it came in and the person and
    /// drive opening it: it must name this package and its purpose, be for this
    /// recipient (and this device, when it says one), not be past its end, and
    /// refer to the package's parts by hash with each part used by exactly one
    /// step: a part no step names is refused, so nothing rides along unseen.
    /// `manifest_at` is the manifest's own place among the package's parts.
    pub fn check_against(
        &self,
        package: &Package,
        manifest_at: usize,
        recipient_public_key: &[u8; 32],
        device_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<()> {
        if self.package_id != hex::encode(package.id)
            || self.purpose != package.purpose.name()
            || self.recipient != hex::encode(recipient_public_key)
            || self
                .device_id
                .as_deref()
                .is_some_and(|d| d != hex::encode(device_id))
            || now_unix >= self.expires_at
            || self.expires_at > package.expires_at
            || !package.components.iter().any(|c| {
                c.kind == ComponentKind::Certificate && hash_of(&c.bytes) == self.certificate_sha256
            })
        {
            return Err(Error::InvalidSetupManifest);
        }
        let mut parts: HashMap<String, ComponentKind> = HashMap::new();
        for (index, component) in package.components.iter().enumerate() {
            if index != manifest_at {
                parts.insert(hash_of(&component.bytes), component.kind);
            }
        }
        let mut used = HashSet::new();
        for operation in &self.operations {
            let Some(hash) = operation.component() else {
                continue;
            };
            let wanted = match operation {
                Operation::InstallCertificate { .. } => &[ComponentKind::Certificate][..],
                _ => &[ComponentKind::ApiKeyBundle, ComponentKind::ApiKeyLetter][..],
            };
            match parts.get(hash) {
                Some(kind) if wanted.contains(kind) => {}
                _ => return Err(Error::KqpkgComponentRejected),
            }
            // The default-relay step names a key a key step already used; every
            // other step claims its part once.
            if !matches!(operation, Operation::UseRelay { .. }) && !used.insert(hash.to_string()) {
                return Err(Error::KqpkgComponentRejected);
            }
        }
        if used.len() != parts.len() {
            return Err(Error::KqpkgComponentRejected);
        }
        Ok(())
    }
}

/// Seals a manifest to `recipient`, signed by the relay key with its
/// certificate. The body is validated first, so the relay never signs a
/// manifest a reader would refuse.
pub fn seal(identity: &ProviderIdentity, recipient: &[u8; 32], body: &Body) -> Result<Vec<u8>> {
    body.validate()?;
    if body.recipient != hex::encode(recipient) {
        return Err(Error::InvalidSetupManifest);
    }
    let body_json = serde_json::to_string(body).map_err(|_| Error::InvalidSetupManifest)?;
    let signature = signing::sign(
        &identity.relay_private_key,
        &signing::relay_setup_manifest_preimage(body_json.as_bytes()),
    );
    let payload = serde_json::to_vec(&Signed {
        body_json,
        signature: hex::encode(signature),
        certificate: STANDARD.encode(&identity.certificate),
    })
    .map_err(|_| Error::InvalidSetupManifest)?;
    let sealed = envelope::seal(
        EXPORT_BUNDLE,
        BUNDLE_TYPE_SETUP_MANIFEST,
        recipient,
        &payload,
    )?;
    if sealed.len() > MAX_MANIFEST_BYTES {
        return Err(Error::InvalidSetupManifest);
    }
    Ok(sealed)
}

/// Opens a manifest with the recipient's encryption secret and verifies it:
/// sealed to this key, a certificate that chains to `root` (unrevoked, valid at
/// `now_utc`, `YYYY-MM-DD HH:MM:SS`) names the key that signed it, the body is
/// well formed and names the recipient it was sealed to.
pub fn open(
    bytes: &[u8],
    secret: &[u8; 32],
    root: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<Opened> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::InvalidSetupManifest);
    }
    let (kind, sealed_to, payload) =
        envelope::open_as(EXPORT_BUNDLE, bytes, secret).map_err(|_| Error::InvalidSetupManifest)?;
    if kind != BUNDLE_TYPE_SETUP_MANIFEST {
        return Err(Error::InvalidSetupManifest);
    }
    let signed: Signed =
        serde_json::from_slice(&payload).map_err(|_| Error::InvalidSetupManifest)?;
    let body: Body =
        serde_json::from_str(&signed.body_json).map_err(|_| Error::InvalidSetupManifest)?;
    let certificate = STANDARD
        .decode(&signed.certificate)
        .map_err(|_| Error::InvalidSetupManifest)?;
    let verified = provider::verify_certificate(root, &certificate, now_utc, revoked)
        .map_err(|_| Error::InvalidSetupManifest)?;
    let signature: [u8; 64] = hex::decode(&signed.signature)
        .ok()
        .and_then(|raw| raw.try_into().ok())
        .ok_or(Error::InvalidSetupManifest)?;
    signing::verify_signature(
        &verified.relay_public_key,
        &signing::relay_setup_manifest_preimage(signed.body_json.as_bytes()),
        &signature,
    )
    .map_err(|_| Error::InvalidSetupManifest)?;
    body.validate()?;
    if body.recipient != hex::encode(sealed_to) {
        return Err(Error::InvalidSetupManifest);
    }
    Ok(Opened {
        body,
        relay_public_key: verified.relay_public_key,
    })
}

#[cfg(test)]
#[path = "setup_manifest/tests.rs"]
mod tests;
