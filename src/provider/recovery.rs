//! Provider recovery (issue #107): a relay identity restored on a provider
//! host from a root-signed `ProviderRecovery` `.kqpkg`.
//!
//! The package holds two components: the relay's `KQPC` certificate and a
//! recovery payload (`KQXB` type 5) sealed to an operator key enrolled for
//! recovery (`host recovery keygen`, its fingerprint confirmed out of band
//! when the package is issued). The payload is the relay's private key and
//! a context the offline root signs: the purpose, the package id, the
//! operator key it is sealed to, the provider id, serial and relay public
//! key the certificate names, the certificate's SHA-256, the validity window
//! and the closed list of operations an installer runs. The root private key
//! is never in it, nor anything but that one relay key.
//!
//! Sealing is custody, not authority: opening the payload proves only that
//! the operator key opened it. [`open`] trusts it only when the package and
//! the context are signed by the root the caller pins (never a root the
//! package carries), every context field matches the package and the
//! certificate, the certificate verifies against that root, unrevoked and
//! valid now, and the key derived from the recovered secret is the one the
//! certificate names (`provider::self_check`). [`install`] (native only)
//! writes the key and the certificate into a directory the operator names,
//! owner-only and never over a different file, and checks the result before
//! it reports success.
//!
//! Restoring these files configures nothing else: no Worker secret, deploy
//! variable or platform credential is set, and deploying the restored
//! identity is a separate, separately approved operation.
//!
//! Payload layout (before sealing): `context_len(u32) context_json
//! relay_secret[32] signature[64]`, the signature by the root over
//! [`signing::provider_recovery_preimage`] of the context bytes.

use crate::envelope::{self, push_len_prefixed_u32, take_array, take_len_prefixed_u32};
use crate::error::{Error, Result};
use crate::export::BUNDLE_TYPE_PROVIDER_RECOVERY;
use crate::package::{self, Component, ComponentKind, Package, Purpose};
use crate::signing;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use zeroize::Zeroizing;

/// The context's schema version.
pub const VERSION: u32 = 1;
/// The longest a recovery package may be valid. It carries a private key,
/// so it is short-lived; a lost or expired one is replaced by issuing again.
pub const MAX_VALID_DAYS: u64 = 7;
/// The largest context, in bytes.
const MAX_CONTEXT_BYTES: usize = 16 * 1024;
const PURPOSE: &str = "provider_recovery";

/// The steps a recovery installer runs, a closed list separate from the
/// client setup manifest's: a recovery package never installs a customer key
/// and a client package never installs a relay key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// Write the relay's private key as `relay.key`.
    InstallRelayKey,
    /// Write the relay's certificate as `provider.kqcert`.
    InstallCertificate,
}

/// The only operation list this version runs, in order.
pub const OPERATIONS: [Operation; 2] = [Operation::InstallRelayKey, Operation::InstallCertificate];

/// What the root signs. Public: it holds no secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub version: u32,
    pub purpose: String,
    pub package_id: String,
    /// The operator's X25519 public key the payload is sealed to, hex.
    pub recipient: String,
    pub provider_id: String,
    pub serial: String,
    pub relay_public_key: String,
    pub certificate_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub operations: Vec<Operation>,
}

/// What [`issue`] needs. The root key is read, used and zeroized by the
/// caller; it never enters the package.
pub struct Issue<'a> {
    pub root_private_key: &'a [u8; 32],
    pub relay_private_key: &'a [u8; 32],
    pub certificate: &'a [u8],
    /// The enrolled operator key, whose fingerprint the caller confirmed.
    pub recipient: &'a [u8; 32],
    /// `YYYY-MM-DD HH:MM:SS`
    pub now_utc: &'a str,
    pub valid_days: u64,
    pub revoked: &'a HashSet<String>,
}

/// A recovery payload opened and checked. The private key is zeroized when
/// this is dropped, and `Debug` never shows it.
pub struct Recovered {
    pub package_id: String,
    pub provider_id: String,
    pub serial: String,
    pub certificate_expires_at: String,
    pub relay_public_key: [u8; 32],
    pub certificate: Vec<u8>,
    pub relay_private_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Recovered {
    /// The public fields only; the relay private key prints as `[redacted]`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovered")
            .field("package_id", &self.package_id)
            .field("provider_id", &self.provider_id)
            .field("serial", &self.serial)
            .field("relay_public_key", &hex::encode(self.relay_public_key))
            .field("relay_private_key", &"[redacted]")
            .finish()
    }
}

/// The fingerprint of an operator recovery key, compared out of band before
/// a package is sealed to it: its SHA-256 in groups of eight hex digits.
pub fn recipient_fingerprint(public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public_key))
        .as_bytes()
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `given` is `public_key`'s fingerprint, ignoring spaces and case.
pub fn fingerprint_matches(public_key: &[u8; 32], given: &str) -> bool {
    let normalize = |text: &str| {
        text.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    normalize(given) == normalize(&recipient_fingerprint(public_key))
}

/// A recovery refusal, naming what was wrong and never a key.
fn refused(reason: &str) -> Error {
    Error::KqpkgRefused(format!("provider recovery: {reason}"))
}

/// The SHA-256 of `bytes`, lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Builds a root-signed `ProviderRecovery` package for the identity in
/// `spec`, sealed to the operator key. The identity is checked first exactly
/// as a relay checks itself (`provider::self_check` against the root whose
/// key signs here, unrevoked and valid now), so a package is never made for
/// an identity that would not install. The package expires after
/// `valid_days` (1 to [`MAX_VALID_DAYS`]) or when the certificate does,
/// whichever is sooner.
pub fn issue(spec: &Issue<'_>) -> Result<Vec<u8>> {
    if !(1..=MAX_VALID_DAYS).contains(&spec.valid_days) {
        return Err(refused("valid days must be 1 to 7"));
    }
    let root_public = SigningKey::from_bytes(spec.root_private_key)
        .verifying_key()
        .to_bytes();
    let certificate = super::self_check(
        &root_public,
        spec.certificate,
        spec.relay_private_key,
        spec.now_utc,
        spec.revoked,
    )?;
    let issued_at = super::unix_from_utc(spec.now_utc)?;
    let expires_at =
        (issued_at + spec.valid_days * 86_400).min(super::unix_from_utc(&certificate.expires_at)?);
    if expires_at <= issued_at {
        return Err(refused("the certificate expires too soon"));
    }
    let mut id = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    let context = Context {
        version: VERSION,
        purpose: PURPOSE.to_string(),
        package_id: hex::encode(id),
        recipient: hex::encode(spec.recipient),
        provider_id: certificate.provider_id,
        serial: certificate.serial,
        relay_public_key: hex::encode(certificate.relay_public_key),
        certificate_sha256: sha256_hex(spec.certificate),
        issued_at,
        expires_at,
        operations: OPERATIONS.to_vec(),
    };
    let payload = seal_context(
        spec.root_private_key,
        spec.recipient,
        &context,
        spec.relay_private_key,
    )?;
    package::encode(
        &Package {
            purpose: Purpose::ProviderRecovery,
            id,
            issued_at,
            expires_at,
            issuer: root_public,
            components: vec![
                Component {
                    kind: ComponentKind::Certificate,
                    bytes: spec.certificate.to_vec(),
                },
                Component {
                    kind: ComponentKind::RecoveryPayload,
                    bytes: payload,
                },
            ],
        },
        spec.root_private_key,
    )
}

/// Signs `context` with the root and seals it with the relay key to
/// `recipient` as `KQXB` type 5. The plaintext is zeroized when dropped.
pub(crate) fn seal_context(
    root_private_key: &[u8; 32],
    recipient: &[u8; 32],
    context: &Context,
    relay_private_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(context).map_err(|_| refused("context"))?;
    if json.len() > MAX_CONTEXT_BYTES {
        return Err(refused("context too large"));
    }
    let signature = signing::sign(
        root_private_key,
        &signing::provider_recovery_preimage(&json),
    );
    let mut payload = Zeroizing::new(Vec::with_capacity(json.len() + 100));
    push_len_prefixed_u32(&mut payload, &json)?;
    payload.extend_from_slice(relay_private_key);
    payload.extend_from_slice(&signature);
    envelope::seal(
        envelope::EXPORT_BUNDLE,
        BUNDLE_TYPE_PROVIDER_RECOVERY,
        recipient,
        &payload,
    )
}

/// Opens and checks a recovery package with the operator's X25519 secret
/// against `root` (the caller's pinned root), at `now_utc`, with `revoked`
/// serials. Everything is checked before anything is returned; nothing is
/// written. See the module documentation for the checks.
pub fn open(
    bytes: &[u8],
    operator_secret: &[u8; 32],
    root: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<Recovered> {
    let package = package::decode(bytes)?;
    if package.purpose != Purpose::ProviderRecovery {
        return Err(refused("this is not a provider recovery package"));
    }
    package.check_valid_at(super::unix_from_utc(now_utc)?)?;
    package.verify_issuer(root, now_utc, revoked)?;
    let component = |kind| {
        package
            .components
            .iter()
            .find(|c| c.kind == kind)
            .map(|c| c.bytes.as_slice())
            .ok_or(Error::KqpkgComponentRejected)
    };
    let certificate = component(ComponentKind::Certificate)?;
    let sealed = component(ComponentKind::RecoveryPayload)?;

    let operator_public = crate::keys::encryption_public_from_secret(operator_secret);
    let (kind, sealed_to, payload) =
        envelope::open_as(envelope::EXPORT_BUNDLE, sealed, operator_secret)
            .map_err(|_| refused("the payload does not open with this operator key"))?;
    if kind != BUNDLE_TYPE_PROVIDER_RECOVERY || sealed_to != operator_public {
        return Err(refused("the payload is not sealed to this operator key"));
    }
    let mut data: &[u8] = &payload;
    let json = take_len_prefixed_u32(&mut data).map_err(|_| refused("malformed payload"))?;
    if json.len() > MAX_CONTEXT_BYTES {
        return Err(refused("context too large"));
    }
    let relay_private_key =
        Zeroizing::new(take_array::<32>(&mut data).map_err(|_| refused("malformed payload"))?);
    let signature = take_array::<64>(&mut data).map_err(|_| refused("malformed payload"))?;
    if !data.is_empty() {
        return Err(refused("malformed payload"));
    }
    signing::verify_signature(root, &signing::provider_recovery_preimage(json), &signature)
        .map_err(|_| refused("the context is not signed by the pinned root"))?;
    let context: Context =
        serde_json::from_slice(json).map_err(|_| refused("the context is not understood"))?;

    let verified = super::self_check(root, certificate, &relay_private_key, now_utc, revoked)?;
    let expected = Context {
        version: VERSION,
        purpose: PURPOSE.to_string(),
        package_id: hex::encode(package.id),
        recipient: hex::encode(operator_public),
        provider_id: verified.provider_id.clone(),
        serial: verified.serial.clone(),
        relay_public_key: hex::encode(verified.relay_public_key),
        certificate_sha256: sha256_hex(certificate),
        issued_at: package.issued_at,
        expires_at: package.expires_at,
        operations: OPERATIONS.to_vec(),
    };
    if context.operations != expected.operations {
        return Err(refused(
            "the package asks for operations this version does not run",
        ));
    }
    if context != expected {
        return Err(refused(
            "the signed context does not match the package, the operator key or the certificate",
        ));
    }
    Ok(Recovered {
        package_id: context.package_id,
        provider_id: verified.provider_id,
        serial: verified.serial,
        certificate_expires_at: verified.expires_at,
        relay_public_key: verified.relay_public_key,
        certificate: certificate.to_vec(),
        relay_private_key,
    })
}

#[cfg(not(target_arch = "wasm32"))]
mod install;
#[cfg(not(target_arch = "wasm32"))]
pub use install::{
    dispose_package, install, install_and_dispose, plan_install, verify_installed, Disposal,
    FileAction, InstallPlan, CERTIFICATE_FILE, RELAY_KEY_FILE,
};

#[cfg(test)]
#[path = "recovery/tests.rs"]
mod tests;
