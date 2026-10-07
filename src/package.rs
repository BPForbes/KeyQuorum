//! `.kqpkg`, the KeyQuorum Package (`KQPK` v1): a signed, declarative setup
//! bundle a provider hands a client (issue #104).
//!
//! A package is a purpose, an issuer, a validity window and a short list of
//! components, each one the unchanged bytes of an artifact another module
//! owns. It adds no cryptography of its own beyond one signature over the
//! whole container, and it is not a sealed envelope: every component keeps
//! its own recipient binding, signature, licence, scope and expiry, and the
//! owning handler still checks them. A valid outer signature never stands in
//! for those checks, and opening a package never executes anything.
//!
//! Dispatch is by the component's own magic, version and kind byte, never by
//! a file name or by the kind the package claims for it ([`classify`]); a
//! claim that disagrees with the bytes is refused. Version 1 knows six
//! components. Everything else (`.kqenc`, `.kqtf`, `.kqhs`, `.kqbs`,
//! `.kqbn`, raw `KQTX`, generic `KQXB` types, other `KQPB` kinds) fails
//! before anything is accepted, as does a component the purpose does not
//! allow. The recipient-sealed provider recovery payload and protected
//! manifest the issue proposes are later slices and have no kind yet.
//!
//! This module only frames, bounds and authenticates. The wizard, drive
//! enrollment and the console generator call it and are not here.
//!
//! Wire layout, big-endian:
//! `"KQPK" version purpose id[16] issued_at(u64) expires_at(u64) issuer[32]
//! count(u16) { kind hash[32] len(u32) bytes }* signature[64]`. Times are
//! Unix seconds. The signature covers [`DOMAIN`] and the SHA-256 of every
//! byte before it. Purpose and kind bytes are wire format: append, never
//! renumber.

use crate::envelope::{self, push_len_prefixed_u32, take_array, take_len_prefixed_u32, take_n};
use crate::error::{Error, Result};
use crate::export;
use crate::provider::{self, policy};
use crate::setup_manifest;
use crate::signing;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const MAGIC: &[u8; 4] = b"KQPK";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"KQ-PACKAGE-v1";
const SIG_LEN: usize = 64;

/// The largest package, in bytes, that is decoded or encoded.
pub const MAX_PACKAGE_BYTES: usize = 16 * 1024 * 1024;
/// The most components one package holds.
pub const MAX_COMPONENTS: usize = 16;
/// The largest single component, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 8 * 1024 * 1024;

/// What a package is for, and so who may sign it and what it may carry. The
/// purpose is authenticated; nothing is inferred from the components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// First delivery to one enrolled client, signed by the relay key.
    ClientSetup,
    /// A credential replacement for an installed client, signed by the relay key.
    ClientUpdate,
    /// Public provider information, signed by the relay key.
    ProviderInfo,
    /// Restoring a relay identity on a provider host, signed by the offline root.
    ProviderRecovery,
}

impl Purpose {
    fn tag(self) -> u8 {
        match self {
            Self::ClientSetup => 1,
            Self::ClientUpdate => 2,
            Self::ProviderInfo => 3,
            Self::ProviderRecovery => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        Ok(match tag {
            1 => Self::ClientSetup,
            2 => Self::ClientUpdate,
            3 => Self::ProviderInfo,
            4 => Self::ProviderRecovery,
            _ => return Err(Error::InvalidKqpkg),
        })
    }

    fn is_client(self) -> bool {
        matches!(self, Self::ClientSetup | Self::ClientUpdate)
    }

    /// The purpose as the console and reports spell it.
    pub fn name(self) -> &'static str {
        match self {
            Self::ClientSetup => "client_setup",
            Self::ClientUpdate => "client_update",
            Self::ProviderInfo => "provider_info",
            Self::ProviderRecovery => "provider_recovery",
        }
    }

    /// Whose package this purpose is.
    pub fn user_type(self) -> UserType {
        if self.is_client() {
            UserType::Client
        } else {
            UserType::Provider
        }
    }
}

/// Who a package is for, derived from its authenticated purpose and never
/// stored apart from it, so the two cannot disagree. An enum rather than a
/// flag so a later kind of user is a new variant, not a second boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserType {
    /// An enrolled customer: installs a licence and credentials.
    Client,
    /// The provider: public information, or restoring its own identity.
    Provider,
}

impl UserType {
    /// The name the console and reports use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "CLIENT",
            Self::Provider => "PROVIDER",
        }
    }
}

/// A component a version 1 package may hold, named by what its bytes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComponentKind {
    /// A provider-root-signed relay certificate (`KQPC`).
    Certificate,
    /// A provider-root-signed revocation list (`KQRL`).
    RevocationList,
    /// A provider-root-signed hardware-authority policy (`KQPL`).
    Policy,
    /// A recipient-sealed relay API key, the `.kqkey` (`KQXB` type 4).
    ApiKeyBundle,
    /// A recipient-sealed relay API key letter (`KQPB` kind 20).
    ApiKeyLetter,
    /// The package's typed setup steps (`KQXB` type 6, `setup_manifest`): sealed
    /// to the recipient, signed by the relay, bound to this package.
    SetupManifest,
}

impl ComponentKind {
    fn tag(self) -> u8 {
        match self {
            Self::Certificate => 1,
            Self::RevocationList => 2,
            Self::Policy => 3,
            Self::ApiKeyBundle => 4,
            Self::ApiKeyLetter => 5,
            Self::SetupManifest => 6,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        Ok(match tag {
            1 => Self::Certificate,
            2 => Self::RevocationList,
            3 => Self::Policy,
            4 => Self::ApiKeyBundle,
            5 => Self::ApiKeyLetter,
            6 => Self::SetupManifest,
            _ => return Err(Error::KqpkgComponentRejected),
        })
    }

    /// A sealed customer API key, installed through the verified key path.
    pub fn carries_key(self) -> bool {
        matches!(self, Self::ApiKeyBundle | Self::ApiKeyLetter)
    }

    /// Whether `purpose` may carry this kind. Customer keys travel only in
    /// client purposes; revocation lists and policies only in provider ones.
    fn allowed_in(self, purpose: Purpose) -> bool {
        match self {
            Self::Certificate => true,
            Self::RevocationList | Self::Policy => !purpose.is_client(),
            Self::ApiKeyBundle | Self::ApiKeyLetter | Self::SetupManifest => purpose.is_client(),
        }
    }
}

/// One component: its claimed kind and the unchanged bytes of the artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub kind: ComponentKind,
    pub bytes: Vec<u8>,
}

/// A decoded, signature-checked package. The issuer key is the one that
/// signed it; whether that key is the right one for the purpose is
/// [`Package::verify_issuer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub purpose: Purpose,
    pub id: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    pub issuer: [u8; 32],
    pub components: Vec<Component>,
}

/// What a component's own bytes say it is, from its magic, version and kind
/// byte alone. Anything this version has no handler for is
/// [`Error::KqpkgComponentRejected`], so a new artifact kind never slips in
/// by looking like an old one.
pub fn classify(bytes: &[u8]) -> Result<ComponentKind> {
    let magic = bytes.get(..4).ok_or(Error::KqpkgComponentRejected)?;
    if magic == provider::CERT_MAGIC {
        return Ok(ComponentKind::Certificate);
    }
    if magic == provider::KRL_MAGIC {
        return Ok(ComponentKind::RevocationList);
    }
    if magic == policy::POLICY_MAGIC {
        return Ok(ComponentKind::Policy);
    }
    match envelope::format_of(bytes) {
        Some(format) if format == envelope::PACKAGE => {
            match envelope::parse_outer(bytes).map_err(|_| Error::KqpkgComponentRejected)? {
                (envelope::KIND_API_KEY_ISSUE, _, _) => Ok(ComponentKind::ApiKeyLetter),
                _ => Err(Error::KqpkgComponentRejected),
            }
        }
        Some(format) if format == envelope::EXPORT_BUNDLE => {
            match envelope::parse_outer_as(format, bytes)
                .map_err(|_| Error::KqpkgComponentRejected)?
            {
                (export::BUNDLE_TYPE_API_KEY, _, _) => Ok(ComponentKind::ApiKeyBundle),
                (export::BUNDLE_TYPE_SETUP_MANIFEST, _, _) => Ok(ComponentKind::SetupManifest),
                _ => Err(Error::KqpkgComponentRejected),
            }
        }
        _ => Err(Error::KqpkgComponentRejected),
    }
}

/// Every component is what it claims, is allowed in `purpose`, and the set
/// has the shape the purpose needs. Run before encoding and after decoding,
/// so no purpose ever installs a component it should not.
fn check_components(purpose: Purpose, components: &[Component]) -> Result<()> {
    if components.len() > MAX_COMPONENTS {
        return Err(Error::InvalidKqpkg);
    }
    let mut seen = HashSet::new();
    let mut keys = 0usize;
    for component in components {
        if component.bytes.len() > MAX_COMPONENT_BYTES {
            return Err(Error::InvalidKqpkg);
        }
        if classify(&component.bytes)? != component.kind || !component.kind.allowed_in(purpose) {
            return Err(Error::KqpkgComponentRejected);
        }
        if component.kind.carries_key() {
            keys += 1;
        } else if !seen.insert(component.kind) {
            return Err(Error::KqpkgComponentRejected);
        }
    }
    let certificates = usize::from(seen.contains(&ComponentKind::Certificate));
    if certificates != 1 {
        return Err(Error::KqpkgComponentRejected);
    }
    if purpose.is_client() && keys == 0 {
        return Err(Error::KqpkgComponentRejected);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + 32);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&digest(body));
    message
}

/// Encodes and signs `package` with the issuer's 32-byte seed. Refuses a
/// package its own purpose would refuse to open, and one whose `issuer` is
/// not the signing key's public half.
pub fn encode(package: &Package, issuer_private_key: &[u8; 32]) -> Result<Vec<u8>> {
    let public = SigningKey::from_bytes(issuer_private_key)
        .verifying_key()
        .to_bytes();
    if public != package.issuer || package.expires_at <= package.issued_at {
        return Err(Error::InvalidKqpkg);
    }
    check_components(package.purpose, &package.components)?;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(package.purpose.tag());
    out.extend_from_slice(&package.id);
    out.extend_from_slice(&package.issued_at.to_be_bytes());
    out.extend_from_slice(&package.expires_at.to_be_bytes());
    out.extend_from_slice(&package.issuer);
    let count = u16::try_from(package.components.len()).map_err(|_| Error::InvalidKqpkg)?;
    out.extend_from_slice(&count.to_be_bytes());
    for component in &package.components {
        out.push(component.kind.tag());
        out.extend_from_slice(&digest(&component.bytes));
        push_len_prefixed_u32(&mut out, &component.bytes).map_err(|_| Error::InvalidKqpkg)?;
    }
    let signature = signing::sign(issuer_private_key, &signed_message(&out));
    out.extend_from_slice(&signature);
    if out.len() > MAX_PACKAGE_BYTES {
        return Err(Error::InvalidKqpkg);
    }
    Ok(out)
}

/// Decodes a package with bounded parsing and checks the structure, every
/// component hash, the component allowlist for the purpose and the
/// signature under the embedded issuer key. It does not check the validity
/// window ([`Package::check_valid_at`]) or that the issuer is the right one
/// ([`Package::verify_issuer`]), and it opens nothing.
pub fn decode(bytes: &[u8]) -> Result<Package> {
    let malformed = |_| Error::InvalidKqpkg;
    if bytes.len() > MAX_PACKAGE_BYTES || bytes.len() < SIG_LEN {
        return Err(Error::InvalidKqpkg);
    }
    let (body, signature) = bytes.split_at(bytes.len() - SIG_LEN);
    let mut data = body;
    if take_n(&mut data, 4).map_err(malformed)? != MAGIC {
        return Err(Error::InvalidKqpkg);
    }
    if take_array::<1>(&mut data).map_err(malformed)?[0] != VERSION {
        return Err(Error::InvalidKqpkg);
    }
    let purpose = Purpose::from_tag(take_array::<1>(&mut data).map_err(malformed)?[0])?;
    let id = take_array::<16>(&mut data).map_err(malformed)?;
    let issued_at = u64::from_be_bytes(take_array(&mut data).map_err(malformed)?);
    let expires_at = u64::from_be_bytes(take_array(&mut data).map_err(malformed)?);
    let issuer = take_array::<32>(&mut data).map_err(malformed)?;
    let count = u16::from_be_bytes(take_array(&mut data).map_err(malformed)?) as usize;
    if count > MAX_COMPONENTS {
        return Err(Error::InvalidKqpkg);
    }
    let mut components = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = ComponentKind::from_tag(take_array::<1>(&mut data).map_err(malformed)?[0])?;
        let hash = take_array::<32>(&mut data).map_err(malformed)?;
        let component = take_len_prefixed_u32(&mut data).map_err(malformed)?;
        if component.len() > MAX_COMPONENT_BYTES || digest(component) != hash {
            return Err(Error::InvalidKqpkg);
        }
        components.push(Component {
            kind,
            bytes: component.to_vec(),
        });
    }
    if !data.is_empty() {
        return Err(Error::InvalidKqpkg);
    }
    let signature: [u8; SIG_LEN] = signature.try_into().map_err(|_| Error::InvalidKqpkg)?;
    signing::verify_signature(&issuer, &signed_message(body), &signature)
        .map_err(|_| Error::InvalidKqpkg)?;
    if expires_at <= issued_at {
        return Err(Error::InvalidKqpkg);
    }
    check_components(purpose, &components)?;
    Ok(Package {
        purpose,
        id,
        issued_at,
        expires_at,
        issuer,
        components,
    })
}

/// A `ClientSetup` package for `.kqkey` bundles the relay just sealed: the
/// relay's own certificate, the sealed keys (at least one, at most fourteen) and
/// the setup manifest that says what `keyquorum setup` does with them
/// ([`setup_manifest`]), signed with the relay key, valid for `valid_days` (1 to
/// 365) from `issued_at`, under a fresh random id. The manifest is sealed to
/// `recipient` and bound to this package's id, to that recipient and to
/// `device_id`. The sealed keys are not opened or altered, and the package holds
/// no bearer in the clear.
pub fn issue_client_package(
    identity: &crate::relay::ProviderIdentity,
    sealed_keys: &[&[u8]],
    recipient: &[u8; 32],
    device_id: Option<[u8; 16]>,
    issued_at: u64,
    valid_days: u64,
) -> Result<Vec<u8>> {
    if !(1..=365).contains(&valid_days) || sealed_keys.is_empty() {
        return Err(Error::InvalidKqpkg);
    }
    let mut id = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    let expires_at = issued_at + valid_days * 86_400;
    let certificate = certificate_component(identity);
    let certificate_hash = setup_manifest::hash_of(&certificate.bytes);
    let key_hashes: Vec<String> = sealed_keys
        .iter()
        .map(|sealed| setup_manifest::hash_of(sealed))
        .collect();
    let manifest = setup_manifest::seal(
        identity,
        recipient,
        &setup_manifest::Body {
            version: setup_manifest::VERSION,
            package_id: hex::encode(id),
            purpose: Purpose::ClientSetup.name().to_string(),
            recipient: hex::encode(recipient),
            device_id: device_id.map(hex::encode),
            expires_at,
            operations: setup_manifest::standard_operations(&certificate_hash, &key_hashes),
        },
    )?;
    let mut components = vec![certificate];
    components.extend(sealed_keys.iter().map(|sealed| Component {
        kind: ComponentKind::ApiKeyBundle,
        bytes: sealed.to_vec(),
    }));
    components.push(Component {
        kind: ComponentKind::SetupManifest,
        bytes: manifest,
    });
    issue_with_id(
        identity,
        Purpose::ClientSetup,
        id,
        components,
        issued_at,
        valid_days,
    )
}

/// A `ProviderInfo` package: the relay's own certificate and nothing else
/// from this relay (it holds no revocation list or policy to add). Public
/// information, signed with the relay key.
pub fn issue_provider_info_package(
    identity: &crate::relay::ProviderIdentity,
    issued_at: u64,
    valid_days: u64,
) -> Result<Vec<u8>> {
    issue(
        identity,
        Purpose::ProviderInfo,
        vec![certificate_component(identity)],
        issued_at,
        valid_days,
    )
}

fn certificate_component(identity: &crate::relay::ProviderIdentity) -> Component {
    Component {
        kind: ComponentKind::Certificate,
        bytes: identity.certificate.clone(),
    }
}

fn issue(
    identity: &crate::relay::ProviderIdentity,
    purpose: Purpose,
    components: Vec<Component>,
    issued_at: u64,
    valid_days: u64,
) -> Result<Vec<u8>> {
    let mut id = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    issue_with_id(identity, purpose, id, components, issued_at, valid_days)
}

fn issue_with_id(
    identity: &crate::relay::ProviderIdentity,
    purpose: Purpose,
    id: [u8; 16],
    components: Vec<Component>,
    issued_at: u64,
    valid_days: u64,
) -> Result<Vec<u8>> {
    if !(1..=365).contains(&valid_days) {
        return Err(Error::InvalidKqpkg);
    }
    let certificate = provider::parse_certificate(&identity.certificate)?;
    encode(
        &Package {
            purpose,
            id,
            issued_at,
            expires_at: issued_at + valid_days * 86_400,
            issuer: certificate.relay_public_key,
            components,
        },
        &identity.relay_private_key,
    )
}

impl Package {
    /// The package is inside its validity window at `now` (Unix seconds).
    pub fn check_valid_at(&self, now: u64) -> Result<()> {
        if now < self.issued_at || now >= self.expires_at {
            return Err(Error::KqpkgExpired);
        }
        Ok(())
    }

    /// The signer is the one this purpose requires. A relay purpose must be
    /// signed by the key its own `KQPC` certificate names, and that
    /// certificate must verify against `root_public_key` at `now_utc`
    /// ("YYYY-MM-DD HH:MM:SS") and not be revoked. A recovery package must be
    /// signed by the root itself. The root is the caller's pinned one, never
    /// anything the package carries.
    pub fn verify_issuer(
        &self,
        root_public_key: &[u8; 32],
        now_utc: &str,
        revoked: &HashSet<String>,
    ) -> Result<()> {
        if self.purpose == Purpose::ProviderRecovery {
            return if &self.issuer == root_public_key {
                Ok(())
            } else {
                Err(Error::KqpkgIssuerUntrusted)
            };
        }
        let certificate = self
            .components
            .iter()
            .find(|c| c.kind == ComponentKind::Certificate)
            .ok_or(Error::KqpkgComponentRejected)?;
        let verified =
            provider::verify_certificate(root_public_key, &certificate.bytes, now_utc, revoked)?;
        if verified.relay_public_key != self.issuer {
            return Err(Error::KqpkgIssuerUntrusted);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "package/tests.rs"]
mod tests;
