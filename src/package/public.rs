//! A package checked as far as anyone without the recipient's key can check
//! it (issue #108): the operator console runs this in the browser
//! (`provision_wasm::verify_package`), and it is the same code `setup` and
//! `host recovery install` start with. The signature, every component hash,
//! the component allowlist for the purpose, the validity window, the signer
//! (the relay a root-verified certificate names, or the root itself for
//! recovery) and the certificate are checked against a root the caller pins;
//! the sealed parts are read only as far as their public header, and they
//! must all be sealed to one recipient. Nothing sealed is opened, so a sealed
//! key, setup step or recovery payload is checked only by the native command
//! that installs it; this says so rather than claim more.

use super::{decode, ComponentKind, Purpose};
use crate::envelope;
use crate::error::{Error, Result};
use crate::provider;
use serde::Serialize;
use std::collections::HashSet;

/// One component as the public check sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicComponent {
    pub kind: &'static str,
    pub sha256: String,
    pub bytes: usize,
    /// The X25519 key a sealed component is sealed to, hex.
    pub sealed_to: Option<String>,
}

/// What a package is, once checked. Everything here is public.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicCheck {
    pub purpose: &'static str,
    pub user_type: &'static str,
    pub package_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// `relay` or `root`: who signed the package.
    pub signed_by: &'static str,
    pub provider_id: String,
    pub serial: String,
    pub certificate_expires_at: String,
    /// The one recipient every sealed part is sealed to, hex, if any part is.
    pub sealed_to: Option<String>,
    pub components: Vec<PublicComponent>,
}

/// Checks `bytes` against `root` at `now_utc` (`YYYY-MM-DD HH:MM:SS`) with
/// `revoked` serials. Opens nothing; see the module documentation.
pub fn verify(
    bytes: &[u8],
    root: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<PublicCheck> {
    let package = decode(bytes)?;
    package.check_valid_at(provider::unix_from_utc(now_utc)?)?;
    package.verify_issuer(root, now_utc, revoked)?;
    let certificate = package
        .components
        .iter()
        .find(|c| c.kind == ComponentKind::Certificate)
        .ok_or(Error::KqpkgComponentRejected)?;
    let verified = provider::verify_certificate(root, &certificate.bytes, now_utc, revoked)?;
    let mut sealed_to = None;
    let mut components = Vec::new();
    for component in &package.components {
        let recipient = sealed_recipient(component.kind, &component.bytes)?;
        if let Some(recipient) = &recipient {
            match &sealed_to {
                None => sealed_to = Some(recipient.clone()),
                Some(first) if first != recipient => {
                    return Err(Error::KqpkgRefused(
                        "its sealed parts are sealed to different recipients".into(),
                    ))
                }
                Some(_) => {}
            }
        }
        components.push(PublicComponent {
            kind: component.kind.name(),
            sha256: crate::setup_manifest::hash_of(&component.bytes),
            bytes: component.bytes.len(),
            sealed_to: recipient,
        });
    }
    Ok(PublicCheck {
        purpose: package.purpose.name(),
        user_type: package.purpose.user_type().as_str(),
        package_id: hex::encode(package.id),
        issued_at: package.issued_at,
        expires_at: package.expires_at,
        signed_by: if package.purpose == Purpose::ProviderRecovery {
            "root"
        } else {
            "relay"
        },
        provider_id: verified.provider_id,
        serial: verified.serial,
        certificate_expires_at: verified.expires_at,
        sealed_to,
        components,
    })
}

/// The recipient in a sealed component's public header; `None` for a
/// component that is not sealed.
fn sealed_recipient(kind: ComponentKind, bytes: &[u8]) -> Result<Option<String>> {
    let format = match kind {
        ComponentKind::ApiKeyLetter => envelope::PACKAGE,
        ComponentKind::ApiKeyBundle
        | ComponentKind::SetupManifest
        | ComponentKind::RecoveryPayload => envelope::EXPORT_BUNDLE,
        ComponentKind::Certificate | ComponentKind::RevocationList | ComponentKind::Policy => {
            return Ok(None)
        }
    };
    let (_, recipient, _) =
        envelope::parse_outer_as(format, bytes).map_err(|_| Error::KqpkgComponentRejected)?;
    Ok(Some(hex::encode(recipient)))
}
