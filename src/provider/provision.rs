//! A provider's whole identity made in one step: the root keypair, the relay
//! keypair, the certificate the root signs for the relay and the public
//! `ProviderInfo` package, built in memory and checked the way the relay and
//! every client check them (`provider::self_check`) before anything is
//! handed back. `keyquorum host provision` writes the result to files and the
//! operator console's setup guide (`console` feature, `provision_wasm.rs`)
//! offers the same files for download in the browser. Nothing here stores,
//! prints or sends a key: that is the caller's responsibility, and the two
//! callers above hand the private halves only to the operator.

use super::{issue_certificate, self_check, NewCertificate};
use crate::error::Result;
use crate::relay::ProviderIdentity;
use zeroize::Zeroizing;

/// What the certificate names; the keys are made here.
pub struct Spec<'a> {
    pub provider_id: &'a str,
    pub serial: &'a str,
    pub issued_at: &'a str,
    pub expires_at: &'a str,
    pub capabilities: u32,
    pub issuer_id: &'a str,
}

/// The result: two keypairs, the certificate and the package. The private
/// halves are zeroized when this is dropped.
pub struct Identity {
    pub root_private_key: Zeroizing<[u8; 32]>,
    pub root_public_key: [u8; 32],
    pub relay_private_key: Zeroizing<[u8; 32]>,
    pub relay_public_key: [u8; 32],
    /// `provider.kqcert`
    pub certificate: Vec<u8>,
    /// `provider-info.kqpkg`, signed by the relay key.
    pub package: Vec<u8>,
}

/// The `ProviderInfo` package made at provisioning is good for this long; the
/// console issues a fresh one at any time.
pub const PACKAGE_VALID_DAYS: u64 = 30;

/// Makes the identity. `now_utc` is the current time (`YYYY-MM-DD HH:MM:SS`),
/// passed in because the wasm build reads no clock; the certificate must be
/// valid at it, so a spec that would already be expired is refused with
/// nothing made.
pub fn provision(spec: &Spec<'_>, now_utc: &str) -> Result<Identity> {
    let (root_private_key, root_public_key) = crate::keys::generate_signing_keypair();
    let (relay_private_key, relay_public_key) = super::generate_relay_identity();
    let certificate = issue_certificate(
        &root_private_key,
        &NewCertificate {
            provider_id: spec.provider_id,
            serial: spec.serial,
            relay_public_key: &relay_public_key,
            issued_at: spec.issued_at,
            expires_at: spec.expires_at,
            capabilities: spec.capabilities,
            issuer_id: spec.issuer_id,
        },
    )?;
    self_check(
        &root_public_key,
        &certificate,
        &relay_private_key,
        now_utc,
        &std::collections::HashSet::new(),
    )?;
    let identity = ProviderIdentity {
        certificate: certificate.clone(),
        relay_private_key: relay_private_key.clone(),
    };
    let package = crate::package::issue_provider_info_package(
        &identity,
        super::unix_from_utc(now_utc)?,
        PACKAGE_VALID_DAYS,
    )?;
    Ok(Identity {
        root_private_key,
        root_public_key,
        relay_private_key,
        relay_public_key,
        certificate,
        package,
    })
}

#[cfg(test)]
#[path = "provision/tests.rs"]
mod tests;
