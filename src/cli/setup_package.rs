//! `keyquorum setup <package.kqpkg>`: open a provider's package, show what it
//! would do, and with `--yes` do it (issue #104).
//!
//! The package is read with bounded parsing and everything is checked before
//! a single write: its signature and component hashes ([`package::decode`]),
//! its validity window, that its signer is the relay a root-verified, unrevoked
//! certificate names ([`Package::verify_issuer`], against this environment's
//! pinned root), and that nothing it would write conflicts with what is on the
//! drive. Without `--yes` the plan is printed and nothing is changed.
//!
//! Applying runs the same steps a person would: the identity steps of plain
//! `setup`, the relay certificate placed beside the container (never over a
//! different file), and each sealed key opened with the slot and installed
//! through the one path `loadkey --bundle` and `inbox open` use
//! (`install_key_component`: the relay challenge runs before any bearer is
//! sent). It decides no trust of its own, never prints a bearer, and
//! leaves no bootstrap file behind. Running it again finishes what stopped.
//!
//! It is a real-drive command: an environment that cannot honestly offer it,
//! the browser lab, refuses it ([`env::package_setup`]).

use super::env::{self, outln};
use super::{profile, revocation_list, setup, usage};
use crate::error::Result;
use crate::package::{self, Component, ComponentKind, Package, Purpose};
use crate::provider;
use rusqlite::Connection;
use std::path::Path;

const CERTIFICATE_NAME: &str = "provider.kqcert";

/// A package that passed every check, and what applying it would do.
struct Plan {
    package: Package,
    provider_id: String,
    serial: String,
    certificate_expires: String,
    certificate: Vec<u8>,
    /// The certificate is already on the drive, byte for byte.
    certificate_present: bool,
}

#[inline(never)]
pub(super) fn run(
    conn: &Connection,
    package_path: &Path,
    device: &Path,
    label: &str,
    yes: bool,
) -> Result<()> {
    if !env::package_setup() {
        return Err(usage("setup with a package is not available here"));
    }
    let plan = plan(package_path, device)?;
    show(&plan, device, label);
    match plan.package.purpose {
        Purpose::ClientSetup | Purpose::ClientUpdate => {}
        _ => {
            outln!("This package is information only; nothing to install.");
            return Ok(());
        }
    }
    if !yes {
        outln!("Nothing was changed. Run again with --yes to apply this plan.");
        return Ok(());
    }
    apply(conn, &plan, device, label)
}

/// Read, verify and plan. Writes nothing.
fn plan(package_path: &Path, device: &Path) -> Result<Plan> {
    let bytes = env::read(package_path)?;
    let package = package::decode(&bytes)?;
    let now = env::now_utc()?;
    package.check_valid_at(provider::unix_from_utc(&now)?)?;
    let root = env::provider_root();
    let (revoked, _) = revocation_list(&root)?;
    package.verify_issuer(&root, &now, &revoked)?;
    if package.purpose == Purpose::ProviderRecovery {
        return Err(usage(
            "a provider recovery package is installed on the provider host, not by setup",
        ));
    }
    let certificate = certificate_of(&package)?.bytes.clone();
    let parsed = provider::parse_certificate(&certificate)?;
    let target = device.join(CERTIFICATE_NAME);
    let certificate_present = if env::exists(&target) {
        if env::read(&target)? != certificate {
            return Err(usage(&format!(
                "{} already holds a different certificate; setup will not replace it",
                target.display()
            )));
        }
        true
    } else {
        false
    };
    Ok(Plan {
        package,
        provider_id: parsed.provider_id,
        serial: parsed.serial,
        certificate_expires: parsed.expires_at,
        certificate,
        certificate_present,
    })
}

fn certificate_of(package: &Package) -> Result<&Component> {
    package
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Certificate)
        .ok_or(crate::error::Error::KqpkgComponentRejected)
}

fn kind_name(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Certificate => "relay certificate",
        ComponentKind::RevocationList => "revocation list",
        ComponentKind::Policy => "hardware-authority policy",
        ComponentKind::ApiKeyBundle => "sealed API key (.kqkey)",
        ComponentKind::ApiKeyLetter => "sealed API key letter",
    }
}

fn show(plan: &Plan, device: &Path, label: &str) {
    let purpose = match plan.package.purpose {
        Purpose::ClientSetup => "client setup",
        Purpose::ClientUpdate => "client update",
        Purpose::ProviderInfo => "provider information",
        Purpose::ProviderRecovery => "provider recovery",
    };
    outln!(
        "Package {} ({purpose}), verified: signed by the relay {} ({}), certificate valid until {}",
        hex::encode(plan.package.id),
        plan.provider_id,
        plan.serial,
        plan.certificate_expires
    );
    for component in &plan.package.components {
        outln!("  contains: {}", kind_name(component.kind));
    }
    if matches!(
        plan.package.purpose,
        Purpose::ClientSetup | Purpose::ClientUpdate
    ) {
        outln!(
            "Plan for slot {label} on {}: set up the drive identity if missing, {} the relay \
             certificate, install each sealed key after the relay proves itself.",
            device.display(),
            if plan.certificate_present {
                "keep"
            } else {
                "write"
            }
        );
    }
}

fn apply(conn: &Connection, plan: &Plan, device: &Path, label: &str) -> Result<()> {
    setup::ensure_identity(conn, device, label)?;
    if !plan.certificate_present {
        let target = device.join(CERTIFICATE_NAME);
        env::write_new(&target, &plan.certificate)?;
        outln!("Wrote relay certificate {}", target.display());
    }
    let slot = format!("{}={label}", device.display());
    let mut relay_url = None;
    let mut installed = 0usize;
    for component in plan
        .package
        .components
        .iter()
        .filter(|component| component.kind.carries_key())
    {
        relay_url = Some(super::install_key_component(conn, &component.bytes, &slot)?);
        installed += 1;
    }
    profile::run_use(
        conn,
        profile::UseOpts {
            label: Some(label.to_string()),
            slot: Some(label.to_string()),
            device: Some(device.to_path_buf()),
            url: relay_url,
            cache: None,
            show: false,
            clear: false,
        },
    )?;
    outln!("Installed {installed} sealed key(s). Setup from the package is complete.");
    Ok(())
}

/// Refuses, before any change, an enrollment file that cannot be written: the
/// request is never written over another file, and the lab has no honest
/// equivalent.
pub(super) fn check_enrollment_target(out: &Path) -> Result<()> {
    if !env::package_setup() {
        return Err(usage("setup --enroll-out is not available here"));
    }
    if env::exists(out) {
        return Err(usage(&format!(
            "{} already exists; setup will not overwrite it",
            out.display()
        )));
    }
    Ok(())
}

/// Writes the signed public enrollment request for the slot and prints the
/// fingerprint to compare with the provider. The slot's passphrase is asked
/// for once, to sign; nothing secret is written.
pub(super) fn write_enrollment(device: &Path, label: &str, out: &Path) -> Result<()> {
    let container = env::fs(|fs| crate::device::open_in(fs, device))?;
    let secrets = super::open_slot_secrets(&format!("{}={label}", device.display()))?;
    let request = crate::enrollment::Request {
        device_id: *container.device_id(),
        created_at: provider::unix_from_utc(&env::now_utc()?)?,
        label: label.to_string(),
        encryption_public: secrets.encryption_public,
        signing_public: secrets.signing_public,
    };
    let bytes = crate::enrollment::encode(&request, &secrets.signing_secret)?;
    env::write_new(out, &bytes)?;
    outln!("Wrote enrollment request {}", out.display());
    outln!(
        "Fingerprint (tell your provider, out of band): {}",
        request.fingerprint()?
    );
    Ok(())
}
