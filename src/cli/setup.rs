//! `keyquorum setup`: one command from nothing to a working identity.
//!
//! It runs the steps a person would have typed, in order, with the same
//! library calls: `device init`, `device provision`, `device register` for the
//! encryption and signing keys, `device bind`, optionally `loadkey`, and
//! `use`. It can be run again: a step that is already done is skipped, so a
//! setup that stopped halfway is finished by running the same line.

use super::env::{self, errln, outln};
use super::profile;
use super::usage;
use crate::db;
use crate::error::Result;
use crate::keys::{self, KeyType};
use crate::{device, relay};
use clap::Args;
use rusqlite::Connection;
use std::path::PathBuf;

#[derive(Args)]
pub struct SetupOpts {
    /// A `.kqpkg` from your provider to install. Without --yes it is only
    /// inspected and the plan shown; nothing is written.
    #[arg(value_name = "PACKAGE")]
    pub package: Option<PathBuf>,
    /// The device container directory (created if it does not exist)
    #[arg(long, required_unless_present = "package")]
    pub device: Option<PathBuf>,
    /// Your label: the slot's name and the label its keys are registered under
    #[arg(long, required_unless_present = "package")]
    pub label: Option<String>,
    /// Apply the package's plan after showing it
    #[arg(long, requires = "package")]
    pub yes: bool,
    /// The relay you use; with it, the relay key is loaded too
    #[arg(long, conflicts_with = "package")]
    pub url: Option<String>,
    /// Relay API key (prompted if omitted and --url is given)
    #[arg(long, requires = "url")]
    pub api_key: Option<String>,
}

/// Register `public` under `label` unless it already is. A different key
/// already registered for the label is refused rather than shadowed.
pub(super) fn ensure_registered(
    conn: &Connection,
    label: &str,
    kind: KeyType,
    public: &[u8; 32],
) -> Result<bool> {
    if let Ok(existing) = keys::get_key_by_public_key(conn, public) {
        if existing.label == label && existing.key_type == kind && existing.revoked_at.is_none() {
            return Ok(false);
        }
        return Err(usage(&format!(
            "this {} key is already registered in this store as {} {} ({}); \
             pick another key or label",
            kind.as_str(),
            existing.key_type.as_str(),
            existing.label,
            if existing.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            }
        )));
    }
    if !keys::active_keys_for(conn, label, kind)?.is_empty() {
        return Err(usage(&format!(
            "a different {} key is already registered for {label} in this store; \
             pick another --label or revoke it first",
            kind.as_str()
        )));
    }
    keys::register_key(conn, label, kind, public)?;
    Ok(true)
}

/// The drive's container, the slot, its registered keys and its binding:
/// `device init`, `provision`, `register` and `bind`, each skipped when done.
pub(super) fn ensure_identity(
    conn: &Connection,
    path: &std::path::Path,
    label: &str,
) -> Result<()> {
    let mut container = match env::fs(|fs| device::open_in(fs, path)) {
        Ok(container) => container,
        Err(open_error) => match env::fs(|fs| device::init_in(fs, path)) {
            Ok(container) => {
                outln!(
                    "Initialized {} device {}",
                    path.display(),
                    hex::encode(container.device_id())
                );
                container
            }
            Err(_) => return Err(open_error),
        },
    };

    let passphrase = if container.slot(label).is_none() {
        let passphrase = env::confirm_passphrase(
            &format!("Passphrase for {label}: "),
            &format!("Repeat passphrase for {label}: "),
        )?;
        let slot = env::fs(|fs| device::provision_in(fs, &mut container, label, &passphrase))?;
        outln!("Provisioned slot {}", slot.label);
        passphrase
    } else {
        outln!("Slot {label} already exists; keeping it");
        env::prompt_passphrase(&format!("Passphrase for {label}: "))?
    };

    let slot = container
        .slot(label)
        .ok_or(crate::error::Error::InvalidSlot)?;
    let (encryption, signing) = (slot.encryption_public, slot.signing_public);
    for (kind, public) in [
        (KeyType::Encryption, encryption),
        (KeyType::Signing, signing),
    ] {
        if ensure_registered(conn, label, kind, &public)? {
            outln!("Registered {} key for {label}", kind.as_str());
        }
    }
    env::fs(|fs| device::bind_slot_in(fs, conn, &container, label, &passphrase))?;
    outln!(
        "Bound {label} to device {}",
        hex::encode(container.device_id())
    );
    Ok(())
}

pub(crate) fn run(conn: &Connection, opts: SetupOpts) -> Result<()> {
    let SetupOpts {
        package,
        device: path,
        label,
        url,
        api_key,
        yes,
    } = opts;
    if let Some(package) = package {
        let (Some(path), Some(label)) = (path, label) else {
            return Err(usage(
                "setup with a package needs --device and --label: the drive and slot it is installed for",
            ));
        };
        return super::setup_package::run(conn, &package, &path, &label, yes);
    }
    let (Some(path), Some(label)) = (path, label) else {
        return Err(usage("setup needs --device and --label"));
    };
    let url = url
        .map(|url| {
            let url = db::relay_credential::normalize_url(&url);
            relay::validate_relay_url(&url).map(|_| url)
        })
        .transpose()?;
    ensure_identity(conn, &path, &label)?;

    super::profile::run_use(
        conn,
        profile::UseOpts {
            label: Some(label.clone()),
            slot: Some(label),
            device: Some(path),
            url: url.clone(),
            cache: None,
            show: false,
            clear: false,
        },
    )?;
    if let Some(url) = url {
        super::loadkey_in_store(conn, api_key, Some(url))?;
    } else {
        errln!(
            "note: no relay yet; add one with `keyquorum use --url URL` and `keyquorum loadkey`"
        );
    }
    Ok(())
}
