//! `keyquorum device` — container operations, plus `bind`, which records
//! the container's device id in the org store. One-key files still use
//! `register` and `--share-file`; those keys count as their own devices.

use super::env::{self, errln, outln};
use crate::device::{self, CustodyMode, CustodyPolicy, UnlockApproval};
use crate::device_relay;
use crate::error::{Error, Result};
use crate::keys::{self, KeyType};
use crate::relay::{self, ApiKeyScope};
use clap::Subcommand;
use rusqlite::Connection;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum DeviceCommand {
    /// Create device.kq and an empty vault/
    Init { path: PathBuf },
    /// Add a slot. Prints the public keys. Prompts for a passphrase.
    Provision {
        path: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// List slot labels and public keys
    List { path: PathBuf },
    /// Record this container's device id for the slot's registered keys
    Bind {
        path: PathBuf,
        #[arg(long)]
        slot: String,
    },
    /// Register a slot's public key. A lone key file still uses `register`.
    Register {
        path: PathBuf,
        #[arg(long)]
        slot: String,
        #[arg(long = "type")]
        key_type: super::CliKeyType,
        /// Registry label. Defaults to the slot label.
        #[arg(long)]
        label: Option<String>,
    },
    /// Publish this container's public descriptor. Slot secrets stay local.
    Publish {
        path: PathBuf,
        #[arg(long)]
        url: Option<String>,
        /// device.push bearer. A stored key is used when this is omitted.
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Seal one slot onto another device. Prints the relocate id. The source
    /// slot stays until `relay-drop` sees the acknowledgement for that id.
    RelayRelocate {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        label: String,
        /// Hex device id of the destination.
        #[arg(long)]
        to_device_id: String,
        /// X25519 public key that opens the letter on the destination.
        #[arg(long)]
        recipient_key_file: PathBuf,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Pull sealed relocates, install each slot, and post the acknowledgement.
    /// A slot already installed with the same keys is acknowledged again.
    RelayAccept {
        path: PathBuf,
        /// Slot whose encryption key opens the letter.
        #[arg(long)]
        slot: String,
        #[arg(long)]
        url: Option<String>,
        /// device.pull bearer. A stored key is used when this is omitted.
        #[arg(long)]
        api_key: Option<String>,
        /// device.push bearer for the acknowledgement.
        #[arg(long)]
        push_key: Option<String>,
    },
    /// Delete the source slot after a verified relocate acknowledgement.
    RelayDrop {
        path: PathBuf,
        #[arg(long)]
        label: String,
        /// Hex device id that signed the acknowledgement.
        #[arg(long)]
        to_device_id: String,
        /// Hex relocate id that `relay-relocate` printed. An acknowledgement
        /// for any other relocation of this slot is ignored.
        #[arg(long)]
        relocate_id: String,
        #[arg(long)]
        url: Option<String>,
        /// device.pull bearer. A stored key is used when this is omitted.
        #[arg(long)]
        api_key: Option<String>,
    },
}

pub fn run(conn: &Connection, command: DeviceCommand) -> Result<()> {
    match command {
        DeviceCommand::Init { path } => {
            let container = env::fs(|fs| device::init_in(fs, &path))?;
            outln!(
                "Initialized {} device {}",
                path.display(),
                hex::encode(container.device_id())
            );
        }
        DeviceCommand::Provision { path, label } => {
            let mut container = env::fs(|fs| device::open_in(fs, &path))?;
            let passphrase = env::confirm_passphrase("Slot passphrase: ", "Repeat passphrase: ")?;
            let slot = env::fs(|fs| device::provision_in(fs, &mut container, &label, &passphrase))?;
            outln!("slot {}", slot.label);
            outln!("  encryption {}", hex::encode(slot.encryption_public));
            outln!("  signing {}", hex::encode(slot.signing_public));
        }
        DeviceCommand::List { path } => {
            let container = env::fs(|fs| device::open_in(fs, &path))?;
            outln!("device {}", hex::encode(container.device_id()));
            for slot in container.slots() {
                outln!("slot {}", slot.label);
                outln!("  encryption {}", hex::encode(slot.encryption_public));
                outln!("  signing {}", hex::encode(slot.signing_public));
            }
        }
        DeviceCommand::Bind { path, slot } => {
            let container = env::fs(|fs| device::open_in(fs, &path))?;
            let passphrase = env::confirm_passphrase(
                &format!("Passphrase for {slot}: "),
                &format!("Repeat passphrase for {slot}: "),
            )?;
            env::fs(|fs| device::bind_slot_in(fs, conn, &container, &slot, &passphrase))?;
            outln!(
                "Bound {slot} to device {}",
                hex::encode(container.device_id())
            );
        }
        DeviceCommand::Register {
            path,
            slot,
            key_type,
            label,
        } => {
            let container = env::fs(|fs| device::open_in(fs, &path))?;
            let record = container
                .slot(&slot)
                .ok_or(crate::error::Error::InvalidSlot)?;
            let label = label.unwrap_or_else(|| slot.clone());
            let (public, kind) = match key_type {
                super::CliKeyType::Encryption => (record.encryption_public, KeyType::Encryption),
                super::CliKeyType::Signing => (record.signing_public, KeyType::Signing),
            };
            let id = keys::register_key(conn, &label, kind, &public)?;
            outln!("Registered key {id} ({label}, {})", kind.as_str());
        }
        DeviceCommand::Publish { path, url, api_key } => {
            let container = env::fs(|fs| device::open_in(fs, &path))?;
            let descriptor = device_relay::public_descriptor_in(&env::EnvStorage, &container)?;
            let (url, api_key) =
                super::resolve_relay_auth(conn, url, api_key, ApiKeyScope::DevicePush)?;
            relay::put_device(&env::EnvRelay, &url, &api_key, &descriptor)?;
            outln!("published {}", hex::encode(container.device_id()));
        }
        DeviceCommand::RelayRelocate {
            from,
            label,
            to_device_id,
            recipient_key_file,
            url,
            api_key,
        } => {
            let source = env::fs(|fs| device::open_in(fs, &from))?;
            let destination_device_id = parse_device_id(&to_device_id)?;
            let recipient = super::read_key_array_32(&recipient_key_file)?;
            let passphrase = env::confirm_passphrase(
                &format!("Passphrase for {label}: "),
                &format!("Repeat passphrase for {label}: "),
            )?;
            let sealed = device_relay::seal_relocate_in(
                &env::EnvStorage,
                &recipient,
                &source,
                &label,
                &destination_device_id,
                &passphrase,
            )?;
            let (url, api_key) =
                super::resolve_relay_auth(conn, url, api_key, ApiKeyScope::DevicePush)?;
            let accepted =
                relay::push_device_package(&env::EnvRelay, &url, &api_key, &sealed.bytes)?;
            outln!(
                "relocating {label} to {} relocate {} package {}",
                hex::encode(destination_device_id),
                hex::encode(sealed.relocate_id),
                accepted.id
            );
        }
        DeviceCommand::RelayAccept {
            path,
            slot,
            url,
            api_key,
            push_key,
        } => {
            let mut dest = env::fs(|fs| device::open_in(fs, &path))?;
            let (url, pull_key) =
                super::resolve_relay_auth(conn, url, api_key, ApiKeyScope::DevicePull)?;
            let (_push_url, push_key) = super::resolve_relay_auth(
                conn,
                Some(url.clone()),
                push_key,
                ApiKeyScope::DevicePush,
            )?;
            let passphrase = env::confirm_passphrase(
                &format!("Passphrase for {slot}: "),
                &format!("Repeat passphrase for {slot}: "),
            )?;
            let opener = env::fs(|fs| device::open_slot_in(fs, &dest, &slot, &passphrase))?;
            let packages = super::pull_all_device_packages(&url, &pull_key)?;
            let mut accepted = 0u32;
            for item in packages {
                let bytes = decode_package(&item.bytes)?;
                let letter = match device_relay::open_relocate(&opener.encryption_secret, &bytes) {
                    Ok(letter) if letter.destination_device_id == *dest.device_id() => letter,
                    _ => continue,
                };
                let published = relay::get_device(
                    &env::EnvRelay,
                    &url,
                    &pull_key,
                    &hex::encode(letter.source_device_id),
                )?;
                if parse_verify_key(&published.verify_key)? != letter.source_verify_key {
                    continue;
                }
                // A retry after a failed acknowledgement upload, or an old
                // letter still in the mailbox, finds the slot already here.
                // Same keys: acknowledge again. Different keys: skip it so
                // one conflicting letter does not stop the rest.
                let installed = match device::slot_matches(
                    &dest,
                    &letter.label,
                    &letter.encryption_secret,
                    &letter.signing_secret,
                ) {
                    Ok(installed) => installed,
                    Err(Error::InvalidSlot) => {
                        errln!(
                            "skipped slot {}: a different key already holds that label",
                            letter.label
                        );
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                if !installed {
                    let install_pass = env::confirm_passphrase(
                        &format!("Passphrase for {}: ", letter.label),
                        &format!("Repeat passphrase for {}: ", letter.label),
                    )?;
                    env::fs(|fs| {
                        device::install_slot_in(
                            fs,
                            &mut dest,
                            &letter.label,
                            &install_pass,
                            &letter.encryption_secret,
                            &letter.signing_secret,
                        )
                    })?;
                }
                let ack = device_relay::seal_relocate_ack_in(&env::EnvStorage, &letter, &dest)?;
                relay::push_device_package(&env::EnvRelay, &url, &push_key, &ack)?;
                if installed {
                    outln!("acknowledged slot {} again", letter.label);
                } else {
                    outln!("accepted slot {}", letter.label);
                }
                accepted += 1;
            }
            if accepted == 0 {
                outln!("(no device packages)");
            }
        }
        DeviceCommand::RelayDrop {
            path,
            label,
            to_device_id,
            relocate_id,
            url,
            api_key,
        } => {
            let mut container = env::fs(|fs| device::open_in(fs, &path))?;
            let relocate_id = parse_device_id(&relocate_id)?;
            let (url, pull_key) =
                super::resolve_relay_auth(conn, url, api_key, ApiKeyScope::DevicePull)?;
            let destination_device_id = parse_device_id(&to_device_id)?;
            let published = relay::get_device(
                &env::EnvRelay,
                &url,
                &pull_key,
                &hex::encode(destination_device_id),
            )?;
            if parse_device_id(&published.device_id)? != destination_device_id {
                return Err(Error::InvalidDevice);
            }
            let destination_verify = parse_verify_key(&published.verify_key)?;
            let passphrase = env::confirm_passphrase(
                &format!("Passphrase for {label}: "),
                &format!("Repeat passphrase for {label}: "),
            )?;
            let opener = env::fs(|fs| device::open_slot_in(fs, &container, &label, &passphrase))?;
            let packages = super::pull_all_device_packages(&url, &pull_key)?;
            let mut dropped = false;
            for item in packages {
                let bytes = decode_package(&item.bytes)?;
                let ack = match device_relay::open_relocate_ack(
                    &opener.encryption_secret,
                    &bytes,
                    &destination_verify,
                ) {
                    Ok(ack) => ack,
                    Err(_) => continue,
                };
                if ack.relocate_id != relocate_id
                    || ack.label != label
                    || ack.source_device_id != *container.device_id()
                    || ack.destination_device_id != destination_device_id
                {
                    continue;
                }
                env::fs(|fs| device::remove_slot_in(fs, &mut container, &label))?;
                outln!("dropped {label}");
                dropped = true;
                break;
            }
            if !dropped {
                outln!("(no relocate acknowledgement)");
            }
        }
    }
    Ok(())
}

fn parse_device_id(value: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value.trim()).map_err(|_| Error::InvalidDevice)?;
    bytes.try_into().map_err(|_| Error::InvalidDevice)
}

fn parse_verify_key(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value.trim()).map_err(|_| Error::InvalidPublicKey)?;
    bytes.try_into().map_err(|_| Error::InvalidPublicKey)
}

fn decode_package(value: &str) -> Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|_| Error::InvalidBridgePackage)
}

pub fn apply_policy(
    conn: &Connection,
    key_id: i64,
    custody: Option<&str>,
    minimum_physical_devices: Option<u8>,
    unlock_approval: Option<&str>,
) -> Result<()> {
    if custody.is_none() && minimum_physical_devices.is_none() && unlock_approval.is_none() {
        return Ok(());
    }
    let current = device::custody_policy(conn, key_id)?;
    let mode = match custody {
        Some("hardware") => CustodyMode::Hardware,
        Some("logical") => CustodyMode::Logical,
        Some(_) => return Err(crate::error::Error::InvalidDevice),
        None => current.mode,
    };
    let minimum = minimum_physical_devices.unwrap_or(current.minimum_physical_devices);
    let approval = match unlock_approval {
        Some(value) => UnlockApproval::parse(value)?,
        None => current.unlock_approval,
    };
    device::set_custody_policy(
        conn,
        key_id,
        &CustodyPolicy {
            mode,
            minimum_physical_devices: minimum,
            unlock_approval: approval,
        },
    )
}
