//! `keyquorum device` — container operations, plus `bind`, which records
//! the container's device id in the org store. One-key files still use
//! `register` and `--share-file`; those keys count as their own devices.

use clap::Subcommand;
use keyquorum::device::{self, CustodyMode, CustodyPolicy, UnlockApproval};
use keyquorum::error::Result;
use keyquorum::keys::{self, KeyType};
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
        key_type: crate::CliKeyType,
        /// Registry label. Defaults to the slot label.
        #[arg(long)]
        label: Option<String>,
    },
}

pub fn run(conn: &Connection, command: DeviceCommand) -> Result<()> {
    match command {
        DeviceCommand::Init { path } => {
            let container = device::init(&path)?;
            println!(
                "Initialized {} device {}",
                path.display(),
                hex::encode(container.device_id())
            );
        }
        DeviceCommand::Provision { path, label } => {
            let mut container = device::open(&path)?;
            let passphrase =
                device::confirm_passphrase("Slot passphrase: ", "Repeat passphrase: ")?;
            let slot = device::provision(&mut container, &label, &passphrase)?;
            println!("slot {}", slot.label);
            println!("  encryption {}", hex::encode(slot.encryption_public));
            println!("  signing {}", hex::encode(slot.signing_public));
        }
        DeviceCommand::List { path } => {
            let container = device::open(&path)?;
            println!("device {}", hex::encode(container.device_id()));
            for slot in container.slots() {
                println!("slot {}", slot.label);
                println!("  encryption {}", hex::encode(slot.encryption_public));
                println!("  signing {}", hex::encode(slot.signing_public));
            }
        }
        DeviceCommand::Bind { path, slot } => {
            let container = device::open(&path)?;
            let passphrase = device::confirm_passphrase(
                &format!("Passphrase for {slot}: "),
                &format!("Repeat passphrase for {slot}: "),
            )?;
            device::bind_slot(conn, &container, &slot, &passphrase)?;
            println!(
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
            let container = device::open(&path)?;
            let record = container
                .slot(&slot)
                .ok_or(keyquorum::error::Error::InvalidSlot)?;
            let label = label.unwrap_or_else(|| slot.clone());
            let (public, kind) = match key_type {
                crate::CliKeyType::Encryption => (record.encryption_public, KeyType::Encryption),
                crate::CliKeyType::Signing => (record.signing_public, KeyType::Signing),
            };
            let id = keys::register_key(conn, &label, kind, &public)?;
            println!("Registered key {id} ({label}, {})", kind.as_str());
        }
    }
    Ok(())
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
        Some(_) => return Err(keyquorum::error::Error::InvalidDevice),
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
