//! `keyquorum-device`, the operator tool for a KeyQuorum container: one
//! physical directory, many logically isolated slots. Private keys stay in
//! the slot token; this tool never prints them. Hosted in the library,
//! like [`super::Cli`], so the browser lab runs the same commands.

use super::env::{self, outln, EnvStorage};
use crate::device;
use crate::error::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keyquorum-device",
    about = "Manage a KeyQuorum container of logical identity slots",
    version
)]
pub struct DeviceToolCli {
    #[command(subcommand)]
    pub command: DeviceToolCommand,
}

#[derive(Subcommand)]
pub enum DeviceToolCommand {
    /// Create device.kq and an empty vault/
    Init { path: PathBuf },
    /// Add a slot. Prints the public keys. Prompts for a passphrase.
    Provision {
        path: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// List slot labels and public keys from device.kq
    List { path: PathBuf },
    /// Print one slot's public keys
    Public {
        path: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// Unwrap a sealed share with the slot's encryption key. Raw share on stdout.
    UnwrapShare {
        path: PathBuf,
        #[arg(long)]
        label: String,
        /// File containing the crypto_box sealed share
        #[arg(long)]
        wrapped_file: PathBuf,
    },
    /// Sign stdin with the slot's signing key. Hex signature on stdout.
    Sign {
        path: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// Move a slot onto another container. The keypair stays; the device id changes.
    Relocate {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        label: String,
    },
}

/// Run one parsed `keyquorum-device` command.
pub fn run(cli: DeviceToolCli) -> Result<()> {
    match cli.command {
        DeviceToolCommand::Init { path } => {
            let container = device::init_in(&mut EnvStorage, &path)?;
            outln!(
                "Initialized {} device {}",
                path.display(),
                hex::encode(container.device_id())
            );
        }
        DeviceToolCommand::Provision { path, label } => {
            let mut container = device::open_in(&EnvStorage, &path)?;
            let passphrase = env::confirm_passphrase(
                &format!("Passphrase for {label}: "),
                &format!("Repeat passphrase for {label}: "),
            )?;
            let slot = device::provision_in(&mut EnvStorage, &mut container, &label, &passphrase)?;
            print_slot(&slot.label, &slot.encryption_public, &slot.signing_public);
        }
        DeviceToolCommand::List { path } => {
            let container = device::open_in(&EnvStorage, &path)?;
            outln!("device {}", hex::encode(container.device_id()));
            for slot in container.slots() {
                print_slot(&slot.label, &slot.encryption_public, &slot.signing_public);
            }
        }
        DeviceToolCommand::Public { path, label } => {
            let container = device::open_in(&EnvStorage, &path)?;
            let slot = container
                .slot(&label)
                .ok_or(crate::error::Error::InvalidSlot)?;
            print_slot(&slot.label, &slot.encryption_public, &slot.signing_public);
        }
        DeviceToolCommand::UnwrapShare {
            path,
            label,
            wrapped_file,
        } => {
            let container = device::open_in(&EnvStorage, &path)?;
            let passphrase = env::prompt_passphrase(&format!("Passphrase for {label}: "))?;
            let secrets = device::open_slot_in(&EnvStorage, &container, &label, &passphrase)?;
            let wrapped = env::read(&wrapped_file)?;
            let share = device::unwrap_share(&secrets, &wrapped)?;
            env::stdout_bytes(&share)?;
        }
        DeviceToolCommand::Sign { path, label } => {
            let container = device::open_in(&EnvStorage, &path)?;
            let passphrase = env::prompt_passphrase(&format!("Passphrase for {label}: "))?;
            let secrets = device::open_slot_in(&EnvStorage, &container, &label, &passphrase)?;
            let message = env::read_stdin()?;
            let signature = device::sign_message(&secrets, &message);
            outln!("{}", hex::encode(signature));
        }
        DeviceToolCommand::Relocate { from, to, label } => {
            let mut source = device::open_in(&EnvStorage, &from)?;
            let mut dest = device::open_in(&EnvStorage, &to)?;
            let passphrase = env::prompt_passphrase(&format!("Passphrase for {label}: "))?;
            device::relocate_slot_in(&mut EnvStorage, &mut source, &mut dest, &label, &passphrase)?;
            outln!("Moved {label} to device {}", hex::encode(dest.device_id()));
        }
    }
    Ok(())
}

fn print_slot(label: &str, encryption: &[u8; 32], signing: &[u8; 32]) {
    outln!("slot {label}");
    outln!("  encryption {}", hex::encode(encryption));
    outln!("  signing {}", hex::encode(signing));
}
