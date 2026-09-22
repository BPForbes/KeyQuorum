//! Operator tool for a KeyQuorum container: one physical directory, many
//! logically isolated slots. Private keys stay in the slot token. This
//! binary never prints them.

use clap::{Parser, Subcommand};
use keyquorum::device;
use keyquorum::error::Result;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "keyquorum-device",
    about = "Manage a KeyQuorum container of logical identity slots",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { path } => {
            let container = device::init(&path)?;
            println!(
                "Initialized {} device {}",
                path.display(),
                hex::encode(container.device_id())
            );
        }
        Command::Provision { path, label } => {
            let mut container = device::open(&path)?;
            let passphrase = device::prompt_passphrase("Slot passphrase: ")?;
            let again = device::prompt_passphrase("Repeat passphrase: ")?;
            if passphrase != again {
                eprintln!("error: passphrases did not match");
                std::process::exit(1);
            }
            let slot = device::provision(&mut container, &label, &passphrase)?;
            print_slot(&slot.label, &slot.encryption_public, &slot.signing_public);
        }
        Command::List { path } => {
            let container = device::open(&path)?;
            println!("device {}", hex::encode(container.device_id()));
            for slot in container.slots() {
                print_slot(&slot.label, &slot.encryption_public, &slot.signing_public);
            }
        }
        Command::Public { path, label } => {
            let container = device::open(&path)?;
            let slot = container
                .slot(&label)
                .ok_or(keyquorum::error::Error::InvalidSlot)?;
            print_slot(&slot.label, &slot.encryption_public, &slot.signing_public);
        }
        Command::UnwrapShare {
            path,
            label,
            wrapped_file,
        } => {
            let container = device::open(&path)?;
            let passphrase = device::prompt_passphrase(&format!("Passphrase for {label}: "))?;
            let secrets = device::open_slot(&container, &label, &passphrase)?;
            let wrapped = std::fs::read(&wrapped_file)?;
            let share = device::unwrap_share(&secrets, &wrapped)?;
            io::stdout().write_all(&share)?;
        }
        Command::Sign { path, label } => {
            let container = device::open(&path)?;
            let passphrase = device::prompt_passphrase(&format!("Passphrase for {label}: "))?;
            let secrets = device::open_slot(&container, &label, &passphrase)?;
            let mut message = Vec::new();
            io::stdin().read_to_end(&mut message)?;
            let signature = device::sign_message(&secrets, &message);
            println!("{}", hex::encode(signature));
        }
        Command::Relocate { from, to, label } => {
            let mut source = device::open(&from)?;
            let mut dest = device::open(&to)?;
            let passphrase = device::prompt_passphrase(&format!("Passphrase for {label}: "))?;
            device::relocate_slot(&mut source, &mut dest, &label, &passphrase)?;
            println!("Moved {label} to device {}", hex::encode(dest.device_id()));
        }
    }
    Ok(())
}

fn print_slot(label: &str, encryption: &[u8; 32], signing: &[u8; 32]) {
    println!("slot {label}");
    println!("  encryption {}", hex::encode(encryption));
    println!("  signing {}", hex::encode(signing));
}
