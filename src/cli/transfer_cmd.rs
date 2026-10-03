//! `keyquorum transfer` — copy or move an active key identity between two
//! devices that are both open. Ghosts stay in the hierarchy and are not
//! exportable. The global `--db` is not used; each device has its own file.

use super::env::{self, outln};
use crate::device::{self, Container};
use crate::device_relay;
use crate::error::{Error, Result};
use crate::relay::{self, ApiKeyScope};
use crate::transfer::{self, DescendantMode, TransferAuth, TransferOp, TransferRequest};
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum TransferCommand {
    /// Copy an active identity. The source stays active.
    Copy(TransferArgs),
    /// Move an active identity. The source becomes a ghost only after the
    /// destination commits.
    Move(TransferArgs),
    /// Finish or roll back a transfer that stopped between the two devices.
    Recover {
        #[arg(long)]
        from_device: PathBuf,
        #[arg(long)]
        from_db: PathBuf,
        #[arg(long)]
        to_device: PathBuf,
        #[arg(long)]
        to_db: PathBuf,
        /// Hex transaction id from the transfer that stopped.
        #[arg(long)]
        transaction: String,
    },
    /// Record a slot on this device as an active key identity.
    Enroll {
        #[arg(long)]
        device: PathBuf,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// List identities on a device. Ghosts are hidden unless `--all` is set.
    List {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        all: bool,
    },
    /// Seal a copy or move to the destination and leave the source prepared.
    /// `relay-finalize` applies the ghost only after the acknowledgement.
    RelaySend {
        #[arg(long, value_enum)]
        operation: CliRelayOp,
        #[arg(long)]
        from_device: PathBuf,
        #[arg(long)]
        from_db: PathBuf,
        #[arg(long)]
        label: String,
        #[arg(long, value_enum, default_value = "key-only")]
        descendants: CliDescendants,
        /// Active identity authorizing the transfer. Defaults to `--label`.
        #[arg(long = "as")]
        actor: Option<String>,
        /// Hex device id of the destination.
        #[arg(long)]
        to_device_id: String,
        /// X25519 public key that opens the letter on the destination.
        #[arg(long)]
        recipient_key_file: PathBuf,
        #[arg(long)]
        url: Option<String>,
        /// device.push bearer. A stored key is used when this is omitted.
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Pull a sealed copy or move, install it, and post the acknowledgement.
    #[command(group(
        ArgGroup::new("source_identity")
            .required(true)
            .args(["from_device", "from_device_id"])
    ))]
    RelayCollect {
        #[arg(long)]
        to_device: PathBuf,
        #[arg(long)]
        to_db: PathBuf,
        /// Slot whose encryption key opens the letter.
        #[arg(long)]
        slot: String,
        /// Source container. Only its device id and verify key are read.
        #[arg(long, group = "source_identity")]
        from_device: Option<PathBuf>,
        /// Hex source device id. The published descriptor supplies the verify key.
        #[arg(long, group = "source_identity")]
        from_device_id: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// device.pull bearer. A stored key is used when this is omitted.
        #[arg(long)]
        api_key: Option<String>,
        /// device.push bearer for the acknowledgement.
        #[arg(long)]
        push_key: Option<String>,
    },
    /// Apply a destination acknowledgement and finish the source.
    RelayFinalize {
        #[arg(long)]
        from_device: PathBuf,
        #[arg(long)]
        from_db: PathBuf,
        /// Slot the acknowledgement was sealed back to.
        #[arg(long)]
        slot: String,
        /// Hex device id of the destination that signed the acknowledgement
        /// (default: the one destination this device has a transfer waiting for)
        #[arg(long)]
        to_device_id: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// device.pull bearer. A stored key is used when this is omitted.
        #[arg(long)]
        api_key: Option<String>,
    },
}

#[derive(Args)]
pub struct TransferArgs {
    #[arg(long)]
    from_device: PathBuf,
    #[arg(long)]
    from_db: PathBuf,
    #[arg(long)]
    to_device: PathBuf,
    #[arg(long)]
    to_db: PathBuf,
    #[arg(long)]
    label: String,
    #[arg(long, value_enum, default_value = "key-only")]
    descendants: CliDescendants,
    /// Active identity authorizing the transfer. Defaults to `--label`.
    #[arg(long = "as")]
    actor: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CliRelayOp {
    Copy,
    Move,
}

impl CliRelayOp {
    fn operation(self) -> TransferOp {
        match self {
            Self::Copy => TransferOp::Copy,
            Self::Move => TransferOp::Move,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CliDescendants {
    KeyOnly,
    DirectChildren,
    AllDescendants,
}

impl CliDescendants {
    fn mode(self) -> DescendantMode {
        match self {
            Self::KeyOnly => DescendantMode::KeyOnly,
            Self::DirectChildren => DescendantMode::DirectChildren,
            Self::AllDescendants => DescendantMode::AllDescendants,
        }
    }
}

pub fn run(command: TransferCommand) -> Result<()> {
    match command {
        TransferCommand::Copy(args) => run_transfer(args, TransferOp::Copy)?,
        TransferCommand::Move(args) => run_transfer(args, TransferOp::Move)?,
        TransferCommand::Recover {
            from_device,
            from_db,
            to_device,
            to_db,
            transaction,
        } => {
            let tx_id = parse_tx(&transaction)?;
            let source_conn = open_db(&from_db)?;
            let dest_conn = open_db(&to_db)?;
            let mut source = env::fs(|fs| device::open_in(fs, &from_device))?;
            let mut dest = env::fs(|fs| device::open_in(fs, &to_device))?;
            let outcome = transfer::recover_pair_in(
                &mut env::EnvStorage,
                &mut env::EnvStorage,
                &source_conn,
                &mut source,
                &dest_conn,
                &mut dest,
                &tx_id,
            )?;
            outln!("recovery {outcome:?}");
        }
        TransferCommand::Enroll { device, db, label } => {
            let conn = open_db(&db)?;
            let mut container = env::fs(|fs| device::open_in(fs, &device))?;
            let passphrase = env::confirm_passphrase(
                &format!("Passphrase for {label}: "),
                &format!("Repeat passphrase for {label}: "),
            )?;
            let id = transfer::enroll_in(
                &mut env::EnvStorage,
                &conn,
                &mut container,
                &label,
                &passphrase,
            )?;
            outln!("enrolled {label} {}", hex::encode(id));
        }
        TransferCommand::RelaySend {
            operation,
            from_device,
            from_db,
            label,
            descendants,
            actor,
            to_device_id,
            recipient_key_file,
            url,
            api_key,
        } => run_relay_send(
            operation,
            &from_device,
            &from_db,
            &label,
            descendants,
            actor.as_deref(),
            &to_device_id,
            &recipient_key_file,
            url,
            api_key,
        )?,
        TransferCommand::RelayCollect {
            to_device,
            to_db,
            slot,
            from_device,
            from_device_id,
            url,
            api_key,
            push_key,
        } => run_relay_collect(
            &to_device,
            &to_db,
            &slot,
            from_device.as_deref(),
            from_device_id.as_deref(),
            url,
            api_key,
            push_key,
        )?,
        TransferCommand::RelayFinalize {
            from_device,
            from_db,
            slot,
            to_device_id,
            url,
            api_key,
        } => run_relay_finalize(
            &from_device,
            &from_db,
            &slot,
            to_device_id.as_deref(),
            url,
            api_key,
        )?,
        TransferCommand::List { db, all } => {
            let conn = open_db(&db)?;
            let rows = transfer::list_identities(&conn, all)?;
            if rows.is_empty() {
                outln!("(no identities)");
            }
            for row in rows {
                outln!(
                    "{}\t{}\t{}\tgeneration {}",
                    row.label,
                    match row.state {
                        transfer::Possession::Active => "active",
                        transfer::Possession::Ghost => "ghost",
                    },
                    hex::encode(row.id),
                    row.generation
                );
            }
        }
    }
    Ok(())
}

fn run_transfer(args: TransferArgs, operation: TransferOp) -> Result<()> {
    let source_conn = open_db(&args.from_db)?;
    let dest_conn = open_db(&args.to_db)?;
    let mut source = env::fs(|fs| device::open_in(fs, &args.from_device))?;
    let mut dest = env::fs(|fs| device::open_in(fs, &args.to_device))?;
    let actor = args.actor.unwrap_or_else(|| args.label.clone());
    let mode = args.descendants.mode();
    let labels = transfer::export_secret_labels(&source_conn, &args.label, mode)?;
    let passphrases = prompt_passphrases(&source, &labels)?;
    let auth = TransferAuth::default();
    let id = transfer::transfer(TransferRequest {
        source_conn: &source_conn,
        source: &mut source,
        source_storage: &mut env::EnvStorage,
        dest_conn: &dest_conn,
        dest: &mut dest,
        dest_storage: &mut env::EnvStorage,
        actor: &actor,
        label: &args.label,
        operation,
        descendants: mode,
        passphrases: &passphrases,
        auth: &auth,
    })?;
    outln!(
        "{} {} {}",
        operation_name(operation),
        args.label,
        hex::encode(id)
    );
    Ok(())
}

fn prompt_passphrases(source: &Container, labels: &[String]) -> Result<HashMap<String, String>> {
    let mut passphrases = HashMap::new();
    for label in labels {
        if source.slot(label).is_none() {
            continue;
        }
        let passphrase = env::confirm_passphrase(
            &format!("Passphrase for {label}: "),
            &format!("Repeat passphrase for {label}: "),
        )?;
        passphrases.insert(label.clone(), passphrase);
    }
    Ok(passphrases)
}

fn prompt_new_passphrases(labels: &[String]) -> Result<HashMap<String, String>> {
    let mut passphrases = HashMap::new();
    for label in labels {
        let passphrase = env::confirm_passphrase(
            &format!("Passphrase for {label}: "),
            &format!("Repeat passphrase for {label}: "),
        )?;
        passphrases.insert(label.clone(), passphrase);
    }
    Ok(passphrases)
}

fn open_db(path: &Path) -> Result<env::Store> {
    env::open_store(path)
}

fn parse_tx(value: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value).map_err(|_| crate::error::Error::TransferIncomplete)?;
    bytes
        .try_into()
        .map_err(|_| crate::error::Error::TransferIncomplete)
}

fn operation_name(operation: TransferOp) -> &'static str {
    match operation {
        TransferOp::Copy => "copied",
        TransferOp::Move => "moved",
    }
}

#[allow(clippy::too_many_arguments)]
fn run_relay_send(
    operation: CliRelayOp,
    from_device: &Path,
    from_db: &Path,
    label: &str,
    descendants: CliDescendants,
    actor: Option<&str>,
    to_device_id: &str,
    recipient_key_file: &Path,
    url: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let source_conn = open_db(from_db)?;
    let source = env::fs(|fs| device::open_in(fs, from_device))?;
    let actor = actor.unwrap_or(label).to_string();
    let mode = descendants.mode();
    let labels = transfer::export_secret_labels(&source_conn, label, mode)?;
    let passphrases = prompt_passphrases(&source, &labels)?;
    let destination_device_id = parse_device_id(to_device_id)?;
    let recipient = super::read_key_array_32(recipient_key_file)?;
    let return_public = source
        .slot(&actor)
        .ok_or(Error::InvalidSlot)?
        .encryption_public;
    let prepared = transfer::prepare_in(
        &env::EnvStorage,
        &source_conn,
        &source,
        &destination_device_id,
        &actor,
        label,
        operation.operation(),
        mode,
        &passphrases,
        &TransferAuth::default(),
    )?;
    let sealed = device_relay::seal_transfer(&recipient, &return_public, prepared.package())?;
    let (url, api_key) =
        super::resolve_relay_auth(&source_conn, url, api_key, ApiKeyScope::DevicePush)?;
    let accepted = relay::push_device_package(&env::EnvRelay, &url, &api_key, &sealed)?;
    outln!(
        "sent {} {} {} package {}",
        operation_name(operation.operation()),
        label,
        hex::encode(prepared.id),
        accepted.id
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_relay_collect(
    to_device: &Path,
    to_db: &Path,
    slot: &str,
    from_device: Option<&Path>,
    from_device_id: Option<&str>,
    url: Option<String>,
    api_key: Option<String>,
    push_key: Option<String>,
) -> Result<()> {
    let dest_conn = open_db(to_db)?;
    let mut dest = env::fs(|fs| device::open_in(fs, to_device))?;
    let (url, pull_key) =
        super::resolve_relay_auth(&dest_conn, url, api_key, ApiKeyScope::DevicePull)?;
    let (_push_url, push_key) = super::resolve_relay_auth(
        &dest_conn,
        Some(url.clone()),
        push_key,
        ApiKeyScope::DevicePush,
    )?;
    let (source_id, source_verify) = source_identity(&url, &pull_key, from_device, from_device_id)?;
    let passphrase = env::confirm_passphrase(
        &format!("Passphrase for {slot}: "),
        &format!("Repeat passphrase for {slot}: "),
    )?;
    let opener = env::fs(|fs| device::open_slot_in(fs, &dest, slot, &passphrase))?;
    let packages = super::pull_all_device_packages(&url, &pull_key)?;
    let mut accepted = 0u32;
    for item in packages {
        let bytes = decode_package(&item.bytes)?;
        let opened = match device_relay::open_transfer(&opener.encryption_secret, &bytes) {
            Ok(opened) => opened,
            Err(_) => continue,
        };
        let header = match transfer::authenticated_package(opened.package.as_slice()) {
            Ok(header)
                if header.destination_device_id == *dest.device_id()
                    && header.source_device_id == source_id
                    && header.verify_key == source_verify =>
            {
                header
            }
            _ => continue,
        };
        let labels = transfer::package_secret_labels(
            opened.package.as_slice(),
            &source_id,
            &source_verify,
            &dest,
        )?;
        let passphrases = prompt_new_passphrases(&labels)?;
        let id = transfer::accept_package_in(
            &mut env::EnvStorage,
            &dest_conn,
            &mut dest,
            &source_id,
            &source_verify,
            opened.package.as_slice(),
            &passphrases,
            false,
        )?;
        let hash = transfer::package_hash(opened.package.as_slice());
        let ack = device_relay::seal_transfer_ack_in(
            &env::EnvStorage,
            &dest,
            &opened.return_public,
            &header,
            &hash,
        )?;
        relay::push_device_package(&env::EnvRelay, &url, &push_key, &ack)?;
        outln!("accepted {}", hex::encode(id));
        accepted += 1;
    }
    if accepted == 0 {
        outln!("(no device packages)");
    }
    Ok(())
}

/// The destination a finalize is for: the one given, or else the only one this
/// store has a prepared transfer waiting on.
fn waiting_destination(conn: &rusqlite::Connection, given: Option<&str>) -> Result<String> {
    if let Some(given) = given {
        return Ok(given.to_string());
    }
    let mut stmt = conn.prepare(
        "SELECT DISTINCT peer_device_id FROM transfer_transactions
         WHERE role = 'source' AND state = 'prepared' ORDER BY peer_device_id",
    )?;
    let waiting: Vec<String> = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0).map(hex::encode))?
        .collect::<rusqlite::Result<_>>()?;
    match waiting.as_slice() {
        [only] => Ok(only.clone()),
        [] => Err(super::usage(
            "no transfer is waiting on a destination; pass --to-device-id",
        )),
        several => Err(super::usage(&format!(
            "transfers are waiting on {} destinations; pass --to-device-id one of: {}",
            several.len(),
            several.join(", ")
        ))),
    }
}

fn run_relay_finalize(
    from_device: &Path,
    from_db: &Path,
    slot: &str,
    to_device_id: Option<&str>,
    url: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let source_conn = open_db(from_db)?;
    let to_device_id = &waiting_destination(&source_conn, to_device_id)?;
    let mut source = env::fs(|fs| device::open_in(fs, from_device))?;
    let (url, pull_key) =
        super::resolve_relay_auth(&source_conn, url, api_key, ApiKeyScope::DevicePull)?;
    let destination_device_id = parse_device_id(to_device_id)?;
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
        &format!("Passphrase for {slot}: "),
        &format!("Repeat passphrase for {slot}: "),
    )?;
    let opener = env::fs(|fs| device::open_slot_in(fs, &source, slot, &passphrase))?;
    let packages = super::pull_all_device_packages(&url, &pull_key)?;
    let mut finalized = 0u32;
    for item in packages {
        let bytes = decode_package(&item.bytes)?;
        let ack = match device_relay::open_transfer_ack(
            &opener.encryption_secret,
            &bytes,
            &destination_verify,
        ) {
            Ok(ack) if ack.destination_device_id == destination_device_id => ack,
            _ => continue,
        };
        if !transfer::has_transfer(&source_conn, &ack.tx_id)? {
            continue;
        }
        transfer::finalize_after_ack_in(
            &mut env::EnvStorage,
            &source_conn,
            &mut source,
            &ack.tx_id,
            &ack.package_hash,
        )?;
        outln!("finalized {}", hex::encode(ack.tx_id));
        finalized += 1;
    }
    if finalized == 0 {
        outln!("(no device packages)");
    }
    Ok(())
}

fn source_identity(
    url: &str,
    pull_key: &str,
    from_device: Option<&Path>,
    from_device_id: Option<&str>,
) -> Result<([u8; 16], [u8; 32])> {
    match (from_device, from_device_id) {
        (Some(path), None) => {
            let source = env::fs(|fs| device::open_in(fs, path))?;
            Ok((*source.device_id(), *source.verify_key()))
        }
        (None, Some(id)) => {
            let source_id = parse_device_id(id)?;
            let published =
                relay::get_device(&env::EnvRelay, url, pull_key, &hex::encode(source_id))?;
            if parse_device_id(&published.device_id)? != source_id {
                return Err(Error::InvalidDevice);
            }
            Ok((source_id, parse_verify_key(&published.verify_key)?))
        }
        _ => Err(Error::InvalidDevice),
    }
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
