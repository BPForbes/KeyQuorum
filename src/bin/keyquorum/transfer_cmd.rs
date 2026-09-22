//! `keyquorum transfer` — copy or move an active key identity between two
//! devices that are both open. Ghosts stay in the hierarchy and are not
//! exportable. The global `--db` is not used; each device has its own file.

use clap::{Args, Subcommand, ValueEnum};
use keyquorum::db;
use keyquorum::device::{self, Container};
use keyquorum::error::Result;
use keyquorum::transfer::{self, DescendantMode, TransferAuth, TransferOp, TransferRequest};
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
enum CliDescendants {
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
            let mut source = device::open(&from_device)?;
            let mut dest = device::open(&to_device)?;
            let outcome =
                transfer::recover_pair(&source_conn, &mut source, &dest_conn, &mut dest, &tx_id)?;
            println!("recovery {outcome:?}");
        }
        TransferCommand::Enroll { device, db, label } => {
            let conn = open_db(&db)?;
            let mut container = device::open(&device)?;
            let passphrase = device::confirm_passphrase(
                &format!("Passphrase for {label}: "),
                &format!("Repeat passphrase for {label}: "),
            )?;
            let id = transfer::enroll(&conn, &mut container, &label, &passphrase)?;
            println!("enrolled {label} {}", hex::encode(id));
        }
        TransferCommand::List { db, all } => {
            let conn = open_db(&db)?;
            let rows = transfer::list_identities(&conn, all)?;
            if rows.is_empty() {
                println!("(no identities)");
            }
            for row in rows {
                println!(
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
    let mut source = device::open(&args.from_device)?;
    let mut dest = device::open(&args.to_device)?;
    let actor = args.actor.unwrap_or_else(|| args.label.clone());
    let mode = args.descendants.mode();
    let labels = transfer::export_secret_labels(&source_conn, &args.label, mode)?;
    let passphrases = prompt_passphrases(&source, &labels)?;
    let auth = TransferAuth::default();
    let id = transfer::transfer(TransferRequest {
        source_conn: &source_conn,
        source: &mut source,
        dest_conn: &dest_conn,
        dest: &mut dest,
        actor: &actor,
        label: &args.label,
        operation,
        descendants: mode,
        passphrases: &passphrases,
        auth: &auth,
    })?;
    println!(
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
        let passphrase = device::confirm_passphrase(
            &format!("Passphrase for {label}: "),
            &format!("Repeat passphrase for {label}: "),
        )?;
        passphrases.insert(label.clone(), passphrase);
    }
    Ok(passphrases)
}

fn open_db(path: &Path) -> Result<rusqlite::Connection> {
    let path = path.to_str().ok_or(keyquorum::error::Error::InvalidPath)?;
    db::open(path)
}

fn parse_tx(value: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value).map_err(|_| keyquorum::error::Error::TransferIncomplete)?;
    bytes
        .try_into()
        .map_err(|_| keyquorum::error::Error::TransferIncomplete)
}

fn operation_name(operation: TransferOp) -> &'static str {
    match operation {
        TransferOp::Copy => "copied",
        TransferOp::Move => "moved",
    }
}
