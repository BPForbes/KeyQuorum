//! `keyquorum send`: one command for sending a file to another label.
//!
//! It picks the right sender from the file itself. A tracked file (`.kqtf`)
//! goes as `file share` would send it, the newest trusted revision only; any
//! other file goes as `deliver send` would. It adds no rule of its own: it
//! builds the same command the user would have typed and runs it.

use super::deliver_cmd::DeliverCommand;
use super::env::{self, errln};
use super::file_cmd::FileCommand;
use super::{configured_relay_url, deliver_cmd, file_cmd, unlock_quorum_file, usage};
use crate::error::Result;
use crate::file_history::CONTAINER_MAGIC;
use crate::quorum;
use crate::relay::ApiKeyScope;
use clap::Args;
use rusqlite::Connection;
use std::path::PathBuf;

#[derive(Args)]
pub struct SendOpts {
    /// The file to send (or use --quorum-file)
    #[arg(
        required_unless_present = "quorum_file",
        conflicts_with = "quorum_file"
    )]
    pub path: Option<PathBuf>,
    /// Send a quorum-protected file by id instead: it is unlocked in memory
    /// with the same shares `access quorum --state 1` takes, and never
    /// written to disk
    #[arg(long)]
    pub quorum_file: Option<i64>,
    /// With --quorum-file: container=slot that unwraps a leaf share (repeatable)
    #[arg(long = "unlock-slot", requires = "quorum_file")]
    pub unlock_slots: Vec<String>,
    /// With --quorum-file: key file that unwraps a leaf share (repeatable)
    #[arg(long = "unlock-share-file", requires = "quorum_file")]
    pub unlock_share_files: Vec<String>,
    /// With --quorum-file: leaf=signing-key-file or leaf=container>slot, when
    /// the file's unlock approval is `parent` (repeatable)
    #[arg(long = "approve", requires = "quorum_file")]
    pub approves: Vec<String>,
    /// Recipient label (its encryption key must be registered here)
    #[arg(long)]
    pub to: String,
    /// Your label (default: from `keyquorum use`)
    #[arg(long = "as")]
    pub as_label: Option<String>,
    /// Your identity slot, container=label (default: from `keyquorum use`)
    #[arg(long, conflicts_with = "signing_key_file")]
    pub slot: Option<String>,
    /// Your signing private key file, instead of --slot
    #[arg(long)]
    pub signing_key_file: Option<PathBuf>,
    /// Name the recipient sees (default: the file's name)
    #[arg(long)]
    pub name: Option<String>,
    /// For a tracked file: share up to this revision instead of the head
    #[arg(long)]
    pub revision: Option<String>,
    /// Write the letter here instead of uploading it
    #[arg(long, conflicts_with = "offline")]
    pub output_dir: Option<PathBuf>,
    /// Write the letter to ./outbox instead of uploading it
    #[arg(long)]
    pub offline: bool,
    /// Relay base URL (default: `keyquorum use --url`)
    #[arg(long)]
    pub url: Option<String>,
    /// Push-scope API key (default: a key from `loadkey`)
    #[arg(long)]
    pub api_key: Option<String>,
}

/// Where the sealed letter goes: written to a directory, or uploaded.
fn transport(conn: &Connection, args: &SendOpts) -> Result<(Option<PathBuf>, bool)> {
    if let Some(dir) = &args.output_dir {
        return Ok((Some(dir.clone()), false));
    }
    if args.offline {
        return Ok((Some(PathBuf::from("outbox")), false));
    }
    match configured_relay_url(conn, args.url.clone(), ApiKeyScope::InboxPush)? {
        Some(_) => Ok((None, true)),
        None => {
            errln!("note: no relay is set up, so the letter is written to ./outbox; see `keyquorum use --url` and `keyquorum loadkey`");
            Ok((Some(PathBuf::from("outbox")), false))
        }
    }
}

#[inline(never)]
pub(crate) fn run(conn: &Connection, args: SendOpts) -> Result<()> {
    if let Some(id) = args.quorum_file {
        return send_quorum_file(conn, id, args);
    }
    if !(args.unlock_slots.is_empty()
        && args.unlock_share_files.is_empty()
        && args.approves.is_empty())
    {
        return Err(usage(
            "--unlock-slot, --unlock-share-file and --approve apply only with --quorum-file",
        ));
    }
    let path = args
        .path
        .clone()
        .ok_or_else(|| usage("pass a file or --quorum-file"))?;
    let head = env::read(&path)?;
    let tracked = head.starts_with(CONTAINER_MAGIC);
    if tracked && args.name.is_some() {
        return Err(usage("--name does not apply to a tracked file"));
    }
    if !tracked && args.revision.is_some() {
        return Err(usage("--revision applies only to a tracked file"));
    }
    let (output_dir, push) = transport(conn, &args)?;
    let SendOpts {
        to,
        as_label,
        slot,
        signing_key_file,
        name,
        revision,
        url,
        api_key,
        ..
    } = args;
    if tracked {
        file_cmd::run(
            conn,
            FileCommand::Share {
                kqtf: path,
                to,
                as_label,
                slot,
                signing_key_file,
                revision,
                output_dir,
                push,
                url: url.filter(|_| push),
                api_key: api_key.filter(|_| push),
            },
        )
    } else {
        deliver_cmd::run(
            conn,
            DeliverCommand::Send {
                file: path,
                to,
                as_label,
                slot,
                signing_key_file,
                name,
                output_dir,
                push,
                url: url.filter(|_| push),
                api_key: api_key.filter(|_| push),
            },
        )
    }
}

/// `send --quorum-file`: unlock with the shares presented, seal the bytes, and
/// carry the letter. The unlock is `access quorum --state 1`'s own, so the
/// custody policy, parent approval, expiry and gate history all apply, and a
/// refused unlock sends nothing. The plaintext lives only in this function.
#[inline(never)]
fn send_quorum_file(conn: &Connection, id: i64, args: SendOpts) -> Result<()> {
    if args.revision.is_some() {
        return Err(usage("--revision applies only to a tracked file"));
    }
    let (output_dir, push) = transport(conn, &args)?;
    let plaintext = zeroize::Zeroizing::new(unlock_quorum_file(
        conn,
        id,
        &args.unlock_share_files,
        &args.unlock_slots,
        &args.approves,
        false,
    )?);
    let file_name = match args.name {
        Some(name) => name,
        None => quorum::status(conn, id)?.name,
    };
    deliver_cmd::seal_and_carry(
        conn,
        deliver_cmd::Outbound {
            contents: &plaintext,
            file_name: &file_name,
            to: &args.to,
            as_label: args.as_label,
            slot: args.slot,
            signing_key_file: args.signing_key_file,
            output_dir,
            push,
            url: args.url.filter(|_| push),
            api_key: args.api_key.filter(|_| push),
        },
    )
}
