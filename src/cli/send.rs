//! `keyquorum send`: one command for sending a file to another label.
//!
//! It picks the right sender from the file itself. A tracked file (`.kqtf`)
//! goes as `file share` would send it, the newest trusted revision only; any
//! other file goes as `deliver send` would. It adds no rule of its own: it
//! builds the same command the user would have typed and runs it.

use super::deliver_cmd::DeliverCommand;
use super::env::{self, errln};
use super::file_cmd::FileCommand;
use super::{deliver_cmd, file_cmd, resolve_relay_url, usage};
use crate::error::Result;
use crate::file_history::CONTAINER_MAGIC;
use crate::relay::ApiKeyScope;
use clap::Args;
use rusqlite::Connection;
use std::path::PathBuf;

#[derive(Args)]
pub struct SendOpts {
    /// The file to send
    pub path: PathBuf,
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
    match resolve_relay_url(conn, args.url.clone(), ApiKeyScope::InboxPush) {
        Ok(_) => Ok((None, true)),
        Err(_) => {
            errln!("note: no relay is set up, so the letter is written to ./outbox; see `keyquorum use --url` and `keyquorum loadkey`");
            Ok((Some(PathBuf::from("outbox")), false))
        }
    }
}

#[inline(never)]
pub(crate) fn run(conn: &Connection, args: SendOpts) -> Result<()> {
    let head = env::read(&args.path)?;
    let tracked = head.starts_with(CONTAINER_MAGIC);
    if tracked && args.name.is_some() {
        return Err(usage("--name does not apply to a tracked file"));
    }
    if !tracked && args.revision.is_some() {
        return Err(usage("--revision applies only to a tracked file"));
    }
    let (output_dir, push) = transport(conn, &args)?;
    let SendOpts {
        path,
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
