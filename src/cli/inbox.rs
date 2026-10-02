//! `keyquorum inbox`: pull what is waiting and open it, in one command.
//!
//! `inbox` lists the letters a relay holds for you. `inbox open` opens each
//! one the way the single-purpose command would have, and posts the signed
//! answer: a delivery with `deliver open`, an answer to your delivery with
//! `deliver ack`, a tracked file with `file receive`, a bridge or org update
//! with the import `relay pull --import` runs. It judges nothing itself.
//!
//! Pulled letters are kept in `--dir` (`inbox/`) as `<id>.kqpb`; the store
//! remembers the cursor and which letters it has handled, so a later pull
//! resumes after the newest and a letter is opened once. Receipt is already
//! idempotent by delivery id, so losing that record only repeats an answer.
//!
//! A letter that asks for a decision (a file or change request), an answer to
//! a request, a history snapshot, or an acknowledgement of a tracked file is
//! listed with the command that opens it; none of those is guessed.

use super::deliver_cmd::DeliverCommand;
use super::env::{self, errln, outln};
use super::file_cmd::FileCommand;
use super::{
    deliver_cmd, encryption_secret_from, file_cmd, import_envelope, profile, resolve_relay_auth,
    usage,
};
use crate::db;
use crate::envelope;
use crate::error::{Error, Result};
use crate::{key_tree, relay};
use clap::{Args, Subcommand};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Args, Clone)]
pub struct InboxOpts {
    /// Where pulled letters are kept
    #[arg(long, default_value = "inbox")]
    pub dir: PathBuf,
    /// Your identity slot, container=label (default: from `keyquorum use`)
    #[arg(long)]
    pub slot: Option<String>,
    /// Relay base URL (or `keyquorum use --url`, or KEYQUORUM_RELAY_URL)
    #[arg(long)]
    pub url: Option<String>,
    /// Pull-scope API key (or a key from `loadkey`)
    #[arg(long)]
    pub api_key: Option<String>,
}

impl Default for InboxOpts {
    fn default() -> Self {
        InboxOpts {
            dir: PathBuf::from("inbox"),
            slot: None,
            url: None,
            api_key: None,
        }
    }
}

#[derive(Args)]
pub struct OpenArgs {
    #[command(flatten)]
    pub opts: InboxOpts,
    /// One letter by its id (default: every letter not yet handled)
    pub id: Option<i64>,
    /// Refuse a delivered file or tracked file and say so in the answer
    #[arg(long)]
    pub reject: bool,
    /// Keep delivered files here, under the name the sender gave
    #[arg(long, default_value = "received")]
    pub save_dir: PathBuf,
    /// Write answers here instead of uploading them
    #[arg(long)]
    pub ack_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum InboxCommand {
    /// Pull, then list what is waiting (the default)
    List(InboxOpts),
    /// Pull, then open what is waiting and answer it
    Open(OpenArgs),
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        envelope::KIND_FILE_DELIVERY => "file delivery",
        envelope::KIND_FILE_DELIVERY_ACK => "answer to your delivery",
        envelope::KIND_FILE_HISTORY => "tracked file",
        envelope::KIND_FILE_HISTORY_ACK => "answer to your tracked file",
        envelope::KIND_FILE_HISTORY_SNAPSHOT => "history snapshot",
        envelope::KIND_FILE_REQUEST => "file or change request",
        envelope::KIND_FILE_REQUEST_ANSWER => "answer to your request",
        envelope::KIND_DEVICE_TRANSFER
        | envelope::KIND_DEVICE_TRANSFER_ACK
        | envelope::KIND_DEVICE_RELOCATE
        | envelope::KIND_DEVICE_RELOCATE_ACK => "device letter",
        _ => "bridge or org update",
    }
}

/// The command that opens a kind `inbox open` leaves alone, if there is one.
fn manual_command(kind: u8) -> Option<&'static str> {
    match kind {
        envelope::KIND_FILE_HISTORY_ACK => Some("keyquorum file ack <file.kqtf> --ack"),
        envelope::KIND_FILE_HISTORY_SNAPSHOT => Some("keyquorum file open-history --letter"),
        envelope::KIND_FILE_REQUEST => Some("keyquorum file open-request --request"),
        envelope::KIND_FILE_REQUEST_ANSWER => Some("keyquorum file open-answer --answer"),
        envelope::KIND_DEVICE_TRANSFER
        | envelope::KIND_DEVICE_TRANSFER_ACK
        | envelope::KIND_DEVICE_RELOCATE
        | envelope::KIND_DEVICE_RELOCATE_ACK => Some("keyquorum transfer relay-collect"),
        _ => None,
    }
}

fn letter_path(dir: &Path, id: i64) -> PathBuf {
    dir.join(format!("{id}.kqpb"))
}

/// Fetch every letter after the newest one this store has, keep each in
/// `dir`, and merge any public-tree slices. Returns the relay used.
fn pull(conn: &Connection, opts: &InboxOpts) -> Result<String> {
    let (url, api_key) = resolve_relay_auth(
        conn,
        opts.url.clone(),
        opts.api_key.clone(),
        relay::ApiKeyScope::InboxPull,
    )?;
    env::create_dir_all(&opts.dir)?;
    let mut after = db::inbox::cursor(conn, &url)?;
    loop {
        let page = relay::pull_inbox(
            &env::EnvRelay,
            &url,
            &api_key,
            after,
            Some(relay::MAX_INBOX_PAGE),
        )?;
        for slice in &page.trees {
            let applied = key_tree::apply_public_tree(conn, None, slice)?;
            outln!(
                "Merged {} (generation {}, {} nodes) into key {applied}",
                slice.label,
                slice.generation,
                slice.nodes.len()
            );
        }
        for item in &page.envelopes {
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &item.bytes)
                    .map_err(|_| Error::InvalidBridgePackage)?;
            let kind = match envelope::kind(&bytes) {
                Ok(kind) => kind,
                Err(_) => {
                    errln!("letter {}: not a KeyQuorum letter; skipped", item.id);
                    continue;
                }
            };
            let path = letter_path(&opts.dir, item.id);
            if !env::exists(&path) {
                env::write_new(&path, &bytes)?;
            }
            db::inbox::record(conn, &url, item.id, kind)?;
        }
        match page.next_after {
            Some(next) if after.is_none_or(|previous| next > previous) => after = Some(next),
            Some(_) => {
                return Err(Error::RelayRequest(
                    "relay returned a cursor that does not advance".into(),
                ))
            }
            None => return Ok(url),
        }
    }
}

fn list(conn: &Connection, opts: &InboxOpts) -> Result<()> {
    let url = pull(conn, opts)?;
    let letters = db::inbox::list(conn, &url)?;
    if letters.iter().all(|l| l.status == db::inbox::HANDLED) {
        outln!("(nothing waiting)");
        return Ok(());
    }
    for letter in letters.iter().filter(|l| l.status != db::inbox::HANDLED) {
        match manual_command(letter.kind) {
            Some(command) => outln!(
                "{}  {}  (open with `{command} {}`)",
                letter.id,
                kind_name(letter.kind),
                letter_path(&opts.dir, letter.id).display()
            ),
            None => outln!("{}  {}", letter.id, kind_name(letter.kind)),
        }
    }
    outln!("Open them with `keyquorum inbox open`");
    Ok(())
}

#[inline(never)]
/// Open one letter the way its own command would. `Ok(false)` is a kind that
/// is left for a person.
fn open_letter(conn: &Connection, args: &OpenArgs, slot: &str, id: i64, kind: u8) -> Result<bool> {
    let path = letter_path(&args.opts.dir, id);
    let push_answer = args.ack_dir.is_none();
    match kind {
        envelope::KIND_FILE_DELIVERY => deliver_cmd::run(
            conn,
            DeliverCommand::Open {
                file: Some(path),
                slot: Some(slot.to_string()),
                share_file: None,
                signing_key_file: None,
                save: None,
                save_dir: Some(args.save_dir.clone()),
                reject: args.reject,
                ack_dir: args.ack_dir.clone(),
                push_ack: push_answer,
                url: args.opts.url.clone().filter(|_| push_answer),
                api_key: args.opts.api_key.clone().filter(|_| push_answer),
            },
        )?,
        envelope::KIND_FILE_DELIVERY_ACK => deliver_cmd::run(
            conn,
            DeliverCommand::Ack {
                file: Some(path),
                slot: Some(slot.to_string()),
                share_file: None,
            },
        )?,
        envelope::KIND_FILE_HISTORY => file_cmd::run(
            conn,
            FileCommand::Receive {
                letter: path,
                slot: Some(slot.to_string()),
                share_file: None,
                signing_key_file: None,
                into: None,
                out: Some(args.save_dir.join(format!("{id}.kqtf"))),
                reject: args.reject,
                ack_dir: args.ack_dir.clone(),
                push_ack: push_answer,
                url: args.opts.url.clone().filter(|_| push_answer),
                api_key: args.opts.api_key.clone().filter(|_| push_answer),
            },
        )?,
        kind if manual_command(kind).is_some() => return Ok(false),
        _ => {
            let bytes = env::read(&path)?;
            let secret = encryption_secret_from(None, Some(slot))?;
            import_envelope(conn, id, &bytes, &secret)?;
        }
    }
    Ok(true)
}

fn open(conn: &Connection, args: OpenArgs) -> Result<()> {
    let url = pull(conn, &args.opts)?;
    let wanted: Vec<_> = db::inbox::list(conn, &url)?
        .into_iter()
        .filter(|l| match args.id {
            Some(id) => l.id == id,
            None => l.status != db::inbox::HANDLED,
        })
        .collect();
    if wanted.is_empty() {
        match args.id {
            Some(id) => return Err(usage(&format!("no letter {id} in this inbox"))),
            None => {
                outln!("(nothing waiting)");
                return Ok(());
            }
        }
    }
    if args.reject
        && wanted.iter().all(|l| {
            l.kind != envelope::KIND_FILE_DELIVERY && l.kind != envelope::KIND_FILE_HISTORY
        })
    {
        errln!("note: --reject applies to delivered files only");
    }
    let slot = profile::resolve_identity(conn, None, args.opts.slot.as_deref())?.slot;
    if args.ack_dir.is_some() {
        env::create_dir_all(args.ack_dir.as_deref().unwrap_or(Path::new(".")))?;
    }
    env::create_dir_all(&args.save_dir)?;
    let mut failed = 0usize;
    for letter in wanted {
        match open_letter(conn, &args, &slot, letter.id, letter.kind) {
            Ok(true) => db::inbox::mark_handled(conn, &url, letter.id)?,
            Ok(false) => {
                if let Some(command) = manual_command(letter.kind) {
                    outln!(
                        "{}  {}: open with `{command} {}`",
                        letter.id,
                        kind_name(letter.kind),
                        letter_path(&args.opts.dir, letter.id).display()
                    );
                }
            }
            Err(err) => {
                failed += 1;
                errln!("letter {}: {err}", letter.id);
            }
        }
    }
    if failed > 0 {
        return Err(Error::RelayRequest(format!(
            "{failed} letter{} could not be opened; they stay in the inbox",
            if failed == 1 { "" } else { "s" }
        )));
    }
    Ok(())
}

pub(crate) fn run(conn: &Connection, command: Option<InboxCommand>) -> Result<()> {
    match command {
        None => list(conn, &InboxOpts::default()),
        Some(InboxCommand::List(opts)) => list(conn, &opts),
        Some(InboxCommand::Open(args)) => open(conn, args),
    }
}
