//! `keyquorum inbox`: pull what is waiting and open it, in one command.
//!
//! `inbox` lists the letters a relay holds for you. `inbox open` opens each
//! one the way the single-purpose command would have, and posts the signed
//! answer: a delivery with `deliver open`, an answer to your delivery with
//! `deliver ack`, a tracked file with `file receive`, a bridge or org update
//! with the import `relay pull --import` runs. It judges nothing itself.
//!
//! Pulled letters are kept in a relay-specific directory below `--dir`
//! (`inbox/`) as `<relay hash>/<id>.kqpb`; the store
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
use sha2::{Digest, Sha256};
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
    /// Pull-scope API key for this pull (or a key from `loadkey`). Answers are
    /// uploaded with your stored push key
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
    /// One tracked-file letter: merge it into this copy of the file
    #[arg(long, conflicts_with = "out")]
    pub into: Option<PathBuf>,
    /// One tracked-file letter: write it as a new copy here
    /// (default: <save-dir>/<id>.kqtf)
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// One letter: the copy of the tracked file it concerns. An answer to your
    /// tracked file or request is recorded in it; a request is recorded in it;
    /// a history snapshot is compared with it. A letter never picks this
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// One request letter: say yes (a decision is never guessed)
    #[arg(long, conflicts_with = "decline")]
    pub accept: bool,
    /// One request letter: say no
    #[arg(long)]
    pub decline: bool,
}

impl OpenArgs {
    /// Options that name a file or a decision belong to one letter.
    fn names_a_target(&self) -> bool {
        self.into.is_some()
            || self.out.is_some()
            || self.file.is_some()
            || self.accept
            || self.decline
    }
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

/// What a person does to open a letter `inbox open` cannot open alone: it
/// needs a copy of a file or a decision only they can give.
fn manual_hint(kind: u8, id: i64) -> Option<String> {
    match kind {
        envelope::KIND_FILE_HISTORY_ACK => Some(format!(
            "keyquorum inbox open {id} --file <your copy of the file.kqtf>"
        )),
        envelope::KIND_FILE_REQUEST_ANSWER => Some(format!(
            "keyquorum inbox open {id} [--file <your copy of the file.kqtf>]"
        )),
        envelope::KIND_FILE_REQUEST => Some(format!(
            "keyquorum inbox open {id} --accept   (or --decline)"
        )),
        envelope::KIND_DEVICE_TRANSFER
        | envelope::KIND_DEVICE_TRANSFER_ACK
        | envelope::KIND_DEVICE_RELOCATE
        | envelope::KIND_DEVICE_RELOCATE_ACK => {
            Some("keyquorum transfer relay-collect".to_string())
        }
        _ => None,
    }
}

fn relay_dir(dir: &Path, url: &str) -> PathBuf {
    dir.join(hex::encode(Sha256::digest(url.as_bytes())))
}

pub(super) fn letter_path(dir: &Path, url: &str, id: i64) -> PathBuf {
    relay_dir(dir, url).join(format!("{id}.kqpb"))
}

/// Locate a pulled letter, including files written before inboxes were
/// namespaced by relay. Existing database rows advance the pull cursor, so a
/// legacy file must remain openable rather than waiting for a redownload that
/// will never happen.
fn stored_letter_path(dir: &Path, url: &str, id: i64) -> Result<PathBuf> {
    let namespaced = letter_path(dir, url, id);
    if env::exists(&namespaced) {
        return Ok(namespaced);
    }

    let legacy = dir.join(format!("{id}.kqpb"));
    if env::exists(&legacy) {
        // Move the compatibility file into its selected relay namespace as
        // soon as it is used. Leaving it at the shared legacy path could let
        // another relay with the same numeric id consume the wrong letter.
        env::fs(|fs| fs.rename(&legacy, &namespaced))?;
        return Ok(namespaced);
    }

    Ok(namespaced)
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
    env::create_dir_all(&relay_dir(&opts.dir, &url))?;
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
            let path = letter_path(&opts.dir, &url, item.id);
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
        match manual_hint(letter.kind, letter.id) {
            Some(hint) => outln!(
                "{}  {}  (open with `{hint}`)",
                letter.id,
                kind_name(letter.kind)
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
fn open_letter(
    conn: &Connection,
    args: &OpenArgs,
    url: &str,
    slot: &str,
    id: i64,
    kind: u8,
) -> Result<bool> {
    let path = stored_letter_path(&args.opts.dir, url, id)?;
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
                api_key: None,
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
                out: match &args.into {
                    Some(_) => None,
                    None => Some(
                        args.out
                            .clone()
                            .unwrap_or_else(|| args.save_dir.join(format!("{id}.kqtf"))),
                    ),
                },
                into: args.into.clone(),
                reject: args.reject,
                ack_dir: args.ack_dir.clone(),
                push_ack: push_answer,
                url: args.opts.url.clone().filter(|_| push_answer),
                api_key: None,
            },
        )?,
        envelope::KIND_FILE_HISTORY_ACK => match &args.file {
            Some(copy) => file_cmd::inbox::ack(conn, copy, &path, slot)?,
            None => return Ok(false),
        },
        // An answer is opened for one letter; the sweep leaves it for a person
        // who can say which copy to record it in. A requester who kept no copy
        // can still read it by naming the letter.
        envelope::KIND_FILE_REQUEST_ANSWER => {
            if args.file.is_none() && args.id.is_none() {
                return Ok(false);
            }
            file_cmd::inbox::answer(conn, &path, slot, args.file.clone())?
        }
        envelope::KIND_FILE_HISTORY_SNAPSHOT => {
            file_cmd::inbox::snapshot(conn, &path, slot, args.file.clone())?
        }
        envelope::KIND_FILE_REQUEST => {
            if !(args.accept || args.decline) {
                return Ok(false);
            }
            file_cmd::inbox::request(
                conn,
                &path,
                slot,
                args.accept,
                args.file.clone(),
                (
                    args.ack_dir.clone(),
                    push_answer,
                    args.opts.url.clone().filter(|_| push_answer),
                    None,
                ),
            )?
        }
        kind if manual_hint(kind, id).is_some() => return Ok(false),
        _ => {
            let bytes = env::read(&path)?;
            let secret = encryption_secret_from(None, Some(slot))?;
            import_envelope(conn, id, &bytes, &secret)?;
        }
    }
    Ok(true)
}

fn open(conn: &Connection, args: OpenArgs) -> Result<()> {
    if args.id.is_none() && args.names_a_target() {
        return Err(usage(
            "--into, --out, --file, --accept and --decline name one letter's file or decision; give the letter's id",
        ));
    }
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
        match open_letter(conn, &args, &url, &slot, letter.id, letter.kind) {
            Ok(true) => db::inbox::mark_handled(conn, &url, letter.id)?,
            Ok(false) => {
                if let Some(hint) = manual_hint(letter.kind, letter.id) {
                    outln!(
                        "{}  {}: open with `{hint}`",
                        letter.id,
                        kind_name(letter.kind)
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
