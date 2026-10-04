//! `keyquorum outbox`: your outbox ring buffer, over `crate::outbox`.
//!
//! `outbox add` queues sealed letters (`.kqpb`, the passport between two
//! people's rings) for a trusted recipient at the write pointer; a
//! tracked-file letter also names your copy of the file (`--file`), whose
//! history shows whether the step before it has happened. `outbox send`
//! sends from the read pointer, oldest first, to the relay with your stored
//! push key or to `--output-dir`. Only a send that succeeds moves the read
//! pointer. `outbox` alone shows the ring: index, size, free slots and its
//! state (empty, partial, full). `outbox refusals` lists the letters the ring
//! turned away at departure and the rule each broke. The rules are
//! `outbox`'s and `file_delivery::exchange`'s; this command adds none of its
//! own.

use super::env::{self, errln, outln};
use super::inbox::kind_name;
use super::{file_cmd, resolve_relay_auth, sanitize_label, usage};
use crate::db::profile;
use crate::error::Result;
use crate::file_delivery::exchange::Visa;
use crate::file_history::TrackedFile;
use crate::outbox::{self, QueuedItem, Refusal, Ring};
use crate::relay::{self, ApiKeyScope};
use clap::{Args, Subcommand};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct OutboxOpts {
    /// Whose outbox (default: your label from `keyquorum use`)
    #[arg(long = "as", global = true)]
    pub as_label: Option<String>,
    #[command(subcommand)]
    pub command: Option<OutboxCommand>,
}

#[derive(Subcommand)]
pub enum OutboxCommand {
    /// Show the ring and what it holds, oldest first (the default)
    Status,
    /// Queue sealed letters (.kqpb) for one recipient, each sealed to the
    /// encryption key registered here for them
    Add {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Recipient label (their encryption key must be registered here)
        #[arg(long)]
        to: String,
        /// Your copy of the tracked file the letters concern: needed for an
        /// answer, a tracked file, a receipt or a snapshot, whose order is
        /// read from this copy's history
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Send the oldest item (or, with --all, every item in order)
    Send {
        /// Keep sending until the ring is empty or a send fails
        #[arg(long)]
        all: bool,
        /// Write the letters here instead of uploading them to the relay
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Relay base URL (default: `keyquorum use --url`)
        #[arg(long)]
        url: Option<String>,
        /// Push-scope API key (default: a key from `loadkey`)
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Discard the oldest item without sending it (it is wiped)
    Drop,
    /// Set the number of slots (1 to 1024). Only an empty ring is resized
    Capacity { slots: u32 },
    /// The letters the ring turned away at departure, newest first, and the
    /// rule each broke (the letters themselves are not kept)
    Refusals {
        /// How many to show
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
}

fn owner(conn: &Connection, as_label: Option<String>) -> Result<String> {
    match as_label {
        Some(label) => Ok(label),
        None => profile::get(conn, profile::DEFAULT_LABEL)?.ok_or_else(|| {
            usage("whose outbox? pass --as LABEL, or set it with `keyquorum use --as LABEL`")
        }),
    }
}

fn print_ring(ring: &Ring) {
    outln!(
        "Outbox for {}: {} of {} slots held, {} free ({}); read index {}, write index {}; {} sent",
        ring.owner,
        ring.size,
        ring.capacity,
        ring.free(),
        ring.state().as_str(),
        ring.read_index,
        ring.write_index,
        ring.sent_total
    );
}

/// What a refusal means, in a sentence.
fn refusal_text(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::NoPassport => "not a sealed letter (.kqpb): no passport",
        Refusal::DeviceLetter => "a device letter: it never leaves your own devices",
        Refusal::UnrecognisedDestination => {
            "not sealed to an active key this store holds for the recipient"
        }
        Refusal::OutOfOrder => "out of order: the step before it is missing",
        Refusal::RingFull => "the outbox was full",
        Refusal::Oversized => "larger than the outbox takes",
        Refusal::Tampered => "the held letter no longer matched what was queued",
    }
}

fn print_item(prefix: &str, item: &QueuedItem) {
    outln!(
        "{prefix} slot {}: {} to {} ({} bytes, sha256 {}, queued {})",
        item.index,
        kind_name(item.kind),
        item.recipient,
        item.len,
        &item.content_hash[..16],
        item.queued_at
    );
}

#[inline(never)]
pub(crate) fn run(conn: &Connection, opts: OutboxOpts) -> Result<()> {
    let owner = owner(conn, opts.as_label)?;
    match opts.command.unwrap_or(OutboxCommand::Status) {
        OutboxCommand::Status => {
            print_ring(&outbox::ring(conn, &owner)?);
            for item in outbox::list(conn, &owner)? {
                print_item(" ", &item);
            }
            if let Some(last) = outbox::refusals(conn, &owner, 1)?.first() {
                outln!(
                    "Last refused at departure: to {} at {} ({}); see `keyquorum outbox refusals`",
                    last.recipient,
                    last.refused_at,
                    last.refusal.as_str()
                );
            }
        }
        OutboxCommand::Refusals { limit } => {
            let refused = outbox::refusals(conn, &owner, limit)?;
            if refused.is_empty() {
                outln!("Outbox for {owner} has refused nothing");
            }
            for record in refused {
                let kind = record.kind.map_or("unreadable", kind_name);
                outln!(
                    "{}  to {}  {}  {}: {}{}",
                    record.refused_at,
                    record.recipient,
                    kind,
                    record.refusal.as_str(),
                    refusal_text(record.refusal),
                    record
                        .step
                        .map(|step| format!(" ({step})"))
                        .unwrap_or_default()
                );
            }
        }
        OutboxCommand::Add { files, to, file } => {
            let copy = file.as_deref().map(file_cmd::load).transpose()?;
            for path in files {
                let bytes = env::read(&path)?;
                let item = outbox::push(
                    conn,
                    &owner,
                    &to,
                    &bytes,
                    copy.as_ref().map(|c| (c, Visa::Required)),
                )?;
                print_item(&format!("Queued {}:", path.display()), &item);
            }
            print_ring(&outbox::ring(conn, &owner)?);
        }
        OutboxCommand::Send {
            all,
            output_dir,
            url,
            api_key,
        } => send(conn, &owner, all, output_dir, url, api_key)?,
        OutboxCommand::Drop => match outbox::drop_next(conn, &owner)? {
            Some(item) => print_item("Dropped", &item),
            None => outln!("Outbox for {owner} is empty: nothing to drop"),
        },
        OutboxCommand::Capacity { slots } => {
            if slots == 0 || slots > outbox::MAX_CAPACITY {
                return Err(usage(&format!(
                    "capacity must be 1 to {}",
                    outbox::MAX_CAPACITY
                )));
            }
            print_ring(&outbox::set_capacity(conn, &owner, slots)?);
        }
    }
    Ok(())
}

/// How far a send from the read pointer goes.
enum Until {
    /// The oldest letter only.
    One,
    /// Every letter, until the ring is empty.
    Empty,
    /// Through the letter just queued in this slot (`send`'s own).
    Through { index: u32, content_hash: String },
}

fn send(
    conn: &Connection,
    owner: &str,
    all: bool,
    output_dir: Option<PathBuf>,
    url: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let until = if all { Until::Empty } else { Until::One };
    let sent = drain(conn, owner, until, output_dir.as_deref(), url, api_key)?;
    if sent == 0 {
        outln!("Outbox for {owner} is empty: nothing to send");
    }
    print_ring(&outbox::ring(conn, owner)?);
    Ok(())
}

/// `send`'s way out: queue the sealed letter in the sender's outbox, then send
/// the ring in order, oldest first, through that letter. The ring's checks
/// (passport, destination, size, and for a tracked file its visa when the
/// recipient asked for it) apply to every letter `send` makes, and a refusal
/// is recorded. A letter that cannot be sent now stays queued for `outbox
/// send`; nothing is lost and nothing jumps the queue.
pub(super) fn carry_via_outbox(
    conn: &Connection,
    owner: &str,
    recipient: &str,
    bytes: &[u8],
    copy: Option<&TrackedFile>,
    (output_dir, url, api_key): (Option<&Path>, Option<String>, Option<String>),
) -> Result<()> {
    let item = outbox::push(
        conn,
        owner,
        recipient,
        bytes,
        copy.map(|c| (c, Visa::IfRequested)),
    )?;
    print_item("Queued", &item);
    let until = Until::Through {
        index: item.index,
        content_hash: item.content_hash.clone(),
    };
    drain(conn, owner, until, output_dir, url, api_key).map(|_| ()).inspect_err(|_| {
        errln!("note: the letter stays in your outbox; `keyquorum outbox` shows it, `keyquorum outbox send` retries and `keyquorum outbox drop` discards the oldest");
    })
}

/// Send from the read pointer, oldest first, until `until` is met. Returns
/// how many were sent.
fn drain(
    conn: &Connection,
    owner: &str,
    until: Until,
    output_dir: Option<&Path>,
    url: Option<String>,
    api_key: Option<String>,
) -> Result<usize> {
    if let Some(dir) = output_dir {
        env::create_dir_all(dir)?;
    }
    // The relay is resolved (and proven) once, before the first send, and
    // only when letters go to it.
    let mut relay_auth = None;
    let mut sent = 0;
    loop {
        if outbox::ring(conn, owner)?.state() == outbox::RingState::Empty {
            break;
        }
        if output_dir.is_none() && relay_auth.is_none() {
            relay_auth = Some(resolve_relay_auth(
                conn,
                url.clone(),
                api_key.clone(),
                ApiKeyScope::InboxPush,
            )?);
        }
        // Files are never overwritten, so a letter left in the directory by
        // a send whose dequeue then failed would block the retry the ring
        // promises. One this attempt wrote is removed again when the
        // dequeue fails; one already there with the same bytes (a crash
        // between the write and the commit) counts as written.
        let mut written = None;
        let sent_item = outbox::send_next(conn, owner, |item, bytes| match output_dir {
            Some(dir) => {
                // Labels are not restricted to filename-safe characters; a
                // recipient like `../x` must not escape the directory.
                let path = dir.join(format!(
                    "{}-{}.kqpb",
                    sanitize_label(&item.recipient)?,
                    &item.content_hash[..16]
                ));
                if env::exists(&path) && env::read(&path)? == bytes {
                    written = Some((path, false));
                    return Ok(());
                }
                env::write_new(&path, bytes)?;
                written = Some((path, true));
                Ok(())
            }
            None => {
                let (url, key) = relay_auth.as_ref().expect("resolved above");
                let accepted = relay::push_inbox(&env::EnvRelay, url, key, bytes)?;
                outln!(
                    "Relay stored letter {} for {}",
                    accepted.id,
                    accepted.recipient_fingerprint
                );
                Ok(())
            }
        });
        let item = match sent_item {
            Ok(item) => {
                match &written {
                    Some((path, true)) => outln!("Wrote {}", path.display()),
                    Some((path, false)) => outln!("Already written {}", path.display()),
                    None => {}
                }
                item
            }
            Err(err) => {
                if let Some((path, true)) = &written {
                    let _ = env::remove_file(path);
                }
                return Err(err);
            }
        };
        let Some(item) = item else { break };
        print_item("Sent", &item);
        sent += 1;
        let done = match &until {
            Until::One => true,
            Until::Empty => false,
            Until::Through {
                index,
                content_hash,
            } => item.index == *index && &item.content_hash == content_hash,
        };
        if done {
            break;
        }
    }
    Ok(sent)
}
