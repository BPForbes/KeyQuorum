//! `keyquorum outbox`: your outbox ring buffer, over `crate::outbox`.
//!
//! `outbox add` queues sealed letters (`.kqpb`, the passport between two
//! people's rings) for a trusted recipient at the write pointer; a
//! tracked-file letter also names your copy of the file (`--file`), whose
//! history shows whether the step before it has happened. `outbox send`
//! sends from the read pointer, oldest first, to the relay with your stored
//! push key or to `--output-dir`. Only a send that succeeds moves the read
//! pointer. `outbox` alone shows the ring: index, size, free slots and its
//! state (empty, partial, full). The rules are `outbox`'s and
//! `file_delivery::exchange`'s; this command adds none of its own.

use super::env::{self, outln};
use super::inbox::kind_name;
use super::{file_cmd, resolve_relay_auth, usage};
use crate::db::profile;
use crate::error::Result;
use crate::outbox::{self, QueuedItem, Ring};
use crate::relay::{self, ApiKeyScope};
use clap::{Args, Subcommand};
use rusqlite::Connection;
use std::path::PathBuf;

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
        }
        OutboxCommand::Add { files, to, file } => {
            let copy = file.as_deref().map(file_cmd::load).transpose()?;
            for path in files {
                let bytes = env::read(&path)?;
                let item = outbox::push(conn, &owner, &to, &bytes, copy.as_ref())?;
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

fn send(
    conn: &Connection,
    owner: &str,
    all: bool,
    output_dir: Option<PathBuf>,
    url: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    if let Some(dir) = &output_dir {
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
        let item = outbox::send_next(conn, owner, |item, bytes| match &output_dir {
            Some(dir) => {
                let path = dir.join(format!(
                    "{}-{}.kqpb",
                    item.recipient,
                    &item.content_hash[..16]
                ));
                env::write_new(&path, bytes)?;
                outln!("Wrote {}", path.display());
                Ok(())
            }
            None => {
                let (url, key) = relay_auth.as_ref().expect("resolved above");
                let accepted = relay::push_inbox(&env::EnvRelay, url, key, bytes)?;
                outln!("Relay stored letter {}", accepted.id);
                Ok(())
            }
        })?;
        match item {
            Some(item) => {
                print_item("Sent", &item);
                sent += 1;
            }
            None => break,
        }
        if !all {
            break;
        }
    }
    if sent == 0 {
        outln!("Outbox for {owner} is empty: nothing to send");
    }
    print_ring(&outbox::ring(conn, owner)?);
    Ok(())
}
