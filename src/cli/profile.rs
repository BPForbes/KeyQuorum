//! `keyquorum use` and `keyquorum cache`, and the rules that let a command
//! leave a flag out.
//!
//! A flag that is left out resolves, in order, from the explicit argument,
//! then a recent parameter (fresh for [`crate::db::cache::TTL_MINUTES`]),
//! then the stored profile, then the command's own behaviour or error. The
//! profile is pointers only; the device container, the slot token and
//! `relay_credentials` stay the authority, and nothing here reads or stores a
//! passphrase, key or bearer.

use super::env::{self, errln, outln};
use super::usage;
use crate::db::{self, cache, profile};
use crate::error::Result;
use crate::{device, keys, relay};
use clap::{Subcommand, ValueEnum};
use rusqlite::Connection;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, ValueEnum)]
pub enum CacheSwitch {
    On,
    Off,
}

#[derive(Subcommand)]
pub enum CacheCommand {
    /// Forget recent parameters, relay trust checks and verified facts. The
    /// stored defaults (`keyquorum use`) are kept.
    Clear,
    /// Say whether caching is on and what is held
    Status,
}

thread_local! {
    static NO_CACHE: Cell<bool> = const { Cell::new(false) };
    /// Slot secrets opened during this command, so a command that touches
    /// the same slot twice asks for its passphrase once. In memory only,
    /// zeroized when the command ends; never shared across commands.
    static SLOTS: RefCell<HashMap<String, device::SlotSecrets>> = RefCell::new(HashMap::new());
    /// Relays whose identity this command already proved.
    static PROVEN_RELAYS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

/// State that lives for exactly one top-level command: `--no-cache`, the
/// opened slots and the relays already proven. Dropping it (even on an error)
/// restores the flag and zeroizes the secrets.
pub(crate) struct RunScope {
    previous_no_cache: bool,
}

impl RunScope {
    pub(crate) fn enter(no_cache: bool) -> Self {
        SLOTS.with(|slots| slots.borrow_mut().clear());
        PROVEN_RELAYS.with(|relays| relays.borrow_mut().clear());
        RunScope {
            previous_no_cache: NO_CACHE.with(|flag| flag.replace(no_cache)),
        }
    }
}

impl Drop for RunScope {
    fn drop(&mut self) {
        SLOTS.with(|slots| slots.borrow_mut().clear());
        PROVEN_RELAYS.with(|relays| relays.borrow_mut().clear());
        NO_CACHE.with(|flag| flag.set(self.previous_no_cache));
    }
}

fn copy_secrets(secrets: &device::SlotSecrets) -> device::SlotSecrets {
    device::SlotSecrets {
        label: secrets.label.clone(),
        encryption_secret: secrets.encryption_secret.clone(),
        signing_secret: secrets.signing_secret.clone(),
        encryption_public: secrets.encryption_public,
        signing_public: secrets.signing_public,
    }
}

/// The secrets for `entry` (`container=label`) if this command already
/// opened that slot, or else whatever `open` returns, kept for the rest of
/// the command.
pub(crate) fn slot_secrets(
    entry: &str,
    open: impl FnOnce() -> Result<device::SlotSecrets>,
) -> Result<device::SlotSecrets> {
    if let Some(found) = SLOTS.with(|slots| slots.borrow().get(entry).map(copy_secrets)) {
        return Ok(found);
    }
    let opened = open()?;
    SLOTS.with(|slots| {
        slots
            .borrow_mut()
            .insert(entry.to_string(), copy_secrets(&opened))
    });
    Ok(opened)
}

/// Whether this command already proved the relay's identity.
pub(crate) fn relay_proven(url: &str) -> bool {
    PROVEN_RELAYS.with(|relays| relays.borrow().contains(url))
}

pub(crate) fn mark_relay_proven(url: &str) {
    PROVEN_RELAYS.with(|relays| relays.borrow_mut().insert(url.to_string()));
}

/// Whether this command may read or write the caches: not with `--no-cache`
/// or `KEYQUORUM_NO_CACHE`, and not once `keyquorum use --cache off` was run.
pub(crate) fn caching(conn: &Connection) -> bool {
    if NO_CACHE.with(Cell::get) {
        return false;
    }
    if matches!(env::var("KEYQUORUM_NO_CACHE"), Ok(v) if !v.is_empty() && v != "0" && v != "false")
    {
        return false;
    }
    profile::cache_enabled(conn).unwrap_or(true)
}

/// A resolved identity: the label a command acts as, and the
/// `container=label` slot that signs for it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub label: String,
    pub slot: String,
}

fn split_slot(slot: &str) -> Result<(&str, &str)> {
    match slot.rsplit_once('=') {
        Some((path, label)) if !path.is_empty() && !label.is_empty() => Ok((path, label)),
        _ => Err(usage("--slot must be container=label")),
    }
}

/// Who a command acts as. `--slot` and `--as` win; what they leave out comes
/// from the profile. If both are given they must name the same label, which
/// nothing checked before.
pub(crate) fn resolve_identity(
    conn: &Connection,
    as_label: Option<&str>,
    slot: Option<&str>,
) -> Result<Identity> {
    if let Some(slot) = slot {
        let (_, slot_label) = split_slot(slot)?;
        if let Some(label) = as_label {
            if label != slot_label {
                return Err(usage(&format!(
                    "--as {label} does not match the label of --slot {slot} ({slot_label})"
                )));
            }
        }
        return Ok(Identity {
            label: slot_label.to_string(),
            slot: slot.to_string(),
        });
    }
    let default_label = profile::get(conn, profile::DEFAULT_LABEL)?;
    let default_slot_label = profile::get(conn, profile::DEFAULT_SLOT_LABEL)?;
    let container = profile::get(conn, profile::DEFAULT_CONTAINER)?;
    let slot_label = as_label
        .map(str::to_string)
        .or(default_slot_label)
        .or_else(|| default_label.clone());
    let (Some(container), Some(slot_label)) = (container, slot_label) else {
        return Err(usage(
            "no identity: pass --slot container=label, or set defaults with \
             `keyquorum use --device PATH --slot LABEL`",
        ));
    };
    Ok(Identity {
        label: as_label
            .map(str::to_string)
            .or(default_label)
            .unwrap_or_else(|| slot_label.clone()),
        slot: format!("{container}={slot_label}"),
    })
}

/// The label and slot of someone who signs: from `--slot`/`--as` and the
/// profile, or, with a `--signing-key-file`, just the label (there is no slot).
pub(crate) fn resolve_signer(
    conn: &Connection,
    as_label: Option<String>,
    slot: Option<String>,
    signing_key_file: Option<&Path>,
) -> Result<(String, Option<String>)> {
    if signing_key_file.is_some() {
        let label = match as_label {
            Some(label) => label,
            None => profile::get(conn, profile::DEFAULT_LABEL)?
                .ok_or_else(|| usage("pass --as, or set a default with `keyquorum use`"))?,
        };
        return Ok((label, None));
    }
    let identity = resolve_identity(conn, as_label.as_deref(), slot.as_deref())?;
    Ok((identity.label, Some(identity.slot)))
}

/// Remember what the user gave a command that succeeded, so the next one can
/// leave it out. Best effort: a cache failure never fails a command.
pub(crate) fn remember(conn: &Connection, name: &str, value: &str) {
    if !caching(conn) {
        return;
    }
    if let Ok(now) = env::now_utc() {
        let _ = cache::remember(conn, name, value, &now);
    }
}

/// A parameter the user left out, filled from a recent use when there is
/// one. `name` is a key such as `deliver-open:file`; the part after the colon
/// is the flag it stands for, and the part before keeps commands from
/// borrowing each other's values. It says so on stderr every time. Commands that act outward or cannot
/// be undone (`outward`) never take a target from a recent use: they return
/// `None` and the usual "required" error follows.
pub(crate) fn recent_or(
    conn: &Connection,
    name: &str,
    explicit: Option<String>,
    outward: bool,
) -> Result<Option<String>> {
    if explicit.is_some() || outward || !caching(conn) {
        return Ok(explicit);
    }
    let found = cache::recall(conn, name, &env::now_utc()?)?;
    Ok(found.map(|recent| {
        let flag = name.rsplit(':').next().unwrap_or(name);
        errln!(
            "using --{flag} {} from {}m ago; pass it to override or --no-cache to ignore",
            recent.value,
            recent.age_minutes
        );
        recent.value
    }))
}

#[derive(clap::Args)]
pub struct UseOpts {
    /// Your label (defaults to the slot label the first time)
    #[arg(long)]
    pub label: Option<String>,
    /// Your slot label in the device container
    #[arg(long)]
    pub slot: Option<String>,
    /// The device container directory that holds the slot
    #[arg(long)]
    pub device: Option<PathBuf>,
    /// The relay you normally use
    #[arg(long)]
    pub url: Option<String>,
    /// Turn the caches on or off (off also empties them)
    #[arg(long, value_enum)]
    pub cache: Option<CacheSwitch>,
    /// Print the stored defaults (the default when nothing is set)
    #[arg(long)]
    pub show: bool,
    /// Forget every stored default
    #[arg(long, conflicts_with_all = ["label", "slot", "device", "url", "cache", "show"])]
    pub clear: bool,
}

pub(crate) fn run_use(conn: &Connection, args: UseOpts) -> Result<()> {
    if args.clear {
        profile::clear_all(conn)?;
        outln!("Cleared stored defaults");
        return Ok(());
    }
    let changing = args.label.is_some()
        || args.slot.is_some()
        || args.device.is_some()
        || args.url.is_some()
        || args.cache.is_some();
    if !changing || args.show {
        return show(conn);
    }

    let container = match &args.device {
        Some(path) => Some(path.display().to_string()),
        None => profile::get(conn, profile::DEFAULT_CONTAINER)?,
    };
    let slot_label = match &args.slot {
        Some(label) => Some(label.clone()),
        None => profile::get(conn, profile::DEFAULT_SLOT_LABEL)?,
    };
    // A device or slot change is checked against the container, without a
    // passphrase, before anything is stored.
    if args.device.is_some() || args.slot.is_some() {
        let (Some(path), Some(label)) = (&container, &slot_label) else {
            return Err(usage("--device and --slot are set together the first time"));
        };
        let opened = env::fs(|fs| device::open_in(fs, Path::new(path)))?;
        if opened.slot(label).is_none() {
            return Err(usage(&format!("no slot {label} in {path}")));
        }
    }
    if let Some(url) = &args.url {
        let url = db::relay_credential::normalize_url(url);
        relay::validate_relay_url(&url)?;
        profile::set(conn, profile::DEFAULT_RELAY_URL, &url)?;
        if !db::relay_credential::has_any_for_url(conn, &url)? {
            errln!("note: no relay key is loaded for {url}; run `keyquorum loadkey --url {url}`");
        }
    }
    if let Some(path) = &container {
        if args.device.is_some() {
            profile::set(conn, profile::DEFAULT_CONTAINER, path)?;
        }
    }
    if let Some(label) = &args.slot {
        profile::set(conn, profile::DEFAULT_SLOT_LABEL, label)?;
    }
    let label = args.label.clone().or_else(|| {
        // The label defaults to the slot's the first time only.
        match (&args.slot, profile::get(conn, profile::DEFAULT_LABEL)) {
            (Some(slot), Ok(None)) => Some(slot.clone()),
            _ => None,
        }
    });
    if let Some(label) = &label {
        profile::set(conn, profile::DEFAULT_LABEL, label)?;
        if keys::active_keys_for(conn, label, keys::KeyType::Encryption)?.is_empty() {
            errln!(
                "note: no encryption key is registered for {label} in this store; \
                 run `keyquorum device register ... --slot {label} --type encryption`"
            );
        }
    }
    if let Some(switch) = args.cache {
        match switch {
            CacheSwitch::Off => {
                profile::set(conn, profile::CACHE_ENABLED, "off")?;
                cache::clear(conn)?;
            }
            CacheSwitch::On => profile::clear(conn, profile::CACHE_ENABLED)?,
        }
    }
    show(conn)
}

fn show(conn: &Connection) -> Result<()> {
    let stored = profile::all(conn)?;
    if stored.is_empty() {
        outln!("No defaults set. See `keyquorum use --help`.");
    }
    for (key, value) in stored {
        outln!("{key} = {value}");
    }
    outln!(
        "caching = {}",
        if profile::cache_enabled(conn)? {
            "on"
        } else {
            "off"
        }
    );
    Ok(())
}

pub(crate) fn run_cache(conn: &Connection, command: CacheCommand) -> Result<()> {
    match command {
        CacheCommand::Clear => {
            cache::clear(conn)?;
            outln!("Cleared recent parameters, relay trust checks and verified facts");
        }
        CacheCommand::Status => {
            let count = |table: &str| -> Result<i64> {
                Ok(
                    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?,
                )
            };
            outln!(
                "caching {} (entries fresh for {} minutes)",
                if caching(conn) { "on" } else { "off" },
                cache::TTL_MINUTES
            );
            outln!("recent parameters: {}", count("recent_params")?);
            outln!("relay trust checks: {}", count("relay_trust_cache")?);
            outln!("verified facts: {}", count("verified_cache")?);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "profile/tests.rs"]
mod tests;
