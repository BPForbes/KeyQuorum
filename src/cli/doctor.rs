//! `keyquorum doctor`: what is missing before a task will work, and the
//! command that fixes each thing. It only reads: no passphrase is asked, no
//! relay is called, nothing is written except a note that a check passed.

use super::env::{self, outln};
use super::profile;
use super::usage;
use crate::db::{self, cache, profile as stored};
use crate::error::Result;
use crate::keys::{self, KeyType};
use crate::{device, relay};
use clap::Args;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Args)]
pub struct DoctorOpts {
    /// Also check that this recipient can be sent to
    #[arg(long)]
    pub to: Option<String>,
}

struct Report {
    problems: usize,
}

impl Report {
    fn ok(&self, what: &str) {
        outln!("ok    {what}");
    }

    fn fix(&mut self, what: &str, how: &str) {
        self.problems += 1;
        outln!("FIX   {what}\n      -> {how}");
    }

    fn info(&self, what: &str) {
        outln!("info  {what}");
    }
}

/// A fingerprint of the container's descriptor, so a cached "this slot exists"
/// goes stale the moment the container changes.
fn container_fingerprint(path: &Path) -> Option<String> {
    env::read(&path.join("device.kq"))
        .ok()
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
}

fn check_identity(conn: &Connection, report: &mut Report) -> Result<()> {
    let label = stored::get(conn, stored::DEFAULT_LABEL)?;
    let slot_label = stored::get(conn, stored::DEFAULT_SLOT_LABEL)?;
    let container = stored::get(conn, stored::DEFAULT_CONTAINER)?;
    let (Some(label), Some(slot_label), Some(container)) = (label, slot_label, container) else {
        report.fix(
            "no default identity is set",
            "keyquorum setup --device PATH --label LABEL   (or: keyquorum use --device PATH --slot LABEL)",
        );
        return Ok(());
    };
    report.ok(&format!(
        "acting as {label} (slot {slot_label} in {container})"
    ));

    let path = Path::new(&container);
    let subject = format!("{container}={slot_label}");
    let now = env::now_utc()?;
    let fingerprint = container_fingerprint(path);
    let cached = profile::caching(conn)
        && match &fingerprint {
            Some(fp) => cache::verified_hit(conn, "slot", &subject, fp, &now)?,
            None => false,
        };
    let opened = match env::fs(|fs| device::open_in(fs, path)) {
        Ok(opened) => opened,
        Err(_) => {
            report.fix(
                &format!("the device container {container} cannot be opened"),
                "plug the device in, or point at it again with `keyquorum use --device PATH`",
            );
            return Ok(());
        }
    };
    let Some(slot) = opened.slot(&slot_label) else {
        report.fix(
            &format!("slot {slot_label} is not in {container}"),
            "keyquorum setup --device PATH --label LABEL",
        );
        return Ok(());
    };
    if cached {
        report.ok(&format!(
            "slot {slot_label} is in the container (checked recently)"
        ));
    } else {
        report.ok(&format!("slot {slot_label} is in the container"));
        if let (true, Some(fp)) = (profile::caching(conn), &fingerprint) {
            let _ = cache::store_verified(conn, "slot", &subject, fp, &now);
        }
    }

    for (kind, public) in [
        (KeyType::Encryption, slot.encryption_public),
        (KeyType::Signing, slot.signing_public),
    ] {
        match keys::get_key_by_public_key(conn, &public) {
            Ok(_) => report.ok(&format!(
                "{} key is registered in this store",
                kind.as_str()
            )),
            Err(_) => report.fix(
                &format!(
                    "the {} key of {slot_label} is not registered in this store",
                    kind.as_str()
                ),
                &format!(
                    "keyquorum device register {container} --slot {slot_label} --type {}",
                    kind.as_str()
                ),
            ),
        }
    }
    let bound: bool = keys::get_key_by_public_key(conn, &slot.encryption_public)
        .ok()
        .map(|key| {
            conn.query_row(
                "SELECT 1 FROM device_placements
                 WHERE hardware_key_id = ?1 AND device_id = ?2",
                rusqlite::params![key.id, opened.device_id().as_slice()],
                |_| Ok(()),
            )
            .is_ok()
        })
        .unwrap_or(false);
    if bound {
        report.ok("the slot is bound to its device");
    } else {
        report.fix(
            "the slot is not bound to its device",
            &format!("keyquorum device bind {container} --slot {slot_label}"),
        );
    }
    Ok(())
}

/// The relay each scope would use is chosen by the same function `send` and
/// `inbox` call, so the report cannot describe a different relay from the one
/// the command talks to.
fn check_relay(conn: &Connection, report: &mut Report) -> Result<()> {
    let mut shown: Vec<String> = Vec::new();
    let mut any = false;
    for (scope, purpose) in [
        (relay::ApiKeyScope::InboxPush, "sending"),
        (relay::ApiKeyScope::InboxPull, "receiving"),
    ] {
        match super::configured_relay_url(conn, None, scope) {
            Err(err) => {
                any = true;
                report.fix(
                    &format!("the relay for {purpose} cannot be chosen: {err}"),
                    "keyquorum use --url URL (or pass --url, or unset KEYQUORUM_RELAY_URL)",
                );
            }
            Ok(None) => {}
            Ok(Some(url)) => {
                any = true;
                if !shown.contains(&url) {
                    report.ok(&format!("relay {url}"));
                    shown.push(url.clone());
                }
                if db::relay_credential::get(conn, &url, scope.as_str())?.is_some() {
                    report.ok(&format!("a {} key is loaded for {purpose}", scope.as_str()));
                } else {
                    report.fix(
                        &format!("no {} key is loaded for {purpose}", scope.as_str()),
                        &format!("keyquorum loadkey --url {url}"),
                    );
                }
            }
        }
    }
    if !any {
        report
            .info("no relay is set; sends go to ./outbox (add one with `keyquorum use --url URL`)");
    }
    Ok(())
}

pub(crate) fn run(conn: &Connection, opts: DoctorOpts) -> Result<()> {
    let mut report = Report { problems: 0 };
    check_identity(conn, &mut report)?;
    check_relay(conn, &mut report)?;
    if let Some(to) = &opts.to {
        if keys::active_keys_for(conn, to, KeyType::Encryption)?.is_empty() {
            report.fix(
                &format!("no encryption key is registered for {to} in this store"),
                &format!(
                    "keyquorum register --type encryption --label {to} --public-key-file {to}.pub"
                ),
            );
        } else {
            report.ok(&format!("{to} has a registered encryption key"));
        }
    }
    report.info(&format!(
        "caching is {}",
        if profile::caching(conn) { "on" } else { "off" }
    ));
    if report.problems > 0 {
        return Err(usage(&format!(
            "{} problem{} found; the lines marked FIX say how to fix each",
            report.problems,
            if report.problems == 1 { "" } else { "s" }
        )));
    }
    outln!("Everything checks out.");
    Ok(())
}
