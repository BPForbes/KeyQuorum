//! `keyquorum setup <package.kqpkg>`: open a provider's package, show what it
//! would do, and with `--yes` do it (issue #104).
//!
//! The package is read with bounded parsing and everything is checked before
//! a single write: its signature and component hashes ([`package::decode`]),
//! its validity window, that its signer is the relay a root-verified, unrevoked
//! certificate names ([`Package::verify_issuer`], against this environment's
//! pinned root), and that nothing it would write conflicts with what is on the
//! drive. Without `--yes` the plan is printed and nothing is changed.
//!
//! Applying runs the same steps a person would: the identity steps of plain
//! `setup`, the relay certificate placed beside the container (never over a
//! different file), and each sealed key opened with the slot and installed
//! through the one path `loadkey --bundle` and `inbox open` use
//! (`install_key_component`: the relay challenge runs before any bearer is
//! sent). It decides no trust of its own, never prints a bearer, and
//! leaves no bootstrap file behind. Running it again finishes what stopped.
//!
//! It is a real-drive command: an environment that cannot honestly offer it,
//! the browser lab, refuses it ([`env::package_setup`]).

use super::env::{self, outln};
use super::{profile, revocation_list, setup, usage, KeyPreview};
use crate::db::package_ledger::{Decision, Incoming, Target};
use crate::db::{self, package_ledger};
use crate::error::{Error, Result};
use crate::package::{self, Component, ComponentKind, Package, Purpose};
use crate::provider;
use crate::setup_manifest::{self, Operation};
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const CERTIFICATE_NAME: &str = "provider.kqcert";

/// The most packages one `setup` takes (issue #108).
pub const MAX_BATCH_PACKAGES: usize = 16;
/// The most package bytes one `setup` reads, all files together.
pub const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;

/// A package that passed every check, and what applying it would do.
pub(super) struct Plan {
    pub(super) package: Package,
    provider_id: String,
    serial: String,
    certificate_expires: String,
    certificate: Vec<u8>,
    /// The steps, in order: the package's own setup manifest, or for a package
    /// without one the fixed steps of its purpose.
    pub(super) steps: Vec<Operation>,
    /// The manifest was in the package (a signed generation exists).
    from_manifest: bool,
    /// What each sealed key says about itself, by the part's SHA-256, checked
    /// before any write.
    keys: HashMap<String, KeyPlan>,
    /// The parts of the package, by SHA-256.
    parts: HashMap<String, Vec<u8>>,
    /// What the ledger knows of this package and its stream.
    pub(super) incoming: Option<Incoming>,
    pub(super) decision: Option<Decision>,
}

/// One sealed key and, for an update, the stored key it replaces.
struct KeyPlan {
    preview: KeyPreview,
    /// The hash of the different key already stored for this relay and scope,
    /// which this update replaces.
    replaces: Option<String>,
}

#[inline(never)]
pub(super) fn run(
    conn: &Connection,
    package_path: &Path,
    device: &Path,
    label: &str,
    yes: bool,
) -> Result<()> {
    if !env::package_setup() {
        return Err(usage("setup with a package is not available here"));
    }
    let bytes = env::read_bounded(package_path, package::MAX_PACKAGE_BYTES)?;
    let plan = plan(conn, &bytes, device, label)?;
    show(&plan, device, label);
    if !plan.package.purpose.is_client() {
        outln!("This package is information only; nothing to install.");
        return Ok(());
    }
    if plan.decision == Some(Decision::AlreadyInstalled) {
        outln!("This package is already installed; nothing to do.");
        return Ok(());
    }
    if !yes {
        outln!("Nothing was changed. Run again with --yes to apply this plan.");
        return Ok(());
    }
    apply(conn, &plan, device, label)
}

/// One selected file in a batch, verified and planned.
struct Batched {
    path: PathBuf,
    bytes: Vec<u8>,
    plan: Plan,
}

impl Batched {
    /// The package id, as the ledger and the results name it.
    fn id(&self) -> String {
        hex::encode(self.plan.package.id)
    }

    /// The stream, generation and purpose the order is decided by.
    fn order_key(&self) -> (String, u64, bool, String) {
        let incoming = self.plan.incoming.as_ref();
        let stream = incoming
            .map(|i| {
                let t = &i.target;
                format!(
                    "{}\0{}\0{}\0{}",
                    t.provider_id, t.recipient, t.device_id, t.slot_label
                )
            })
            .unwrap_or_default();
        (
            stream,
            incoming.and_then(|i| i.generation).unwrap_or(0),
            self.plan.package.purpose == Purpose::ClientUpdate,
            self.id(),
        )
    }
}

/// `keyquorum setup A.kqpkg B.kqpkg ...` (issue #108). Every selected file is
/// read with a bound (each, and all together), verified and planned exactly as
/// one package is, before anything is written; a refusal of any of them writes
/// nothing. Identical files count once. Then the batch is checked as a whole
/// and put in a fixed order: by stream (provider, recipient, drive, slot), then
/// by signed generation, a setup before an update. Refused before any write:
/// two files with one package id, two packages of one stream at the same
/// generation, a setup package after another package of its stream, two
/// packages that would place different certificates on the drive or name
/// different default relays, and anything but client packages. One
/// certificate and one slot make every package of a batch one stream. The combined plan is
/// shown, and `--yes` applies the packages one at a time through the same
/// ledger and executor as one package, re-checking each against the state the
/// ones before it left. It is not one transaction: a package that stops leaves
/// the ones before it installed and the rest not started, each reported, and
/// running the same command again skips what is installed and resumes the rest.
#[inline(never)]
pub(super) fn run_batch(
    conn: &Connection,
    paths: &[PathBuf],
    device: &Path,
    label: &str,
    yes: bool,
) -> Result<()> {
    if !env::package_setup() {
        return Err(usage("setup with a package is not available here"));
    }
    if let [only] = paths {
        return run(conn, only, device, label, yes);
    }
    if paths.len() > MAX_BATCH_PACKAGES {
        return Err(usage(&format!(
            "setup takes at most {MAX_BATCH_PACKAGES} packages at once"
        )));
    }
    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for path in paths {
        let bytes = env::read_bounded(path, package::MAX_PACKAGE_BYTES)?;
        total += bytes.len();
        if total > MAX_BATCH_BYTES {
            return Err(usage(&format!(
                "the selected packages are larger than {} MiB together",
                MAX_BATCH_BYTES / (1024 * 1024)
            )));
        }
        if seen.insert(setup_manifest::hash_of(&bytes)) {
            files.push((path.clone(), bytes));
        } else {
            outln!(
                "{} is the same file as one already selected; it counts once.",
                path.display()
            );
        }
    }
    // The ids the files claim, read from the signed header before planning, so
    // a package left pending by an earlier run of this batch does not block
    // the others in its stream.
    let ids = files
        .iter()
        .map(|(_, bytes)| package::decode(bytes).map(|p| hex::encode(p.id)))
        .collect::<Result<Vec<_>>>()?;
    let mut batch = Vec::new();
    for (path, bytes) in files {
        outln!("Checking {}", path.display());
        let plan = plan_in_batch(conn, &bytes, device, label, &ids)?;
        if !plan.package.purpose.is_client() {
            return Err(usage(&format!(
                "{} is not a client package; open it on its own (several packages are installed \
                 together only when all are client packages)",
                path.display()
            )));
        }
        batch.push(Batched { path, bytes, plan });
    }
    batch.sort_by_key(Batched::order_key);
    check_batch(&batch, device)?;

    outln!("{} packages, in the order they are applied:", batch.len());
    for (number, item) in batch.iter().enumerate() {
        outln!("[{}/{}] {}", number + 1, batch.len(), item.path.display());
        show(&item.plan, device, label);
        if item.plan.decision == Some(Decision::AlreadyInstalled) {
            outln!("  already installed; it is skipped.");
        }
    }
    if !yes {
        outln!(
            "Nothing was changed. Run again with --yes to apply these {} packages in this order.",
            batch.len()
        );
        return Ok(());
    }

    let mut results: Vec<(String, String)> = Vec::new();
    let mut failure = None;
    for item in &batch {
        let id = item.id();
        if failure.is_some() {
            results.push((id, "not started".into()));
            continue;
        }
        outln!("Applying {} ({})", item.path.display(), id);
        // Planned again against what the packages before it left behind.
        let step = plan(conn, &item.bytes, device, label).and_then(|fresh| {
            if fresh.decision == Some(Decision::AlreadyInstalled) {
                Ok(false)
            } else {
                apply(conn, &fresh, device, label).map(|()| true)
            }
        });
        match step {
            Ok(true) => results.push((id, "installed".into())),
            Ok(false) => results.push((id, "already installed".into())),
            Err(err) => {
                let state = match package_ledger::record(conn, &id)? {
                    Some(record) if record.state == "pending" => format!(
                        "stopped, pending (run the same command again, or `keyquorum setup \
                         --abandon {id}`)"
                    ),
                    _ => "refused, nothing recorded".into(),
                };
                results.push((id, state));
                failure = Some(err);
            }
        }
    }
    outln!("Results:");
    for (item, (id, state)) in batch.iter().zip(&results) {
        outln!("  {id} ({}): {state}", item.path.display());
    }
    match failure {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// The batch-wide rules, on the sorted batch. Writes nothing.
fn check_batch(batch: &[Batched], device: &Path) -> Result<()> {
    let refuse = |reason: String| Err(Error::KqpkgRefused(reason));
    let mut ids = HashSet::new();
    let mut relays = HashSet::new();
    for (index, item) in batch.iter().enumerate() {
        let id = item.id();
        if !ids.insert(id.clone()) {
            return refuse(format!(
                "two different files claim to be package {id}; select only the one your provider sent"
            ));
        }
        if item.plan.certificate != batch[0].plan.certificate {
            return refuse(format!(
                "{} and {} would place different relay certificates in {}",
                batch[0].path.display(),
                item.path.display(),
                device.join(CERTIFICATE_NAME).display()
            ));
        }
        for step in &item.plan.steps {
            if let Operation::UseRelay { key, .. } = step {
                if let Some(plan) = item.plan.keys.get(key) {
                    relays.insert(plan.preview.relay_url.clone());
                }
            }
        }
        if relays.len() > 1 {
            return refuse(
                "the packages name different default relays; install them one at a time".into(),
            );
        }
        let (stream, generation, _, _) = item.order_key();
        if let Some(before) = index.checked_sub(1).map(|i| &batch[i]) {
            let (before_stream, before_generation, _, _) = before.order_key();
            if before_stream == stream {
                if before_generation == generation {
                    return refuse(format!(
                        "{} and {} are both generation {generation} for the same slot; select one",
                        before.path.display(),
                        item.path.display()
                    ));
                }
                if item.plan.package.purpose == Purpose::ClientSetup {
                    return refuse(format!(
                        "{} is a setup package after another package for the same slot; a setup \
                         never replaces keys, so select it alone or with its updates",
                        item.path.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `setup --abandon ID`: the explicit reconciliation a stuck package needs
/// before another package can proceed for the same slot. It changes nothing
/// that was installed and keeps the generation it reached.
pub(super) fn abandon(conn: &Connection, package_id: &str) -> Result<()> {
    if !env::package_setup() {
        return Err(usage("setup --abandon is not available here"));
    }
    let record = package_ledger::abandon(conn, &package_id.to_ascii_lowercase())?;
    outln!(
        "Abandoned package {} for {} on {} after {} step(s). What it installed stays; an older \
         package still cannot replace it.",
        record.package_id,
        record.target.slot_label,
        record.target.container,
        record.steps_done.len()
    );
    Ok(())
}

/// Read, verify and plan. Writes nothing.
pub(super) fn plan(conn: &Connection, bytes: &[u8], device: &Path, label: &str) -> Result<Plan> {
    plan_in_batch(conn, bytes, device, label, &[])
}

/// [`plan`] for one package of a batch whose package ids are `batch`
/// ([`package_ledger::decide_in_batch`]).
fn plan_in_batch(
    conn: &Connection,
    bytes: &[u8],
    device: &Path,
    label: &str,
    batch: &[String],
) -> Result<Plan> {
    let package = package::decode(bytes)?;
    let now = env::now_utc()?;
    package.check_valid_at(provider::unix_from_utc(&now)?)?;
    let root = env::provider_root();
    let (revoked, _) = revocation_list(&root)?;
    package.verify_issuer(&root, &now, &revoked)?;
    if package.purpose == Purpose::ProviderRecovery {
        return Err(usage(
            "a provider recovery package is installed on the provider host with \
             `keyquorum host recovery install`, not by setup",
        ));
    }
    let certificate = certificate_of(&package)?.bytes.clone();
    let parsed = provider::parse_certificate(&certificate)?;
    let target = device.join(CERTIFICATE_NAME);
    if env::exists(&target) && env::read(&target)? != certificate {
        return Err(usage(&format!(
            "{} already holds a different certificate; setup will not replace it",
            target.display()
        )));
    }
    let parts: HashMap<String, Vec<u8>> = package
        .components
        .iter()
        .map(|c| (setup_manifest::hash_of(&c.bytes), c.bytes.clone()))
        .collect();
    let mut plan = Plan {
        provider_id: parsed.provider_id,
        serial: parsed.serial,
        certificate_expires: parsed.expires_at,
        certificate,
        steps: Vec::new(),
        from_manifest: false,
        keys: HashMap::new(),
        parts,
        incoming: None,
        decision: None,
        package,
    };
    if !plan.package.purpose.is_client() {
        return Ok(plan);
    }
    // The slot must already exist: a key is sealed to an identity the provider
    // has seen (`setup --enroll-out`), and a new identity made here would not be
    // that one. Its secrets are opened once (the passphrase is asked once).
    let container = env::fs(|fs| crate::device::open_in(fs, device)).map_err(|_| {
        usage(
            "this package's keys are sealed to your slot, which must exist first: run \
             `keyquorum setup --device DIR --label NAME --enroll-out FILE`, send the file to \
             your provider, and open the package they send you",
        )
    })?;
    let slot = format!("{}={label}", device.display());
    let secrets = super::open_slot_secrets(&slot)?;
    let manifest_at = plan
        .package
        .components
        .iter()
        .position(|component| component.kind == ComponentKind::SetupManifest);
    let mut generation = None;
    if let Some(at) = manifest_at {
        let opened = setup_manifest::open(
            &plan.package.components[at].bytes,
            &secrets.encryption_secret,
            &root,
            &now,
            &revoked,
        )?;
        if opened.relay_public_key != plan.package.issuer {
            return Err(Error::KqpkgIssuerUntrusted);
        }
        opened.body.check_against(
            &plan.package,
            at,
            &secrets.encryption_public,
            container.device_id(),
            provider::unix_from_utc(&now)?,
        )?;
        generation = Some(opened.body.package_generation);
        plan.steps = opened.body.operations;
        plan.from_manifest = true;
    } else {
        let key_hashes: Vec<String> = plan
            .package
            .components
            .iter()
            .filter(|c| c.kind.carries_key())
            .map(|c| setup_manifest::hash_of(&c.bytes))
            .collect();
        plan.steps = setup_manifest::standard_operations(
            &setup_manifest::hash_of(&plan.certificate),
            &key_hashes,
        );
    }
    // An update replaces credentials, so it must carry a signed generation the
    // ledger can compare: an update without a manifest is refused.
    let update = plan.package.purpose == Purpose::ClientUpdate;
    if update && generation.is_none() {
        return Err(Error::KqpkgRefused(
            "an update package must carry a signed setup manifest with its generation".into(),
        ));
    }
    let stream = Target {
        provider_id: plan.provider_id.clone(),
        recipient: hex::encode(secrets.encryption_public),
        device_id: hex::encode(container.device_id()),
        slot_label: label.to_string(),
        container: device.display().to_string(),
    };
    let mut incoming = Incoming {
        package_id: hex::encode(plan.package.id),
        package_sha256: setup_manifest::hash_of(bytes),
        purpose: plan.package.purpose.name(),
        issuer: hex::encode(plan.package.issuer),
        target: stream.clone(),
        generation,
        licence_sha256: None,
    };
    let decision = package_ledger::decide_in_batch(conn, &incoming, batch)?;
    if decision == Decision::AlreadyInstalled {
        // Installed before: nothing is opened, checked or run again.
        plan.decision = Some(decision);
        plan.incoming = Some(incoming);
        return Ok(plan);
    }
    // Every sealed key is opened and checked offline now, before the first
    // write (the relay challenge still runs when it installs): a key that cannot
    // open, is for another drive, was issued by another relay than the one that
    // signed this package, was replaced by an earlier update, or would replace a
    // different stored key without being a newer update, leaves nothing behind.
    let mut licence = None;
    for component in plan
        .package
        .components
        .iter()
        .filter(|component| component.kind.carries_key())
    {
        let key = super::precheck_key_component(&component.bytes, &slot, &plan.package.issuer)?;
        if package_ledger::is_retired(conn, &stream, &key.key_hash)? {
            return Err(Error::KqpkgRefused(format!(
                "this package carries a {} key for {} that a later update already replaced",
                key.scope, key.relay_url
            )));
        }
        let mut replaces = None;
        if let Some(stored) = db::relay_credential::get(conn, &key.relay_url, &key.scope)? {
            if stored.key_hash != key.key_hash {
                if !update {
                    return Err(usage(&format!(
                        "a different {} key for {} is already stored; setup will not replace it \
                         (revoke it with your provider first, or install an update package)",
                        key.scope, key.relay_url
                    )));
                }
                replaces = Some(stored.key_hash);
            }
        }
        if licence.is_none() {
            licence = key
                .licence
                .as_deref()
                .map(|text| setup_manifest::hash_of(text.as_bytes()));
        }
        plan.keys.insert(
            setup_manifest::hash_of(&component.bytes),
            KeyPlan {
                preview: key,
                replaces,
            },
        );
    }
    incoming.licence_sha256 = licence;
    plan.decision = Some(decision);
    plan.incoming = Some(incoming);
    Ok(plan)
}

fn certificate_of(package: &Package) -> Result<&Component> {
    package
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Certificate)
        .ok_or(Error::KqpkgComponentRejected)
}

fn kind_name(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Certificate => "relay certificate",
        ComponentKind::RevocationList => "revocation list",
        ComponentKind::Policy => "hardware-authority policy",
        ComponentKind::ApiKeyBundle => "sealed API key (.kqkey)",
        ComponentKind::ApiKeyLetter => "sealed API key letter",
        ComponentKind::SetupManifest => "setup steps (sealed to you, signed by the relay)",
        ComponentKind::RecoveryPayload => "provider recovery payload (sealed to an operator)",
    }
}

/// Prints a verified plan: what signed the package, what it holds, its
/// generation, each key it installs and the steps in order. Never a bearer.
pub(super) fn show(plan: &Plan, device: &Path, label: &str) {
    let purpose = match plan.package.purpose {
        Purpose::ClientSetup => "client setup",
        Purpose::ClientUpdate => "client update",
        Purpose::ProviderInfo => "provider information",
        Purpose::ProviderRecovery => "provider recovery",
    };
    outln!(
        "Package {} ({purpose}), verified: signed by the relay {} ({}), certificate valid until {}",
        hex::encode(plan.package.id),
        plan.provider_id,
        plan.serial,
        plan.certificate_expires
    );
    for component in &plan.package.components {
        outln!("  contains: {}", kind_name(component.kind));
    }
    if !plan.package.purpose.is_client() {
        return;
    }
    if let Some(generation) = plan.incoming.as_ref().and_then(|i| i.generation) {
        outln!("  generation: {generation}");
    }
    for step in &plan.steps {
        let Operation::InstallKey { component, .. } = step else {
            continue;
        };
        let Some(KeyPlan {
            preview: key,
            replaces,
        }) = plan.keys.get(component)
        else {
            continue;
        };
        outln!(
            "  key: {} scope, relay {}, {}{}{}",
            key.scope,
            key.relay_url,
            key.expires_at
                .as_deref()
                .map_or("no expiry".to_string(), |at| format!("expires {at}")),
            key.licence
                .as_deref()
                .map_or(String::new(), |text| format!(", licence: {text}")),
            if replaces.is_some() {
                ", replaces the key stored now"
            } else {
                ""
            }
        );
    }
    match &plan.decision {
        Some(Decision::Resume { steps_done }) => outln!(
            "This package was started before and did not finish ({} step(s) done); applying it \
             again checks what is in place and finishes the rest.",
            steps_done.len()
        ),
        Some(Decision::AlreadyInstalled) => {}
        _ => {}
    }
    outln!(
        "Steps for slot {label} on {}, in this order{}:",
        device.display(),
        if plan.from_manifest {
            ""
        } else {
            " (this package has no setup manifest; these are its fixed steps)"
        }
    );
    for (number, step) in plan.steps.iter().enumerate() {
        outln!("  {}. {}", number + 1, step.describe());
    }
}

/// Whether step `step`'s effect is in place now, read from the drive and the
/// store, never from an earlier run's memory.
fn step_in_place(
    conn: &Connection,
    plan: &Plan,
    step: &Operation,
    device: &Path,
    label: &str,
) -> Result<bool> {
    Ok(match step {
        Operation::EnsureIdentity { .. } => {
            env::fs(|fs| crate::device::open_in(fs, device)).is_ok()
                && !crate::keys::active_keys_for(conn, label, crate::keys::KeyType::Encryption)?
                    .is_empty()
        }
        Operation::InstallCertificate { .. } => {
            let target = device.join(CERTIFICATE_NAME);
            env::exists(&target) && env::read(&target)? == plan.certificate
        }
        Operation::InstallKey { component, .. } => match plan.keys.get(component) {
            Some(KeyPlan { preview, .. }) => {
                db::relay_credential::get(conn, &preview.relay_url, &preview.scope)?
                    .is_some_and(|stored| stored.key_hash == preview.key_hash)
            }
            None => false,
        },
        // Every field `run_step`'s `use` writes must already match: the relay,
        // the drive, the slot and the label, so another slot's profile on the
        // same relay does not count as this step done.
        Operation::UseRelay { key, .. } => match plan.keys.get(key) {
            Some(KeyPlan { preview, .. }) => {
                let device_text = device.display().to_string();
                let is = |name: &str, want: &str| -> Result<bool> {
                    Ok(db::profile::get(conn, name)?.as_deref() == Some(want))
                };
                is(db::profile::DEFAULT_RELAY_URL, &preview.relay_url)?
                    && is(db::profile::DEFAULT_CONTAINER, &device_text)?
                    && is(db::profile::DEFAULT_SLOT_LABEL, label)?
                    && is(db::profile::DEFAULT_LABEL, label)?
            }
            None => false,
        },
    })
}

/// Runs one step's handler. Each handler is idempotent; it runs only when the
/// step's effect is not already in place.
fn run_step(
    conn: &Connection,
    plan: &Plan,
    step: &Operation,
    device: &Path,
    label: &str,
) -> Result<()> {
    let slot = format!("{}={label}", device.display());
    match step {
        Operation::EnsureIdentity { .. } => setup::ensure_identity(conn, device, label),
        Operation::InstallCertificate { .. } => {
            let target = device.join(CERTIFICATE_NAME);
            if !env::exists(&target) {
                env::write_new(&target, &plan.certificate)?;
                outln!("Wrote relay certificate {}", target.display());
            }
            Ok(())
        }
        Operation::InstallKey { component, .. } => {
            let bytes = plan
                .parts
                .get(component)
                .ok_or(Error::KqpkgComponentRejected)?;
            if let (
                Some(KeyPlan {
                    replaces: Some(old),
                    ..
                }),
                Some(incoming),
            ) = (plan.keys.get(component), plan.incoming.as_ref())
            {
                // The key being replaced can never be put back by any package.
                package_ledger::retire_key(conn, &incoming.target, old)?;
            }
            super::install_key_component(conn, bytes, &slot).map(|_| ())
        }
        Operation::UseRelay { key, .. } => {
            let url = plan.keys.get(key).map(|k| k.preview.relay_url.clone());
            profile::run_use(
                conn,
                profile::UseOpts {
                    label: Some(label.to_string()),
                    slot: Some(label.to_string()),
                    device: Some(device.to_path_buf()),
                    url,
                    cache: None,
                    show: false,
                    clear: false,
                },
            )
        }
    }
}

/// Applies a verified plan through the ledger: the package is recorded pending
/// and its generation reserved before the first change; each step is checked
/// against the real state, run only if its effect is missing, checked again,
/// then marked done; and the package is complete only when every step's effect
/// is in place together. An interrupted run is finished by running it again.
pub(super) fn apply(conn: &Connection, plan: &Plan, device: &Path, label: &str) -> Result<()> {
    let incoming = plan
        .incoming
        .as_ref()
        .ok_or(Error::KqpkgComponentRejected)?;
    let id = &incoming.package_id;
    let decision = package_ledger::begin(conn, incoming)?;
    if decision == Decision::AlreadyInstalled {
        outln!("Package {id} is already installed; nothing to do.");
        return Ok(());
    }
    // The drive must still be the one approved: the same container (by device
    // id) under the same path.
    let container = env::fs(|fs| crate::device::open_in(fs, device))?;
    if hex::encode(container.device_id()) != incoming.target.device_id {
        return Err(Error::KqpkgRefused(format!(
            "{} is no longer the container this package was approved for",
            device.display()
        )));
    }
    for (number, step) in plan.steps.iter().enumerate() {
        outln!(
            "Step {}/{}: {}",
            number + 1,
            plan.steps.len(),
            step.describe()
        );
        if !step_in_place(conn, plan, step, device, label)? {
            if let Err(err) = run_step(conn, plan, step, device, label) {
                outln!(
                    "Setup stopped at step {}. Run the same command again to finish it, or \
                     abandon it with `keyquorum setup --abandon {id}`.",
                    number + 1
                );
                return Err(err);
            }
            if !step_in_place(conn, plan, step, device, label)? {
                return Err(Error::KqpkgRefused(format!(
                    "step {} ran but its result is not in place; nothing further was done",
                    number + 1
                )));
            }
        }
        package_ledger::mark_step(conn, id, step.id())?;
    }
    for step in &plan.steps {
        if !step_in_place(conn, plan, step, device, label)? {
            return Err(Error::KqpkgRefused(format!(
                "after every step ran, `{}` is no longer in place; the package stays pending",
                step.id()
            )));
        }
    }
    package_ledger::complete(conn, id)?;
    outln!("Setup from the package is complete.");
    outln!("Package {id} is recorded as installed for this slot.");
    Ok(())
}

/// Refuses, before any change, an enrollment file that cannot be written: the
/// request is never written over another file, and the lab has no honest
/// equivalent.
pub(super) fn check_enrollment_target(out: &Path) -> Result<()> {
    if !env::package_setup() {
        return Err(usage("setup --enroll-out is not available here"));
    }
    if env::exists(out) {
        return Err(usage(&format!(
            "{} already exists; setup will not overwrite it",
            out.display()
        )));
    }
    Ok(())
}

/// Writes the signed public enrollment request for the slot and prints the
/// fingerprint to compare with the provider. The slot's passphrase is asked
/// for once, to sign; nothing secret is written.
pub(super) fn write_enrollment(device: &Path, label: &str, out: &Path) -> Result<()> {
    let container = env::fs(|fs| crate::device::open_in(fs, device))?;
    let secrets = super::open_slot_secrets(&format!("{}={label}", device.display()))?;
    let request = crate::enrollment::Request {
        device_id: *container.device_id(),
        created_at: provider::unix_from_utc(&env::now_utc()?)?,
        label: label.to_string(),
        encryption_public: secrets.encryption_public,
        signing_public: secrets.signing_public,
    };
    let bytes = crate::enrollment::encode(&request, &secrets.signing_secret)?;
    env::write_new(out, &bytes)?;
    outln!("Wrote enrollment request {}", out.display());
    outln!(
        "Fingerprint (tell your provider, out of band): {}",
        request.fingerprint()?
    );
    Ok(())
}
