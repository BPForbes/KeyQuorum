//! `keyquorum file`: tracked files with a signed, hash-chained history
//! ([`crate::file_history`]). A tracked file is a `.kqtf` container that
//! carries its own history and policy; this store supplies only the signing
//! keys used to check it. Trust is never decided here: the commands call
//! `file_history` and print what it says.
//!
//! Authors are named by label. Their 16-byte identity is the one enrolled
//! by `transfer enroll` when the store has it; otherwise it is derived from
//! the label (see [`identity_for`]).

use super::env::{self, errln, outln};
use super::{open_slot_secrets, read_key_array_32, usage};
use crate::error::{Error, Result};
use crate::file_history::{
    evaluate_revision_trust, select_shareable_revision, verify_tracked_file, BridgeEvidence,
    DeliveryDecisionKind, EventDetails, FilePolicy, HistoryEvent, HistoryEventType, HistoryOutcome,
    NewEvent, NewRevision, TrackedFile, TrustContext, TrustReason, TrustState,
};
use crate::{key_tree, private_bridge, transfer};
use clap::Subcommand;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum FileCommand {
    /// Start tracking a file: make its first revision, sign it as its
    /// author, and write `<file>.kqtf`
    Track {
        /// The native file to track
        path: PathBuf,
        /// The label the file is scoped to (its owner)
        #[arg(long)]
        scope: String,
        /// Your label (the revision's author)
        #[arg(long = "as")]
        as_label: String,
        /// Your identity slot, container=label (signs the revision)
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        /// Your signing private key file, instead of --slot
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// A short description of this revision
        #[arg(long)]
        label: Option<String>,
        /// Name recorded for the file (defaults to the file's name)
        #[arg(long)]
        name: Option<String>,
        /// Where to write the container (defaults to `<file>.kqtf`)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check in a new revision from a native file
    Checkin {
        /// The tracked file (.kqtf)
        kqtf: PathBuf,
        /// The edited native file
        #[arg(long)]
        from: PathBuf,
        #[arg(long = "as")]
        as_label: String,
        #[arg(long, conflicts_with_all = ["signing_key_file", "unsigned"])]
        slot: Option<String>,
        #[arg(long, conflicts_with = "unsigned")]
        signing_key_file: Option<PathBuf>,
        /// Check in without signing; the revision stays untrusted
        #[arg(long)]
        unsigned: bool,
        #[arg(long)]
        label: Option<String>,
    },
    /// Sign a revision you authored (the current head unless --revision)
    Sign {
        kqtf: PathBuf,
        /// Revision id or unique prefix
        #[arg(long)]
        revision: Option<String>,
        #[arg(long = "as")]
        as_label: String,
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
    },
    /// Countersign a revision the author has signed
    Countersign {
        kqtf: PathBuf,
        #[arg(long)]
        revision: Option<String>,
        /// Your label (the supervisor)
        #[arg(long = "as")]
        as_label: String,
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
    },
    /// Show the heads, their trust, and what would be shared
    Status { kqtf: PathBuf },
    /// List the recorded events
    History { kqtf: PathBuf },
    /// Verify the history chain and revision graph, and judge every revision
    Verify { kqtf: PathBuf },
}

pub fn run(conn: &Connection, command: FileCommand) -> Result<()> {
    match command {
        FileCommand::Track {
            path,
            scope,
            as_label,
            slot,
            signing_key_file,
            label,
            name,
            out,
        } => track(
            conn,
            &path,
            &scope,
            &as_label,
            slot,
            signing_key_file,
            label,
            name,
            out,
        ),
        FileCommand::Checkin {
            kqtf,
            from,
            as_label,
            slot,
            signing_key_file,
            unsigned,
            label,
        } => checkin(
            conn,
            &kqtf,
            &from,
            &as_label,
            slot,
            signing_key_file,
            unsigned,
            label,
        ),
        FileCommand::Sign {
            kqtf,
            revision,
            as_label,
            slot,
            signing_key_file,
        } => sign(conn, &kqtf, revision, &as_label, slot, signing_key_file),
        FileCommand::Countersign {
            kqtf,
            revision,
            as_label,
            slot,
            signing_key_file,
        } => countersign(conn, &kqtf, revision, &as_label, slot, signing_key_file),
        FileCommand::Status { kqtf } => status(conn, &kqtf),
        FileCommand::History { kqtf } => history(&kqtf),
        FileCommand::Verify { kqtf } => verify(conn, &kqtf),
    }
}

/// The store as the source of signing keys. A key counts only for the
/// identity this store knows for that label.
struct StoreTrust<'a> {
    conn: &'a Connection,
}

impl TrustContext for StoreTrust<'_> {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        if identity_for(self.conn, label).ok()? != *identity {
            return None;
        }
        private_bridge::signing_public_for_label(self.conn, label).ok()
    }

    fn bridge_evidence(&self, _revision_id: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }
}

/// The 16-byte identity of `label`: the stable one from `transfer enroll`
/// when this store has it, else `SHA-256("KQ-FILE-IDENTITY-v1" || label)`
/// truncated. The derived id is stable while the label is, but differs from
/// an identity enrolled later, so enroll before tracking if you will.
fn identity_for(conn: &Connection, label: &str) -> Result<[u8; 16]> {
    if let Some(info) = transfer::identity(conn, label)? {
        return Ok(info.id);
    }
    let digest = Sha256::new()
        .chain_update(b"KQ-FILE-IDENTITY-v1")
        .chain_update((label.len() as u16).to_be_bytes())
        .chain_update(label.as_bytes())
        .finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(id)
}

fn signing_secret(slot: Option<String>, key_file: Option<PathBuf>) -> Result<Zeroizing<[u8; 32]>> {
    match (slot, key_file) {
        (Some(slot), None) => Ok(open_slot_secrets(&slot)?.signing_secret),
        (None, Some(path)) => Ok(Zeroizing::new(read_key_array_32(&path)?)),
        _ => Err(usage("pass --slot or --signing-key-file")),
    }
}

/// `2026-09-27 00:00` or `2026-09-27 00:00:00` as `2026-09-27T00:00:00Z`.
fn utc_instant() -> Result<String> {
    let now = env::now_utc()?;
    let now = now.trim().replace(' ', "T");
    let now = if now.len() == 16 {
        format!("{now}:00")
    } else {
        now
    };
    Ok(if now.ends_with('Z') {
        now
    } else {
        format!("{now}Z")
    })
}

fn generation_for(conn: &Connection, scope: &str) -> Result<u64> {
    let root = scope.split('.').next().unwrap_or(scope);
    Ok(key_tree::tree_by_label(conn, root)?
        .map(|(_, generation)| u64::from(generation))
        .unwrap_or(0))
}

fn load(path: &Path) -> Result<TrackedFile> {
    TrackedFile::decode(&env::read(path)?)
}

fn policy_of(file: &TrackedFile) -> Result<&FilePolicy> {
    file.policy()
        .ok_or_else(|| usage("this tracked file has no policy"))
}

/// Replace the container atomically: write a sibling, then rename over it.
fn save(path: &Path, file: &TrackedFile) -> Result<()> {
    let bytes = file.encode()?;
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    if env::exists(&temp) {
        env::remove_file(&temp)?;
    }
    env::write_new(&temp, &bytes)?;
    env::fs(|fs| fs.rename(&temp, path))
}

fn short(id: &[u8; 32]) -> String {
    hex::encode(&id[..6])
}

fn trust_text(state: TrustState) -> String {
    let reason = |r: TrustReason| format!("{r:?}");
    match state {
        TrustState::Trusted => "TRUSTED".into(),
        TrustState::Pending(r) => format!("PENDING ({})", reason(r)),
        TrustState::Denied(r) => format!("DENIED ({})", reason(r)),
    }
}

/// The revision to act on: the one named by `--revision` (an id or unique
/// prefix), else the sole head. A forked history has no single head.
fn pick_revision(file: &TrackedFile, wanted: Option<&str>) -> Result<[u8; 32]> {
    let graph = file.graph();
    match wanted {
        Some(prefix) => {
            let prefix = prefix.to_ascii_lowercase();
            let mut found = file
                .revisions()
                .iter()
                .map(|stored| stored.revision.revision_id)
                .filter(|id| hex::encode(id).starts_with(&prefix));
            match (found.next(), found.next()) {
                (Some(id), None) if !prefix.is_empty() => Ok(id),
                (Some(_), Some(_)) => Err(usage("that revision prefix is ambiguous")),
                _ => Err(usage("no such revision")),
            }
        }
        None => match graph.heads().as_slice() {
            [only] => Ok(*only),
            [] => Err(usage("this tracked file has no revisions")),
            _ => Err(usage(
                "the history has forked: name a revision with --revision",
            )),
        },
    }
}

fn event(
    kind: HistoryEventType,
    revision_id: Option<[u8; 32]>,
    at: &str,
    identity: [u8; 16],
    label: &str,
    generation: u64,
    details: EventDetails,
) -> NewEvent {
    NewEvent {
        revision_id,
        occurred_at: at.to_string(),
        actor_identity: Some(identity),
        actor_label: Some(label.to_string()),
        topology_generation: Some(generation),
        event_type: kind,
        outcome: HistoryOutcome::Success,
        details,
    }
}

/// Record the policy decision for `revision` and return it. A `Denied`
/// state means the evidence is invalid, so the caller should not save.
#[allow(clippy::too_many_arguments)]
fn decide(
    conn: &Connection,
    file: &mut TrackedFile,
    revision: [u8; 32],
    at: &str,
    identity: [u8; 16],
    label: &str,
    generation: u64,
) -> Result<TrustState> {
    let policy = policy_of(file)?.clone();
    let state = evaluate_revision_trust(file, &revision, &policy, &StoreTrust { conn })?;
    let mut recorded = event(
        HistoryEventType::PolicyDecision,
        Some(revision),
        at,
        identity,
        label,
        generation,
        EventDetails::new().with("result", &trust_text(state)),
    );
    if matches!(state, TrustState::Denied(_)) {
        recorded.outcome = HistoryOutcome::Denied;
    }
    file.append(recorded)?;
    Ok(state)
}

fn refuse_if_denied(state: TrustState, label: &str) -> Result<()> {
    match state {
        TrustState::Denied(TrustReason::UnknownSigner | TrustReason::InvalidContentSignature) => {
            Err(usage(&format!(
                "the signing key you supplied is not the one registered for {label} in this store"
            )))
        }
        TrustState::Denied(reason) => Err(usage(&format!("not allowed: {reason:?}"))),
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn track(
    conn: &Connection,
    path: &Path,
    scope: &str,
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
    user_label: Option<String>,
    name: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let policy = FilePolicy::standard(scope);
    if !policy.may_author(as_label) {
        return Err(usage("--as is outside the scope of this file"));
    }
    let name = match name {
        Some(name) => name,
        None => path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| usage("the file has no name; pass --name"))?,
    };
    let out = out.unwrap_or_else(|| {
        let mut target = path.as_os_str().to_owned();
        target.push(".kqtf");
        PathBuf::from(target)
    });
    if env::exists(&out) {
        return Err(usage(&format!("{} already exists", out.display())));
    }
    let secret = signing_secret(slot, key_file)?;
    let contents = env::read(path)?;
    let (identity, at, generation) = (
        identity_for(conn, as_label)?,
        utc_instant()?,
        generation_for(conn, scope)?,
    );
    let mut file_id = [0u8; 16];
    OsRng.fill_bytes(&mut file_id);

    let mut file = TrackedFile::with_policy(file_id, &name, policy.clone());
    let revision = file.check_in(
        NewRevision {
            parent_revision_ids: Vec::new(),
            user_label,
            author_identity: Some(identity),
            author_hcp_label: as_label.to_string(),
            created_at_utc: at.clone(),
            topology_generation: generation,
            policy_hash: policy.policy_hash()?,
        },
        contents,
    )?;
    let started = EventDetails::new().with("scope", scope);
    file.append(event(
        HistoryEventType::TrackingStarted,
        Some(revision),
        &at,
        identity,
        as_label,
        generation,
        started,
    ))?;
    file.sign_revision(&revision, identity, as_label, &secret)?;
    file.append(event(
        HistoryEventType::RevisionSigned,
        Some(revision),
        &at,
        identity,
        as_label,
        generation,
        EventDetails::new(),
    ))?;
    let state = decide(
        conn, &mut file, revision, &at, identity, as_label, generation,
    )?;
    refuse_if_denied(state, as_label)?;
    env::write_new(&out, &file.encode()?)?;
    let stored = file.graph().get(&revision).expect("just checked in");
    outln!("Tracking {name} as {}", hex::encode(file_id));
    outln!("  revision {}", stored.revision.generated_label);
    outln!("  id       {}", short(&revision));
    outln!("  trust    {}", trust_text(state));
    outln!("Wrote {}", out.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn checkin(
    conn: &Connection,
    kqtf: &Path,
    from: &Path,
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
    unsigned: bool,
    user_label: Option<String>,
) -> Result<()> {
    let mut file = load(kqtf)?;
    let policy = policy_of(&file)?.clone();
    if !policy.may_author(as_label) {
        return Err(usage("--as is outside the scope of this file"));
    }
    let parent = pick_revision(&file, None)?;
    let secret = if unsigned {
        None
    } else {
        Some(signing_secret(slot, key_file)?)
    };
    let contents = env::read(from)?;
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy.scope_root)?;
    let revision = file.check_in(
        NewRevision {
            parent_revision_ids: vec![parent],
            user_label,
            author_identity: Some(identity),
            author_hcp_label: as_label.to_string(),
            created_at_utc: at.clone(),
            topology_generation: generation,
            policy_hash: policy.policy_hash()?,
        },
        contents,
    )?;
    let details = EventDetails::new().with("base_revision", &hex::encode(parent));
    file.append(event(
        HistoryEventType::EditCheckedIn,
        Some(revision),
        &at,
        identity,
        as_label,
        generation,
        details,
    ))?;
    if let Some(secret) = &secret {
        file.sign_revision(&revision, identity, as_label, secret)?;
        file.append(event(
            HistoryEventType::RevisionSigned,
            Some(revision),
            &at,
            identity,
            as_label,
            generation,
            EventDetails::new(),
        ))?;
    }
    let state = decide(
        conn, &mut file, revision, &at, identity, as_label, generation,
    )?;
    refuse_if_denied(state, as_label)?;
    save(kqtf, &file)?;
    let stored = file.graph().get(&revision).expect("just checked in");
    outln!("Checked in {}", stored.revision.generated_label);
    outln!("  id    {}", short(&revision));
    outln!("  trust {}", trust_text(state));
    if unsigned {
        errln!("Unsigned: sharing falls back to the last trusted revision.");
    }
    Ok(())
}

fn sign(
    conn: &Connection,
    kqtf: &Path,
    revision: Option<String>,
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
) -> Result<()> {
    let mut file = load(kqtf)?;
    let target = pick_revision(&file, revision.as_deref())?;
    let secret = signing_secret(slot, key_file)?;
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy_of(&file)?.scope_root)?;
    file.sign_revision(&target, identity, as_label, &secret)
        .map_err(|_| usage("only a revision's author can sign it, and only once"))?;
    file.append(event(
        HistoryEventType::RevisionSigned,
        Some(target),
        &at,
        identity,
        as_label,
        generation,
        EventDetails::new(),
    ))?;
    let state = decide(conn, &mut file, target, &at, identity, as_label, generation)?;
    refuse_if_denied(state, as_label)?;
    save(kqtf, &file)?;
    outln!("Signed {} as {as_label}", short(&target));
    outln!("  trust {}", trust_text(state));
    Ok(())
}

fn countersign(
    conn: &Connection,
    kqtf: &Path,
    revision: Option<String>,
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
) -> Result<()> {
    let mut file = load(kqtf)?;
    let target = pick_revision(&file, revision.as_deref())?;
    let secret = signing_secret(slot, key_file)?;
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy_of(&file)?.scope_root)?;
    file.countersign_revision(&target, identity, as_label, &secret)
        .map_err(|_| usage("the author must sign first, and you can countersign only once"))?;
    let author = file
        .graph()
        .get(&target)
        .map(|s| s.revision.author_hcp_label.clone())
        .unwrap_or_default();
    file.append(event(
        HistoryEventType::CountersignatureAdded,
        Some(target),
        &at,
        identity,
        as_label,
        generation,
        EventDetails::new().with("for_actor", &author),
    ))?;
    let state = decide(conn, &mut file, target, &at, identity, as_label, generation)?;
    // A countersignature by the wrong person is stored but earns nothing;
    // only invalid evidence stops the write.
    refuse_if_denied(state, as_label)?;
    save(kqtf, &file)?;
    outln!("Countersigned {} as {as_label}", short(&target));
    outln!("  trust {}", trust_text(state));
    Ok(())
}

fn status(conn: &Connection, kqtf: &Path) -> Result<()> {
    let file = load(kqtf)?;
    let policy = policy_of(&file)?;
    let ctx = StoreTrust { conn };
    outln!("{} ({})", file.logical_name, hex::encode(file.file_id));
    outln!("  scope        {}", policy.scope_root);
    outln!("  history root {}", hex::encode(file.history_root()));
    let heads = file.graph().heads();
    if heads.len() > 1 {
        outln!("  FORK: {} heads; neither is overwritten", heads.len());
    }
    for head in &heads {
        let stored = file.graph().get(head).expect("head exists");
        let revision = &stored.revision;
        outln!("  head {}", short(head));
        if let Some(user) = &revision.user_label {
            outln!("    {user}");
        }
        outln!("    {}", revision.generated_label);
        outln!(
            "    trust {}",
            trust_text(evaluate_revision_trust(&file, head, policy, &ctx)?)
        );
        let share = select_shareable_revision(&file, head, None, policy, &ctx)?;
        match (share.decision, share.delivered_revision) {
            (DeliveryDecisionKind::CurrentTrustedRevision, _) => {
                outln!("    would share this revision")
            }
            (DeliveryDecisionKind::LastTrustedRevision, Some(id)) => {
                outln!("    would share the last trusted revision {}", short(&id))
            }
            _ => outln!("    nothing trusted to share"),
        }
    }
    Ok(())
}

fn describe(event: &HistoryEvent) -> String {
    let actor = event.actor_label.as_deref().unwrap_or("UNKNOWN");
    let revision = event
        .revision_id
        .map(|id| format!(" rev {}", short(&id)))
        .unwrap_or_default();
    let details: Vec<String> = event
        .details
        .entries()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    format!(
        "{:>3} {} {:?} {:?} by {actor}{revision} {}",
        event.sequence,
        event.occurred_at,
        event.event_type,
        event.outcome,
        details.join(" ")
    )
    .trim_end()
    .to_string()
}

fn history(kqtf: &Path) -> Result<()> {
    let file = load(kqtf)?;
    for event in file.events() {
        outln!("{}", describe(event));
    }
    Ok(())
}

fn verify(conn: &Connection, kqtf: &Path) -> Result<()> {
    let file = load(kqtf)?;
    let root = verify_tracked_file(&file)?;
    let policy = policy_of(&file)?;
    let ctx = StoreTrust { conn };
    outln!(
        "History and revision graph verify; root {}",
        hex::encode(root)
    );
    let mut denied = 0;
    for stored in file.revisions() {
        let id = stored.revision.revision_id;
        let state = evaluate_revision_trust(&file, &id, policy, &ctx)?;
        denied += usize::from(matches!(state, TrustState::Denied(_)));
        outln!("  {} {}", short(&id), trust_text(state));
    }
    if denied > 0 {
        return Err(Error::InvalidTrackedFile);
    }
    Ok(())
}
