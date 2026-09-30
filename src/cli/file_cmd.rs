//! `keyquorum file`: tracked files with a signed, hash-chained history
//! ([`crate::file_history`]). A tracked file is a `.kqtf` container that
//! carries its own history and policy; this store supplies only the signing
//! keys used to check it. Trust is never decided here: the commands call
//! `file_history` and print what it says.
//!
//! Authors are named by label. Their 16-byte identity is the one enrolled
//! by `transfer enroll` when the store has it; otherwise it is derived from
//! the label (see [`identity_for`]).

use super::deliver_cmd::{
    carry, recipient_secrets, registered_encryption_key, require_recipient_key, sender_keys,
    Letter, RecipientSecrets,
};
use super::env::{self, errln, outln};
use super::gate_link::{self, Gate};
use super::review_view::ReviewView;
use super::{open_slot_secrets, read_key_array_32, usage};
use crate::error::{Error, Result};
use crate::file_history::{
    current_revision, diff_text, evaluate_revision_trust, event_attested, index, is_finalized,
    latest_finalized_ancestor, latest_trusted_revision, proof_descriptor,
    select_shareable_revision, verify_tracked_file, AutoMergeOutcome, BridgeEvidence, ChangeKind,
    DeliveryDecisionKind, EventDetails, ExpiryContext, FilePolicy, GenerationEvidence,
    HistoryEvent, HistoryEventType, HistoryOutcome, HistoryRelation, HistorySnapshot,
    ImportContext, MergeBase, NewEvent, NewRevision, Requirement, Resolution, ResolverSelection,
    TrackedFile, TrustContext, TrustReason, TrustState,
};
use crate::{authority, file_delivery, key_tree, private_bridge, signing, transfer};
use clap::Subcommand;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
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
        /// Never merge divergent heads automatically; a fork always goes to
        /// a person, however clean the merge would be
        #[arg(long)]
        no_auto_merge: bool,
        /// What the scope owner must present: forbidden, author,
        /// author+parent
        #[arg(long, value_parser = parse_requirement)]
        owner_rule: Option<Requirement>,
        /// What a descendant must present (default author+parent)
        #[arg(long, value_parser = parse_requirement)]
        descendants_rule: Option<Requirement>,
        /// What an ancestor must present (default author)
        #[arg(long, value_parser = parse_requirement)]
        ancestors_rule: Option<Requirement>,
        /// What a cross-branch author must present (default
        /// author+bridge-or-owner)
        #[arg(long, value_parser = parse_requirement)]
        cross_branch_rule: Option<Requirement>,
    },
    /// Show the rules a tracked file's revisions are judged by
    Policy { kqtf: PathBuf },
    /// Mark a trusted revision final. Only the file's scope owner or one of
    /// its ancestors may, and the revision must already be trusted; trust
    /// itself is unchanged.
    Finalize {
        kqtf: PathBuf,
        /// Revision id or unique prefix (the sole head by default)
        #[arg(long)]
        revision: Option<String>,
        /// Your label: the file's scope owner or one of its ancestors
        #[arg(long = "as")]
        as_label: String,
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
    },
    /// As a member of a private bridge that reaches from a revision's author
    /// to the file's scope, approve that revision with the bridge. The
    /// approval stays in this store (it names the bridge); the file never
    /// carries it.
    BridgeApprove {
        kqtf: PathBuf,
        /// Revision id or unique prefix (the sole head by default)
        #[arg(long)]
        revision: Option<String>,
        /// The private bridge's uid
        #[arg(long)]
        bridge: String,
        /// Your label: a member of that bridge
        #[arg(long = "as")]
        as_label: String,
        /// Your slot: its encryption key opens your sealed bridge key
        #[arg(long)]
        slot: String,
    },
    /// Settle a conflict as its reviewer: keep one side, or supply the merge
    /// you edited; the result is signed as yours. `--reject` refuses a
    /// proposed merge instead.
    Resolve {
        kqtf: PathBuf,
        /// Keep one conflicting side as it is: `left` or `right`
        #[arg(long, value_parser = ["left", "right"], conflicts_with_all = ["from", "reject"])]
        keep: Option<String>,
        /// Your edited merge result (a native file)
        #[arg(long, conflicts_with = "reject")]
        from: Option<PathBuf>,
        /// Refuse the proposed merge at the head
        #[arg(long)]
        reject: bool,
        /// Your label: the assigned reviewer, or an ancestor of theirs
        #[arg(long = "as")]
        as_label: String,
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// A name for the resolved revision
        #[arg(long)]
        label: Option<String>,
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
        /// A tracked `.kqtf`, or a native file with no container yet: signing
        /// it is the first content signature, which starts tracking
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
        /// HCP scope of a newly tracked file (only with a native file;
        /// defaults to your own label)
        #[arg(long)]
        scope: Option<String>,
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
    /// Merge two divergent heads automatically when the edits allow it;
    /// otherwise record the conflict and who must review it. A merge is a
    /// new revision that stays untrusted until it is signed.
    Merge {
        kqtf: PathBuf,
        /// Your label (the merge's author)
        #[arg(long = "as")]
        as_label: String,
        #[arg(long)]
        label: Option<String>,
    },
    /// Show what each side of a fork changed, and who reviews a conflict
    Review {
        kqtf: PathBuf,
        /// Open the interactive review (Vim keys, mouse hover for who wrote
        /// a line). Needs a build with the `tui` feature.
        #[arg(long)]
        interactive: bool,
        /// With --interactive: your label, so the review can resolve, sign or
        /// finalize as you (you can also type `:as LABEL`)
        #[arg(long = "as", requires = "interactive")]
        as_label: Option<String>,
        /// With --interactive: your `container=label` signing slot
        #[arg(long, requires = "interactive")]
        slot: Option<String>,
    },
    /// Show the revisions, their parents and their trust
    Graph { kqtf: PathBuf },
    /// Show the changed lines between two revisions of text
    Diff {
        kqtf: PathBuf,
        /// Revision id or unique prefix (default: the first parent of --to)
        #[arg(long)]
        from: Option<String>,
        /// Revision id or unique prefix (default: the sole head)
        #[arg(long)]
        to: Option<String>,
    },
    /// Write a revision's native bytes to a new file
    Checkout {
        kqtf: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Revision id or unique prefix (default: the sole head)
        #[arg(long)]
        revision: Option<String>,
        /// The revision that would be shared: the head if trusted, else the
        /// last trusted one
        #[arg(long, conflicts_with = "revision")]
        shareable: bool,
        /// Record this checkout in the file's history
        #[arg(long)]
        record: bool,
        /// With --record: the label to attribute it to (else no one)
        #[arg(long = "as", requires = "record")]
        as_label: Option<String>,
    },
    /// List the tracked files this store has indexed (a cache; see `reindex`)
    List,
    /// Rebuild index rows from tracked files. Every file is verified first;
    /// if any fails, nothing changes. `--clear` also drops rows for files
    /// not named here.
    Reindex {
        #[arg(required = true)]
        kqtf: Vec<PathBuf>,
        #[arg(long)]
        clear: bool,
    },
    /// Show the heads, their trust, and what would be shared
    Status { kqtf: PathBuf },
    /// List the recorded events
    History {
        kqtf: PathBuf,
        /// Also write the event history as a portable snapshot (KQHS)
        #[arg(long)]
        export: Option<PathBuf>,
    },
    /// Check a history snapshot; with --against, that it belongs to a file
    VerifySnapshot {
        snapshot: PathBuf,
        /// A tracked file the snapshot must be a point in the history of
        #[arg(long)]
        against: Option<PathBuf>,
    },
    /// Bring another copy of the same file's revisions and proofs into this
    /// one. A fork is kept as two heads; nothing is overwritten.
    Import {
        kqtf: PathBuf,
        /// The other copy (.kqtf)
        #[arg(long)]
        from: PathBuf,
        /// Your label (recorded as the importer)
        #[arg(long = "as")]
        as_label: String,
    },
    /// Verify the history chain and revision graph, and judge every revision
    Verify {
        kqtf: PathBuf,
        /// Record this check and its result in the file's history
        #[arg(long)]
        record: bool,
        /// With --record: the label to attribute it to (else no one)
        #[arg(long = "as", requires = "record")]
        as_label: Option<String>,
    },
    /// Schedule when this file's content is destroyed, or destroy it now.
    /// Every retained revision's content goes at once; the history, the
    /// revision graph and every signature stay behind as a tombstone.
    Expire {
        kqtf: PathBuf,
        /// Your label: the file's scope owner or one of its ancestors
        #[arg(long = "as")]
        as_label: String,
        /// UTC expiry as `yyyy-mm-dd hh:mm` or `yyyy-mm-ddThh:mm`
        #[arg(long, conflicts_with = "now", required_unless_present = "now", value_parser = parse_expiry_arg)]
        at: Option<String>,
        /// Destroy the content now
        #[arg(long)]
        now: bool,
        /// Prove you hold `--as`: the slot is opened only for this proof
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
    },
    /// Change the name the file is shown under. The stable file id and every
    /// revision id stay as they are; the old and new names are recorded.
    Rename {
        kqtf: PathBuf,
        /// The new logical name
        new_name: String,
        /// Your label: the file's scope owner or one of its ancestors
        #[arg(long = "as")]
        as_label: String,
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
    },
    /// Record what happens at a quorum-protected or password-locked file's
    /// gate in this tracked file's history. The gate is unchanged and never
    /// depends on it.
    Link {
        kqtf: PathBuf,
        /// The quorum-protected file id (see `keyquorum access quorum`)
        #[arg(
            long,
            conflicts_with = "locked_file",
            required_unless_present = "locked_file"
        )]
        quorum_file: Option<i64>,
        /// The password-locked file id (see `keyquorum access password`)
        #[arg(long)]
        locked_file: Option<i64>,
    },
    /// Stop recording a gate in this tracked file's history
    Unlink {
        kqtf: PathBuf,
        #[arg(
            long,
            conflicts_with = "locked_file",
            required_unless_present = "locked_file"
        )]
        quorum_file: Option<i64>,
        #[arg(long)]
        locked_file: Option<i64>,
    },
    /// Seal the newest trusted revision to another label as a `.kqpb`
    /// letter. A newer revision that is not trusted is never included.
    Share {
        kqtf: PathBuf,
        /// Recipient label (its encryption key must be registered here)
        #[arg(long)]
        to: String,
        /// Your label
        #[arg(long = "as")]
        as_label: String,
        /// Your identity slot, container=label (signs the letter)
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        /// Your signing private key file, instead of --slot
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// Share up to this revision instead of the sole head
        #[arg(long)]
        revision: Option<String>,
        /// Write the sealed letter to this directory
        #[arg(long, required_unless_present = "push")]
        output_dir: Option<PathBuf>,
        /// Upload the letter to the relay (inbox.push key)
        #[arg(long)]
        push: bool,
        #[arg(long, requires = "push")]
        url: Option<String>,
        #[arg(long, requires = "push")]
        api_key: Option<String>,
    },
    /// Send another label this file's event history (a `KQHS` snapshot,
    /// no content), its root signed by you, so they can compare it with
    /// their own copy.
    SendHistory {
        kqtf: PathBuf,
        /// Recipient label (its encryption key must be registered here)
        #[arg(long)]
        to: String,
        /// Your label
        #[arg(long = "as")]
        as_label: String,
        #[arg(long, conflicts_with = "signing_key_file")]
        slot: Option<String>,
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// Write the sealed letter to this directory
        #[arg(long, required_unless_present = "push")]
        output_dir: Option<PathBuf>,
        /// Upload the letter to the relay (inbox.push key)
        #[arg(long)]
        push: bool,
        #[arg(long, requires = "push")]
        url: Option<String>,
        #[arg(long, requires = "push")]
        api_key: Option<String>,
    },
    /// Open a history snapshot letter addressed to you: check the sender's
    /// signature and the snapshot, and compare it with your copy
    OpenHistory {
        /// The letter (.kqpb)
        #[arg(long)]
        letter: PathBuf,
        #[arg(
            long = "slot",
            required_unless_present = "share_file",
            conflicts_with = "share_file"
        )]
        slot: Option<String>,
        /// Your encryption private key file, instead of --slot
        #[arg(long)]
        share_file: Option<String>,
        /// Your copy of the file, to compare the sender's history with
        #[arg(long)]
        against: Option<PathBuf>,
        /// Also write the snapshot (.kqhs) here
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Open a tracked-file letter addressed to you. The sender is checked
    /// as the transport; the delivered revision is then judged by the
    /// file's own policy and accepted only if it is trusted here.
    Receive {
        /// The letter (.kqpb)
        #[arg(long)]
        letter: PathBuf,
        /// Your identity slot, container=label
        #[arg(
            long = "slot",
            required_unless_present = "share_file",
            conflicts_with_all = ["share_file", "signing_key_file"]
        )]
        slot: Option<String>,
        /// Your encryption private key file, instead of --slot
        #[arg(long, requires = "signing_key_file")]
        share_file: Option<String>,
        /// Your signing private key file, with --share-file
        #[arg(long, requires = "share_file")]
        signing_key_file: Option<PathBuf>,
        /// Merge into your existing copy of this file
        #[arg(long, conflicts_with_all = ["out", "reject"])]
        into: Option<PathBuf>,
        /// Write a new container here
        #[arg(long, required_unless_present_any = ["into", "reject"], conflicts_with = "reject")]
        out: Option<PathBuf>,
        /// Refuse the delivery and say so in the acknowledgement
        #[arg(long)]
        reject: bool,
        /// Write the sealed acknowledgement to this directory
        #[arg(long, required_unless_present = "push_ack")]
        ack_dir: Option<PathBuf>,
        /// Upload the acknowledgement to the relay (inbox.push key)
        #[arg(long)]
        push_ack: bool,
        #[arg(long, requires = "push_ack")]
        url: Option<String>,
        #[arg(long, requires = "push_ack")]
        api_key: Option<String>,
    },
    /// Record an acknowledgement sealed back to you in your copy's history
    Ack {
        kqtf: PathBuf,
        /// The acknowledgement (.kqpb)
        #[arg(long)]
        ack: PathBuf,
        /// Your identity slot, container=label
        #[arg(
            long = "slot",
            required_unless_present = "share_file",
            conflicts_with = "share_file"
        )]
        slot: Option<String>,
        /// Your encryption private key file, instead of --slot
        #[arg(long)]
        share_file: Option<String>,
    },
}

pub fn run(conn: &Connection, command: FileCommand) -> Result<()> {
    READ_AT.with(|read| read.borrow_mut().clear());
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
            no_auto_merge,
            owner_rule,
            descendants_rule,
            ancestors_rule,
            cross_branch_rule,
        } => {
            let policy = FilePolicy::with_rules(
                &scope,
                [owner_rule, descendants_rule, ancestors_rule, cross_branch_rule],
                !no_auto_merge,
            )
            .map_err(|_| usage("those rules cannot be met: the owner cannot be forbidden, only cross-branch authors use a bridge, and a parent countersignature needs a parent"))?;
            track(
                conn,
                &path,
                &as_label,
                slot,
                signing_key_file,
                label,
                name,
                out,
                policy,
                false,
            )
        }
        FileCommand::Policy { kqtf } => show_policy(&kqtf),
        FileCommand::Finalize {
            kqtf,
            revision,
            as_label,
            slot,
            signing_key_file,
        } => finalize(conn, &kqtf, revision, &as_label, slot, signing_key_file),
        FileCommand::BridgeApprove {
            kqtf,
            revision,
            bridge,
            as_label,
            slot,
        } => bridge_approve(conn, &kqtf, revision, &bridge, &as_label, &slot),
        FileCommand::Resolve {
            kqtf,
            keep,
            from,
            reject,
            as_label,
            slot,
            signing_key_file,
            label,
        } => {
            let keys = (slot, signing_key_file);
            if reject {
                reject_merge(conn, &kqtf, &as_label, keys)
            } else {
                let resolution = match (keep.as_deref(), from) {
                    (Some("left"), None) => Resolution::KeepLeft,
                    (Some("right"), None) => Resolution::KeepRight,
                    (None, Some(path)) => Resolution::Edited(env::read(&path)?),
                    _ => return Err(usage("pass --keep left|right, --from FILE, or --reject")),
                };
                resolve(conn, &kqtf, resolution, &as_label, keys, label)
            }
        }
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
            scope,
        } => {
            if is_container(&kqtf) {
                if scope.is_some() {
                    return Err(usage("--scope only applies to a file that is not tracked"));
                }
                sign(conn, &kqtf, revision, &as_label, slot, signing_key_file)
            } else {
                activate_on_first_signature(
                    conn,
                    &kqtf,
                    revision,
                    &as_label,
                    slot,
                    signing_key_file,
                    scope,
                )
            }
        }
        FileCommand::Countersign {
            kqtf,
            revision,
            as_label,
            slot,
            signing_key_file,
        } => countersign(conn, &kqtf, revision, &as_label, slot, signing_key_file),
        FileCommand::Merge {
            kqtf,
            as_label,
            label,
        } => merge(conn, &kqtf, &as_label, label),
        FileCommand::Review {
            kqtf,
            interactive,
            as_label,
            slot,
        } => {
            if interactive {
                review_interactive(conn, &kqtf, (as_label, slot))
            } else {
                review(conn, &kqtf)
            }
        }
        FileCommand::Graph { kqtf } => graph(conn, &kqtf),
        FileCommand::Diff { kqtf, from, to } => diff(conn, &kqtf, from, to),
        FileCommand::Checkout {
            kqtf,
            out,
            revision,
            shareable,
            record,
            as_label,
        } => checkout(
            conn,
            &kqtf,
            &out,
            revision,
            shareable,
            record.then_some(as_label.as_deref()),
        ),
        FileCommand::List => list(conn),
        FileCommand::Reindex { kqtf, clear } => reindex(conn, &kqtf, clear),
        FileCommand::Status { kqtf } => status(conn, &kqtf),
        FileCommand::History { kqtf, export } => history(conn, &kqtf, export),
        FileCommand::VerifySnapshot { snapshot, against } => verify_snapshot(&snapshot, against),
        FileCommand::Import {
            kqtf,
            from,
            as_label,
        } => import(conn, &kqtf, &from, &as_label),
        FileCommand::Verify {
            kqtf,
            record,
            as_label,
        } => verify(conn, &kqtf, record.then_some(as_label.as_deref())),
        FileCommand::Expire {
            kqtf,
            as_label,
            at,
            now,
            slot,
            signing_key_file,
        } => expire(conn, &kqtf, &as_label, (at, now), (slot, signing_key_file)),
        FileCommand::Rename {
            kqtf,
            new_name,
            as_label,
            slot,
            signing_key_file,
        } => rename(conn, &kqtf, &new_name, &as_label, (slot, signing_key_file)),
        FileCommand::Link {
            kqtf,
            quorum_file,
            locked_file,
        } => {
            let (gate, id) = gate_target(quorum_file, locked_file)?;
            gate_link::link(conn, &kqtf, gate, id)
        }
        FileCommand::Unlink {
            kqtf,
            quorum_file,
            locked_file,
        } => {
            let (gate, id) = gate_target(quorum_file, locked_file)?;
            gate_link::unlink(conn, &kqtf, gate, id)
        }
        FileCommand::Share {
            kqtf,
            to,
            as_label,
            slot,
            signing_key_file,
            revision,
            output_dir,
            push,
            url,
            api_key,
        } => share(
            conn,
            &kqtf,
            &to,
            &as_label,
            (slot, signing_key_file),
            revision,
            (output_dir, push, url, api_key),
        ),
        FileCommand::SendHistory {
            kqtf,
            to,
            as_label,
            slot,
            signing_key_file,
            output_dir,
            push,
            url,
            api_key,
        } => send_history(
            conn,
            &kqtf,
            &to,
            &as_label,
            (slot, signing_key_file),
            (output_dir, push, url, api_key),
        ),
        FileCommand::OpenHistory {
            letter,
            slot,
            share_file,
            against,
            out,
        } => open_history(
            conn,
            &letter,
            share_file.as_deref(),
            slot.as_deref(),
            against,
            out,
        ),
        FileCommand::Receive {
            letter,
            slot,
            share_file,
            signing_key_file,
            into,
            out,
            reject,
            ack_dir,
            push_ack,
            url,
            api_key,
        } => receive(
            conn,
            &letter,
            recipient_secrets(slot, share_file, signing_key_file)?,
            (into, out, reject),
            (ack_dir, push_ack, url, api_key),
        ),
        FileCommand::Ack {
            kqtf,
            ack,
            slot,
            share_file,
        } => record_ack(conn, &kqtf, &ack, share_file.as_deref(), slot.as_deref()),
    }
}

fn gate_target(quorum_file: Option<i64>, locked_file: Option<i64>) -> Result<(Gate, i64)> {
    match (quorum_file, locked_file) {
        (Some(id), None) => Ok((Gate::Quorum, id)),
        (None, Some(id)) => Ok((Gate::Password, id)),
        _ => Err(usage("pass --quorum-file or --locked-file")),
    }
}

/// The store as the source of signing keys. A key counts only for the
/// identity this store knows for that label.
pub(crate) struct StoreTrust<'a> {
    pub(crate) conn: &'a Connection,
}

impl TrustContext for StoreTrust<'_> {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        if identity_for(self.conn, label).ok()? != *identity {
            return None;
        }
        private_bridge::signing_public_for_label(self.conn, label).ok()
    }

    fn historical_signing_publics(
        &self,
        identity: &[u8; 16],
        label: &str,
        generation: u64,
    ) -> Vec<[u8; 32]> {
        authority::historical_signing_publics(self.conn, label, identity, generation)
            .unwrap_or_default()
    }

    fn bridge_evidence(&self, _revision_id: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }

    /// A private bridge's signed approval of this revision, re-verified
    /// now against the live bridge, from a bridge whose parties reach from
    /// the author to the scope. Reported only as "satisfied".
    fn revision_bridge_evidence(
        &self,
        revision: &crate::file_history::FileRevision,
        scope_root: &str,
    ) -> BridgeEvidence {
        let Ok(message) = signing::file_bridge_approval_preimage(
            &revision.file_id,
            &revision.revision_id,
            &revision.author_hcp_label,
            scope_root,
            revision.topology_generation,
            &revision.policy_hash,
        ) else {
            return BridgeEvidence::None;
        };
        let author = revision.author_hcp_label.as_str();
        let reaches = |parties: &[String]| {
            parties.iter().any(|a| {
                parties
                    .iter()
                    .any(|b| authority::bridge_connects(a, b, author, scope_root))
            })
        };
        match private_bridge::revision_approved(self.conn, &revision.revision_id, &message, reaches)
        {
            Ok(true) => BridgeEvidence::PrivateAuthorized,
            _ => BridgeEvidence::None,
        }
    }

    fn generation_evidence(&self, scope_root: &str, generation: u64) -> GenerationEvidence {
        let root = scope_root.split('.').next().unwrap_or(scope_root);
        let tree = key_tree::tree_by_label(self.conn, root).ok().flatten();
        match tree {
            _ if generation == 0 => GenerationEvidence::Current,
            None => GenerationEvidence::Unavailable,
            Some((_, current)) if u64::from(current) == generation => GenerationEvidence::Current,
            Some((key_id, _)) => {
                if key_tree::generation_seen(self.conn, key_id, generation).unwrap_or(false) {
                    GenerationEvidence::Recorded
                } else {
                    GenerationEvidence::Unavailable
                }
            }
        }
    }

    /// Live bridges this store holds right now: an established tree bridge
    /// is reported as such; otherwise a live private bridge only as
    /// "satisfied", never which one. A store that cannot read its bridges
    /// reports none.
    fn bridge_between(&self, from: &str, to: &str) -> BridgeEvidence {
        let joins = |a: &str, b: &str| authority::bridge_connects(a, b, from, to);
        let tree = key_tree::established_bridge_pairs(self.conn).unwrap_or_default();
        if tree.iter().any(|(a, b)| joins(a, b)) {
            return BridgeEvidence::NonPrivateAuthorized;
        }
        let rosters = private_bridge::active_rosters(self.conn).unwrap_or_default();
        let private = rosters
            .iter()
            .any(|labels| labels.iter().any(|a| labels.iter().any(|b| joins(a, b))));
        if private {
            BridgeEvidence::PrivateAuthorized
        } else {
            BridgeEvidence::None
        }
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

/// A ghost keeps its place in the hierarchy but has given up its private
/// key (a MOVE), so it may not author or sign anything new. Verifying what
/// it signed earlier is unaffected: that goes through `StoreTrust`.
pub(super) fn require_active(conn: &Connection, label: &str) -> Result<()> {
    if transfer::possession(conn, label)? == Some(transfer::Possession::Ghost) {
        return Err(usage(&format!(
            "{label} is a ghost on this store and cannot author or sign"
        )));
    }
    Ok(())
}

fn signing_secret(slot: Option<String>, key_file: Option<PathBuf>) -> Result<Zeroizing<[u8; 32]>> {
    match (slot, key_file) {
        (Some(slot), None) => Ok(open_slot_secrets(&slot)?.signing_secret),
        (None, Some(path)) => Ok(Zeroizing::new(read_key_array_32(&path)?)),
        _ => Err(usage("pass --slot or --signing-key-file")),
    }
}

/// The creation time of a revision, with sub-second precision where the
/// clock has it, so adjacent check-ins get distinguishable generated labels.
pub(super) fn revision_instant() -> Result<String> {
    utc_form(&env::now_utc_precise()?)
}

/// `2026-09-27 00:00` or `2026-09-27 00:00:00` as `2026-09-27T00:00:00Z`.
pub(super) fn utc_instant() -> Result<String> {
    utc_form(&env::now_utc()?)
}

fn utc_form(now: &str) -> Result<String> {
    let now = now.to_string();
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

/// The scope's current topology generation (0 when this store has no tree
/// for it), remembered as held so later revisions stamped with it can be
/// judged after a restructure.
fn generation_for(conn: &Connection, scope: &str) -> Result<u64> {
    let root = scope.split('.').next().unwrap_or(scope);
    let Some((key_id, generation)) = key_tree::tree_by_label(conn, root)? else {
        note_label_authority(conn, root, 0)?;
        return Ok(0);
    };
    let generation = u64::from(generation);
    key_tree::note_generation(conn, key_id, generation)?;
    note_label_authority(conn, root, generation)?;
    Ok(generation)
}

/// Remember which identity and signing key each label under `root` holds
/// right now, against `generation`, so revisions stamped with it stay
/// checkable after a label is reissued or reassigned (`authority`).
fn note_label_authority(conn: &Connection, root: &str, generation: u64) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT label, public_key FROM hardware_keys
         WHERE key_type = 'signing' AND revoked_at IS NULL
           AND (label = ?1 OR label LIKE ?2 ESCAPE '\\')",
    )?;
    let pattern = format!(
        "{}.%",
        root.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let rows = stmt
        .query_map(rusqlite::params![root, pattern], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (label, public) in rows {
        let Ok(public) = <[u8; 32]>::try_from(public) else {
            continue;
        };
        let identity = identity_for(conn, &label)?;
        authority::record_label_evidence(conn, root, &label, &identity, &public, generation)?;
    }
    Ok(())
}

thread_local! {
    /// SHA-256 of each container as this command read it, so `save` can
    /// refuse to replace a file another command changed in between.
    static READ_AT: RefCell<HashMap<PathBuf, [u8; 32]>> = RefCell::new(HashMap::new());
}

pub(super) fn load(path: &Path) -> Result<TrackedFile> {
    let bytes = env::read(path)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    READ_AT.with(|read| read.borrow_mut().insert(path.to_path_buf(), digest));
    TrackedFile::decode(&bytes)
}

/// Exclusive right to replace one container, held as a sibling `.lock`
/// file that is created without overwriting and removed when dropped.
struct WriteLock(PathBuf);

impl WriteLock {
    fn acquire(path: &Path) -> Result<Self> {
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        env::write_new(&lock, b"keyquorum file lock\n").map_err(|_| {
            usage(&format!(
                "another command is updating this file; if none is running, remove {}",
                lock.display()
            ))
        })?;
        Ok(Self(lock))
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let _ = env::remove_file(&self.0);
    }
}

fn expiry_context(
    conn: &Connection,
    file: &TrackedFile,
    actor: Option<&str>,
    now: &str,
) -> Result<ExpiryContext> {
    let generation = match file.policy() {
        Some(policy) => Some(generation_for(conn, &policy.scope_root)?),
        None => None,
    };
    Ok(ExpiryContext {
        actor_identity: actor.map(|label| identity_for(conn, label)).transpose()?,
        actor_label: actor.map(str::to_string),
        occurred_at: now.to_string(),
        topology_generation: generation,
    })
}

/// Load a container for a command that needs its content. Like a quorum or
/// password file, the first touch after a scheduled expiry destroys every
/// retained payload; from then on each attempt to use the content is
/// recorded as `EXPIRED_ACCESS_ATTEMPT` and refused. `actor` is recorded
/// only when the command names one (`--as`); otherwise the attempt is
/// attributed to no one rather than guessed.
fn load_live(
    conn: &Connection,
    path: &Path,
    actor: Option<&str>,
    action: &str,
) -> Result<TrackedFile> {
    let mut file = load(path)?;
    let now = utc_instant()?;
    let due = !file.is_destroyed() && file.is_expired_at(&now);
    if !due && !file.is_destroyed() {
        return Ok(file);
    }
    let context = expiry_context(conn, &file, actor, &now)?;
    if due {
        let destroyed = file.destroy_content("scheduled expiry passed", &context)?;
        errln!(
            "{} expired: the content of {destroyed} revision(s) was destroyed",
            file.logical_name
        );
    }
    file.record_expired_access(action, &context)?;
    save(path, &file)?;
    index_after(conn, &file);
    Err(Error::FileExpired)
}

fn policy_of(file: &TrackedFile) -> Result<&FilePolicy> {
    file.policy()
        .ok_or_else(|| usage("this tracked file has no policy"))
}

/// Replace the container atomically: write a sibling, then rename over it.
/// The write happens under an exclusive lock, and it is refused when the
/// container on disk is no longer the one this command read, so two commands
/// cannot silently overwrite each other's changes.
pub(super) fn save(path: &Path, file: &TrackedFile) -> Result<()> {
    let bytes = file.encode()?;
    let _lock = WriteLock::acquire(path)?;
    let read_at = READ_AT.with(|read| read.borrow_mut().remove(path));
    match read_at {
        // Replacing a container this command read: it must be unchanged.
        Some(expected) => {
            let unchanged = env::exists(path)
                && Into::<[u8; 32]>::into(Sha256::digest(env::read(path)?)) == expected;
            if !unchanged {
                return Err(usage(
                    "this file changed since the command read it; run the command again",
                ));
            }
        }
        // Never read: this must be a new file, never a silent replacement.
        None if env::exists(path) => {
            return Err(usage(
                "this file appeared while the command ran; run the command again",
            ));
        }
        None => {}
    }
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    if env::exists(&temp) {
        env::remove_file(&temp)?;
    }
    env::write_new(&temp, &bytes)?;
    env::fs(|fs| fs.rename(&temp, path))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    READ_AT.with(|read| read.borrow_mut().insert(path.to_path_buf(), digest));
    Ok(())
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
    let mut details = EventDetails::new()
        .with("result", &trust_text(state))
        .with("reason", &decision_reason(&policy, file, &revision, state));
    if let Some(satisfied_by) = approval_satisfaction(conn, &policy, file, &revision, state) {
        details = details.with("satisfied_by", satisfied_by);
    }
    let mut recorded = event(
        HistoryEventType::PolicyDecision,
        Some(revision),
        at,
        identity,
        label,
        generation,
        details,
    );
    if matches!(state, TrustState::Denied(_)) {
        recorded.outcome = HistoryOutcome::Denied;
    }
    file.append(recorded)?;
    Ok(state)
}

/// Which privacy-safe cross-branch alternative made a trusted decision.
///
/// This deliberately records no bridge id, generation, signer or roster.
/// For the OR rule, valid live bridge evidence wins this description; if it
/// is absent, a trusted result necessarily came from the scope owner. The AND
/// rule can only be trusted when both checks succeeded.
fn approval_satisfaction(
    conn: &Connection,
    policy: &FilePolicy,
    file: &TrackedFile,
    revision_id: &[u8; 32],
    state: TrustState,
) -> Option<&'static str> {
    if state != TrustState::Trusted {
        return None;
    }
    let revision = &file.graph().get(revision_id)?.revision;
    match policy.requirement_for(&revision.author_hcp_label)? {
        Requirement::AuthorSignBridgeOrOwner => {
            if (StoreTrust { conn }).revision_bridge_evidence(revision, &policy.scope_root)
                != BridgeEvidence::None
            {
                Some("BRIDGE")
            } else {
                Some("SCOPE_OWNER")
            }
        }
        Requirement::AuthorSignBridgeAndOwner => Some("BRIDGE_AND_SCOPE_OWNER"),
        _ => None,
    }
}

/// The design's wording for why the policy decided as it did.
fn decision_reason(
    policy: &FilePolicy,
    file: &TrackedFile,
    revision: &[u8; 32],
    state: TrustState,
) -> String {
    match state {
        TrustState::Trusted => file
            .graph()
            .get(revision)
            .and_then(|stored| policy.requirement_for(&stored.revision.author_hcp_label))
            .map_or_else(String::new, |rule| rule.trusted_because().to_string()),
        TrustState::Pending(reason) | TrustState::Denied(reason) => {
            format!("{reason:?}").to_uppercase()
        }
    }
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
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
    user_label: Option<String>,
    name: Option<String>,
    out: Option<PathBuf>,
    policy: FilePolicy,
    require_trusted: bool,
) -> Result<()> {
    let scope = policy.scope_root.as_str();
    if !policy.may_author(as_label) {
        return Err(usage("--as is outside the scope of this file"));
    }
    require_active(conn, as_label)?;
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
            created_at_utc: revision_instant()?,
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
    // Tracking that starts by signing a native file begins at the first
    // *trusted* content signature: a first revision still waiting on a
    // countersignature has nothing to be tracked under yet. An explicit
    // `file track` may begin with a pending revision.
    if require_trusted && state != TrustState::Trusted {
        return Err(usage(&format!(
            "the first revision is not trusted under this file's rules ({}); have the scope owner or an author whose signature alone is enough start tracking",
            trust_text(state)
        )));
    }
    env::write_new(&out, &file.encode()?)?;
    index_after(conn, &file);
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
    let mut file = load_live(conn, kqtf, Some(as_label), "checkin")?;
    let policy = policy_of(&file)?.clone();
    if !policy.may_author(as_label) {
        return Err(usage("--as is outside the scope of this file"));
    }
    require_active(conn, as_label)?;
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
            created_at_utc: revision_instant()?,
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
    index_after(conn, &file);
    let stored = file.graph().get(&revision).expect("just checked in");
    outln!("Checked in {}", stored.revision.generated_label);
    outln!("  id    {}", short(&revision));
    outln!("  trust {}", trust_text(state));
    if unsigned {
        errln!("Unsigned: sharing falls back to the last trusted revision.");
    }
    Ok(())
}

/// True when `path` starts with the KQTF magic.
fn is_container(path: &Path) -> bool {
    env::read(path).is_ok_and(|bytes| bytes.starts_with(crate::file_history::CONTAINER_MAGIC))
}

/// The first content signature over a native file starts tracking it: the
/// same steps as `file track`, so the file gets its stable id, revision R1,
/// a signature, and the `TRACKING_STARTED` and `REVISION_SIGNED` events.
/// The scope defaults to the signer's own label (a scope owner's own
/// signature is trusted), so ordinary signing activates tracking; the first
/// revision must be trusted or nothing is written. Legacy files that are
/// never signed stay untracked. A copy of the same bytes at another path is
/// its own file: signing it starts a separate lineage with its own id, since
/// content commitments are bound to the file id and a copy's later history
/// is not this file's.
fn activate_on_first_signature(
    conn: &Connection,
    native: &Path,
    revision: Option<String>,
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
    scope: Option<String>,
) -> Result<()> {
    if revision.is_some() {
        return Err(usage("a file that is not tracked has no revisions to pick"));
    }
    let scope = scope.unwrap_or_else(|| as_label.to_string());
    let mut container = native.as_os_str().to_owned();
    container.push(".kqtf");
    let container = PathBuf::from(container);
    if env::exists(&container) {
        return Err(usage(&format!(
            "{} already tracks this file; sign that container",
            container.display()
        )));
    }
    track(
        conn,
        native,
        as_label,
        slot,
        key_file,
        None,
        None,
        Some(container),
        FilePolicy::standard(&scope),
        true,
    )
}

fn sign(
    conn: &Connection,
    kqtf: &Path,
    revision: Option<String>,
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
) -> Result<()> {
    let mut file = load_live(conn, kqtf, Some(as_label), "sign")?;
    require_active(conn, as_label)?;
    let target = pick_revision(&file, revision.as_deref())?;
    refuse_if_rejected(&file, &target)?;
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
    index_after(conn, &file);
    outln!("Signed {} as {as_label}", short(&target));
    outln!("  trust {}", trust_text(state));
    Ok(())
}

/// A reviewer refused this proposed merge; it is never signed into trust.
fn refuse_if_rejected(file: &TrackedFile, revision: &[u8; 32]) -> Result<()> {
    if file.is_rejected(revision) {
        return Err(usage(&format!(
            "revision {} was rejected by its reviewer; resolve the conflict with `file resolve`",
            short(revision)
        )));
    }
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
    let mut file = load_live(conn, kqtf, Some(as_label), "countersign")?;
    require_active(conn, as_label)?;
    let target = pick_revision(&file, revision.as_deref())?;
    let secret = signing_secret(slot, key_file)?;
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy_of(&file)?.scope_root)?;
    file.countersign_revision_checked(&target, identity, as_label, &secret, &StoreTrust { conn })
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
        EventDetails::new().with("for_actor", &author).with(
            "relationship",
            countersigner_relationship(as_label, &author),
        ),
    ))?;
    let state = decide(conn, &mut file, target, &at, identity, as_label, generation)?;
    // A countersignature by the wrong person is stored but earns nothing;
    // only invalid evidence stops the write.
    refuse_if_denied(state, as_label)?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!("Countersigned {} as {as_label}", short(&target));
    outln!("  trust {}", trust_text(state));
    Ok(())
}

fn parse_requirement(word: &str) -> std::result::Result<Requirement, String> {
    Requirement::from_keyword(word)
        .ok_or_else(|| "use forbidden, author, author+parent or author+bridge-or-owner".to_string())
}

/// Finalize a trusted revision. This is the deliberate act on top of trust:
/// the scope owner or an ancestor signs a finalization proof that any store
/// holding their key can check. Trust is not changed and no history is
/// rewritten.
fn finalize(
    conn: &Connection,
    kqtf: &Path,
    revision: Option<String>,
    as_label: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
) -> Result<()> {
    let mut file = load_live(conn, kqtf, Some(as_label), "finalize")?;
    let policy = policy_of(&file)?.clone();
    if !authority::is_ancestor_or_self(as_label, &policy.scope_root) {
        return Err(usage(&format!(
            "only {} or one of its ancestors may finalize a revision of this file",
            policy.scope_root
        )));
    }
    require_active(conn, as_label)?;
    let target = pick_revision(&file, revision.as_deref())?;
    let ctx = StoreTrust { conn };
    let state = evaluate_revision_trust(&file, &target, &policy, &ctx)?;
    if state != TrustState::Trusted {
        return Err(usage(&format!(
            "only a trusted revision can be finalized; this one is {}",
            trust_text(state)
        )));
    }
    let secret = signing_secret(slot, key_file)?;
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy.scope_root)?;
    file.finalize_revision(&target, identity, as_label, &secret)
        .map_err(|_| usage(&format!("{as_label} already finalized this revision")))?;
    // The signature must verify under the key this store registered for the
    // label; a wrong key is refused before anything is written.
    if !is_finalized(&file, &target, &policy, &ctx) {
        return Err(usage(&format!(
            "the signing key you supplied is not the one registered for {as_label} in this store"
        )));
    }
    file.append(event(
        HistoryEventType::RevisionFinalized,
        Some(target),
        &at,
        identity,
        as_label,
        generation,
        EventDetails::new(),
    ))?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!("Finalized {} as {as_label}", short(&target));
    Ok(())
}

/// The rules the file's revisions are judged by, and the hash every
/// revision carries so later verification knows which rules applied.
fn show_policy(kqtf: &Path) -> Result<()> {
    let file = load(kqtf)?;
    let policy = policy_of(&file)?;
    outln!("{} ({})", file.logical_name, hex::encode(file.file_id));
    outln!("  scope_root          {}", policy.scope_root);
    outln!("  scope owner         {}", policy.scope_owner.keyword());
    outln!("  descendants         {}", policy.descendants.keyword());
    outln!("  ancestors           {}", policy.ancestors.keyword());
    outln!("  cross-branch        {}", policy.cross_branch.keyword());
    outln!(
        "  edits by descendants {}",
        policy.descendants != Requirement::Forbidden
    );
    outln!("  auto merge          {}", policy.auto_merge);
    outln!(
        "  policy_hash         {}",
        hex::encode(policy.policy_hash()?)
    );
    outln!("The rules are fixed when the file is tracked; every revision carries this hash.");
    Ok(())
}

/// How the countersigner stands to the author it backs.
fn countersigner_relationship(countersigner: &str, author: &str) -> &'static str {
    if authority::direct_parent(countersigner, author) {
        "DIRECT_PARENT"
    } else if authority::is_ancestor_or_self(countersigner, author) {
        "ANCESTOR"
    } else {
        "OTHER"
    }
}

fn status(conn: &Connection, kqtf: &Path) -> Result<()> {
    let file = load(kqtf)?;
    let policy = policy_of(&file)?;
    let ctx = StoreTrust { conn };
    outln!("{} ({})", file.logical_name, hex::encode(file.file_id));
    outln!("  scope        {}", policy.scope_root);
    outln!("  history root {}", hex::encode(file.history_root()));
    if file.is_destroyed() {
        outln!("  EXPIRED: content destroyed; history kept as a tombstone");
    } else if let Some(at) = file.expires_at() {
        outln!("  expires      {at}");
    }
    let heads = file.graph().heads();
    if heads.len() > 1 {
        outln!("  FORK: {} heads; neither is overwritten", heads.len());
    }
    // Derived here, from this store's keys; a container never stores trust.
    match current_revision(&file) {
        Some(id) => outln!("  current_revision_id {}", short(&id)),
        None => outln!("  current_revision_id none (forked)"),
    }
    match latest_trusted_revision(&file, policy, &ctx) {
        Some(id) => outln!("  trusted_revision_id {}", short(&id)),
        None => outln!("  trusted_revision_id none"),
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
        match latest_finalized_ancestor(&file, head, policy, &ctx) {
            Some(id) => outln!("    finalized {}", short(&id)),
            None => outln!("    finalized none"),
        }
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

fn history(conn: &Connection, kqtf: &Path, export: Option<PathBuf>) -> Result<()> {
    let file = load(kqtf)?;
    let ctx = StoreTrust { conn };
    for event in file.events() {
        // An actor's signature on the event, if this store's key for that
        // actor verifies it; otherwise the line is a hash-chained record.
        let signed = file
            .event_proofs()
            .iter()
            .any(|proof| proof.sequence == event.sequence);
        let mark = match event_attested(&file, event.sequence, &ctx) {
            Some(label) => format!(" [signed by {label}]"),
            None if signed => " [signature not verified in this store]".to_string(),
            None => String::new(),
        };
        outln!("{}{mark}", describe(event));
    }
    if let Some(path) = export {
        env::write_new(&path, &file.history_snapshot().encode()?)?;
        errln!(
            "Wrote a snapshot of {} event(s), root {}, to {}",
            file.events().len(),
            hex::encode(&file.history_root()[..6]),
            path.display()
        );
    }
    Ok(())
}

fn verify_snapshot(snapshot: &Path, against: Option<PathBuf>) -> Result<()> {
    let snapshot = HistorySnapshot::decode(&env::read(snapshot)?)?;
    outln!(
        "Snapshot verifies: file {}, {} event(s), root {}",
        hex::encode(snapshot.file_id),
        snapshot.events.len(),
        hex::encode(&snapshot.history_root[..6])
    );
    if let Some(path) = against {
        let file = load(&path)?;
        if !snapshot.is_prefix_of(&file) {
            return Err(usage(&format!(
                "the snapshot is not a point in the history of {}",
                path.display()
            )));
        }
        outln!("It is a point in the history of {}", file.logical_name);
    }
    Ok(())
}

fn import(conn: &Connection, kqtf: &Path, from: &Path, as_label: &str) -> Result<()> {
    let mut file = load_live(conn, kqtf, Some(as_label), "import")?;
    let other = load(from)?;
    let policy = policy_of(&file)?.clone();
    if !policy.may_author(as_label) {
        return Err(usage("--as is outside the scope of this file"));
    }
    require_active(conn, as_label)?;
    let context = ImportContext {
        actor_identity: Some(identity_for(conn, as_label)?),
        actor_label: as_label.to_string(),
        occurred_at: utc_instant()?,
        topology_generation: generation_for(conn, &policy.scope_root)?,
    };
    let merged = file.merge_history(&other, &context).map_err(|_| {
        usage("that is not another copy of this file (same id and policy, and it must verify)")
    })?;
    if merged.revisions_added == 0 && merged.proofs_added == 0 {
        outln!("Nothing new to import ({:?}).", merged.relation);
        return Ok(());
    }
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!(
        "Imported: {:?}; {} revision(s) and {} proof(s) added",
        merged.relation,
        merged.revisions_added,
        merged.proofs_added
    );
    if merged.relation == HistoryRelation::Diverged {
        outln!("The history has forked. Run `keyquorum file merge` to join the heads.");
    }
    Ok(())
}

type Transport = (Option<PathBuf>, bool, Option<String>, Option<String>);

fn share(
    conn: &Connection,
    kqtf: &Path,
    to: &str,
    as_label: &str,
    keys: (Option<String>, Option<PathBuf>),
    revision: Option<String>,
    (output_dir, push, url, api_key): Transport,
) -> Result<()> {
    require_active(conn, as_label)?;
    let mut file = load_live(conn, kqtf, Some(as_label), "share")?;
    let policy = policy_of(&file)?.clone();
    let candidate = pick_revision(&file, revision.as_deref())?;
    let decision =
        select_shareable_revision(&file, &candidate, None, &policy, &StoreTrust { conn })?;
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy.scope_root)?;
    let Some(delivered) = decision.delivered_revision else {
        // Refused outright by the rules, or simply not trusted yet.
        let by_policy = decision.decision == DeliveryDecisionKind::DeniedPolicy;
        let (recorded, message) = if by_policy {
            (
                "delivery denied by policy",
                "the file's rules refuse to deliver this revision",
            )
        } else {
            (
                "no trusted revision to share",
                "no trusted revision exists to share",
            )
        };
        let mut refused = event(
            HistoryEventType::ShareAttempted,
            Some(candidate),
            &at,
            identity,
            as_label,
            generation,
            EventDetails::new().with("to", to).with("result", recorded),
        );
        refused.outcome = HistoryOutcome::Denied;
        file.append(refused)?;
        save(kqtf, &file)?;
        index_after(conn, &file);
        return Err(usage(message));
    };
    let extract = file.extract_revision(&delivered)?;
    // The extract must carry exactly the proofs the decision relied on.
    let content_proof = proof_descriptor(&extract, &delivered)?;
    if Some(content_proof) != decision.content_proof {
        return Err(usage(
            "the extract does not carry the proofs the decision relied on",
        ));
    }
    let container = extract.encode()?;
    let (signing_secret, encryption_public) = sender_keys(conn, keys.0, keys.1, as_label)?;
    let recipient = registered_encryption_key(conn, to)?;
    let sealed = file_delivery::seal_history_letter(&file_delivery::OutgoingHistory {
        sender_label: as_label,
        sender_signing_secret: &signing_secret,
        sender_encryption_public: &encryption_public,
        recipient_label: to,
        recipient_encryption_public: &recipient,
        file_name: &file.logical_name,
        file_id: file.file_id,
        revision_id: delivered,
        history_root: extract.history_root(),
        decision: decision.decision.code(),
        content_proof,
        container: &container,
    })?;
    // Recorded before the letter leaves, so a failed upload still leaves a
    // truthful "attempted" entry and the delivery id an ack must match.
    let delivery = hex::encode(sealed.delivery_id);
    let mut details = EventDetails::new()
        .with("to", to)
        .with("delivery_id", &delivery)
        .with("decision", &format!("{:?}", decision.decision))
        .with("container_hash", &hex::encode(sealed.container_hash));
    if delivered != candidate {
        // A fallback: name what was asked for and why it stayed behind,
        // as the candidate's trust state (never its content).
        let state = evaluate_revision_trust(&file, &candidate, &policy, &StoreTrust { conn })?;
        details = details.with("candidate", &hex::encode(candidate)).with(
            "fallback_reason",
            &decision_reason(&policy, &file, &candidate, state),
        );
    }
    file.append(event(
        HistoryEventType::ShareAttempted,
        Some(delivered),
        &at,
        identity,
        as_label,
        generation,
        details,
    ))?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!(
        "Sealed {} revision {} to {to} (delivery {delivery}, {:?})",
        file.logical_name,
        short(&delivered),
        decision.decision
    );
    if delivered != candidate {
        outln!(
            "Revision {} is not trusted, so it was left out.",
            short(&candidate)
        );
    }
    let letter = Letter {
        name: delivery,
        bytes: sealed.bytes,
    };
    carry(conn, &letter, output_dir.as_deref(), push, url, api_key)
}

fn send_history(
    conn: &Connection,
    kqtf: &Path,
    to: &str,
    as_label: &str,
    keys: (Option<String>, Option<PathBuf>),
    (output_dir, push, url, api_key): Transport,
) -> Result<()> {
    require_active(conn, as_label)?;
    let file = load(kqtf)?;
    let snapshot = file.history_snapshot();
    let bytes = snapshot.encode()?;
    let (signing_secret, encryption_public) = sender_keys(conn, keys.0, keys.1, as_label)?;
    let recipient = registered_encryption_key(conn, to)?;
    let (delivery_id, sealed) =
        file_delivery::seal_history_snapshot(&file_delivery::OutgoingSnapshot {
            sender_label: as_label,
            sender_signing_secret: &signing_secret,
            sender_encryption_public: &encryption_public,
            recipient_label: to,
            recipient_encryption_public: &recipient,
            file_name: &file.logical_name,
            file_id: file.file_id,
            history_root: snapshot.history_root,
            event_count: u32::try_from(snapshot.events.len())
                .map_err(|_| Error::BundleFieldTooLarge)?,
            snapshot: &bytes,
        })?;
    outln!(
        "Sealed the history of {} ({} event(s), root {}) to {to}",
        file.logical_name,
        snapshot.events.len(),
        hex::encode(&snapshot.history_root[..6])
    );
    let letter = Letter {
        name: format!("{}-history", hex::encode(delivery_id)),
        bytes: sealed,
    };
    carry(conn, &letter, output_dir.as_deref(), push, url, api_key)
}

fn open_history(
    conn: &Connection,
    letter_path: &Path,
    share_file: Option<&str>,
    slot: Option<&str>,
    against: Option<PathBuf>,
    out: Option<PathBuf>,
) -> Result<()> {
    let secret = super::encryption_secret_from(share_file, slot)?;
    let letter = file_delivery::open_history_snapshot(conn, &secret, &env::read(letter_path)?)?;
    require_recipient_key(conn, &letter.recipient_label, &secret)?;
    // The header is the sender's claim; the snapshot must say the same.
    let snapshot = HistorySnapshot::decode(&letter.snapshot)
        .map_err(|_| usage("the snapshot in the letter does not verify"))?;
    if snapshot.file_id != letter.file_id
        || snapshot.history_root != letter.history_root
        || snapshot.events.len() != letter.event_count as usize
    {
        return Err(usage("the letter does not match the snapshot it carries"));
    }
    outln!(
        "History of {} from {}: {} event(s), root {}, sender signature verified",
        letter.file_name,
        letter.sender_label,
        letter.event_count,
        hex::encode(&letter.history_root[..6])
    );
    if let Some(path) = against {
        let local = load(&path)?;
        if local.file_id != snapshot.file_id {
            return Err(usage("that is not a copy of the same file"));
        }
        let local_is_prefix = local.events().len() <= snapshot.events.len()
            && local
                .events()
                .iter()
                .zip(&snapshot.events)
                .all(|(a, b)| a.event_hash == b.event_hash);
        let relation = match (snapshot.is_prefix_of(&local), local_is_prefix) {
            (true, true) => "SAME",
            (true, false) => "LOCAL_AHEAD",
            (false, true) => "REMOTE_AHEAD",
            (false, false) => "DIVERGED",
        };
        outln!("Compared with {}: {relation}", path.display());
    }
    if let Some(path) = out {
        env::write_new(&path, &letter.snapshot)?;
        outln!("Wrote {}", path.display());
    }
    Ok(())
}

fn receive(
    conn: &Connection,
    letter_path: &Path,
    secrets: RecipientSecrets,
    (into, out, reject): (Option<PathBuf>, Option<PathBuf>, bool),
    (ack_dir, push_ack, url, api_key): Transport,
) -> Result<()> {
    let bytes = env::read(letter_path)?;
    let letter = file_delivery::open_history_letter(conn, &secrets.encryption, &bytes)?;
    require_recipient_key(conn, &letter.recipient_label, &secrets.encryption)?;
    // The letter's header is only a claim about the container.
    let mut incoming = TrackedFile::decode(&letter.container)
        .map_err(|_| usage("the delivered container does not verify"))?;
    if incoming.file_id != letter.file_id
        || incoming.history_root() != letter.history_root
        || incoming.logical_name != letter.file_name
        || incoming.graph().get(&letter.revision_id).is_none()
        || incoming.graph().heads() != [letter.revision_id]
        || DeliveryDecisionKind::from_code(letter.decision).is_none()
        || proof_descriptor(&incoming, &letter.revision_id)? != letter.content_proof
    {
        return Err(usage("the letter does not match the container it carries"));
    }
    errln!(
        "From {} to {}: {} revision {}, sender signature verified",
        letter.sender_label,
        letter.recipient_label,
        letter.file_name,
        short(&letter.revision_id)
    );
    // Compared with what this store accepted before, never assumed newest.
    let freshness = file_delivery::freshness(
        conn,
        &letter,
        |id| incoming.graph().get(id).is_some(),
        |root| incoming.passes_through(root),
    )?;
    errln!(
        "History: {} (against what this store accepted before)",
        freshness.name()
    );
    let policy = policy_of(&incoming)?.clone();
    let state = evaluate_revision_trust(
        &incoming,
        &letter.revision_id,
        &policy,
        &StoreTrust { conn },
    )?;
    let mut accepted = !reject;
    if accepted && state != TrustState::Trusted {
        errln!(
            "Refused: revision {} is {} here.",
            short(&letter.revision_id),
            trust_text(state)
        );
        accepted = false;
    }
    if reject {
        errln!("Rejected {}", letter.file_name);
    }
    if accepted {
        require_active(conn, &letter.recipient_label)?;
        let (identity, at) = (identity_for(conn, &letter.recipient_label)?, utc_instant()?);
        let generation = generation_for(conn, &policy.scope_root)?;
        let delivered = || {
            event(
                HistoryEventType::ShareDelivered,
                Some(letter.revision_id),
                &at,
                identity,
                &letter.recipient_label,
                generation,
                EventDetails::new()
                    .with("from", &letter.sender_label)
                    .with("freshness", freshness.name())
                    .with("delivery_id", &hex::encode(letter.delivery_id))
                    .with("container_hash", &hex::encode(letter.container_hash)),
            )
        };
        match (into, out) {
            (Some(target), _) => {
                let mut file = load_live(conn, &target, Some(&letter.recipient_label), "receive")?;
                let context = ImportContext {
                    actor_identity: Some(identity),
                    actor_label: letter.recipient_label.clone(),
                    occurred_at: at.clone(),
                    topology_generation: generation,
                };
                let merged = file.merge_history(&incoming, &context).map_err(|_| {
                    usage("that is not another copy of this file (same id and policy)")
                })?;
                // A retry after a lost acknowledgement must not record the
                // same delivery twice: the delivery id makes receipt idempotent.
                if delivery_recorded(&file, &letter.delivery_id) {
                    outln!(
                        "Delivery {} was already recorded here.",
                        hex::encode(letter.delivery_id)
                    );
                } else {
                    file.append(delivered())?;
                }
                save(&target, &file)?;
                index_after(conn, &file);
                outln!(
                    "Merged into {}: {:?}; {} revision(s) and {} proof(s) added",
                    target.display(),
                    merged.relation,
                    merged.revisions_added,
                    merged.proofs_added
                );
            }
            (None, Some(target)) if env::exists(&target) => {
                // The same letter saved here before (its acknowledgement was
                // lost): nothing to write, only the answer to send again.
                let held = load(&target).ok().filter(|held| {
                    held.file_id == letter.file_id && delivery_recorded(held, &letter.delivery_id)
                });
                if held.is_none() {
                    return Err(usage("--out already exists; use --into to merge"));
                }
                outln!(
                    "Delivery {} was already saved to {}.",
                    hex::encode(letter.delivery_id),
                    target.display()
                );
            }
            (None, Some(target)) => {
                incoming.append(delivered())?;
                save(&target, &incoming)?;
                index_after(conn, &incoming);
                outln!("Saved {} to {}", letter.file_name, target.display());
            }
            (None, None) => return Err(usage("pass --into or --out")),
        }
    }
    if accepted {
        file_delivery::record_seen_root(conn, &letter)?;
    }
    let ack = Letter {
        name: format!("{}-ack", hex::encode(letter.delivery_id)),
        bytes: file_delivery::seal_history_ack(&letter, &secrets.signing, accepted)?,
    };
    carry(conn, &ack, ack_dir.as_deref(), push_ack, url, api_key)
}

/// Whether this container already records accepting `delivery_id`.
fn delivery_recorded(file: &TrackedFile, delivery_id: &[u8; 16]) -> bool {
    let delivery = hex::encode(delivery_id);
    file.events().iter().any(|e| {
        e.event_type == HistoryEventType::ShareDelivered
            && e.details
                .entries()
                .iter()
                .any(|(k, v)| k == "delivery_id" && *v == delivery)
    })
}

fn record_ack(
    conn: &Connection,
    kqtf: &Path,
    ack_path: &Path,
    share_file: Option<&str>,
    slot: Option<&str>,
) -> Result<()> {
    let secret = super::encryption_secret_from(share_file, slot)?;
    let ack = file_delivery::open_history_ack(conn, &secret, &env::read(ack_path)?)?;
    let mut file = load(kqtf)?;
    let delivery = hex::encode(ack.delivery_id);
    let has = |event: &HistoryEvent, key: &str| {
        event
            .details
            .entries()
            .iter()
            .any(|(k, v)| k == key && *v == delivery)
    };
    let answered = file.events().iter().any(|e| has(e, "answers"));
    let sent = file
        .events()
        .iter()
        .find(|e| e.event_type == HistoryEventType::ShareAttempted && has(e, "delivery_id"))
        .cloned()
        .filter(|e| {
            let entries = e.details.entries();
            file.file_id == ack.file_id
                && e.revision_id == Some(ack.revision_id)
                && entries.contains(&("container_hash".into(), hex::encode(ack.container_hash)))
                && entries.contains(&("to".into(), ack.recipient_label.clone()))
        })
        .ok_or_else(|| usage("that acknowledgement does not answer any delivery from this file"))?;
    if answered {
        outln!("Delivery {delivery} was already recorded.");
        return Ok(());
    }
    let (Some(identity), Some(sender)) = (sent.actor_identity, sent.actor_label.as_deref()) else {
        return Err(usage("the original delivery has no recorded sender"));
    };
    let policy = policy_of(&file)?.clone();
    let mut recorded = event(
        if ack.accepted {
            HistoryEventType::ShareDelivered
        } else {
            HistoryEventType::ShareAttempted
        },
        Some(ack.revision_id),
        &utc_instant()?,
        identity,
        sender,
        generation_for(conn, &policy.scope_root)?,
        EventDetails::new()
            .with("answers", &delivery)
            .with("by", &ack.recipient_label)
            .with("result", if ack.accepted { "accepted" } else { "rejected" }),
    );
    if !ack.accepted {
        recorded.outcome = HistoryOutcome::Denied;
    }
    file.append(recorded)?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!(
        "Delivery {delivery} {} by {}",
        if ack.accepted { "accepted" } else { "rejected" },
        ack.recipient_label
    );
    Ok(())
}

fn parse_expiry_arg(value: &str) -> std::result::Result<String, String> {
    crate::locked_files::parse_expires_utc(&value.replacen('T', " ", 1))
        .map_err(|err| err.to_string())
}

/// `2026-10-01 09:30:00` (the form `--at` parses to) as `2026-10-01T09:30:00Z`.
fn as_instant(value: &str) -> String {
    format!("{}Z", value.trim().replace(' ', "T"))
}

fn expire(
    conn: &Connection,
    kqtf: &Path,
    as_label: &str,
    (at, now): (Option<String>, bool),
    (slot, key_file): (Option<String>, Option<PathBuf>),
) -> Result<()> {
    let mut file = load(kqtf)?;
    let scope = policy_of(&file)?.scope_root.clone();
    // Deciding when a file's content ends belongs to whoever owns its scope.
    if !authority::is_ancestor_or_self(as_label, &scope) {
        return Err(usage(&format!(
            "only {scope} or one of its ancestors may expire this file"
        )));
    }
    require_active(conn, as_label)?;
    if file.is_destroyed() {
        return Err(usage("this file's content was already destroyed"));
    }
    let instant = utc_instant()?;
    let secret = prove_possession(conn, &file, "expire", as_label, &instant, slot, key_file)?;
    let start = file.events().len();
    let context = expiry_context(conn, &file, Some(as_label), &instant)?;
    match (at, now) {
        (_, true) => {
            let destroyed = file.destroy_content("expired on request", &context)?;
            sign_events_since(conn, &mut file, start, as_label, &secret)?;
            save(kqtf, &file)?;
            index_after(conn, &file);
            outln!(
                "Destroyed the content of {destroyed} revision(s) of {}; its history remains",
                file.logical_name
            );
        }
        (Some(at), false) => {
            let at = as_instant(&at);
            if at <= instant {
                return Err(usage(
                    "that time has passed; use --now to destroy the content now",
                ));
            }
            file.schedule_expiry(&at, &context)?;
            sign_events_since(conn, &mut file, start, as_label, &secret)?;
            save(kqtf, &file)?;
            index_after(conn, &file);
            outln!("{} expires at {at}", file.logical_name);
        }
        (None, false) => return Err(usage("pass --at or --now")),
    }
    Ok(())
}

fn rename(
    conn: &Connection,
    kqtf: &Path,
    new_name: &str,
    as_label: &str,
    (slot, key_file): (Option<String>, Option<PathBuf>),
) -> Result<()> {
    let new_name = new_name.trim();
    if new_name.is_empty() || new_name.contains(['/', '\\']) {
        return Err(usage("give a file name, not a path"));
    }
    let mut file = load_live(conn, kqtf, Some(as_label), "rename")?;
    let policy = policy_of(&file)?.clone();
    // The name people see is the owner's to change, like when the content ends.
    if !authority::is_ancestor_or_self(as_label, &policy.scope_root) {
        return Err(usage(&format!(
            "only {} or one of its ancestors may rename this file",
            policy.scope_root
        )));
    }
    require_active(conn, as_label)?;
    let at = utc_instant()?;
    let secret = prove_possession(conn, &file, "rename", as_label, &at, slot, key_file)?;
    let start = file.events().len();
    let old = std::mem::replace(&mut file.logical_name, new_name.to_string());
    if old == new_name {
        return Err(usage("that is already the file's name"));
    }
    let generation = generation_for(conn, &policy.scope_root)?;
    file.append(event(
        HistoryEventType::FileRenamed,
        None,
        &at,
        identity_for(conn, as_label)?,
        as_label,
        generation,
        EventDetails::new().with("from", &old).with("to", new_name),
    ))?;
    sign_events_since(conn, &mut file, start, as_label, &secret)?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!("Renamed {old} to {new_name}; the file id and every revision id are unchanged");
    Ok(())
}

/// Ending a file's content is irreversible, so naming an owner label is not
/// enough: the caller must sign a challenge bound to this file and moment
/// with the key the store has registered for `label`. The secret is opened
/// only here and dropped before anything is changed.
fn prove_possession(
    conn: &Connection,
    file: &TrackedFile,
    purpose: &str,
    label: &str,
    instant: &str,
    slot: Option<String>,
    key_file: Option<PathBuf>,
) -> Result<Zeroizing<[u8; 32]>> {
    let registered = private_bridge::signing_public_for_label(conn, label).map_err(|_| {
        usage(&format!(
            "{label} has no registered signing key on this store"
        ))
    })?;
    let secret = signing_secret(slot, key_file)?;
    let challenge: [u8; 32] = Sha256::new()
        .chain_update(b"KQ-FILE-POSSESSION-v1")
        .chain_update((purpose.len() as u16).to_be_bytes())
        .chain_update(purpose.as_bytes())
        .chain_update(file.file_id)
        .chain_update((label.len() as u16).to_be_bytes())
        .chain_update(label.as_bytes())
        .chain_update(instant.as_bytes())
        .finalize()
        .into();
    let signature = signing::sign(&secret, &challenge);
    signing::verify_signature(&registered, &challenge, &signature)
        .map_err(|_| usage(&format!("that key is not the registered key of {label}")))?;
    Ok(secret)
}

/// Sign, as their actor, the events `label` appended from `start` on: the
/// key was just proven, so the record of what it did is attested too.
fn sign_events_since(
    conn: &Connection,
    file: &mut TrackedFile,
    start: usize,
    label: &str,
    secret: &[u8; 32],
) -> Result<()> {
    let identity = identity_for(conn, label)?;
    let mine: Vec<u64> = file.events()[start..]
        .iter()
        .filter(|event| {
            event.actor_label.as_deref() == Some(label) && event.actor_identity == Some(identity)
        })
        .map(|event| event.sequence)
        .collect();
    for sequence in mine {
        file.sign_event(sequence, identity, label, secret)?;
    }
    Ok(())
}

/// `record`: `Some(actor)` appends a `VERIFICATION_RUN` event, attributed to
/// `actor` when the command names one.
fn verify(conn: &Connection, kqtf: &Path, record: Option<Option<&str>>) -> Result<()> {
    let file = load(kqtf)?;
    let root = verify_tracked_file(&file)?;
    let policy = policy_of(&file)?;
    let ctx = StoreTrust { conn };
    outln!(
        "History and revision graph verify; root {}",
        hex::encode(root)
    );
    if file.is_destroyed() {
        outln!(
            "Tombstone: the content of all {} revision(s) was destroyed at expiry",
            file.revisions().len()
        );
    }
    let (mut trusted, mut pending, mut denied) = (0, 0, 0);
    for stored in file.revisions() {
        let id = stored.revision.revision_id;
        let state = evaluate_revision_trust(&file, &id, policy, &ctx)?;
        match state {
            TrustState::Trusted => trusted += 1,
            TrustState::Pending(_) => pending += 1,
            TrustState::Denied(_) => denied += 1,
        }
        outln!("  {} {}", short(&id), trust_text(state));
    }
    if let Some(actor) = record {
        let details = EventDetails::new()
            .with("revisions", &file.revisions().len().to_string())
            .with("trusted", &trusted.to_string())
            .with("pending", &pending.to_string())
            .with("denied", &denied.to_string());
        let outcome = if denied > 0 {
            HistoryOutcome::Failure
        } else {
            HistoryOutcome::Success
        };
        record_access(
            conn,
            kqtf,
            HistoryEventType::VerificationRun,
            outcome,
            None,
            actor,
            details,
        )?;
    }
    if denied > 0 {
        return Err(Error::InvalidTrackedFile);
    }
    Ok(())
}

fn text_of(file: &TrackedFile, id: &[u8; 32]) -> Result<String> {
    let stored = file
        .graph()
        .get(id)
        .ok_or_else(|| usage("no such revision"))?;
    let content = stored
        .content()
        .ok_or_else(|| usage("that revision's content was destroyed at expiry"))?;
    String::from_utf8(content.to_vec())
        .map_err(|_| usage("that revision is not UTF-8 text, so there is no line view"))
}

fn print_changes(old: &str, new: &str) -> Result<()> {
    let changes =
        diff_text(old, new).ok_or_else(|| usage("the revisions are too large to compare"))?;
    if changes.is_empty() {
        outln!("  (no changed lines)");
    }
    for change in changes {
        let mark = match change.kind {
            ChangeKind::Removed => '-',
            ChangeKind::Added => '+',
        };
        outln!(
            "  {mark} {:>4} | {}",
            change.line,
            change.text.trim_end_matches('\n')
        );
    }
    Ok(())
}

fn bridge_approve(
    conn: &Connection,
    kqtf: &Path,
    revision: Option<String>,
    bridge: &str,
    as_label: &str,
    slot: &str,
) -> Result<()> {
    let mut file = load_live(conn, kqtf, Some(as_label), "bridge-approve")?;
    require_active(conn, as_label)?;
    let policy = policy_of(&file)?.clone();
    let target = pick_revision(&file, revision.as_deref())?;
    let stored = file
        .graph()
        .get(&target)
        .ok_or(Error::InvalidTrackedFile)?
        .revision
        .clone();
    if !matches!(
        policy.requirement_for(&stored.author_hcp_label),
        Some(Requirement::AuthorSignBridgeOrOwner | Requirement::AuthorSignBridgeAndOwner)
    ) {
        return Err(usage(
            "the file's rules do not accept a bridge approval for this revision's author",
        ));
    }
    let message = signing::file_bridge_approval_preimage(
        &stored.file_id,
        &stored.revision_id,
        &stored.author_hcp_label,
        &policy.scope_root,
        stored.topology_generation,
        &stored.policy_hash,
    )?;
    let secrets = open_slot_secrets(slot)?;
    private_bridge::approve_revision(
        conn,
        bridge,
        as_label,
        &secrets.encryption_secret,
        &secrets.signing_secret,
        &target,
        &message,
    )
    .map_err(|err| usage(&format!("the bridge refused to sign: {err}")))?;
    // What the store now makes of it; the bridge itself is never named.
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy.scope_root)?;
    let state = decide(conn, &mut file, target, &at, identity, as_label, generation)?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!("Approved {} through a private bridge", short(&target));
    outln!("  trust {}", trust_text(state));
    Ok(())
}

fn resolve(
    conn: &Connection,
    kqtf: &Path,
    resolution: Resolution,
    as_label: &str,
    (slot, key_file): (Option<String>, Option<PathBuf>),
    user_label: Option<String>,
) -> Result<()> {
    let mut file = load_live(conn, kqtf, Some(as_label), "resolve")?;
    let policy = policy_of(&file)?.clone();
    require_active(conn, as_label)?;
    let ctx = StoreTrust { conn };
    let Some(conflict) = file.open_conflict(policy.auto_merge)? else {
        return Err(usage(
            "nothing to resolve: no conflict waits for a person (see `file review`)",
        ));
    };
    if !file.may_decide(&conflict.left, &conflict.right, as_label, &policy, &ctx)? {
        return Err(usage(&format!(
            "{as_label} is not the reviewer of this conflict (see `file review`); \
             a conflicting author never resolves their own collision"
        )));
    }
    let secret = signing_secret(slot, key_file)?;
    let (identity, at) = (identity_for(conn, as_label)?, utc_instant()?);
    let generation = generation_for(conn, &policy.scope_root)?;
    let new = NewRevision {
        parent_revision_ids: Vec::new(),
        user_label,
        author_identity: Some(identity),
        author_hcp_label: as_label.to_string(),
        created_at_utc: revision_instant()?,
        topology_generation: generation,
        policy_hash: policy.policy_hash()?,
    };
    let id = file
        .resolve_conflict(resolution, new, &policy, &ctx)
        .map_err(|err| match err {
            Error::FileExpired => usage("that side's content was destroyed at expiry"),
            _ => usage("the conflict could not be resolved as asked"),
        })?;
    // The reviewer's decision is their content signature on the result.
    file.sign_revision(&id, identity, as_label, &secret)?;
    file.append(event(
        HistoryEventType::RevisionSigned,
        Some(id),
        &at,
        identity,
        as_label,
        generation,
        EventDetails::new(),
    ))?;
    let state = decide(conn, &mut file, id, &at, identity, as_label, generation)?;
    refuse_if_denied(state, as_label)?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!(
        "Resolved {} and {} as {} (revision {})",
        short(&conflict.left),
        short(&conflict.right),
        as_label,
        short(&id)
    );
    outln!("  trust {}", trust_text(state));
    Ok(())
}

fn reject_merge(
    conn: &Connection,
    kqtf: &Path,
    as_label: &str,
    (slot, key_file): (Option<String>, Option<PathBuf>),
) -> Result<()> {
    let mut file = load_live(conn, kqtf, Some(as_label), "reject")?;
    let policy = policy_of(&file)?.clone();
    require_active(conn, as_label)?;
    let heads = file.graph().heads();
    let [head] = heads.as_slice() else {
        return Err(usage(
            "nothing to reject: the history has no single proposed merge",
        ));
    };
    let head = *head;
    let at = utc_instant()?;
    let secret = prove_possession(conn, &file, "reject", as_label, &at, slot, key_file)?;
    let start = file.events().len();
    let actor = event(
        HistoryEventType::MergeRejected,
        Some(head),
        &at,
        identity_for(conn, as_label)?,
        as_label,
        generation_for(conn, &policy.scope_root)?,
        EventDetails::new(),
    );
    file.reject_merge(&head, actor, &policy, &StoreTrust { conn })
        .map_err(|_| {
            usage(&format!(
                "{as_label} cannot reject {}: only an untrusted merge at the head, \
                 by its reviewer or the scope owner",
                short(&head)
            ))
        })?;
    sign_events_since(conn, &mut file, start, as_label, &secret)?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!("Rejected merge {} as {as_label}", short(&head));
    outln!("  resolve it with `keyquorum file resolve --keep left|right` or `--from FILE`");
    Ok(())
}

fn merge(conn: &Connection, kqtf: &Path, as_label: &str, user_label: Option<String>) -> Result<()> {
    let mut file = load_live(conn, kqtf, Some(as_label), "merge")?;
    let policy = policy_of(&file)?.clone();
    if !policy.may_author(as_label) {
        return Err(usage("--as is outside the scope of this file"));
    }
    require_active(conn, as_label)?;
    let heads = file.graph().heads();
    let [left, right] = heads.as_slice() else {
        return Err(usage(&format!(
            "nothing to merge: the history has {} head(s); a merge joins exactly two",
            heads.len()
        )));
    };
    let (left, right) = (*left, *right);
    let identity = identity_for(conn, as_label)?;
    let generation = generation_for(conn, &policy.scope_root)?;
    let new = NewRevision {
        parent_revision_ids: Vec::new(),
        user_label,
        author_identity: Some(identity),
        author_hcp_label: as_label.to_string(),
        created_at_utc: revision_instant()?,
        topology_generation: generation,
        policy_hash: policy.policy_hash()?,
    };
    let ctx = StoreTrust { conn };
    let result = file.resolve_divergence(&left, &right, policy.auto_merge, new, &policy, &ctx)?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    outln!(
        "Automatic merge: {:?} ({})",
        result.auto.outcome,
        result.auto.reason
    );
    match (result.auto.outcome, result.auto.merge_revision) {
        (AutoMergeOutcome::CleanMerge | AutoMergeOutcome::AlreadyEquivalent, Some(id)) => {
            let state = evaluate_revision_trust(&file, &id, &policy, &ctx)?;
            outln!("  merged revision {}", short(&id));
            outln!("  trust {}", trust_text(state));
            outln!("Review the result, then sign it with `keyquorum file sign`.");
            return open_review_if_interactive(conn, kqtf, as_label);
        }
        _ => match result.selection {
            Some(ResolverSelection::Assigned { reviewer, rule, .. }) => {
                outln!("  a person must resolve this; review assigned to {reviewer} ({rule:?})");
                outln!("  the reviewer runs `keyquorum file resolve --keep left|right` or `--from FILE`");
                return open_review_if_interactive(conn, kqtf, as_label);
            }
            Some(ResolverSelection::Unresolved) => {
                outln!("  a person must resolve this, but no authorized reviewer exists;");
                outln!("  an explicit root or admin decision is required");
                return open_review_if_interactive(conn, kqtf, as_label);
            }
            None => outln!("  nothing to merge: one head already contains the other"),
        },
    }
    Ok(())
}

/// At a terminal, a merge that stopped for a person opens the review there
/// and then; scripts, tests and builds without `tui` keep the printed form.
fn open_review_if_interactive(conn: &Connection, kqtf: &Path, as_label: &str) -> Result<()> {
    if cfg!(all(feature = "tui", not(target_arch = "wasm32"))) && env::interactive() {
        review_interactive(conn, kqtf, (Some(as_label.to_string()), None))
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "tui", not(target_arch = "wasm32")))]
fn review_interactive(
    conn: &Connection,
    kqtf: &Path,
    who: (Option<String>, Option<String>),
) -> Result<()> {
    let view = review_view_of(conn, kqtf)?.ok_or_else(|| {
        usage("nothing to review: the history has neither two heads nor one merge head")
    })?;
    super::review_tui::run(view, who, &mut |action, as_label, slot| {
        review_action(conn, kqtf, action, as_label, slot)
    })
}

#[cfg(not(all(feature = "tui", not(target_arch = "wasm32"))))]
fn review_interactive(
    _conn: &Connection,
    _kqtf: &Path,
    _who: (Option<String>, Option<String>),
) -> Result<()> {
    Err(usage(
        "this build has no interactive review; rebuild with `--features tui`, or use `file review`",
    ))
}

/// The review of the container as it stands now, with its merge status.
#[cfg_attr(
    not(all(feature = "tui", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
fn review_view_of(conn: &Connection, kqtf: &Path) -> Result<Option<ReviewView>> {
    let file = load_live(conn, kqtf, None, "review")?;
    let policy = policy_of(&file)?.clone();
    let Some(mut view) = ReviewView::of(&file) else {
        return Ok(None);
    };
    view.status = merge_status(conn, &file, &policy)?;
    Ok(Some(view))
}

/// Run one action from the interactive review as the label and slot the
/// person gave, through the same commands as the command line (so the
/// reviewer, scope and key checks are theirs), then return the refreshed
/// review.
#[cfg(all(feature = "tui", not(target_arch = "wasm32")))]
fn review_action(
    conn: &Connection,
    kqtf: &Path,
    action: &super::review_view::Action,
    as_label: &str,
    slot: &str,
) -> Result<Option<ReviewView>> {
    use super::review_view::Action;
    let keys = (Some(slot.to_string()), None);
    match action {
        Action::KeepLeft => resolve(conn, kqtf, Resolution::KeepLeft, as_label, keys, None)?,
        Action::KeepRight => resolve(conn, kqtf, Resolution::KeepRight, as_label, keys, None)?,
        Action::Result(text) => resolve(
            conn,
            kqtf,
            Resolution::Edited(text.clone().into_bytes()),
            as_label,
            keys,
            None,
        )?,
        Action::Reject => reject_merge(conn, kqtf, as_label, keys)?,
        Action::Sign => sign(conn, kqtf, None, as_label, Some(slot.to_string()), None)?,
        Action::Finalize => finalize(conn, kqtf, None, as_label, Some(slot.to_string()), None)?,
    }
    review_view_of(conn, kqtf)
}

fn review(conn: &Connection, kqtf: &Path) -> Result<()> {
    let file = load_live(conn, kqtf, None, "review")?;
    let policy = policy_of(&file)?.clone();
    let heads = file.graph().heads();
    let Some(view) = ReviewView::of(&file) else {
        outln!(
            "Nothing to review: the history has {} head(s).",
            heads.len()
        );
        return Ok(());
    };
    outln!("{}", view.title);
    for pane in &view.panes {
        outln!("");
        outln!("CHANGED LINES ({})", pane.heading);
        outln!("  {}", pane.revision);
        if let Some(note) = &pane.note {
            outln!("  ({note})");
        }
        for line in &pane.lines {
            let mark = match line.kind {
                ChangeKind::Removed => '-',
                ChangeKind::Added => '+',
            };
            outln!("  {mark} {:>4} | {}", line.number, line.text);
        }
    }
    outln!("");
    for line in merge_status(conn, &file, &policy)? {
        outln!("{line}");
    }
    Ok(())
}

/// The MERGE and STATUS section of a review: the heads, what the automatic
/// merge would do, and who reviews when it stops. Both the printed and the
/// interactive review show exactly these lines.
fn merge_status(conn: &Connection, file: &TrackedFile, policy: &FilePolicy) -> Result<Vec<String>> {
    let heads = file.graph().heads();
    if let [head] = heads.as_slice() {
        return pending_merge_status(conn, file, policy, head);
    }
    let [left, right] = heads.as_slice() else {
        return Ok(Vec::new());
    };
    let base = match file.graph().merge_base(left, right) {
        MergeBase::Unique(id) => Some(id),
        _ => None,
    };
    let plan = file.plan_auto_merge(left, right, policy.auto_merge)?;
    let mut lines = vec!["MERGE".to_string()];
    if let Some(base) = base {
        lines.push(format!("  base   {}", short(&base)));
    }
    lines.push(format!("  left   {}", short(left)));
    lines.push(format!("  right  {}", short(right)));
    lines.push("STATUS".to_string());
    lines.push(format!("  merge  {:?} ({})", plan.outcome, plan.reason));
    if !matches!(
        plan.outcome,
        AutoMergeOutcome::CleanMerge | AutoMergeOutcome::AlreadyEquivalent
    ) {
        let selection = file.select_resolver(left, right, policy, &StoreTrust { conn })?;
        lines.push(match selection {
            ResolverSelection::Assigned { reviewer, rule, .. } => {
                format!("  review {reviewer} ({rule:?})")
            }
            ResolverSelection::Unresolved => {
                "  review UNRESOLVED (no authorized reviewer)".to_string()
            }
        });
    } else {
        lines.push("  review the result, then `keyquorum file merge` and `file sign`".to_string());
    }
    Ok(lines)
}

/// The MERGE and STATUS lines for a sole head that is a two-parent merge:
/// its parents and where it stands, so a clean merge can be reviewed before
/// it is signed. Empty for any other head.
fn pending_merge_status(
    conn: &Connection,
    file: &TrackedFile,
    policy: &FilePolicy,
    head: &[u8; 32],
) -> Result<Vec<String>> {
    let Some(stored) = file.graph().get(head) else {
        return Ok(Vec::new());
    };
    let [left, right] = stored.revision.parent_revision_ids.as_slice() else {
        return Ok(Vec::new());
    };
    let state = evaluate_revision_trust(file, head, policy, &StoreTrust { conn })?;
    let mut lines = vec![
        "MERGE".to_string(),
        format!("  left   {}", short(left)),
        format!("  right  {}", short(right)),
        format!("  merged {}", short(head)),
        "STATUS".to_string(),
        format!("  trust  {}", trust_text(state)),
    ];
    lines.push(match state {
        TrustState::Trusted => "  merged revision is trusted".to_string(),
        _ => "  review the result, then sign it with `keyquorum file sign`".to_string(),
    });
    Ok(lines)
}

fn graph(conn: &Connection, kqtf: &Path) -> Result<()> {
    let file = load(kqtf)?;
    let policy = policy_of(&file)?;
    let ctx = StoreTrust { conn };
    let heads = file.graph().heads();
    for stored in file.revisions() {
        let revision = &stored.revision;
        let id = revision.revision_id;
        let mark = if heads.contains(&id) { "*" } else { " " };
        let parents = if revision.parent_revision_ids.is_empty() {
            "root".to_string()
        } else {
            revision
                .parent_revision_ids
                .iter()
                .map(short)
                .collect::<Vec<_>>()
                .join(" + ")
        };
        // The user label first when there is one, then the generated label
        // and the short hash; the full id stays authoritative.
        match &revision.user_label {
            Some(user) => {
                outln!("{mark} {user}");
                outln!("    {} {}", revision.generated_label, short(&id));
            }
            None => outln!("{mark} {} {}", revision.generated_label, short(&id)),
        }
        outln!(
            "    by {} · parents {parents} · {}",
            revision.author_hcp_label,
            trust_text(evaluate_revision_trust(&file, &id, policy, &ctx)?)
        );
    }
    if heads.len() > 1 {
        outln!("FORK: {} heads (*); none is overwritten", heads.len());
    }
    Ok(())
}

fn diff(conn: &Connection, kqtf: &Path, from: Option<String>, to: Option<String>) -> Result<()> {
    let file = load_live(conn, kqtf, None, "diff")?;
    let to = pick_revision(&file, to.as_deref())?;
    let from = match from {
        Some(prefix) => Some(pick_revision(&file, Some(&prefix))?),
        None => file
            .graph()
            .get(&to)
            .and_then(|stored| stored.revision.parent_revision_ids.first().copied()),
    };
    let old = match &from {
        Some(id) => text_of(&file, id)?,
        None => String::new(),
    };
    let new = text_of(&file, &to)?;
    outln!(
        "{} → {}",
        from.map(|id| short(&id))
            .unwrap_or_else(|| "(empty)".into()),
        short(&to)
    );
    print_changes(&old, &new)
}

fn checkout(
    conn: &Connection,
    kqtf: &Path,
    out: &Path,
    revision: Option<String>,
    shareable: bool,
    record: Option<Option<&str>>,
) -> Result<()> {
    let file = load_live(conn, kqtf, record.flatten(), "checkout")?;
    let id = if shareable {
        let policy = policy_of(&file)?;
        let head = pick_revision(&file, None)?;
        let decision = select_shareable_revision(&file, &head, None, policy, &StoreTrust { conn })?;
        decision
            .delivered_revision
            .ok_or_else(|| usage("no trusted revision exists to share"))?
    } else {
        pick_revision(&file, revision.as_deref())?
    };
    let payload = file
        .graph()
        .get(&id)
        .ok_or_else(|| usage("no such revision"))?
        .content()
        .ok_or_else(|| usage("that revision's content was destroyed at expiry"))?
        .to_vec();
    env::write_new(out, &payload)?;
    outln!(
        "Wrote {} revision {} to {}",
        file.logical_name,
        short(&id),
        out.display()
    );
    if let Some(actor) = record {
        let details =
            EventDetails::new().with("shareable", if shareable { "true" } else { "false" });
        record_access(
            conn,
            kqtf,
            HistoryEventType::RevisionCheckedOut,
            HistoryOutcome::Success,
            Some(id),
            actor,
            details,
        )?;
    }
    Ok(())
}

/// Append one access event (a checkout, a verification run or an export) to
/// the container at `kqtf`. These commands read a file, so recording is
/// opt-in (`--record`), and the event names an actor only when the command
/// was given `--as`; the label is a claim, not a proof, so the event is
/// hash-chained but never attested.
pub(super) fn record_access(
    conn: &Connection,
    kqtf: &Path,
    kind: HistoryEventType,
    outcome: HistoryOutcome,
    revision_id: Option<[u8; 32]>,
    actor: Option<&str>,
    details: EventDetails,
) -> Result<()> {
    let mut file = load(kqtf)?;
    let generation = match file.policy() {
        Some(policy) => Some(generation_for(conn, &policy.scope_root)?),
        None => None,
    };
    file.append(NewEvent {
        revision_id,
        occurred_at: utc_instant()?,
        actor_identity: actor.map(|label| identity_for(conn, label)).transpose()?,
        actor_label: actor.map(str::to_string),
        topology_generation: generation,
        event_type: kind,
        outcome,
        details,
    })?;
    save(kqtf, &file)?;
    index_after(conn, &file);
    Ok(())
}

/// Refresh this file's index rows. The index is only a cache, so a failure
/// is reported but never fails the command that already wrote the file.
pub(super) fn index_after(conn: &Connection, file: &TrackedFile) {
    if let Err(error) = index::record(conn, file) {
        errln!("Warning: could not update the file index: {error}");
    }
}

fn list(conn: &Connection) -> Result<()> {
    let files = index::list(conn)?;
    if files.is_empty() {
        outln!("No tracked files are indexed. (`keyquorum file reindex <file>.kqtf` adds them.)");
    }
    for file in files {
        outln!("{} ({})", file.logical_name, hex::encode(file.file_id));
        outln!(
            "  scope {} · heads {} · events {} · root {}",
            file.scope_root.as_deref().unwrap_or("-"),
            file.head_count,
            file.event_count,
            hex::encode(&file.history_root[..6])
        );
    }
    Ok(())
}

fn reindex(conn: &Connection, paths: &[PathBuf], clear: bool) -> Result<()> {
    // Decoding verifies each container; nothing is indexed unless all pass.
    let files = paths
        .iter()
        .map(|path| load(path))
        .collect::<Result<Vec<_>>>()?;
    if clear {
        index::rebuild(conn, &files)?;
    } else {
        for file in &files {
            index::record(conn, file)?;
        }
    }
    outln!("Indexed {} file(s)", files.len());
    Ok(())
}
