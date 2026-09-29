//! Bringing another copy of the same tracked file's history into this one.
//!
//! Two holders of a file each extend it; when one sends theirs, the other
//! imports it. Revisions and proofs are unioned: nothing existing is
//! rewritten, a fork is kept as two heads rather than resolved by time or
//! by whichever copy arrived last, and the import is refused whole if the
//! incoming copy fails verification or is not the same file under the same
//! policy. Proofs are stored, not trusted: signatures are checked against
//! keys by `policy`, as for any proof.
//!
//! Each copy's event chain is its own hash chain, and two diverged chains
//! cannot be joined into one. The importer records a single
//! `HISTORY_IMPORTED` event (with the source's history root and what was
//! added) in its own chain; the other side's events stay in its own
//! container and can be checked from a `HistorySnapshot`.

use super::container::TrackedFile;
use super::event::{EventDetails, HistoryEventType, HistoryOutcome, NewEvent};
use super::verify::verify_structure;
use crate::error::{Error, Result};

/// How the incoming copy relates to the local one, by revisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryRelation {
    /// Both hold the same revisions.
    Identical,
    /// The local copy already has everything the incoming one has.
    LocalAhead,
    /// The incoming copy has everything local has, and more: a fast-forward.
    RemoteAhead,
    /// Each has revisions the other lacks: the union has more than one head.
    Diverged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryMerge {
    pub relation: HistoryRelation,
    pub revisions_added: usize,
    pub proofs_added: usize,
}

/// Who imported, and when, for the recorded event.
#[derive(Clone, Debug)]
pub struct ImportContext {
    pub actor_identity: Option<[u8; 16]>,
    pub actor_label: String,
    pub occurred_at: String,
    pub topology_generation: u64,
}

impl TrackedFile {
    /// Import `other`'s revisions and proofs into this file. Refused, with
    /// nothing changed, unless both copies verify, name the same file id,
    /// and carry the same policy. Importing what is already here changes
    /// nothing and records nothing.
    pub fn merge_history(
        &mut self,
        other: &TrackedFile,
        context: &ImportContext,
    ) -> Result<HistoryMerge> {
        if self.file_id != other.file_id || self.policy != other.policy {
            return Err(Error::InvalidTrackedFile);
        }
        verify_structure(self)?;
        verify_structure(other)?;
        self.atomically(|file| file.merge_history_steps(other, context))
    }

    fn merge_history_steps(
        &mut self,
        other: &TrackedFile,
        context: &ImportContext,
    ) -> Result<HistoryMerge> {
        let has = |file: &TrackedFile, id: &[u8; 32]| file.graph().get(id).is_some();
        let other_new = other
            .revisions
            .iter()
            .filter(|stored| !has(self, &stored.revision.revision_id))
            .count();
        let local_new = self
            .revisions
            .iter()
            .filter(|stored| !has(other, &stored.revision.revision_id))
            .count();
        let relation = match (local_new, other_new) {
            (0, 0) => HistoryRelation::Identical,
            (_, 0) => HistoryRelation::LocalAhead,
            (0, _) => HistoryRelation::RemoteAhead,
            _ => HistoryRelation::Diverged,
        };

        // `other` is stored parents-first, so each new revision's parents
        // are already here when it is added.
        let mut revisions_added = 0;
        for stored in &other.revisions {
            match self.graph().get(&stored.revision.revision_id) {
                Some(existing) if existing == stored => {}
                Some(_) => return Err(Error::InvalidTrackedFile),
                None => {
                    self.revisions.push(stored.clone());
                    revisions_added += 1;
                }
            }
        }
        let mut proofs_added = 0;
        for proof in &other.proofs {
            let known = self.proofs.iter().any(|mine| {
                mine.revision_id == proof.revision_id
                    && mine.kind == proof.kind
                    && mine.signer_label == proof.signer_label
            });
            if !known {
                self.proofs.push(proof.clone());
                proofs_added += 1;
            }
        }
        verify_structure(self)?;

        if revisions_added > 0 || proofs_added > 0 {
            let details = EventDetails::new()
                .with("from_history_root", &hex::encode(other.history_root()))
                .with("relation", &format!("{relation:?}"))
                .with("revisions_added", &revisions_added.to_string())
                .with("proofs_added", &proofs_added.to_string());
            self.append(NewEvent {
                revision_id: None,
                occurred_at: context.occurred_at.clone(),
                actor_identity: context.actor_identity,
                actor_label: Some(context.actor_label.clone()),
                topology_generation: Some(context.topology_generation),
                event_type: HistoryEventType::HistoryImported,
                outcome: HistoryOutcome::Success,
                details,
            })?;
        }
        Ok(HistoryMerge {
            relation,
            revisions_added,
            proofs_added,
        })
    }
}
