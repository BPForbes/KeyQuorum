//! Structural verification of a tracked file. Signatures are checked by the
//! policy layer through `signing::verify_signature`, which needs signer
//! keys; nothing here verifies them.

use super::container::TrackedFile;
use super::event::verify_chain;
use super::expiry::destroys_this_content;
use super::proof::{ProofKind, MAX_PROOFS_PER_SLOT};
use super::revision::content_commitment;
use crate::error::{Error, Result};
use std::collections::{HashMap, HashSet};

/// One proof slot: revision, role, signer label.
type SlotKey<'a> = ([u8; 32], u8, &'a str);

/// Verify the history chain and the revision DAG; returns the history root.
///
/// - every revision id recomputes from its body and belongs to this file,
///   and its generated label matches its own timestamp and HCP label;
/// - ids are unique and stored parents-first, so parents always exist and
///   the graph cannot contain a cycle;
/// - only the first revision is a root;
/// - each revision's content commitment matches the payload stored with it;
/// - each proof names a known revision, is well formed for its kind (a
///   content proof must come from the revision's author), and a slot (revision, role, signer label) holds no repeated signature and at most `MAX_PROOFS_PER_SLOT` proofs;
/// - each event's revision (when present) exists;
/// - content is destroyed all at once or not at all: a payload may be
///   absent only when the chain records this container's `CONTENT_DESTROYED`
///   (not a linked gate's, which names its `gate`), and once it
///   does, no payload survives and no revision is added after it.
pub(super) fn verify_structure(file: &TrackedFile) -> Result<[u8; 32]> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for (index, stored) in file.revisions.iter().enumerate() {
        let revision = &stored.revision;
        let parents = &revision.parent_revision_ids;
        let ok = revision.file_id == file.file_id
            && revision.compute_id()? == revision.revision_id
            && revision.generated_label_is_consistent()
            && !seen.contains(&revision.revision_id)
            && parents.iter().all(|parent| seen.contains(parent))
            && parents.iter().collect::<HashSet<_>>().len() == parents.len()
            && (index == 0) == parents.is_empty()
            && stored.payload.as_ref().is_none_or(|payload| {
                revision.content_commitment == content_commitment(&file.file_id, payload)
            });
        if !ok {
            return Err(Error::InvalidTrackedFile);
        }
        seen.insert(revision.revision_id);
    }
    let by_id: HashMap<[u8; 32], usize> = file
        .revisions
        .iter()
        .enumerate()
        .map(|(index, stored)| (stored.revision.revision_id, index))
        .collect();
    // Signatures already seen in each slot (revision, role, signer label).
    let mut slots: HashMap<SlotKey<'_>, Vec<[u8; 64]>> = HashMap::new();
    for proof in &file.proofs {
        let Some(&position) = by_id.get(&proof.revision_id) else {
            return Err(Error::InvalidTrackedFile);
        };
        let stored = &file.revisions[position];
        let revision = &stored.revision;
        let well_formed = match proof.kind {
            // Only the revision's author content-signs it.
            ProofKind::Content => {
                proof.author_signature_hash.is_none()
                    && proof.signer_label == revision.author_hcp_label
                    && Some(proof.signer_identity) == revision.author_identity
            }
            ProofKind::Countersignature => proof.author_signature_hash.is_some(),
            ProofKind::Finalization => proof.author_signature_hash.is_none(),
        };
        // A slot may hold competing proofs (an unverified import must not
        // block the real one), but never the same signature twice and never
        // more than `MAX_PROOFS_PER_SLOT`.
        let earlier = slots
            .entry((
                proof.revision_id,
                proof.kind as u8,
                proof.signer_label.as_str(),
            ))
            .or_default();
        let duplicate = earlier.contains(&proof.signature);
        if !well_formed || duplicate || earlier.len() >= MAX_PROOFS_PER_SLOT {
            return Err(Error::InvalidTrackedFile);
        }
        earlier.push(proof.signature);
    }
    let destroyed = file.events.iter().any(destroys_this_content);
    let any_payload = file.revisions.iter().any(|stored| stored.payload.is_some());
    let all_payloads = file.revisions.iter().all(|stored| stored.payload.is_some());
    if (destroyed && any_payload) || (!destroyed && !all_payloads) {
        return Err(Error::InvalidTrackedFile);
    }
    if file
        .events
        .iter()
        .filter_map(|event| event.revision_id)
        .any(|id| !seen.contains(&id))
    {
        return Err(Error::InvalidTrackedFile);
    }
    verify_chain(&file.file_id, &file.events)
}

/// Verify a tracked file's chain and revision graph.
pub fn verify_tracked_file(file: &TrackedFile) -> Result<[u8; 32]> {
    verify_structure(file)
}
