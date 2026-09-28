//! Structural verification of a tracked file. Signatures are checked by the
//! policy layer through `signing::verify_signature`, which needs signer
//! keys; nothing here verifies them.

use super::container::TrackedFile;
use super::event::verify_chain;
use super::proof::ProofKind;
use super::revision::content_commitment;
use crate::error::{Error, Result};

/// Verify the history chain and the revision DAG; returns the history root.
///
/// - every revision id recomputes from its body and belongs to this file;
/// - ids are unique and stored parents-first, so parents always exist and
///   the graph cannot contain a cycle;
/// - only the first revision is a root;
/// - each revision's content commitment matches the payload stored with it;
/// - each proof names a known revision, is well formed for its kind, and
///   no signer proves the same revision twice in the same role;
/// - each event's revision (when present) exists.
pub(super) fn verify_structure(file: &TrackedFile) -> Result<[u8; 32]> {
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for (index, stored) in file.revisions.iter().enumerate() {
        let revision = &stored.revision;
        let parents = &revision.parent_revision_ids;
        let ok = revision.file_id == file.file_id
            && revision.compute_id()? == revision.revision_id
            && !seen.contains(&revision.revision_id)
            && parents.iter().all(|parent| seen.contains(parent))
            && parents
                .iter()
                .enumerate()
                .all(|(i, parent)| !parents[..i].contains(parent))
            && (index == 0) == parents.is_empty()
            && revision.content_commitment == content_commitment(&file.file_id, &stored.payload);
        if !ok {
            return Err(Error::InvalidTrackedFile);
        }
        seen.push(revision.revision_id);
    }
    for (index, proof) in file.proofs.iter().enumerate() {
        let well_formed = match proof.kind {
            ProofKind::Content => proof.author_signature_hash.is_none(),
            ProofKind::Countersignature => proof.author_signature_hash.is_some(),
        };
        let duplicate = file.proofs[..index].iter().any(|earlier| {
            earlier.revision_id == proof.revision_id
                && earlier.kind == proof.kind
                && earlier.signer_label == proof.signer_label
        });
        if !well_formed || duplicate || !seen.contains(&proof.revision_id) {
            return Err(Error::InvalidTrackedFile);
        }
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
