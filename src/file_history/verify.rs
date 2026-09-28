//! Structural verification of a tracked file. Cryptographic proofs
//! (content signatures, countersignatures) are checked by the policy layer
//! through `signing::verify_signature`; nothing here verifies signatures.

use super::container::TrackedFile;
use super::event::verify_chain;
use super::revision::content_commitment;
use crate::error::{Error, Result};

/// Verify the history chain and the revision DAG; returns the history root.
///
/// - every revision id recomputes from its body and belongs to this file;
/// - ids are unique and stored parents-first, so parents always exist and
///   the graph cannot contain a cycle;
/// - only the first revision is a root;
/// - each revision's content commitment matches the payload stored with it;
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
