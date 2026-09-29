//! Delegated authority over dotted labels.
//!
//! `M` is final authority. A label with a parent, such as `M.S`, can
//! finish routine work on its own: reissuing a direct descendant employee's
//! token stays a single ancestor signature. Restructuring the tree does
//! not. That proposal is effective only after the parent countersigns.
//!
//! Unlock approval is separate and opt-in. `unlock_approval = parent`
//! means a leaf share is not enough; the leaf's direct parent must sign
//! the unlock. The default is Shamir plus the physical-device count.
//!
//! This module also owns the one dotted-label topology algorithm
//! ([`parent_node_label`], [`is_ancestor_or_self`], [`ancestry_distance`],
//! [`relationship`], [`lowest_common_ancestor`], [`direct_parent`]).
//! `private_bridge` re-exports the first two for its callers.
//!
//! This is not the private-bridge supervisor role. That role is notified
//! and holds no signing key.

use crate::device::{PresentedDevice, UsedLeaf};
use crate::envelope::hash_len_prefixed;
use crate::error::{Error, Result};
use crate::private_bridge;
use crate::signing;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const UNLOCK_DOMAIN: &[u8] = b"KQ-UNLOCK-APPROVAL-v1";

/// Signature presented at unlock time for one leaf.
#[derive(Clone, Debug)]
pub struct UnlockGrant {
    pub leaf_label: String,
    pub countersigner_label: String,
    pub signature: [u8; 64],
}

/// Direct parent in the dotted tree: `M.S.2` → `M.S`, `M.S` → `M`.
pub fn parent_node_label(label: &str) -> Option<&str> {
    label.rsplit_once('.').map(|(parent, _)| parent)
}

/// `M` and `M.S` both have standing over `M.S.2` — ancestor-or-self in
/// the same dotted hierarchy [`parent_node_label`] walks one step at a
/// time; `M.A` and `M.S.3` do not. Segment-wise, so `M.S` never covers
/// `M.SALES.1`. `org_update` uses this to decide who may authorize a
/// hardware-key reissue or key-tree restructure for a label.
pub fn is_ancestor_or_self(authorizer: &str, subject: &str) -> bool {
    if !is_well_formed(authorizer) || !is_well_formed(subject) {
        return false;
    }
    if authorizer == subject {
        return true;
    }
    subject
        .strip_prefix(authorizer)
        .is_some_and(|rest| rest.starts_with('.'))
}

/// True when `parent` is the direct (one-step) parent of `child`.
pub fn direct_parent(parent: &str, child: &str) -> bool {
    parent_node_label(child) == Some(parent)
}

/// Number of steps from `ancestor` down to `descendant`; `Some(0)` for the
/// same label, `None` when `ancestor` does not cover `descendant`.
pub fn ancestry_distance(ancestor: &str, descendant: &str) -> Option<usize> {
    (is_well_formed(ancestor)
        && is_well_formed(descendant)
        && is_ancestor_or_self(ancestor, descendant))
    .then(|| segment_count(descendant) - segment_count(ancestor))
}

/// Deepest label that is ancestor-or-self of both, or `None` when they
/// share no root (or either is empty). The common prefix stops at the first
/// empty segment (`.A`, `M..A`, `M.`), so the result never contains one.
pub fn lowest_common_ancestor(left: &str, right: &str) -> Option<String> {
    if left.is_empty() || right.is_empty() {
        return None;
    }
    let common: Vec<&str> = left
        .split('.')
        .zip(right.split('.'))
        .take_while(|(l, r)| l == r && !l.is_empty())
        .map(|(l, _)| l)
        .collect();
    (!common.is_empty()).then(|| common.join("."))
}

/// How an actor relates to a scope root. An input to revision policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevisionAuthority {
    ScopeOwner,
    /// The actor sits below `ancestor` (the scope root), `depth` steps down.
    Descendant {
        ancestor: String,
        depth: usize,
    },
    /// The actor sits `depth` steps above the scope root.
    Ancestor {
        depth: usize,
    },
    CrossBranch {
        common_ancestor: String,
    },
    /// No shared root, or an empty label.
    Unrelated,
}

/// Classify `actor` against `scope_root`.
pub fn relationship(scope_root: &str, actor: &str) -> RevisionAuthority {
    if !is_well_formed(scope_root) || !is_well_formed(actor) {
        return RevisionAuthority::Unrelated;
    }
    if scope_root == actor {
        return RevisionAuthority::ScopeOwner;
    }
    if let Some(depth) = ancestry_distance(scope_root, actor) {
        return RevisionAuthority::Descendant {
            ancestor: scope_root.to_string(),
            depth,
        };
    }
    if let Some(depth) = ancestry_distance(actor, scope_root) {
        return RevisionAuthority::Ancestor { depth };
    }
    match lowest_common_ancestor(scope_root, actor) {
        Some(common_ancestor) => RevisionAuthority::CrossBranch { common_ancestor },
        None => RevisionAuthority::Unrelated,
    }
}

/// Parent that must countersign a restructure, if the authorizer is not
/// the root. `M` returns `None` and the restructure is effective immediately.
pub fn restructure_countersigner(authorizer_label: &str) -> Option<&str> {
    parent_node_label(authorizer_label)
}

/// Employee reissue a delegated supervisor can finish alone: the subject
/// is a direct descendant and sits below a department label (`M.S.1`).
pub fn is_routine_employee_reissue(authorizer_label: &str, subject_label: &str) -> bool {
    direct_parent(authorizer_label, subject_label) && segment_count(subject_label) >= 3
}

/// Check opt-in parent approval. `grants` may be empty when the tree's
/// policy is `none`. Device ids are bound into the preimage so a signature
/// cannot be replayed against a different set of presented devices.
pub fn require_unlock_approval(
    conn: &Connection,
    key_id: i64,
    file_id: i64,
    leaves: &[UsedLeaf],
    devices: &[PresentedDevice],
    grants: &[UnlockGrant],
) -> Result<()> {
    let policy = crate::device::custody_policy(conn, key_id)?;
    if policy.unlock_approval != crate::device::UnlockApproval::Parent {
        return Ok(());
    }
    let mut device_ids: Vec<[u8; 16]> = devices.iter().map(|device| device.device_id).collect();
    device_ids.sort();
    for leaf in leaves {
        let parent = parent_node_label(&leaf.leaf_label).ok_or(Error::UnlockApprovalRequired)?;
        let preimage =
            unlock_approval_preimage(file_id, key_id, &leaf.leaf_label, parent, &device_ids)?;
        let grant = grants
            .iter()
            .find(|grant| {
                grant.leaf_label == leaf.leaf_label && grant.countersigner_label == parent
            })
            .ok_or(Error::UnlockApprovalRequired)?;
        let public = private_bridge::signing_public_for_label(conn, parent)?;
        signing::verify_signature(&public, &preimage, &grant.signature)?;
    }
    Ok(())
}

pub fn unlock_approval_preimage(
    file_id: i64,
    key_id: i64,
    leaf_label: &str,
    countersigner_label: &str,
    device_ids: &[[u8; 16]],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(UNLOCK_DOMAIN);
    hasher.update(file_id.to_be_bytes());
    hasher.update(key_id.to_be_bytes());
    hash_len_prefixed(&mut hasher, leaf_label.as_bytes())?;
    hash_len_prefixed(&mut hasher, countersigner_label.as_bytes())?;
    let count = u16::try_from(device_ids.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    hasher.update(count.to_be_bytes());
    for device_id in device_ids {
        hasher.update(device_id);
    }
    Ok(hasher.finalize().into())
}

/// Non-empty with no empty segment (rejects `.A`, `M..A`, `M.`).
fn is_well_formed(label: &str) -> bool {
    !label.is_empty() && label.split('.').all(|segment| !segment.is_empty())
}

fn segment_count(label: &str) -> usize {
    if label.is_empty() {
        0
    } else {
        label.split('.').count()
    }
}

#[cfg(test)]
#[path = "authority/tests.rs"]
mod tests;
