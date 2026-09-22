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
//! This is not the private-bridge supervisor role. That role is notified
//! and holds no signing key.

use crate::device::{PresentedDevice, UsedLeaf};
use crate::envelope::hash_len_prefixed;
use crate::error::{Error, Result};
use crate::private_bridge::{self, parent_node_label};
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

/// Parent that must countersign a restructure, if the authorizer is not
/// the root. `M` returns `None` and the restructure is effective immediately.
pub fn restructure_countersigner(authorizer_label: &str) -> Option<&str> {
    parent_node_label(authorizer_label)
}

/// Employee reissue a delegated supervisor can finish alone: the subject
/// is a direct descendant and sits below a department label (`M.S.1`).
pub fn is_routine_employee_reissue(authorizer_label: &str, subject_label: &str) -> bool {
    parent_node_label(subject_label) == Some(authorizer_label) && segment_count(subject_label) >= 3
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
