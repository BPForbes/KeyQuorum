//! Revision trust and shareable-revision selection.
//!
//! A cryptographically valid signature is not the same as a trusted
//! revision: trust also needs the applicable topology relationship and the
//! supervisor or bridge approval the file's policy asks for. This module
//! only composes results other modules own: relationship classification
//! from `authority`, signature checks from `signing::verify_signature`, and
//! bridge evidence supplied by the caller from `private_bridge`. It adds no
//! ancestry, signature or bridge logic of its own.

use super::container::TrackedFile;
use super::proof::{ProofKind, RevisionProof};
use super::revision::FileRevision;
use crate::authority::{self, RevisionAuthority};
use crate::envelope::push_len_prefixed;
use crate::error::{Error, Result};
use crate::signing;
use sha2::{Digest, Sha256};

const POLICY_DOMAIN: &[u8] = b"KQ-FILE-POLICY-v1";

/// What a role must present before its revision is trusted. The wire codes
/// feed `policy_hash`, so they never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Requirement {
    /// The role may not create trusted revisions of this file.
    Forbidden = 0,
    /// The author's own content signature.
    AuthorSign = 1,
    /// Author signature plus a countersignature by the author's direct parent.
    AuthorSignDirectParent = 2,
    /// Author signature plus either bridge authorization or a scope-owner
    /// countersignature.
    AuthorSignBridgeOrOwner = 3,
}

/// Per-file revision policy, anchored at `scope_root`. An unrelated actor
/// is never trusted, whatever the policy says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePolicy {
    pub scope_root: String,
    pub scope_owner: Requirement,
    pub descendants: Requirement,
    pub ancestors: Requirement,
    pub cross_branch: Requirement,
}

impl FilePolicy {
    /// The document's default: owner and ancestors self-sign, descendants
    /// need their direct parent, cross-branch needs a bridge or the owner.
    pub fn standard(scope_root: &str) -> Self {
        Self {
            scope_root: scope_root.to_string(),
            scope_owner: Requirement::AuthorSign,
            descendants: Requirement::AuthorSignDirectParent,
            ancestors: Requirement::AuthorSign,
            cross_branch: Requirement::AuthorSignBridgeOrOwner,
        }
    }

    /// Stored in each revision so later verification knows which rules
    /// applied when it was made.
    pub fn policy_hash(&self) -> Result<[u8; 32]> {
        let mut bytes = Vec::new();
        push_len_prefixed(&mut bytes, self.scope_root.as_bytes())?;
        bytes.extend_from_slice(&[
            self.scope_owner as u8,
            self.descendants as u8,
            self.ancestors as u8,
            self.cross_branch as u8,
        ]);
        let mut hasher = Sha256::new();
        hasher.update(POLICY_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    fn requirement_for(&self, author_label: &str) -> Option<Requirement> {
        match authority::relationship(&self.scope_root, author_label) {
            RevisionAuthority::ScopeOwner => Some(self.scope_owner),
            RevisionAuthority::Descendant { .. } => Some(self.descendants),
            RevisionAuthority::Ancestor { .. } => Some(self.ancestors),
            RevisionAuthority::CrossBranch { .. } => Some(self.cross_branch),
            RevisionAuthority::Unrelated => None,
        }
    }
}

/// Bridge outcome for a revision, as reported by `private_bridge`. A
/// private bridge only reports that policy was satisfied, never who.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeEvidence {
    None,
    NonPrivateAuthorized,
    PrivateAuthorized,
}

/// What policy evaluation needs from the rest of the system.
pub trait TrustContext {
    /// The Ed25519 signing key registered for this identity and label.
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]>;
    fn bridge_evidence(&self, revision_id: &[u8; 32]) -> BridgeEvidence;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustReason {
    PolicyHashMismatch,
    UnrelatedActor,
    RoleForbidden,
    MissingContentSignature,
    GenerationMismatch,
    UnknownSigner,
    InvalidContentSignature,
    MissingCountersignature,
    InvalidCountersignature,
    MissingBridgeOrOwnerApproval,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustState {
    Trusted,
    /// Something required is not there yet; it may still become trusted.
    Pending(TrustReason),
    /// Evidence is present but invalid or the policy forbids it.
    Denied(TrustReason),
}

fn check_signature(
    revision: &FileRevision,
    proof: &RevisionProof,
    ctx: &dyn TrustContext,
) -> Option<bool> {
    let public = ctx.signing_public(&proof.signer_identity, &proof.signer_label)?;
    let ok = proof
        .preimage(revision)
        .and_then(|digest| signing::verify_signature(&public, &digest, &proof.signature))
        .is_ok();
    Some(ok)
}

fn bound_to(revision: &FileRevision, proof: &RevisionProof) -> bool {
    proof.topology_generation == revision.topology_generation
        && proof.policy_hash == revision.policy_hash
}

/// Decide whether `revision_id` is trusted under `policy`. Errors only when
/// the revision is unknown.
pub fn evaluate_revision_trust(
    file: &TrackedFile,
    revision_id: &[u8; 32],
    policy: &FilePolicy,
    ctx: &dyn TrustContext,
) -> Result<TrustState> {
    use TrustReason as R;
    use TrustState::{Denied, Pending, Trusted};
    let revision = &file
        .graph()
        .get(revision_id)
        .ok_or(Error::InvalidTrackedFile)?
        .revision;
    if revision.policy_hash != policy.policy_hash()? {
        return Ok(Denied(R::PolicyHashMismatch));
    }
    let Some(requirement) = policy.requirement_for(&revision.author_hcp_label) else {
        return Ok(Denied(R::UnrelatedActor));
    };
    if requirement == Requirement::Forbidden {
        return Ok(Denied(R::RoleForbidden));
    }

    // Only the author's own content proof counts; a proof from anyone else
    // is ignored rather than allowed to shadow it.
    let Some(content) = file
        .proofs_for(revision_id, ProofKind::Content)
        .find(|proof| {
            proof.signer_label == revision.author_hcp_label
                && Some(proof.signer_identity) == revision.author_identity
        })
    else {
        return Ok(Pending(R::MissingContentSignature));
    };
    if !bound_to(revision, content) {
        return Ok(Denied(R::GenerationMismatch));
    }
    match check_signature(revision, content, ctx) {
        None => return Ok(Denied(R::UnknownSigner)),
        Some(false) => return Ok(Denied(R::InvalidContentSignature)),
        Some(true) => {}
    }

    // Which supervisor label may back this revision, if the role needs one.
    let (supervisor, missing) = match requirement {
        Requirement::AuthorSign | Requirement::Forbidden => return Ok(Trusted),
        Requirement::AuthorSignDirectParent => (
            authority::parent_node_label(&revision.author_hcp_label),
            R::MissingCountersignature,
        ),
        Requirement::AuthorSignBridgeOrOwner => {
            if ctx.bridge_evidence(revision_id) != BridgeEvidence::None {
                return Ok(Trusted);
            }
            (
                Some(policy.scope_root.as_str()),
                R::MissingBridgeOrOwnerApproval,
            )
        }
    };
    let counter = supervisor.and_then(|label| {
        file.proofs_for(revision_id, ProofKind::Countersignature)
            .find(|proof| proof.signer_label == label)
    });
    let Some(counter) = counter else {
        return Ok(Pending(missing));
    };
    if !bound_to(revision, counter) {
        return Ok(Denied(R::GenerationMismatch));
    }
    if counter.author_signature_hash != Some(content.signature_hash()) {
        return Ok(Denied(R::InvalidCountersignature));
    }
    Ok(match check_signature(revision, counter, ctx) {
        None => Denied(R::UnknownSigner),
        Some(false) => Denied(R::InvalidCountersignature),
        Some(true) => Trusted,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryDecisionKind {
    CurrentTrustedRevision,
    LastTrustedRevision,
    RequesterAlreadyCurrent,
    DeniedNoTrustedRevision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryDecision {
    pub candidate_revision: [u8; 32],
    /// `None` when nothing trusted exists to deliver.
    pub delivered_revision: Option<[u8; 32]>,
    pub decision: DeliveryDecisionKind,
}

/// Newer is not trusted. Deliver `candidate` if trusted; otherwise the most
/// recently stored trusted ancestor of it; otherwise nothing. When the
/// requester already holds the revision that would be delivered, say so.
pub fn select_shareable_revision(
    file: &TrackedFile,
    candidate: &[u8; 32],
    requester_has: Option<&[u8; 32]>,
    policy: &FilePolicy,
    ctx: &dyn TrustContext,
) -> Result<DeliveryDecision> {
    let graph = file.graph();
    graph.get(candidate).ok_or(Error::InvalidTrackedFile)?;
    let is_trusted = |id: &[u8; 32]| {
        matches!(
            evaluate_revision_trust(file, id, policy, ctx),
            Ok(TrustState::Trusted)
        )
    };
    let (delivered, kind) = if is_trusted(candidate) {
        (
            Some(*candidate),
            DeliveryDecisionKind::CurrentTrustedRevision,
        )
    } else {
        let fallback = file
            .revisions
            .iter()
            .rev()
            .map(|stored| stored.revision.revision_id)
            .find(|id| {
                id != candidate && graph.is_ancestor_or_self(id, candidate) && is_trusted(id)
            });
        match fallback {
            Some(id) => (Some(id), DeliveryDecisionKind::LastTrustedRevision),
            None => (None, DeliveryDecisionKind::DeniedNoTrustedRevision),
        }
    };
    let kind = match (delivered, requester_has) {
        (Some(id), Some(held)) if id == *held => DeliveryDecisionKind::RequesterAlreadyCurrent,
        _ => kind,
    };
    Ok(DeliveryDecision {
        candidate_revision: *candidate,
        delivered_revision: delivered,
        decision: kind,
    })
}
