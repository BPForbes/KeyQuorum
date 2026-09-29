//! Revision trust and shareable-revision selection.
//!
//! A cryptographically valid signature is not the same as a trusted
//! revision: trust also needs the applicable topology relationship and the
//! supervisor or bridge approval the file's policy asks for. This module
//! only composes results other modules own: relationship classification
//! from `authority`, signature checks from `signing::verify_signature`, and
//! bridge evidence supplied by the caller from `private_bridge`. It adds no
//! ancestry, signature or bridge logic of its own.

use super::codec::{take_fixed, take_str};
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

impl Requirement {
    fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::Forbidden,
            1 => Self::AuthorSign,
            2 => Self::AuthorSignDirectParent,
            3 => Self::AuthorSignBridgeOrOwner,
            _ => return Err(Error::InvalidTrackedFile),
        })
    }
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
    /// Whether two divergent heads may be merged automatically. Off means a
    /// divergence always goes to a person, however clean the merge would be.
    pub auto_merge: bool,
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
            auto_merge: true,
        }
    }

    /// `lp(scope_root) | owner | descendants | ancestors | cross_branch |
    /// auto_merge`: what the container stores and `policy_hash` covers.
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        push_len_prefixed(&mut out, self.scope_root.as_bytes())?;
        out.extend_from_slice(&[
            self.scope_owner as u8,
            self.descendants as u8,
            self.ancestors as u8,
            self.cross_branch as u8,
            u8::from(self.auto_merge),
        ]);
        Ok(out)
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.bytes()?);
        Ok(())
    }

    pub(super) fn decode(data: &mut &[u8]) -> Result<Self> {
        let scope_root = take_str(data)?;
        let [owner, descendants, ancestors, cross_branch, auto_merge] = take_fixed::<5>(data)?;
        Ok(Self {
            scope_root,
            scope_owner: Requirement::from_u8(owner)?,
            descendants: Requirement::from_u8(descendants)?,
            ancestors: Requirement::from_u8(ancestors)?,
            cross_branch: Requirement::from_u8(cross_branch)?,
            auto_merge: match auto_merge {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidTrackedFile),
            },
        })
    }

    /// Stored in each revision so later verification knows which rules
    /// applied when it was made.
    pub fn policy_hash(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_DOMAIN);
        hasher.update(self.bytes()?);
        Ok(hasher.finalize().into())
    }

    /// Whether `label` may create or review revisions of this file at all:
    /// related to the scope and not in a forbidden role.
    pub fn may_author(&self, label: &str) -> bool {
        self.requirement_for(label)
            .is_some_and(|requirement| requirement != Requirement::Forbidden)
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

    /// Whether an authorized bridge connects the branches of `from` and `to`
    /// (labels). This is about the review path between two branches, not
    /// about a revision's authorization; the default reports none.
    fn bridge_between(&self, _from: &str, _to: &str) -> BridgeEvidence {
        BridgeEvidence::None
    }
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

/// Whether `proof` is bound to `revision` and its signature verifies under
/// a key `ctx` knows. Unknown keys and bad signatures both read as false.
pub(super) fn proof_verifies(
    revision: &FileRevision,
    proof: &RevisionProof,
    ctx: &dyn TrustContext,
) -> bool {
    bound_to(revision, proof) && check_signature(revision, proof, ctx) == Some(true)
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

    // Only the author's own content proofs count; a proof from anyone else
    // is ignored rather than allowed to shadow it. A slot may hold several
    // competing proofs (an import can carry one that does not verify); the
    // revision stands if any of them does.
    let mut candidates = file
        .proofs_for(revision_id, ProofKind::Content)
        .filter(|proof| {
            proof.signer_label == revision.author_hcp_label
                && Some(proof.signer_identity) == revision.author_identity
        });
    let Some(first) = candidates.next() else {
        return Ok(Pending(R::MissingContentSignature));
    };
    let content = std::iter::once(first)
        .chain(candidates)
        .find(|proof| proof_verifies(revision, proof, ctx));
    let Some(content) = content else {
        if !bound_to(revision, first) {
            return Ok(Denied(R::GenerationMismatch));
        }
        return Ok(match check_signature(revision, first, ctx) {
            None => Denied(R::UnknownSigner),
            _ => Denied(R::InvalidContentSignature),
        });
    };

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
    let counters: Vec<&RevisionProof> = supervisor
        .into_iter()
        .flat_map(|label| {
            file.proofs_for(revision_id, ProofKind::Countersignature)
                .filter(move |proof| proof.signer_label == label)
        })
        .collect();
    let Some(&first) = counters.first() else {
        return Ok(Pending(missing));
    };
    let author_hash = content.signature_hash();
    if counters.iter().any(|proof| {
        proof.author_signature_hash == Some(author_hash) && proof_verifies(revision, proof, ctx)
    }) {
        return Ok(Trusted);
    }
    Ok(Denied(if !bound_to(revision, first) {
        R::GenerationMismatch
    } else if first.author_signature_hash != Some(author_hash) {
        R::InvalidCountersignature
    } else if check_signature(revision, first, ctx).is_none() {
        R::UnknownSigner
    } else {
        R::InvalidCountersignature
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryDecisionKind {
    CurrentTrustedRevision,
    LastTrustedRevision,
    RequesterAlreadyCurrent,
    DeniedNoTrustedRevision,
}

impl DeliveryDecisionKind {
    /// The byte a delivery letter carries. Wire format: append-only.
    pub fn code(self) -> u8 {
        match self {
            Self::CurrentTrustedRevision => 1,
            Self::LastTrustedRevision => 2,
            Self::RequesterAlreadyCurrent => 3,
            Self::DeniedNoTrustedRevision => 4,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::CurrentTrustedRevision,
            2 => Self::LastTrustedRevision,
            3 => Self::RequesterAlreadyCurrent,
            4 => Self::DeniedNoTrustedRevision,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryDecision {
    pub candidate_revision: [u8; 32],
    /// `None` when nothing trusted exists to deliver.
    pub delivered_revision: Option<[u8; 32]>,
    pub decision: DeliveryDecisionKind,
}

/// The head the file is at: its only head, or `None` when the history has
/// forked and neither side is "the" current revision.
pub fn current_revision(file: &TrackedFile) -> Option<[u8; 32]> {
    match file.graph().heads().as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// The most recently stored revision that is trusted under `policy`, which
/// need not be the current one: a newer byte sequence is not automatically a
/// newer trusted version. Derived on demand by the store that holds the
/// keys, never stored in the container.
pub fn latest_trusted_revision(
    file: &TrackedFile,
    policy: &FilePolicy,
    ctx: &dyn TrustContext,
) -> Option<[u8; 32]> {
    file.revisions()
        .iter()
        .rev()
        .map(|stored| stored.revision.revision_id)
        .find(|id| {
            matches!(
                evaluate_revision_trust(file, id, policy, ctx),
                Ok(TrustState::Trusted)
            )
        })
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
