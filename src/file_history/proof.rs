//! Signatures attached to revisions: the author's content signature and a
//! supervisor's countersignature. This module builds and stores them with
//! the preimages in `signing` and signs through `signing::sign`; checking
//! them against keys and policy happens in `policy`.

use super::codec::{
    push_opt_array, push_str, push_u64, take_fixed, take_opt_array, take_str, take_u64,
};
use super::container::TrackedFile;
use super::event::HistoryEvent;
use super::policy::{BridgeEvidence, TrustContext};
use super::revision::FileRevision;
use crate::error::{Error, Result};
use crate::signing;
use sha2::{Digest, Sha256};

/// Most proofs kept for one (revision, kind, signer label) slot. Proofs are
/// unauthenticated until policy checks them against a key, so an import may
/// carry several competing ones for a slot; this bounds that growth.
pub const MAX_PROOFS_PER_SLOT: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofKind {
    Content = 1,
    Countersignature = 2,
    /// The scope owner or an ancestor marks a trusted revision final.
    Finalization = 3,
}

impl ProofKind {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Content),
            2 => Ok(Self::Countersignature),
            3 => Ok(Self::Finalization),
            _ => Err(Error::InvalidTrackedFile),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionProof {
    pub revision_id: [u8; 32],
    pub kind: ProofKind,
    pub signer_identity: [u8; 16],
    pub signer_label: String,
    /// Countersignatures only: hash of the author signature being backed.
    pub author_signature_hash: Option<[u8; 32]>,
    pub topology_generation: u64,
    pub policy_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl RevisionProof {
    /// True when both proofs occupy the same (revision, kind, label) slot.
    pub(super) fn same_slot(&self, other: &RevisionProof) -> bool {
        self.revision_id == other.revision_id
            && self.kind == other.kind
            && self.signer_label == other.signer_label
    }

    pub fn signature_hash(&self) -> [u8; 32] {
        Sha256::digest(self.signature).into()
    }

    /// The digest this proof's signature covers. A countersignature needs
    /// the revision to name its author.
    pub fn preimage(&self, revision: &FileRevision) -> Result<[u8; 32]> {
        match (
            self.kind,
            self.author_signature_hash,
            revision.author_identity,
        ) {
            (ProofKind::Content, None, _) => Ok(signing::file_revision_preimage(
                &revision.file_id,
                &revision.revision_id,
                &revision.content_commitment,
                &self.signer_identity,
                self.topology_generation,
                &self.policy_hash,
            )),
            (ProofKind::Countersignature, Some(author_hash), Some(author)) => {
                signing::file_countersign_preimage(
                    &revision.file_id,
                    &revision.revision_id,
                    &author,
                    &author_hash,
                    &self.signer_identity,
                    &self.signer_label,
                    self.topology_generation,
                    &self.policy_hash,
                )
            }
            (ProofKind::Finalization, None, _) => signing::file_finalize_preimage(
                &revision.file_id,
                &revision.revision_id,
                &self.signer_identity,
                &self.signer_label,
                self.topology_generation,
                &self.policy_hash,
            ),
            _ => Err(Error::InvalidTrackedFile),
        }
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.revision_id);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.signer_identity);
        push_str(out, &self.signer_label)?;
        push_opt_array(out, self.author_signature_hash.as_ref());
        push_u64(out, self.topology_generation);
        out.extend_from_slice(&self.policy_hash);
        out.extend_from_slice(&self.signature);
        Ok(())
    }

    pub(super) fn decode(data: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            revision_id: take_fixed::<32>(data)?,
            kind: ProofKind::from_u8(take_fixed::<1>(data)?[0])?,
            signer_identity: take_fixed::<16>(data)?,
            signer_label: take_str(data)?,
            author_signature_hash: take_opt_array::<32>(data)?,
            topology_generation: take_u64(data)?,
            policy_hash: take_fixed::<32>(data)?,
            signature: take_fixed::<64>(data)?,
        })
    }
}

/// An event's own actor signing its place in the chain
/// (`signing::file_history_event_preimage`: the file, the event's revision,
/// its sequence, the previous hash and its own hash). Optional: only events
/// whose command already made the actor prove the key carry one. Unsigned
/// events stay hash-chained and are never read as attested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventProof {
    pub sequence: u64,
    pub signer_identity: [u8; 16],
    pub signer_label: String,
    pub signature: [u8; 64],
}

impl EventProof {
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        push_u64(out, self.sequence);
        out.extend_from_slice(&self.signer_identity);
        push_str(out, &self.signer_label)?;
        out.extend_from_slice(&self.signature);
        Ok(())
    }

    pub(super) fn decode(data: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            sequence: take_u64(data)?,
            signer_identity: take_fixed::<16>(data)?,
            signer_label: take_str(data)?,
            signature: take_fixed::<64>(data)?,
        })
    }
}

/// The digest an event proof signs, for the event it names.
pub(super) fn event_preimage(file_id: &[u8; 16], event: &HistoryEvent) -> [u8; 32] {
    signing::file_history_event_preimage(
        file_id,
        event.revision_id.as_ref(),
        event.sequence,
        &event.previous_event_hash,
        &event.event_hash,
    )
}

impl TrackedFile {
    pub fn event_proofs(&self) -> &[EventProof] {
        &self.event_proofs
    }

    /// Sign event `sequence` as its actor, after its hash is final. Refused
    /// for an event with another actor, or one this signer already signed.
    pub fn sign_event(
        &mut self,
        sequence: u64,
        signer_identity: [u8; 16],
        signer_label: &str,
        secret: &[u8; 32],
    ) -> Result<()> {
        let event = usize::try_from(sequence)
            .ok()
            .and_then(|index| self.events.get(index))
            .ok_or(Error::InvalidTrackedFile)?;
        if event.actor_label.as_deref() != Some(signer_label)
            || event.actor_identity != Some(signer_identity)
            || self
                .event_proofs
                .iter()
                .any(|p| p.sequence == sequence && p.signer_label == signer_label)
        {
            return Err(Error::InvalidTrackedFile);
        }
        let signature = signing::sign(secret, &event_preimage(&self.file_id, event));
        self.event_proofs.push(EventProof {
            sequence,
            signer_identity,
            signer_label: signer_label.to_string(),
            signature,
        });
        Ok(())
    }

    pub fn proofs_for<'a>(
        &'a self,
        revision_id: &'a [u8; 32],
        kind: ProofKind,
    ) -> impl Iterator<Item = &'a RevisionProof> {
        self.proofs
            .iter()
            .filter(move |proof| &proof.revision_id == revision_id && proof.kind == kind)
    }

    /// Add a proof unless the identical one (same slot, same signature)
    /// is already held. A slot holds competing proofs, because an imported
    /// proof cannot be told from a forgery without the signer's key; policy
    /// accepts the slot if any of them verifies. When the slot is full the
    /// oldest proof in it is dropped, so a local signer can always add
    /// their own. Returns false when the proof was already present.
    pub(super) fn add_proof(&mut self, proof: RevisionProof) -> bool {
        if self
            .proofs
            .iter()
            .any(|mine| mine.same_slot(&proof) && mine.signature == proof.signature)
        {
            return false;
        }
        let in_slot = |p: &RevisionProof| p.same_slot(&proof);
        while self.proofs.iter().filter(|p| in_slot(p)).count() >= MAX_PROOFS_PER_SLOT {
            if let Some(oldest) = self.proofs.iter().position(in_slot) {
                self.proofs.remove(oldest);
            }
        }
        self.proofs.push(proof);
        true
    }

    /// Content-sign a revision as its author. The proof binds the
    /// revision's own topology generation and policy hash, so it cannot be
    /// replayed under different ones. The signature is not checked here;
    /// policy evaluation verifies it against the signer's registered key.
    pub fn sign_revision(
        &mut self,
        revision_id: &[u8; 32],
        signer_identity: [u8; 16],
        signer_label: &str,
        secret: &[u8; 32],
    ) -> Result<()> {
        let revision = self
            .graph()
            .get(revision_id)
            .ok_or(Error::InvalidTrackedFile)?;
        let revision = &revision.revision;
        if revision.author_identity != Some(signer_identity)
            || revision.author_hcp_label != signer_label
        {
            return Err(Error::InvalidTrackedFile);
        }
        let mut proof = RevisionProof {
            revision_id: *revision_id,
            kind: ProofKind::Content,
            signer_identity,
            signer_label: signer_label.to_string(),
            author_signature_hash: None,
            topology_generation: revision.topology_generation,
            policy_hash: revision.policy_hash,
            signature: [0; 64],
        };
        proof.signature = signing::sign(secret, &proof.preimage(revision)?);
        // Only an equivalent proof (same signature) blocks; a competing
        // one that does not verify must never keep the author out.
        if self.add_proof(proof) {
            Ok(())
        } else {
            Err(Error::InvalidTrackedFile)
        }
    }

    /// Finalize a revision as `signer_label`. Whether that label may
    /// finalize, whether the revision is trusted, and whether the signature
    /// verifies are policy questions answered by `is_finalized`; this only
    /// signs and stores. Refuses an identical finalization already held.
    pub fn finalize_revision(
        &mut self,
        revision_id: &[u8; 32],
        signer_identity: [u8; 16],
        signer_label: &str,
        secret: &[u8; 32],
    ) -> Result<()> {
        let revision = self
            .graph()
            .get(revision_id)
            .ok_or(Error::InvalidTrackedFile)?;
        let revision = &revision.revision;
        let mut proof = RevisionProof {
            revision_id: *revision_id,
            kind: ProofKind::Finalization,
            signer_identity,
            signer_label: signer_label.to_string(),
            author_signature_hash: None,
            topology_generation: revision.topology_generation,
            policy_hash: revision.policy_hash,
            signature: [0; 64],
        };
        proof.signature = signing::sign(secret, &proof.preimage(revision)?);
        if self.add_proof(proof) {
            Ok(())
        } else {
            Err(Error::InvalidTrackedFile)
        }
    }

    /// Countersign a revision the author has already signed, backing the
    /// first content proof (no keys are consulted; use
    /// `countersign_revision_checked` to back one that verifies). Whether
    /// this signer is an acceptable supervisor is a policy question.
    pub fn countersign_revision(
        &mut self,
        revision_id: &[u8; 32],
        supervisor_identity: [u8; 16],
        supervisor_label: &str,
        secret: &[u8; 32],
    ) -> Result<()> {
        struct NoKeys;
        impl TrustContext for NoKeys {
            fn signing_public(&self, _: &[u8; 16], _: &str) -> Option<[u8; 32]> {
                None
            }
            fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
                BridgeEvidence::None
            }
        }
        self.countersign_revision_checked(
            revision_id,
            supervisor_identity,
            supervisor_label,
            secret,
            &NoKeys,
        )
    }

    /// Like `countersign_revision`, but when the author slot holds several
    /// competing proofs, backs the one that verifies under `ctx` (falling
    /// back to the first when none does or the key is unknown). Refuses
    /// only when an identical countersignature is already present.
    pub fn countersign_revision_checked(
        &mut self,
        revision_id: &[u8; 32],
        supervisor_identity: [u8; 16],
        supervisor_label: &str,
        secret: &[u8; 32],
        ctx: &dyn TrustContext,
    ) -> Result<()> {
        let revision = self
            .graph()
            .get(revision_id)
            .ok_or(Error::InvalidTrackedFile)?;
        let revision = &revision.revision;
        let author_hash = self
            .proofs_for(revision_id, ProofKind::Content)
            .find(|proof| super::policy::proof_verifies(revision, proof, ctx))
            .or_else(|| self.proofs_for(revision_id, ProofKind::Content).next())
            .map(RevisionProof::signature_hash)
            .ok_or(Error::InvalidTrackedFile)?;
        let mut proof = RevisionProof {
            revision_id: *revision_id,
            kind: ProofKind::Countersignature,
            signer_identity: supervisor_identity,
            signer_label: supervisor_label.to_string(),
            author_signature_hash: Some(author_hash),
            topology_generation: revision.topology_generation,
            policy_hash: revision.policy_hash,
            signature: [0; 64],
        };
        proof.signature = signing::sign(secret, &proof.preimage(revision)?);
        if self.add_proof(proof) {
            Ok(())
        } else {
            Err(Error::InvalidTrackedFile)
        }
    }
}
