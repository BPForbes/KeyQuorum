//! Signatures attached to revisions: the author's content signature and a
//! supervisor's countersignature. This module builds and stores them with
//! the preimages in `signing` and signs through `signing::sign`; checking
//! them against keys and policy happens in `policy`.

use super::codec::{
    push_opt_array, push_str, push_u64, take_fixed, take_opt_array, take_str, take_u64,
};
use super::container::TrackedFile;
use super::revision::FileRevision;
use crate::error::{Error, Result};
use crate::signing;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofKind {
    Content = 1,
    Countersignature = 2,
}

impl ProofKind {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Content),
            2 => Ok(Self::Countersignature),
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
                Ok(signing::file_countersign_preimage(
                    &revision.file_id,
                    &revision.revision_id,
                    &author,
                    &author_hash,
                    &self.signer_identity,
                    self.topology_generation,
                    &self.policy_hash,
                ))
            }
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

impl TrackedFile {
    pub fn proofs_for<'a>(
        &'a self,
        revision_id: &'a [u8; 32],
        kind: ProofKind,
    ) -> impl Iterator<Item = &'a RevisionProof> {
        self.proofs
            .iter()
            .filter(move |proof| &proof.revision_id == revision_id && proof.kind == kind)
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
            || self
                .proofs_for(revision_id, ProofKind::Content)
                .next()
                .is_some()
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
        self.proofs.push(proof);
        Ok(())
    }

    /// Countersign a revision the author has already signed. Backs that
    /// exact author signature. Whether this signer is an acceptable
    /// supervisor is a policy question, not decided here.
    pub fn countersign_revision(
        &mut self,
        revision_id: &[u8; 32],
        supervisor_identity: [u8; 16],
        supervisor_label: &str,
        secret: &[u8; 32],
    ) -> Result<()> {
        let revision = self
            .graph()
            .get(revision_id)
            .ok_or(Error::InvalidTrackedFile)?;
        let revision = &revision.revision;
        let author_hash = self
            .proofs_for(revision_id, ProofKind::Content)
            .next()
            .map(RevisionProof::signature_hash)
            .ok_or(Error::InvalidTrackedFile)?;
        if self
            .proofs_for(revision_id, ProofKind::Countersignature)
            .any(|proof| proof.signer_label == supervisor_label)
        {
            return Err(Error::InvalidTrackedFile);
        }
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
        self.proofs.push(proof);
        Ok(())
    }
}
