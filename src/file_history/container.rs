//! `KQTF`: the tracked-file container. Layout (all integers big-endian):
//!
//! `magic(4) | version(1) | file_id(16) | lp(logical_name) | history_root(32)
//!  | policy_flag(1) [policy] | revision_count(u32) | revisions… | proof_count(u32) | proofs…
//!  | event_count(u32) | events…`
//!
//! Each revision is its canonical body, its id, and the payload it commits
//! to. Decoding rebuilds the chain and the DAG and refuses a container
//! whose stored `history_root` disagrees, whose revision ids or content
//! commitments do not recompute, or whose events name unknown revisions.
//! Version 2 replaced the single payload of version 1 with revisions;
//! version 3 added revision proofs (signatures) between revisions and events;
//! version 4 added the file's policy after the history root.
//! Version 7 appends `event_proof_count(u32) | event proofs…` after the
//! events; it is written only when an event proof exists.

use super::codec::{bad, take_fixed};
use super::event::{genesis_hash, verify_chain, HistoryEvent, NewEvent};
use super::policy::FilePolicy;
use super::proof::{EventProof, RevisionProof};
use super::revision::{FileRevision, NewRevision, RevisionGraph, StoredRevision};
use super::verify::verify_structure;
use crate::envelope::{push_len_prefixed, take_len_prefixed, take_u32, utf8};
use crate::error::{Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;

pub const CONTAINER_MAGIC: &[u8; 4] = b"KQTF";
/// Version 5 lets a revision's payload be absent (destroyed at expiry).
/// Version 4 containers, where every payload is present, still decode.
/// Version 6 adds the finalization proof kind; versions 4 and 5 never
/// carry one and still decode. Version 7 adds optional event proofs after
/// the events; a container without any is still written as 5 or 6.
pub const CONTAINER_VERSION: u8 = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedFile {
    /// Stable identity, independent of name, path or revision.
    pub file_id: [u8; 16],
    pub logical_name: String,
    /// Read through [`TrackedFile::revisions`]; only this module adds
    /// revisions, so callers cannot rewrite or drop them.
    pub(super) revisions: Vec<StoredRevision>,
    /// Signatures over revisions, read through [`TrackedFile::proofs`] and
    /// added by `sign_revision` / `countersign_revision`; checked against
    /// keys by `policy`.
    pub(super) proofs: Vec<RevisionProof>,
    /// Read through [`TrackedFile::events`]; only this module appends, so
    /// callers cannot rewrite or drop events behind the chain's back.
    pub(super) events: Vec<HistoryEvent>,
    /// Actors' signatures on individual events, read through
    /// [`TrackedFile::event_proofs`] and added by `sign_event`.
    pub(super) event_proofs: Vec<EventProof>,
    /// The rules revisions of this file are judged by; `None` for a file
    /// that has not been given a policy.
    pub(super) policy: Option<FilePolicy>,
}

impl TrackedFile {
    pub fn new(file_id: [u8; 16], logical_name: &str) -> Self {
        Self {
            file_id,
            logical_name: logical_name.to_string(),
            revisions: Vec::new(),
            proofs: Vec::new(),
            events: Vec::new(),
            event_proofs: Vec::new(),
            policy: None,
        }
    }

    /// A new file bound to `policy`.
    pub fn with_policy(file_id: [u8; 16], logical_name: &str, policy: FilePolicy) -> Self {
        let mut file = Self::new(file_id, logical_name);
        file.policy = Some(policy);
        file
    }

    pub fn policy(&self) -> Option<&FilePolicy> {
        self.policy.as_ref()
    }

    pub fn graph(&self) -> RevisionGraph<'_> {
        RevisionGraph::new(&self.revisions)
    }

    pub fn revisions(&self) -> &[StoredRevision] {
        &self.revisions
    }

    pub fn proofs(&self) -> &[RevisionProof] {
        &self.proofs
    }

    pub fn events(&self) -> &[HistoryEvent] {
        &self.events
    }

    /// Record a new revision of `payload` and return its id. The first
    /// revision has no parents; every later one must name existing
    /// revisions (no duplicates), so a second root can never appear. An
    /// identical retry (same parents, content and metadata) yields an id
    /// that already exists and is refused rather than stored twice. This
    /// records content lineage only; trust is decided elsewhere and no
    /// event is appended here.
    pub fn check_in(&mut self, new: NewRevision, payload: Vec<u8>) -> Result<[u8; 32]> {
        if self.is_destroyed() {
            return Err(Error::FileExpired);
        }
        let parents = &new.parent_revision_ids;
        let graph = self.graph();
        let known = parents.iter().all(|parent| graph.get(parent).is_some());
        let distinct = parents
            .iter()
            .enumerate()
            .all(|(i, parent)| !parents[..i].contains(parent));
        if parents.is_empty() != self.revisions.is_empty() || !known || !distinct {
            return Err(Error::InvalidTrackedFile);
        }
        let revision = FileRevision::create(self.file_id, &self.logical_name, &payload, new)?;
        let id = revision.revision_id;
        if self.graph().get(&id).is_some() {
            return Err(Error::InvalidTrackedFile);
        }
        self.revisions.push(StoredRevision {
            revision,
            payload: Some(payload),
        });
        Ok(id)
    }

    /// Last event hash, or the file's genesis hash before any event.
    pub fn history_root(&self) -> [u8; 32] {
        self.events
            .last()
            .map_or_else(|| genesis_hash(&self.file_id), |event| event.event_hash)
    }

    /// Whether this history was once at `root`: the genesis hash, or the
    /// hash of one of its events. Each event hash covers the one before, so
    /// on a verified chain this means the whole history up to `root` is a
    /// prefix of this one.
    pub fn passes_through(&self, root: &[u8; 32]) -> bool {
        *root == genesis_hash(&self.file_id) || self.events.iter().any(|e| e.event_hash == *root)
    }

    /// Append an event: assigns a random event id, the next sequence and
    /// the link to the current root. Existing events are never touched, and
    /// the chain is verified first so a damaged history is not extended.
    pub fn append(&mut self, new: NewEvent) -> Result<&HistoryEvent> {
        verify_chain(&self.file_id, &self.events)?;
        if new.details.unsafe_key().is_some() {
            return Err(Error::InvalidTrackedFile);
        }
        if new
            .revision_id
            .is_some_and(|id| self.graph().get(&id).is_none())
        {
            return Err(Error::InvalidTrackedFile);
        }
        let mut event_id = [0u8; 16];
        OsRng.fill_bytes(&mut event_id);
        let event = HistoryEvent::seal(
            event_id,
            self.events.len() as u64,
            self.file_id,
            self.history_root(),
            new,
        )?;
        self.events.push(event);
        Ok(&self.events[self.events.len() - 1])
    }

    /// Serialize, refusing a history that would not decode again.
    pub fn encode(&self) -> Result<Vec<u8>> {
        verify_structure(self)?;
        self.encode_unchecked()
    }

    /// Serialize without verifying. Kept apart so tests can build the bytes
    /// of a broken file and prove `decode` rejects them.
    pub(super) fn encode_unchecked(&self) -> Result<Vec<u8>> {
        let count = u32::try_from(self.events.len()).map_err(|_| Error::BundleFieldTooLarge)?;
        let mut out = Vec::new();
        out.extend_from_slice(CONTAINER_MAGIC);
        // A container without a finalization stays readable by builds that
        // predate it.
        let finalized = self
            .proofs
            .iter()
            .any(|proof| proof.kind == super::proof::ProofKind::Finalization);
        out.push(match (self.event_proofs.is_empty(), finalized) {
            (false, _) => CONTAINER_VERSION,
            (true, true) => 6,
            (true, false) => 5,
        });
        out.extend_from_slice(&self.file_id);
        push_len_prefixed(&mut out, self.logical_name.as_bytes())?;
        out.extend_from_slice(&self.history_root());
        match &self.policy {
            Some(policy) => {
                out.push(1);
                policy.encode(&mut out)?;
            }
            None => out.push(0),
        }
        let revision_count =
            u32::try_from(self.revisions.len()).map_err(|_| Error::BundleFieldTooLarge)?;
        out.extend_from_slice(&revision_count.to_be_bytes());
        for stored in &self.revisions {
            stored.encode(&mut out)?;
        }
        let proof_count =
            u32::try_from(self.proofs.len()).map_err(|_| Error::BundleFieldTooLarge)?;
        out.extend_from_slice(&proof_count.to_be_bytes());
        for proof in &self.proofs {
            proof.encode(&mut out)?;
        }
        out.extend_from_slice(&count.to_be_bytes());
        for event in &self.events {
            event.encode(&mut out)?;
        }
        if !self.event_proofs.is_empty() {
            let proof_count =
                u32::try_from(self.event_proofs.len()).map_err(|_| Error::BundleFieldTooLarge)?;
            out.extend_from_slice(&proof_count.to_be_bytes());
            for proof in &self.event_proofs {
                proof.encode(&mut out)?;
            }
        }
        Ok(out)
    }

    /// Parse a container and verify its history chain and stored root.
    /// Trailing bytes are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut data = bytes;
        if take_fixed::<4>(&mut data)? != *CONTAINER_MAGIC {
            return Err(Error::InvalidTrackedFile);
        }
        let version = take_fixed::<1>(&mut data)?[0];
        if !(4..=CONTAINER_VERSION).contains(&version) {
            return Err(Error::InvalidTrackedFile);
        }
        let file_id = take_fixed::<16>(&mut data)?;
        let logical_name = bad(take_len_prefixed(&mut data).and_then(utf8))?;
        let stored_root = take_fixed::<32>(&mut data)?;
        let policy = match take_fixed::<1>(&mut data)?[0] {
            0 => None,
            1 => Some(FilePolicy::decode(&mut data)?),
            _ => return Err(Error::InvalidTrackedFile),
        };
        let revision_count = bad(take_u32(&mut data))?;
        let mut revisions = Vec::new();
        for _ in 0..revision_count {
            revisions.push(StoredRevision::decode(&mut data, version)?);
        }
        let proof_count = bad(take_u32(&mut data))?;
        let mut proofs = Vec::new();
        for _ in 0..proof_count {
            proofs.push(RevisionProof::decode(&mut data)?);
        }
        if version < 6
            && proofs
                .iter()
                .any(|proof| proof.kind == super::proof::ProofKind::Finalization)
        {
            return Err(Error::InvalidTrackedFile);
        }
        let count = bad(take_u32(&mut data))?;
        let mut events = Vec::new();
        for _ in 0..count {
            events.push(HistoryEvent::decode(&mut data)?);
        }
        let mut event_proofs = Vec::new();
        if version >= 7 {
            let proof_count = bad(take_u32(&mut data))?;
            // Written only when there is one; an empty list would be a
            // second encoding of the same file.
            if proof_count == 0 {
                return Err(Error::InvalidTrackedFile);
            }
            for _ in 0..proof_count {
                event_proofs.push(EventProof::decode(&mut data)?);
            }
        }
        let file = Self {
            file_id,
            logical_name,
            revisions,
            proofs,
            events,
            event_proofs,
            policy,
        };
        if !data.is_empty() || verify_structure(&file)? != stored_root {
            return Err(Error::InvalidTrackedFile);
        }
        Ok(file)
    }
}
