//! KeyQuorum File History: the tracked-file container (`KQTF`) and its
//! hash-chained event history.
//!
//! The history travels with the tracked file; SQLite may index it but is
//! never the authority. This module only frames and chains events. It does
//! not decide who may do what: signatures go through `signing`, ancestry
//! through `authority`, quorum through `quorum`. The container has its own
//! magic and version because it is not a sealed envelope, so it does not
//! belong in `envelope.rs`; it does reuse that module's length-prefixed
//! codec helpers.
//!
//! History records outcomes, never secrets: no passwords, PINs, KDF output,
//! bearer tokens or key material may be placed in [`EventDetails`].

mod codec;
mod container;
mod event;
pub mod index;
mod merge;
mod policy;
mod proof;
mod resolve;
mod revision;
mod verify;

pub use container::{TrackedFile, CONTAINER_MAGIC, CONTAINER_VERSION};
pub use event::{
    genesis_hash, verify_chain, EventDetails, HistoryEvent, HistoryEventType, HistoryOutcome,
    NewEvent,
};
pub use merge::{diff_text, AutoMerge, AutoMergeOutcome, ChangeKind, LineChange};
pub use policy::{
    evaluate_revision_trust, select_shareable_revision, BridgeEvidence, DeliveryDecision,
    DeliveryDecisionKind, FilePolicy, Requirement, TrustContext, TrustReason, TrustState,
};
pub use proof::{ProofKind, RevisionProof};
pub use resolve::{Divergence, ResolverSelection, SelectionRule};
pub use revision::{
    content_commitment, generated_label, FileRevision, HeadRelation, MergeBase, NewRevision,
    RevisionGraph, StoredRevision,
};
pub use verify::verify_tracked_file;

#[cfg(test)]
mod tests;
