//! History events and the hash chain over them.
//!
//! `event_hash = SHA-256("KQ-FILE-HISTORY-v1" || canonical_body)`, where the
//! canonical body already carries `previous_event_hash`, so each hash
//! commits to the whole prefix. The chain starts from a per-file genesis
//! hash. Changing any earlier event changes every later hash.

use super::codec::{
    bad, push_opt_array, push_opt_str, push_opt_u64, push_str, push_u64, take_byte, take_fixed,
    take_opt_array, take_opt_str, take_opt_u64, take_str, take_u64,
};
use crate::envelope::{push_len_prefixed, take_len_prefixed};
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

const HISTORY_DOMAIN: &[u8] = b"KQ-FILE-HISTORY-v1";
const GENESIS_DOMAIN: &[u8] = b"KQ-FILE-HISTORY-GENESIS-v1";

/// Kinds of recorded event. The numeric codes are wire format: never
/// renumber, only append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HistoryEventType {
    TrackingStarted = 1,
    EditCheckedIn = 2,
    RevisionSigned = 3,
    CountersignatureAdded = 4,
    PolicyDecision = 5,
    ShareAttempted = 6,
    ShareDelivered = 7,
    FileExpired = 8,
    ContentDestroyed = 9,
    TamperDetected = 10,
    AutoMergeAttempted = 11,
    AutoMergeFastForward = 12,
    AutoMergeEquivalent = 13,
    AutoMergeClean = 14,
    AutoMergeBlocked = 15,
    AutoMergeRequiresHuman = 16,
    HistoryForkDetected = 17,
    ContentConflictDetected = 18,
    ConflictReviewAssigned = 19,
    ConflictReviewEscalated = 20,
    BridgeUsed = 21,
    ConflictUnresolved = 22,
    HistoryImported = 23,
    QuorumUnlockAttempted = 24,
    PasswordUnlockAttempted = 25,
    ExpiredAccessAttempt = 26,
    GateLinked = 27,
    ShareLinkCreated = 28,
    ShareLinkRedeemed = 29,
    ShareLinkRevoked = 30,
    ExpiryScheduled = 31,
    FileRenamed = 32,
    RevisionFinalized = 33,
    ConflictResolved = 34,
    MergeRejected = 35,
    RevisionCheckedOut = 36,
    VerificationRun = 37,
    HistoryExported = 38,
    FileRequested = 39,
    ChangeRequested = 40,
    RequestAnswered = 41,
}

impl HistoryEventType {
    /// Which group of activity this event belongs to, for a reader that
    /// filters a history: `file`, `revision`, `security`, `sharing` or
    /// `conflict`. Presentation only; it is not part of the wire format.
    pub fn category(self) -> &'static str {
        use HistoryEventType as E;
        match self {
            E::TrackingStarted
            | E::HistoryImported
            | E::GateLinked
            | E::FileRenamed
            | E::RevisionCheckedOut
            | E::HistoryExported => "file",
            E::EditCheckedIn
            | E::RevisionFinalized
            | E::RevisionSigned
            | E::CountersignatureAdded
            | E::PolicyDecision
            | E::AutoMergeAttempted
            | E::AutoMergeFastForward
            | E::AutoMergeEquivalent
            | E::AutoMergeClean
            | E::ChangeRequested => "revision",
            E::QuorumUnlockAttempted
            | E::PasswordUnlockAttempted
            | E::FileExpired
            | E::ContentDestroyed
            | E::ExpiredAccessAttempt
            | E::ExpiryScheduled
            | E::TamperDetected
            | E::VerificationRun => "security",
            E::ShareAttempted
            | E::ShareDelivered
            | E::ShareLinkCreated
            | E::ShareLinkRedeemed
            | E::ShareLinkRevoked
            | E::FileRequested
            | E::RequestAnswered => "sharing",
            E::AutoMergeBlocked
            | E::AutoMergeRequiresHuman
            | E::HistoryForkDetected
            | E::ContentConflictDetected
            | E::ConflictReviewAssigned
            | E::ConflictResolved
            | E::MergeRejected
            | E::ConflictReviewEscalated
            | E::BridgeUsed
            | E::ConflictUnresolved => "conflict",
        }
    }

    pub(super) fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::TrackingStarted,
            2 => Self::EditCheckedIn,
            3 => Self::RevisionSigned,
            4 => Self::CountersignatureAdded,
            5 => Self::PolicyDecision,
            6 => Self::ShareAttempted,
            7 => Self::ShareDelivered,
            8 => Self::FileExpired,
            9 => Self::ContentDestroyed,
            10 => Self::TamperDetected,
            11 => Self::AutoMergeAttempted,
            12 => Self::AutoMergeFastForward,
            13 => Self::AutoMergeEquivalent,
            14 => Self::AutoMergeClean,
            15 => Self::AutoMergeBlocked,
            16 => Self::AutoMergeRequiresHuman,
            17 => Self::HistoryForkDetected,
            18 => Self::ContentConflictDetected,
            19 => Self::ConflictReviewAssigned,
            20 => Self::ConflictReviewEscalated,
            21 => Self::BridgeUsed,
            22 => Self::ConflictUnresolved,
            23 => Self::HistoryImported,
            24 => Self::QuorumUnlockAttempted,
            25 => Self::PasswordUnlockAttempted,
            26 => Self::ExpiredAccessAttempt,
            27 => Self::GateLinked,
            28 => Self::ShareLinkCreated,
            29 => Self::ShareLinkRedeemed,
            30 => Self::ShareLinkRevoked,
            31 => Self::ExpiryScheduled,
            32 => Self::FileRenamed,
            33 => Self::RevisionFinalized,
            34 => Self::ConflictResolved,
            35 => Self::MergeRejected,
            36 => Self::RevisionCheckedOut,
            37 => Self::VerificationRun,
            38 => Self::HistoryExported,
            39 => Self::FileRequested,
            40 => Self::ChangeRequested,
            41 => Self::RequestAnswered,
            _ => return Err(Error::InvalidTrackedFile),
        })
    }
}

/// Result of the recorded action. Wire format, append-only like the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HistoryOutcome {
    Success = 1,
    Failure = 2,
    Denied = 3,
    Info = 4,
}

impl HistoryOutcome {
    fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Success,
            2 => Self::Failure,
            3 => Self::Denied,
            4 => Self::Info,
            _ => return Err(Error::InvalidTrackedFile),
        })
    }
}

/// Ordered key/value facts about an event. Order is preserved exactly as
/// given, so the encoding is deterministic. Never put secrets here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventDetails(Vec<(String, String)>);

/// Every detail key a producer in this crate may append. A new producer
/// adds its key here, which is where a reviewer checks that the value it
/// carries is safe to keep: ids, labels, counts, outcomes and policy words,
/// never a share, token, PIN, password, key or plaintext. Appending any
/// other key is refused; histories decoded from elsewhere are not re-judged.
pub const SAFE_DETAIL_KEYS: &[&str] = &[
    "action",
    "answers",
    "approval",
    "approvals",
    "base",
    "base_revision",
    "by",
    "bundle_type",
    "candidate",
    "container_hash",
    "custody",
    "denied",
    "decision",
    "delivery_id",
    "devices",
    "expires_at",
    "fallback_reason",
    "for_actor",
    "freshness",
    "from",
    "from_history_root",
    "gate",
    "gate_file",
    "left",
    "minimum_devices",
    "operation",
    "pending",
    "pin",
    "presented",
    "proofs_added",
    "reason",
    "redeemer",
    "relation",
    "relationship",
    "result",
    "request_id",
    "request_kind",
    "reviewer",
    "revision_a",
    "revision_b",
    "revisions",
    "revisions_added",
    "revisions_destroyed",
    "resolution",
    "right",
    "scope",
    "selection_rule",
    "satisfied_by",
    "share",
    "shareable",
    "shares",
    "state",
    "threshold",
    "to",
    "trust_state",
    "trusted",
];

impl EventDetails {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.0.push((key.to_string(), value.to_string()));
        self
    }

    pub fn entries(&self) -> &[(String, String)] {
        &self.0
    }

    /// The first key not in [`SAFE_DETAIL_KEYS`], if any.
    pub fn unsafe_key(&self) -> Option<&str> {
        self.0
            .iter()
            .map(|(key, _)| key.as_str())
            .find(|key| !SAFE_DETAIL_KEYS.contains(key))
    }
}

/// Caller-supplied part of an event. The container assigns the event id,
/// sequence and hash links when it appends.
#[derive(Clone, Debug)]
pub struct NewEvent {
    pub revision_id: Option<[u8; 32]>,
    pub occurred_at: String,
    pub actor_identity: Option<[u8; 16]>,
    pub actor_label: Option<String>,
    pub topology_generation: Option<u64>,
    pub event_type: HistoryEventType,
    pub outcome: HistoryOutcome,
    pub details: EventDetails,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEvent {
    pub event_id: [u8; 16],
    pub sequence: u64,
    pub file_id: [u8; 16],
    pub revision_id: Option<[u8; 32]>,
    pub previous_event_hash: [u8; 32],
    pub event_hash: [u8; 32],
    pub occurred_at: String,
    pub actor_identity: Option<[u8; 16]>,
    pub actor_label: Option<String>,
    pub topology_generation: Option<u64>,
    pub event_type: HistoryEventType,
    pub outcome: HistoryOutcome,
    pub details: EventDetails,
}

/// Hash every chain for `file_id` starts from; binds the chain to the file.
pub fn genesis_hash(file_id: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_DOMAIN);
    hasher.update(file_id);
    hasher.finalize().into()
}

impl HistoryEvent {
    pub(super) fn seal(
        event_id: [u8; 16],
        sequence: u64,
        file_id: [u8; 16],
        previous_event_hash: [u8; 32],
        new: NewEvent,
    ) -> Result<Self> {
        let mut event = Self {
            event_id,
            sequence,
            file_id,
            revision_id: new.revision_id,
            previous_event_hash,
            event_hash: [0; 32],
            occurred_at: new.occurred_at,
            actor_identity: new.actor_identity,
            actor_label: new.actor_label,
            topology_generation: new.topology_generation,
            event_type: new.event_type,
            outcome: new.outcome,
            details: new.details,
        };
        event.event_hash = event.compute_hash()?;
        Ok(event)
    }

    /// Canonical encoding of every field except `event_hash`.
    fn body(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.event_id);
        push_u64(&mut out, self.sequence);
        out.extend_from_slice(&self.file_id);
        push_opt_array(&mut out, self.revision_id.as_ref());
        out.extend_from_slice(&self.previous_event_hash);
        push_str(&mut out, &self.occurred_at)?;
        push_opt_array(&mut out, self.actor_identity.as_ref());
        push_opt_str(&mut out, self.actor_label.as_deref())?;
        push_opt_u64(&mut out, self.topology_generation);
        out.push(self.event_type as u8);
        out.push(self.outcome as u8);
        let count = u16::try_from(self.details.0.len()).map_err(|_| Error::BundleFieldTooLarge)?;
        out.extend_from_slice(&count.to_be_bytes());
        for (key, value) in &self.details.0 {
            push_len_prefixed(&mut out, key.as_bytes())?;
            push_len_prefixed(&mut out, value.as_bytes())?;
        }
        Ok(out)
    }

    pub fn compute_hash(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(HISTORY_DOMAIN);
        hasher.update(self.body()?);
        Ok(hasher.finalize().into())
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.body()?);
        out.extend_from_slice(&self.event_hash);
        Ok(())
    }

    pub(super) fn decode(data: &mut &[u8]) -> Result<Self> {
        let event_id = take_fixed::<16>(data)?;
        let sequence = take_u64(data)?;
        let file_id = take_fixed::<16>(data)?;
        let revision_id = take_opt_array::<32>(data)?;
        let previous_event_hash = take_fixed::<32>(data)?;
        let occurred_at = take_str(data)?;
        let actor_identity = take_opt_array::<16>(data)?;
        let actor_label = take_opt_str(data)?;
        let topology_generation = take_opt_u64(data)?;
        let event_type = HistoryEventType::from_u8(take_byte(data)?)?;
        let outcome = HistoryOutcome::from_u8(take_byte(data)?)?;
        let count = u16::from_be_bytes(take_fixed::<2>(data)?);
        let mut details = Vec::new();
        for _ in 0..count {
            let key = bad(take_len_prefixed(data).and_then(crate::envelope::utf8))?;
            let value = bad(take_len_prefixed(data).and_then(crate::envelope::utf8))?;
            details.push((key, value));
        }
        let event_hash = take_fixed::<32>(data)?;
        Ok(Self {
            event_id,
            sequence,
            file_id,
            revision_id,
            previous_event_hash,
            event_hash,
            occurred_at,
            actor_identity,
            actor_label,
            topology_generation,
            event_type,
            outcome,
            details: EventDetails(details),
        })
    }
}

/// Check that `events` form an unbroken chain for `file_id` and return the
/// history root (the last event hash, or the genesis hash when empty).
/// Sequences must be `0, 1, 2, …`; every event must name this file, link to
/// the previous hash, and carry a hash that matches its contents.
pub fn verify_chain(file_id: &[u8; 16], events: &[HistoryEvent]) -> Result<[u8; 32]> {
    let mut previous = genesis_hash(file_id);
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64
            || &event.file_id != file_id
            || event.previous_event_hash != previous
            || event.compute_hash()? != event.event_hash
        {
            return Err(Error::InvalidTrackedFile);
        }
        previous = event.event_hash;
    }
    Ok(previous)
}
