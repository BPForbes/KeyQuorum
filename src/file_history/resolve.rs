//! Choosing the human who resolves a conflict the automatic merge could not.
//!
//! Content is never decided here, and seniority never picks a winning line:
//! it only selects who reviews. The rules run in order, and the first that
//! yields exactly one reviewer wins:
//!
//! 1. the most recent prior owner, from the history both heads share, who is
//!    not one of the two conflicting authors;
//! 2. the most senior (shallowest) eligible owner in the file's history;
//! 3. among equally senior owners in different sectors, the one from the
//!    sector with the most owners in the history;
//! 4. the lowest common ancestor of the owners still tied.
//!
//! An "owner" is the author of a revision that is `Trusted` under the file's
//! policy judged on signatures alone (bridge evidence is ignored, so a private
//! bridge can never influence the choice), so it rests on authenticated
//! history rather than on who holds a copy. Current conflicting authors never review their own
//! collision. If nothing qualifies the conflict stays unresolved.

use super::container::TrackedFile;
use super::event::{EventDetails, HistoryEventType, HistoryOutcome, NewEvent};
use super::merge::{AutoMerge, AutoMergeOutcome};
use super::policy::{
    evaluate_revision_trust, BridgeEvidence, FilePolicy, GenerationEvidence, TrustContext,
    TrustState,
};
use super::revision::{HeadRelation, NewRevision};
use crate::authority;
use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionRule {
    PriorNeutralOwner,
    MostSeniorHistoricalOwner,
    DominantSector,
    LowestCommonSeniorAncestor,
}

impl SelectionRule {
    fn name(self) -> &'static str {
        match self {
            Self::PriorNeutralOwner => "PRIOR_NEUTRAL_OWNER",
            Self::MostSeniorHistoricalOwner => "MOST_SENIOR_HISTORICAL_OWNER",
            Self::DominantSector => "DOMINANT_SECTOR",
            Self::LowestCommonSeniorAncestor => "LOWEST_COMMON_SENIOR_ANCESTOR",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolverSelection {
    Assigned {
        reviewer: String,
        rule: SelectionRule,
        /// The owners that were still tied when the rule chose (escalation).
        from: Vec<String>,
    },
    /// No authorized reviewer exists; an explicit root or admin decision is
    /// required. Nothing is guessed.
    Unresolved,
}

/// What `resolve_divergence` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    pub auto: AutoMerge,
    /// Set when the automatic merge stopped and a reviewer was looked for.
    pub selection: Option<ResolverSelection>,
}

/// A view of a trust context that reports no bridge evidence. Owners are
/// judged on signatures and countersignatures, which travel with the file;
/// bridge outcomes (private ones especially) must not decide who reviews.
struct WithoutBridges<'a>(&'a dyn TrustContext);

impl TrustContext for WithoutBridges<'_> {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        self.0.signing_public(identity, label)
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }

    fn generation_evidence(&self, scope_root: &str, generation: u64) -> GenerationEvidence {
        self.0.generation_evidence(scope_root, generation)
    }
}

fn depth(label: &str) -> usize {
    label.split('.').count()
}

/// The branch under the root a label belongs to: `M.A.2` is in sector
/// `M.A`. A root label is its own sector.
fn sector(label: &str) -> String {
    label.split('.').take(2).collect::<Vec<_>>().join(".")
}

fn distinct(labels: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for label in labels {
        if !out.contains(&label) {
            out.push(label);
        }
    }
    out
}

impl TrackedFile {
    /// Pick the reviewer for the conflict between heads `left` and `right`.
    pub fn select_resolver(
        &self,
        left: &[u8; 32],
        right: &[u8; 32],
        policy: &FilePolicy,
        ctx: &dyn TrustContext,
    ) -> Result<ResolverSelection> {
        let graph = self.graph();
        let label_of = |id: &[u8; 32]| {
            graph
                .get(id)
                .map(|stored| stored.revision.author_hcp_label.clone())
                .ok_or(Error::InvalidTrackedFile)
        };
        let conflicting = distinct([label_of(left)?, label_of(right)?]);
        let ctx = &WithoutBridges(ctx);
        let trusted: Vec<(&[u8; 32], &str)> = self
            .revisions
            .iter()
            .map(|stored| {
                (
                    &stored.revision.revision_id,
                    stored.revision.author_hcp_label.as_str(),
                )
            })
            .filter(|(id, _)| {
                matches!(
                    evaluate_revision_trust(self, id, policy, ctx),
                    Ok(TrustState::Trusted)
                )
            })
            .collect();
        let eligible =
            |label: &str| policy.may_author(label) && !conflicting.iter().any(|c| c == label);

        // Rule 1: the most recent trusted author in the shared history who
        // is not one of the conflicting authors.
        let (of_left, of_right) = (graph.ancestor_set(left), graph.ancestor_set(right));
        if let Some((_, label)) = trusted
            .iter()
            .rev()
            .find(|(id, label)| of_left.contains(*id) && of_right.contains(*id) && eligible(label))
        {
            return Ok(ResolverSelection::Assigned {
                reviewer: label.to_string(),
                rule: SelectionRule::PriorNeutralOwner,
                from: Vec::new(),
            });
        }

        // The whole authenticated ownership history, conflicting authors
        // included for the sector tally.
        let history = distinct(
            trusted
                .iter()
                .map(|(_, label)| label.to_string())
                .chain(conflicting.iter().cloned()),
        );
        let candidates: Vec<String> = history.iter().filter(|l| eligible(l)).cloned().collect();
        let Some(shallowest) = candidates.iter().map(|l| depth(l)).min() else {
            return Ok(ResolverSelection::Unresolved);
        };

        // Rule 2: a single most senior owner.
        let mut tied: Vec<String> = candidates
            .into_iter()
            .filter(|l| depth(l) == shallowest)
            .collect();
        if let [only] = tied.as_slice() {
            return Ok(ResolverSelection::Assigned {
                reviewer: only.clone(),
                rule: SelectionRule::MostSeniorHistoricalOwner,
                from: Vec::new(),
            });
        }

        // Rule 3: break the tie by how many owners each sector has.
        let count = |s: &str| history.iter().filter(|l| sector(l) == s).count();
        let sectors = distinct(tied.iter().map(|l| sector(l)));
        let top = sectors.iter().map(|s| count(s)).max().unwrap_or(0);
        let leaders: Vec<&String> = sectors.iter().filter(|s| count(s) == top).collect();
        if let [leader] = leaders.as_slice() {
            tied.retain(|l| &sector(l) == *leader);
            if let [only] = tied.as_slice() {
                return Ok(ResolverSelection::Assigned {
                    reviewer: only.clone(),
                    rule: SelectionRule::DominantSector,
                    from: Vec::new(),
                });
            }
        }

        // Rule 4: the nearest ancestor of everything still tied.
        let ancestor = tied
            .iter()
            .try_fold(None::<String>, |acc, label| match acc {
                None => Some(Some(label.clone())),
                Some(current) => authority::lowest_common_ancestor(&current, label).map(Some),
            })
            .flatten();
        Ok(match ancestor {
            Some(label) if eligible(&label) => ResolverSelection::Assigned {
                reviewer: label,
                rule: SelectionRule::LowestCommonSeniorAncestor,
                from: tied,
            },
            _ => ResolverSelection::Unresolved,
        })
    }

    /// Try the automatic merge; if it stops, record the fork and conflict
    /// and choose the reviewer. The revision graph is never changed by a
    /// conflict, so both heads stay. `new` supplies the actor, time,
    /// generation and (for a clean merge) the new revision's metadata. Either
    /// everything is recorded or, on error, nothing is.
    pub fn resolve_divergence(
        &mut self,
        left: &[u8; 32],
        right: &[u8; 32],
        allowed: bool,
        new: NewRevision,
        policy: &FilePolicy,
        ctx: &dyn TrustContext,
    ) -> Result<Divergence> {
        self.atomically(|file| {
            file.resolve_divergence_steps(left, right, allowed, new, policy, ctx)
        })
    }

    fn resolve_divergence_steps(
        &mut self,
        left: &[u8; 32],
        right: &[u8; 32],
        allowed: bool,
        new: NewRevision,
        policy: &FilePolicy,
        ctx: &dyn TrustContext,
    ) -> Result<Divergence> {
        let actor = (
            new.author_identity,
            new.author_hcp_label.clone(),
            super::revision::whole_seconds(&new.created_at_utc),
            new.topology_generation,
        );
        let auto = self.auto_merge(left, right, allowed, new)?;
        if !matches!(
            auto.outcome,
            AutoMergeOutcome::RequiresHuman
                | AutoMergeOutcome::UnsupportedContent
                | AutoMergeOutcome::PolicyBlocked
        ) {
            return Ok(Divergence {
                auto,
                selection: None,
            });
        }
        // A conflict exists only between heads that really diverged. A failed
        // verification or a disabled policy on related heads records nothing.
        if self.graph().compare(left, right)? != HeadRelation::Diverged {
            return Ok(Divergence {
                auto,
                selection: None,
            });
        }
        let selection = self.select_resolver(left, right, policy, ctx)?;
        let event = |kind, details: EventDetails, outcome| NewEvent {
            revision_id: None,
            occurred_at: actor.2.clone(),
            actor_identity: actor.0,
            actor_label: Some(actor.1.clone()),
            topology_generation: Some(actor.3),
            event_type: kind,
            outcome,
            details,
        };
        let heads = EventDetails::new()
            .with("revision_a", &hex::encode(left))
            .with("revision_b", &hex::encode(right));
        self.append(event(
            HistoryEventType::HistoryForkDetected,
            heads.clone(),
            HistoryOutcome::Info,
        ))?;
        self.append(event(
            HistoryEventType::ContentConflictDetected,
            heads.with("reason", auto.reason),
            HistoryOutcome::Info,
        ))?;
        match &selection {
            ResolverSelection::Assigned {
                reviewer,
                rule,
                from,
            } if *rule == SelectionRule::LowestCommonSeniorAncestor => {
                // Only an authorized non-private bridge between the tied
                // branches is recorded; a private one never appears in
                // portable history, and revision-level bridge evidence says
                // nothing about the review path.
                let bridged = from.iter().enumerate().any(|(i, a)| {
                    from[i + 1..]
                        .iter()
                        .any(|b| ctx.bridge_between(a, b) == BridgeEvidence::NonPrivateAuthorized)
                });
                if bridged {
                    self.append(event(
                        HistoryEventType::BridgeUsed,
                        EventDetails::new()
                            .with("operation", "CONFLICT_ESCALATION")
                            .with("result", "REVIEW_PATH_ESTABLISHED"),
                        HistoryOutcome::Success,
                    ))?;
                }
                self.append(event(
                    HistoryEventType::ConflictReviewEscalated,
                    EventDetails::new()
                        .with("from", &from.join(","))
                        .with("to", reviewer)
                        .with("selection_rule", rule.name()),
                    HistoryOutcome::Success,
                ))?;
            }
            ResolverSelection::Assigned { reviewer, rule, .. } => {
                self.append(event(
                    HistoryEventType::ConflictReviewAssigned,
                    EventDetails::new()
                        .with("reviewer", reviewer)
                        .with("selection_rule", rule.name()),
                    HistoryOutcome::Success,
                ))?;
            }
            ResolverSelection::Unresolved => {
                self.append(event(
                    HistoryEventType::ConflictUnresolved,
                    EventDetails::new().with("reason", "NO_AUTHORIZED_RESOLVER"),
                    HistoryOutcome::Denied,
                ))?;
            }
        }
        Ok(Divergence {
            auto,
            selection: Some(selection),
        })
    }
}

/// How a reviewer settles a conflict the automatic merge left for a person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Take the first conflicting head's content as it is.
    KeepLeft,
    /// Take the second conflicting head's content as it is.
    KeepRight,
    /// Content the reviewer wrote (the merge result, edited).
    Edited(Vec<u8>),
}

impl Resolution {
    fn name(&self) -> &'static str {
        match self {
            Self::KeepLeft => "KEEP_LEFT",
            Self::KeepRight => "KEEP_RIGHT",
            Self::Edited(_) => "EDITED",
        }
    }
}

/// The conflict a reviewer is being asked to settle: the two diverged heads,
/// and the revision a resolution builds on (both heads, or a rejected
/// proposed merge of them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenConflict {
    pub left: [u8; 32],
    pub right: [u8; 32],
    pub parents: Vec<[u8; 32]>,
}

impl TrackedFile {
    /// Whether this container records `revision` as rejected by a reviewer.
    pub fn is_rejected(&self, revision: &[u8; 32]) -> bool {
        self.events().iter().any(|event| {
            event.event_type == HistoryEventType::MergeRejected
                && event.revision_id.as_ref() == Some(revision)
        })
    }

    /// The conflict open on this file: two diverged heads the automatic
    /// merge cannot settle, or a sole head that is a rejected proposed merge
    /// of two heads. `None` when nothing waits for a person.
    pub fn open_conflict(&self, allowed: bool) -> Result<Option<OpenConflict>> {
        let graph = self.graph();
        match graph.heads().as_slice() {
            [left, right] => {
                if graph.compare(left, right)? != HeadRelation::Diverged {
                    return Ok(None);
                }
                let plan = self.plan_auto_merge(left, right, allowed)?;
                Ok(needs_person(plan.outcome).then(|| OpenConflict {
                    left: *left,
                    right: *right,
                    parents: vec![*left, *right],
                }))
            }
            [head] if self.is_rejected(head) => {
                let stored = graph.get(head).ok_or(Error::InvalidTrackedFile)?;
                match stored.revision.parent_revision_ids.as_slice() {
                    [left, right] => Ok(Some(OpenConflict {
                        left: *left,
                        right: *right,
                        parents: vec![*head],
                    })),
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    /// Whether `label` may decide the conflict between `left` and `right`:
    /// the reviewer the rules select, or an ancestor of that reviewer; when
    /// no reviewer qualifies, the scope owner or an ancestor (the explicit
    /// root decision). A conflicting author never decides their own
    /// collision.
    pub fn may_decide(
        &self,
        left: &[u8; 32],
        right: &[u8; 32],
        label: &str,
        policy: &FilePolicy,
        ctx: &dyn TrustContext,
    ) -> Result<bool> {
        let graph = self.graph();
        for id in [left, right] {
            let author = &graph
                .get(id)
                .ok_or(Error::InvalidTrackedFile)?
                .revision
                .author_hcp_label;
            if author == label {
                return Ok(false);
            }
        }
        Ok(match self.select_resolver(left, right, policy, ctx)? {
            ResolverSelection::Assigned { reviewer, .. } => {
                authority::is_ancestor_or_self(label, &reviewer)
            }
            ResolverSelection::Unresolved => {
                authority::is_ancestor_or_self(label, &policy.scope_root)
            }
        })
    }

    /// Settle the open conflict with a new revision whose content is the
    /// chosen head's or the reviewer's own. It has no proofs: the caller
    /// signs it, and the normal trust policy judges it like any revision.
    /// `new` supplies the reviewer as author; its parents are replaced.
    /// Records `CONFLICT_RESOLVED`. Either everything is recorded or nothing.
    pub fn resolve_conflict(
        &mut self,
        resolution: Resolution,
        new: NewRevision,
        policy: &FilePolicy,
        ctx: &dyn TrustContext,
    ) -> Result<[u8; 32]> {
        self.atomically(|file| file.resolve_conflict_steps(resolution, new, policy, ctx))
    }

    fn resolve_conflict_steps(
        &mut self,
        resolution: Resolution,
        mut new: NewRevision,
        policy: &FilePolicy,
        ctx: &dyn TrustContext,
    ) -> Result<[u8; 32]> {
        let conflict = self
            .open_conflict(policy.auto_merge)?
            .ok_or(Error::InvalidTrackedFile)?;
        let reviewer = new.author_hcp_label.clone();
        if !self.may_decide(&conflict.left, &conflict.right, &reviewer, policy, ctx)? {
            return Err(Error::InvalidTrackedFile);
        }
        let content_of = |id: &[u8; 32]| {
            self.graph()
                .get(id)
                .and_then(|stored| stored.payload.clone())
                .ok_or(Error::FileExpired)
        };
        let content = match &resolution {
            Resolution::KeepLeft => content_of(&conflict.left)?,
            Resolution::KeepRight => content_of(&conflict.right)?,
            Resolution::Edited(bytes) => bytes.clone(),
        };
        let (identity, at, generation) = (
            new.author_identity,
            super::revision::whole_seconds(&new.created_at_utc),
            new.topology_generation,
        );
        new.parent_revision_ids = conflict.parents.clone();
        let id = self.check_in(new, content)?;
        self.append(NewEvent {
            revision_id: Some(id),
            occurred_at: at,
            actor_identity: identity,
            actor_label: Some(reviewer.clone()),
            topology_generation: Some(generation),
            event_type: HistoryEventType::ConflictResolved,
            outcome: HistoryOutcome::Success,
            details: EventDetails::new()
                .with("revision_a", &hex::encode(conflict.left))
                .with("revision_b", &hex::encode(conflict.right))
                .with("resolution", resolution.name())
                .with("reviewer", &reviewer)
                .with("trust_state", "PENDING"),
        })?;
        Ok(id)
    }

    /// A reviewer refuses a proposed merge: the sole head, joining two
    /// revisions, and not trusted. The revision stays (nothing is rewritten);
    /// `MERGE_REJECTED` names it, and a resolution then builds on it.
    pub fn reject_merge(
        &mut self,
        merge: &[u8; 32],
        actor: NewEvent,
        policy: &FilePolicy,
        ctx: &dyn TrustContext,
    ) -> Result<()> {
        let graph = self.graph();
        let heads = graph.heads();
        let stored = graph.get(merge).ok_or(Error::InvalidTrackedFile)?;
        let [left, right] = stored.revision.parent_revision_ids.as_slice() else {
            return Err(Error::InvalidTrackedFile);
        };
        let (left, right) = (*left, *right);
        if heads != [*merge]
            || self.is_rejected(merge)
            || evaluate_revision_trust(self, merge, policy, ctx)? == TrustState::Trusted
        {
            return Err(Error::InvalidTrackedFile);
        }
        let label = actor.actor_label.clone().ok_or(Error::InvalidTrackedFile)?;
        let owner = authority::is_ancestor_or_self(&label, &policy.scope_root)
            && !self.authored(&left, &label)?
            && !self.authored(&right, &label)?;
        if !owner && !self.may_decide(&left, &right, &label, policy, ctx)? {
            return Err(Error::InvalidTrackedFile);
        }
        self.append(NewEvent {
            revision_id: Some(*merge),
            event_type: HistoryEventType::MergeRejected,
            outcome: HistoryOutcome::Denied,
            details: EventDetails::new()
                .with("revision_a", &hex::encode(left))
                .with("revision_b", &hex::encode(right))
                .with("reviewer", &label),
            ..actor
        })?;
        Ok(())
    }

    fn authored(&self, id: &[u8; 32], label: &str) -> Result<bool> {
        Ok(self
            .graph()
            .get(id)
            .ok_or(Error::InvalidTrackedFile)?
            .revision
            .author_hcp_label
            == label)
    }
}

fn needs_person(outcome: AutoMergeOutcome) -> bool {
    matches!(
        outcome,
        AutoMergeOutcome::RequiresHuman
            | AutoMergeOutcome::UnsupportedContent
            | AutoMergeOutcome::PolicyBlocked
    )
}
