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
    evaluate_revision_trust, BridgeEvidence, FilePolicy, TrustContext, TrustState,
};
use super::revision::NewRevision;
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
        if let Some((_, label)) = trusted.iter().rev().find(|(id, label)| {
            graph.is_ancestor_or_self(id, left)
                && graph.is_ancestor_or_self(id, right)
                && eligible(label)
        }) {
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
            new.created_at_utc.clone(),
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
                // A non-private bridge between the branches may say so; a
                // private one never appears in portable history.
                if [left, right]
                    .iter()
                    .any(|id| ctx.bridge_evidence(id) == BridgeEvidence::NonPrivateAuthorized)
                {
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
