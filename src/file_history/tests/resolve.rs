use super::*;
use ed25519_dalek::SigningKey;

const KEYS: [(u8, &str); 8] = [
    (1, "M"),
    (2, "M.A"),
    (3, "M.A.1"),
    (4, "M.A.2"),
    (5, "M.S"),
    (6, "M.S.1"),
    (7, "X.1"),
    (8, "M.S.2"),
];

struct Ctx(BridgeEvidence);

impl TrustContext for Ctx {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        KEYS.iter()
            .find(|(n, l)| [*n; 16] == *identity && *l == label)
            .map(|(n, _)| SigningKey::from_bytes(&[*n; 32]).verifying_key().to_bytes())
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        self.0
    }
}

/// Everyone in scope "M" needs only their own signature to be trusted, so
/// a test can make an owner by signing one revision.
fn policy() -> FilePolicy {
    FilePolicy {
        scope_root: "M".into(),
        scope_owner: Requirement::AuthorSign,
        descendants: Requirement::AuthorSign,
        ancestors: Requirement::AuthorSign,
        cross_branch: Requirement::AuthorSign,
    }
}

fn label_id(label: &str) -> u8 {
    KEYS.iter().find(|(_, l)| *l == label).unwrap().0
}

struct Story {
    file: TrackedFile,
    clock: u32,
}

impl Story {
    fn new() -> Self {
        Self {
            file: TrackedFile::new(FILE, "decision.txt"),
            clock: 0,
        }
    }

    fn stamp(&mut self) -> String {
        self.clock += 1;
        format!("2026-10-02T{:02}:00:00Z", self.clock)
    }

    /// A revision by `label`; `signed` decides whether it counts as trusted.
    fn rev(&mut self, parents: &[[u8; 32]], label: &str, text: &str, signed: bool) -> [u8; 32] {
        let at = self.stamp();
        let mut new = new_revision(parents.to_vec(), &at);
        new.author_hcp_label = label.to_string();
        new.author_identity = Some([label_id(label); 16]);
        new.policy_hash = policy().policy_hash().unwrap();
        let id = self.file.check_in(new, text.as_bytes().to_vec()).unwrap();
        if signed {
            self.file
                .sign_revision(&id, [label_id(label); 16], label, &[label_id(label); 32])
                .unwrap();
        }
        id
    }

    /// Two heads that edit the same line differently.
    fn conflict(&mut self, base: [u8; 32], left: &str, right: &str) -> ([u8; 32], [u8; 32]) {
        let l = self.rev(&[base], left, "line: L\n", false);
        let r = self.rev(&[base], right, "line: R\n", false);
        (l, r)
    }

    fn pick(&self, l: &[u8; 32], r: &[u8; 32]) -> ResolverSelection {
        self.file
            .select_resolver(l, r, &policy(), &Ctx(BridgeEvidence::None))
            .unwrap()
    }
}

fn assigned(reviewer: &str, rule: SelectionRule) -> ResolverSelection {
    ResolverSelection::Assigned {
        reviewer: reviewer.into(),
        rule,
        from: Vec::new(),
    }
}

#[test]
fn rule_one_prefers_the_prior_owner_who_is_not_in_the_conflict() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A", "line: base\n", true);
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    assert_eq!(
        s.pick(&l, &r),
        assigned("M.A", SelectionRule::PriorNeutralOwner)
    );
}

#[test]
fn rule_one_takes_the_most_recent_prior_owner() {
    let mut s = Story::new();
    let first = s.rev(&[], "M", "line: base\n", true);
    let second = s.rev(&[first], "M.A", "line: base\n", true);
    let (l, r) = s.conflict(second, "M.A.2", "M.S.1");
    assert_eq!(
        s.pick(&l, &r),
        assigned("M.A", SelectionRule::PriorNeutralOwner)
    );
}

#[test]
fn current_conflicting_authors_never_review_their_own_collision() {
    let mut s = Story::new();
    // The only prior owner is one of the two conflicting authors.
    let base = s.rev(&[], "M.A.2", "line: base\n", true);
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    assert_eq!(s.pick(&l, &r), ResolverSelection::Unresolved);
}

#[test]
fn an_unsigned_or_unrelated_author_is_not_an_owner() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A", "line: base\n", false); // unsigned
    s.rev(&[base], "X.1", "line: x\n", true); // unrelated scope
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    assert_eq!(s.pick(&l, &r), ResolverSelection::Unresolved);
}

#[test]
fn rule_two_takes_the_single_most_senior_owner_elsewhere_in_the_history() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A.2", "line: base\n", true);
    // A trusted revision on a side branch, so M is not in the shared history.
    s.rev(&[base], "M", "line: side\n", true);
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    assert_eq!(
        s.pick(&l, &r),
        assigned("M", SelectionRule::MostSeniorHistoricalOwner)
    );
}

#[test]
fn rule_three_breaks_a_seniority_tie_by_sector_size() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A.2", "line: base\n", true);
    for label in ["M.A", "M.A.1", "M.S"] {
        s.rev(&[base], label, "line: side\n", true);
    }
    // Accounting has M.A, M.A.1, M.A.2; Software has M.S and M.S.1.
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    assert_eq!(
        s.pick(&l, &r),
        assigned("M.A", SelectionRule::DominantSector)
    );
}

#[test]
fn rule_four_escalates_to_the_common_ancestor_when_everything_ties() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A.1", "line: base\n", true);
    for label in ["M.A", "M.S"] {
        s.rev(&[base], label, "line: side\n", true);
    }
    // Two owners per sector, and M.A and M.S are equally senior.
    let (l, r) = s.conflict(base, "M.A.1", "M.S.1");
    let ResolverSelection::Assigned {
        reviewer,
        rule,
        from,
    } = s.pick(&l, &r)
    else {
        panic!("expected an escalation");
    };
    assert_eq!(
        (reviewer.as_str(), rule),
        ("M", SelectionRule::LowestCommonSeniorAncestor)
    );
    assert_eq!(from, vec!["M.A".to_string(), "M.S".to_string()]);
}

#[test]
fn a_tied_sector_with_two_siblings_escalates_to_their_parent() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A.1", "line: base\n", true);
    for label in ["M.S.1", "M.S.2"] {
        s.rev(&[base], label, "line: side\n", true);
    }
    // Candidates are M.S.1 and M.S.2 (one sector, same depth): their parent.
    let (l, r) = s.conflict(base, "M.A.1", "M.A.1");
    let ResolverSelection::Assigned { reviewer, rule, .. } = s.pick(&l, &r) else {
        panic!("expected an escalation");
    };
    assert_eq!(
        (reviewer.as_str(), rule),
        ("M.S", SelectionRule::LowestCommonSeniorAncestor)
    );
}

#[test]
fn the_same_author_on_both_heads_is_one_conflicting_owner() {
    let mut s = Story::new();
    let base = s.rev(&[], "M", "line: base\n", true);
    let (l, r) = s.conflict(base, "M.A.1", "M.A.1");
    assert_eq!(
        s.pick(&l, &r),
        assigned("M", SelectionRule::PriorNeutralOwner)
    );
}

#[test]
fn an_unknown_head_is_an_error() {
    let mut s = Story::new();
    let base = s.rev(&[], "M", "line: base\n", true);
    assert!(s
        .file
        .select_resolver(&base, &[9; 32], &policy(), &Ctx(BridgeEvidence::None))
        .is_err());
}

fn merge_meta(at: &str) -> NewRevision {
    let mut new = new_revision(vec![], at);
    new.policy_hash = policy().policy_hash().unwrap();
    new
}

fn kinds(file: &TrackedFile) -> Vec<HistoryEventType> {
    file.events().iter().map(|e| e.event_type).collect()
}

#[test]
fn a_conflict_is_recorded_and_the_graph_is_left_alone() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A", "line: base\n", true);
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    let revisions = s.file.revisions().len();
    let outcome = s
        .file
        .resolve_divergence(
            &l,
            &r,
            true,
            merge_meta("2026-10-05T00:00:00Z"),
            &policy(),
            &Ctx(BridgeEvidence::None),
        )
        .unwrap();
    assert_eq!(outcome.auto.outcome, AutoMergeOutcome::RequiresHuman);
    assert_eq!(
        outcome.selection,
        Some(assigned("M.A", SelectionRule::PriorNeutralOwner))
    );
    // No revision was created and seniority chose no winning content.
    assert_eq!(s.file.revisions().len(), revisions);
    assert_eq!(s.file.graph().heads().len(), 2);
    assert_eq!(
        kinds(&s.file),
        vec![
            HistoryEventType::AutoMergeAttempted,
            HistoryEventType::AutoMergeRequiresHuman,
            HistoryEventType::HistoryForkDetected,
            HistoryEventType::ContentConflictDetected,
            HistoryEventType::ConflictReviewAssigned,
        ]
    );
    let assigned_event = s.file.events().last().unwrap();
    assert!(assigned_event.details.entries().contains(&(
        "selection_rule".to_string(),
        "PRIOR_NEUTRAL_OWNER".to_string()
    )));
    assert!(assigned_event
        .details
        .entries()
        .contains(&("reviewer".to_string(), "M.A".to_string())));
    assert_eq!(
        TrackedFile::decode(&s.file.encode().unwrap()).unwrap(),
        s.file
    );
}

#[test]
fn a_clean_merge_records_no_conflict() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A", "a\nb\nc\n", true);
    let l = s.rev(&[base], "M.A.2", "A\nb\nc\n", false);
    let r = s.rev(&[base], "M.S.1", "a\nb\nC\n", false);
    let outcome = s
        .file
        .resolve_divergence(
            &l,
            &r,
            true,
            merge_meta("2026-10-05T00:00:00Z"),
            &policy(),
            &Ctx(BridgeEvidence::None),
        )
        .unwrap();
    assert_eq!(outcome.auto.outcome, AutoMergeOutcome::CleanMerge);
    assert_eq!(outcome.selection, None);
    assert!(!kinds(&s.file).contains(&HistoryEventType::HistoryForkDetected));
}

#[test]
fn an_unresolved_conflict_is_recorded_as_such() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A.2", "line: base\n", true);
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    let outcome = s
        .file
        .resolve_divergence(
            &l,
            &r,
            true,
            merge_meta("2026-10-05T00:00:00Z"),
            &policy(),
            &Ctx(BridgeEvidence::None),
        )
        .unwrap();
    assert_eq!(outcome.selection, Some(ResolverSelection::Unresolved));
    assert_eq!(
        kinds(&s.file).last(),
        Some(&HistoryEventType::ConflictUnresolved)
    );
}

#[test]
fn a_disabled_auto_merge_still_finds_a_reviewer() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A", "a\nb\nc\n", true);
    let l = s.rev(&[base], "M.A.2", "A\nb\nc\n", false);
    let r = s.rev(&[base], "M.S.1", "a\nb\nC\n", false);
    let outcome = s
        .file
        .resolve_divergence(
            &l,
            &r,
            false,
            merge_meta("2026-10-05T00:00:00Z"),
            &policy(),
            &Ctx(BridgeEvidence::None),
        )
        .unwrap();
    assert_eq!(outcome.auto.outcome, AutoMergeOutcome::PolicyBlocked);
    assert_eq!(
        outcome.selection,
        Some(assigned("M.A", SelectionRule::PriorNeutralOwner))
    );
}

fn escalation_story() -> (Story, [u8; 32], [u8; 32]) {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A.1", "line: base\n", true);
    for label in ["M.A", "M.S"] {
        s.rev(&[base], label, "line: side\n", true);
    }
    let (l, r) = s.conflict(base, "M.A.1", "M.S.1");
    (s, l, r)
}

#[test]
fn escalation_records_a_non_private_bridge_but_never_a_private_one() {
    let bridged = |evidence| {
        let (mut s, l, r) = escalation_story();
        s.file
            .resolve_divergence(
                &l,
                &r,
                true,
                merge_meta("2026-10-05T00:00:00Z"),
                &policy(),
                &Ctx(evidence),
            )
            .unwrap();
        kinds(&s.file)
    };
    let tail = HistoryEventType::ConflictReviewEscalated;
    let open = bridged(BridgeEvidence::NonPrivateAuthorized);
    assert!(open.contains(&HistoryEventType::BridgeUsed));
    assert_eq!(open.last(), Some(&tail));
    for evidence in [BridgeEvidence::PrivateAuthorized, BridgeEvidence::None] {
        let events = bridged(evidence);
        assert!(!events.contains(&HistoryEventType::BridgeUsed));
        assert_eq!(events.last(), Some(&tail));
    }
}

#[test]
fn a_bridge_never_decides_the_reviewer() {
    let (s, l, r) = escalation_story();
    let with = |evidence| {
        s.file
            .select_resolver(&l, &r, &policy(), &Ctx(evidence))
            .unwrap()
    };
    assert_eq!(
        with(BridgeEvidence::NonPrivateAuthorized),
        with(BridgeEvidence::None)
    );
}

#[test]
fn stale_heads_change_nothing_and_record_nothing() {
    let mut s = Story::new();
    let base = s.rev(&[], "M.A", "line: base\n", true);
    let (l, r) = s.conflict(base, "M.A.2", "M.S.1");
    // Both branches move on, so `l` and `r` are stale.
    s.rev(&[l], "M.A.2", "line: L2\n", false);
    s.rev(&[r], "M.S.1", "line: R2\n", false);
    let (revisions, events) = (s.file.revisions().len(), s.file.events().len());
    let outcome = s.file.resolve_divergence(
        &l,
        &r,
        true,
        merge_meta("2026-10-05T00:00:00Z"),
        &policy(),
        &Ctx(BridgeEvidence::None),
    );
    assert!(outcome.is_err());
    assert_eq!(
        (s.file.revisions().len(), s.file.events().len()),
        (revisions, events)
    );
}
