use super::super::merge::{merge_text, TextMerge};
use super::*;
use crate::error::Error;
use crate::file_history::{diff_text, ChangeKind};

fn merged(base: &str, left: &str, right: &str) -> Option<String> {
    match merge_text(base, left, right) {
        TextMerge::Clean(text) => Some(text),
        _ => None,
    }
}

#[test]
fn edits_to_different_lines_combine() {
    // The document's example: 66 and 67 change on different sides.
    let base = "line 65: North\nline 66: 100\nline 67: South\n";
    let left = "line 65: North\nline 66: 125\nline 67: South\n";
    let right = "line 65: North\nline 66: 100\nline 67: South-East\n";
    assert_eq!(
        merged(base, left, right).as_deref(),
        Some("line 65: North\nline 66: 125\nline 67: South-East\n")
    );
    // Order of the two sides does not change a clean result.
    assert_eq!(merged(base, right, left), merged(base, left, right));
}

#[test]
fn a_one_sided_edit_is_taken_and_identical_edits_collapse() {
    let base = "a\nb\nc\n";
    let edited = "a\nB\nc\n";
    assert_eq!(merged(base, base, edited).as_deref(), Some(edited));
    assert_eq!(merged(base, edited, base).as_deref(), Some(edited));
    assert_eq!(merged(base, edited, edited).as_deref(), Some(edited));
}

#[test]
fn overlapping_different_edits_conflict() {
    let base = "a\nb\nc\n";
    assert_eq!(merged(base, "a\nX\nc\n", "a\nY\nc\n"), None);
    // A deletion against an edit of the same line conflicts too.
    assert_eq!(merged(base, "a\nc\n", "a\nB\nc\n"), None);
    // As does an edit over a range the other side rewrote.
    assert_eq!(merged(base, "a\nX\nY\n", "a\nb\nZ\n"), None);
}

#[test]
fn insertions_at_different_points_merge_and_at_one_point_conflict() {
    let base = "a\nb\nc\n";
    assert_eq!(
        merged(base, "top\na\nb\nc\n", "a\nb\nc\nend\n").as_deref(),
        Some("top\na\nb\nc\nend\n")
    );
    assert_eq!(merged(base, "a\nL\nb\nc\n", "a\nR\nb\nc\n"), None);
    assert_eq!(
        merged(base, "a\nsame\nb\nc\n", "a\nsame\nb\nc\n").as_deref(),
        Some("a\nsame\nb\nc\n")
    );
}

#[test]
fn a_deletion_and_a_distant_edit_combine() {
    let base = "a\nb\nc\nd\n";
    assert_eq!(
        merged(base, "b\nc\nd\n", "a\nb\nc\nD\n").as_deref(),
        Some("b\nc\nD\n")
    );
}

#[test]
fn unrelated_bytes_survive_exactly() {
    // CRLF, tabs, trailing spaces and a missing final newline are kept.
    let base = "keep \t\r\nchange\r\nend";
    let left = "keep \t\r\nCHANGED\r\nend";
    let right = "keep \t\r\nchange\r\nend\n";
    assert_eq!(
        merged(base, left, right).as_deref(),
        Some("keep \t\r\nCHANGED\r\nend\n")
    );
    // Appending to the last line without a newline is a change to that line.
    assert_eq!(merged("a\nb", "a\nb!", "a\nb?"), None);
}

#[test]
fn empty_and_growing_bases_work_and_results_are_deterministic() {
    assert_eq!(merged("", "x\n", "").as_deref(), Some("x\n"));
    assert_eq!(merged("", "x\n", "y\n"), None);
    let (b, l, r) = ("1\n2\n3\n4\n5\n", "1\n2\nX\n4\n5\n", "1\nY\n3\n4\n5\nZ\n");
    let first = merged(b, l, r);
    assert_eq!(first.as_deref(), Some("1\nY\nX\n4\n5\nZ\n"));
    assert_eq!(first, merged(b, l, r));
}

#[test]
fn oversized_inputs_are_not_guessed() {
    let base: String = (0..3000).map(|i| format!("base {i}\n")).collect();
    let left: String = (0..3000).map(|i| format!("left {i}\n")).collect();
    let right: String = (0..3000).map(|i| format!("right {i}\n")).collect();
    assert_eq!(merge_text(&base, &left, &right), TextMerge::TooLarge);
}

// ---- graph level ----------------------------------------------------------

fn policy() -> FilePolicy {
    FilePolicy::standard("M.A")
}

fn rev(parents: Vec<[u8; 32]>, at: &str) -> NewRevision {
    let mut new = new_revision(parents, at);
    new.policy_hash = policy().policy_hash().unwrap();
    new
}

struct NoKeys;

impl TrustContext for NoKeys {
    fn signing_public(&self, _: &[u8; 16], _: &str) -> Option<[u8; 32]> {
        None
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }
}

/// base → (left, right), each carrying the given text.
fn fork(base: &[u8], left: &[u8], right: &[u8]) -> (TrackedFile, [u8; 32], [u8; 32], [u8; 32]) {
    let mut file = TrackedFile::new(FILE, "decision.txt");
    let b = file.check_in(rev(vec![], T1), base.to_vec()).unwrap();
    let l = file.check_in(rev(vec![b], T2), left.to_vec()).unwrap();
    let r = file
        .check_in(rev(vec![b], "2026-10-02T15:00:00Z"), right.to_vec())
        .unwrap();
    (file, b, l, r)
}

const MERGE_AT: &str = "2026-10-03T08:00:00Z";

fn kinds(file: &TrackedFile) -> Vec<HistoryEventType> {
    file.events().iter().map(|e| e.event_type).collect()
}

#[test]
fn a_clean_merge_is_a_pending_two_parent_revision() {
    let (mut file, base, left, right) = fork(
        b"North\n100\nSouth\n",
        b"North\n125\nSouth\n",
        b"North\n100\nSouth-East\n",
    );
    let result = file
        .auto_merge(&left, &right, true, rev(vec![], MERGE_AT))
        .unwrap();
    assert_eq!(result.outcome, AutoMergeOutcome::CleanMerge);
    assert_eq!(result.merge_base, Some(base));
    let id = result.merge_revision.unwrap();
    let stored = file.graph().get(&id).unwrap();
    assert_eq!(stored.revision.parent_revision_ids, vec![left, right]);
    assert_eq!(stored.content(), Some(&b"North\n125\nSouth-East\n"[..]));
    assert_eq!(file.graph().heads(), vec![id]);
    // The parents' signatures do not carry over: no proofs, so not trusted.
    assert!(file.proofs().is_empty());
    assert_eq!(
        evaluate_revision_trust(&file, &id, &policy(), &NoKeys).unwrap(),
        TrustState::Pending(TrustReason::MissingContentSignature)
    );
    assert_eq!(
        kinds(&file),
        vec![
            HistoryEventType::AutoMergeAttempted,
            HistoryEventType::AutoMergeClean
        ]
    );
    let done = &file.events()[1];
    assert_eq!(done.revision_id, Some(id));
    assert!(done
        .details
        .entries()
        .contains(&("trust_state".to_string(), "PENDING".to_string())));
    assert_eq!(TrackedFile::decode(&file.encode().unwrap()).unwrap(), file);
}

#[test]
fn a_one_sided_edit_merges_to_the_changed_head() {
    let (mut file, _, left, right) = fork(b"a\nb\n", b"a\nb\n", b"a\nB\n");
    // `left` is byte-identical to the base here, `right` holds the change.
    let result = file
        .auto_merge(&left, &right, true, rev(vec![], MERGE_AT))
        .unwrap();
    assert_eq!(result.outcome, AutoMergeOutcome::CleanMerge);
    assert_eq!(result.content.as_deref(), Some(&b"a\nB\n"[..]));
}

#[test]
fn a_descendant_head_is_a_fast_forward_with_no_new_revision() {
    let mut file = TrackedFile::new(FILE, "a.txt");
    let r1 = file.check_in(rev(vec![], T1), b"1".to_vec()).unwrap();
    let r2 = file.check_in(rev(vec![r1], T2), b"2".to_vec()).unwrap();
    for (a, b) in [(r1, r2), (r2, r1)] {
        let before = file.revisions().len();
        let result = file
            .auto_merge(&a, &b, true, rev(vec![], MERGE_AT))
            .unwrap();
        assert_eq!(result.outcome, AutoMergeOutcome::FastForward);
        assert_eq!(result.content.as_deref(), Some(&b"2"[..]));
        assert_eq!(result.merge_revision, None);
        assert_eq!(file.revisions().len(), before);
    }
    assert_eq!(file.graph().heads(), vec![r2]);
    assert!(kinds(&file).contains(&HistoryEventType::AutoMergeFastForward));
}

#[test]
fn equivalent_heads_collapse_into_one_merge_revision() {
    let (mut file, _, left, right) = fork(b"base", b"same", b"same");
    let result = file
        .auto_merge(&left, &right, true, rev(vec![], MERGE_AT))
        .unwrap();
    assert_eq!(result.outcome, AutoMergeOutcome::AlreadyEquivalent);
    let id = result.merge_revision.unwrap();
    assert_eq!(file.graph().heads(), vec![id]);
    assert_eq!(file.graph().get(&id).unwrap().content(), Some(&b"same"[..]));
    assert!(kinds(&file).contains(&HistoryEventType::AutoMergeEquivalent));
}

#[test]
fn equivalent_content_that_is_not_text_still_collapses() {
    let (mut file, _, left, right) = fork(b"base", &[0xff, 0xfe], &[0xff, 0xfe]);
    let result = file
        .auto_merge(&left, &right, true, rev(vec![], MERGE_AT))
        .unwrap();
    assert_eq!(result.outcome, AutoMergeOutcome::AlreadyEquivalent);
}

#[test]
fn stops_leave_the_revision_graph_alone_and_say_why() {
    type Case = (
        &'static [u8],
        &'static [u8],
        &'static [u8],
        bool,
        AutoMergeOutcome,
        &'static str,
    );
    let cases: [Case; 4] = [
        (
            b"a\nb\n",
            b"a\nL\n",
            b"a\nR\n",
            true,
            AutoMergeOutcome::RequiresHuman,
            "OVERLAPPING_EDIT",
        ),
        (
            b"a\n",
            &[0xff, 0x00],
            b"a\nb\n",
            true,
            AutoMergeOutcome::UnsupportedContent,
            "NOT_UTF8_TEXT",
        ),
        (
            b"a\n",
            b"b\n",
            b"c\n",
            true,
            AutoMergeOutcome::RequiresHuman,
            "OVERLAPPING_EDIT",
        ),
        (
            b"a\nb\n",
            b"a\nL\n",
            b"R\nb\n",
            false,
            AutoMergeOutcome::PolicyBlocked,
            "AUTO_MERGE_DISABLED",
        ),
    ];
    for (base, left, right, allowed, outcome, reason) in cases {
        let (mut file, _, l, r) = fork(base, left, right);
        let result = file
            .auto_merge(&l, &r, allowed, rev(vec![], MERGE_AT))
            .unwrap();
        assert_eq!(result.outcome, outcome, "{reason}");
        assert_eq!(result.reason, reason);
        assert_eq!(result.merge_revision, None);
        assert_eq!(result.content, None);
        assert_eq!(file.revisions().len(), 3, "no revision was added");
        assert_eq!(file.graph().heads().len(), 2, "both heads stay");
        assert_eq!(file.events().len(), 2);
    }
}

#[test]
fn the_merge_base_is_the_nearest_common_ancestor() {
    let mut file = TrackedFile::new(FILE, "a.txt");
    let r1 = file.check_in(rev(vec![], T1), b"1\n".to_vec()).unwrap();
    let r2 = file
        .check_in(rev(vec![r1], T2), b"1\n2\n".to_vec())
        .unwrap();
    let l = file
        .check_in(rev(vec![r2], "2026-10-02T15:00:00Z"), b"L\n2\n".to_vec())
        .unwrap();
    let r = file
        .check_in(rev(vec![r2], "2026-10-02T16:00:00Z"), b"1\n2\nR\n".to_vec())
        .unwrap();
    assert_eq!(file.graph().merge_base(&l, &r), MergeBase::Unique(r2));
    let result = file.plan_auto_merge(&l, &r, true).unwrap();
    assert_eq!(result.merge_base, Some(r2));
    assert_eq!(result.content.as_deref(), Some(&b"L\n2\nR\n"[..]));
}

#[test]
fn a_criss_cross_history_has_no_single_base_and_goes_to_a_human() {
    let mut file = TrackedFile::new(FILE, "a.txt");
    let b = file.check_in(rev(vec![], T1), b"b\n".to_vec()).unwrap();
    let a1 = file.check_in(rev(vec![b], T2), b"a1\n".to_vec()).unwrap();
    let a2 = file
        .check_in(rev(vec![b], "2026-10-02T15:00:00Z"), b"a2\n".to_vec())
        .unwrap();
    let m1 = file
        .check_in(rev(vec![a1, a2], "2026-10-03T01:00:00Z"), b"m1\n".to_vec())
        .unwrap();
    let m2 = file
        .check_in(rev(vec![a2, a1], "2026-10-03T02:00:00Z"), b"m2\n".to_vec())
        .unwrap();
    assert_eq!(file.graph().merge_base(&m1, &m2), MergeBase::Ambiguous);
    let result = file.plan_auto_merge(&m1, &m2, true).unwrap();
    assert_eq!(result.outcome, AutoMergeOutcome::RequiresHuman);
    assert_eq!(result.reason, "AMBIGUOUS_MERGE_BASE");
}

#[test]
fn a_damaged_file_is_not_merged() {
    let (mut file, _, l, r) = fork(b"a\nb\n", b"a\nL\n", b"R\nb\n");
    file.events
        .push(file.events.last().cloned().unwrap_or_else(|| {
            // No events yet: fabricate a broken chain entry instead.
            let mut probe = TrackedFile::new(FILE, "p");
            probe
                .append(new_event(HistoryEventType::TrackingStarted, None))
                .unwrap();
            let mut event = probe.events()[0].clone();
            event.sequence = 5;
            event
        }));
    let result = file.plan_auto_merge(&l, &r, true).unwrap();
    assert_eq!(result.outcome, AutoMergeOutcome::RequiresHuman);
    assert_eq!(result.reason, "VERIFICATION_FAILED");
}

#[test]
fn unknown_heads_are_an_error() {
    let (mut file, _, l, _) = fork(b"a", b"b", b"c");
    assert!(file.plan_auto_merge(&l, &[9; 32], true).is_err());
    assert!(file
        .auto_merge(&[9; 32], &l, true, rev(vec![], MERGE_AT))
        .is_err());
    assert!(file.events().is_empty());
}

#[test]
fn stale_revisions_are_not_merged_while_newer_heads_exist() {
    let (mut file, _, l, r) = fork(b"a\nb\nc\n", b"A\nb\nc\n", b"a\nb\nC\n");
    // Both branches move on, so `l` and `r` are no longer heads.
    let l2 = file
        .check_in(rev(vec![l], "2026-10-04T00:00:00Z"), b"A\nb2\nc\n".to_vec())
        .unwrap();
    let r2 = file
        .check_in(rev(vec![r], "2026-10-04T01:00:00Z"), b"a\nb\nC2\n".to_vec())
        .unwrap();
    let (revisions, events) = (file.revisions().len(), file.events().len());
    assert!(file.plan_auto_merge(&l, &r, true).is_err());
    assert!(file
        .auto_merge(&l, &r, true, rev(vec![], MERGE_AT))
        .is_err());
    assert_eq!(
        (file.revisions().len(), file.events().len()),
        (revisions, events)
    );
    assert_eq!(file.graph().heads(), vec![l2, r2]);
    // The current heads still merge.
    let result = file
        .auto_merge(&l2, &r2, true, rev(vec![], MERGE_AT))
        .unwrap();
    assert_eq!(result.outcome, AutoMergeOutcome::CleanMerge);
    assert_eq!(file.graph().heads().len(), 1);
}

#[test]
fn merge_events_keep_whole_seconds_even_when_the_revision_is_millisecond_stamped() {
    let (mut file, _, left, right) = fork(b"a\nb\nc\n", b"a\nB\nc\n", b"a\nb\nC\n");
    file.auto_merge(&left, &right, true, rev(vec![], "2026-10-03T08:00:00.482Z"))
        .unwrap();
    let merged = file.graph().heads()[0];
    assert!(file
        .graph()
        .get(&merged)
        .unwrap()
        .revision
        .generated_label
        .contains("T080000.482Z"));
    let stamped: Vec<&str> = file
        .events()
        .iter()
        .map(|e| e.occurred_at.as_str())
        .collect();
    assert!(!stamped.is_empty());
    assert!(stamped.iter().all(|at| !at.contains('.')), "{stamped:?}");
}

#[test]
fn a_failed_multi_step_change_leaves_nothing_behind() {
    let (mut file, _, l, r) = fork(b"a\n", b"b\n", b"c\n");
    let (revisions, events) = (file.revisions().len(), file.events().len());
    let outcome: Result<(), _> = file.atomically(|f| {
        f.check_in(rev(vec![l, r], MERGE_AT), b"merged".to_vec())?;
        f.append(new_event(HistoryEventType::AutoMergeClean, None))?;
        Err(Error::InvalidTrackedFile)
    });
    assert!(outcome.is_err());
    assert_eq!(
        (file.revisions().len(), file.events().len()),
        (revisions, events)
    );
    assert_eq!(file.graph().heads().len(), 2);
    // A successful run keeps its work.
    let kept = file
        .atomically(|f| f.check_in(rev(vec![l, r], MERGE_AT), b"merged".to_vec()))
        .unwrap();
    assert_eq!(file.graph().heads(), vec![kept]);
}

#[test]
fn a_disabled_policy_blocks_a_divergence_but_not_a_fast_forward() {
    let mut file = TrackedFile::new(FILE, "a.txt");
    let r1 = file.check_in(rev(vec![], T1), b"1".to_vec()).unwrap();
    let r2 = file.check_in(rev(vec![r1], T2), b"2".to_vec()).unwrap();
    // Equal and ancestor-related heads are not a divergence.
    for (a, b) in [(r1, r2), (r2, r1), (r2, r2)] {
        let result = file.plan_auto_merge(&a, &b, false).unwrap();
        assert_eq!(result.outcome, AutoMergeOutcome::FastForward);
    }
    let (fork_file, _, l, r) = fork(b"a\nb\n", b"a\nL\n", b"R\nb\n");
    let blocked = fork_file.plan_auto_merge(&l, &r, false).unwrap();
    assert_eq!(blocked.outcome, AutoMergeOutcome::PolicyBlocked);
    // Identical content on a divergence still counts as a merge, so it is blocked too.
    let (same, _, sl, sr) = fork(b"base", b"same", b"same");
    let blocked = same.plan_auto_merge(&sl, &sr, false).unwrap();
    assert_eq!(blocked.outcome, AutoMergeOutcome::PolicyBlocked);
}

fn changes(old: &str, new: &str) -> Vec<(ChangeKind, usize, String)> {
    diff_text(old, new)
        .unwrap()
        .into_iter()
        .map(|c| (c.kind, c.line, c.text))
        .collect()
}

#[test]
fn diff_reports_removed_then_added_lines_with_their_positions() {
    use ChangeKind::{Added, Removed};
    assert_eq!(changes("a\nb\nc\n", "a\nb\nc\n"), vec![]);
    assert_eq!(
        changes("a\nb\nc\n", "a\nB\nc\n"),
        vec![(Removed, 2, "b\n".into()), (Added, 2, "B\n".into())]
    );
    // Positions track the shift caused by earlier hunks.
    assert_eq!(
        changes("a\nb\nc\nd\n", "x\ny\na\nb\nc\nD\n"),
        vec![
            (Added, 1, "x\n".into()),
            (Added, 2, "y\n".into()),
            (Removed, 4, "d\n".into()),
            (Added, 6, "D\n".into()),
        ]
    );
    assert_eq!(changes("", "a\n"), vec![(Added, 1, "a\n".into())]);
    assert_eq!(changes("a\n", ""), vec![(Removed, 1, "a\n".into())]);
    // A changed last line without a newline is a change to that line.
    assert_eq!(
        changes("a\nb", "a\nb\n"),
        vec![(Removed, 2, "b".into()), (Added, 2, "b\n".into())]
    );
}

#[test]
fn diff_gives_up_on_oversized_inputs() {
    let old: String = (0..3000).map(|i| format!("old {i}\n")).collect();
    let new: String = (0..3000).map(|i| format!("new {i}\n")).collect();
    assert_eq!(diff_text(&old, &new), None);
}
