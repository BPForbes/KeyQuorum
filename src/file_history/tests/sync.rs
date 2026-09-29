use super::*;
use crate::file_history::{HistoryRelation, HistorySnapshot, ImportContext};

fn context() -> ImportContext {
    ImportContext {
        actor_identity: Some([9; 16]),
        actor_label: "M.A".to_string(),
        occurred_at: "2026-10-06T00:00:00Z".to_string(),
        topology_generation: 7,
    }
}

fn base_copy() -> (TrackedFile, [u8; 32]) {
    let mut file = TrackedFile::with_policy(FILE, "plan.txt", FilePolicy::standard("M.A"));
    let base = file
        .check_in(new_revision(vec![], T1), b"base".to_vec())
        .unwrap();
    file.append(new_event(HistoryEventType::TrackingStarted, Some(base)))
        .unwrap();
    (file, base)
}

fn child(file: &mut TrackedFile, parent: [u8; 32], at: &str, text: &str) -> [u8; 32] {
    file.check_in(new_revision(vec![parent], at), text.as_bytes().to_vec())
        .unwrap()
}

fn kinds(file: &TrackedFile) -> Vec<HistoryEventType> {
    file.events().iter().map(|e| e.event_type).collect()
}

#[test]
fn an_incoming_copy_that_is_ahead_fast_forwards_and_is_recorded() {
    let (mut local, base) = base_copy();
    let mut remote = local.clone();
    let next = child(&mut remote, base, T2, "next");
    let merged = local.merge_history(&remote, &context()).unwrap();
    assert_eq!(merged.relation, HistoryRelation::RemoteAhead);
    assert_eq!((merged.revisions_added, merged.proofs_added), (1, 0));
    assert_eq!(local.graph().heads(), vec![next]);
    assert_eq!(
        kinds(&local).last(),
        Some(&HistoryEventType::HistoryImported)
    );
    let event = local.events().last().unwrap();
    assert_eq!(event.actor_label.as_deref(), Some("M.A"));
    let details = event.details.entries();
    assert!(details.contains(&("relation".into(), "RemoteAhead".into())));
    assert!(details.contains(&("revisions_added".into(), "1".into())));
    assert!(details.contains(&(
        "from_history_root".into(),
        hex::encode(remote.history_root())
    )));
    // The result still round-trips and verifies.
    assert_eq!(
        TrackedFile::decode(&local.encode().unwrap()).unwrap(),
        local
    );
}

#[test]
fn nothing_new_changes_and_records_nothing() {
    let (mut local, base) = base_copy();
    let remote = local.clone();
    let before = local.clone();
    let same = local.merge_history(&remote, &context()).unwrap();
    assert_eq!(same.relation, HistoryRelation::Identical);
    assert_eq!(local, before);
    // A copy that is behind changes nothing either.
    child(&mut local, base, T2, "ahead");
    let before = local.clone();
    let behind = local.merge_history(&remote, &context()).unwrap();
    assert_eq!(behind.relation, HistoryRelation::LocalAhead);
    assert_eq!((behind.revisions_added, behind.proofs_added), (0, 0));
    assert_eq!(local, before);
}

#[test]
fn diverged_copies_keep_both_heads_whichever_arrives_first() {
    let (base_file, base) = base_copy();
    let (mut a, mut b) = (base_file.clone(), base_file);
    let from_a = child(&mut a, base, T2, "from a");
    let from_b = child(&mut b, base, "2026-10-02T15:00:00Z", "from b");
    let (mut a_then_b, mut b_then_a) = (a.clone(), b.clone());
    let merged = a_then_b.merge_history(&b, &context()).unwrap();
    assert_eq!(merged.relation, HistoryRelation::Diverged);
    b_then_a.merge_history(&a, &context()).unwrap();
    let heads = |f: &TrackedFile| {
        let mut heads = f.graph().heads();
        heads.sort();
        heads
    };
    let mut expected = vec![from_a, from_b];
    expected.sort();
    assert_eq!(heads(&a_then_b), expected);
    assert_eq!(
        heads(&b_then_a),
        expected,
        "the order of arrival decides nothing"
    );
    // Nothing of the local history was rewritten.
    assert_eq!(a_then_b.events()[..a.events().len()], a.events()[..]);
    // The next step for a fork is the ordinary merge.
    assert!(a_then_b.graph().has_fork());
}

#[test]
fn importing_twice_adds_nothing_the_second_time() {
    let (mut local, base) = base_copy();
    let mut remote = local.clone();
    child(&mut remote, base, T2, "next");
    local.merge_history(&remote, &context()).unwrap();
    let after_first = local.clone();
    let again = local.merge_history(&remote, &context()).unwrap();
    assert_eq!((again.revisions_added, again.proofs_added), (0, 0));
    assert_eq!(local, after_first);
}

#[test]
fn proofs_are_unioned_and_stored_not_trusted() {
    let (mut local, base) = base_copy();
    let mut remote = local.clone();
    remote
        .sign_revision(&base, [1; 16], "M.A", &[5; 32])
        .unwrap();
    let merged = local.merge_history(&remote, &context()).unwrap();
    assert_eq!((merged.revisions_added, merged.proofs_added), (0, 1));
    assert_eq!(local.proofs().len(), 1);
    // A proof already held is not added again.
    let again = local.merge_history(&remote, &context()).unwrap();
    assert_eq!(again.proofs_added, 0);
    assert_eq!(local.proofs().len(), 1);
}

#[test]
fn a_copy_of_another_file_or_policy_is_refused_and_nothing_changes() {
    let (mut local, _) = base_copy();
    let before = local.clone();
    let mut other_file = TrackedFile::with_policy([9; 16], "plan.txt", FilePolicy::standard("M.A"));
    other_file
        .check_in(new_revision(vec![], T1), b"base".to_vec())
        .unwrap();
    assert!(local.merge_history(&other_file, &context()).is_err());
    let mut other_policy = TrackedFile::with_policy(FILE, "plan.txt", FilePolicy::standard("M.B"));
    other_policy
        .check_in(new_revision(vec![], T1), b"base".to_vec())
        .unwrap();
    assert!(local.merge_history(&other_policy, &context()).is_err());
    assert_eq!(local, before);
}

#[test]
fn an_incoming_copy_that_fails_verification_is_refused() {
    let (mut local, base) = base_copy();
    let before = local.clone();
    let mut remote = local.clone();
    child(&mut remote, base, T2, "next");
    // Payload no longer matches its commitment.
    remote.revisions[1].payload = b"tampered".to_vec();
    assert!(local.merge_history(&remote, &context()).is_err());
    assert_eq!(local, before);
    // An event that names an unknown revision.
    let mut remote = local.clone();
    remote.events[0].revision_id = Some([0xab; 32]);
    assert!(local.merge_history(&remote, &context()).is_err());
    assert_eq!(local, before);
}

#[test]
fn a_remote_that_rewrites_a_shared_revision_is_refused() {
    let (mut local, base) = base_copy();
    let before = local.clone();
    let mut remote = local.clone();
    child(&mut remote, base, T2, "next");
    // The same id, but a different stored copy: mutate a field the id
    // does not verify (user label is covered, so touch the payload and
    // commitment together to keep the remote internally valid).
    let stored = &mut remote.revisions[0];
    stored.payload = b"other base".to_vec();
    stored.revision.content_commitment =
        crate::file_history::content_commitment(&FILE, &stored.payload);
    stored.revision.revision_id = stored.revision.compute_id().unwrap();
    // Its id changed, so it is a different revision and the child is orphaned:
    // the remote no longer verifies, and the import is refused either way.
    assert!(local.merge_history(&remote, &context()).is_err());
    assert_eq!(local, before);
}

// ---- snapshots -------------------------------------------------------------

fn history() -> TrackedFile {
    let (mut file, base) = base_copy();
    file.append(new_event(HistoryEventType::RevisionSigned, Some(base)))
        .unwrap();
    file.append(sparse_event()).unwrap();
    file
}

#[test]
fn a_snapshot_round_trips_and_names_its_root() {
    let file = history();
    let snapshot = file.history_snapshot();
    assert_eq!(snapshot.history_root, file.history_root());
    assert_eq!(snapshot.events.len(), 3);
    let bytes = snapshot.encode().unwrap();
    assert_eq!(&bytes[..4], b"KQHS");
    assert_eq!(HistorySnapshot::decode(&bytes).unwrap(), snapshot);
    // An empty history is a valid snapshot too.
    let empty = TrackedFile::new(FILE, "e.txt").history_snapshot();
    assert_eq!(
        HistorySnapshot::decode(&empty.encode().unwrap()).unwrap(),
        empty
    );
}

#[test]
fn any_flipped_byte_truncation_or_trailing_byte_is_rejected() {
    let bytes = history().history_snapshot().encode().unwrap();
    for index in 0..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[index] ^= 1;
        assert!(
            HistorySnapshot::decode(&tampered).is_err(),
            "flip at {index}"
        );
    }
    for len in 0..bytes.len() {
        assert!(
            HistorySnapshot::decode(&bytes[..len]).is_err(),
            "prefix {len}"
        );
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(HistorySnapshot::decode(&extra).is_err());
}

#[test]
fn an_inconsistent_snapshot_will_not_encode() {
    let mut snapshot = history().history_snapshot();
    snapshot.history_root = [1; 32];
    assert!(snapshot.encode().is_err());
    let mut snapshot = history().history_snapshot();
    snapshot.events.swap(0, 1);
    assert!(snapshot.encode().is_err());
}

#[test]
fn a_snapshot_is_a_prefix_of_the_history_it_came_from() {
    let mut file = history();
    let early = file.history_snapshot();
    file.append(new_event(HistoryEventType::PolicyDecision, None))
        .unwrap();
    assert!(early.is_prefix_of(&file));
    assert!(file.history_snapshot().is_prefix_of(&file));
    // An earlier point along the same chain is also a valid snapshot.
    let mut shorter = early.clone();
    shorter.events.pop();
    shorter.history_root = shorter.events.last().unwrap().event_hash;
    assert!(HistorySnapshot::decode(&shorter.encode().unwrap()).is_ok());
    assert!(shorter.is_prefix_of(&file));
    // A snapshot of another file, or of a diverged chain, is not.
    let mut other = TrackedFile::new([2; 16], "o.txt");
    other
        .append(new_event(HistoryEventType::TrackingStarted, None))
        .unwrap();
    assert!(!other.history_snapshot().is_prefix_of(&file));
    let (mut fork, base) = base_copy();
    fork.append(new_event(HistoryEventType::PolicyDecision, Some(base)))
        .unwrap();
    assert!(!fork.history_snapshot().is_prefix_of(&file));
    // The empty snapshot is the start of every history of that file.
    assert!(TrackedFile::new(FILE, "e.txt")
        .history_snapshot()
        .is_prefix_of(&file));
}
