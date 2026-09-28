use super::*;
use crate::error::Error;
use sha2::Digest;

mod chain;
mod merge;
mod policy;
mod resolve;

const FILE: [u8; 16] = [7; 16];

fn new_event(kind: HistoryEventType, revision: Option<[u8; 32]>) -> NewEvent {
    NewEvent {
        revision_id: revision,
        occurred_at: "2026-10-02T14:32:05.482Z".to_string(),
        actor_identity: Some([1; 16]),
        actor_label: Some("M.A".to_string()),
        topology_generation: Some(7),
        event_type: kind,
        outcome: HistoryOutcome::Success,
        details: EventDetails::new().with("result", "TRUSTED"),
    }
}

fn sparse_event() -> NewEvent {
    NewEvent {
        revision_id: None,
        occurred_at: "2026-10-03T00:00:00Z".to_string(),
        actor_identity: None,
        actor_label: None,
        topology_generation: None,
        event_type: HistoryEventType::ShareAttempted,
        outcome: HistoryOutcome::Denied,
        details: EventDetails::new(),
    }
}

fn new_revision(parents: Vec<[u8; 32]>, at: &str) -> NewRevision {
    NewRevision {
        parent_revision_ids: parents,
        user_label: None,
        author_identity: Some([1; 16]),
        author_hcp_label: "M.A".to_string(),
        created_at_utc: at.to_string(),
        topology_generation: 7,
        policy_hash: [5; 32],
    }
}

const T1: &str = "2026-10-01T09:00:00.000Z";
const T2: &str = "2026-10-02T14:32:05.482Z";

fn tracked_file() -> TrackedFile {
    TrackedFile::new(FILE, "sales-report.xlsx")
}

fn sample() -> TrackedFile {
    let mut file = TrackedFile::new(FILE, "sales-report.xlsx");
    let r1 = file
        .check_in(new_revision(vec![], T1), b"v1".to_vec())
        .unwrap();
    file.append(new_event(HistoryEventType::TrackingStarted, None))
        .unwrap();
    file.append(new_event(HistoryEventType::RevisionSigned, Some(r1)))
        .unwrap();
    file.append(sparse_event()).unwrap();
    file
}

#[test]
fn container_round_trips_with_optional_fields() {
    let file = sample();
    let bytes = file.encode().unwrap();
    assert_eq!(TrackedFile::decode(&bytes).unwrap(), file);
    assert_eq!(&bytes[..4], CONTAINER_MAGIC);
}

#[test]
fn empty_history_root_is_the_files_genesis() {
    let empty = TrackedFile::new(FILE, "a.txt");
    assert_eq!(empty.history_root(), genesis_hash(&FILE));
    assert_ne!(genesis_hash(&FILE), genesis_hash(&[8; 16]));
    assert_eq!(
        TrackedFile::decode(&empty.encode().unwrap()).unwrap(),
        empty
    );
}

#[test]
fn appending_links_each_event_to_the_previous_root() {
    let file = sample();
    assert_eq!(file.events[0].previous_event_hash, genesis_hash(&FILE));
    for pair in file.events.windows(2) {
        assert_eq!(pair[1].previous_event_hash, pair[0].event_hash);
        assert_eq!(pair[1].sequence, pair[0].sequence + 1);
    }
    assert_eq!(file.history_root(), file.events[2].event_hash);
    assert_eq!(
        verify_chain(&FILE, &file.events).unwrap(),
        file.history_root()
    );
}

#[test]
fn events_get_distinct_random_ids() {
    let file = sample();
    assert_ne!(file.events[0].event_id, file.events[1].event_id);
}

#[test]
fn changing_an_earlier_event_breaks_the_chain() {
    let mut file = sample();
    file.events[0].outcome = HistoryOutcome::Failure;
    assert!(matches!(
        verify_chain(&FILE, &file.events),
        Err(Error::InvalidTrackedFile)
    ));
}

#[test]
fn removing_or_reordering_events_breaks_the_chain() {
    let file = sample();
    let mut removed = file.events.clone();
    removed.remove(1);
    assert!(verify_chain(&FILE, &removed).is_err());
    let mut swapped = file.events.clone();
    swapped.swap(0, 1);
    assert!(verify_chain(&FILE, &swapped).is_err());
    let mut duplicated = file.events.clone();
    duplicated.push(duplicated[2].clone());
    assert!(verify_chain(&FILE, &duplicated).is_err());
}

#[test]
fn an_event_from_another_file_is_refused() {
    let mut other = TrackedFile::new([9; 16], "b.txt");
    other
        .append(new_event(HistoryEventType::TrackingStarted, None))
        .unwrap();
    assert!(verify_chain(&FILE, &other.events).is_err());
}

#[test]
fn any_flipped_byte_outside_the_name_is_detected() {
    let mut file = TrackedFile::new(FILE, "n");
    let r1 = file
        .check_in(new_revision(vec![], T1), b"v1".to_vec())
        .unwrap();
    file.check_in(new_revision(vec![r1], T2), b"v2".to_vec())
        .unwrap();
    file.append(new_event(HistoryEventType::TrackingStarted, None))
        .unwrap();
    file.append(sparse_event()).unwrap();
    let bytes = file.encode().unwrap();
    // magic(4) + version(1) + file_id(16) + lp(name)=2+1 → name text is byte 23.
    // Payloads are covered too, through each revision's content commitment.
    let name_text = 23;
    for index in 0..bytes.len() {
        if index == name_text {
            continue;
        }
        let mut tampered = bytes.clone();
        tampered[index] ^= 0x01;
        assert!(
            TrackedFile::decode(&tampered).is_err(),
            "flip at byte {index} went unnoticed"
        );
    }
}

#[test]
fn truncation_and_trailing_bytes_are_rejected() {
    let bytes = sample().encode().unwrap();
    for len in 0..bytes.len() {
        assert!(TrackedFile::decode(&bytes[..len]).is_err(), "prefix {len}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(matches!(
        TrackedFile::decode(&extra),
        Err(Error::InvalidTrackedFile)
    ));
}

#[test]
fn a_stale_stored_root_is_rejected() {
    let file = sample();
    let mut bytes = file.encode().unwrap();
    // Root sits after magic, version, file id and the length-prefixed name.
    let root_at = 4 + 1 + 16 + 2 + file.logical_name.len();
    bytes[root_at] ^= 0xff;
    assert!(TrackedFile::decode(&bytes).is_err());
}

#[test]
fn unknown_event_type_and_outcome_codes_are_rejected() {
    let file = sample();
    let mut bytes = file.encode().unwrap();
    let last = file.events.last().unwrap();
    // The last event has no details, so its type and outcome bytes sit just
    // before the u16 detail count and the 32-byte hash at the end.
    let outcome_at = bytes.len() - 32 - 2 - 1;
    assert_eq!(bytes[outcome_at], last.outcome as u8);
    bytes[outcome_at] = 0xee;
    assert!(TrackedFile::decode(&bytes).is_err());
    let mut bytes = file.encode().unwrap();
    bytes[outcome_at - 1] = 0xee;
    assert!(TrackedFile::decode(&bytes).is_err());
}

#[test]
fn version_and_magic_are_checked() {
    let bytes = sample().encode().unwrap();
    let mut wrong_version = bytes.clone();
    wrong_version[4] = CONTAINER_VERSION + 1;
    assert!(TrackedFile::decode(&wrong_version).is_err());
    let mut wrong_magic = bytes;
    wrong_magic[0] = b'X';
    assert!(TrackedFile::decode(&wrong_magic).is_err());
}

#[test]
fn oversized_fields_fail_to_encode_instead_of_truncating() {
    let mut file = TrackedFile::new(FILE, "n");
    let mut event = new_event(HistoryEventType::TrackingStarted, None);
    event.occurred_at = "x".repeat(70_000);
    assert!(matches!(
        file.append(event),
        Err(Error::BundleFieldTooLarge)
    ));
    assert!(file.events.is_empty());
}

#[test]
fn hostile_event_count_does_not_preallocate() {
    let empty = TrackedFile::new(FILE, "n").encode().unwrap();
    let mut events = empty.clone();
    let at = events.len() - 4;
    events[at..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(TrackedFile::decode(&events).is_err());
    let mut revisions = empty;
    let at = revisions.len() - 12;
    revisions[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(TrackedFile::decode(&revisions).is_err());
}

// ---- revisions ------------------------------------------------------------

fn forked() -> (TrackedFile, [u8; 32], [u8; 32], [u8; 32]) {
    let mut file = TrackedFile::new(FILE, "decision.txt");
    let base = file
        .check_in(new_revision(vec![], T1), b"base".to_vec())
        .unwrap();
    let left = file
        .check_in(new_revision(vec![base], T2), b"left".to_vec())
        .unwrap();
    let right = file
        .check_in(
            new_revision(vec![base], "2026-10-02T14:40:00Z"),
            b"right".to_vec(),
        )
        .unwrap();
    (file, base, left, right)
}

#[test]
fn generated_label_matches_the_documented_shape() {
    assert_eq!(
        generated_label("sales-report.xlsx", T2, "M.A").unwrap(),
        "Rsales-report-20261002T143205.482Z-M.A"
    );
    assert_eq!(
        generated_label("Q3  sales (final)!.tar.gz", "2026-10-02T14:32:05Z", "M.S.1").unwrap(),
        "RQ3-sales-finaltar-20261002T143205Z-M.S.1"
    );
    assert_eq!(
        generated_label("my_file - copy", T1, "M").unwrap(),
        "Rmy-file-copy-20261001T090000.000Z-M"
    );
    assert_eq!(
        generated_label(".bashrc", T1, "M").unwrap(),
        "Rbashrc-20261001T090000.000Z-M"
    );
    assert_eq!(
        generated_label("!!!.txt", T1, "M").unwrap(),
        "Rfile-20261001T090000.000Z-M"
    );
}

#[test]
fn generated_label_rejects_non_utc_timestamps_and_empty_hcp() {
    for bad in [
        "2026-10-02 14:32:05Z",
        "2026-10-02T14:32:05",
        "2026-10-02T14:32:05+00:00",
        "2026-10-02T14:32Z",
        "2026-10-02T14:32:05.Z",
        "26-10-02T14:32:05Z",
        "",
    ] {
        assert!(generated_label("a.txt", bad, "M").is_err(), "{bad}");
    }
    assert!(generated_label("a.txt", T1, "").is_err());
}

#[test]
fn content_commitment_is_bound_to_the_file() {
    let plain: [u8; 32] = sha2::Sha256::digest(b"same bytes").into();
    let a = content_commitment(&[1; 16], b"same bytes");
    assert_ne!(a, content_commitment(&[2; 16], b"same bytes"));
    assert_ne!(a, plain);
    assert_eq!(a, content_commitment(&[1; 16], b"same bytes"));
}

#[test]
fn revision_ids_are_deterministic_and_commit_to_every_field() {
    let make = |f: &dyn Fn(&mut NewRevision)| {
        let mut new = new_revision(vec![], T1);
        f(&mut new);
        FileRevision::create(FILE, "a.txt", b"x", new)
            .unwrap()
            .revision_id
    };
    let base = make(&|_| {});
    assert_eq!(base, make(&|_| {}));
    assert_ne!(base, make(&|n| n.user_label = Some("note".into())));
    assert_ne!(base, make(&|n| n.author_identity = None));
    assert_ne!(base, make(&|n| n.author_hcp_label = "M.B".into()));
    assert_ne!(base, make(&|n| n.created_at_utc = T2.into()));
    assert_ne!(base, make(&|n| n.topology_generation = 8));
    assert_ne!(base, make(&|n| n.policy_hash = [6; 32]));
    assert_ne!(
        base,
        FileRevision::create(FILE, "a.txt", b"y", new_revision(vec![], T1))
            .unwrap()
            .revision_id
    );
    assert_ne!(
        base,
        FileRevision::create([9; 16], "a.txt", b"x", new_revision(vec![], T1))
            .unwrap()
            .revision_id
    );
}

#[test]
fn a_revision_id_commits_to_its_parents_and_their_order() {
    let mk = |parents: Vec<[u8; 32]>| {
        FileRevision::create(FILE, "a.txt", b"x", new_revision(parents, T1))
            .unwrap()
            .revision_id
    };
    let (a, b) = ([1; 32], [2; 32]);
    assert_ne!(mk(vec![a]), mk(vec![b]));
    assert_ne!(mk(vec![a]), mk(vec![a, b]));
    assert_ne!(mk(vec![a, b]), mk(vec![b, a]));
}

#[test]
fn check_in_builds_a_chain_and_enforces_lineage() {
    let mut file = TrackedFile::new(FILE, "a.txt");
    // A first revision cannot claim parents; a later one must have them.
    assert!(file
        .check_in(new_revision(vec![[1; 32]], T1), vec![])
        .is_err());
    let r1 = file
        .check_in(new_revision(vec![], T1), b"1".to_vec())
        .unwrap();
    assert!(file
        .check_in(new_revision(vec![], T2), b"2".to_vec())
        .is_err());
    assert!(file
        .check_in(new_revision(vec![[9; 32]], T2), b"2".to_vec())
        .is_err());
    assert!(file
        .check_in(new_revision(vec![r1, r1], T2), b"2".to_vec())
        .is_err());
    let r2 = file
        .check_in(new_revision(vec![r1], T2), b"2".to_vec())
        .unwrap();
    assert_eq!(file.graph().heads(), vec![r2]);
    assert_eq!(file.revisions[1].revision.parent_revision_ids, vec![r1]);
    assert_eq!(file.revisions[1].revision.file_id, FILE);
    assert_eq!(
        file.revisions[0].revision.generated_label,
        "Ra-20261001T090000.000Z-M.A"
    );
    verify_tracked_file(&file).unwrap();
}

#[test]
fn a_user_label_never_replaces_the_generated_label() {
    let mut file = TrackedFile::new(FILE, "sales-report.xlsx");
    let mut new = new_revision(vec![], T2);
    new.user_label = Some("Updated sales totals".into());
    let id = file.check_in(new, b"x".to_vec()).unwrap();
    let revision = &file.graph().get(&id).unwrap().revision;
    assert_eq!(revision.user_label.as_deref(), Some("Updated sales totals"));
    assert_eq!(
        revision.generated_label,
        "Rsales-report-20261002T143205.482Z-M.A"
    );
}

#[test]
fn a_fork_keeps_both_heads_and_a_merge_has_two_parents() {
    let (mut file, base, left, right) = forked();
    assert!(file.graph().has_fork());
    assert_eq!(file.graph().heads(), vec![left, right]);
    let merged = file
        .check_in(
            new_revision(vec![left, right], "2026-10-03T08:00:00Z"),
            b"merged".to_vec(),
        )
        .unwrap();
    assert!(!file.graph().has_fork());
    assert_eq!(file.graph().heads(), vec![merged]);
    let graph = file.graph();
    assert_eq!(
        graph.get(&merged).unwrap().revision.parent_revision_ids,
        vec![left, right]
    );
    assert!(graph.is_ancestor_or_self(&base, &merged));
    verify_tracked_file(&file).unwrap();
}

#[test]
fn compare_is_structural_never_by_timestamp() {
    let (file, base, left, right) = forked();
    let graph = file.graph();
    assert_eq!(graph.compare(&base, &base).unwrap(), HeadRelation::Equal);
    assert_eq!(
        graph.compare(&base, &left).unwrap(),
        HeadRelation::IncomingAhead
    );
    assert_eq!(
        graph.compare(&left, &base).unwrap(),
        HeadRelation::IncomingBehind
    );
    // `right` has the later timestamp but is still a fork against `left`.
    assert_eq!(
        graph.compare(&left, &right).unwrap(),
        HeadRelation::Diverged
    );
    assert_eq!(
        graph.compare(&right, &left).unwrap(),
        HeadRelation::Diverged
    );
    assert!(graph.compare(&base, &[9; 32]).is_err());
    assert!(!graph.is_ancestor_or_self(&[9; 32], &[9; 32]));
}

#[test]
fn revisions_round_trip_through_the_container() {
    let (mut file, _, left, right) = forked();
    file.check_in(
        new_revision(vec![left, right], "2026-10-03T08:00:00Z"),
        b"m".to_vec(),
    )
    .unwrap();
    file.append(new_event(HistoryEventType::EditCheckedIn, Some(left)))
        .unwrap();
    let bytes = file.encode().unwrap();
    assert_eq!(TrackedFile::decode(&bytes).unwrap(), file);
}

#[test]
fn decode_rejects_broken_revision_graphs() {
    let (file, _, _, _) = forked();
    let round = |f: &dyn Fn(&mut TrackedFile)| {
        let mut broken = file.clone();
        f(&mut broken);
        TrackedFile::decode(&broken.encode_unchecked().unwrap())
    };
    // Sanity: the untouched file decodes.
    assert!(round(&|_| {}).is_ok());
    // Payload no longer matches its commitment.
    assert!(round(&|f| f.revisions[1].payload = b"other".to_vec()).is_err());
    // A child stored before its parent.
    assert!(round(&|f| f.revisions.swap(0, 1)).is_err());
    // A missing parent.
    assert!(round(&|f| {
        f.revisions.remove(0);
    })
    .is_err());
    // A second root.
    assert!(round(&|f| f.revisions[2].revision.parent_revision_ids.clear()).is_err());
    // A revision from another file.
    assert!(round(&|f| f.revisions[1].revision.file_id = [9; 16]).is_err());
    // A duplicated revision.
    assert!(round(&|f| {
        let copy = f.revisions[1].clone();
        f.revisions.push(copy);
    })
    .is_err());
    // A tampered label no longer matches the id.
    assert!(round(&|f| f.revisions[1].revision.generated_label = "Rforged".into()).is_err());
}

#[test]
fn events_may_only_name_known_revisions() {
    let mut file = TrackedFile::new(FILE, "a.txt");
    let r1 = file
        .check_in(new_revision(vec![], T1), b"1".to_vec())
        .unwrap();
    // A stale or mistyped reference is refused before anything is stored.
    assert!(matches!(
        file.append(new_event(
            HistoryEventType::RevisionSigned,
            Some([0xaa; 32])
        )),
        Err(Error::InvalidTrackedFile)
    ));
    assert!(file.events().is_empty());
    file.append(new_event(HistoryEventType::RevisionSigned, Some(r1)))
        .unwrap();
    assert!(TrackedFile::decode(&file.encode().unwrap()).is_ok());
    // A graph that loses a referenced revision no longer verifies or encodes.
    file.revisions.clear();
    assert!(verify_tracked_file(&file).is_err());
    assert!(file.encode().is_err());
}

#[test]
fn an_identical_retry_is_refused_not_stored_twice() {
    let mut file = TrackedFile::new(FILE, "a.txt");
    let r1 = file
        .check_in(new_revision(vec![], T1), b"1".to_vec())
        .unwrap();
    let again = new_revision(vec![r1], T2);
    let r2 = file.check_in(again.clone(), b"2".to_vec()).unwrap();
    assert!(matches!(
        file.check_in(again, b"2".to_vec()),
        Err(Error::InvalidTrackedFile)
    ));
    assert_eq!(file.revisions().len(), 2);
    assert_eq!(file.graph().heads(), vec![r2]);
    assert!(TrackedFile::decode(&file.encode().unwrap()).is_ok());
}

#[test]
fn timestamps_must_be_real_utc_instants() {
    for good in [
        "2026-02-28T23:59:59Z",
        "2024-02-29T00:00:00Z",
        "2000-02-29T12:00:00.5Z",
        "2026-12-31T23:59:59.999999999Z",
    ] {
        assert!(generated_label("a", good, "M").is_ok(), "{good}");
    }
    for bad in [
        "2026-99-99T99:99:99Z",
        "2026-13-01T00:00:00Z",
        "2026-00-10T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2026-01-00T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
        "0000-01-01T00:00:00Z",
    ] {
        assert!(generated_label("a", bad, "M").is_err(), "{bad}");
    }
}

#[test]
fn a_damaged_history_is_neither_extended_nor_encoded() {
    let mut file = sample();
    file.events[0].outcome = HistoryOutcome::Failure;
    assert!(matches!(file.encode(), Err(Error::InvalidTrackedFile)));
    let before = file.events.len();
    assert!(matches!(
        file.append(sparse_event()),
        Err(Error::InvalidTrackedFile)
    ));
    assert_eq!(file.events.len(), before);
    // Dropping an event in the middle is caught the same way.
    let mut gapped = sample();
    gapped.events.remove(1);
    assert!(gapped.encode().is_err());
    assert_eq!(sample().events().len(), 3);
}

#[test]
fn a_forged_generated_label_is_rejected_even_with_a_recomputed_id() {
    let (file, _, _, _) = forked();
    let forge = |f: &dyn Fn(&mut FileRevision)| {
        let mut forged = file.clone();
        f(&mut forged.revisions[1].revision);
        // An attacker fixes the id up so only the label rule can catch it.
        let revision = &mut forged.revisions[1].revision;
        revision.revision_id = revision.compute_id().unwrap();
        TrackedFile::decode(&forged.encode_unchecked().unwrap())
    };
    assert!(forge(&|_| {}).is_ok());
    assert!(forge(&|r| r.generated_label = "Rforged".into()).is_err());
    assert!(forge(&|r| r.generated_label = "not-a-label".into()).is_err());
    // Timestamp or HCP label swapped without regenerating the label.
    assert!(forge(&|r| r.created_at_utc = "2026-10-05T00:00:00Z".into()).is_err());
    assert!(forge(&|r| r.author_hcp_label = "M.B".into()).is_err());
    // An empty or unnormalized name part.
    assert!(forge(&|r| r.generated_label = "R-20261002T143205.482Z-M.A".into()).is_err());
    assert!(forge(&|r| r.generated_label = "Rmy report-20261002T143205.482Z-M.A".into()).is_err());
}

#[test]
fn renaming_a_file_does_not_invalidate_older_revisions() {
    let (mut file, _, _, _) = forked();
    file.logical_name = "renamed.txt".into();
    let decoded = TrackedFile::decode(&file.encode().unwrap()).unwrap();
    assert_eq!(
        decoded.revisions()[0].revision.generated_label.as_str(),
        "Rdecision-20261001T090000.000Z-M.A"
    );
    assert_eq!(decoded.logical_name, "renamed.txt");
}
