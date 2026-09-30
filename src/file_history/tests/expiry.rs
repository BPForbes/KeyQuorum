use super::*;
use crate::file_history::ExpiryContext;

fn context() -> ExpiryContext {
    ExpiryContext {
        actor_identity: Some([3; 16]),
        actor_label: Some("M.A".to_string()),
        occurred_at: "2026-10-05T00:00:00Z".to_string(),
        topology_generation: Some(7),
    }
}

/// Two revisions with distinctive content, one signed-looking event each.
fn live() -> TrackedFile {
    let mut file = TrackedFile::with_policy(FILE, "plan.txt", FilePolicy::standard("M.A"));
    let base = file
        .check_in(new_revision(vec![], T1), b"SECRET-ONE".to_vec())
        .unwrap();
    file.append(new_event(HistoryEventType::TrackingStarted, Some(base)))
        .unwrap();
    let next = file
        .check_in(new_revision(vec![base], T2), b"SECRET-TWO".to_vec())
        .unwrap();
    file.append(new_event(HistoryEventType::EditCheckedIn, Some(next)))
        .unwrap();
    file
}

fn kinds(file: &TrackedFile) -> Vec<HistoryEventType> {
    file.events().iter().map(|e| e.event_type).collect()
}

#[test]
fn destroying_removes_every_payload_and_keeps_a_verifiable_tombstone() {
    let mut file = live();
    let ids: Vec<_> = file
        .revisions()
        .iter()
        .map(|s| s.revision.revision_id)
        .collect();
    assert_eq!(file.destroy_content("test", &context()).unwrap(), 2);
    assert!(file.is_destroyed());
    assert!(file.revisions().iter().all(|s| s.content().is_none()));
    assert_eq!(
        &kinds(&file)[2..],
        [
            HistoryEventType::FileExpired,
            HistoryEventType::ContentDestroyed
        ]
    );
    // The graph and history survive, encoded and decoded.
    let bytes = file.encode().unwrap();
    for secret in [&b"SECRET-ONE"[..], b"SECRET-TWO"] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
    }
    let back = TrackedFile::decode(&bytes).unwrap();
    assert_eq!(back, file);
    let kept: Vec<_> = back
        .revisions()
        .iter()
        .map(|s| s.revision.revision_id)
        .collect();
    assert_eq!(kept, ids);
    assert_eq!(
        crate::file_history::verify_tracked_file(&back).unwrap(),
        back.history_root()
    );
}

#[test]
fn content_cannot_be_half_destroyed_or_silently_stripped() {
    // A payload missing without a recorded destruction.
    let mut stripped = live();
    stripped.revisions[0].payload = None;
    assert!(stripped.encode().is_err());
    assert!(TrackedFile::decode(&stripped.encode_unchecked().unwrap()).is_err());
    // A destroyed file with one payload put back.
    let mut revived = live();
    revived.destroy_content("test", &context()).unwrap();
    revived.revisions[1].payload = Some(b"SECRET-TWO".to_vec());
    assert!(revived.encode().is_err());
}

#[test]
fn a_tombstone_takes_no_new_content_and_is_not_merged_or_extracted() {
    let mut file = live();
    let head = file.graph().heads()[0];
    let copy = file.clone();
    file.destroy_content("test", &context()).unwrap();
    assert!(matches!(
        file.check_in(
            new_revision(vec![head], "2026-10-06T00:00:00Z"),
            b"x".to_vec()
        ),
        Err(Error::FileExpired)
    ));
    assert!(matches!(
        file.extract_revision(&head),
        Err(Error::FileExpired)
    ));
    let import = crate::file_history::ImportContext {
        actor_identity: None,
        actor_label: "M.A".into(),
        occurred_at: "2026-10-06T00:00:00Z".into(),
        topology_generation: 7,
    };
    // Neither direction: live content is not brought into a tombstone, and a
    // tombstone is not brought into a live copy.
    assert!(matches!(
        file.clone().merge_history(&copy, &import),
        Err(Error::FileExpired)
    ));
    assert!(matches!(
        copy.clone().merge_history(&file, &import),
        Err(Error::FileExpired)
    ));
    assert!(matches!(
        file.destroy_content("again", &context()),
        Err(Error::FileExpired)
    ));
    assert!(file
        .schedule_expiry("2027-01-01T00:00:00Z", &context())
        .is_err());
}

#[test]
fn a_scheduled_expiry_destroys_only_once_it_has_passed() {
    let mut file = live();
    assert!(file
        .schedule_expiry("2026-13-01T00:00:00Z", &context())
        .is_err());
    assert!(file
        .schedule_expiry("2026-10-10 00:00", &context())
        .is_err());
    file.schedule_expiry("2026-10-10T00:00:00Z", &context())
        .unwrap();
    assert_eq!(file.expires_at().as_deref(), Some("2026-10-10T00:00:00Z"));
    assert!(!file
        .expire_if_due("2026-10-09T23:59:59Z", &context())
        .unwrap());
    assert!(!file.is_destroyed());
    // Moving it is recorded too; the newest schedule applies.
    file.schedule_expiry("2026-10-08T00:00:00Z", &context())
        .unwrap();
    assert!(file
        .expire_if_due("2026-10-09T00:00:00Z", &context())
        .unwrap());
    assert!(file.is_destroyed());
    file.record_expired_access("checkout", &context()).unwrap();
    let last = file.events().last().unwrap();
    assert_eq!(last.event_type, HistoryEventType::ExpiredAccessAttempt);
    assert_eq!(last.outcome, HistoryOutcome::Denied);
    assert!(TrackedFile::decode(&file.encode().unwrap()).is_ok());
}

#[test]
fn a_linked_gates_destruction_is_not_this_files_tombstone() {
    let mut file = live();
    // What `cli::gate_link` records when a linked quorum file is purged.
    file.append(NewEvent {
        revision_id: None,
        occurred_at: "2026-10-05T00:00:00Z".into(),
        actor_identity: None,
        actor_label: None,
        topology_generation: None,
        event_type: HistoryEventType::ContentDestroyed,
        outcome: HistoryOutcome::Success,
        details: EventDetails::new()
            .with("gate", "quorum")
            .with("gate_file", "1"),
    })
    .unwrap();
    assert!(!file.is_destroyed());
    assert!(TrackedFile::decode(&file.encode().unwrap()).is_ok());
    // And the real one still counts afterwards.
    file.destroy_content("test", &context()).unwrap();
    assert!(file.is_destroyed());
}
