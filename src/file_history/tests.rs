use super::*;
use crate::error::Error;

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

fn sample() -> TrackedFile {
    let mut file = TrackedFile::new(FILE, "sales-report.xlsx", b"native bytes".to_vec());
    file.append(new_event(HistoryEventType::TrackingStarted, None))
        .unwrap();
    file.append(new_event(HistoryEventType::RevisionSigned, Some([2; 32])))
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
    let empty = TrackedFile::new(FILE, "a.txt", Vec::new());
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
    let mut other = TrackedFile::new([9; 16], "b.txt", Vec::new());
    other
        .append(new_event(HistoryEventType::TrackingStarted, None))
        .unwrap();
    assert!(verify_chain(&FILE, &other.events).is_err());
}

#[test]
fn any_flipped_byte_outside_the_name_and_payload_is_detected() {
    let file = TrackedFile::new(FILE, "n", Vec::new());
    let mut file = file;
    file.append(new_event(HistoryEventType::TrackingStarted, None))
        .unwrap();
    file.append(sparse_event()).unwrap();
    let bytes = file.encode().unwrap();
    // magic(4) + version(1) + file_id(16) + lp(name)=2+1 → name text is byte 23.
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
    let mut file = TrackedFile::new(FILE, "n", Vec::new());
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
    let mut bytes = TrackedFile::new(FILE, "n", Vec::new()).encode().unwrap();
    let count_at = bytes.len() - 4;
    bytes[count_at..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(TrackedFile::decode(&bytes).is_err());
}
