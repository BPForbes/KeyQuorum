use super::*;
use crate::error::Error;

const ALL_TYPES: [HistoryEventType; 10] = [
    HistoryEventType::TrackingStarted,
    HistoryEventType::EditCheckedIn,
    HistoryEventType::RevisionSigned,
    HistoryEventType::CountersignatureAdded,
    HistoryEventType::PolicyDecision,
    HistoryEventType::ShareAttempted,
    HistoryEventType::ShareDelivered,
    HistoryEventType::FileExpired,
    HistoryEventType::ContentDestroyed,
    HistoryEventType::TamperDetected,
];

const ALL_OUTCOMES: [HistoryOutcome; 4] = [
    HistoryOutcome::Success,
    HistoryOutcome::Failure,
    HistoryOutcome::Denied,
    HistoryOutcome::Info,
];

#[test]
fn every_declared_code_round_trips_and_stays_stable() {
    let mut file = tracked_file();
    for (index, kind) in ALL_TYPES.iter().enumerate() {
        let mut event = new_event(*kind, None);
        event.outcome = ALL_OUTCOMES[index % ALL_OUTCOMES.len()];
        file.append(event).unwrap();
    }
    let decoded = TrackedFile::decode(&file.encode().unwrap()).unwrap();
    assert_eq!(decoded, file);
    // Wire codes are fixed: 1..=10 for types and 1..=4 for outcomes.
    for (index, kind) in ALL_TYPES.iter().enumerate() {
        assert_eq!(*kind as u8, index as u8 + 1);
    }
    for (index, outcome) in ALL_OUTCOMES.iter().enumerate() {
        assert_eq!(*outcome as u8, index as u8 + 1);
    }
}

#[test]
fn optional_field_tags_other_than_zero_and_one_are_rejected() {
    use super::super::codec::{take_opt_array, take_opt_str, take_opt_u64};
    assert_eq!(take_opt_array::<2>(&mut &[0u8][..]).unwrap(), None);
    assert_eq!(
        take_opt_array::<2>(&mut &[1u8, 7, 8][..]).unwrap(),
        Some([7, 8])
    );
    for tag in [2u8, 3, 0x80, 0xff] {
        assert!(matches!(
            take_opt_array::<2>(&mut &[tag, 7, 8][..]),
            Err(Error::InvalidTrackedFile)
        ));
        assert!(take_opt_str(&mut &[tag, 0, 0][..]).is_err());
        assert!(take_opt_u64(&mut &[tag, 0, 0, 0, 0, 0, 0, 0, 1][..]).is_err());
    }
}

#[test]
fn a_truncated_history_is_valid_on_its_own_but_has_a_different_root() {
    // Without a signature or a root the reader already holds, a holder can
    // drop tail events and re-encode. The chain stays consistent; only the
    // root differs, which is why the root must be retained or signed.
    let file = sample();
    let mut shortened = file.clone();
    shortened.events.pop();
    let decoded = TrackedFile::decode(&shortened.encode().unwrap()).unwrap();
    assert_eq!(decoded.events().len(), 2);
    assert_ne!(decoded.history_root(), file.history_root());
    assert_eq!(decoded.history_root(), file.events()[1].event_hash);
}

#[test]
fn name_changes_are_not_authenticated_at_this_stage() {
    let file = sample();
    let mut renamed = file.clone();
    renamed.logical_name = "other.txt".into();
    let decoded = TrackedFile::decode(&renamed.encode().unwrap()).unwrap();
    assert_eq!(decoded.logical_name, "other.txt");
    assert_eq!(decoded.history_root(), file.history_root());
}
