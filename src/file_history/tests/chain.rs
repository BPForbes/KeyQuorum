use super::*;
use crate::error::Error;

const ALL_TYPES: [HistoryEventType; 30] = [
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
    HistoryEventType::AutoMergeAttempted,
    HistoryEventType::AutoMergeFastForward,
    HistoryEventType::AutoMergeEquivalent,
    HistoryEventType::AutoMergeClean,
    HistoryEventType::AutoMergeBlocked,
    HistoryEventType::AutoMergeRequiresHuman,
    HistoryEventType::HistoryForkDetected,
    HistoryEventType::ContentConflictDetected,
    HistoryEventType::ConflictReviewAssigned,
    HistoryEventType::ConflictReviewEscalated,
    HistoryEventType::BridgeUsed,
    HistoryEventType::ConflictUnresolved,
    HistoryEventType::HistoryImported,
    HistoryEventType::QuorumUnlockAttempted,
    HistoryEventType::PasswordUnlockAttempted,
    HistoryEventType::ExpiredAccessAttempt,
    HistoryEventType::GateLinked,
    HistoryEventType::ShareLinkCreated,
    HistoryEventType::ShareLinkRedeemed,
    HistoryEventType::ShareLinkRevoked,
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
    // Wire codes are fixed: 1..=23 for types and 1..=4 for outcomes.
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

#[test]
fn a_files_policy_round_trips_and_is_optional() {
    let policy = FilePolicy {
        scope_root: "M.A".into(),
        scope_owner: Requirement::AuthorSign,
        descendants: Requirement::AuthorSignDirectParent,
        ancestors: Requirement::Forbidden,
        cross_branch: Requirement::AuthorSignBridgeOrOwner,
        auto_merge: false,
    };
    let bound = TrackedFile::with_policy(FILE, "a.txt", policy.clone());
    let decoded = TrackedFile::decode(&bound.encode().unwrap()).unwrap();
    assert_eq!(decoded.policy(), Some(&policy));
    assert_eq!(decoded, bound);
    let bare = TrackedFile::new(FILE, "a.txt");
    assert_eq!(
        TrackedFile::decode(&bare.encode().unwrap())
            .unwrap()
            .policy(),
        None
    );
}

#[test]
fn a_bad_policy_block_is_rejected() {
    let bound = TrackedFile::with_policy(FILE, "a.txt", FilePolicy::standard("M"));
    let bytes = bound.encode().unwrap();
    // Layout: magic(4) version(1) id(16) lp(name)=2+5 root(32) flag(1)
    // lp(scope)=2+1 then four requirement bytes and the auto-merge flag.
    let flag_at = 4 + 1 + 16 + 2 + 5 + 32;
    assert_eq!(bytes[flag_at], 1);
    let mut wrong_flag = bytes.clone();
    wrong_flag[flag_at] = 2;
    assert!(TrackedFile::decode(&wrong_flag).is_err());
    let first_requirement = flag_at + 1 + 2 + 1;
    for offset in 0..5 {
        let mut wrong_code = bytes.clone();
        wrong_code[first_requirement + offset] = 9;
        assert!(
            TrackedFile::decode(&wrong_code).is_err(),
            "requirement {offset}"
        );
    }
}
