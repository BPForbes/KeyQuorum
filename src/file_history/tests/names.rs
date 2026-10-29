//! The C-visible names of history event types and outcomes (`name_c`, `name_of`).

use super::*;

/// Every stored event code names itself exactly as the variant is spelled, and the first code
/// past the last variant is unknown. A variant added without a name does not compile (the match
/// is exhaustive); one added with the wrong name, or out of order, fails here.
#[test]
fn every_event_code_has_its_variant_name() {
    let mut known = 0u8;
    for code in 1..=u8::MAX {
        match HistoryEventType::name_of(code) {
            Some(name) => {
                let ty = HistoryEventType::from_u8(code).unwrap();
                assert_eq!(ty as u8, code);
                assert_eq!(name.to_str().unwrap(), format!("{ty:?}"));
                assert_eq!(name.to_bytes_with_nul().last(), Some(&0));
                known = code;
            }
            None => {
                assert!(HistoryEventType::from_u8(code).is_err());
                assert!(code > known, "a gap in the codes at {code}");
            }
        }
    }
    assert_eq!(known, HistoryEventType::LetterOpened as u8);
    assert!(HistoryEventType::name_of(0).is_none());
}

#[test]
fn outcome_names_match_their_variants() {
    for (code, name) in [(1u8, "Success"), (2, "Failure"), (3, "Denied"), (4, "Info")] {
        let found = HistoryOutcome::name_of(code).unwrap();
        assert_eq!(found.to_str().unwrap(), name);
        assert_eq!(
            format!("{:?}", HistoryOutcome::from_u8(code).unwrap()),
            name
        );
    }
    assert!(HistoryOutcome::name_of(0).is_none());
    assert!(HistoryOutcome::name_of(5).is_none());
}
