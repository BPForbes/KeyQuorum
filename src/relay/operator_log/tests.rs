use super::*;
use crate::relay;

fn store() -> rusqlite::Connection {
    relay::open_in_memory().expect("schema")
}

fn note<'a>(operation_id: Option<&'a str>, action: &'a str, subject: &'a str) -> Note<'a> {
    Note { operation_id, operator: "ops@example.test", action, subject }
}

#[test]
fn an_attempt_is_listed_newest_first_with_who_and_whether_it_went_through() {
    let conn = store();
    record(&conn, "ops@example.test", "issue", Some("Acme"), true).expect("record");
    record(&conn, "ops@example.test", "void_licence", Some("licence 1"), false).expect("record");
    let got = recent(&conn, 10, None).expect("recent");
    assert_eq!(got.len(), 2);
    assert_eq!((got[0].action.as_str(), got[0].success), ("void_licence", false));
    assert_eq!(got[1].subject.as_deref(), Some("Acme"));
    assert_eq!(got[1].operator, "ops@example.test");
    assert!(got.iter().all(|a| a.operation_id.is_none() && a.result.is_none()));
}

#[test]
fn control_characters_never_reach_the_log_and_long_text_is_cut() {
    let conn = store();
    record(&conn, "ops@example.test", "issue", Some(&format!("a\nb\u{7}{}", "x".repeat(500))), true).expect("record");
    let subject = recent(&conn, 1, None).expect("recent").remove(0).subject.expect("subject");
    assert!(subject.starts_with("ab"));
    assert_eq!(subject.chars().count(), 200);
}

#[test]
fn an_empty_operator_or_action_is_refused() {
    let conn = store();
    assert!(record(&conn, "  ", "issue", None, true).is_err());
    assert!(record(&conn, "ops@example.test", "", None, true).is_err());
    assert!(note(None, "", "x").record_done(&conn, "{}").is_err());
    assert!(recent(&conn, 10, None).expect("recent").is_empty());
}

#[test]
fn the_limit_is_clamped_and_the_cursor_pages_back() {
    let conn = store();
    for n in 0..5 {
        record(&conn, "ops@example.test", &format!("a{n}"), None, true).expect("record");
    }
    assert_eq!(recent(&conn, 0, None).expect("recent").len(), 1);
    assert_eq!(recent(&conn, 10_000, None).expect("recent").len(), 5);
    let first = recent(&conn, 2, None).expect("page");
    let second = recent(&conn, 2, first.last().map(|a| a.id)).expect("page");
    assert_eq!(first.iter().map(|a| a.action.as_str()).collect::<Vec<_>>(), ["a4", "a3"]);
    assert_eq!(second.iter().map(|a| a.action.as_str()).collect::<Vec<_>>(), ["a2", "a1"]);
}

#[test]
fn an_operation_id_is_eight_to_sixty_four_safe_characters() {
    assert!(valid_operation_id("abcdefgh"));
    assert!(valid_operation_id("0b9e-4C1d_aa77"));
    assert!(valid_operation_id(&"a".repeat(64)));
    for bad in ["short", "", &"a".repeat(65), "has space 123", "semi;colon1", "quote'quote", "émoji-émoji"] {
        assert!(!valid_operation_id(bad), "{bad}");
    }
}

#[test]
fn a_change_is_recorded_with_its_operation_id_and_found_again_by_it() {
    let conn = store();
    note(Some("op-0123456789"), "issue", "Acme").record_done(&conn, r#"{"licence_id":3}"#).expect("done");
    let found = find_operation(&conn, "op-0123456789").expect("find").expect("recorded");
    assert_eq!((found.action.as_str(), found.success), ("issue", true));
    assert_eq!(found.result.as_deref(), Some(r#"{"licence_id":3}"#));
    assert_eq!(found.operation_id.as_deref(), Some("op-0123456789"));
    assert!(find_operation(&conn, "op-someother1").expect("find").is_none());
}

#[test]
fn an_operation_id_can_be_recorded_once_and_a_second_try_fails_whole() {
    let conn = store();
    note(Some("op-0123456789"), "issue", "Acme").record_done(&conn, "{}").expect("done");
    assert!(note(Some("op-0123456789"), "issue", "Acme").record_done(&conn, "{}").is_err());
    // A malformed id or an over-long result is refused before it is written.
    assert!(note(Some("bad id"), "issue", "x").record_done(&conn, "{}").is_err());
    assert!(note(Some("op-9999999999"), "issue", "x").record_done(&conn, &"r".repeat(1001)).is_err());
    // Without an id a change is still recorded, any number of times.
    note(None, "issue", "x").record_done(&conn, "{}").expect("no id");
    note(None, "issue", "x").record_done(&conn, "{}").expect("no id again");
    assert_eq!(recent(&conn, 10, None).expect("recent").len(), 3);
}
