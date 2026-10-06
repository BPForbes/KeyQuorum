use super::*;
use crate::relay;

fn store() -> rusqlite::Connection {
    relay::open_in_memory().expect("schema")
}

#[test]
fn actions_are_listed_newest_first_with_who_and_whether_they_went_through() {
    let conn = store();
    record(&conn, "ops@example.test", "issue", Some("Acme"), true).expect("record");
    record(&conn, "ops@example.test", "void_licence", Some("licence 1"), false).expect("record");
    let got = recent(&conn, 10).expect("recent");
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].action, "void_licence");
    assert!(!got[0].success);
    assert_eq!(got[1].subject.as_deref(), Some("Acme"));
    assert_eq!(got[1].operator, "ops@example.test");
}

#[test]
fn control_characters_never_reach_the_log_and_long_text_is_cut() {
    let conn = store();
    record(
        &conn,
        "ops@example.test",
        "issue",
        Some(&format!("a\nb\u{7}{}", "x".repeat(500))),
        true,
    )
    .expect("record");
    let got = recent(&conn, 1).expect("recent");
    let subject = got[0].subject.as_deref().expect("subject");
    assert!(subject.starts_with("ab"));
    assert_eq!(subject.chars().count(), 200);
}

#[test]
fn an_empty_operator_or_action_is_refused() {
    let conn = store();
    assert!(record(&conn, "  ", "issue", None, true).is_err());
    assert!(record(&conn, "ops@example.test", "", None, true).is_err());
    assert!(recent(&conn, 10).expect("recent").is_empty());
}

#[test]
fn the_limit_is_clamped() {
    let conn = store();
    for n in 0..3 {
        record(&conn, "ops@example.test", &format!("a{n}"), None, true).expect("record");
    }
    assert_eq!(recent(&conn, 0).expect("recent").len(), 1);
    assert_eq!(recent(&conn, 10_000).expect("recent").len(), 3);
}
