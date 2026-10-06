use super::*;
use crate::relay;

fn store() -> rusqlite::Connection {
    relay::open_in_memory().expect("schema")
}

fn new(client: &str) -> NewLicence {
    NewLicence {
        client: client.to_string(),
        terms: "Seats: 5.".to_string(),
        expires_at: None,
    }
}

#[test]
fn a_licence_is_recorded_trimmed_and_active() {
    let conn = store();
    let made = create(&conn, &new("  Acme Ltd  ")).expect("create");
    assert_eq!(made.client, "Acme Ltd");
    assert_eq!(made.terms, "Seats: 5.");
    assert!(made.active);
    assert!(made.expires_at.is_none() && made.voided_at.is_none());
    assert_eq!(get(&conn, made.id).expect("get"), made);
    assert_eq!(list(&conn).expect("list"), vec![made]);
}

#[test]
fn a_malformed_licence_is_refused() {
    let conn = store();
    for bad in [
        NewLicence { client: "   ".into(), ..new("x") },
        NewLicence { client: "x".repeat(MAX_CLIENT_CHARS + 1), ..new("x") },
        NewLicence { client: "a\nb".into(), ..new("x") },
        NewLicence { terms: "y".repeat(MAX_TERMS_BYTES + 1), ..new("x") },
        NewLicence { terms: "bell\u{7}".into(), ..new("x") },
    ] {
        assert!(matches!(create(&conn, &bad), Err(Error::InvalidLicence)));
    }
    assert!(list(&conn).expect("list").is_empty());
}

#[test]
fn the_end_date_is_normalised_and_must_be_in_the_future() {
    let conn = store();
    let future = create(
        &conn,
        &NewLicence { expires_at: Some("2999-01-31".into()), ..new("Acme") },
    )
    .expect("create");
    assert_eq!(future.expires_at.as_deref(), Some("2999-01-31 00:00:00"));
    for bad in ["2000-01-01", "not a date", "2999-13-45"] {
        let result = create(
            &conn,
            &NewLicence { expires_at: Some(bad.into()), ..new("Acme") },
        );
        assert!(matches!(result, Err(Error::InvalidLicence)), "{bad}");
    }
    let blank = create(&conn, &NewLicence { expires_at: Some("  ".into()), ..new("Acme") })
        .expect("a blank date is no date");
    assert!(blank.expires_at.is_none());
}

#[test]
fn voiding_is_once_records_the_reason_and_ends_the_licence() {
    let conn = store();
    let made = create(&conn, &new("Acme")).expect("create");
    assert!(mark_void(&conn, made.id, Some("  unpaid  ")).expect("void"));
    assert!(!mark_void(&conn, made.id, Some("again")).expect("void twice"));
    let voided = get(&conn, made.id).expect("get");
    assert!(!voided.active);
    assert_eq!(voided.void_reason.as_deref(), Some("unpaid"));
    assert!(voided.voided_at.is_some());
    assert!(matches!(mark_void(&conn, 99, None), Err(Error::LicenceNotFound)));
    let other = create(&conn, &new("Beta")).expect("create");
    assert!(matches!(
        mark_void(&conn, other.id, Some(&"r".repeat(MAX_REASON_CHARS + 1))),
        Err(Error::InvalidLicence)
    ));
    assert!(get(&conn, other.id).expect("get").active);
}

#[test]
fn time_remaining_is_refused_for_a_voided_or_ended_licence() {
    let conn = store();
    let open = create(&conn, &new("Acme")).expect("create");
    assert_eq!(seconds_remaining(&conn, &open).expect("open"), None);
    let dated = create(
        &conn,
        &NewLicence { expires_at: Some("2999-01-01".into()), ..new("Beta") },
    )
    .expect("create");
    assert!(seconds_remaining(&conn, &dated).expect("dated").expect("some") > 0);
    mark_void(&conn, open.id, None).expect("void");
    assert!(matches!(
        seconds_remaining(&conn, &open),
        Err(Error::LicenceNotActive)
    ));
    let dyn_conn: &dyn Sql = &conn;
    dyn_conn
        .execute(
            "UPDATE licences SET expires_at = datetime('now', '-1 minute') WHERE id = ?1",
            params![dated.id],
        )
        .expect("age");
    let aged = get(&conn, dated.id).expect("get");
    assert!(!aged.active);
    assert!(matches!(
        seconds_remaining(&conn, &aged),
        Err(Error::LicenceNotActive)
    ));
}

#[test]
fn the_statement_names_the_licensee_scope_dates_and_terms() {
    let conn = store();
    let made = create(
        &conn,
        &NewLicence { expires_at: Some("2999-01-01".into()), ..new("Acme") },
    )
    .expect("create");
    let text = statement(&made, "inbox.push", "2026-10-06 12:00:00");
    assert!(text.starts_with(&format!("KeyQuorum licence {}\n", made.id)));
    assert!(text.contains("Licensee: Acme\n"));
    assert!(text.contains("Scope: inbox.push\n"));
    assert!(text.contains("Issued: 2026-10-06 12:00:00 UTC\n"));
    assert!(text.contains("Ends: 2999-01-01 00:00:00 UTC\n"));
    assert!(text.ends_with("Seats: 5.\n"));
    let open = create(&conn, &NewLicence { terms: String::new(), ..new("Beta") }).expect("create");
    let text = statement(&open, "inbox.pull", "2026-10-06 12:00:00");
    assert!(text.contains("Ends: no fixed end\n"));
    assert!(text.ends_with("no fixed end\n"));
}
