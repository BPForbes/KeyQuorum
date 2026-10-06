use super::*;
use crate::relay::customer::{self, NewCustomer};
use crate::relay::{self, ApiKeyScope, NewApiKey};
use rusqlite::Connection;

fn store() -> Connection {
    relay::open_in_memory().expect("schema")
}

fn customer(conn: &Connection, name: &str) -> Customer {
    customer::create(conn, &NewCustomer { name: name.into(), reference: None }).expect("customer")
}

fn new(terms: &str) -> NewLicence {
    NewLicence { terms: terms.into(), expires_at: None, replaces: None }
}

fn key(conn: &Connection) -> i64 {
    relay::create_api_key(
        conn,
        &NewApiKey { scope: ApiKeyScope::InboxPush, recipient_fingerprint: None, label: None, ttl_seconds: None },
    )
    .expect("key")
    .info
    .id
}

#[test]
fn a_licence_is_recorded_for_a_customer_with_its_first_statement() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let made = create(&conn, acme.id, &new("  Seats: 5.  ")).expect("create");
    assert_eq!((made.customer_id, made.version, made.terms.as_str()), (acme.id, 1, "Seats: 5."));
    assert!(made.active && made.expires_at.is_none() && made.voided_at.is_none());
    assert_eq!(get(&conn, made.id).expect("get"), made);
    assert_eq!(list_for_customer(&conn, acme.id).expect("list"), vec![made.clone()]);
    assert_eq!(versions(&conn, made.id).expect("versions").len(), 1);
    assert!(matches!(get(&conn, 99), Err(Error::LicenceNotFound)));
    assert_eq!(customer_of(&conn, made.id).expect("owner"), acme);
}

#[test]
fn a_malformed_licence_is_refused_and_leaves_nothing() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    for bad in [
        NewLicence { terms: "y".repeat(MAX_TERMS_BYTES + 1), ..new("") },
        NewLicence { terms: "bell\u{7}".into(), ..new("") },
        NewLicence { expires_at: Some("2000-01-01".into()), ..new("") },
        NewLicence { expires_at: Some("not a date".into()), ..new("") },
        NewLicence { expires_at: Some("2999-13-45".into()), ..new("") },
    ] {
        assert!(matches!(create(&conn, acme.id, &bad), Err(Error::InvalidLicence)));
    }
    assert!(list_for_customer(&conn, acme.id).expect("list").is_empty());
}

#[test]
fn the_end_date_is_normalised_and_a_blank_one_is_none() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let dated = create(&conn, acme.id, &NewLicence { expires_at: Some("2999-01-31".into()), ..new("") }).expect("create");
    assert_eq!(dated.expires_at.as_deref(), Some("2999-01-31 00:00:00"));
    let blank = create(&conn, acme.id, &NewLicence { expires_at: Some("  ".into()), ..new("") }).expect("create");
    assert!(blank.expires_at.is_none());
}

#[test]
fn a_replacement_must_name_a_licence_of_the_same_customer() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let beta = customer(&conn, "Beta");
    let old = create(&conn, acme.id, &new("old")).expect("create");
    let newer = create(&conn, acme.id, &NewLicence { replaces: Some(old.id), ..new("new") }).expect("replace");
    assert_eq!(newer.replaces_licence_id, Some(old.id));
    assert!(matches!(
        create(&conn, beta.id, &NewLicence { replaces: Some(old.id), ..new("x") }),
        Err(Error::InvalidLicence)
    ));
    assert!(matches!(
        create(&conn, acme.id, &NewLicence { replaces: Some(99), ..new("x") }),
        Err(Error::LicenceNotFound)
    ));
}

#[test]
fn a_renewal_adds_a_statement_version_and_never_rewrites_an_old_one() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let made = create(&conn, acme.id, &NewLicence { expires_at: Some("2998-01-01".into()), ..new("Five seats.") }).expect("create");
    let renewed = renew(&conn, made.id, Some("Ten seats."), Some("2999-01-01")).expect("renew");
    assert_eq!((renewed.version, renewed.terms.as_str()), (2, "Ten seats."));
    assert_eq!(renewed.expires_at.as_deref(), Some("2999-01-01 00:00:00"));
    // Terms alone, or the date alone, each make a version and keep the other.
    let dated = renew(&conn, made.id, None, Some("2999-06-01")).expect("date");
    assert_eq!((dated.version, dated.terms.as_str()), (3, "Ten seats."));
    let worded = renew(&conn, made.id, Some("Twelve seats."), None).expect("terms");
    assert_eq!((worded.version, worded.expires_at.as_deref()), (4, Some("2999-06-01 00:00:00")));

    let all = versions(&conn, made.id).expect("versions");
    assert_eq!(all.iter().map(|v| v.version).collect::<Vec<_>>(), [1, 2, 3, 4]);
    assert_eq!(all[0].terms, "Five seats.");
    assert_eq!(all[0].expires_at.as_deref(), Some("2998-01-01 00:00:00"));

    // Nothing to change, a past date, and a voided licence are refused.
    assert!(matches!(renew(&conn, made.id, Some("Twelve seats."), None), Err(Error::InvalidLicence)));
    assert!(matches!(renew(&conn, made.id, None, Some("2000-01-01")), Err(Error::InvalidLicence)));
    assert!(matches!(renew(&conn, made.id, Some("x".repeat(MAX_TERMS_BYTES + 1).as_str()), None), Err(Error::InvalidLicence)));
    mark_void(&conn, made.id, None).expect("void");
    assert!(matches!(renew(&conn, made.id, Some("late"), None), Err(Error::LicenceNotActive)));
    assert_eq!(versions(&conn, made.id).expect("versions").len(), 4);
}

#[test]
fn a_delivered_statement_cannot_be_changed_or_removed_even_by_a_stray_statement() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let made = create(&conn, acme.id, &new("As delivered.")).expect("create");
    let dyn_conn: &dyn Sql = &conn;
    for sql in [
        "UPDATE licence_versions SET terms = 'rewritten'",
        "DELETE FROM licence_versions",
    ] {
        assert!(dyn_conn.execute(sql, params![]).is_err(), "{sql}");
    }
    assert_eq!(get(&conn, made.id).expect("get").terms, "As delivered.");
}

#[test]
fn voiding_is_once_records_the_reason_and_ends_the_licence() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let made = create(&conn, acme.id, &new("")).expect("create");
    assert!(mark_void(&conn, made.id, Some("  unpaid  ")).expect("void"));
    assert!(!mark_void(&conn, made.id, Some("again")).expect("void twice"));
    let voided = get(&conn, made.id).expect("get");
    assert!(!voided.active && voided.voided_at.is_some());
    assert_eq!(voided.void_reason.as_deref(), Some("unpaid"));
    assert!(matches!(mark_void(&conn, 99, None), Err(Error::LicenceNotFound)));
    let other = create(&conn, acme.id, &new("")).expect("create");
    assert!(matches!(
        mark_void(&conn, other.id, Some(&"r".repeat(MAX_REASON_CHARS + 1))),
        Err(Error::InvalidLicence)
    ));
    assert!(get(&conn, other.id).expect("get").active);
}

#[test]
fn time_remaining_is_refused_for_a_voided_or_ended_licence() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let open = create(&conn, acme.id, &new("")).expect("create");
    assert_eq!(seconds_remaining(&conn, &open).expect("open"), None);
    let dated = create(&conn, acme.id, &NewLicence { expires_at: Some("2999-01-01".into()), ..new("") }).expect("create");
    assert!(seconds_remaining(&conn, &dated).expect("dated").expect("some") > 0);
    mark_void(&conn, open.id, None).expect("void");
    assert!(matches!(seconds_remaining(&conn, &open), Err(Error::LicenceNotActive)));
    let dyn_conn: &dyn Sql = &conn;
    dyn_conn
        .execute("UPDATE licences SET expires_at = datetime('now', '-1 minute') WHERE id = ?1", params![dated.id])
        .expect("age");
    assert!(matches!(seconds_remaining(&conn, &dated), Err(Error::LicenceNotActive)));
    // The counts follow the same three states.
    assert_eq!(counts(&conn).expect("counts"), Counts { active: 0, voided: 1, ended: 1 });
}

#[test]
fn a_key_link_records_the_licence_the_version_and_the_key_it_replaced() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let made = create(&conn, acme.id, &new("")).expect("create");
    let (first, second, stray) = (key(&conn), key(&conn), key(&conn));
    link_key(&conn, &KeyLink { api_key_id: first, licence_id: made.id, licence_version: Some(1), replaces_key_id: None }).expect("link");
    let replacement = KeyLink { api_key_id: second, licence_id: made.id, licence_version: Some(1), replaces_key_id: Some(first) };
    link_key(&conn, &replacement).expect("link");
    assert_eq!(link_of_key(&conn, second).expect("link"), Some(replacement));
    assert_eq!(link_of_key(&conn, stray).expect("none"), None);
    assert_eq!(keys_of(&conn, made.id).expect("keys"), [first, second]);
    assert_eq!(all_links(&conn).expect("links").len(), 2);
    // A key belongs to one licence, once.
    assert!(link_key(&conn, &KeyLink { api_key_id: first, licence_id: made.id, licence_version: None, replaces_key_id: None }).is_err());
}

#[test]
fn the_statement_names_the_licensee_version_scope_dates_and_terms() {
    let conn = store();
    let acme = customer(&conn, "Acme");
    let made = create(&conn, acme.id, &NewLicence { expires_at: Some("2999-01-01".into()), ..new("Seats: 5.") }).expect("create");
    let text = statement(&acme, &made, "inbox.push", "2026-10-06 12:00:00");
    assert!(text.starts_with(&format!("KeyQuorum licence {} (statement 1)\n", made.id)));
    assert!(text.contains("Licensee: Acme\n"));
    assert!(text.contains("Scope: inbox.push\n"));
    assert!(text.contains("Issued: 2026-10-06 12:00:00 UTC\n"));
    assert!(text.contains("Ends: 2999-01-01 00:00:00 UTC\n"));
    assert!(text.ends_with("Seats: 5.\n"));
    let open = create(&conn, acme.id, &new("")).expect("create");
    assert!(statement(&acme, &open, "inbox.pull", "2026-10-06 12:00:00").ends_with("Ends: no fixed end\n"));
    let renewed = renew(&conn, made.id, Some("Ten seats."), None).expect("renew");
    assert!(statement(&acme, &renewed, "inbox.push", "2026-10-06 12:00:00").contains("(statement 2)"));
}
