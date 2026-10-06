use super::*;
use crate::relay::licence::{self, NewLicence};
use crate::relay::{self, ApiKeyScope, NewApiKey};
use rusqlite::Connection;

fn store() -> Connection {
    relay::open_in_memory().expect("schema")
}

fn made(conn: &Connection, name: &str) -> Customer {
    create(
        conn,
        &NewCustomer {
            name: name.to_string(),
            reference: None,
        },
    )
    .expect("customer")
}

fn licence_for(conn: &Connection, customer: i64, ends: Option<&str>) -> licence::Licence {
    licence::create(
        conn,
        customer,
        &NewLicence {
            terms: String::new(),
            expires_at: ends.map(str::to_string),
            replaces: None,
        },
    )
    .expect("licence")
}

fn names(page: &Page<UserRow>) -> Vec<String> {
    page.items.iter().map(|r| r.customer.name.clone()).collect()
}

#[test]
fn a_customer_is_recorded_trimmed_with_an_optional_unique_reference() {
    let conn = store();
    let first = create(
        &conn,
        &NewCustomer {
            name: "  Acme Ltd  ".into(),
            reference: Some("  C-100 ".into()),
        },
    )
    .expect("create");
    assert_eq!(first.name, "Acme Ltd");
    assert_eq!(first.reference.as_deref(), Some("C-100"));
    assert_eq!(get(&conn, first.id).expect("get"), first);
    // The same reference twice is refused; a blank one is none, repeatable.
    let again = create(
        &conn,
        &NewCustomer { name: "Other".into(), reference: Some("C-100".into()) },
    );
    assert!(matches!(again, Err(Error::InvalidLicence)));
    for name in ["Beta", "Gamma"] {
        let blank = create(&conn, &NewCustomer { name: name.into(), reference: Some("  ".into()) })
            .expect("blank reference");
        assert!(blank.reference.is_none());
    }
    assert_eq!(count(&conn).expect("count"), 3);
    assert!(matches!(get(&conn, 99), Err(Error::CustomerNotFound)));
}

#[test]
fn a_malformed_customer_is_refused() {
    let conn = store();
    for bad in [
        NewCustomer { name: "   ".into(), reference: None },
        NewCustomer { name: "x".repeat(MAX_NAME_CHARS + 1), reference: None },
        NewCustomer { name: "a\nb".into(), reference: None },
        NewCustomer { name: "ok".into(), reference: Some("r".repeat(MAX_REFERENCE_CHARS + 1)) },
        NewCustomer { name: "ok".into(), reference: Some("a\u{7}b".into()) },
    ] {
        assert!(matches!(create(&conn, &bad), Err(Error::InvalidLicence)));
    }
    assert_eq!(count(&conn).expect("count"), 0);
}

#[test]
fn a_list_pages_newest_first_with_a_cursor_that_ends() {
    let conn = store();
    for n in 1..=5 {
        made(&conn, &format!("Customer {n}"));
    }
    let first = list(&conn, None, LicenceFilter::All, None, Some(2)).expect("page");
    assert_eq!(names(&first), ["Customer 5", "Customer 4"]);
    let second = list(&conn, None, LicenceFilter::All, first.next_before, Some(2)).expect("page");
    assert_eq!(names(&second), ["Customer 3", "Customer 2"]);
    let third = list(&conn, None, LicenceFilter::All, second.next_before, Some(2)).expect("page");
    assert_eq!(names(&third), ["Customer 1"]);
    assert_eq!(third.next_before, None);
    // The limit is clamped, never zero and never unbounded.
    assert_eq!(list(&conn, None, LicenceFilter::All, None, Some(0)).expect("page").items.len(), 1);
    assert_eq!(list(&conn, None, LicenceFilter::All, None, Some(10_000)).expect("page").items.len(), 5);
}

#[test]
fn search_matches_a_name_or_reference_and_takes_pattern_characters_literally() {
    let conn = store();
    made(&conn, "Acme Ltd");
    made(&conn, "100% Pure");
    made(&conn, "Under_score");
    create(&conn, &NewCustomer { name: "Beta".into(), reference: Some("CONTRACT-77".into()) }).expect("create");
    let find = |term: &str| names(&list(&conn, Some(term), LicenceFilter::All, None, None).expect("page"));
    assert_eq!(find("acme"), ["Acme Ltd"]);
    assert_eq!(find("contract-7"), ["Beta"]);
    assert_eq!(find("100%"), ["100% Pure"]);
    assert_eq!(find("%"), ["100% Pure"], "a percent sign is not a wildcard");
    assert_eq!(find("_"), ["Under_score"], "an underscore is not a wildcard");
    assert_eq!(find("\\"), Vec::<String>::new());
    assert_eq!(find("   ").len(), 4, "a blank search is no search");
    assert!(find("nothing like it").is_empty());
}

#[test]
fn a_row_counts_licences_live_keys_and_last_use_and_the_filter_follows_the_licences_in_force() {
    let conn = store();
    let with = made(&conn, "With licence");
    let without = made(&conn, "Without licence");
    let ended = made(&conn, "Ended");
    let active = licence_for(&conn, with.id, None);
    let dyn_conn: &dyn Sql = &conn;
    let old = licence_for(&conn, ended.id, Some("2999-01-01"));
    dyn_conn
        .execute("UPDATE licences SET expires_at = datetime('now', '-1 day') WHERE id = ?1", params![old.id])
        .expect("age");
    licence_for(&conn, with.id, None);
    // A live and a revoked key under the first licence.
    let live = relay::create_api_key(
        &conn,
        &NewApiKey { scope: ApiKeyScope::InboxPush, recipient_fingerprint: None, label: None, ttl_seconds: None },
    )
    .expect("key");
    let revoked = relay::create_api_key(
        &conn,
        &NewApiKey { scope: ApiKeyScope::InboxPush, recipient_fingerprint: None, label: None, ttl_seconds: None },
    )
    .expect("key");
    relay::revoke_api_key(&conn, revoked.info.id).expect("revoke");
    for key in [live.info.id, revoked.info.id] {
        licence::link_key(
            &conn,
            &licence::KeyLink { api_key_id: key, licence_id: active.id, licence_version: Some(1), replaces_key_id: None },
        )
        .expect("link");
    }
    dyn_conn
        .execute("UPDATE api_keys SET last_used_at = '2026-10-05T10:00:00.000Z' WHERE id = ?1", params![live.info.id])
        .expect("use");

    let all = list(&conn, None, LicenceFilter::All, None, None).expect("page");
    let row = all.items.iter().find(|r| r.customer.id == with.id).expect("row");
    assert_eq!((row.licences, row.active_licences, row.live_keys), (2, 2, 1));
    assert_eq!(row.last_used_at.as_deref(), Some("2026-10-05T10:00:00.000Z"));
    let ended_row = all.items.iter().find(|r| r.customer.id == ended.id).expect("row");
    assert_eq!((ended_row.licences, ended_row.active_licences), (1, 0));

    let active_only = list(&conn, None, LicenceFilter::WithActive, None, None).expect("page");
    assert_eq!(names(&active_only), ["With licence"]);
    let inactive = list(&conn, None, LicenceFilter::WithoutActive, None, None).expect("page");
    assert_eq!(names(&inactive), ["Ended", "Without licence"]);
    let _ = without;
    // A filtered page still pages: the cursor skips what the filter dropped.
    let first = list(&conn, None, LicenceFilter::WithoutActive, None, Some(1)).expect("page");
    let next = list(&conn, None, LicenceFilter::WithoutActive, first.next_before, Some(1)).expect("page");
    assert_eq!((names(&first), names(&next)), (vec!["Ended".to_string()], vec!["Without licence".to_string()]));
}

#[test]
fn a_filter_is_read_from_its_name_and_nothing_else() {
    assert_eq!(LicenceFilter::parse("all").expect("all"), LicenceFilter::All);
    assert_eq!(LicenceFilter::parse("active").expect("active"), LicenceFilter::WithActive);
    assert_eq!(LicenceFilter::parse("inactive").expect("inactive"), LicenceFilter::WithoutActive);
    assert!(LicenceFilter::parse("ACTIVE").is_err());
    assert!(LicenceFilter::parse("'; DROP TABLE customers; --").is_err());
}
