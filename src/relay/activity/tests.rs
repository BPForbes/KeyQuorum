use super::*;
use crate::relay::customer::{self, NewCustomer};
use crate::relay::licence::{self, KeyLink, NewLicence};
use crate::relay::{self, ApiKeyScope, NewApiKey};
use rusqlite::Connection;

fn store() -> Connection {
    relay::open_in_memory().expect("schema")
}

fn key(conn: &Connection) -> (i64, String) {
    let created = relay::create_api_key(
        conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: Some("activity".into()),
            ttl_seconds: None,
        },
    )
    .expect("key");
    (created.info.id, created.token.as_str().to_owned())
}

fn cost(millis: u32, bytes_in: u64, bytes_out: u64) -> Cost {
    Cost { millis, bytes_in, bytes_out }
}

type Row4 = (i64, String, String, i64);

fn rows(conn: &Connection) -> Vec<Row4> {
    let dyn_conn: &dyn Sql = conn;
    dyn_conn
        .query_map(
            "SELECT api_key_id, route, outcome, count FROM access_activity
             ORDER BY api_key_id, route, outcome",
            params![],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("rows")
}

fn window(hours: i64) -> Filter {
    Filter { hours, ..Filter::default() }
}

#[test]
fn a_route_is_the_first_path_segment_and_nothing_finer() {
    assert_eq!(Route::of_path("/inbox"), Route::Inbox);
    assert_eq!(Route::of_path("inbox/"), Route::Inbox);
    assert_eq!(Route::of_path("/devices/packages"), Route::Devices);
    assert_eq!(Route::of_path("/trees/secret-label/context"), Route::Trees);
    assert_eq!(Route::of_path("/audit/api-keys"), Route::Audit);
    assert_eq!(Route::of_path("/keycheck"), Route::Other);
    assert_eq!(Route::of_path("/"), Route::Other);
    for route in [Route::Inbox, Route::Devices, Route::Trees, Route::Audit, Route::Other] {
        assert_eq!(Route::parse(route.as_str()), Some(route));
    }
    assert_eq!(Route::parse("keys"), None);
}

#[test]
fn a_request_is_classified_by_the_key_and_what_it_was_answered() {
    assert_eq!(classify(false, false, 200), Some(Outcome::Ok));
    assert_eq!(classify(false, false, 204), Some(Outcome::Ok));
    assert_eq!(classify(false, false, 404), Some(Outcome::ClientError));
    assert_eq!(classify(false, false, 413), Some(Outcome::ClientError));
    assert_eq!(classify(false, false, 500), Some(Outcome::ServerError));
    assert_eq!(classify(false, false, 503), Some(Outcome::ServerError));
    assert_eq!(classify(false, false, 401), Some(Outcome::Scope));
    assert_eq!(classify(false, false, 403), Some(Outcome::Scope));
    assert_eq!(classify(true, false, 401), Some(Outcome::Revoked));
    assert_eq!(classify(true, true, 401), Some(Outcome::Revoked));
    assert_eq!(classify(false, true, 401), Some(Outcome::Expired));
    // A dead key on a route that never asked for it says nothing about it.
    assert_eq!(classify(true, false, 200), None);
    assert_eq!(classify(false, true, 404), None);
    for outcome in [Outcome::Ok, Outcome::ClientError, Outcome::ServerError, Outcome::Revoked, Outcome::Expired, Outcome::Scope] {
        assert_eq!(Outcome::parse(outcome.as_str()), Some(outcome));
    }
    assert!(Outcome::Revoked.is_blocked() && Outcome::Expired.is_blocked() && Outcome::Scope.is_blocked());
    assert!(!Outcome::Ok.is_blocked() && !Outcome::ClientError.is_blocked() && !Outcome::ServerError.is_blocked());
}

#[test]
fn requests_of_a_known_key_are_counted_in_place_by_hour_route_and_outcome() {
    let conn = store();
    let (id, token) = key(&conn);
    for _ in 0..3 {
        record(&conn, &token, "/inbox", 200, Cost::default()).expect("record");
    }
    record(&conn, &token, "/devices/packages", 200, Cost::default()).expect("record");
    record(&conn, &token, "/inbox", 403, Cost::default()).expect("record");
    record(&conn, &token, "/inbox", 404, Cost::default()).expect("record");
    record(&conn, &token, "/trees", 500, Cost::default()).expect("record");
    assert_eq!(
        rows(&conn),
        vec![
            (id, "devices".to_string(), "ok".to_string(), 1),
            (id, "inbox".to_string(), "client_error".to_string(), 1),
            (id, "inbox".to_string(), "ok".to_string(), 3),
            (id, "inbox".to_string(), "scope".to_string(), 1),
            (id, "trees".to_string(), "server_error".to_string(), 1),
        ]
    );
}

#[test]
fn time_and_bytes_are_summed_and_the_slowest_is_kept() {
    let conn = store();
    let (id, token) = key(&conn);
    record(&conn, &token, "/inbox", 200, cost(10, 100, 5)).expect("record");
    record(&conn, &token, "/inbox", 200, cost(40, 200, 7)).expect("record");
    record(&conn, &token, "/inbox", 200, cost(20, 0, 0)).expect("record");
    let summary = summary(&conn, &window(24)).expect("summary");
    let row = summary.by_key.iter().find(|a| a.api_key_id == id).expect("row");
    assert_eq!((row.count, row.ms_total, row.ms_max), (3, 70, 40));
    assert_eq!((row.bytes_in, row.bytes_out), (300, 12));
}

#[test]
fn a_revoked_or_expired_key_is_counted_as_blocked() {
    let conn = store();
    let (revoked, revoked_token) = key(&conn);
    relay::revoke_api_key(&conn, revoked).expect("revoke");
    record(&conn, &revoked_token, "/inbox", 401, Cost::default()).expect("record");
    let expired = relay::create_api_key(
        &conn,
        &NewApiKey { scope: ApiKeyScope::InboxPush, recipient_fingerprint: None, label: None, ttl_seconds: Some(3600) },
    )
    .expect("key");
    let dyn_conn: &dyn Sql = &conn;
    dyn_conn
        .execute("UPDATE api_keys SET expires_at = datetime('now', '-1 minute') WHERE id = ?1", params![expired.info.id])
        .expect("age");
    record(&conn, expired.token.as_str(), "/trees", 401, Cost::default()).expect("record");
    let got = rows(&conn);
    assert!(got.contains(&(revoked, "inbox".to_string(), "revoked".to_string(), 1)));
    assert!(got.contains(&(expired.info.id, "trees".to_string(), "expired".to_string(), 1)));
}

#[test]
fn an_unknown_or_malformed_bearer_records_nothing() {
    let conn = store();
    key(&conn);
    for token in ["kq_not-a-real-key", "", "not even prefixed"] {
        record(&conn, token, "/inbox", 401, Cost::default()).expect("record");
    }
    assert!(rows(&conn).is_empty());
}

#[test]
fn a_summary_adds_up_and_clamps_its_window() {
    let conn = store();
    let (id, token) = key(&conn);
    record(&conn, &token, "/inbox", 200, Cost::default()).expect("record");
    record(&conn, &token, "/inbox", 200, Cost::default()).expect("record");
    record(&conn, &token, "/inbox", 403, Cost::default()).expect("record");
    let got = summary(&conn, &window(24)).expect("summary");
    assert_eq!(got.hours, 24);
    let ok = got.by_key.iter().find(|a| a.api_key_id == id && a.outcome == "ok").expect("ok row");
    assert_eq!((ok.route.as_str(), ok.count), ("inbox", 2));
    assert_eq!(got.by_hour.iter().map(|h| h.count).sum::<i64>(), 3);
    assert_eq!(summary(&conn, &window(0)).expect("clamped").hours, 1);
    assert_eq!(summary(&conn, &window(i64::MAX)).expect("clamped").hours, MAX_SUMMARY_HOURS);
}

#[test]
fn a_summary_narrows_by_key_route_outcome_and_customer() {
    let conn = store();
    let (a, token_a) = key(&conn);
    let (b, token_b) = key(&conn);
    record(&conn, &token_a, "/inbox", 200, Cost::default()).expect("record");
    record(&conn, &token_a, "/devices/x", 200, Cost::default()).expect("record");
    record(&conn, &token_b, "/inbox", 403, Cost::default()).expect("record");
    let acme = customer::create(&conn, &NewCustomer { name: "Acme".into(), reference: None }).expect("customer");
    let held = licence::create(&conn, acme.id, &NewLicence { terms: String::new(), expires_at: None, replaces: None }).expect("licence");
    licence::link_key(&conn, &KeyLink { api_key_id: a, licence_id: held.id, licence_version: Some(1), replaces_key_id: None }).expect("link");

    let count = |filter: Filter| summary(&conn, &filter).expect("summary").by_key.iter().map(|r| r.count).sum::<i64>();
    assert_eq!(count(window(24)), 3);
    assert_eq!(count(Filter { key_id: Some(b), ..window(24) }), 1);
    assert_eq!(count(Filter { route: Some(Route::Devices), ..window(24) }), 1);
    assert_eq!(count(Filter { outcome: Some(Outcome::Scope), ..window(24) }), 1);
    assert_eq!(count(Filter { customer_id: Some(acme.id), ..window(24) }), 2, "only the customer's own keys");
    assert_eq!(count(Filter { customer_id: Some(acme.id), outcome: Some(Outcome::Scope), ..window(24) }), 0);
    assert_eq!(count(Filter { customer_id: Some(999), ..window(24) }), 0);
    // The hourly series follows the same filter.
    let hourly = summary(&conn, &Filter { customer_id: Some(acme.id), ..window(24) }).expect("summary");
    assert_eq!(hourly.by_hour.iter().map(|h| h.count).sum::<i64>(), 2);
}

#[test]
fn old_counts_are_dropped_and_recent_ones_kept() {
    let conn = store();
    let (id, token) = key(&conn);
    record(&conn, &token, "/inbox", 200, Cost::default()).expect("record");
    let dyn_conn: &dyn Sql = &conn;
    dyn_conn
        .execute(
            "INSERT INTO access_activity (api_key_id, hour, route, outcome, count)
             VALUES (?1, strftime('%Y-%m-%dT%H:00:00Z', 'now', '-91 days'), 'inbox', 'ok', 5)",
            params![id],
        )
        .expect("old row");
    assert_eq!(purge_old(&conn).expect("purge"), 1);
    assert_eq!(rows(&conn).len(), 1);
}
