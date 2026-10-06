use super::*;
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

fn rows(conn: &Connection) -> Vec<(i64, String, String, i64)> {
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

#[test]
fn a_route_is_the_first_path_segment_and_nothing_finer() {
    assert_eq!(Route::of_path("/inbox"), Route::Inbox);
    assert_eq!(Route::of_path("inbox/"), Route::Inbox);
    assert_eq!(Route::of_path("/devices/packages"), Route::Devices);
    assert_eq!(Route::of_path("/trees/secret-label/context"), Route::Trees);
    assert_eq!(Route::of_path("/audit/api-keys"), Route::Audit);
    assert_eq!(Route::of_path("/keycheck"), Route::Other);
    assert_eq!(Route::of_path("/"), Route::Other);
}

#[test]
fn a_request_is_classified_by_the_key_and_what_it_was_answered() {
    assert_eq!(classify(false, false, 200), Some(Outcome::Ok));
    assert_eq!(classify(false, false, 404), Some(Outcome::Ok));
    assert_eq!(classify(false, false, 401), Some(Outcome::Scope));
    assert_eq!(classify(false, false, 403), Some(Outcome::Scope));
    assert_eq!(classify(true, false, 401), Some(Outcome::Revoked));
    assert_eq!(classify(true, true, 401), Some(Outcome::Revoked));
    assert_eq!(classify(false, true, 401), Some(Outcome::Expired));
    // A dead key on a route that never asked for it says nothing about it,
    // and neither does a server error.
    assert_eq!(classify(true, false, 200), None);
    assert_eq!(classify(false, true, 200), None);
    assert_eq!(classify(false, false, 500), None);
}

#[test]
fn requests_of_a_known_key_are_counted_in_place_by_hour_route_and_outcome() {
    let conn = store();
    let (id, token) = key(&conn);
    for _ in 0..3 {
        record(&conn, &token, "/inbox", 200).expect("record");
    }
    record(&conn, &token, "/devices/packages", 200).expect("record");
    record(&conn, &token, "/inbox", 403).expect("record");
    assert_eq!(
        rows(&conn),
        vec![
            (id, "devices".to_string(), "ok".to_string(), 1),
            (id, "inbox".to_string(), "ok".to_string(), 3),
            (id, "inbox".to_string(), "scope".to_string(), 1),
        ]
    );
}

#[test]
fn a_revoked_or_expired_key_is_counted_as_blocked() {
    let conn = store();
    let (revoked, revoked_token) = key(&conn);
    relay::revoke_api_key(&conn, revoked).expect("revoke");
    record(&conn, &revoked_token, "/inbox", 401).expect("record");
    let expired = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: Some(3600),
        },
    )
    .expect("key");
    let dyn_conn: &dyn Sql = &conn;
    dyn_conn
        .execute(
            "UPDATE api_keys SET expires_at = datetime('now', '-1 minute') WHERE id = ?1",
            params![expired.info.id],
        )
        .expect("age");
    record(&conn, expired.token.as_str(), "/trees", 401).expect("record");
    let got = rows(&conn);
    assert!(got.contains(&(revoked, "inbox".to_string(), "revoked".to_string(), 1)));
    assert!(got.contains(&(expired.info.id, "trees".to_string(), "expired".to_string(), 1)));
}

#[test]
fn an_unknown_or_malformed_bearer_records_nothing() {
    let conn = store();
    key(&conn);
    record(&conn, "kq_not-a-real-key", "/inbox", 401).expect("record");
    record(&conn, "", "/inbox", 401).expect("record");
    record(&conn, "not even prefixed", "/inbox", 401).expect("record");
    assert!(rows(&conn).is_empty());
}

#[test]
fn a_summary_adds_up_per_key_and_per_hour_and_clamps_its_window() {
    let conn = store();
    let (id, token) = key(&conn);
    record(&conn, &token, "/inbox", 200).expect("record");
    record(&conn, &token, "/inbox", 200).expect("record");
    record(&conn, &token, "/inbox", 403).expect("record");
    let summary = summary(&conn, 24).expect("summary");
    assert_eq!(summary.hours, 24);
    let ok = summary
        .by_key
        .iter()
        .find(|a| a.api_key_id == id && a.outcome == "ok")
        .expect("ok row");
    assert_eq!((ok.route.as_str(), ok.count), ("inbox", 2));
    let total: i64 = summary.by_hour.iter().map(|h| h.count).sum();
    assert_eq!(total, 3);
    assert_eq!(super::summary(&conn, 0).expect("clamped").hours, 1);
    assert_eq!(
        super::summary(&conn, i64::MAX).expect("clamped").hours,
        MAX_SUMMARY_HOURS
    );
}

#[test]
fn old_counts_are_dropped_and_recent_ones_kept() {
    let conn = store();
    let (id, token) = key(&conn);
    record(&conn, &token, "/inbox", 200).expect("record");
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
