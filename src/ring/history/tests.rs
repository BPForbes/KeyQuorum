use super::*;

fn store() -> Connection {
    crate::db::open_in_memory().expect("store")
}

fn queued(conn: &Connection, timeline: Timeline, slot: &str) {
    record(
        conn,
        timeline,
        HistoryEventType::LetterQueued,
        HistoryOutcome::Success,
        Some("alice"),
        EventDetails::new().with("slot", slot).with("to", "bob"),
    )
    .expect("record");
}

#[test]
fn a_timeline_is_a_kqhs_chain_that_round_trips() {
    let conn = store();
    let outbox = Timeline::Outbox("alice");
    assert!(snapshot(&conn, outbox).unwrap().events.is_empty());
    queued(&conn, outbox, "0");
    queued(&conn, outbox, "1");

    let timeline = snapshot(&conn, outbox).unwrap();
    assert_eq!(timeline.file_id, outbox.id());
    assert_eq!(timeline.events.len(), 2);
    assert!(timeline.events.iter().all(|e| e.occurred_at.ends_with('Z')));
    let bytes = timeline.encode().unwrap();
    assert_eq!(&bytes[..4], b"KQHS");
    assert_eq!(HistorySnapshot::decode(&bytes).unwrap(), timeline);
}

#[test]
fn an_earlier_point_is_a_prefix_and_rings_do_not_mix() {
    let conn = store();
    let outbox = Timeline::Outbox("alice");
    queued(&conn, outbox, "0");
    let earlier = snapshot(&conn, outbox).unwrap();
    queued(&conn, outbox, "1");
    let later = snapshot(&conn, outbox).unwrap();
    assert!(earlier.is_prefix_of_snapshot(&later));
    assert!(!later.is_prefix_of_snapshot(&earlier));

    // Another ring has its own id and chain.
    let inbox = Timeline::Inbox("https://relay.example");
    queued(&conn, inbox, "0");
    let other = snapshot(&conn, inbox).unwrap();
    assert_ne!(other.file_id, later.file_id);
    assert!(!earlier.is_prefix_of_snapshot(&other));
}

#[test]
fn a_changed_time_breaks_the_chain() {
    let conn = store();
    let outbox = Timeline::Outbox("alice");
    queued(&conn, outbox, "0");
    queued(&conn, outbox, "1");
    // Move the first event's time back an hour, re-encoded but not re-hashed.
    let first: Vec<u8> = conn
        .query_row(
            "SELECT event FROM ring_events WHERE sequence = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut event = HistoryEvent::from_bytes(&first).unwrap();
    event.occurred_at = "2000-01-01T00:00:00Z".into();
    conn.execute(
        "UPDATE ring_events SET event = ?1 WHERE sequence = 0",
        [event.to_bytes().unwrap()],
    )
    .unwrap();
    assert!(matches!(
        snapshot(&conn, outbox),
        Err(Error::IntegrityCheckFailed)
    ));
}

#[test]
fn a_deleted_last_event_no_longer_matches_the_recorded_head() {
    let conn = store();
    let outbox = Timeline::Outbox("alice");
    queued(&conn, outbox, "0");
    queued(&conn, outbox, "1");
    conn.execute("DELETE FROM ring_events WHERE sequence = 1", [])
        .unwrap();
    assert!(matches!(
        snapshot(&conn, outbox),
        Err(Error::IntegrityCheckFailed)
    ));
}

#[test]
fn only_safe_detail_keys_are_recorded() {
    let conn = store();
    let refused = record(
        &conn,
        Timeline::Outbox("alice"),
        HistoryEventType::LetterQueued,
        HistoryOutcome::Success,
        None,
        EventDetails::new().with("content_hash", "abc"),
    );
    assert!(refused.is_err());
    assert!(snapshot(&conn, Timeline::Outbox("alice"))
        .unwrap()
        .events
        .is_empty());
}
