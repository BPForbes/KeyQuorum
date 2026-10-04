use super::*;

const INBOX: Table = Table {
    rings: "inbox_rings",
    slots: "inbox_slots",
    key: "relay_url",
    content: None,
};

const URL: &str = "https://relay.test";

fn store() -> Connection {
    crate::db::open_in_memory().expect("store")
}

/// Take the slot at the write pointer for letter `id`; its index.
fn take(conn: &Connection, id: i64) -> u32 {
    let ring = ensure(conn, &INBOX, URL, 3).unwrap();
    assert!(!ring.is_full());
    conn.execute(
        "INSERT INTO inbox_slots (relay_url, slot_index, letter_id, envelope_kind, content_hash)
         VALUES (?1, ?2, ?3, 1, 'h')",
        params![URL, ring.write_index, id],
    )
    .unwrap();
    advance_write(conn, &INBOX, URL).unwrap();
    ring.write_index
}

fn pointers(conn: &Connection) -> Pointers {
    load(conn, &INBOX, URL).unwrap().unwrap()
}

#[test]
fn a_slot_released_out_of_order_is_reused_only_once_the_head_has_gone() {
    let conn = store();
    let (a, b, c) = (take(&conn, 1), take(&conn, 2), take(&conn, 3));
    assert_eq!((a, b, c), (0, 1, 2));
    assert!(pointers(&conn).is_full());

    // The middle letter leaves first: the head still holds slot 0, so the
    // ring stays full and nothing is overwritten.
    release(&conn, &INBOX, URL, b).unwrap();
    let p = pointers(&conn);
    assert_eq!((p.read_index, p.size), (0, 3));
    assert!(p.is_full());

    // The head leaves: the read pointer moves past it and the slot released
    // before it, freeing both.
    release(&conn, &INBOX, URL, a).unwrap();
    let p = pointers(&conn);
    assert_eq!((p.read_index, p.write_index, p.size), (2, 0, 1));
    assert_eq!(take(&conn, 4), 0, "the ring wraps into the freed slot");

    release(&conn, &INBOX, URL, c).unwrap();
    release(&conn, &INBOX, URL, 0).unwrap();
    assert_eq!(pointers(&conn).size, 0);
}

#[test]
fn only_an_empty_ring_is_resized() {
    let conn = store();
    let index = take(&conn, 1);
    assert!(!resize(&conn, &INBOX, URL, 8).unwrap());
    release(&conn, &INBOX, URL, index).unwrap();
    assert!(resize(&conn, &INBOX, URL, 8).unwrap());
    assert_eq!(pointers(&conn).capacity, 8);
}

#[test]
fn a_released_slot_with_content_is_overwritten_before_it_is_deleted() {
    let conn = store();
    let outbox = Table {
        rings: "outbox_rings",
        slots: "outbox_slots",
        key: "owner_label",
        content: Some("content"),
    };
    let ring = ensure(&conn, &outbox, "alice", 4).unwrap();
    conn.execute(
        "INSERT INTO outbox_slots
         (owner_label, slot_index, envelope_kind, recipient_label, content, content_hash)
         VALUES ('alice', ?1, 1, 'bob', x'0102030405', 'h')",
        params![ring.write_index],
    )
    .unwrap();
    advance_write(&conn, &outbox, "alice").unwrap();
    // Watch the row as it is wiped: the content is zeroed, then deleted.
    conn.execute_batch(
        "CREATE TEMP TABLE seen (content BLOB);
         CREATE TEMP TRIGGER watch BEFORE DELETE ON outbox_slots
         BEGIN INSERT INTO seen VALUES (old.content); END;",
    )
    .unwrap();
    release(&conn, &outbox, "alice", ring.write_index).unwrap();
    let seen: Vec<u8> = conn
        .query_row("SELECT content FROM seen", [], |row| row.get(0))
        .unwrap();
    assert_eq!(seen, vec![0u8; 5]);
    assert_eq!(load(&conn, &outbox, "alice").unwrap().unwrap().size, 0);
}
