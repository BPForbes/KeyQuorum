use super::*;

fn rows(sizes: &[usize]) -> Vec<(i64, usize)> {
    sizes
        .iter()
        .enumerate()
        .map(|(i, len)| (i as i64 + 1, *len))
        .collect()
}

fn bound(sizes: &[usize], page: i64) -> (Vec<(i64, usize)>, Option<i64>) {
    bound_page(
        rows(sizes).into_iter().map(Ok::<_, ()>),
        page,
        |r| r.0,
        |r| r.1,
    )
    .expect("no row fails")
}

#[test]
fn a_short_page_has_no_next_page() {
    let (kept, next) = bound(&[10, 10], 5);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, None);
}

#[test]
fn the_extra_row_fetched_to_detect_a_next_page_is_dropped() {
    let (kept, next) = bound(&[10, 10, 10], 2);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, Some(2));
}

#[test]
fn a_page_stops_before_the_byte_budget_and_points_at_the_last_letter_kept() {
    let third = MAX_INBOX_PAGE_BYTES / 3 + 1;
    let (kept, next) = bound(&[third, third, third, third], 100);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, Some(2));
}

#[test]
fn a_page_at_exactly_the_budget_is_kept_whole() {
    let (kept, next) = bound(&[MAX_INBOX_PAGE_BYTES / 2, MAX_INBOX_PAGE_BYTES / 2], 100);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, None);
}

#[test]
fn the_first_letter_is_always_returned_even_over_the_budget() {
    let (kept, next) = bound(&[MAX_INBOX_PAGE_BYTES + 1, 10], 100);
    assert_eq!(kept.len(), 1);
    assert_eq!(next, Some(1));
}

#[test]
fn a_page_stops_pulling_rows_once_it_is_decided() {
    let third = MAX_INBOX_PAGE_BYTES / 3 + 1;
    let pulled = std::cell::Cell::new(0);
    let source = rows(&[third; 50]).into_iter().map(|row| {
        pulled.set(pulled.get() + 1);
        Ok::<_, ()>(row)
    });
    let (kept, next) = bound_page(source, 100, |r| r.0, |r| r.1).expect("no row fails");
    assert_eq!(kept.len(), 2);
    assert_eq!(next, Some(2));
    // The two kept and the one that did not fit: never the other forty-seven.
    assert_eq!(pulled.get(), 3);
}

#[test]
fn a_row_that_fails_to_read_fails_the_page() {
    let source = vec![Ok((1, 10)), Err("unreadable"), Ok((3, 10))];
    let result = bound_page(source, 5, |r: &(i64, usize)| r.0, |r| r.1);
    assert_eq!(result.unwrap_err(), "unreadable");
}

#[test]
fn a_mailbox_from_before_held_letters_gets_the_columns_once() {
    let conn = rusqlite::Connection::open_in_memory().expect("memory database");
    conn.execute_batch(
        "CREATE TABLE mailbox (id INTEGER PRIMARY KEY, envelope BLOB NOT NULL);
         INSERT INTO mailbox (envelope) VALUES (x'01');",
    )
    .expect("old table");
    let sql: &dyn Sql = &conn;
    ensure_blob_columns(sql).expect("first run");
    ensure_blob_columns(sql).expect("a second run changes nothing");
    let ready: i64 = conn
        .query_row("SELECT blob_ready FROM mailbox WHERE id = 1", [], |row| {
            row.get(0)
        })
        .expect("blob_ready exists");
    assert_eq!(ready, 1, "an old letter is ready");
    let held: Option<i64> = conn
        .query_row("SELECT blob_len FROM mailbox WHERE id = 1", [], |row| {
            row.get(0)
        })
        .expect("blob_len exists");
    assert_eq!(held, None, "an old letter has no held length");
    let expires: Option<String> = conn
        .query_row("SELECT expires_at FROM mailbox WHERE id = 1", [], |row| {
            row.get(0)
        })
        .expect("expires_at exists");
    assert_eq!(expires, None);
    // A table that is not there yet is left for the schema to create.
    ensure_blob_columns(sql).expect("device_mailbox is absent");
}
