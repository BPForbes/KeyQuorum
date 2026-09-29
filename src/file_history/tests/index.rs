use super::*;
use crate::file_history::index;
use rusqlite::Connection;

fn db() -> Connection {
    crate::db::open_in_memory().unwrap()
}

fn rev(parents: Vec<[u8; 32]>, at: &str, label: &str) -> NewRevision {
    let mut new = new_revision(parents, at);
    new.author_hcp_label = label.to_string();
    new
}

/// Two tracked files; the first has a fork.
fn files() -> (TrackedFile, TrackedFile) {
    let mut a = TrackedFile::with_policy([1; 16], "a.txt", FilePolicy::standard("M.A"));
    let base = a
        .check_in(rev(vec![], T1, "M.A"), b"secret payload".to_vec())
        .unwrap();
    a.check_in(rev(vec![base], T2, "M.A.1"), b"left".to_vec())
        .unwrap();
    a.check_in(
        rev(vec![base], "2026-10-02T15:00:00Z", "M.S.1"),
        b"right".to_vec(),
    )
    .unwrap();
    a.append(new_event(HistoryEventType::TrackingStarted, Some(base)))
        .unwrap();
    a.append(sparse_event()).unwrap();
    let b = TrackedFile::new([2; 16], "b.txt");
    (a, b)
}

#[test]
fn record_and_list_round_trip() {
    let conn = db();
    let (a, b) = files();
    index::record(&conn, &a).unwrap();
    index::record(&conn, &b).unwrap();
    let listed = index::list(&conn).unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].logical_name, "a.txt");
    assert_eq!(listed[0].file_id, [1; 16]);
    assert_eq!(listed[0].scope_root.as_deref(), Some("M.A"));
    assert_eq!(listed[0].history_root, a.history_root());
    assert_eq!((listed[0].head_count, listed[0].event_count), (2, 2));
    assert_eq!(listed[1].scope_root, None);
    assert_eq!((listed[1].head_count, listed[1].event_count), (0, 0));

    let events = index::events(&conn, &[1; 16]).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, "TrackingStarted");
    assert_eq!(events[0].actor_label.as_deref(), Some("M.A"));
    assert_eq!(
        events[0].revision_id,
        Some(a.revisions()[0].revision.revision_id)
    );
    assert_eq!(events[1].actor_label, None);
    assert_eq!(events[1].outcome, "Denied");
}

#[test]
fn revisions_record_parents_labels_and_heads() {
    let conn = db();
    let (a, _) = files();
    index::record(&conn, &a).unwrap();
    let mut statement = conn
        .prepare(
            "SELECT ordinal, length(parent_ids), author_label, is_head
             FROM tracked_revisions ORDER BY ordinal",
        )
        .unwrap();
    let rows: Vec<(i64, i64, String, i64)> = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        rows,
        vec![
            (0, 0, "M.A".into(), 0),
            (1, 32, "M.A.1".into(), 1),
            (2, 32, "M.S.1".into(), 1),
        ]
    );
}

#[test]
fn recording_again_replaces_rather_than_duplicates() {
    let conn = db();
    let (mut a, _) = files();
    index::record(&conn, &a).unwrap();
    let heads = a.graph().heads();
    a.check_in(
        rev(heads, "2026-10-03T00:00:00Z", "M.A"),
        b"merged".to_vec(),
    )
    .unwrap();
    index::record(&conn, &a).unwrap();
    index::record(&conn, &a).unwrap();
    let listed = index::list(&conn).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].head_count, 1);
    let revisions: i64 = conn
        .query_row("SELECT count(*) FROM tracked_revisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(revisions, 4);
    let events: i64 = conn
        .query_row("SELECT count(*) FROM tracked_history_index", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(events, 2);
}

#[test]
fn forget_and_rebuild_leave_exactly_what_the_containers_say() {
    let conn = db();
    let (a, b) = files();
    index::record(&conn, &a).unwrap();
    index::record(&conn, &b).unwrap();
    index::forget(&conn, &[2; 16]).unwrap();
    assert_eq!(index::list(&conn).unwrap().len(), 1);
    // Cascade: the forgotten file leaves no revision or event rows.
    index::forget(&conn, &[1; 16]).unwrap();
    for table in ["tracked_revisions", "tracked_history_index"] {
        let n: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "{table}");
    }
    // A rebuild drops stale rows and restores the rest.
    index::record(&conn, &b).unwrap();
    index::rebuild(&conn, std::slice::from_ref(&a)).unwrap();
    let listed = index::list(&conn).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].file_id, [1; 16]);
}

#[test]
fn the_index_holds_metadata_only() {
    let conn = db();
    let (a, _) = files();
    index::record(&conn, &a).unwrap();
    for table in [
        "tracked_files",
        "tracked_revisions",
        "tracked_history_index",
    ] {
        let mut statement = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap();
        let columns: Vec<String> = statement
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(
            columns
                .iter()
                .all(|c| !c.contains("payload") && !c.contains("secret")),
            "{table}: {columns:?}"
        );
    }
}

#[test]
fn a_failed_rebuild_leaves_the_previous_index_untouched() {
    let conn = db();
    let (a, b) = files();
    index::record(&conn, &b).unwrap();
    let before = index::list(&conn).unwrap();
    // A second "file" that reuses the first one's revision ids makes the
    // second insert fail after the clear and the first file's rows.
    let mut clash = a.clone();
    clash.file_id = [3; 16];
    assert!(index::rebuild(&conn, &[a, clash]).is_err());
    assert_eq!(index::list(&conn).unwrap(), before);
    let revisions: i64 = conn
        .query_row("SELECT count(*) FROM tracked_revisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        revisions, 0,
        "b has no revisions, and nothing from a leaked in"
    );
}

#[test]
fn revisions_are_indexed_by_file() {
    let conn = db();
    let plan: String = conn
        .query_row(
            "EXPLAIN QUERY PLAN SELECT * FROM tracked_revisions WHERE file_id = x'00'",
            [],
            |r| r.get(3),
        )
        .unwrap();
    assert!(plan.contains("tracked_revisions_by_file"), "{plan}");
}
