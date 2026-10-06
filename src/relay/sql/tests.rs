use super::{Sql, Value};
use crate::error::Error;
use rusqlite::Connection;

fn db() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, data BLOB, n INTEGER);")
        .expect("schema");
    conn
}

fn sql(conn: &Connection) -> &dyn Sql {
    conn
}

#[test]
fn values_round_trip_through_a_row() {
    let conn = db();
    let s = sql(&conn);
    s.execute(
        "INSERT INTO t (name, data, n) VALUES (?1, ?2, ?3)",
        params!["alpha", &[1u8, 2, 3][..], true],
    )
    .expect("insert");
    assert_eq!(s.changes(), 1);
    assert_eq!(s.last_insert_rowid(), 1);
    let (name, data, n): (String, Vec<u8>, bool) = s
        .query_row(
            "SELECT name, data, n FROM t WHERE id = ?1",
            params![1i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("row");
    assert_eq!((name.as_str(), data, n), ("alpha", vec![1, 2, 3], true));
}

#[test]
fn null_and_option_parameters() {
    let conn = db();
    let s = sql(&conn);
    s.execute(
        "INSERT INTO t (name, data) VALUES (?1, ?2)",
        params![None::<&str>, Some(vec![9u8])],
    )
    .expect("insert");
    let (name, data): (Option<String>, Option<Vec<u8>>) = s
        .query_row("SELECT name, data FROM t", params![], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("row");
    assert_eq!((name, data), (None, Some(vec![9])));
}

#[test]
fn a_missing_row_is_no_rows_for_query_row_and_none_for_query_opt() {
    let conn = db();
    let s = sql(&conn);
    let missing = s.query_row("SELECT id FROM t", params![], |row| row.get::<i64>(0));
    assert!(matches!(
        missing,
        Err(Error::Db(rusqlite::Error::QueryReturnedNoRows))
    ));
    let none = s
        .query_opt("SELECT id FROM t", params![], |row| row.get::<i64>(0))
        .expect("query");
    assert_eq!(none, None);
}

#[test]
fn query_map_keeps_order_and_query_each_stops_early() {
    let conn = db();
    let s = sql(&conn);
    for n in 0..5i64 {
        s.execute("INSERT INTO t (n) VALUES (?1)", params![n])
            .expect("insert");
    }
    let all = s
        .query_map("SELECT n FROM t ORDER BY id", params![], |row| {
            row.get::<i64>(0)
        })
        .expect("rows");
    assert_eq!(all, vec![0, 1, 2, 3, 4]);

    let mut seen = 0;
    s.query_each("SELECT n FROM t ORDER BY id", params![], &mut |_| {
        seen += 1;
        Ok(seen < 3)
    })
    .expect("stream");
    assert_eq!(seen, 3);
}

#[test]
fn a_wrong_column_type_names_the_column_and_not_the_value() {
    let conn = db();
    let s = sql(&conn);
    let secret = "a-value-that-must-not-be-printed";
    s.execute("INSERT INTO t (name) VALUES (?1)", params![secret])
        .expect("insert");
    let wrong = s.query_row("SELECT name FROM t", params![], |row| row.get::<i64>(0));
    let text = match wrong {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a text column read as an integer"),
    };
    assert!(text.contains("column 0"), "{text}");
    assert!(!text.contains(secret));
    let missing = s.query_row("SELECT name FROM t", params![], |row| row.get::<String>(4));
    assert!(missing.is_err());
}

#[test]
fn a_transaction_commits_on_ok_and_rolls_back_on_err() {
    let conn = db();
    let s = sql(&conn);
    s.with_transaction(|| {
        s.execute("INSERT INTO t (n) VALUES (1)", params![])?;
        Ok(())
    })
    .expect("commit");
    let failed: Result<(), Error> = s.with_transaction(|| {
        s.execute("INSERT INTO t (n) VALUES (2)", params![])?;
        Err(Error::Store("stop".into()))
    });
    assert!(failed.is_err());
    let count: i64 = s
        .query_row("SELECT COUNT(*) FROM t", params![], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 1);
}

#[test]
fn a_nested_transaction_joins_the_outer_one() {
    let conn = db();
    let s = sql(&conn);
    let outer: Result<(), Error> = s.with_transaction(|| {
        s.with_transaction(|| {
            s.execute("INSERT INTO t (n) VALUES (1)", params![])?;
            Ok(())
        })?;
        Err(Error::Store("outer fails after the inner returned".into()))
    });
    assert!(outer.is_err());
    let count: i64 = s
        .query_row("SELECT COUNT(*) FROM t", params![], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 0, "the inner block must not commit on its own");
}

#[test]
fn debug_never_prints_content() {
    let secret = "a-value-that-must-not-be-printed";
    let text = format!("{:?}", Value::from(secret));
    assert!(!text.contains(secret));
    assert!(!format!("{:?}", Value::Blob(vec![7, 7, 7])).contains('7'));
}
