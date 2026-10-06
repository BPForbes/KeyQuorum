//! The SQLite store against the conformance suite every backend must pass,
//! and the same store over an executor that behaves like a Durable Object's
//! SQL API, where `BEGIN` is refused and a transaction is the host's own.

use super::conformance;
use super::{RelayStore, SqlRelayStore, SqliteRelayStore};
use crate::error::{Error, Result};
use crate::relay::sql::{Row, Sql, Value};
use rusqlite::Connection;
use std::cell::Cell;

fn fresh() -> SqliteRelayStore {
    SqliteRelayStore::open_in_memory().expect("schema")
}

#[test]
fn sqlite_store_passes_the_conformance_suite() {
    for case in conformance::CASES {
        eprintln!("conformance case: {}", case.name);
        let store = fresh();
        (case.run)(&store);
    }
}

#[test]
fn sqlite_store_serializes_concurrent_writers_without_breaking_the_audit_chain() {
    conformance::concurrent_writers_keep_every_invariant(&fresh());
}

#[test]
fn sqlite_store_names_its_backend_and_answers_a_ping() {
    let store = fresh();
    assert_eq!(RelayStore::backend(&store), "sqlite");
    RelayStore::ping(&store).expect("ping");
}

/// An executor that works like a Durable Object's SQL API: every statement
/// the modules run is plain data access, and a transaction statement of their
/// own is refused (a Durable Object points to `transactionSync`). A
/// transaction is the executor's own `transaction`, which nests by joining the
/// outer one and rolls everything back when the body fails.
struct HostTransactions {
    conn: Connection,
    depth: Cell<u32>,
}

impl HostTransactions {
    fn open() -> Self {
        Self {
            conn: crate::relay::open_in_memory().expect("schema"),
            depth: Cell::new(0),
        }
    }
}

fn refuse_transaction_statements(sql: &str) -> Result<()> {
    for statement in sql.split(';') {
        let head = statement
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if ["BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE"].contains(&head.as_str()) {
            return Err(Error::Store(
                "transaction statements are refused; use transaction()".into(),
            ));
        }
    }
    Ok(())
}

impl Sql for HostTransactions {
    fn execute(&self, sql: &str, params: &[Value]) -> Result<usize> {
        refuse_transaction_statements(sql)?;
        Sql::execute(&self.conn, sql, params)
    }

    fn execute_batch(&self, sql: &str) -> Result<()> {
        refuse_transaction_statements(sql)?;
        Sql::execute_batch(&self.conn, sql)
    }

    fn query_each(
        &self,
        sql: &str,
        params: &[Value],
        each: &mut dyn FnMut(&Row) -> Result<bool>,
    ) -> Result<()> {
        refuse_transaction_statements(sql)?;
        Sql::query_each(&self.conn, sql, params, each)
    }

    fn last_insert_rowid(&self) -> Result<i64> {
        Sql::last_insert_rowid(&self.conn)
    }

    fn changes(&self) -> Result<u64> {
        Sql::changes(&self.conn)
    }

    fn transaction(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        if self.depth.get() > 0 {
            return f();
        }
        self.conn.execute_batch("SAVEPOINT host_txn")?;
        self.depth.set(1);
        let outcome = f();
        self.depth.set(0);
        match outcome {
            Ok(()) => Ok(self.conn.execute_batch("RELEASE host_txn")?),
            Err(error) => {
                let _ = self
                    .conn
                    .execute_batch("ROLLBACK TO host_txn; RELEASE host_txn");
                Err(error)
            }
        }
    }
}

fn host_transactions() -> SqlRelayStore<HostTransactions> {
    SqlRelayStore::new(HostTransactions::open(), "host-transactions")
}

#[test]
fn the_executor_refuses_a_transaction_statement_of_its_own() {
    let sql = HostTransactions::open();
    for statement in [
        "BEGIN IMMEDIATE",
        "commit",
        "ROLLBACK",
        "SAVEPOINT x",
        "RELEASE x",
    ] {
        assert!(
            Sql::execute(&sql, statement, &[]).is_err(),
            "{statement} must be refused"
        );
    }
    assert!(Sql::execute_batch(&sql, "SELECT 1; BEGIN").is_err());
}

#[test]
fn a_store_over_a_host_transaction_executor_passes_the_conformance_suite() {
    for case in conformance::CASES {
        eprintln!("conformance case over host transactions: {}", case.name);
        let store = host_transactions();
        (case.run)(&store);
    }
}

#[test]
fn a_store_over_a_host_transaction_executor_serializes_concurrent_writers() {
    conformance::concurrent_writers_keep_every_invariant(&host_transactions());
}

#[test]
fn a_store_reports_the_backend_name_it_was_given() {
    let store = host_transactions();
    assert_eq!(RelayStore::backend(&store), "host-transactions");
    RelayStore::ping(&store).expect("ping");
}
