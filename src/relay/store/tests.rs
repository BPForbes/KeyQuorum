//! The SQLite store against the conformance suite every backend must pass.

use super::conformance;
use super::SqliteRelayStore;

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
    assert_eq!(super::RelayStore::backend(&store), "sqlite");
    super::RelayStore::ping(&store).expect("ping");
}
