use super::*;
use crate::envelope::{self, PACKAGE};
use crate::keys;
use crate::relay;

fn sealed(kind: u8, payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let (_secret, public) = keys::generate_encryption_keypair();
    let bytes = envelope::seal(PACKAGE, kind, &public, payload).expect("seal");
    (bytes, public)
}

#[test]
fn stores_a_device_letter_without_opening_it() {
    let conn = relay::open_in_memory().expect("schema");
    let secret = b"slot-secret-must-stay-sealed";
    let (bytes, public) = sealed(envelope::KIND_DEVICE_TRANSFER, secret);
    let (id, fingerprint, duplicate) = store(&conn, &bytes).expect("store");
    assert!(!duplicate);
    assert_eq!(fingerprint, keys::fingerprint(&public));
    let page = list_after(&conn, &fingerprint, None, None).expect("list");
    assert_eq!(page.packages.len(), 1);
    assert_eq!(page.packages[0].id, id);
    assert_eq!(page.packages[0].bytes, bytes);
    assert!(!page.packages[0]
        .bytes
        .windows(secret.len())
        .any(|window| window == secret));
}

#[test]
fn rejects_raw_kqtx_and_bridge_kinds() {
    let conn = relay::open_in_memory().expect("schema");
    let mut raw = b"KQTX".to_vec();
    raw.extend_from_slice(&[0u8; 64]);
    assert!(matches!(
        store(&conn, &raw),
        Err(crate::error::Error::InvalidBridgePackage)
    ));
    let (bridge, _) = sealed(envelope::KIND_INVITE, b"bridge");
    assert!(matches!(
        store(&conn, &bridge),
        Err(crate::error::Error::InvalidBridgePackage)
    ));
}

#[test]
fn dedupes_the_same_letter() {
    let conn = relay::open_in_memory().expect("schema");
    let (bytes, _) = sealed(envelope::KIND_DEVICE_RELOCATE, b"moved");
    let (first, _, duplicate) = store(&conn, &bytes).expect("first");
    let (second, _, again) = store(&conn, &bytes).expect("second");
    assert!(!duplicate);
    assert!(again);
    assert_eq!(first, second);
}

#[test]
fn every_device_letter_gets_an_expiry() {
    let conn = relay::open_in_memory().expect("schema");
    let (bytes, _) = sealed(envelope::KIND_DEVICE_RELOCATE_ACK, b"ack");
    let (id, _, _) = store(&conn, &bytes).expect("store");
    let days: f64 = conn
        .query_row(
            "SELECT julianday(expires_at) - julianday('now') FROM device_mailbox WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .expect("expiry");
    let ttl = DEVICE_PACKAGE_TTL_DAYS as f64;
    assert!(days > ttl - 0.01 && days <= ttl, "{days}");
}

#[test]
fn expired_device_letters_are_hidden_and_purged() {
    let conn = relay::open_in_memory().expect("schema");
    let (live, public) = sealed(envelope::KIND_DEVICE_TRANSFER, b"live");
    let (dead, _) = envelope_for(&public, envelope::KIND_DEVICE_TRANSFER_ACK, b"dead");
    let fingerprint = keys::fingerprint(&public);
    store(&conn, &live).expect("store live");
    let (dead_id, _, _) = store(&conn, &dead).expect("store dead");
    conn.execute(
        "UPDATE device_mailbox SET expires_at = datetime('now', '-1 minutes') WHERE id = ?1",
        [dead_id],
    )
    .expect("stamp past expiry");

    let page = list_after(&conn, &fingerprint, None, None).expect("list");
    assert_eq!(page.packages.len(), 1);
    assert_eq!(page.packages[0].bytes, live);
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM device_mailbox", [], |row| row.get(0))
        .expect("count");
    assert_eq!(remaining, 1);

    conn.execute(
        "UPDATE device_mailbox SET expires_at = datetime('now', '-1 minutes')",
        [],
    )
    .expect("expire all");
    assert_eq!(purge_expired(&conn).expect("scan"), 1);
}

#[test]
fn letters_stored_before_retention_are_given_an_expiry() {
    let conn = rusqlite::Connection::open_in_memory().expect("open");
    conn.execute_batch(
        "CREATE TABLE device_mailbox (
            id                      INTEGER PRIMARY KEY,
            recipient_fingerprint   TEXT NOT NULL,
            package                 BLOB NOT NULL,
            content_hash            TEXT NOT NULL,
            created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            UNIQUE (recipient_fingerprint, content_hash)
         );
         INSERT INTO device_mailbox (recipient_fingerprint, package, content_hash, created_at)
            VALUES ('old', x'00', 'a', '2000-01-01T00:00:00.000Z'),
                   ('new', x'00', 'b', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));",
    )
    .expect("old schema");
    crate::relay::init(&conn).expect("migrate");
    let unset: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM device_mailbox WHERE expires_at IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(unset, 0);
    assert_eq!(purge_expired(&conn).expect("scan"), 1);
    let left: String = conn
        .query_row(
            "SELECT recipient_fingerprint FROM device_mailbox",
            [],
            |row| row.get(0),
        )
        .expect("row");
    assert_eq!(left, "new");
}

fn envelope_for(public: &[u8; 32], kind: u8, payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let bytes = envelope::seal(PACKAGE, kind, public, payload).expect("seal");
    (bytes, *public)
}
