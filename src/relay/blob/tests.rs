use super::*;
use crate::envelope::{self, KIND_DEVICE_TRANSFER, KIND_INVITE};
use crate::keys;
use crate::relay::store::{RelayStore, SqliteRelayStore};
use sha2::{Digest, Sha256};

const THRESHOLD: usize = 4096;

fn store() -> SqliteRelayStore {
    SqliteRelayStore::open_in_memory()
        .expect("schema")
        .with_blob_threshold(THRESHOLD)
}

/// A sealed letter of about `size` bytes for `recipient`.
fn letter(kind: u8, recipient: &[u8; 32], size: usize) -> Vec<u8> {
    envelope::seal(
        envelope::PACKAGE,
        kind,
        recipient,
        &vec![0x5a; size.saturating_sub(100)],
    )
    .expect("seal")
}

fn recipient() -> ([u8; 32], String) {
    let (_, public) = keys::generate_encryption_keypair();
    (public, keys::fingerprint(&public))
}

fn hash_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn push(store: &SqliteRelayStore, bytes: &[u8]) -> crate::relay::store::StoredLetter {
    store.inbox_push(&[], bytes, None).expect("push")
}

fn page(store: &SqliteRelayStore, fingerprint: &str) -> crate::relay::MailboxPage {
    store
        .list_envelopes_after(fingerprint, None, None)
        .expect("list")
}

#[test]
fn a_small_letter_stays_in_its_row_and_nothing_is_held() {
    let store = store();
    let (public, fingerprint) = recipient();
    let small = letter(KIND_INVITE, &public, 600);
    let stored = push(&store, &small);
    assert_eq!(stored.blob, None);
    assert!(!stored.duplicate);
    let listed = page(&store, &fingerprint);
    assert_eq!(listed.envelopes[0].bytes, small);
    assert_eq!(listed.envelopes[0].blob, None);

    let plain = SqliteRelayStore::open_in_memory().expect("schema");
    let big = letter(KIND_INVITE, &public, 3 * THRESHOLD);
    assert_eq!(
        plain.inbox_push(&[], &big, None).expect("push").blob,
        None,
        "without a threshold nothing is held out"
    );
}

#[test]
fn a_large_letter_is_held_not_ready_until_its_bytes_are_stored() {
    let store = store();
    let (public, fingerprint) = recipient();
    let big = letter(KIND_INVITE, &public, 3 * THRESHOLD);
    let stored = push(&store, &big);
    let held = stored
        .blob
        .clone()
        .expect("the bytes are still to be stored");
    assert_eq!(held.key, format!("inbox/{}", hash_of(&big)));
    assert_eq!(held.len, big.len());
    assert!(!stored.duplicate);

    // Not ready: not listed, not counted, not summarised.
    assert!(page(&store, &fingerprint).envelopes.is_empty());
    let (total, letters) =
        crate::relay::mailbox::summaries(&*store.connection(), 10).expect("summaries");
    assert_eq!((total, letters.len()), (0, 0));

    assert!(store
        .blob_ready(MailTable::Inbox, stored.id)
        .expect("ready"));
    let listed = page(&store, &fingerprint);
    assert_eq!(listed.envelopes.len(), 1);
    let entry = &listed.envelopes[0];
    assert_eq!(
        entry.bytes,
        big[..HEADER_LEN],
        "the row keeps only the header"
    );
    assert_eq!(entry.blob.as_ref(), Some(&held));
    assert_eq!(
        envelope::kind_of_prefix(&entry.bytes),
        Some(KIND_INVITE),
        "the kind still reads from the header"
    );
    let (total, letters) =
        crate::relay::mailbox::summaries(&*store.connection(), 10).expect("summaries");
    assert_eq!(total, 1);
    assert_eq!(
        letters[0].size as usize,
        big.len(),
        "the true size, not the header's"
    );
    assert_eq!(letters[0].kind, Some(KIND_INVITE));
}

#[test]
fn a_page_is_bounded_by_the_true_sizes_of_held_letters() {
    let store = store();
    let (public, fingerprint) = recipient();
    for index in 0..3u8 {
        let mut big = letter(KIND_INVITE, &public, 7 * 1024 * 1024);
        big[100] = index; // a different content hash for each
        let stored = push(&store, &big);
        store
            .blob_ready(MailTable::Inbox, stored.id)
            .expect("ready");
    }
    let listed = page(&store, &fingerprint);
    assert_eq!(
        listed.envelopes.len(),
        2,
        "two 7 MiB letters fit in 16 MiB, three do not"
    );
    assert!(listed.next_after.is_some());
}

#[test]
fn a_repeat_before_the_bytes_are_confirmed_asks_for_them_again_and_a_repeat_after_does_not() {
    let store = store();
    let (public, _) = recipient();
    let big = letter(KIND_INVITE, &public, 3 * THRESHOLD);
    let first = push(&store, &big);
    let again = push(&store, &big);
    assert_eq!(again.id, first.id, "one row");
    assert!(!again.duplicate);
    assert_eq!(again.blob, first.blob, "the same object is asked for");
    store.blob_ready(MailTable::Inbox, first.id).expect("ready");
    let repeat = push(&store, &big);
    assert!(repeat.duplicate);
    assert_eq!(repeat.blob, None);
}

#[test]
fn abort_drops_only_a_not_ready_held_row_and_ready_only_marks_one() {
    let store = store();
    let (public, fingerprint) = recipient();
    let big = letter(KIND_INVITE, &public, 3 * THRESHOLD);
    let small = letter(KIND_INVITE, &public, 700);

    let held = push(&store, &big);
    assert!(store.blob_abort(MailTable::Inbox, held.id).expect("abort"));
    assert!(!store.blob_abort(MailTable::Inbox, held.id).expect("again"));
    let retried = push(&store, &big);
    assert!(!retried.duplicate, "the retry starts clean");
    store
        .blob_ready(MailTable::Inbox, retried.id)
        .expect("ready");
    assert!(
        !store
            .blob_abort(MailTable::Inbox, retried.id)
            .expect("abort"),
        "a ready row is never aborted"
    );
    assert!(!store
        .blob_ready(MailTable::Inbox, retried.id)
        .expect("twice"));

    let inline = push(&store, &small);
    assert!(!store
        .blob_ready(MailTable::Inbox, inline.id)
        .expect("inline"));
    assert!(!store
        .blob_abort(MailTable::Inbox, inline.id)
        .expect("inline"));
    assert_eq!(page(&store, &fingerprint).envelopes.len(), 2);
}

#[test]
fn a_stale_not_ready_row_is_dropped_and_its_key_tombstoned() {
    let store = store();
    let (public, _) = recipient();
    let big = letter(KIND_INVITE, &public, 3 * THRESHOLD);
    let stored = push(&store, &big);
    assert_eq!(store.blob_drop_stale(30).expect("fresh"), 0);
    store
        .connection()
        .execute(
            "UPDATE mailbox SET created_at = datetime('now', '-2 hours') WHERE id = ?1",
            rusqlite::params![stored.id],
        )
        .expect("age it");
    assert_eq!(store.blob_drop_stale(30).expect("stale"), 1);
    assert_eq!(
        store.blob_tombstones(10).expect("keys"),
        vec![stored.blob.expect("held").key],
        "a half-stored object is cleaned up too"
    );
}

#[test]
fn any_delete_of_a_held_row_leaves_a_tombstone_that_waits_for_no_live_row() {
    let store = store();
    let (public, _) = recipient();
    let big = letter(KIND_INVITE, &public, 3 * THRESHOLD);
    let stored = push(&store, &big);
    let key = stored.blob.clone().expect("held").key;
    store
        .blob_ready(MailTable::Inbox, stored.id)
        .expect("ready");
    assert!(store.blob_tombstones(10).expect("none yet").is_empty());

    // A delete by a path nothing in this module knows about.
    store
        .connection()
        .execute(
            "DELETE FROM mailbox WHERE id = ?1",
            rusqlite::params![stored.id],
        )
        .expect("delete");
    assert_eq!(store.blob_tombstones(10).expect("keys"), vec![key.clone()]);

    // The same letter stored anew before the object was deleted: the key is
    // live again and is not offered, and finishing the old deletion keeps it.
    let again = push(&store, &big);
    assert!(store.blob_tombstones(10).expect("live again").is_empty());
    assert_eq!(
        store
            .blob_tombstones_done(std::slice::from_ref(&key))
            .expect("done"),
        0
    );
    store.blob_ready(MailTable::Inbox, again.id).expect("ready");

    // Gone for good: offered, deleted, forgotten.
    store
        .connection()
        .execute(
            "DELETE FROM mailbox WHERE id = ?1",
            rusqlite::params![again.id],
        )
        .expect("delete");
    assert_eq!(store.blob_tombstones(10).expect("keys"), vec![key.clone()]);
    assert_eq!(store.blob_tombstones_done(&[key]).expect("done"), 1);
    assert!(store.blob_tombstones(10).expect("empty").is_empty());
}

#[test]
fn an_expired_held_letter_is_purged_and_tombstoned_and_never_listed() {
    let store = store();
    let (public, fingerprint) = recipient();
    let big = letter(KIND_INVITE, &public, 3 * THRESHOLD);
    let stored = push(&store, &big);
    store
        .blob_ready(MailTable::Inbox, stored.id)
        .expect("ready");
    store
        .connection()
        .execute(
            "UPDATE mailbox SET expires_at = datetime('now', '-1 minutes')",
            [],
        )
        .expect("expire");
    assert!(page(&store, &fingerprint).envelopes.is_empty());
    assert_eq!(store.blob_tombstones(10).expect("keys").len(), 1);
}

#[test]
fn device_letters_are_held_the_same_way_under_their_own_prefix() {
    let store = store();
    let (public, fingerprint) = recipient();
    let big = letter(KIND_DEVICE_TRANSFER, &public, 3 * THRESHOLD);
    let stored = store.store_device_package(&big).expect("store");
    let held = stored.blob.clone().expect("held");
    assert_eq!(held.key, format!("device/{}", hash_of(&big)));
    assert!(store
        .list_device_packages_after(&fingerprint, None, None)
        .expect("list")
        .packages
        .is_empty());
    store
        .blob_ready(MailTable::Devices, stored.id)
        .expect("ready");
    let listed = store
        .list_device_packages_after(&fingerprint, None, None)
        .expect("list");
    assert_eq!(listed.packages[0].bytes, big[..HEADER_LEN]);
    assert_eq!(listed.packages[0].blob, Some(held.clone()));
    store
        .connection()
        .execute("DELETE FROM device_mailbox", [])
        .expect("delete");
    assert_eq!(store.blob_tombstones(10).expect("keys"), vec![held.key]);
}

#[test]
fn a_database_from_before_held_letters_gains_the_columns_and_keeps_its_letters() {
    let conn = rusqlite::Connection::open_in_memory().expect("memory");
    conn.execute_batch(
        "CREATE TABLE mailbox (
            id INTEGER PRIMARY KEY, recipient_fingerprint TEXT NOT NULL, envelope BLOB NOT NULL,
            content_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT, UNIQUE (recipient_fingerprint, content_hash));
         INSERT INTO mailbox (recipient_fingerprint, envelope, content_hash) VALUES ('f', x'01', 'h');",
    )
    .expect("an old mailbox");
    crate::relay::init(&conn).expect("schema and migration");
    let (len, ready): (Option<i64>, i64) = conn
        .query_row("SELECT blob_len, blob_ready FROM mailbox", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("row");
    assert_eq!(
        (len, ready),
        (None, 1),
        "an old letter is an inline, ready one"
    );
}
