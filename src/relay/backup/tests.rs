use super::*;
use crate::keys;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::customer::NewCustomer;
use crate::relay::issuance::{CustomerRef, Issuance, LicenceRef};
use crate::relay::licence::NewLicence;
use crate::relay::store::{RelayStore, SqliteRelayStore};
use crate::relay::{ApiKeyScope, MailTable};
use rusqlite::Connection;

const TAKEN: &str = "2026-10-07 12:00:00.123";

struct Fixture {
    store: SqliteRelayStore,
    identity: ProviderIdentity,
    root: [u8; 32],
    secret: zeroize::Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

fn fixture() -> Fixture {
    let issued = issued_identity("2099-01-01 00:00:00");
    let (secret, public) = keys::generate_encryption_keypair();
    let identity = ProviderIdentity {
        certificate: issued.certificate,
        relay_private_key: issued.relay_private,
    };
    let store = SqliteRelayStore::open_in_memory()
        .expect("schema")
        .with_blob_threshold(4096);
    // A licence and its keys (customers, licences, keys, deliveries, audit rows),
    // a few letters, and one held letter, with the audit chains anchored.
    let (_, client) = keys::generate_encryption_keypair();
    store
        .issue_licensed_bundles(
            &identity,
            &Issuance {
                customer: CustomerRef::New(NewCustomer {
                    name: "Acme Ltd".into(),
                    reference: Some("CONTRACT-7731".into()),
                }),
                licence: LicenceRef::New(NewLicence {
                    terms: "Five seats, renewable.".into(),
                    expires_at: Some("2999-01-01".into()),
                    replaces: None,
                }),
                scopes: vec![ApiKeyScope::InboxPush, ApiKeyScope::InboxPull],
                recipient_public_key: client,
                relay_url: "https://relay.example.test".into(),
                device_id: None,
            },
            None,
        )
        .expect("issue");
    for size in [300usize, 900, 2000] {
        let letter = crate::envelope::seal(
            crate::envelope::PACKAGE,
            crate::envelope::KIND_INVITE,
            &client,
            &vec![size as u8; size],
        )
        .expect("seal");
        store.inbox_push(&[], &letter, None).expect("push");
    }
    let big = crate::envelope::seal(
        crate::envelope::PACKAGE,
        crate::envelope::KIND_INVITE,
        &client,
        &vec![9u8; 20_000],
    )
    .expect("seal");
    let held = store.inbox_push(&[], &big, None).expect("push");
    assert!(held.blob.is_some());
    store.blob_ready(MailTable::Inbox, held.id).expect("ready");
    store.anchor_audit(&identity, TAKEN).expect("anchor");
    Fixture {
        store,
        identity,
        root: issued.root_public,
        secret,
        public,
    }
}

fn snapshot_of(f: &Fixture) -> Snapshot {
    snapshot(
        &*f.store.connection(),
        &f.identity,
        &f.public,
        TAKEN,
        8 * 1024 * 1024,
    )
    .expect("snapshot")
}

fn restore_into(f: &Fixture, snapshot: &Snapshot, target: &Connection) -> Result<Restored> {
    restore(
        target,
        &snapshot.manifest,
        &mut |name| {
            snapshot
                .objects
                .iter()
                .find(|(object, _)| object == name)
                .map(|(_, bytes)| bytes.clone())
                .ok_or(Error::InvalidBackup)
        },
        &f.secret,
        &f.root,
        &empty_revoked(),
    )
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
        row.get(0)
    })
    .expect("count")
}

fn tables(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .expect("prepare");
    stmt.query_map([], |row| row.get(0))
        .expect("query")
        .collect::<std::result::Result<_, _>>()
        .expect("names")
}

fn dump(conn: &Connection, table: &str, columns: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("SELECT {columns} FROM \"{table}\" ORDER BY rowid"))
        .expect("prepare");
    let width = stmt.column_count();
    stmt.query_map([], |row| {
        (0..width)
            .map(|i| {
                row.get::<_, rusqlite::types::Value>(i)
                    .map(|v| format!("{v:?}"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(|cells| cells.join("|"))
    })
    .expect("query")
    .collect::<std::result::Result<_, _>>()
    .expect("rows")
}

#[test]
fn a_snapshot_restores_every_row_and_the_audit_chains_still_verify() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    assert!(snapshot.rows > 10, "a real database was dumped");
    let target = crate::relay::open_in_memory().expect("empty relay database");
    let restored = restore_into(&f, &snapshot, &target).expect("restore");
    assert_eq!(restored.backup_id, snapshot.backup_id);
    assert_eq!(restored.taken_at, TAKEN);
    assert!(
        restored.audit_intact,
        "the chains and anchors verify after a restore"
    );
    assert_eq!(
        restored.held_skipped, 1,
        "the held letter's object is not in the backup"
    );

    let source = f.store.connection();
    for table in tables(&source) {
        let expected = count(&source, &table) - if table == "mailbox" { 1 } else { 0 };
        assert_eq!(count(&target, &table), expected, "rows of {table}");
    }
    for (table, columns) in [
        ("customers", "*"),
        ("licences", "*"),
        ("licence_versions", "*"),
        ("api_keys", "*"),
        ("api_key_events", "*"),
        ("audit_anchors", "*"),
    ] {
        assert_eq!(
            dump(&source, table, columns),
            dump(&target, table, columns),
            "{table} is the same"
        );
    }
    // The letters that were in their rows come back byte for byte; only the
    // held one (whose object is not in the backup) does not.
    let inline = |conn: &Connection| {
        let mut stmt = conn
            .prepare(
                "SELECT id, recipient_fingerprint, envelope, content_hash FROM mailbox
                 WHERE blob_len IS NULL ORDER BY id",
            )
            .expect("prepare");
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .expect("query")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("rows")
    };
    assert_eq!(inline(&source).len(), 3);
    assert_eq!(inline(&source), inline(&target));
}

#[test]
fn nothing_in_a_backup_is_readable_without_the_backup_key() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    let everything: Vec<&[u8]> = snapshot
        .objects
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .chain([snapshot.manifest.as_slice()])
        .collect();
    for needle in [
        "Acme Ltd",
        "CONTRACT-7731",
        "Five seats",
        "customers",
        "api_keys",
        "relay.example.test",
    ] {
        for bytes in &everything {
            assert!(
                !bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes()),
                "{needle} appears in a sealed backup object"
            );
        }
    }
    let (other, _) = keys::generate_encryption_keypair();
    let target = crate::relay::open_in_memory().expect("empty");
    let wrong = restore(
        &target,
        &snapshot.manifest,
        &mut |_| Err(Error::InvalidBackup),
        &other,
        &f.root,
        &empty_revoked(),
    );
    assert!(matches!(wrong, Err(Error::InvalidBackup)));
}

#[test]
fn any_changed_chunk_or_manifest_is_refused_and_the_target_stays_empty() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    for index in 0..snapshot.objects.len() {
        let target = crate::relay::open_in_memory().expect("empty");
        let mut changed = Snapshot {
            objects: snapshot.objects.clone(),
            manifest: snapshot.manifest.clone(),
            ..snapshot_of(&f)
        };
        let at = changed.objects[index].1.len() / 2;
        changed.objects[index].1[at] ^= 1;
        let result = restore_into(&f, &changed, &target);
        assert!(matches!(result, Err(Error::InvalidBackup)), "chunk {index}");
        for table in tables(&target) {
            assert_eq!(
                count(&target, &table),
                0,
                "{table} was written despite a bad chunk"
            );
        }
    }
    let target = crate::relay::open_in_memory().expect("empty");
    let mut bad = snapshot_of(&f);
    let at = bad.manifest.len() / 2;
    bad.manifest[at] ^= 1;
    assert!(matches!(
        restore_into(&f, &bad, &target),
        Err(Error::InvalidBackup)
    ));
}

#[test]
fn a_chunk_from_another_place_or_a_missing_one_is_refused() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    // Two chunks swapped under each other's names: each is a genuine sealed
    // chunk, but not the one the manifest names.
    let mut swapped = snapshot_of(&f);
    let (a, b) = (swapped.objects[0].1.clone(), swapped.objects[1].1.clone());
    swapped.objects[0].1 = b;
    swapped.objects[1].1 = a;
    let target = crate::relay::open_in_memory().expect("empty");
    assert!(matches!(
        restore_into(&f, &swapped, &target),
        Err(Error::InvalidBackup)
    ));
    // A chunk that is simply not there.
    let mut missing = snapshot_of(&f);
    missing.objects.remove(2);
    assert!(restore_into(
        &f,
        &missing,
        &crate::relay::open_in_memory().expect("empty")
    )
    .is_err());
    let _ = snapshot;
}

#[test]
fn a_manifest_the_relay_did_not_sign_is_refused() {
    let f = fixture();
    // The same database, snapshotted by a relay whose certificate chains to
    // another root, restored against the pinned root.
    let other = issued_identity("2099-01-01 00:00:00");
    let foreign = ProviderIdentity {
        certificate: other.certificate,
        relay_private_key: other.relay_private,
    };
    let snapshot = snapshot(
        &*f.store.connection(),
        &foreign,
        &f.public,
        TAKEN,
        8 * 1024 * 1024,
    )
    .expect("snapshot");
    let target = crate::relay::open_in_memory().expect("empty");
    assert!(matches!(
        restore_into(&f, &snapshot, &target),
        Err(Error::InvalidBackup)
    ));
    // A revoked certificate does not restore either.
    let genuine = snapshot_of(&f);
    let serial = provider::parse_certificate(&f.identity.certificate)
        .expect("cert")
        .serial;
    let revoked: HashSet<String> = [serial].into();
    let result = restore(
        &crate::relay::open_in_memory().expect("empty"),
        &genuine.manifest,
        &mut |_| Err(Error::InvalidBackup),
        &f.secret,
        &f.root,
        &revoked,
    );
    assert!(matches!(result, Err(Error::InvalidBackup)));
}

#[test]
fn a_backup_is_restored_only_into_an_empty_database_of_the_same_shape() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    let used = crate::relay::open_in_memory().expect("empty");
    used.execute(
        "INSERT INTO api_keys (key_hash, scope) VALUES ('h', 'inbox.push')",
        [],
    )
    .expect("a row");
    assert!(matches!(
        restore_into(&f, &snapshot, &used),
        Err(Error::BackupTargetNotEmpty)
    ));
    assert_eq!(count(&used, "api_keys"), 1, "nothing was merged");

    let missing = crate::relay::open_in_memory().expect("empty");
    missing
        .execute_batch("DROP TABLE blob_tombstones")
        .expect("drop");
    assert!(matches!(
        restore_into(&f, &snapshot, &missing),
        Err(Error::BackupTargetNotEmpty)
    ));

    let wider = crate::relay::open_in_memory().expect("empty");
    wider
        .execute_batch("ALTER TABLE customers ADD COLUMN extra TEXT")
        .expect("alter");
    assert!(matches!(
        restore_into(&f, &snapshot, &wider),
        Err(Error::BackupTargetNotEmpty)
    ));
}

#[test]
fn a_database_over_the_limit_is_refused_before_it_fills_memory() {
    let f = fixture();
    let result = snapshot(&*f.store.connection(), &f.identity, &f.public, TAKEN, 2000);
    assert!(matches!(result, Err(Error::BackupTooLarge)));
}

#[test]
fn an_empty_database_backs_up_and_restores() {
    let f = fixture();
    let empty = SqliteRelayStore::open_in_memory().expect("schema");
    let snapshot = snapshot(
        &*empty.connection(),
        &f.identity,
        &f.public,
        TAKEN,
        1024 * 1024,
    )
    .expect("snapshot");
    assert_eq!(snapshot.rows, 0);
    let target = crate::relay::open_in_memory().expect("empty");
    let restored = restore_into(&f, &snapshot, &target).expect("restore");
    assert_eq!((restored.rows, restored.held_skipped), (0, 0));
    assert!(restored.audit_intact);
}

#[test]
fn backup_ids_sort_by_time_and_differ_for_every_run() {
    let f = fixture();
    let early = snapshot(
        &*f.store.connection(),
        &f.identity,
        &f.public,
        "2026-10-07 11:00:00.000",
        8 * 1024 * 1024,
    )
    .expect("a");
    let late = snapshot(
        &*f.store.connection(),
        &f.identity,
        &f.public,
        "2026-10-07 12:00:00.000",
        8 * 1024 * 1024,
    )
    .expect("b");
    assert!(early.backup_id < late.backup_id);
    assert_ne!(early.backup_id, late.backup_id);
    assert!(snapshot(
        &*f.store.connection(),
        &f.identity,
        &f.public,
        "bad\" time",
        1024
    )
    .is_err());
}

#[test]
fn the_manifest_names_every_chunk_by_its_hash_and_inspect_says_what_is_in_it() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    let seen = inspect(&snapshot.manifest, &f.secret, &f.root, &empty_revoked()).expect("inspect");
    assert_eq!(
        (seen.backup_id.as_str(), seen.taken_at.as_str()),
        (snapshot.backup_id.as_str(), TAKEN)
    );
    assert!(seen
        .tables
        .iter()
        .any(|(name, rows)| name == "customers" && *rows == 1));
    let total: u64 = seen.tables.iter().map(|(_, rows)| rows).sum();
    assert_eq!(total, snapshot.rows);
}

fn write_dir(dir: &std::path::Path, snapshot: &Snapshot) {
    std::fs::write(dir.join(&snapshot.manifest_name), &snapshot.manifest).expect("manifest");
    for (name, bytes) in &snapshot.objects {
        std::fs::write(dir.join(name), bytes).expect("chunk");
    }
}

#[test]
fn a_downloaded_backup_restores_into_a_new_database_file_and_inspects_without_one() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    let dir = tempfile::tempdir().expect("dir");
    write_dir(dir.path(), &snapshot);
    let seen = inspect_dir(dir.path(), &f.secret, &f.root, &empty_revoked()).expect("inspect");
    assert_eq!(
        (seen.backup_id.as_str(), seen.taken_at.as_str()),
        (snapshot.backup_id.as_str(), TAKEN)
    );
    assert!(!seen.tables.is_empty());

    let out = dir.path().join("restored.sqlite");
    let restored =
        restore_dir(dir.path(), &out, &f.secret, &f.root, &empty_revoked()).expect("restore");
    assert!(restored.audit_intact);
    assert!(out.exists());
    let conn = Connection::open(&out).expect("open");
    assert_eq!(count(&conn, "customers"), 1);
    // Never over an existing file.
    assert!(matches!(
        restore_dir(dir.path(), &out, &f.secret, &f.root, &empty_revoked()),
        Err(Error::BackupTargetNotEmpty)
    ));
}

#[test]
fn a_failed_restore_leaves_no_database_and_a_forged_manifest_creates_none() {
    let f = fixture();
    let snapshot = snapshot_of(&f);
    let dir = tempfile::tempdir().expect("dir");
    write_dir(dir.path(), &snapshot);

    // A chunk altered on disk: the database is created, fails, and is removed.
    let mut chunk = std::fs::read(dir.path().join("chunk-000001.kqbk")).expect("read");
    let at = chunk.len() / 2;
    chunk[at] ^= 1;
    std::fs::write(dir.path().join("chunk-000001.kqbk"), chunk).expect("write");
    let out = dir.path().join("restored.sqlite");
    assert!(restore_dir(dir.path(), &out, &f.secret, &f.root, &empty_revoked()).is_err());
    assert!(!out.exists(), "no half-restored database is left");

    // A wrong key reads nothing and makes nothing.
    let (other, _) = keys::generate_encryption_keypair();
    let out = dir.path().join("other.sqlite");
    assert!(restore_dir(dir.path(), &out, &other, &f.root, &empty_revoked()).is_err());
    assert!(!out.exists());
}

#[test]
fn a_manifest_cannot_point_a_restore_outside_its_directory() {
    assert!(plain_name("chunk-000001.kqbk"));
    for bad in [
        "",
        ".hidden",
        "../x",
        "a/b",
        "/etc/passwd",
        "a\\b",
        "x y",
        &"x".repeat(101),
    ] {
        assert!(!plain_name(bad), "{bad:?}");
    }
}
