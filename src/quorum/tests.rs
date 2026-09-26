use super::*;
use crate::db;
use crate::key_tree::NodeSpec;
use crate::keys::{self, KeyType};

fn register_encryption_key(conn: &Connection, label: &str) -> (i64, crypto_box::SecretKey) {
    let secret_key = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let public_key = *secret_key.public_key().as_bytes();
    let id = keys::register_key(conn, label, KeyType::Encryption, &public_key)
        .expect("register_key should succeed");
    (id, secret_key)
}

fn unwrap_leaf_share(
    conn: &Connection,
    node_id: i64,
    secret_key: &crypto_box::SecretKey,
) -> Vec<u8> {
    crate::key_tree::unwrap_leaf_share(conn, node_id, &secret_key.to_bytes())
        .expect("unseal should succeed with the matching secret key")
}

fn leaf_ids_by_label(conn: &Connection, key_id: i64) -> HashMap<String, i64> {
    let mut stmt = conn
        .prepare(
            "SELECT id, label FROM key_nodes WHERE key_id = ?1 AND hardware_key_id IS NOT NULL",
        )
        .unwrap();
    stmt.query_map(params![key_id], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(0)?))
    })
    .unwrap()
    .collect::<rusqlite::Result<HashMap<_, _>>>()
    .unwrap()
}

#[test]
fn lock_status_and_unlock_roundtrip_with_threshold_met() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
    let (id_b, sk_b) = register_encryption_key(&conn, "b");
    let (id_c, _sk_c) = register_encryption_key(&conn, "c");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "c".into(),
                hardware_key_id: id_c,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let file_id = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec)
        .expect("lock_file should succeed");

    let file_status = status(&conn, file_id).expect("status should succeed");
    assert_eq!(file_status.tree.root.threshold, Some(2));
    assert_eq!(file_status.tree.root.children.len(), 3);

    let key_id = file_status.tree.key_id;
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
    let raw_b = unwrap_leaf_share(&conn, leaves[&"b".to_string()], &sk_b);
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);
    shares.insert(leaves[&"b".to_string()], raw_b);

    let plaintext = unlock_file(&conn, file_id, &shares).expect("unlock_file should succeed");
    assert_eq!(plaintext, b"the quorum has been reached");
}

#[test]
fn unlock_fails_with_too_few_shares() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
    let (id_b, _sk_b) = register_encryption_key(&conn, "b");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let file_id = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec)
        .expect("lock_file should succeed");

    let key_id = status(&conn, file_id).unwrap().tree.key_id;
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);

    let result = unlock_file(&conn, file_id, &shares);
    assert!(matches!(result, Err(Error::QuorumNotMet)));
}

#[test]
fn lock_rejects_threshold_above_recipient_count() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![NodeSpec::Leaf {
            label: "a".into(),
            hardware_key_id: id_a,
            allowed_bridges: vec![],
        }],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(matches!(result, Err(Error::InvalidQuorumThreshold)));
    assert!(!encrypted_path.exists());
}

#[test]
fn lock_cleans_up_ciphertext_when_starting_the_transaction_fails() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");

    let spec = NodeSpec::Leaf {
        label: "a".into(),
        hardware_key_id: id_a,
        allowed_bridges: vec![],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    // Force conn.transaction() to fail inside lock_file: open a
    // transaction on this same connection first, via raw SQL rather
    // than rusqlite's Transaction guard (which would hold a Rust-level
    // borrow on `conn` and conflict with passing `&mut conn` below).
    conn.execute_batch("BEGIN").expect("BEGIN should succeed");

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(result.is_err());
    assert!(
        !encrypted_path.exists(),
        "ciphertext should be cleaned up even when the transaction never opens"
    );

    conn.execute_batch("ROLLBACK")
        .expect("ROLLBACK should succeed");
}

#[test]
fn lock_rejects_signing_key_as_recipient() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let id = keys::register_key(&conn, "signer", KeyType::Signing, &public_key)
        .expect("register_key should succeed");
    let (id_b, _sk_b) = register_encryption_key(&conn, "b");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "signer".into(),
                hardware_key_id: id,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(matches!(result, Err(Error::WrongKeyType)));
    assert!(!encrypted_path.exists());
}

#[test]
fn lock_rejects_revoked_recipient() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");
    keys::revoke_key(&conn, id_a).expect("revoke_key should succeed");
    let (id_b, _sk_b) = register_encryption_key(&conn, "b");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(matches!(result, Err(Error::KeyRevoked)));
    assert!(!encrypted_path.exists());
}

#[test]
fn parent_approval_is_required_only_when_the_tree_asks_for_it() {
    let mut conn = db::open_in_memory().expect("schema");
    let (id_emp, sk_emp) = register_encryption_key(&conn, "M.S.1");
    let (manager, manager_public) = keys::generate_signing_keypair();
    keys::register_key(&conn, "M.S", KeyType::Signing, &manager_public).unwrap();
    let spec = NodeSpec::Split {
        label: "M".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: vec![NodeSpec::Leaf {
            label: "M.S.1".into(),
            hardware_key_id: id_emp,
            allowed_bridges: vec![],
        }],
    };
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("secret.txt");
    let encrypted = dir.path().join("secret.txt.kqenc");
    fs::write(&source, b"needs a supervisor").unwrap();
    let file_id = lock_file(&mut conn, &source, &encrypted, None, &spec).unwrap();
    let key_id = status(&conn, file_id).unwrap().tree.key_id;
    crate::device::set_custody_policy(
        &conn,
        key_id,
        &crate::device::CustodyPolicy {
            mode: crate::device::CustodyMode::Hardware,
            minimum_physical_devices: 1,
            unlock_approval: crate::device::UnlockApproval::Parent,
        },
    )
    .unwrap();
    let leaves = leaf_ids_by_label(&conn, key_id);
    let mut shares = HashMap::new();
    shares.insert(
        leaves["M.S.1"],
        unwrap_leaf_share(&conn, leaves["M.S.1"], &sk_emp),
    );
    assert!(matches!(
        unlock_file(&conn, file_id, &shares),
        Err(Error::UnlockApprovalRequired)
    ));
    let presented = crate::key_tree::reconstruct_presented(&conn, key_id, &shares).unwrap();
    let mut device_ids: Vec<[u8; 16]> = presented.devices.iter().map(|d| d.device_id).collect();
    device_ids.sort();
    let preimage =
        crate::authority::unlock_approval_preimage(file_id, key_id, "M.S.1", "M.S", &device_ids)
            .unwrap();
    let grant = crate::authority::UnlockGrant {
        leaf_label: "M.S.1".into(),
        countersigner_label: "M.S".into(),
        signature: crate::signing::sign(&manager, &preimage),
    };
    let plaintext =
        unlock_file_with_approval(&conn, file_id, &shares, &[grant]).expect("parent signed");
    assert_eq!(plaintext, b"needs a supervisor");
}

#[test]
fn a_file_locked_with_a_past_expiry_is_denied_and_destroyed_on_unlock() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
    let spec = NodeSpec::flat_split("root", 1, vec![("a".into(), id_a)]);

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let past: String = conn
        .query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', '-1 day')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut storage = crate::storage::NativeStorage;
    let plaintext = fs::read(&source_path).unwrap();
    let file_id = lock_bytes_until_in(
        &mut storage,
        &mut conn,
        &plaintext,
        &encrypted_path,
        "secret.txt",
        &spec,
        Some(&past),
    )
    .expect("lock should succeed even with a past expiry");

    assert!(is_expired(&conn, file_id).unwrap());
    assert!(encrypted_path.exists());

    let key_id = status(&conn, file_id).unwrap().tree.key_id;
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);

    let result = unlock_file(&conn, file_id, &shares);
    assert!(matches!(result, Err(Error::FileExpired)));
    // The ciphertext and the row are both gone — not just refused.
    assert!(!encrypted_path.exists());
    assert!(status(&conn, file_id).is_err());
}

#[test]
fn a_file_with_a_future_expiry_unlocks_normally_and_keeps_its_ttl() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
    let spec = NodeSpec::flat_split("root", 1, vec![("a".into(), id_a)]);

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let future: String = conn
        .query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', '+1 day')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut storage = crate::storage::NativeStorage;
    let plaintext = fs::read(&source_path).unwrap();
    let file_id = lock_bytes_until_in(
        &mut storage,
        &mut conn,
        &plaintext,
        &encrypted_path,
        "secret.txt",
        &spec,
        Some(&future),
    )
    .unwrap();

    assert!(!is_expired(&conn, file_id).unwrap());
    let key_id = status(&conn, file_id).unwrap().tree.key_id;
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);

    let plaintext = unlock_file(&conn, file_id, &shares).unwrap();
    assert_eq!(plaintext, b"the quorum has been reached");
    assert_eq!(
        status(&conn, file_id).unwrap().expires_at.as_deref(),
        Some(future.as_str())
    );
}

#[test]
fn set_expires_at_and_purge_expired_cover_a_file_with_no_ttl() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");
    let spec = NodeSpec::flat_split("root", 1, vec![("a".into(), id_a)]);

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"never expires yet").unwrap();
    let file_id = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec).unwrap();

    assert_eq!(status(&conn, file_id).unwrap().expires_at, None);
    assert!(!is_expired(&conn, file_id).unwrap());
    assert_eq!(purge_expired(&conn).unwrap(), 0);
    assert!(encrypted_path.exists());

    let past: String = conn
        .query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', '-1 minute')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    set_expires_at(&conn, file_id, Some(&past)).unwrap();
    assert!(is_expired(&conn, file_id).unwrap());
    assert_eq!(purge_expired(&conn).unwrap(), 1);
    assert!(!encrypted_path.exists());
    assert!(status(&conn, file_id).is_err());
}

#[test]
fn an_expired_file_is_purged_even_when_the_presented_shares_are_not_enough() {
    // Regression: the purge must not be reachable only through a
    // *successful* reconstruction — a P1 review finding on PR #33 pointed
    // out that gating it inside `complete_unlock_in` alone means an
    // expired file with too few (or invalid) shares presented would never
    // be destroyed, since `reconstruct_presented` fails and returns before
    // ever reaching that check.
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
    let (id_b, _sk_b) = register_encryption_key(&conn, "b");
    let spec = NodeSpec::flat_split("root", 2, vec![("a".into(), id_a), ("b".into(), id_b)]);

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let past: String = conn
        .query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', '-1 day')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut storage = crate::storage::NativeStorage;
    let plaintext = fs::read(&source_path).unwrap();
    let file_id = lock_bytes_until_in(
        &mut storage,
        &mut conn,
        &plaintext,
        &encrypted_path,
        "secret.txt",
        &spec,
        Some(&past),
    )
    .unwrap();
    assert!(is_expired(&conn, file_id).unwrap());
    assert!(encrypted_path.exists());

    // Only one of the two shares needed — reconstruction alone would fail
    // with QuorumNotMet, never reaching the purge that used to live only
    // inside `complete_unlock_in`.
    let key_id = status(&conn, file_id).unwrap().tree.key_id;
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);

    let result = unlock_file(&conn, file_id, &shares);
    assert!(matches!(result, Err(Error::FileExpired)));
    assert!(!encrypted_path.exists());
    assert!(status(&conn, file_id).is_err());
}

#[test]
fn an_expired_file_is_purged_even_with_zero_shares_presented() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");
    let spec = NodeSpec::flat_split("root", 1, vec![("a".into(), id_a)]);

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let past: String = conn
        .query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', '-1 minute')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut storage = crate::storage::NativeStorage;
    let plaintext = fs::read(&source_path).unwrap();
    let file_id = lock_bytes_until_in(
        &mut storage,
        &mut conn,
        &plaintext,
        &encrypted_path,
        "secret.txt",
        &spec,
        Some(&past),
    )
    .unwrap();

    let result = unlock_file(&conn, file_id, &HashMap::new());
    assert!(matches!(result, Err(Error::FileExpired)));
    assert!(!encrypted_path.exists());
}

/// Wraps a [`crate::storage::MemoryStorage`] but refuses every delete, as a
/// read-only mount or a permission error would.
struct UndeletableStorage(crate::storage::MemoryStorage);

impl crate::storage::Storage for UndeletableStorage {
    fn exists(&self, path: &Path) -> bool {
        self.0.exists(path)
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        self.0.read(path)
    }
    fn write_new(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        self.0.write_new(path, contents)
    }
    fn rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        self.0.rename(from, to)
    }
    fn delete(&mut self, _path: &Path) -> Result<()> {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "read-only",
        )))
    }
    fn create_dir_all(&mut self, path: &Path) -> Result<()> {
        self.0.create_dir_all(path)
    }
    fn remove_empty_dir(&mut self, path: &Path) {
        self.0.remove_empty_dir(path)
    }
    fn list(&self, path: &Path) -> Result<Vec<std::path::PathBuf>> {
        self.0.list(path)
    }
}

#[test]
fn a_failed_ciphertext_delete_keeps_the_row_so_the_purge_can_retry() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");
    let spec = NodeSpec::flat_split("root", 1, vec![("a".into(), id_a)]);
    let past: String = conn
        .query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', '-1 day')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut storage = UndeletableStorage(crate::storage::MemoryStorage::new());
    let path = Path::new("/files/stuck.kqenc");
    let file_id = lock_bytes_until_in(
        &mut storage,
        &mut conn,
        b"cannot be deleted",
        path,
        "stuck.txt",
        &spec,
        Some(&past),
    )
    .unwrap();

    assert!(matches!(
        purge_if_expired_in(&mut storage, &conn, file_id),
        Err(Error::Io(_))
    ));
    assert!(
        status(&conn, file_id).is_ok(),
        "row must survive for a retry"
    );
    assert!(matches!(
        purge_expired_in(&mut storage, &conn),
        Err(Error::Io(_))
    ));
    assert!(status(&conn, file_id).is_ok());

    let mut working = storage.0;
    assert!(matches!(
        purge_if_expired_in(&mut working, &conn, file_id),
        Err(Error::FileExpired)
    ));
    assert!(!working.exists(path));
    assert!(status(&conn, file_id).is_err());
}
