use super::*;
use crate::db;
use crate::error::Error;
use crate::key_tree::{self, NodeSpec};
use crate::keys::{self, KeyType};
use rusqlite::params;
use std::collections::{HashMap, HashSet};
use std::fs;

const PASS: &str = "slot-passphrase";

fn leaf(label: &str, hardware_key_id: i64) -> NodeSpec {
    NodeSpec::Leaf {
        label: label.into(),
        hardware_key_id,
        allowed_bridges: vec![],
    }
}

fn flat_tree(conn: &mut rusqlite::Connection, labels: &[(&str, i64)], threshold: u8) -> i64 {
    let spec = NodeSpec::Split {
        label: "M".into(),
        threshold,
        allowed_bridges: vec![],
        children: labels.iter().map(|(label, id)| leaf(label, *id)).collect(),
    };
    key_tree::split(conn, "org", b"company master secret 32 bytes!", &spec).expect("split")
}

fn share_for(
    conn: &rusqlite::Connection,
    key_id: i64,
    label: &str,
    secret: &[u8; 32],
) -> (i64, Vec<u8>) {
    let node_id: i64 = conn
        .query_row(
            "SELECT id FROM key_nodes WHERE key_id = ?1 AND label = ?2",
            params![key_id, label],
            |row| row.get(0),
        )
        .unwrap();
    let raw = key_tree::unwrap_leaf_share(conn, node_id, secret).expect("unwrap");
    (node_id, raw)
}

#[test]
fn a_slot_roundtrip_rejects_a_bad_label_and_a_wrong_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let mut container = init(dir.path()).unwrap();
    assert!(provision(&mut container, "../M.S", PASS).is_err());
    let slot = provision(&mut container, "M.S.1", PASS).unwrap();
    let opened = open(dir.path()).unwrap();
    assert_eq!(opened.device_id(), container.device_id());
    assert_eq!(opened.slots().len(), 1);
    let secrets = open_slot(&opened, "M.S.1", PASS).unwrap();
    assert_eq!(secrets.encryption_public, slot.encryption_public);
    assert!(open_slot(&opened, "M.S.1", "nope").is_err());
    let mut tampered = fs::read(dir.path().join("device.kq")).unwrap();
    tampered[0] ^= 0xff;
    fs::write(dir.path().join("device.kq"), tampered).unwrap();
    assert!(open(dir.path()).is_err());
}

#[test]
fn unplaced_key_files_are_one_device_each() {
    let mut conn = db::open_in_memory().unwrap();
    let mut secrets = Vec::new();
    let mut ids = Vec::new();
    for label in ["M.S.1", "M.S.2", "M.S.3"] {
        let (secret, public) = keys::generate_encryption_keypair();
        let id = keys::register_key(&conn, label, KeyType::Encryption, &public).unwrap();
        ids.push((label, id));
        secrets.push((*secret, label));
    }
    // Threshold 3 so every presented key file is a share the reconstruction uses.
    let key_id = flat_tree(&mut conn, &ids, 3);
    set_custody_policy(
        &conn,
        key_id,
        &CustodyPolicy {
            mode: CustodyMode::Hardware,
            minimum_physical_devices: 3,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    let mut shares = HashMap::new();
    for (secret, label) in &secrets {
        let (node, raw) = share_for(&conn, key_id, label, secret);
        shares.insert(node, raw);
    }
    key_tree::reconstruct(&conn, key_id, &shares).expect("three key files are three devices");
    set_custody_policy(
        &conn,
        key_id,
        &CustodyPolicy {
            mode: CustodyMode::Hardware,
            minimum_physical_devices: 4,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    assert!(matches!(
        key_tree::reconstruct(&conn, key_id, &shares),
        Err(Error::PhysicalDevicesNotMet)
    ));
}

#[test]
fn slots_on_one_container_count_as_one_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut container = init(dir.path()).unwrap();
    let mut conn = db::open_in_memory().unwrap();
    let labels = ["M.S", "M.S.1", "M.S.2"];
    let mut minted = Vec::new();
    for label in labels {
        let slot = provision(&mut container, label, PASS).unwrap();
        let id =
            keys::register_key(&conn, label, KeyType::Encryption, &slot.encryption_public).unwrap();
        keys::register_key(&conn, label, KeyType::Signing, &slot.signing_public).unwrap();
        bind_slot(&conn, &container, label).unwrap();
        minted.push((label, id, *slot.encryption_secret));
    }
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT device_id FROM device_placements WHERE hardware_key_id = ?1",
            params![minted[0].1],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored.as_slice(), container.device_id().as_slice());

    let pairs: Vec<(&str, i64)> = minted.iter().map(|(l, id, _)| (*l, *id)).collect();
    let key_id = flat_tree(&mut conn, &pairs, 2);
    let mut shares = HashMap::new();
    for (label, _, secret) in minted.iter().take(2) {
        let (node, raw) = share_for(&conn, key_id, label, secret);
        shares.insert(node, raw);
    }

    set_custody_policy(
        &conn,
        key_id,
        &CustodyPolicy {
            mode: CustodyMode::Logical,
            minimum_physical_devices: 2,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    assert!(matches!(
        key_tree::reconstruct(&conn, key_id, &shares),
        Err(Error::PhysicalDevicesNotMet)
    ));

    set_custody_policy(
        &conn,
        key_id,
        &CustodyPolicy {
            mode: CustodyMode::Logical,
            minimum_physical_devices: 1,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    key_tree::reconstruct(&conn, key_id, &shares).expect("logical mode meets shamir on one device");

    set_custody_policy(
        &conn,
        key_id,
        &CustodyPolicy {
            mode: CustodyMode::Hardware,
            minimum_physical_devices: 1,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    assert!(matches!(
        key_tree::reconstruct(&conn, key_id, &shares),
        Err(Error::CustodyViolation)
    ));
}

#[test]
fn moving_a_slot_changes_only_the_device_binding() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    let mut from = init(left.path()).unwrap();
    let mut to = init(right.path()).unwrap();
    let slot = provision(&mut from, "M.S.1", PASS).unwrap();
    let conn = db::open_in_memory().unwrap();
    let id =
        keys::register_key(&conn, "M.S.1", KeyType::Encryption, &slot.encryption_public).unwrap();
    bind_slot(&conn, &from, "M.S.1").unwrap();
    relocate_slot(&mut from, &mut to, "M.S.1", PASS).unwrap();
    let dest = open(right.path()).unwrap();
    bind_slot(&conn, &dest, "M.S.1").unwrap();
    let (device_id, slot_label): (Vec<u8>, String) = conn
        .query_row(
            "SELECT device_id, slot_label FROM device_placements WHERE hardware_key_id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(device_id.as_slice(), dest.device_id().as_slice());
    assert_ne!(device_id.as_slice(), from.device_id().as_slice());
    assert_eq!(slot_label, "M.S.1");
    let key = keys::get_key(&conn, id).unwrap();
    assert_eq!(key.public_key.as_slice(), slot.encryption_public.as_slice());
    assert!(from.slot("M.S.1").is_none());
}

#[test]
fn separate_containers_count_as_separate_devices() {
    let mut conn = db::open_in_memory().unwrap();
    let mut minted = Vec::new();
    for label in ["M.S", "M.S.1", "M.S.2"] {
        let dir = tempfile::tempdir().unwrap();
        let mut container = init(dir.path()).unwrap();
        let slot = provision(&mut container, label, PASS).unwrap();
        let id =
            keys::register_key(&conn, label, KeyType::Encryption, &slot.encryption_public).unwrap();
        bind_slot(&conn, &container, label).unwrap();
        minted.push((
            label,
            id,
            *slot.encryption_secret,
            *container.device_id(),
            dir,
        ));
    }
    let mut seen = HashSet::new();
    for (_, _, _, device_id, _) in &minted {
        assert!(seen.insert(*device_id));
    }
    let pairs: Vec<(&str, i64)> = minted.iter().map(|(l, id, _, _, _)| (*l, *id)).collect();
    let key_id = flat_tree(&mut conn, &pairs, 2);
    set_custody_policy(
        &conn,
        key_id,
        &CustodyPolicy {
            mode: CustodyMode::Hardware,
            minimum_physical_devices: 2,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    let mut shares = HashMap::new();
    for (label, _, secret, _, _) in minted.iter().take(2) {
        let (node, raw) = share_for(&conn, key_id, label, secret);
        shares.insert(node, raw);
    }
    key_tree::reconstruct(&conn, key_id, &shares)
        .expect("two of three identities on separate containers meet the minimum");
}

#[test]
fn placement_follows_the_opened_device_kq() {
    let dir = tempfile::tempdir().unwrap();
    let mut container = init(dir.path()).unwrap();
    let slot = provision(&mut container, "M.S.1", PASS).unwrap();
    let conn = db::open_in_memory().unwrap();
    let id =
        keys::register_key(&conn, "M.S.1", KeyType::Encryption, &slot.encryption_public).unwrap();
    bind_slot(&conn, &container, "M.S.1").unwrap();

    // device_id sits immediately after magic and version. Rewriting it is
    // still a valid descriptor. The next open is the only id bind will store.
    let path = dir.path().join("device.kq");
    let mut bytes = fs::read(&path).unwrap();
    bytes[5] ^= 0xff;
    fs::write(&path, &bytes).unwrap();
    let reopened = open(dir.path()).unwrap();
    assert_ne!(reopened.device_id(), container.device_id());
    bind_slot(&conn, &reopened, "M.S.1").unwrap();
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT device_id FROM device_placements WHERE hardware_key_id = ?1",
            params![id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored.as_slice(), reopened.device_id().as_slice());
}
