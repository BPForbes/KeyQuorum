//! The SQL entry point and the store-free one (`from_nodes` +
//! `StaticContext` + `reconstruct_presented_with`) are one rule: the same
//! tree and the same shares give the same answer on both.

use super::super::*;
use super::common::*;
use crate::db;
use crate::device::{self, CustodyMode, CustodyPolicy, UnlockApproval};
use crate::error::Error;
use std::collections::{BTreeMap, BTreeSet, HashMap};

struct Fixture {
    conn: Connection,
    key_id: i64,
    secret: Vec<u8>,
    key_ids: Vec<i64>,
    publics: Vec<Vec<u8>>,
    leaf_ids: Vec<i64>,
    raw: Vec<Vec<u8>>,
}

/// A 2-of-3 tree over leaves "a", "b", "c" in one SQLite store.
fn fixture() -> Fixture {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let mut key_ids = Vec::new();
    let mut publics = Vec::new();
    let mut secrets = Vec::new();
    for label in ["a", "b", "c"] {
        let (id, sk) = register_encryption_key(&conn, label);
        key_ids.push(id);
        publics.push(sk.public_key().as_bytes().to_vec());
        secrets.push(sk);
    }
    let spec = NodeSpec::flat_split(
        "root",
        2,
        vec![
            ("a".into(), key_ids[0]),
            ("b".into(), key_ids[1]),
            ("c".into(), key_ids[2]),
        ],
    );
    let secret = b"a secret both paths must agree on".to_vec();
    let key_id = split(&mut conn, "equiv", &secret, &spec).expect("split should succeed");
    let by_label = leaf_ids_by_label(&conn, key_id);
    let leaf_ids: Vec<i64> = ["a", "b", "c"].iter().map(|l| by_label[*l]).collect();
    let raw = leaf_ids
        .iter()
        .zip(&secrets)
        .map(|(id, sk)| unseal_leaf(&conn, *id, sk))
        .collect();
    Fixture {
        conn,
        key_id,
        secret,
        key_ids,
        publics,
        leaf_ids,
        raw,
    }
}

/// The same tree as plain rows, read back from the store.
fn node_inputs(conn: &Connection, key_id: i64) -> Vec<NodeInput> {
    let mut stmt = conn
        .prepare(
            "SELECT id, parent_id, label, threshold, hardware_key_id, is_active
             FROM key_nodes WHERE key_id = ?1 ORDER BY id",
        )
        .unwrap();
    stmt.query_map(params![key_id], |row| {
        Ok(NodeInput {
            db_id: row.get(0)?,
            parent_id: row.get(1)?,
            label: row.get(2)?,
            threshold: row.get(3)?,
            hardware_key_id: row.get(4)?,
            is_active: row.get::<_, i64>(5)? != 0,
            allowed_bridges: Vec::new(),
        })
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

fn static_context(f: &Fixture, policy: CustodyPolicy) -> StaticContext {
    let keys: BTreeMap<i64, StaticKey> = f
        .key_ids
        .iter()
        .zip(&f.publics)
        .map(|(id, public)| {
            let placement = f.conn
                .query_row(
                    "SELECT device_id, slot_label FROM device_placements WHERE hardware_key_id = ?1",
                    params![id],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .unwrap()
                .map(|(device_id, slot)| (device_id.as_slice().try_into().unwrap(), slot));
            (
                *id,
                StaticKey {
                    public_key: public.clone(),
                    placement,
                },
            )
        })
        .collect();
    StaticContext {
        ghosts: BTreeSet::new(),
        keys,
        policy,
    }
}

fn shares_of(f: &Fixture, which: &[usize]) -> HashMap<i64, Vec<u8>> {
    which
        .iter()
        .map(|i| (f.leaf_ids[*i], f.raw[*i].clone()))
        .collect()
}

fn place(f: &Fixture, which: usize, device_id: [u8; device::DEVICE_ID_LEN], slot: &str) {
    f.conn
        .execute(
            "INSERT INTO device_placements (hardware_key_id, device_id, slot_label)
             VALUES (?1, ?2, ?3)",
            params![f.key_ids[which], device_id.as_slice(), slot],
        )
        .unwrap();
}

fn policy_of(f: &Fixture) -> CustodyPolicy {
    device::custody_policy(&f.conn, f.key_id).unwrap()
}

/// Run both paths and return (sql, static).
fn both(
    f: &Fixture,
    ctx: &StaticContext,
    shares: &HashMap<i64, Vec<u8>>,
) -> (
    Result<PresentedReconstruction>,
    Result<PresentedReconstruction>,
) {
    let sql = reconstruct_presented(&f.conn, f.key_id, shares);
    let tree = KeyQuorumTree::from_nodes(&node_inputs(&f.conn, f.key_id)).unwrap();
    let stat = reconstruct_presented_with(&tree, ctx, shares);
    (sql, stat)
}

fn assert_same_success(
    sql: Result<PresentedReconstruction>,
    stat: Result<PresentedReconstruction>,
    secret: &[u8],
) {
    let sql = sql.expect("the SQL path should reconstruct");
    let stat = stat.expect("the static path should reconstruct");
    assert_eq!(sql.secret, secret);
    assert_eq!(stat.secret, sql.secret);
    assert_eq!(stat.leaves, sql.leaves);
    assert_eq!(stat.devices, sql.devices);
}

#[test]
fn both_paths_recover_the_same_secret_leaves_and_devices() {
    let f = fixture();
    device::set_custody_policy(
        &f.conn,
        f.key_id,
        &CustodyPolicy {
            mode: CustodyMode::Logical,
            minimum_physical_devices: 1,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    // a and b share one container; c is its own device.
    place(&f, 0, [7u8; device::DEVICE_ID_LEN], "slot-a");
    place(&f, 1, [7u8; device::DEVICE_ID_LEN], "slot-b");
    let ctx = static_context(&f, policy_of(&f));
    for which in [[0, 1], [0, 2], [1, 2]] {
        let shares = shares_of(&f, &which);
        let (sql, stat) = both(&f, &ctx, &shares);
        assert_same_success(sql, stat, &f.secret);
    }
}

#[test]
fn both_paths_refuse_below_the_threshold_alike() {
    let f = fixture();
    let ctx = static_context(&f, policy_of(&f));
    let shares = shares_of(&f, &[0]);
    let (sql, stat) = both(&f, &ctx, &shares);
    assert!(matches!(sql, Err(Error::QuorumNotMet)));
    assert!(matches!(stat, Err(Error::QuorumNotMet)));
}

#[test]
fn a_ghost_leaf_is_skipped_the_same_way_on_both_paths() {
    let f = fixture();
    f.conn
        .execute(
            "INSERT INTO key_identities
                 (id, label, parent_label, enc_public, sign_public, enc_fingerprint, sign_fingerprint)
             VALUES (?1, 'a', NULL, ?2, ?3, 'e', 's')",
            params![vec![5u8; 16], f.publics[0], vec![6u8; 32]],
        )
        .unwrap();
    f.conn
        .execute(
            "INSERT INTO key_possession (identity_id, state, generation) VALUES (?1, 'ghost', 1)",
            params![vec![5u8; 16]],
        )
        .unwrap();
    assert!(device::leaf_is_ghost(&f.conn, f.key_ids[0]).unwrap());

    let mut ctx = static_context(&f, policy_of(&f));
    ctx.ghosts.insert(f.key_ids[0]);

    // b and c still make the threshold: the ghost is passed over.
    let (sql, stat) = both(&f, &ctx, &shares_of(&f, &[0, 1, 2]));
    let (sql_leaves, stat_leaves) = (
        sql.as_ref().unwrap().leaves.clone(),
        stat.as_ref().unwrap().leaves.clone(),
    );
    assert_eq!(sql_leaves, stat_leaves);
    assert!(sql_leaves.iter().all(|l| l.hardware_key_id != f.key_ids[0]));
    assert_same_success(sql, stat, &f.secret);

    // The ghost plus one more is no quorum on either path.
    let (sql, stat) = both(&f, &ctx, &shares_of(&f, &[0, 1]));
    assert!(matches!(sql, Err(Error::QuorumNotMet)));
    assert!(matches!(stat, Err(Error::QuorumNotMet)));
}

#[test]
fn slots_on_one_container_are_no_quorum_on_either_path() {
    let f = fixture();
    device::set_custody_policy(
        &f.conn,
        f.key_id,
        &CustodyPolicy {
            mode: CustodyMode::Logical,
            minimum_physical_devices: 2,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    place(&f, 0, [7u8; device::DEVICE_ID_LEN], "slot-a");
    place(&f, 1, [7u8; device::DEVICE_ID_LEN], "slot-b");
    let ctx = static_context(&f, policy_of(&f));

    // a and b alone meet the threshold but sit on one device.
    let (sql, stat) = both(&f, &ctx, &shares_of(&f, &[0, 1]));
    assert!(matches!(sql, Err(Error::PhysicalDevicesNotMet)));
    assert!(matches!(stat, Err(Error::PhysicalDevicesNotMet)));

    // With c present, the subset search finds a pair on two devices.
    let (sql, stat) = both(&f, &ctx, &shares_of(&f, &[0, 1, 2]));
    let devices = sql.as_ref().unwrap().devices.len();
    assert_eq!(devices, 2);
    assert_same_success(sql, stat, &f.secret);
}

#[test]
fn hardware_custody_refuses_two_keys_on_one_device_on_both_paths() {
    let f = fixture();
    device::set_custody_policy(
        &f.conn,
        f.key_id,
        &CustodyPolicy {
            mode: CustodyMode::Hardware,
            minimum_physical_devices: 1,
            unlock_approval: UnlockApproval::None,
        },
    )
    .unwrap();
    place(&f, 0, [7u8; device::DEVICE_ID_LEN], "slot-a");
    place(&f, 1, [7u8; device::DEVICE_ID_LEN], "slot-b");
    let ctx = static_context(&f, policy_of(&f));
    let (sql, stat) = both(&f, &ctx, &shares_of(&f, &[0, 1]));
    assert!(matches!(sql, Err(Error::CustodyViolation)));
    assert!(matches!(stat, Err(Error::CustodyViolation)));
}

#[test]
fn from_nodes_builds_the_arena_load_builds() {
    let f = fixture();
    let loaded = KeyQuorumTree::load(&f.conn, f.key_id).unwrap();
    let built = KeyQuorumTree::from_nodes(&node_inputs(&f.conn, f.key_id)).unwrap();
    assert_eq!(loaded.root_index, built.root_index);
    assert_eq!(loaded.nodes.len(), built.nodes.len());
    for (l, b) in loaded.nodes.iter().zip(&built.nodes) {
        assert_eq!(l.db_id, b.db_id);
        assert_eq!(l.id, b.id);
        assert_eq!(l.parent_idx, b.parent_idx);
        assert_eq!(l.children_indices, b.children_indices);
        assert_eq!(l.threshold, b.threshold);
        assert_eq!(l.is_active, b.is_active);
        assert_eq!(l.hardware_key_id, b.hardware_key_id);
    }
}

fn row(db_id: i64, parent: Option<i64>, label: &str) -> NodeInput {
    NodeInput {
        db_id,
        parent_id: parent,
        label: label.into(),
        threshold: Some(1),
        hardware_key_id: None,
        is_active: true,
        allowed_bridges: Vec::new(),
    }
}

#[test]
fn from_nodes_refuses_what_load_refuses() {
    // No rows: `load` says NodeNotFound.
    assert!(matches!(
        KeyQuorumTree::from_nodes(&[]),
        Err(Error::NodeNotFound)
    ));
    // Two nodes with one label.
    assert!(matches!(
        KeyQuorumTree::from_nodes(&[row(1, None, "x"), row(2, Some(1), "x")]),
        Err(Error::DuplicateNodeLabel)
    ));
    // A parent that is not among the rows.
    assert!(matches!(
        KeyQuorumTree::from_nodes(&[row(1, None, "r"), row(2, Some(9), "c")]),
        Err(Error::NodeNotFound)
    ));
    // Every node has a parent (a cycle): no root.
    assert!(matches!(
        KeyQuorumTree::from_nodes(&[row(1, Some(2), "p"), row(2, Some(1), "q")]),
        Err(Error::NodeNotFound)
    ));
}
