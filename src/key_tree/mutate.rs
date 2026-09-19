use super::super::*;
use super::common::*;
use crate::db;
use std::collections::HashMap;

#[test]
fn unwrap_leaf_share_rejects_the_wrong_secret() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "alice");
    let (id_b, sk_b) = register_encryption_key(&conn, "bob");
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
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "flat", secret, &spec).expect("split should succeed");
    let leaves = leaf_ids_by_label(&conn, key_id);
    assert!(super::super::unwrap_leaf_share(&conn, leaves["a"], &sk_b.to_bytes()).is_err());
    let raw = super::super::unwrap_leaf_share(&conn, leaves["a"], &sk_a.to_bytes())
        .expect("matching secret should unwrap");
    assert!(!raw.is_empty());
}

#[test]
fn export_spec_omits_inactive_leaves_and_keeps_binds() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, sk_s) = register_encryption_key(&conn, "software");
    let (id_a, sk_a) = register_encryption_key(&conn, "accounting");
    let spec = two_department_spec(id_s, id_a);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "master", secret, &spec).expect("split");
    bind_all_sibling_leaf_pairs(&conn, key_id).expect("auto-bind");
    let exported = export_spec(&conn, key_id).expect("export");
    match exported {
        NodeSpec::Split {
            label,
            threshold,
            children,
            ..
        } => {
            assert_eq!(label, "M");
            assert_eq!(threshold, 2);
            assert_eq!(children.len(), 2);
            let mut peers = children[0].allowed_bridges().to_vec();
            peers.sort();
            assert!(peers.contains(&"M.A".to_string()) || peers.contains(&"M.S".to_string()));
        }
        NodeSpec::Leaf { .. } => panic!("expected split"),
    }

    let (id_f, _sk_f) = register_encryption_key(&conn, "finance");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let mut presented = HashMap::new();
    presented.insert(leaves["M.S"], unseal_leaf(&conn, leaves["M.S"], &sk_s));
    presented.insert(leaves["M.A"], unseal_leaf(&conn, leaves["M.A"], &sk_a));
    add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &presented).expect("add");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let evicted = leaves["M.F"];
    let mut survivors = HashMap::new();
    survivors.insert(leaves["M.S"], unseal_leaf(&conn, leaves["M.S"], &sk_s));
    survivors.insert(leaves["M.A"], unseal_leaf(&conn, leaves["M.A"], &sk_a));
    evict_and_refresh(&mut conn, key_id, evicted, &survivors).expect("evict finance");
    match export_spec(&conn, key_id).expect("export after evict") {
        NodeSpec::Split { children, .. } => {
            let labels: Vec<_> = children.iter().map(|c| c.label().to_string()).collect();
            assert_eq!(labels, vec!["M.S".to_string(), "M.A".to_string()]);
        }
        NodeSpec::Leaf { .. } => panic!("expected split"),
    }
}

#[test]
fn add_leaf_rejects_duplicate_or_zero_share_coordinates() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, sk_s) = register_encryption_key(&conn, "software");
    let (id_a, sk_a) = register_encryption_key(&conn, "accounting");
    let (id_f, _sk_f) = register_encryption_key(&conn, "finance");
    let spec = two_department_spec(id_s, id_a);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "master", secret, &spec).expect("split");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_s = unseal_leaf(&conn, leaves["M.S"], &sk_s);
    let raw_a = unseal_leaf(&conn, leaves["M.A"], &sk_a);
    let before = wrapped_shares_by_id(&conn, key_id);

    let mut duplicate = HashMap::new();
    duplicate.insert(leaves["M.S"], raw_s.clone());
    duplicate.insert(leaves["M.A"], raw_s.clone());
    assert!(matches!(
        add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &duplicate),
        Err(Error::ShareShapeMismatch)
    ));
    assert_eq!(wrapped_shares_by_id(&conn, key_id), before);

    let mut zero_x = raw_s.clone();
    zero_x[0] = 0;
    let mut with_zero = HashMap::new();
    with_zero.insert(leaves["M.S"], zero_x);
    with_zero.insert(leaves["M.A"], raw_a.clone());
    assert!(matches!(
        add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &with_zero),
        Err(Error::ShareShapeMismatch)
    ));
    assert_eq!(wrapped_shares_by_id(&conn, key_id), before);

    let mut distinct = HashMap::new();
    distinct.insert(leaves["M.S"], raw_s);
    distinct.insert(leaves["M.A"], raw_a);
    add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &distinct)
        .expect("distinct shares should add");
    assert_ne!(wrapped_shares_by_id(&conn, key_id), before);
}

#[test]
fn adopt_reissued_hardware_key_repoints_the_leaf_and_drops_its_share() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, _) = register_encryption_key(&conn, "software");
    let (id_a, _) = register_encryption_key(&conn, "accounting");
    let spec = two_department_spec(id_s, id_a);
    let key_id = split(
        &mut conn,
        "master",
        b"company master secret 32 bytes!",
        &spec,
    )
    .expect("split");
    let leaves = leaf_ids_by_label(&conn, key_id);
    assert!(wrapped_shares_by_id(&conn, key_id).contains_key(&leaves["M.S"]));

    let hardware_key_id = |conn: &Connection, node_id: i64| -> i64 {
        conn.query_row(
            "SELECT hardware_key_id FROM key_nodes WHERE id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .expect("leaf row")
    };

    let (new_id, _) = register_encryption_key(&conn, "software-replacement");
    adopt_reissued_hardware_key(&conn, "M.S", Some(key_id), new_id).expect("adopt");

    assert_eq!(hardware_key_id(&conn, leaves["M.S"]), new_id);
    assert!(
        !wrapped_shares_by_id(&conn, key_id).contains_key(&leaves["M.S"]),
        "a share wrapped to the retired key cannot be opened by its replacement"
    );
    // The untouched sibling keeps its own key and share.
    assert_eq!(hardware_key_id(&conn, leaves["M.A"]), id_a);
    assert!(wrapped_shares_by_id(&conn, key_id).contains_key(&leaves["M.A"]));

    // Idempotent: re-running once already adopted changes nothing further.
    adopt_reissued_hardware_key(&conn, "M.S", Some(key_id), new_id).expect("adopt again");
    assert_eq!(hardware_key_id(&conn, leaves["M.S"]), new_id);
}

#[test]
fn adopt_reissued_hardware_key_respects_its_tree_scope() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, _) = register_encryption_key(&conn, "software");
    let (id_a, _) = register_encryption_key(&conn, "accounting");
    let spec = two_department_spec(id_s, id_a);
    let first = split(
        &mut conn,
        "master-1",
        b"company master secret 32 bytes!",
        &spec,
    )
    .expect("split first");
    let (id_s2, _) = register_encryption_key(&conn, "software-2");
    let (id_a2, _) = register_encryption_key(&conn, "accounting-2");
    let second = split(
        &mut conn,
        "master-2",
        b"a different 32-byte escrowed key.",
        &two_department_spec(id_s2, id_a2),
    )
    .expect("split second");
    // Rename the second tree's software leaf to collide with the first's.
    conn.execute(
        "UPDATE key_nodes SET label = 'M.S' WHERE key_id = ?1 AND label = 'M.S'",
        params![second],
    )
    .expect("rename");

    let (new_id, _) = register_encryption_key(&conn, "software-replacement");
    adopt_reissued_hardware_key(&conn, "M.S", Some(first), new_id).expect("adopt scoped");

    let first_leaves = leaf_ids_by_label(&conn, first);
    let second_leaves = leaf_ids_by_label(&conn, second);
    let first_hw: i64 = conn
        .query_row(
            "SELECT hardware_key_id FROM key_nodes WHERE id = ?1",
            params![first_leaves["M.S"]],
            |row| row.get(0),
        )
        .expect("first leaf");
    let second_hw: i64 = conn
        .query_row(
            "SELECT hardware_key_id FROM key_nodes WHERE id = ?1",
            params![second_leaves["M.S"]],
            |row| row.get(0),
        )
        .expect("second leaf");
    assert_eq!(first_hw, new_id);
    assert_eq!(
        second_hw, id_s2,
        "a leaf under a different tree is untouched"
    );
}

#[test]
fn active_encryption_leaves_lists_labels_with_their_registered_public_keys() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, sk_s) = register_encryption_key(&conn, "software");
    let (id_a, sk_a) = register_encryption_key(&conn, "accounting");
    let spec = two_department_spec(id_s, id_a);
    let key_id = split(
        &mut conn,
        "master",
        b"company master secret 32 bytes!",
        &spec,
    )
    .expect("split");

    let leaves = active_encryption_leaves(&conn, key_id).expect("list");
    assert_eq!(
        leaves,
        vec![
            ("M.A".to_string(), *sk_a.public_key().as_bytes()),
            ("M.S".to_string(), *sk_s.public_key().as_bytes()),
        ]
    );
}

#[test]
fn active_encryption_leaves_drops_an_evicted_leaf() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, sk_s) = register_encryption_key(&conn, "software");
    let (id_a, sk_a) = register_encryption_key(&conn, "accounting");
    let (id_f, _) = register_encryption_key(&conn, "finance");
    let spec = two_department_spec(id_s, id_a);
    let key_id = split(
        &mut conn,
        "master",
        b"company master secret 32 bytes!",
        &spec,
    )
    .expect("split");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let mut presented = HashMap::new();
    presented.insert(leaves["M.S"], unseal_leaf(&conn, leaves["M.S"], &sk_s));
    presented.insert(leaves["M.A"], unseal_leaf(&conn, leaves["M.A"], &sk_a));
    add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &presented).expect("add");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let mut survivors = HashMap::new();
    survivors.insert(leaves["M.S"], unseal_leaf(&conn, leaves["M.S"], &sk_s));
    survivors.insert(leaves["M.A"], unseal_leaf(&conn, leaves["M.A"], &sk_a));
    evict_and_refresh(&mut conn, key_id, leaves["M.F"], &survivors).expect("evict");

    let labels: Vec<String> = active_encryption_leaves(&conn, key_id)
        .expect("list")
        .into_iter()
        .map(|(label, _)| label)
        .collect();
    assert!(!labels.contains(&"M.F".to_string()));
    assert_eq!(labels, vec!["M.A".to_string(), "M.S".to_string()]);
}
