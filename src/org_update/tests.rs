use super::*;
use crate::db;
use crate::key_tree::NodeSpec;
use crate::private_bridge::BridgePartyInput;
use rusqlite::Connection;
use std::collections::{BTreeMap, HashMap, HashSet};
use zeroize::Zeroizing;

const LEAVES: [&str; 5] = ["M.A.1", "M.A.2", "M.A.3", "M.S.1", "M.S.2"];

/// The coordinator store: the split tree, the encryption secret of every
/// leaf (so tests can unwrap shares the way each token's holder would),
/// and `M`'s signing secret, which is the authority over the whole tree.
struct Org {
    conn: Connection,
    key_id: i64,
    secrets: BTreeMap<String, crypto_box::SecretKey>,
    authority: Zeroizing<[u8; 32]>,
    authority_public: [u8; 32],
}

fn register_encryption(conn: &Connection, label: &str) -> (i64, crypto_box::SecretKey) {
    let secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let public = *secret.public_key().as_bytes();
    let id = keys::register_key(conn, label, KeyType::Encryption, &public).expect("register");
    (id, secret)
}

fn register_signing(conn: &Connection, label: &str) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let (secret, public) = keys::generate_signing_keypair();
    keys::register_key(conn, label, KeyType::Signing, &public).expect("register signing");
    (secret, public)
}

fn two_branch_spec(ids: &BTreeMap<String, i64>) -> NodeSpec {
    let leaf = |label: &str| NodeSpec::Leaf {
        label: label.into(),
        hardware_key_id: ids[label],
        allowed_bridges: vec![],
    };
    NodeSpec::Split {
        label: "M".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Split {
                label: "M.A".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![leaf("M.A.1"), leaf("M.A.2"), leaf("M.A.3")],
            },
            NodeSpec::Split {
                label: "M.S".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![leaf("M.S.1"), leaf("M.S.2")],
            },
        ],
    }
}

fn coordinator() -> Org {
    let mut conn = db::open_in_memory().expect("schema");
    let mut ids = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    for label in LEAVES {
        let (id, secret) = register_encryption(&conn, label);
        ids.insert(label.to_string(), id);
        secrets.insert(label.to_string(), secret);
    }
    let (authority, authority_public) = register_signing(&conn, "M");
    let spec = two_branch_spec(&ids);
    let key_id = key_tree::split(&mut conn, "org", b"company master secret 32 bytes!", &spec)
        .expect("split");
    Org {
        conn,
        key_id,
        secrets,
        authority,
        authority_public,
    }
}

/// A personal store as a real device would have it before its first
/// update: the person's own encryption key, the signing key of the
/// authority they answer to, and the slice of the tree they can see.
fn person_store(org: &Org, label: &str) -> Connection {
    let conn = db::open_in_memory().expect("schema");
    let public = *org.secrets[label].public_key().as_bytes();
    keys::register_key(&conn, label, KeyType::Encryption, &public).expect("own key");
    keys::register_key(&conn, "M", KeyType::Signing, &org.authority_public).expect("authority");
    let slice = slice_for(org, label);
    key_tree::apply_public_tree(&conn, None, &slice).expect("seed slice");
    conn
}

/// A device with no topology yet: the person's own key and the authority
/// they trust, but nothing of the tree. A new joiner starts here.
fn bare_store(org: &Org, label: &str) -> Connection {
    let conn = db::open_in_memory().expect("schema");
    let public = *org.secrets[label].public_key().as_bytes();
    keys::register_key(&conn, label, KeyType::Encryption, &public).expect("own key");
    keys::register_key(&conn, "M", KeyType::Signing, &org.authority_public).expect("authority");
    conn
}

fn slice_for(org: &Org, label: &str) -> PublicTree {
    let full = key_tree::export_public_tree(&org.conn, org.key_id).expect("export");
    let visible = key_tree::visible_labels(&org.conn, org.key_id, label).expect("visible");
    key_tree::filter_public_tree(&full, &visible)
}

fn node_labels(conn: &Connection) -> HashSet<String> {
    let mut stmt = conn
        .prepare("SELECT label FROM key_nodes")
        .expect("prepare");
    stmt.query_map([], |row| row.get(0))
        .expect("query")
        .collect::<rusqlite::Result<HashSet<String>>>()
        .expect("labels")
}

fn active_labels(conn: &Connection) -> HashSet<String> {
    let mut stmt = conn
        .prepare("SELECT label FROM key_nodes WHERE is_active = 1")
        .expect("prepare");
    stmt.query_map([], |row| row.get(0))
        .expect("query")
        .collect::<rusqlite::Result<HashSet<String>>>()
        .expect("labels")
}

fn leaf_id(conn: &Connection, key_id: i64, label: &str) -> i64 {
    conn.query_row(
        "SELECT id FROM key_nodes WHERE key_id = ?1 AND label = ?2",
        params![key_id, label],
        |row| row.get(0),
    )
    .expect("leaf id")
}

fn raw_shares(org: &Org, labels: &[&str]) -> HashMap<i64, Vec<u8>> {
    labels
        .iter()
        .map(|label| {
            let id = leaf_id(&org.conn, org.key_id, label);
            let raw = key_tree::unwrap_leaf_share(&org.conn, id, &org.secrets[*label].to_bytes())
                .expect("unwrap share");
            (id, raw)
        })
        .collect()
}

fn package_for<'a>(packages: &'a [Addressed], label: &str) -> &'a Addressed {
    packages
        .iter()
        .find(|p| p.label == label)
        .unwrap_or_else(|| panic!("no envelope addressed to {label}"))
}

fn fingerprint_for(conn: &Connection, label: &str, key_type: &str) -> Option<String> {
    conn.query_row(
        "SELECT fingerprint FROM hardware_keys
         WHERE label = ?1 AND key_type = ?2 AND revoked_at IS NULL",
        params![label, key_type],
        |row| row.get(0),
    )
    .optional()
    .expect("fingerprint")
}

// ---------------------------------------------------------------------
// Authorization scope
// ---------------------------------------------------------------------

#[test]
fn authority_follows_the_dotted_label_hierarchy() {
    assert!(is_ancestor_or_self("M", "M.S.2"));
    assert!(is_ancestor_or_self("M.S", "M.S.2"));
    assert!(is_ancestor_or_self("M.S.2", "M.S.2"));

    assert!(!is_ancestor_or_self("M.A", "M.S.2"));
    assert!(!is_ancestor_or_self("M.S.3", "M.S.2"));
    assert!(!is_ancestor_or_self("M.S.2", "M.S"));
    // A shared prefix is not a shared lineage.
    assert!(!is_ancestor_or_self("M.S", "M.SALES.1"));
    assert!(!is_ancestor_or_self("", "M.S.2"));
    assert!(!is_ancestor_or_self("M", ""));
}

// ---------------------------------------------------------------------
// Key-tree restructure
// ---------------------------------------------------------------------

#[test]
fn adding_a_leaf_converges_every_store_on_the_new_topology() {
    let mut org = coordinator();
    let mut stores: BTreeMap<&str, Connection> = LEAVES
        .iter()
        .map(|label| (*label, person_store(&org, label)))
        .collect();

    // Restructure: a third engineer joins M.S, which reshares that split.
    let (new_id, new_secret) = register_encryption(&org.conn, "M.S.3");
    let presented = raw_shares(&org, &["M.S.1", "M.S.2"]);
    key_tree::add_leaf_and_reshare(
        &mut org.conn,
        org.key_id,
        "M.S",
        "M.S.3",
        new_id,
        &presented,
    )
    .expect("add leaf");
    org.secrets.insert("M.S.3".to_string(), new_secret);

    let planned = plan_tree_restructure(&org.conn, org.key_id, "M", &org.authority).expect("plan");
    assert!(planned.skipped.is_empty(), "M authorizes every leaf");
    assert_eq!(planned.packages.len(), 6);
    assert_eq!(planned.generation, 2);
    commit_planned_tree_restructure(&org.conn, &planned).expect("commit");

    // The new joiner's device has never seen the tree; this envelope is
    // the whole of their topology.
    stores.insert("M.S.3", bare_store(&org, "M.S.3"));

    for (label, conn) in &stores {
        let package = package_for(&planned.packages, label);
        let applied = import_update(conn, &package.bytes, &org.secrets[*label].to_bytes())
            .expect("import restructure");
        match applied {
            AppliedUpdate::TreeRestructure {
                generation,
                recipient_label,
                ..
            } => {
                assert_eq!(generation, 2);
                assert_eq!(recipient_label, *label);
            }
            other => panic!("expected a restructure, got {other:?}"),
        }
    }

    // Convergence: every store now holds exactly the slice the
    // coordinator would hand it, at the same generation.
    for (label, conn) in &stores {
        let expected = slice_for(&org, label);
        let expected_labels: HashSet<String> =
            expected.nodes.iter().map(|n| n.label.clone()).collect();
        assert_eq!(node_labels(conn), expected_labels, "{label} topology");
        let local = key_tree::export_public_tree(conn, 1).expect("local export");
        assert_eq!(local.generation, 2, "{label} generation");
    }

    // The engineers on M.S see the new colleague; accounting does not.
    assert!(node_labels(&stores["M.S.1"]).contains("M.S.3"));
    assert!(node_labels(&stores["M.S.2"]).contains("M.S.3"));
    assert!(!node_labels(&stores["M.A.1"]).contains("M.S.3"));
}

#[test]
fn evicting_a_leaf_deactivates_it_in_every_store_that_can_see_it() {
    let mut org = coordinator();
    let stores: BTreeMap<&str, Connection> = LEAVES
        .iter()
        .map(|label| (*label, person_store(&org, label)))
        .collect();

    let evicted = leaf_id(&org.conn, org.key_id, "M.A.2");
    let survivors = raw_shares(&org, &["M.A.1", "M.A.3"]);
    key_tree::evict_and_refresh(&mut org.conn, org.key_id, evicted, &survivors).expect("evict");

    let planned = plan_tree_restructure(&org.conn, org.key_id, "M", &org.authority).expect("plan");
    // An evicted leaf is no longer an active recipient.
    assert!(!planned.packages.iter().any(|p| p.label == "M.A.2"));
    commit_planned_tree_restructure(&org.conn, &planned).expect("commit");

    let conn = &stores["M.A.1"];
    import_update(
        conn,
        &package_for(&planned.packages, "M.A.1").bytes,
        &org.secrets["M.A.1"].to_bytes(),
    )
    .expect("import");

    assert!(node_labels(conn).contains("M.A.2"));
    assert!(!active_labels(conn).contains("M.A.2"));
}

#[test]
fn a_restructure_addressed_to_someone_else_changes_nothing() {
    let org = coordinator();
    let mine = person_store(&org, "M.S.1");
    let planned = plan_tree_restructure(&org.conn, org.key_id, "M", &org.authority).expect("plan");

    // Sealed to M.S.2's key: M.S.1 cannot even open it.
    let theirs = package_for(&planned.packages, "M.S.2");
    assert!(matches!(
        import_update(&mine, &theirs.bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::InvalidBridgePackage)
    ));

    // Opened on a store that does not hold M.S.2 under that key, the
    // recipient check refuses it before anything is written.
    let stranger = db::open_in_memory().expect("schema");
    keys::register_key(&stranger, "M", KeyType::Signing, &org.authority_public).expect("authority");
    assert!(matches!(
        import_update(&stranger, &theirs.bytes, &org.secrets["M.S.2"].to_bytes()),
        Err(Error::UpdateRecipientMismatch)
    ));
    assert!(node_labels(&stranger).is_empty());
}

#[test]
fn a_replayed_restructure_is_refused_and_leaves_the_store_alone() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    let planned = plan_tree_restructure(&org.conn, org.key_id, "M", &org.authority).expect("plan");
    commit_planned_tree_restructure(&org.conn, &planned).expect("commit");
    let package = package_for(&planned.packages, "M.S.1");

    import_update(&conn, &package.bytes, &org.secrets["M.S.1"].to_bytes()).expect("first import");
    let before = node_labels(&conn);

    assert!(matches!(
        import_update(&conn, &package.bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::StaleUpdate)
    ));
    assert_eq!(node_labels(&conn), before);
    assert_eq!(history(&conn, None).expect("history").len(), 1);
}

#[test]
fn a_restructure_signed_by_an_unrelated_branch_is_refused() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    // M.A is a real label with a real signing key, but has no standing
    // over M.S.1, and this store has never registered it either.
    let (peer_secret, peer_public) = keys::generate_signing_keypair();
    keys::register_key(&conn, "M.A", KeyType::Signing, &peer_public).expect("register peer");

    let slice = slice_for(&org, "M.S.1");
    let letter = TreeLetter {
        tree_label: slice.label.clone(),
        generation: slice.generation + 1,
        recipient_label: "M.S.1".into(),
        authorizer_label: "M.A".into(),
        slice_json: serde_json::to_vec(&PublicTree {
            generation: slice.generation + 1,
            ..slice
        })
        .expect("json"),
    };
    let recipient = *org.secrets["M.S.1"].public_key().as_bytes();
    let bytes = letter
        .seal(&recipient, &SigningKey::from_bytes(&peer_secret))
        .expect("seal");

    assert!(matches!(
        import_update(&conn, &bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::UpdateNotAuthorized)
    ));
}

#[test]
fn a_restructure_the_authority_did_not_sign_is_refused() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    let (impostor, _) = keys::generate_signing_keypair();

    let slice = slice_for(&org, "M.S.1");
    let letter = TreeLetter {
        tree_label: slice.label.clone(),
        generation: slice.generation + 1,
        recipient_label: "M.S.1".into(),
        authorizer_label: "M".into(),
        slice_json: serde_json::to_vec(&PublicTree {
            generation: slice.generation + 1,
            ..slice
        })
        .expect("json"),
    };
    let recipient = *org.secrets["M.S.1"].public_key().as_bytes();
    let bytes = letter
        .seal(&recipient, &SigningKey::from_bytes(&impostor))
        .expect("seal");

    assert!(matches!(
        import_update(&conn, &bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::SignatureVerificationFailed)
    ));
}

#[test]
fn planning_refuses_a_signing_key_that_is_not_the_authority_label() {
    let org = coordinator();
    let (other, _) = keys::generate_signing_keypair();
    assert!(matches!(
        plan_tree_restructure(&org.conn, org.key_id, "M", &other),
        Err(Error::UpdateNotAuthorized)
    ));
}

#[test]
fn a_department_manager_only_gets_envelopes_for_their_own_branch() {
    let org = coordinator();
    let (manager, manager_public) = keys::generate_signing_keypair();
    keys::register_key(&org.conn, "M.S", KeyType::Signing, &manager_public).expect("register");

    let planned = plan_tree_restructure(&org.conn, org.key_id, "M.S", &manager).expect("plan");
    let addressed: Vec<&str> = planned.packages.iter().map(|p| p.label.as_str()).collect();
    assert_eq!(addressed, vec!["M.S.1", "M.S.2"]);
    assert_eq!(
        planned.skipped,
        vec![
            "M.A.1".to_string(),
            "M.A.2".to_string(),
            "M.A.3".to_string()
        ]
    );
}

// ---------------------------------------------------------------------
// Hardware-key reissue
// ---------------------------------------------------------------------

#[test]
fn reissuing_a_token_converges_every_store_on_the_new_key() {
    let org = coordinator();
    let mut stores: BTreeMap<&str, Connection> = LEAVES
        .iter()
        .map(|label| (*label, person_store(&org, label)))
        .collect();
    // Only M.S.1 and M.S.2 ever held M.S.2's key; accounting's slice has
    // never named that person.
    let notified = ["M.S.1", "M.S.2"];
    let old_fingerprint =
        fingerprint_for(&stores["M.S.1"], "M.S.2", "encryption").expect("old fingerprint");

    // M.S.2's replacement token. Their own device registers the new key
    // when it generates it, which is also what lets them open the copy
    // addressed to that key.
    let (replacement, new_public) = keys::generate_encryption_keypair();
    keys::register_key(&stores["M.S.2"], "M.S.2", KeyType::Encryption, &new_public)
        .expect("register replacement");

    let planned = plan_key_reissue(
        &org.conn,
        Some(org.key_id),
        "M.S.2",
        Some(new_public),
        None,
        true,
        "M",
        &org.authority,
    )
    .expect("plan");
    assert_eq!(planned.sequence(), 1);
    let addressed: Vec<&str> = planned.packages.iter().map(|p| p.label.as_str()).collect();
    assert_eq!(addressed, notified.to_vec());
    // The subject's copy goes to the incoming key, not the retired one.
    assert_eq!(
        package_for(&planned.packages, "M.S.2").recipient_public_key,
        new_public
    );
    commit_planned_key_reissue(&org.conn, &planned).expect("commit");

    for label in notified {
        let conn = stores.get_mut(label).expect("store");
        let secret: [u8; 32] = if label == "M.S.2" {
            *replacement
        } else {
            org.secrets[label].to_bytes()
        };
        let applied = import_update(conn, &package_for(&planned.packages, label).bytes, &secret)
            .expect("import reissue");
        assert_eq!(
            applied,
            AppliedUpdate::KeyReissue {
                tree_label: "org".into(),
                subject_label: "M.S.2".into(),
                recipient_label: label.into(),
                sequence: 1,
                encryption_rotated: true,
                signing_rotated: false,
            }
        );
    }

    let expected = keys::fingerprint(&new_public);
    for label in notified {
        assert_eq!(
            fingerprint_for(&stores[label], "M.S.2", "encryption"),
            Some(expected.clone()),
            "{label} should hold M.S.2's new key"
        );
        let still_live: i64 = stores[label]
            .query_row(
                "SELECT COUNT(*) FROM hardware_keys WHERE fingerprint = ?1 AND revoked_at IS NULL",
                params![old_fingerprint],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(still_live, 0, "{label} should have retired the old key");
    }
    assert_eq!(
        fingerprint_for(&org.conn, "M.S.2", "encryption"),
        Some(expected)
    );
    // Accounting was never told, and never had anything to tell.
    assert_eq!(
        fingerprint_for(&stores["M.A.1"], "M.S.2", "encryption"),
        None
    );

    // The retired token's sealed share cannot be opened by its
    // replacement, so it is dropped rather than carried over.
    let carried: Option<Vec<u8>> = stores["M.S.2"]
        .query_row(
            "SELECT wrapped_share FROM key_nodes WHERE label = 'M.S.2'",
            [],
            |row| row.get(0),
        )
        .expect("share");
    assert!(carried.is_none());
}

#[test]
fn a_reissue_updates_every_private_bridge_roster_that_named_the_subject() {
    let org = coordinator();
    let conn = db::open_in_memory().expect("schema");

    let mut pubs = BTreeMap::new();
    for label in ["M.S.2", "M.S.3", "M.S"] {
        let (_, secret) = register_encryption(&conn, label);
        pubs.insert(label.to_string(), *secret.public_key().as_bytes());
    }
    let (_, sign_s2) = register_signing(&conn, "M.S.2");
    let (_, sign_s3) = register_signing(&conn, "M.S.3");
    keys::register_key(&conn, "M", KeyType::Signing, &org.authority_public).expect("authority");

    let member = |label: &str, signing: [u8; 32]| BridgePartyInput {
        label: label.into(),
        encryption_public_key: pubs[label],
        signing_public_key: Some(signing),
    };
    private_bridge::create(
        &conn,
        None,
        Some("eng"),
        &[member("M.S.2", sign_s2), member("M.S.3", sign_s3)],
        &[BridgePartyInput {
            label: "M.S".into(),
            encryption_public_key: pubs["M.S"],
            signing_public_key: None,
        }],
        Some("M.S.2"),
    )
    .expect("bridge");

    let (_, new_sign) = keys::generate_signing_keypair();
    let planned = plan_key_reissue(
        &conn,
        None,
        "M.S.3",
        None,
        Some(new_sign),
        false,
        "M",
        &org.authority,
    )
    .expect("plan");
    // Every store on that bridge is notified, supervisor included.
    let addressed: Vec<&str> = planned.packages.iter().map(|p| p.label.as_str()).collect();
    assert_eq!(addressed, vec!["M.S", "M.S.2", "M.S.3"]);
    commit_planned_key_reissue(&conn, &planned).expect("commit");

    let roster: Vec<u8> = conn
        .query_row(
            "SELECT signing_public_key FROM private_bridge_members WHERE node_label = 'M.S.3'",
            [],
            |row| row.get(0),
        )
        .expect("roster");
    assert_eq!(roster, new_sign.to_vec());
}

#[test]
fn a_reissue_that_skips_a_sequence_is_refused() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    let (_, new_public) = keys::generate_encryption_keypair();

    let letter = ReissueLetter {
        tree_label: "org".into(),
        subject_label: "M.S.2".into(),
        sequence: 2,
        recipient_label: "M.S.1".into(),
        authorizer_label: "M".into(),
        new_encryption_public_key: Some(new_public),
        new_signing_public_key: None,
        revoke_previous: false,
        previous_encryption_fingerprint: String::new(),
        previous_signing_fingerprint: String::new(),
    };
    let recipient = *org.secrets["M.S.1"].public_key().as_bytes();
    let bytes = letter
        .seal(&recipient, &SigningKey::from_bytes(&org.authority))
        .expect("seal");

    assert!(matches!(
        import_update(&conn, &bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::StaleUpdate)
    ));
    assert!(history(&conn, None).expect("history").is_empty());
}

#[test]
fn a_reissue_naming_a_key_this_store_already_replaced_is_refused() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    let (_, new_public) = keys::generate_encryption_keypair();

    let letter = ReissueLetter {
        tree_label: "org".into(),
        subject_label: "M.S.2".into(),
        sequence: 1,
        recipient_label: "M.S.1".into(),
        authorizer_label: "M".into(),
        new_encryption_public_key: Some(new_public),
        new_signing_public_key: None,
        revoke_previous: true,
        // Names a token this store has never held for M.S.2.
        previous_encryption_fingerprint: keys::fingerprint(&[9u8; 32]),
        previous_signing_fingerprint: String::new(),
    };
    let recipient = *org.secrets["M.S.1"].public_key().as_bytes();
    let bytes = letter
        .seal(&recipient, &SigningKey::from_bytes(&org.authority))
        .expect("seal");

    assert!(matches!(
        import_update(&conn, &bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::StaleUpdate)
    ));
    let unchanged = fingerprint_for(&conn, "M.S.2", "encryption").expect("still there");
    assert_eq!(
        unchanged,
        keys::fingerprint(org.secrets["M.S.2"].public_key().as_bytes())
    );
}

#[test]
fn a_peer_cannot_authorize_a_reissue_for_someone_else() {
    let org = coordinator();
    let (peer, peer_public) = keys::generate_signing_keypair();
    keys::register_key(&org.conn, "M.A", KeyType::Signing, &peer_public).expect("register");
    let (_, new_public) = keys::generate_encryption_keypair();

    // The producer refuses to build the letter at all …
    assert!(matches!(
        plan_key_reissue(
            &org.conn,
            Some(org.key_id),
            "M.S.2",
            Some(new_public),
            None,
            false,
            "M.A",
            &peer,
        ),
        Err(Error::UpdateNotAuthorized)
    ));

    // … and a store refuses one that was built anyway.
    let conn = person_store(&org, "M.S.1");
    keys::register_key(&conn, "M.A", KeyType::Signing, &peer_public).expect("register");
    let letter = ReissueLetter {
        tree_label: "org".into(),
        subject_label: "M.S.2".into(),
        sequence: 1,
        recipient_label: "M.S.1".into(),
        authorizer_label: "M.A".into(),
        new_encryption_public_key: Some(new_public),
        new_signing_public_key: None,
        revoke_previous: false,
        previous_encryption_fingerprint: String::new(),
        previous_signing_fingerprint: String::new(),
    };
    let recipient = *org.secrets["M.S.1"].public_key().as_bytes();
    let bytes = letter
        .seal(&recipient, &SigningKey::from_bytes(&peer))
        .expect("seal");
    assert!(matches!(
        import_update(&conn, &bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::UpdateNotAuthorized)
    ));
}

#[test]
fn a_replayed_reissue_is_refused() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    let (_, new_public) = keys::generate_encryption_keypair();
    let planned = plan_key_reissue(
        &org.conn,
        Some(org.key_id),
        "M.S.2",
        Some(new_public),
        None,
        true,
        "M",
        &org.authority,
    )
    .expect("plan");
    let package = package_for(&planned.packages, "M.S.1");

    import_update(&conn, &package.bytes, &org.secrets["M.S.1"].to_bytes()).expect("first");
    assert!(matches!(
        import_update(&conn, &package.bytes, &org.secrets["M.S.1"].to_bytes()),
        Err(Error::StaleUpdate)
    ));
    assert_eq!(history(&conn, None).expect("history").len(), 1);
}

#[test]
fn a_tampered_envelope_is_refused() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    let (_, new_public) = keys::generate_encryption_keypair();
    let planned = plan_key_reissue(
        &org.conn,
        Some(org.key_id),
        "M.S.2",
        Some(new_public),
        None,
        false,
        "M",
        &org.authority,
    )
    .expect("plan");

    let mut bytes = package_for(&planned.packages, "M.S.1").bytes.clone();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    assert!(import_update(&conn, &bytes, &org.secrets["M.S.1"].to_bytes()).is_err());
    assert!(history(&conn, None).expect("history").is_empty());
}

#[test]
fn a_reissue_needs_at_least_one_new_key() {
    let org = coordinator();
    assert!(matches!(
        plan_key_reissue(
            &org.conn,
            Some(org.key_id),
            "M.S.2",
            None,
            None,
            false,
            "M",
            &org.authority,
        ),
        Err(Error::InvalidUpdatePackage)
    ));
}

// ---------------------------------------------------------------------
// Delivery: one mailbox, both envelope families
// ---------------------------------------------------------------------

#[test]
fn import_any_routes_bridge_and_update_envelopes_from_one_inbox() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");

    let planned = plan_tree_restructure(&org.conn, org.key_id, "M", &org.authority).expect("plan");
    commit_planned_tree_restructure(&org.conn, &planned).expect("commit");
    let update = package_for(&planned.packages, "M.S.1");

    match import_any(&conn, &update.bytes, &org.secrets["M.S.1"].to_bytes()).expect("import") {
        ImportedEnvelope::Update(AppliedUpdate::TreeRestructure { generation, .. }) => {
            assert_eq!(generation, 2)
        }
        other => panic!("expected a tree restructure, got {other:?}"),
    }

    // A private-bridge invite addressed to the same store still lands as a
    // bridge, because the kind byte in the outer header decides.
    let (peer_secret, peer_signing) = keys::generate_signing_keypair();
    let _ = peer_secret;
    let (_, own_signing) = register_signing(&conn, "M.S.1");
    let peer = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let manager = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let created = private_bridge::create(
        &db::open_in_memory().expect("schema"),
        None,
        Some("eng"),
        &[
            BridgePartyInput {
                label: "M.S.1".into(),
                encryption_public_key: *org.secrets["M.S.1"].public_key().as_bytes(),
                signing_public_key: Some(own_signing),
            },
            BridgePartyInput {
                label: "M.S.9".into(),
                encryption_public_key: *peer.public_key().as_bytes(),
                signing_public_key: Some(peer_signing),
            },
        ],
        &[BridgePartyInput {
            label: "M.S".into(),
            encryption_public_key: *manager.public_key().as_bytes(),
            signing_public_key: None,
        }],
        None,
    )
    .expect("bridge");
    let invite = created
        .packages
        .iter()
        .find(|p| p.label == "M.S.1")
        .expect("invite");

    match import_any(&conn, &invite.bytes, &org.secrets["M.S.1"].to_bytes()).expect("import") {
        ImportedEnvelope::Bridge(summary) => assert_eq!(summary.uid, created.uid),
        other => panic!("expected a bridge import, got {other:?}"),
    }
}

#[test]
fn the_relay_routes_update_envelopes_without_opening_them() {
    let org = coordinator();
    let conn = person_store(&org, "M.S.1");
    let planned = plan_tree_restructure(&org.conn, org.key_id, "M", &org.authority).expect("plan");
    commit_planned_tree_restructure(&org.conn, &planned).expect("commit");

    let mailbox = crate::relay::open_in_memory().expect("relay schema");
    for package in &planned.packages {
        crate::relay::store(&mailbox, &package.bytes).expect("store");
    }

    let mine = keys::fingerprint(org.secrets["M.S.1"].public_key().as_bytes());
    let page = crate::relay::list_after(&mailbox, &mine, None, None).expect("list");
    assert_eq!(page.envelopes.len(), 1);
    // Stored verbatim: the relay neither unsealed nor rewrote the letter.
    assert_eq!(
        page.envelopes[0].bytes,
        package_for(&planned.packages, "M.S.1").bytes
    );

    import_update(
        &conn,
        &page.envelopes[0].bytes,
        &org.secrets["M.S.1"].to_bytes(),
    )
    .expect("import from the mailbox");
}

#[test]
fn the_subjects_replacement_device_applies_its_own_reissue() {
    let org = coordinator();
    // A device holding only the incoming key: that registration is what
    // lets it open the envelope addressed to it, and its view of M.S.2 is
    // already the new token rather than the retired one.
    let conn = db::open_in_memory().expect("schema");
    let (replacement, new_public) = keys::generate_encryption_keypair();
    keys::register_key(&conn, "M.S.2", KeyType::Encryption, &new_public).expect("new key");
    keys::register_key(&conn, "M", KeyType::Signing, &org.authority_public).expect("authority");

    let planned = plan_key_reissue(
        &org.conn,
        Some(org.key_id),
        "M.S.2",
        Some(new_public),
        None,
        true,
        "M",
        &org.authority,
    )
    .expect("plan");

    import_update(
        &conn,
        &package_for(&planned.packages, "M.S.2").bytes,
        &replacement,
    )
    .expect("the subject's own device applies it");
    assert_eq!(history(&conn, None).expect("history").len(), 1);

    // A store holding some third key for M.S.2 still refuses: it never saw
    // the token this envelope says it is replacing.
    let stranger = db::open_in_memory().expect("schema");
    let (_, unrelated) = keys::generate_encryption_keypair();
    keys::register_key(&stranger, "M.S.2", KeyType::Encryption, &unrelated).expect("unrelated");
    keys::register_key(
        &stranger,
        "M.S.1",
        KeyType::Encryption,
        org.secrets["M.S.1"].public_key().as_bytes(),
    )
    .expect("own key");
    keys::register_key(&stranger, "M", KeyType::Signing, &org.authority_public).expect("authority");
    assert!(matches!(
        import_update(
            &stranger,
            &package_for(&planned.packages, "M.S.1").bytes,
            &org.secrets["M.S.1"].to_bytes(),
        ),
        Err(Error::StaleUpdate)
    ));
}

#[test]
fn a_tree_scoped_reissue_leaves_another_trees_leaf_alone() {
    let org = coordinator();
    let (_, new_public) = keys::generate_encryption_keypair();
    let planned = plan_key_reissue(
        &org.conn,
        Some(org.key_id),
        "M.S.2",
        Some(new_public),
        None,
        true,
        "M",
        &org.authority,
    )
    .expect("plan");

    // A store whose only tree is a different one that happens to include
    // the same two people. The letter is scoped to `org`, so this store's
    // `side` leaf keeps pointing at the token it was sealed to.
    let mut conn = db::open_in_memory().expect("schema");
    let mut ids = BTreeMap::new();
    for label in ["M.S.1", "M.S.2"] {
        let public = *org.secrets[label].public_key().as_bytes();
        ids.insert(
            label.to_string(),
            keys::register_key(&conn, label, KeyType::Encryption, &public).expect("key"),
        );
    }
    keys::register_key(&conn, "M", KeyType::Signing, &org.authority_public).expect("authority");
    let spec = NodeSpec::flat_split(
        "M",
        2,
        vec![
            ("M.S.1".into(), ids["M.S.1"]),
            ("M.S.2".into(), ids["M.S.2"]),
        ],
    );
    let side = key_tree::split(
        &mut conn,
        "side",
        b"a different 32-byte escrowed key",
        &spec,
    )
    .expect("split");
    let before: i64 = conn
        .query_row(
            "SELECT hardware_key_id FROM key_nodes WHERE key_id = ?1 AND label = 'M.S.2'",
            params![side],
            |row| row.get(0),
        )
        .expect("leaf");

    import_update(
        &conn,
        &package_for(&planned.packages, "M.S.1").bytes,
        &org.secrets["M.S.1"].to_bytes(),
    )
    .expect("import");

    let after: i64 = conn
        .query_row(
            "SELECT hardware_key_id FROM key_nodes WHERE key_id = ?1 AND label = 'M.S.2'",
            params![side],
            |row| row.get(0),
        )
        .expect("leaf");
    assert_eq!(
        before, after,
        "a leaf outside the letter's tree is untouched"
    );
    // The new key is still registered, and the retired one retired: the
    // announcement itself is not tree-scoped, only the leaf repointing is.
    assert_eq!(
        fingerprint_for(&conn, "M.S.2", "encryption"),
        Some(keys::fingerprint(&new_public))
    );
}
