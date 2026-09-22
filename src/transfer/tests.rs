use super::*;
use crate::device::{self, Container};
use crate::error::Error;
use crate::key_tree::{self, NodeSpec};
use rusqlite::{params, Connection};
use std::collections::HashMap;

const PASS: &str = "slot-passphrase";

struct End {
    conn: Connection,
    _dir: tempfile::TempDir,
    container: Container,
}

fn end() -> End {
    let dir = tempfile::tempdir().unwrap();
    let container = device::init(dir.path()).unwrap();
    let conn = crate::db::open_in_memory().unwrap();
    End {
        conn,
        _dir: dir,
        container,
    }
}

fn enroll_all(end: &mut End, labels: &[&str]) {
    for label in labels {
        enroll(&end.conn, &mut end.container, label, PASS).unwrap();
    }
}

fn passes_for(conn: &Connection, label: &str, mode: DescendantMode) -> HashMap<String, String> {
    let labels = export_secret_labels(conn, label, mode).unwrap();
    labels
        .into_iter()
        .map(|label| (label, PASS.to_string()))
        .collect()
}

fn run(
    source: &mut End,
    dest: &mut End,
    actor: &str,
    label: &str,
    operation: TransferOp,
    descendants: DescendantMode,
    auth: &TransferAuth,
) -> Result<[u8; 16]> {
    let passphrases = passes_for(&source.conn, label, descendants);
    transfer(TransferRequest {
        source_conn: &source.conn,
        source: &mut source.container,
        dest_conn: &dest.conn,
        dest: &mut dest.container,
        actor,
        label,
        operation,
        descendants,
        passphrases: &passphrases,
        auth,
    })
}

fn state(end: &End, label: &str) -> Option<Possession> {
    possession(&end.conn, label).unwrap()
}

fn ident(end: &End, label: &str) -> IdentityInfo {
    identity(&end.conn, label).unwrap().expect(label)
}

fn slot_secret(end: &End, label: &str) -> [u8; 32] {
    let secrets = device::open_slot(&end.container, label, PASS).unwrap();
    *secrets.encryption_secret
}

fn force_ghost(end: &mut End, label: &str) {
    let id = ident(end, label).id;
    end.conn
        .execute(
            "UPDATE key_possession SET state = 'ghost' WHERE identity_id = ?1",
            params![id.to_vec()],
        )
        .unwrap();
    if end.container.slot(label).is_some() {
        device::remove_slot(&mut end.container, label).unwrap();
    }
}

fn assert_no_secret(conn: &Connection, secret: &[u8; 32]) {
    let hex_secret = hex::encode(secret);
    for sql in [
        "SELECT detail FROM transfer_audit",
        "SELECT detail FROM transfer_transactions",
    ] {
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
        for detail in rows {
            let detail = detail.unwrap();
            assert!(!detail.contains(&hex_secret), "{detail}");
            assert!(
                !detail
                    .as_bytes()
                    .windows(secret.len())
                    .any(|window| window == secret),
                "{detail}"
            );
        }
    }
}

fn audit_results(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT result FROM transfer_audit ORDER BY id")
        .unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
}

fn hardware_id(conn: &Connection, label: &str) -> i64 {
    let info = identity(conn, label).unwrap().unwrap();
    keys::get_key_by_fingerprint(conn, &info.enc_fingerprint)
        .unwrap()
        .id
}

fn leaf(label: &str, hardware_key_id: i64) -> NodeSpec {
    NodeSpec::Leaf {
        label: label.into(),
        hardware_key_id,
        allowed_bridges: vec![],
    }
}

#[test]
fn copy_and_move_work_for_empty_and_non_empty_receivers() {
    let mut source = end();
    enroll_all(&mut source, &["M", "M.S", "M.S.2"]);
    let secret = slot_secret(&source, "M.S.2");
    let mut empty = end();
    run(
        &mut source,
        &mut empty,
        "M.S.2",
        "M.S.2",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&source, "M.S.2"), Some(Possession::Active));
    assert_eq!(state(&empty, "M.S.2"), Some(Possession::Active));
    assert_eq!(ident(&source, "M.S.2").id, ident(&empty, "M.S.2").id);
    assert_eq!(slot_secret(&empty, "M.S.2"), secret);
    assert_eq!(
        provenance_devices(&source.conn, &ident(&source, "M.S.2").id),
        2
    );
    assert_no_secret(&source.conn, &secret);
    assert_no_secret(&empty.conn, &secret);

    let mut other = end();
    run(
        &mut source,
        &mut other,
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    run(
        &mut source,
        &mut other,
        "M.S",
        "M.S.2",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&other, "M.S.2"), Some(Possession::Active));
    assert_eq!(ident(&other, "M.S.2").id, ident(&source, "M.S.2").id);

    let mut mover = end();
    enroll_all(&mut mover, &["M.A"]);
    let mut dest = end();
    run(
        &mut mover,
        &mut dest,
        "M.A",
        "M.A",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&mover, "M.A"), Some(Possession::Ghost));
    assert!(mover.container.slot("M.A").is_none());
    assert_eq!(state(&dest, "M.A"), Some(Possession::Active));
    assert_eq!(ident(&mover, "M.A").generation, 2);
    assert_eq!(ident(&dest, "M.A").generation, 2);

    let mut branch = end();
    enroll_all(&mut branch, &["M", "M.A"]);
    let mut occupied = end();
    run(
        &mut branch,
        &mut occupied,
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    run(
        &mut branch,
        &mut occupied,
        "M",
        "M.A",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&branch, "M.A"), Some(Possession::Ghost));
    assert_eq!(state(&branch, "M"), Some(Possession::Active));
    assert_eq!(state(&occupied, "M.A"), Some(Possession::Active));
}

fn provenance_devices(conn: &Connection, id: &[u8; 16]) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM key_provenance WHERE identity_id = ?1",
        params![id.to_vec()],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn descendant_modes_cover_the_whole_subtree_and_partial_moves() {
    let mut source = end();
    enroll_all(
        &mut source,
        &["M", "M.S", "M.S.1", "M.S.1.A", "M.S.1.A.1", "M.S.2"],
    );
    let mut only = end();
    run(
        &mut source,
        &mut only,
        "M.S",
        "M.S",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&only, "M.S"), Some(Possession::Active));
    assert_eq!(state(&only, "M.S.1"), Some(Possession::Ghost));
    assert_eq!(state(&only, "M.S.1.A"), Some(Possession::Ghost));
    assert_eq!(state(&only, "M.S.1.A.1"), Some(Possession::Ghost));
    assert!(only.container.slot("M.S.1.A.1").is_none());
    assert_eq!(state(&source, "M.S.1.A.1"), Some(Possession::Active));

    let mut direct = end();
    run(
        &mut source,
        &mut direct,
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    run(
        &mut source,
        &mut direct,
        "M",
        "M.S",
        TransferOp::Copy,
        DescendantMode::DirectChildren,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&direct, "M.S"), Some(Possession::Active));
    assert_eq!(state(&direct, "M.S.1"), Some(Possession::Active));
    assert_eq!(state(&direct, "M.S.2"), Some(Possession::Active));
    assert_eq!(state(&direct, "M.S.1.A"), Some(Possession::Ghost));
    assert_eq!(state(&direct, "M.S.1.A.1"), Some(Possession::Ghost));

    let mut deep = end();
    run(
        &mut source,
        &mut deep,
        "M",
        "M.S",
        TransferOp::Move,
        DescendantMode::AllDescendants,
        &TransferAuth::default(),
    )
    .unwrap();
    for label in ["M.S", "M.S.1", "M.S.1.A", "M.S.1.A.1", "M.S.2"] {
        assert_eq!(state(&source, label), Some(Possession::Ghost), "{label}");
        assert_eq!(state(&deep, label), Some(Possession::Active), "{label}");
        assert!(source.container.slot(label).is_none(), "{label}");
    }
    assert_eq!(state(&source, "M"), Some(Possession::Active));
    assert_eq!(state(&deep, "M"), Some(Possession::Ghost));

    let mut parent_only = end();
    enroll_all(&mut parent_only, &["M", "M.A", "M.A.1", "M.A.2"]);
    let mut accounting = end();
    run(
        &mut parent_only,
        &mut accounting,
        "M.A",
        "M.A",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&parent_only, "M.A"), Some(Possession::Ghost));
    assert_eq!(state(&parent_only, "M.A.1"), Some(Possession::Active));
    assert_eq!(state(&parent_only, "M.A.2"), Some(Possession::Active));
    assert_eq!(state(&accounting, "M.A"), Some(Possession::Active));
    assert_eq!(state(&accounting, "M.A.1"), Some(Possession::Ghost));
    assert_eq!(state(&accounting, "M.A.2"), Some(Possession::Ghost));
    assert!(sign_active(
        &parent_only.conn,
        &parent_only.container,
        "M.A.1",
        PASS,
        b"ok"
    )
    .is_ok());

    let mut child_moves = end();
    enroll_all(&mut child_moves, &["M", "M.A", "M.A.1"]);
    let mut child_dest = end();
    run(
        &mut child_moves,
        &mut child_dest,
        "M.A",
        "M.A.1",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&child_moves, "M.A"), Some(Possession::Active));
    assert_eq!(state(&child_moves, "M.A.1"), Some(Possession::Ghost));
    assert_eq!(state(&child_dest, "M.A.1"), Some(Possession::Active));
    assert_eq!(state(&child_dest, "M.A"), Some(Possession::Ghost));
}

#[test]
fn ghosts_cannot_act_and_an_active_child_still_can() {
    let mut source = end();
    enroll_all(&mut source, &["M", "M.S", "M.S.1", "M.S.2"]);
    let child_secret = slot_secret(&source, "M.S.1");
    let mut dest = end();
    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M.S",
        "M.S",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &passes_for(&source.conn, "M.S", DescendantMode::KeyOnly),
        &TransferAuth::default(),
    )
    .unwrap();
    assert!(
        !prepared
            .package()
            .windows(32)
            .any(|window| window == child_secret),
        "a key-only package must not carry a child secret"
    );
    run(
        &mut source,
        &mut dest,
        "M.S",
        "M.S",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&source, "M.S"), Some(Possession::Ghost));
    assert_eq!(state(&source, "M.S.1"), Some(Possession::Active));
    assert_eq!(state(&source, "M.S.2"), Some(Possession::Active));
    assert!(sign_active(&source.conn, &source.container, "M.S", PASS, b"no").is_err());
    assert!(matches!(
        sign_active(&source.conn, &source.container, "M.S", PASS, b"no"),
        Err(Error::GhostDenied)
    ));
    assert!(sign_active(&source.conn, &source.container, "M.S.1", PASS, b"yes").is_ok());
    let labels = list_identities(&source.conn, false).unwrap();
    assert!(labels.iter().all(|row| row.label != "M.S"));
    let all = list_identities(&source.conn, true).unwrap();
    assert!(all
        .iter()
        .any(|row| row.label == "M.S" && row.state == Possession::Ghost));
    assert!(all.iter().any(|row| row.label == "M.S.2"));

    assert!(matches!(
        prepare(
            &source.conn,
            &source.container,
            dest.container.device_id(),
            "M",
            "M.S",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &HashMap::new(),
            &TransferAuth::default(),
        ),
        Err(Error::GhostDenied)
    ));
    assert!(audit_results(&source.conn)
        .iter()
        .any(|result| result == "denied"));

    let mut grandchild_src = end();
    enroll_all(&mut grandchild_src, &["M.S.1.A"]);
    let mut under_ghost = end();
    enroll_all(&mut under_ghost, &["M.S", "M.S.1"]);
    force_ghost(&mut under_ghost, "M.S");
    run(
        &mut grandchild_src,
        &mut under_ghost,
        "M.S.1.A",
        "M.S.1.A",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&under_ghost, "M.S"), Some(Possession::Ghost));
    assert_eq!(state(&under_ghost, "M.S.1.A"), Some(Possession::Active));
}

#[test]
fn receiver_rules_follow_active_ancestors_only() {
    let mut empty = end();
    let mut donor = end();
    enroll_all(&mut donor, &["M"]);
    run(
        &mut donor,
        &mut empty,
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&empty, "M"), Some(Possession::Active));

    let mut dest = end();
    enroll_all(&mut dest, &["M.A", "M.S"]);
    force_ghost(&mut dest, "M.S");
    let mut accounting = end();
    enroll_all(&mut accounting, &["M.A.1", "M.A.2"]);
    run(
        &mut accounting,
        &mut dest,
        "M.A.1",
        "M.A.1",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    run(
        &mut accounting,
        &mut dest,
        "M.A.2",
        "M.A.2",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();

    let mut software = end();
    enroll_all(&mut software, &["M.S.1", "M.S.2"]);
    assert!(matches!(
        run(
            &mut software,
            &mut dest,
            "M.S.1",
            "M.S.1",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &TransferAuth::default(),
        ),
        Err(Error::TransferDenied)
    ));
    assert_eq!(state(&dest, "M.S.1"), None);

    let mut manager = end();
    enroll_all(&mut manager, &["M"]);
    assert!(matches!(
        run(
            &mut manager,
            &mut dest,
            "M",
            "M",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &TransferAuth::default(),
        ),
        Err(Error::TransferDenied)
    ));
    let allowed = TransferAuth {
        allow_ancestor_import: true,
        ..TransferAuth::default()
    };
    run(
        &mut manager,
        &mut dest,
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &allowed,
    )
    .unwrap();

    let mut unrelated = end();
    enroll_all(&mut unrelated, &["M.A"]);
    let mut stranger = end();
    enroll_all(&mut stranger, &["M.S.2"]);
    assert!(matches!(
        run(
            &mut stranger,
            &mut unrelated,
            "M.S.2",
            "M.S.2",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &TransferAuth::default(),
        ),
        Err(Error::TransferDenied)
    ));
}

#[test]
fn identity_conflicts_fail_closed_and_matching_copies_reconcile() {
    let mut source = end();
    enroll_all(&mut source, &["M.S"]);
    let mut dest = end();
    enroll_all(&mut dest, &["M.S"]);
    let dest_id = ident(&dest, "M.S").id;
    let dest_fp = ident(&dest, "M.S").enc_fingerprint.clone();
    assert_ne!(ident(&source, "M.S").id, dest_id);
    assert!(matches!(
        run(
            &mut source,
            &mut dest,
            "M.S",
            "M.S",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &TransferAuth::default(),
        ),
        Err(Error::IdentityConflict)
    ));
    assert_eq!(ident(&dest, "M.S").id, dest_id);
    assert_eq!(ident(&dest, "M.S").enc_fingerprint, dest_fp);
    assert_eq!(state(&source, "M.S"), Some(Possession::Active));

    let mut left = end();
    enroll_all(&mut left, &["M.S.2"]);
    let mut right = end();
    run(
        &mut left,
        &mut right,
        "M.S.2",
        "M.S.2",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    run(
        &mut left,
        &mut right,
        "M.S.2",
        "M.S.2",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    let count: i64 = right
        .conn
        .query_row(
            "SELECT COUNT(*) FROM key_identities WHERE label = 'M.S.2'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(state(&left, "M.S.2"), Some(Possession::Active));
    assert_eq!(state(&right, "M.S.2"), Some(Possession::Active));

    let (other_secret, other_public) = keys::generate_encryption_keypair();
    let _ = other_secret;
    right
        .conn
        .execute(
            "UPDATE key_identities
             SET enc_public = ?1, enc_fingerprint = ?2
             WHERE label = 'M.S.2'",
            params![other_public.to_vec(), keys::fingerprint(&other_public)],
        )
        .unwrap();
    assert!(matches!(
        run(
            &mut left,
            &mut right,
            "M.S.2",
            "M.S.2",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &TransferAuth::default(),
        ),
        Err(Error::IdentityConflict)
    ));
    let stored: Vec<u8> = right
        .conn
        .query_row(
            "SELECT enc_public FROM key_identities WHERE label = 'M.S.2'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, other_public);
}

#[test]
fn move_stays_active_until_destination_commit_and_recovery_is_explicit() {
    let mut source = end();
    enroll_all(&mut source, &["M.A", "M.A.1"]);
    let mut dest = end();
    let passes = passes_for(&source.conn, "M.A", DescendantMode::AllDescendants);
    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M.A",
        "M.A",
        TransferOp::Move,
        DescendantMode::AllDescendants,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(
        recover_pair(
            &source.conn,
            &mut source.container,
            &dest.conn,
            &mut dest.container,
            &prepared.id,
        )
        .unwrap(),
        Recovery::Aborted
    );
    assert_eq!(state(&source, "M.A"), Some(Possession::Active));
    assert!(source.container.slot("M.A").is_some());

    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M.A",
        "M.A",
        TransferOp::Move,
        DescendantMode::AllDescendants,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    stage_destination(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    write_destination_slots(
        &dest.conn,
        &mut dest.container,
        &source.container,
        prepared.package(),
        &passes,
        Some(1),
    )
    .unwrap();
    assert_eq!(
        recover_pair(
            &source.conn,
            &mut source.container,
            &dest.conn,
            &mut dest.container,
            &prepared.id,
        )
        .unwrap(),
        Recovery::Aborted
    );
    assert_eq!(state(&source, "M.A"), Some(Possession::Active));
    assert!(dest.container.slot("M.A").is_none());
    assert!(identity(&dest.conn, "M.A").unwrap().is_none());

    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M.A",
        "M.A",
        TransferOp::Move,
        DescendantMode::AllDescendants,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    stage_destination(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    write_destination_slots(
        &dest.conn,
        &mut dest.container,
        &source.container,
        prepared.package(),
        &passes,
        None,
    )
    .unwrap();
    assert_eq!(state(&source, "M.A"), Some(Possession::Active));
    assert!(dest.container.slot("M.A").is_some());
    assert!(identity(&dest.conn, "M.A").unwrap().is_none());
    assert_eq!(
        recover_pair(
            &source.conn,
            &mut source.container,
            &dest.conn,
            &mut dest.container,
            &prepared.id,
        )
        .unwrap(),
        Recovery::Aborted
    );
    assert_eq!(state(&source, "M.A"), Some(Possession::Active));
    assert!(dest.container.slot("M.A").is_none());

    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M.A",
        "M.A",
        TransferOp::Move,
        DescendantMode::AllDescendants,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    stage_destination(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    write_destination_slots(
        &dest.conn,
        &mut dest.container,
        &source.container,
        prepared.package(),
        &passes,
        None,
    )
    .unwrap();
    commit_destination_rows(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    assert_eq!(state(&source, "M.A"), Some(Possession::Active));
    assert_eq!(state(&dest, "M.A"), Some(Possession::Active));
    assert_eq!(
        recover_pair(
            &source.conn,
            &mut source.container,
            &dest.conn,
            &mut dest.container,
            &prepared.id,
        )
        .unwrap(),
        Recovery::Finalized
    );
    assert_eq!(state(&source, "M.A"), Some(Possession::Ghost));
    assert_eq!(state(&source, "M.A.1"), Some(Possession::Ghost));
    assert_eq!(state(&dest, "M.A.1"), Some(Possession::Active));
    assert!(source.container.slot("M.A").is_none());
    assert_eq!(
        recover_pair(
            &source.conn,
            &mut source.container,
            &dest.conn,
            &mut dest.container,
            &prepared.id,
        )
        .unwrap(),
        Recovery::AlreadyComplete
    );
    assert_eq!(state(&source, "M.A"), Some(Possession::Ghost));

    dest.conn
        .execute(
            "UPDATE transfer_transactions SET package_hash = zeroblob(32) WHERE id = ?1",
            params![prepared.id.to_vec()],
        )
        .unwrap();
    let mut again = end();
    enroll_all(&mut again, &["M.S"]);
    let mut other = end();
    let second = prepare(
        &again.conn,
        &again.container,
        other.container.device_id(),
        "M.S",
        "M.S",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &passes_for(&again.conn, "M.S", DescendantMode::KeyOnly),
        &TransferAuth::default(),
    )
    .unwrap();
    stage_destination(
        &other.conn,
        &other.container,
        &again.container,
        second.package(),
        false,
    )
    .unwrap();
    other
        .conn
        .execute(
            "UPDATE transfer_transactions SET package_hash = zeroblob(32) WHERE id = ?1",
            params![second.id.to_vec()],
        )
        .unwrap();
    assert_eq!(
        recover_pair(
            &again.conn,
            &mut again.container,
            &other.conn,
            &mut other.container,
            &second.id,
        )
        .unwrap(),
        Recovery::NeedsAdmin
    );
    assert_eq!(state(&again, "M.S"), Some(Possession::Active));
}

#[test]
fn packages_are_authenticated_replay_resistant_and_policy_gated() {
    let mut source = end();
    enroll_all(&mut source, &["M", "M.S", "M.S.1"]);
    let secret = slot_secret(&source, "M.S.1");
    let mut dest = end();
    run(
        &mut source,
        &mut dest,
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    let passes = passes_for(&source.conn, "M.S.1", DescendantMode::KeyOnly);
    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M.S",
        "M.S.1",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    let mut tampered = prepared.package().to_vec();
    let flip = tampered.len() / 2;
    tampered[flip] ^= 0xff;
    assert!(matches!(
        stage_destination(
            &dest.conn,
            &dest.container,
            &source.container,
            &tampered,
            false
        ),
        Err(Error::SignatureVerificationFailed | Error::IntegrityCheckFailed)
    ));
    assert_eq!(state(&dest, "M.S.1"), Some(Possession::Ghost));

    let stranger = end();
    assert!(matches!(
        stage_destination(
            &dest.conn,
            &dest.container,
            &stranger.container,
            prepared.package(),
            false,
        ),
        Err(Error::SignatureVerificationFailed)
    ));

    stage_destination(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    assert!(matches!(
        stage_destination(
            &dest.conn,
            &dest.container,
            &source.container,
            prepared.package(),
            false,
        ),
        Err(Error::TransferReplay)
    ));
    write_destination_slots(
        &dest.conn,
        &mut dest.container,
        &source.container,
        prepared.package(),
        &passes,
        None,
    )
    .unwrap();
    commit_destination_rows(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    acknowledge(&dest.conn, &prepared.id).unwrap();
    finalize_source(
        &source.conn,
        &mut source.container,
        &dest.conn,
        &prepared.id,
    )
    .unwrap();
    assert_eq!(state(&source, "M.S.1"), Some(Possession::Active));
    assert_no_secret(&source.conn, &secret);
    assert_no_secret(&dest.conn, &secret);

    dest.conn
        .execute(
            "UPDATE key_possession SET generation = 4
             WHERE identity_id = (SELECT id FROM key_identities WHERE label = 'M.S.1')",
            [],
        )
        .unwrap();
    assert!(matches!(
        run(
            &mut source,
            &mut dest,
            "M.S",
            "M.S.1",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &TransferAuth::default(),
        ),
        Err(Error::TransferReplay)
    ));

    let blocked = TransferAuth {
        self_copy: false,
        descendant_copy: false,
        ..TransferAuth::default()
    };
    assert!(matches!(
        run(
            &mut source,
            &mut dest,
            "M.S.1",
            "M.S.1",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &blocked,
        ),
        Err(Error::TransferDenied)
    ));
    let countersign = TransferAuth {
        countersign_required: true,
        ..TransferAuth::default()
    };
    assert!(matches!(
        run(
            &mut source,
            &mut dest,
            "M",
            "M.S",
            TransferOp::Move,
            DescendantMode::KeyOnly,
            &countersign,
        ),
        Err(Error::TransferDenied)
    ));
    let branch_blocked = TransferAuth {
        descendant_move: false,
        ..TransferAuth::default()
    };
    assert!(matches!(
        run(
            &mut source,
            &mut dest,
            "M",
            "M.S",
            TransferOp::Move,
            DescendantMode::AllDescendants,
            &branch_blocked,
        ),
        Err(Error::TransferDenied)
    ));
    force_ghost(&mut source, "M");
    assert!(matches!(
        run(
            &mut source,
            &mut dest,
            "M",
            "M.S.1",
            TransferOp::Copy,
            DescendantMode::KeyOnly,
            &TransferAuth::default(),
        ),
        Err(Error::GhostDenied)
    ));
}

#[test]
fn a_ghost_leaf_cannot_satisfy_quorum_and_other_leaves_still_can() {
    let mut store = end();
    enroll_all(&mut store, &["M.S.1", "M.S.2", "M.S.3"]);
    let ids: Vec<(String, i64)> = ["M.S.1", "M.S.2", "M.S.3"]
        .into_iter()
        .map(|label| (label.to_string(), hardware_id(&store.conn, label)))
        .collect();
    let spec = NodeSpec::Split {
        label: "M".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: ids.iter().map(|(label, id)| leaf(label, *id)).collect(),
    };
    let key_id = key_tree::split(
        &mut store.conn,
        "org",
        b"company master secret 32 bytes!",
        &spec,
    )
    .unwrap();
    let mut shares = HashMap::new();
    for label in ["M.S.1", "M.S.2", "M.S.3"] {
        let secret = slot_secret(&store, label);
        let node_id: i64 = store
            .conn
            .query_row(
                "SELECT id FROM key_nodes WHERE key_id = ?1 AND label = ?2",
                params![key_id, label],
                |row| row.get(0),
            )
            .unwrap();
        let raw = key_tree::unwrap_leaf_share(&store.conn, node_id, &secret).unwrap();
        shares.insert(node_id, raw);
    }
    key_tree::reconstruct(&store.conn, key_id, &shares).unwrap();
    force_ghost(&mut store, "M.S.1");
    key_tree::reconstruct(&store.conn, key_id, &shares).expect("the other two leaves still meet 2");
    let only_ghost: HashMap<i64, Vec<u8>> = shares
        .iter()
        .filter(|(id, _)| {
            let label: String = store
                .conn
                .query_row(
                    "SELECT label FROM key_nodes WHERE id = ?1",
                    params![*id],
                    |row| row.get(0),
                )
                .unwrap();
            label == "M.S.1"
        })
        .map(|(id, raw)| (*id, raw.clone()))
        .collect();
    assert!(matches!(
        key_tree::reconstruct(&store.conn, key_id, &only_ghost),
        Err(Error::QuorumNotMet | Error::GhostDenied)
    ));
    assert!(sign_active(&store.conn, &store.container, "M.S.1", PASS, b"no").is_err());
    assert!(sign_active(&store.conn, &store.container, "M.S.2", PASS, b"yes").is_ok());
}

#[test]
fn copy_does_not_deactivate_the_source() {
    let mut source = end();
    enroll_all(&mut source, &["M.S.2"]);
    let mut dest = end();
    run(
        &mut source,
        &mut dest,
        "M.S.2",
        "M.S.2",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&source, "M.S.2"), Some(Possession::Active));
    assert_eq!(state(&dest, "M.S.2"), Some(Possession::Active));
    assert_eq!(ident(&source, "M.S.2").generation, 1);
    assert!(sign_active(&source.conn, &source.container, "M.S.2", PASS, b"src").is_ok());
    assert!(sign_active(&dest.conn, &dest.container, "M.S.2", PASS, b"dst").is_ok());
}

#[test]
fn ghost_is_recorded_only_after_the_source_slot_is_gone() {
    let mut source = end();
    enroll_all(&mut source, &["M.A"]);
    let mut dest = end();
    let passes = passes_for(&source.conn, "M.A", DescendantMode::KeyOnly);
    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M.A",
        "M.A",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    stage_destination(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    write_destination_slots(
        &dest.conn,
        &mut dest.container,
        &source.container,
        prepared.package(),
        &passes,
        None,
    )
    .unwrap();
    commit_destination_rows(
        &dest.conn,
        &dest.container,
        &source.container,
        prepared.package(),
        false,
    )
    .unwrap();
    acknowledge(&dest.conn, &prepared.id).unwrap();
    assert_eq!(state(&source, "M.A"), Some(Possession::Active));
    assert!(device::open_slot(&source.container, "M.A", PASS).is_ok());

    scrub_moved_slots(&source.conn, &mut source.container, &prepared.id).unwrap();
    assert_eq!(state(&source, "M.A"), Some(Possession::Active));
    assert!(device::open_slot(&source.container, "M.A", PASS).is_err());
    assert!(sign_active(&source.conn, &source.container, "M.A", PASS, b"gone").is_err());

    retire_source_material(
        &source.conn,
        &mut source.container,
        &dest.conn,
        &prepared.id,
    )
    .unwrap();
    assert_eq!(
        tx_state(&source.conn, &prepared.id).unwrap().as_deref(),
        Some("source_finalized")
    );
    assert_eq!(state(&source, "M.A"), Some(Possession::Ghost));
    assert!(source.container.slot("M.A").is_none());
    assert!(device::open_slot(&source.container, "M.A", PASS).is_err());
    assert!(matches!(
        sign_active(&source.conn, &source.container, "M.A", PASS, b"ghost"),
        Err(Error::GhostDenied)
    ));
    assert_eq!(state(&dest, "M.A"), Some(Possession::Active));
    assert!(sign_active(&dest.conn, &dest.container, "M.A", PASS, b"kept").is_ok());

    assert_eq!(
        recover_pair(
            &source.conn,
            &mut source.container,
            &dest.conn,
            &mut dest.container,
            &prepared.id,
        )
        .unwrap(),
        Recovery::AlreadyComplete
    );
    assert_eq!(state(&source, "M.A"), Some(Possession::Ghost));
    assert!(device::open_slot(&source.container, "M.A", PASS).is_err());
    assert!(sign_active(&dest.conn, &dest.container, "M.A", PASS, b"kept").is_ok());
}

#[test]
fn relay_accept_and_ack_finish_a_move_without_keeping_both_databases_open() {
    let mut source = end();
    enroll_all(&mut source, &["M"]);
    let mut dest = end();
    let passes = passes_for(&source.conn, "M", DescendantMode::KeyOnly);
    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M",
        "M",
        TransferOp::Move,
        DescendantMode::KeyOnly,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    assert_eq!(state(&source, "M"), Some(Possession::Active));
    let (source_id, source_verify) = authenticated_source(prepared.package()).unwrap();
    assert_eq!(source_id, *source.container.device_id());
    assert_eq!(source_verify, *source.container.verify_key());
    let id = accept_package(
        &dest.conn,
        &mut dest.container,
        &source_id,
        &source_verify,
        prepared.package(),
        &passes,
        false,
    )
    .unwrap();
    assert_eq!(id, prepared.id);
    assert_eq!(state(&dest, "M"), Some(Possession::Active));
    assert_eq!(state(&source, "M"), Some(Possession::Active));
    assert!(source.container.slot("M").is_some());
    finalize_after_ack(
        &source.conn,
        &mut source.container,
        &prepared.id,
        &package_hash(prepared.package()),
    )
    .unwrap();
    assert_eq!(state(&source, "M"), Some(Possession::Ghost));
    assert!(source.container.slot("M").is_none());
    finalize_after_ack(
        &source.conn,
        &mut source.container,
        &prepared.id,
        &package_hash(prepared.package()),
    )
    .unwrap();

    let mut source = end();
    enroll_all(&mut source, &["M"]);
    let passes = passes_for(&source.conn, "M", DescendantMode::KeyOnly);
    let prepared = prepare(
        &source.conn,
        &source.container,
        dest.container.device_id(),
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    let mut bad = package_hash(prepared.package());
    bad[0] ^= 0xff;
    assert!(finalize_after_ack(&source.conn, &mut source.container, &prepared.id, &bad).is_err());
    assert_eq!(state(&source, "M"), Some(Possession::Active));
    assert!(source.container.slot("M").is_some());
}
