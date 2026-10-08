use super::*;
use crate::db::open_in_memory;

fn target() -> Target {
    Target {
        provider_id: "Acme".into(),
        recipient: "ab".repeat(32),
        device_id: "cd".repeat(16),
        slot_label: "alice".into(),
        container: "/usb/alice".into(),
    }
}

fn incoming(id: u8, generation: Option<u64>) -> Incoming {
    Incoming {
        package_id: format!("{id:02x}").repeat(16),
        package_sha256: format!("{id:02x}").repeat(32),
        purpose: "client_update",
        issuer: "ee".repeat(32),
        target: target(),
        generation,
        licence_sha256: None,
    }
}

/// Case 1: the same id with different bytes is refused.
#[test]
fn the_same_id_with_different_bytes_is_refused() {
    let conn = open_in_memory().unwrap();
    begin(&conn, &incoming(1, Some(1))).unwrap();
    let mut changed = incoming(1, Some(1));
    changed.package_sha256 = "ff".repeat(32);
    assert!(matches!(
        decide(&conn, &changed),
        Err(Error::KqpkgRefused(_))
    ));
}

/// Case 2: the same package for another target is refused.
#[test]
fn the_same_package_for_another_target_is_refused() {
    let conn = open_in_memory().unwrap();
    begin(&conn, &incoming(1, Some(1))).unwrap();
    let mut elsewhere = incoming(1, Some(1));
    elsewhere.target.container = "/usb/other".into();
    assert!(matches!(
        decide(&conn, &elsewhere),
        Err(Error::KqpkgRefused(_))
    ));
    let mut other_slot = incoming(1, Some(1));
    other_slot.target.slot_label = "bob".into();
    assert!(matches!(
        decide(&conn, &other_slot),
        Err(Error::KqpkgRefused(_))
    ));
}

/// Case 3: a pending package resumes with the steps it finished, unless a newer
/// package raised the baseline past it, and an abandoned one never resumes.
#[test]
fn a_pending_package_resumes_unless_superseded_or_abandoned() {
    let conn = open_in_memory().unwrap();
    assert_eq!(
        begin(&conn, &incoming(1, Some(1))).unwrap(),
        Decision::Install
    );
    mark_step(&conn, &incoming(1, None).package_id, "identity").unwrap();
    mark_step(&conn, &incoming(1, None).package_id, "identity").unwrap();
    assert_eq!(
        decide(&conn, &incoming(1, Some(1))).unwrap(),
        Decision::Resume {
            steps_done: vec!["identity".into()]
        }
    );
    // A newer package raised the baseline (as if it had been accepted on a
    // copy of this store): the old pending one can no longer resume.
    conn.execute("UPDATE package_baselines SET generation = 5", [])
        .unwrap();
    assert!(matches!(
        decide(&conn, &incoming(1, Some(1))),
        Err(Error::KqpkgRefused(_))
    ));
    abandon(&conn, &incoming(1, None).package_id).unwrap();
    assert!(matches!(
        decide(&conn, &incoming(1, Some(1))),
        Err(Error::KqpkgRefused(_))
    ));
}

/// Case 4: a complete package is reported installed and not run again.
#[test]
fn a_complete_package_is_already_installed() {
    let conn = open_in_memory().unwrap();
    begin(&conn, &incoming(1, Some(1))).unwrap();
    complete(&conn, &incoming(1, None).package_id).unwrap();
    assert_eq!(
        decide(&conn, &incoming(1, Some(1))).unwrap(),
        Decision::AlreadyInstalled
    );
    assert_eq!(
        begin(&conn, &incoming(1, Some(1))).unwrap(),
        Decision::AlreadyInstalled
    );
    assert!(matches!(
        complete(&conn, &incoming(1, None).package_id),
        Err(Error::KqpkgRefused(_))
    ));
}

/// Case 5: a different package at or below the baseline is stale.
#[test]
fn an_equal_or_older_generation_is_refused_as_stale() {
    let conn = open_in_memory().unwrap();
    begin(&conn, &incoming(1, Some(3))).unwrap();
    complete(&conn, &incoming(1, None).package_id).unwrap();
    assert!(matches!(
        decide(&conn, &incoming(2, Some(3))),
        Err(Error::KqpkgRefused(_))
    ));
    assert!(matches!(
        decide(&conn, &incoming(2, Some(2))),
        Err(Error::KqpkgRefused(_))
    ));
    assert_eq!(
        decide(&conn, &incoming(2, Some(4))).unwrap(),
        Decision::Install
    );
}

/// Case 6: a newer package waits while another is pending in its stream, and
/// abandoning that one keeps the baseline it raised.
#[test]
fn only_one_package_is_pending_per_stream_and_abandoning_keeps_the_baseline() {
    let conn = open_in_memory().unwrap();
    begin(&conn, &incoming(1, Some(2))).unwrap();
    assert!(matches!(
        begin(&conn, &incoming(2, Some(3))),
        Err(Error::KqpkgRefused(_))
    ));
    // Another slot is another stream.
    let mut other = incoming(3, Some(1));
    other.target.slot_label = "bob".into();
    assert_eq!(begin(&conn, &other).unwrap(), Decision::Install);
    let abandoned = abandon(&conn, &incoming(1, None).package_id).unwrap();
    assert_eq!(abandoned.state, "pending");
    assert_eq!(baseline(&conn, &target()).unwrap(), Some(2));
    assert!(matches!(
        decide(&conn, &incoming(4, Some(2))),
        Err(Error::KqpkgRefused(_))
    ));
    assert_eq!(
        begin(&conn, &incoming(2, Some(3))).unwrap(),
        Decision::Install
    );
    assert_eq!(baseline(&conn, &target()).unwrap(), Some(3));
}

/// A package with no setup manifest has no generation: it never raises or
/// passes the baseline check, and it is still recorded.
#[test]
fn a_package_without_a_generation_is_recorded_but_raises_nothing() {
    let conn = open_in_memory().unwrap();
    assert_eq!(begin(&conn, &incoming(1, None)).unwrap(), Decision::Install);
    assert_eq!(baseline(&conn, &target()).unwrap(), None);
    assert_eq!(
        record(&conn, &incoming(1, None).package_id)
            .unwrap()
            .unwrap()
            .generation,
        None
    );
}

/// A retired key is remembered per stream.
#[test]
fn a_retired_key_is_remembered_per_stream() {
    let conn = open_in_memory().unwrap();
    let hash = "12".repeat(32);
    assert!(!is_retired(&conn, &target(), &hash).unwrap());
    retire_key(&conn, &target(), &hash).unwrap();
    retire_key(&conn, &target(), &hash).unwrap();
    assert!(is_retired(&conn, &target(), &hash).unwrap());
    let mut other = target();
    other.slot_label = "bob".into();
    assert!(!is_retired(&conn, &other, &hash).unwrap());
}

/// The unique index is the last guard: two pending rows for one stream cannot
/// exist even if `decide` were skipped.
#[test]
fn the_database_itself_refuses_two_pending_packages_in_one_stream() {
    let conn = open_in_memory().unwrap();
    begin(&conn, &incoming(1, Some(1))).unwrap();
    let t = target();
    let second = conn.execute(
        "INSERT INTO package_installs (package_id, package_sha256, purpose, issuer, provider_id,
            recipient, device_id, slot_label, container, state)
         VALUES (?1, ?2, 'client_setup', ?3, ?4, ?5, ?6, ?7, ?8, 'pending')",
        params![
            "02".repeat(16),
            "02".repeat(32),
            "ee".repeat(32),
            t.provider_id,
            t.recipient,
            t.device_id,
            t.slot_label,
            t.container
        ],
    );
    assert!(second.is_err());
}

/// A batch's preflight lets a package past a pending one only when that
/// pending package is in the same batch; `begin` still refuses it until the
/// pending one is complete.
#[test]
fn a_pending_package_in_the_same_batch_does_not_block_the_preflight() {
    let conn = open_in_memory().unwrap();
    begin(&conn, &incoming(1, Some(2))).unwrap();
    let pending = incoming(1, None).package_id;
    assert_eq!(
        decide_in_batch(&conn, &incoming(2, Some(3)), std::slice::from_ref(&pending)).unwrap(),
        Decision::Install
    );
    assert!(matches!(
        decide_in_batch(&conn, &incoming(2, Some(3)), &["ff".repeat(16)]),
        Err(Error::KqpkgRefused(_))
    ));
    assert!(matches!(
        begin(&conn, &incoming(2, Some(3))),
        Err(Error::KqpkgRefused(_))
    ));
    complete(&conn, &pending).unwrap();
    assert_eq!(
        begin(&conn, &incoming(2, Some(3))).unwrap(),
        Decision::Install
    );
}
