use super::*;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::{self, ApiKeyScope, NewApiKey};

const SIGNED_AT: &str = "2026-06-01 12:00:00.000";

fn relay_identity(expires_at: &str) -> (ProviderIdentity, [u8; 32]) {
    let issued = issued_identity(expires_at);
    (
        ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
        issued.root_public,
    )
}

fn new_key(scope: ApiKeyScope) -> NewApiKey {
    NewApiKey {
        scope,
        recipient_fingerprint: None,
        label: None,
        ttl_seconds: None,
    }
}

fn seeded() -> Connection {
    let conn = relay::open_in_memory().expect("schema");
    let key = relay::create_api_key(&conn, &new_key(ApiKeyScope::InboxPush)).expect("create");
    relay::rotate_api_key(&conn, key.info.id).expect("rotate");
    relay::record_provider_auth_event(&conn, "keys.create", Some("Acme"), None, None, true)
        .expect("auth event");
    conn
}

fn report(conn: &Connection, root: &[u8; 32], table: AuditTable) -> TableReport {
    verify(conn, root, &empty_revoked(), None)
        .expect("verify")
        .into_iter()
        .find(|r| r.table == table.name())
        .expect("table report")
}

#[test]
fn every_row_is_chained_and_an_anchor_vouches_for_the_head() {
    let conn = seeded();
    let (identity, root) = relay_identity("2027-01-01 00:00:00");

    let before = report(&conn, &root, AuditTable::ApiKeyEvents);
    assert_eq!(before.rows, 3);
    assert_eq!(before.broken_at, None);
    assert_eq!(before.anchored_rows(), 0);
    assert_eq!(before.pending_rows(), 3);

    assert_eq!(anchor(&conn, &identity, SIGNED_AT).expect("anchor"), 2);
    // Nothing new to sign.
    assert_eq!(anchor(&conn, &identity, SIGNED_AT).expect("anchor"), 0);

    for table in AuditTable::ALL {
        let after = report(&conn, &root, table);
        assert!(after.is_intact(), "{after:?}");
        assert_eq!(after.pending_rows(), 0, "{after:?}");
        let trusted = after.trusted.expect("trusted anchor");
        assert_eq!(trusted.serial, "KQP-000184");
        assert_eq!(trusted.signed_at, SIGNED_AT);
    }

    // A row written after the anchor is pending until the next one.
    relay::revoke_api_key(&conn, 2).expect("revoke");
    let pending = report(&conn, &root, AuditTable::ApiKeyEvents);
    assert_eq!((pending.anchored_rows(), pending.pending_rows()), (3, 1));
    assert!(pending.is_intact());
}

#[test]
fn editing_or_deleting_a_row_breaks_the_chain_and_the_anchor() {
    let (identity, root) = relay_identity("2027-01-01 00:00:00");

    let edited = seeded();
    anchor(&edited, &identity, SIGNED_AT).expect("anchor");
    edited
        .execute(
            "UPDATE api_key_events SET actor = 'admin:9' WHERE id = 2",
            [],
        )
        .expect("tamper");
    let r = report(&edited, &root, AuditTable::ApiKeyEvents);
    assert_eq!(r.broken_at, Some(2));
    assert_eq!(r.rejected_anchors, 1);
    assert!(r.trusted.is_none());

    let deleted = seeded();
    anchor(&deleted, &identity, SIGNED_AT).expect("anchor");
    deleted
        .execute("DELETE FROM api_key_events WHERE id = 1", [])
        .expect("tamper");
    let r = report(&deleted, &root, AuditTable::ApiKeyEvents);
    assert_eq!(r.broken_at, Some(2));
    assert!(!r.is_intact());
}

#[test]
fn rebuilding_the_chain_without_the_relay_key_is_detected() {
    let conn = seeded();
    let (identity, root) = relay_identity("2027-01-01 00:00:00");
    anchor(&conn, &identity, SIGNED_AT).expect("anchor");

    // Someone with write access rewrites a row and recomputes every hash.
    conn.execute(
        "UPDATE api_key_events SET actor = 'admin:9' WHERE id = 1",
        [],
    )
    .expect("tamper");
    conn.execute("UPDATE api_key_events SET entry_hash = NULL", [])
        .expect("clear");
    backfill(&conn).expect("rebuild");
    let r = report(&conn, &root, AuditTable::ApiKeyEvents);
    assert_eq!(r.broken_at, None, "the rebuilt chain is self-consistent");
    assert_eq!(
        r.rejected_anchors, 1,
        "but the signed head no longer matches"
    );
    assert!(r.trusted.is_none());

    // And an anchor they sign over the rebuilt head with a relay key of
    // their own, certified by some other root, is refused too.
    conn.execute("DELETE FROM audit_anchors", [])
        .expect("drop anchors");
    let (forger, _other_root) = relay_identity("2027-01-01 00:00:00");
    assert_eq!(anchor(&conn, &forger, SIGNED_AT).expect("forge"), 2);
    let r = report(&conn, &root, AuditTable::ApiKeyEvents);
    assert!(r.trusted.is_none());
    assert_eq!(r.rejected_anchors, 1);
}

#[test]
fn an_anchor_counts_only_while_its_certificate_was_valid() {
    let conn = seeded();
    let (identity, root) = relay_identity("2026-03-01 00:00:00");

    // Signed after the certificate expired: refused.
    anchor(&conn, &identity, "2026-04-01 00:00:00.000").expect("anchor");
    let late = report(&conn, &root, AuditTable::ApiKeyEvents);
    assert!(late.trusted.is_none());
    assert_eq!(late.rejected_anchors, 1);

    // Signed before the certificate was issued: refused.
    let early = seeded();
    anchor(&early, &identity, "2025-12-31 23:59:59.000").expect("anchor");
    assert!(report(&early, &root, AuditTable::ApiKeyEvents)
        .trusted
        .is_none());

    // Signed inside the validity window: still trusted after it ends.
    let inside = seeded();
    anchor(&inside, &identity, "2026-02-01 00:00:00.000").expect("anchor");
    assert!(report(&inside, &root, AuditTable::ApiKeyEvents)
        .trusted
        .is_some());

    // Signed by a revoked certificate: refused.
    let revoked: HashSet<String> = ["KQP-000184".to_string()].into();
    let r = verify(&inside, &root, &revoked, None).expect("verify");
    assert!(r.iter().all(|t| t.trusted.is_none()));
}

#[test]
fn migration_chains_rows_written_before_the_chain_existed() {
    let conn = Connection::open_in_memory().expect("db");
    conn.execute_batch(
        "CREATE TABLE provider_auth_events (
            id INTEGER PRIMARY KEY, operation TEXT NOT NULL, provider_id TEXT,
            network_id TEXT, hardware_fingerprints TEXT,
            success INTEGER NOT NULL CHECK (success IN (0, 1)),
            attempted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
         INSERT INTO provider_auth_events (operation, success) VALUES ('register', 1), ('register', 0);",
    )
    .expect("legacy table");
    super::super::init(&conn).expect("migrate");
    let (identity, root) = relay_identity("2027-01-01 00:00:00");
    let r = report(&conn, &root, AuditTable::ProviderAuthEvents);
    assert_eq!((r.rows, r.broken_at), (2, None));
    anchor(&conn, &identity, SIGNED_AT).expect("anchor");
    assert_eq!(
        report(&conn, &root, AuditTable::ProviderAuthEvents).anchored_rows(),
        2
    );
}

fn report_against(
    conn: &Connection,
    root: &[u8; 32],
    checkpoint: &Checkpoint,
    table: AuditTable,
) -> TableReport {
    verify(conn, root, &empty_revoked(), Some(checkpoint))
        .expect("verify")
        .into_iter()
        .find(|r| r.table == table.name())
        .expect("table report")
}

#[test]
fn an_expired_key_cannot_backdate_an_anchor_past_a_checkpoint() {
    // The certificate was valid from 2026-01-01 to 2026-03-01.
    let (identity, root) = relay_identity("2026-03-01 00:00:00");
    let conn = seeded();
    anchor(&conn, &identity, "2026-02-01 00:00:00.000").expect("anchor");
    // The operator takes a checkpoint and keeps it off the relay.
    let checkpoint = Checkpoint::decode(
        &checkpoint(&conn, &identity, "2026-02-15 00:00:00.000")
            .expect("checkpoint")
            .encode()
            .expect("encode"),
    )
    .expect("decode");
    let r = report_against(&conn, &root, &checkpoint, AuditTable::ApiKeyEvents);
    assert!(r.is_intact(), "{r:?}");
    assert_eq!(r.anchored_rows(), 3);
    assert!(r.checkpoint.as_ref().is_some_and(|c| c.matches));

    // Later, with the key long expired, someone who can write the database
    // adds a row and signs an anchor over it dated inside the old window.
    relay::revoke_api_key(&conn, 2).expect("revoke");
    anchor(&conn, &identity, "2026-02-10 00:00:00.000").expect("backdated anchor");
    // Without the checkpoint, the signer's own date is all there is.
    assert_eq!(
        report(&conn, &root, AuditTable::ApiKeyEvents).pending_rows(),
        0
    );
    // With it, the anchor covers a row that did not exist when the
    // checkpoint was taken, yet claims to be older: refused.
    let r = report_against(&conn, &root, &checkpoint, AuditTable::ApiKeyEvents);
    assert_eq!(r.rejected_anchors, 1);
    assert_eq!((r.anchored_rows(), r.pending_rows()), (3, 1));
    assert!(!r.is_intact());
}

#[test]
fn rewriting_rows_a_checkpoint_covers_is_detected_even_with_a_fresh_anchor() {
    let (identity, root) = relay_identity("2027-01-01 00:00:00");
    let conn = seeded();
    let checkpoint = checkpoint(&conn, &identity, SIGNED_AT).expect("checkpoint");

    // Rewrite a row, rebuild the chain and sign it again with the real key.
    conn.execute(
        "UPDATE api_key_events SET actor = 'admin:9' WHERE id = 1",
        [],
    )
    .expect("tamper");
    conn.execute("UPDATE api_key_events SET entry_hash = NULL", [])
        .expect("clear");
    backfill(&conn).expect("rebuild");
    anchor(&conn, &identity, "2026-07-01 00:00:00.000").expect("anchor");
    assert!(report(&conn, &root, AuditTable::ApiKeyEvents).is_intact());

    let r = report_against(&conn, &root, &checkpoint, AuditTable::ApiKeyEvents);
    assert!(r.checkpoint.as_ref().is_some_and(|c| !c.matches), "{r:?}");
    assert!(!r.is_intact());
    // The untouched table still matches.
    let other = report_against(&conn, &root, &checkpoint, AuditTable::ProviderAuthEvents);
    assert!(other.is_intact(), "{other:?}");
}

#[test]
fn a_checkpoint_must_be_signed_by_a_trusted_relay_key() {
    let (identity, root) = relay_identity("2027-01-01 00:00:00");
    let conn = seeded();
    let good = checkpoint(&conn, &identity, SIGNED_AT).expect("checkpoint");

    // Any edit to what was signed is refused, never ignored.
    let mut edited = good.clone();
    edited.heads[0].row_count = 1;
    assert!(verify(&conn, &root, &empty_revoked(), Some(&edited)).is_err());
    let mut redated = good.clone();
    redated.taken_at = "2026-06-02 12:00:00.000".into();
    assert!(verify(&conn, &root, &empty_revoked(), Some(&redated)).is_err());

    // A key certified by another root cannot write one.
    let (forger, _) = relay_identity("2027-01-01 00:00:00");
    let forged = checkpoint(&conn, &forger, SIGNED_AT).expect("checkpoint");
    assert!(verify(&conn, &root, &empty_revoked(), Some(&forged)).is_err());

    // Nor can a key whose certificate had expired when it was taken.
    let (short, short_root) = relay_identity("2026-03-01 00:00:00");
    let late = checkpoint(&conn, &short, "2026-04-01 00:00:00.000").expect("checkpoint");
    assert!(verify(&conn, &short_root, &empty_revoked(), Some(&late)).is_err());

    // And the file is only this format.
    assert!(Checkpoint::decode(b"{}").is_err());
    assert!(verify(&conn, &root, &empty_revoked(), Some(&good)).is_ok());
}
