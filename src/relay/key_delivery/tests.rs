use super::{create_as_bundle, recipient_for, rotate_as_bundle, rotate_as_letter, Recipient, Via};
use crate::api_key_delivery;
use crate::error::Error;
use crate::keys;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::{self, ApiKeyScope, NewApiKey, ProviderIdentity};
use rusqlite::Connection;
use std::cell::RefCell;

const RELAY_URL: &str = "https://relay.example.test/";

fn identity() -> (ProviderIdentity, [u8; 32]) {
    let issued = issued_identity("2999-01-01 00:00:00");
    (
        ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
        issued.root_public,
    )
}

fn pull_key() -> NewApiKey {
    NewApiKey {
        scope: ApiKeyScope::InboxPull,
        recipient_fingerprint: None,
        label: Some("customer".into()),
        ttl_seconds: None,
    }
}

fn recipient(public_key: [u8; 32]) -> Recipient {
    Recipient {
        public_key,
        relay_url: RELAY_URL.to_string(),
        device_id: Some([4u8; 16]),
        licence: Some("One pull key for one device.".to_string()),
    }
}

/// `recipient`, as the host records it: the URL normalized.
fn recorded(public_key: [u8; 32]) -> Recipient {
    Recipient {
        relay_url: "https://relay.example.test".to_string(),
        ..recipient(public_key)
    }
}

fn now(conn: &Connection) -> String {
    conn.query_row("SELECT strftime('%Y-%m-%d %H:%M:%S', 'now')", [], |r| {
        r.get(0)
    })
    .expect("clock")
}

fn events(conn: &Connection) -> Vec<(i64, String, Option<i64>)> {
    relay::api_key_events(conn)
        .expect("events")
        .into_iter()
        .map(|e| (e.key_id, e.event, e.related_key_id))
        .collect()
}

#[test]
fn a_first_key_is_written_once_as_a_bundle_the_recipient_can_load() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, root) = identity();
    let (secret, public) = keys::generate_encryption_keypair();
    let written = RefCell::new(Vec::new());

    let delivered = create_as_bundle(&conn, &identity, &pull_key(), &recipient(public), |bytes| {
        written.borrow_mut().extend_from_slice(bytes);
        Ok(())
    })
    .expect("create_as_bundle should mint and seal the key");

    let fingerprint = keys::fingerprint(&public);
    assert_eq!(delivered.recipient_fingerprint, fingerprint);
    assert_eq!(
        delivered.info.recipient_fingerprint.as_deref(),
        Some(fingerprint.as_str()),
        "a pull key takes the recipient key's fingerprint"
    );
    let Via::Bundle { sha256 } = &delivered.via else {
        panic!("a first key travels as a bundle");
    };
    assert_eq!(sha256.len(), 64);

    let opened = api_key_delivery::open(
        &written.borrow(),
        &secret,
        &root,
        &now(&conn),
        &empty_revoked(),
    )
    .expect("the recipient opens the bundle");
    assert_eq!(opened.carrier, api_key_delivery::Carrier::Bundle);
    assert_eq!(opened.issue.key_id, delivered.info.id);
    assert_eq!(opened.issue.scope, "inbox.pull");
    assert_eq!(opened.issue.relay_url, "https://relay.example.test");
    assert_eq!(opened.issue.device_id, Some([4u8; 16]));
    assert_eq!(
        opened.issue.licence.as_deref(),
        Some("One pull key for one device.")
    );
    let authed = relay::authenticate(&conn, &opened.issue.token, ApiKeyScope::InboxPull)
        .expect("the bearer in the bundle is the live key");
    assert_eq!(authed.id, delivered.info.id);

    assert_eq!(
        recipient_for(&conn, delivered.info.id).expect("recipient_for"),
        Some(recorded(public))
    );
    assert_eq!(
        events(&conn),
        vec![(delivered.info.id, "created".into(), None)]
    );
}

#[test]
fn a_bundle_that_cannot_be_written_leaves_no_key_behind() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, _) = identity();
    let (_, public) = keys::generate_encryption_keypair();

    let result = create_as_bundle(&conn, &identity, &pull_key(), &recipient(public), |_| {
        Err(Error::InvalidPath)
    });
    assert!(matches!(result, Err(Error::InvalidPath)));
    assert!(relay::list_api_keys(&conn).expect("list").is_empty());
    assert!(events(&conn).is_empty());
    let deliveries: i64 = conn
        .query_row("SELECT COUNT(*) FROM api_key_deliveries", [], |r| r.get(0))
        .expect("count");
    assert_eq!(deliveries, 0);
}

#[test]
fn a_given_fingerprint_must_be_the_recipient_keys_own() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, _) = identity();
    let (_, public) = keys::generate_encryption_keypair();
    let (_, other) = keys::generate_encryption_keypair();
    let mut new = pull_key();
    new.recipient_fingerprint = Some(keys::fingerprint(&other));
    let result = create_as_bundle(&conn, &identity, &new, &recipient(public), |_| Ok(()));
    assert!(matches!(result, Err(Error::InvalidApiKeyRequest)));
    assert!(relay::list_api_keys(&conn).expect("list").is_empty());
}

#[test]
fn a_rotation_by_letter_stores_the_letter_and_keeps_the_old_key_for_the_grace_period() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, root) = identity();
    let (secret, public) = keys::generate_encryption_keypair();
    let first = create_as_bundle(
        &conn,
        &identity,
        &pull_key(),
        &recipient(public),
        |_| Ok(()),
    )
    .expect("create_as_bundle");
    let old_id = first.info.id;

    let rotated = rotate_as_letter(&conn, &identity, old_id, None, 3_600)
        .expect("rotate_as_letter should reuse the recorded recipient");
    let new_id = rotated.info.id;
    assert_ne!(new_id, old_id);
    let Via::Letter {
        id: letter_id,
        until,
    } = &rotated.via
    else {
        panic!("a rotation travels as a letter");
    };
    let until = until.clone().expect("the old key now expires");

    let old = relay::api_key_info(&conn, old_id).expect("old key");
    assert_eq!(old.revoked_at, None, "the old key is not revoked yet");
    assert_eq!(old.expires_at.as_deref(), Some(until.as_str()));
    assert!(until > now(&conn));

    let fingerprint = keys::fingerprint(&public);
    let page = relay::list_after(&conn, &fingerprint, None, None).expect("mailbox");
    assert_eq!(page.envelopes.len(), 1);
    assert_eq!(page.envelopes[0].id, *letter_id);
    let opened = api_key_delivery::open(
        &page.envelopes[0].bytes,
        &secret,
        &root,
        &now(&conn),
        &empty_revoked(),
    )
    .expect("the recipient opens the letter");
    assert_eq!(opened.carrier, api_key_delivery::Carrier::Letter);
    assert_eq!(opened.issue.key_id, new_id);
    let authed = relay::authenticate(&conn, &opened.issue.token, ApiKeyScope::InboxPull)
        .expect("the new bearer is live");
    assert_eq!(authed.id, new_id);

    assert_eq!(
        recipient_for(&conn, new_id).expect("recipient_for"),
        Some(recorded(public))
    );
    assert_eq!(
        events(&conn),
        vec![
            (old_id, "created".into(), None),
            (new_id, "rotated".into(), Some(old_id)),
        ]
    );
    let letter_expiry: Option<String> = conn
        .query_row(
            "SELECT expires_at FROM mailbox WHERE id = ?1",
            [letter_id],
            |r| r.get(0),
        )
        .expect("letter row");
    assert_eq!(letter_expiry.as_deref(), Some(until.as_str()));
}

#[test]
fn a_rotation_by_letter_needs_a_recipient_and_a_positive_grace() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, _) = identity();
    let plain = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: None,
        },
    )
    .expect("create");
    assert!(matches!(
        rotate_as_letter(&conn, &identity, plain.info.id, None, 3_600),
        Err(Error::DeliveryRecipientMissing)
    ));
    let (_, public) = keys::generate_encryption_keypair();
    assert!(matches!(
        rotate_as_letter(&conn, &identity, plain.info.id, Some(recipient(public)), 0),
        Err(Error::InvalidApiKeyRequest)
    ));
    assert_eq!(
        events(&conn),
        vec![(plain.info.id, "created".into(), None)],
        "a refused rotation records nothing"
    );
    let mailbox: i64 = conn
        .query_row("SELECT COUNT(*) FROM mailbox", [], |r| r.get(0))
        .expect("count");
    assert_eq!(mailbox, 0);
}

#[test]
fn a_bound_key_is_sealed_only_to_the_key_it_is_bound_to() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, _) = identity();
    let (_, public) = keys::generate_encryption_keypair();
    let (_, other) = keys::generate_encryption_keypair();
    let first = create_as_bundle(
        &conn,
        &identity,
        &pull_key(),
        &recipient(public),
        |_| Ok(()),
    )
    .expect("create_as_bundle");
    assert!(matches!(
        rotate_as_letter(
            &conn,
            &identity,
            first.info.id,
            Some(recipient(other)),
            3_600
        ),
        Err(Error::InvalidApiKeyRequest)
    ));
}

#[test]
fn a_rotation_by_bundle_revokes_the_old_key_at_once() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, root) = identity();
    let (secret, public) = keys::generate_encryption_keypair();
    let first = create_as_bundle(
        &conn,
        &identity,
        &pull_key(),
        &recipient(public),
        |_| Ok(()),
    )
    .expect("create_as_bundle");
    let written = RefCell::new(Vec::new());
    let rotated = rotate_as_bundle(&conn, &identity, first.info.id, None, |bytes| {
        written.borrow_mut().extend_from_slice(bytes);
        Ok(())
    })
    .expect("rotate_as_bundle");
    assert!(matches!(rotated.via, Via::Bundle { .. }));
    let old = relay::api_key_info(&conn, first.info.id).expect("old key");
    assert!(old.revoked_at.is_some());
    let opened = api_key_delivery::open(
        &written.borrow(),
        &secret,
        &root,
        &now(&conn),
        &empty_revoked(),
    )
    .expect("open");
    assert_eq!(opened.issue.key_id, rotated.info.id);
}

#[test]
fn the_relay_database_holds_no_bearer_from_a_delivery() {
    let conn = relay::open_in_memory().expect("schema");
    let (identity, root) = identity();
    let (secret, public) = keys::generate_encryption_keypair();
    let bundle = RefCell::new(Vec::new());
    let first = create_as_bundle(&conn, &identity, &pull_key(), &recipient(public), |bytes| {
        bundle.borrow_mut().extend_from_slice(bytes);
        Ok(())
    })
    .expect("create_as_bundle");
    rotate_as_letter(&conn, &identity, first.info.id, None, 3_600).expect("rotate_as_letter");
    let letter = relay::list_after(&conn, &keys::fingerprint(&public), None, None)
        .expect("mailbox")
        .envelopes
        .remove(0)
        .bytes;
    let tokens: Vec<Vec<u8>> = [bundle.borrow().clone(), letter.clone()]
        .iter()
        .map(|bytes| {
            api_key_delivery::open(bytes, &secret, &root, &now(&conn), &empty_revoked())
                .expect("open")
                .issue
                .token
                .as_bytes()
                .to_vec()
        })
        .collect();

    let mut stored = Vec::new();
    for table in [
        "api_keys",
        "api_key_deliveries",
        "api_key_events",
        "mailbox",
    ] {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM {table}"))
            .expect("prepare");
        let columns = stmt.column_count();
        let mut rows = stmt.query([]).expect("query");
        while let Some(row) = rows.next().expect("row") {
            for i in 0..columns {
                match row.get_ref(i).expect("value") {
                    rusqlite::types::ValueRef::Text(t) => stored.extend_from_slice(t),
                    rusqlite::types::ValueRef::Blob(b) => stored.extend_from_slice(b),
                    _ => {}
                }
            }
        }
    }
    for token in tokens {
        assert!(
            !stored.windows(token.len()).any(|w| w == token.as_slice()),
            "a bearer reached the relay database"
        );
    }
}
