//! The MongoDB store against the conformance suite and the properties only
//! a shared store has. These need a replica set (transactions do): set
//! `KEYQUORUM_TEST_MONGODB_URI` (for example
//! `mongodb://127.0.0.1:27017/?replicaSet=rs0`) and every test makes its own
//! database and drops it; without it every test here is skipped.
//! `.github/workflows/mongodb.yml` runs them against a single-node replica
//! set on every pull request.

use super::{MongoRelayStore, MongoSettings, SCHEMA_VERSION};
use crate::error::Error;
use crate::keys;
use crate::relay::store::conformance::{self, fake_letter};
use crate::relay::{ApiKeyScope, NewApiKey, RelayStore};
use mongodb::bson::{doc, Bson, DateTime, Document};
use std::sync::atomic::{AtomicUsize, Ordering};

const URI_VAR: &str = "KEYQUORUM_TEST_MONGODB_URI";

static NEXT_DATABASE: AtomicUsize = AtomicUsize::new(0);

/// A fresh database on the deployment the environment names, or `None`
/// (and a note on stderr) when there is none to test against.
fn fresh() -> Option<Fresh> {
    let uri = match std::env::var(URI_VAR) {
        Ok(uri) if !uri.trim().is_empty() => uri,
        _ => {
            eprintln!("skipped: {URI_VAR} is not set");
            return None;
        }
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let database = format!(
        "kq_test_{}_{}_{nanos}",
        std::process::id(),
        NEXT_DATABASE.fetch_add(1, Ordering::SeqCst)
    );
    let store = MongoRelayStore::open(&uri, &MongoSettings { database })
        .expect("open a test database on the deployment the environment names");
    Some(Fresh { uri, store })
}

/// A test database, dropped when the test is done with it.
struct Fresh {
    uri: String,
    store: MongoRelayStore,
}

impl Fresh {
    /// A second store on the same database: another relay replica.
    fn replica(&self) -> MongoRelayStore {
        MongoRelayStore::open(
            &self.uri,
            &MongoSettings {
                database: self.store.database_name().to_string(),
            },
        )
        .expect("open the same database again")
    }

    fn collection(&self, name: &str) -> mongodb::sync::Collection<Document> {
        self.store.db.collection::<Document>(name)
    }
}

impl Drop for Fresh {
    fn drop(&mut self) {
        let _ = self.store.drop_database();
    }
}

fn new_key(scope: ApiKeyScope) -> NewApiKey {
    NewApiKey {
        scope,
        recipient_fingerprint: None,
        label: Some("mongo".into()),
        ttl_seconds: None,
    }
}

#[test]
fn mongo_store_passes_the_conformance_suite() {
    for case in conformance::CASES {
        let Some(fresh) = fresh() else { return };
        eprintln!("conformance case: {}", case.name);
        (case.run)(&fresh.store);
    }
}

#[test]
fn mongo_store_keeps_every_invariant_under_concurrent_writers() {
    let Some(fresh) = fresh() else { return };
    conformance::concurrent_writers_keep_every_invariant(&fresh.store);
}

#[test]
fn mongo_store_names_its_backend_and_answers_a_ping() {
    let Some(fresh) = fresh() else { return };
    assert_eq!(fresh.store.backend(), "mongodb");
    fresh.store.ping().expect("ping");
    assert!(fresh.store.database_name().starts_with("kq_test_"));
}

#[test]
fn two_replicas_share_one_store_and_one_audit_chain() {
    let Some(fresh) = fresh() else { return };
    let a = &fresh.store;
    let b = fresh.replica();
    let created = a
        .create_api_key(&new_key(ApiKeyScope::InboxPush))
        .expect("create on a");
    let authed = b
        .authenticate(&created.token, ApiKeyScope::InboxPush)
        .expect("b sees a's key");
    assert_eq!(authed.id, created.info.id);
    b.revoke_api_key_by(created.info.id, "admin:7")
        .expect("revoke on b");
    assert!(matches!(
        a.authenticate(&created.token, ApiKeyScope::InboxPush),
        Err(Error::ApiKeyRevoked)
    ));
    let events = a.api_key_events(None).expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].actor, "admin:7");
    assert_eq!(events[1].id, 2, "one chain, whichever replica appended");

    let (identity, root) = {
        let issued = crate::provider::test_helpers::issued_identity("2099-01-01 00:00:00");
        (
            crate::relay::ProviderIdentity {
                certificate: issued.certificate,
                relay_private_key: issued.relay_private,
            },
            issued.root_public,
        )
    };
    let from_a = a
        .anchor_audit(&identity, "2026-06-01 00:00:00.000")
        .expect("anchor from a");
    let from_b = b
        .anchor_audit(&identity, "2026-06-01 00:00:00.000")
        .expect("anchor from b");
    assert_eq!(
        (from_a, from_b),
        (1, 0),
        "the second replica finds the head anchored"
    );
    let reports = b
        .verify_audit(&root, &Default::default(), None)
        .expect("verify from b");
    let api = reports
        .iter()
        .find(|r| r.table == "api_key_events")
        .expect("report");
    assert!(api.is_intact());
    assert_eq!(api.pending_rows(), 0);
}

#[test]
fn an_expired_letter_is_hidden_and_purged() {
    let Some(fresh) = fresh() else { return };
    let (_, pk) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&pk);
    fresh
        .store
        .inbox_push(&[], &fake_letter(&pk, 1, b"keeps"), None)
        .expect("push");
    // A letter whose cutoff has passed, written the way the store writes one.
    fresh
        .collection("mailbox")
        .insert_one(doc! {
            "_id": 9_999i64,
            "recipient_fingerprint": &fingerprint,
            "envelope": mongodb::bson::Binary { subtype: mongodb::bson::spec::BinarySubtype::Generic, bytes: b"stale".to_vec() },
            "content_hash": "stale",
            "created_at": "2000-01-01T00:00:00.000Z",
            "expires_at": "2000-01-01 00:00:00",
            "purge_at": Bson::DateTime(DateTime::from_millis(946_684_800_000)),
        })
        .run()
        .expect("insert an expired letter");
    let listed = fresh
        .store
        .list_envelopes_after(&fingerprint, None, None)
        .expect("list");
    assert_eq!(listed.envelopes.len(), 1);
    assert_eq!(listed.envelopes[0].bytes, fake_letter(&pk, 1, b"keeps"));
    assert_eq!(
        fresh.store.purge_expired_envelopes().expect("purge"),
        0,
        "the listing already purged it"
    );
    assert_eq!(
        fresh
            .collection("mailbox")
            .count_documents(doc! {})
            .run()
            .expect("count"),
        1
    );
}

#[test]
fn records_carry_the_same_time_text_as_the_sqlite_store() {
    let Some(fresh) = fresh() else { return };
    let created = fresh
        .store
        .create_api_key(&NewApiKey {
            ttl_seconds: Some(3_600),
            ..new_key(ApiKeyScope::Admin)
        })
        .expect("create");
    let iso = &created.info.created_at;
    assert_eq!(iso.len(), 24, "{iso}");
    assert!(iso.ends_with('Z') && iso.as_bytes()[10] == b'T', "{iso}");
    let expires = created.info.expires_at.as_deref().expect("expiry");
    assert_eq!(expires.len(), 19, "{expires}");
    assert_eq!(expires.as_bytes()[10], b' ', "{expires}");
    let event = &fresh.store.api_key_events(None).expect("events")[0];
    assert_eq!(event.occurred_at.len(), 24);
}

#[test]
fn a_database_from_a_newer_build_is_refused() {
    let Some(fresh) = fresh() else { return };
    fresh
        .collection("schema_meta")
        .update_one(
            doc! { "_id": "schema" },
            doc! { "$set": { "version": SCHEMA_VERSION + 1 } },
        )
        .run()
        .expect("bump the version");
    let reopened = MongoRelayStore::open(
        &fresh.uri,
        &MongoSettings {
            database: fresh.store.database_name().to_string(),
        },
    );
    assert!(matches!(reopened, Err(Error::Store(_))));
}

#[test]
fn a_database_holding_an_organization_store_is_refused() {
    let Some(fresh) = fresh() else { return };
    fresh
        .collection("key_nodes")
        .insert_one(doc! { "label": "M" })
        .run()
        .expect("a personal store's collection");
    let reopened = MongoRelayStore::open(
        &fresh.uri,
        &MongoSettings {
            database: fresh.store.database_name().to_string(),
        },
    );
    assert!(matches!(reopened, Err(Error::OrganizationDatabase)));
}

#[test]
fn the_store_holds_no_bearer_after_a_mint_and_a_sealed_rotation() {
    let Some(fresh) = fresh() else { return };
    let issued = crate::provider::test_helpers::issued_identity("2099-01-01 00:00:00");
    let identity = crate::relay::ProviderIdentity {
        certificate: issued.certificate,
        relay_private_key: issued.relay_private,
    };
    let (_, public) = keys::generate_encryption_keypair();
    let recipient = crate::relay::key_delivery::Recipient {
        public_key: public,
        relay_url: "https://relay.example.test".into(),
        device_id: None,
        licence: None,
    };
    let mut bundle = Vec::new();
    let first = fresh
        .store
        .create_api_key_as_bundle(
            &identity,
            &new_key(ApiKeyScope::InboxPull),
            &recipient,
            &mut |bytes| {
                bundle.extend_from_slice(bytes);
                Ok(())
            },
        )
        .expect("first key");
    let rotated = fresh
        .store
        .rotate_api_key_as_letter(&identity, first.info.id, None, 600)
        .expect("rotate by letter");
    let plain = fresh
        .store
        .create_api_key(&new_key(ApiKeyScope::Admin))
        .expect("plain key");
    for name in super::COLLECTIONS {
        let docs: Vec<Document> = fresh
            .collection(name)
            .find(doc! {})
            .run()
            .expect("find")
            .collect::<std::result::Result<_, _>>()
            .expect("docs");
        let text = format!("{docs:?}");
        assert!(
            !text.contains(plain.token.as_str()),
            "collection {name} holds a bearer"
        );
        assert!(
            !text.contains("kq_"),
            "collection {name} holds something bearer-shaped"
        );
    }
    assert!(matches!(
        rotated.via,
        crate::relay::key_delivery::Via::Letter { .. }
    ));
}
