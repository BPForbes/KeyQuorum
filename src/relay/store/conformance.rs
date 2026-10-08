//! What every [`RelayStore`] backend must do, as one suite run against each.
//!
//! The SQLite store runs it in `store/tests.rs` on every `cargo test`; any
//! further backend runs the same cases. A case gets a fresh, empty store and
//! may only reach it through the trait, so what it checks is the relay's
//! behaviour, not a backend's rows.

use super::{ProviderAuthEvent, RelayStore};
use crate::api_key_delivery;
use crate::error::Error;
use crate::key_tree::{PublicEdge, PublicNode, PublicTree};
use crate::keys;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::audit::AuditTable;
use crate::relay::device_directory::{sign_descriptor, DeviceDescriptor, DeviceSlotDescriptor};
use crate::relay::key_delivery::{Recipient, Via};
use crate::relay::{ApiKeyScope, NewApiKey, OldKey, ProviderIdentity, MAX_INBOX_PAGE};
use std::cell::RefCell;
use std::sync::Arc;

/// One conformance case: a name for the failure message and the check.
pub(crate) struct Case {
    pub name: &'static str,
    pub run: fn(&dyn RelayStore),
}

macro_rules! cases {
    ($($name:ident),* $(,)?) => {
        pub(crate) const CASES: &[Case] = &[
            $(Case { name: stringify!($name), run: $name },)*
        ];
    };
}

cases![
    key_lifecycle_create_authenticate_rotate_revoke,
    expired_unknown_and_zero_ttl_keys_are_refused,
    pull_keys_bind_a_fingerprint_and_push_keys_must_not,
    keycheck_reports_liveness_without_stamping_use,
    mailbox_stores_bytes_verbatim_dedupes_and_pages,
    mailbox_refuses_device_letters_and_a_past_expiry,
    device_mailbox_takes_only_sealed_device_letters,
    public_trees_are_versioned_merged_and_validated,
    device_descriptors_are_signed_and_keep_their_verify_key,
    audit_trail_is_chained_anchored_and_checkpointed,
    a_first_key_is_sealed_into_a_bundle_or_not_minted_at_all,
    a_rotation_by_letter_keeps_the_old_key_for_the_grace_period,
    a_rotation_by_bundle_revokes_the_old_key_at_once,
    the_operator_lock_bootstraps_once_and_never_over_a_supplied_key,
    provider_auth_events_are_recorded_without_secrets,
    a_licence_is_issued_replaced_and_voided_as_one_unit_of_work,
    known_keys_activity_is_counted_in_place_and_unknown_bearers_are_not,
    the_operator_lock_is_staged_then_confirmed_and_the_old_one_stands_until_then,
    the_console_views_hold_no_secret_and_name_only_what_the_relay_holds,
    package_generations_rise_per_recipient_and_device,
];

fn new_key(scope: ApiKeyScope, fingerprint: Option<&str>) -> NewApiKey {
    NewApiKey {
        scope,
        recipient_fingerprint: fingerprint.map(str::to_string),
        label: Some("conformance".into()),
        ttl_seconds: None,
    }
}

/// A `KQPB` of the given kind sealed (in name only) to `public_key`.
pub(crate) fn fake_letter(public_key: &[u8; 32], kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"KQPB");
    out.push(2);
    out.push(kind);
    out.extend_from_slice(public_key);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn split(label: &str, parent: Option<&str>) -> PublicNode {
    PublicNode {
        label: label.into(),
        parent_label: parent.map(str::to_string),
        threshold: Some(2),
        is_active: true,
        encryption_fingerprint: None,
        encryption_public_key: None,
    }
}

fn leaf(label: &str, parent: &str, public_key: &[u8; 32]) -> PublicNode {
    PublicNode {
        label: label.into(),
        parent_label: Some(parent.into()),
        threshold: None,
        is_active: true,
        encryption_fingerprint: Some(keys::fingerprint(public_key)),
        encryption_public_key: Some(hex::encode(public_key)),
    }
}

fn identity() -> (ProviderIdentity, [u8; 32]) {
    let issued = issued_identity("2099-01-01 00:00:00");
    (
        ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
        issued.root_public,
    )
}

fn recipient(public_key: [u8; 32]) -> Recipient {
    Recipient {
        public_key,
        relay_url: "https://relay.example.test/".to_string(),
        device_id: None,
        licence: Some("One key for one customer.".to_string()),
    }
}

fn now() -> String {
    crate::provider::system_now_utc().expect("clock")
}

fn key_lifecycle_create_authenticate_rotate_revoke(store: &dyn RelayStore) {
    let created = store
        .mint_key(&new_key(ApiKeyScope::InboxPush, None))
        .expect("create");
    assert!(created.token.starts_with("kq_"));
    let authed = store
        .authenticate(&created.token, ApiKeyScope::InboxPush)
        .expect("valid");
    assert_eq!(authed.id, created.info.id);
    assert!(matches!(
        store.authenticate(&created.token, ApiKeyScope::InboxPull),
        Err(Error::ApiKeyScopeDenied)
    ));
    let any = store.authenticate_any(&created.token).expect("any scope");
    assert_eq!(any.scope, ApiKeyScope::InboxPush);
    assert!(store
        .key_info(created.info.id)
        .expect("info")
        .last_used_at
        .is_some());

    let rotated = store
        .rotate_key_with(created.info.id, OldKey::RevokeNow)
        .expect("rotate");
    assert_ne!(rotated.info.id, created.info.id);
    assert_eq!(rotated.info.scope, "inbox.push");
    assert!(matches!(
        store.authenticate(&created.token, ApiKeyScope::InboxPush),
        Err(Error::ApiKeyRevoked)
    ));
    store
        .authenticate(&rotated.token, ApiKeyScope::InboxPush)
        .expect("new key");
    assert!(matches!(
        store.rotate_key_with(created.info.id, OldKey::RevokeNow),
        Err(Error::ApiKeyRevoked)
    ));

    store
        .revoke_key_by(rotated.info.id, "host")
        .expect("revoke");
    store
        .revoke_key_by(rotated.info.id, "host")
        .expect("revoking again records nothing and is not an error");
    assert!(matches!(
        store.authenticate(&rotated.token, ApiKeyScope::InboxPush),
        Err(Error::ApiKeyRevoked)
    ));
    assert!(matches!(
        store.revoke_key_by(9_999, "host"),
        Err(Error::ApiKeyNotFound)
    ));

    let listed = store.list_keys().expect("list");
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|k| k.revoked_at.is_some()));
    let events: Vec<(i64, String, Option<i64>)> = store
        .key_events(None)
        .expect("events")
        .into_iter()
        .map(|e| (e.key_id, e.event, e.related_key_id))
        .collect();
    assert_eq!(
        events,
        vec![
            (created.info.id, "created".into(), None),
            (created.info.id, "revoked".into(), None),
            (rotated.info.id, "rotated".into(), Some(created.info.id)),
            (rotated.info.id, "revoked".into(), None),
        ]
    );
    let mine = store
        .key_events(Some(created.info.id))
        .expect("events for key");
    assert_eq!(
        mine.len(),
        3,
        "its creation, its revocation and the rotation that replaced it"
    );
}

fn expired_unknown_and_zero_ttl_keys_are_refused(store: &dyn RelayStore) {
    let expired = store
        .mint_key(&NewApiKey {
            ttl_seconds: Some(-1),
            ..new_key(ApiKeyScope::Admin, None)
        })
        .expect("create expired");
    assert!(matches!(
        store.authenticate(&expired.token, ApiKeyScope::Admin),
        Err(Error::ApiKeyExpired)
    ));
    assert!(matches!(
        store.authenticate("kq_not-a-key", ApiKeyScope::Admin),
        Err(Error::InvalidApiKey)
    ));
    assert!(matches!(
        store.authenticate("", ApiKeyScope::Admin),
        Err(Error::InvalidApiKey)
    ));
    assert!(matches!(
        store.mint_key(&NewApiKey {
            ttl_seconds: Some(0),
            ..new_key(ApiKeyScope::Admin, None)
        }),
        Err(Error::InvalidApiKeyRequest)
    ));
    let live = store
        .mint_key(&NewApiKey {
            ttl_seconds: Some(3_600),
            ..new_key(ApiKeyScope::Admin, None)
        })
        .expect("create with ttl");
    assert!(live.info.expires_at.is_some());
    store
        .authenticate(&live.token, ApiKeyScope::Admin)
        .expect("not yet expired");
    // A rotation keeps the expiry of the key it replaces.
    let rotated = store
        .rotate_key_with(live.info.id, OldKey::RevokeNow)
        .expect("rotate");
    assert_eq!(rotated.info.expires_at, live.info.expires_at);
}

fn pull_keys_bind_a_fingerprint_and_push_keys_must_not(store: &dyn RelayStore) {
    let (_, pk) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&pk);
    assert!(matches!(
        store.mint_key(&new_key(ApiKeyScope::InboxPull, None)),
        Err(Error::InvalidApiKeyRequest)
    ));
    assert!(matches!(
        store.mint_key(&new_key(ApiKeyScope::InboxPush, Some(&fingerprint))),
        Err(Error::InvalidApiKeyRequest)
    ));
    assert!(matches!(
        store.mint_key(&new_key(ApiKeyScope::InboxPull, Some("not-hex"))),
        Err(Error::InvalidApiKeyRequest)
    ));
    assert!(!store.has_live_pull_key(&fingerprint).expect("none yet"));
    let upper = fingerprint.to_ascii_uppercase();
    let pull = store
        .mint_key(&new_key(ApiKeyScope::InboxPull, Some(&upper)))
        .expect("pull key");
    assert_eq!(
        pull.info.recipient_fingerprint.as_deref(),
        Some(fingerprint.as_str()),
        "fingerprints are stored lowercase"
    );
    let authed = store
        .authenticate(&pull.token, ApiKeyScope::InboxPull)
        .expect("valid");
    assert_eq!(
        authed.recipient_fingerprint.as_deref(),
        Some(fingerprint.as_str())
    );
    assert!(store.has_live_pull_key(&fingerprint).expect("live"));
    let device = store
        .mint_key(&new_key(ApiKeyScope::DevicePull, Some(&fingerprint)))
        .expect("device pull key");
    assert_eq!(device.info.scope, "device.pull");
    assert!(matches!(
        store.mint_key(&new_key(ApiKeyScope::DevicePush, Some(&fingerprint))),
        Err(Error::InvalidApiKeyRequest)
    ));
    store.revoke_key_by(pull.info.id, "host").expect("revoke");
    assert!(
        !store.has_live_pull_key(&fingerprint).expect("revoked"),
        "a device.pull key is not an inbox.pull key"
    );
}

fn keycheck_reports_liveness_without_stamping_use(store: &dyn RelayStore) {
    let created = store
        .mint_key(&new_key(ApiKeyScope::InboxPush, None))
        .expect("create");
    let check = store.check_token(&created.token).expect("check token");
    assert!(check.valid);
    assert_eq!(check.id, Some(created.info.id));
    assert_eq!(check.scope.as_deref(), Some("inbox.push"));
    assert_eq!(check.label.as_deref(), Some("conformance"));
    let hash = crate::relay::hash_bearer(&created.token).expect("hash");
    let by_hash = store
        .check_hash(&hash.to_ascii_uppercase())
        .expect("check hash");
    assert_eq!(by_hash, check);
    assert!(
        store
            .key_info(created.info.id)
            .expect("info")
            .last_used_at
            .is_none(),
        "a keycheck is not a use"
    );
    assert!(!store.check_token("kq_nope").expect("unknown").valid);
    assert!(!store.check_hash("zz").expect("not a hash").valid);
    store
        .revoke_key_by(created.info.id, "host")
        .expect("revoke");
    assert!(!store.check_hash(&hash).expect("revoked").valid);
}

fn mailbox_stores_bytes_verbatim_dedupes_and_pages(store: &dyn RelayStore) {
    let (_, pk) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&pk);
    let (_, other_pk) = keys::generate_encryption_keypair();
    let first = fake_letter(&pk, 1, b"first letter");
    let stored = store.inbox_push(&[], &first, None).expect("push");
    assert_eq!(stored.recipient_fingerprint, fingerprint);
    assert!(!stored.duplicate);
    let again = store.inbox_push(&[], &first, None).expect("push again");
    assert_eq!(again.id, stored.id);
    assert!(again.duplicate);
    let mut ids = vec![stored.id];
    for i in 0..3u8 {
        let letter = fake_letter(&pk, 1, &[b'x', i]);
        ids.push(store.inbox_push(&[], &letter, None).expect("push").id);
    }
    store
        .inbox_push(&[], &fake_letter(&other_pk, 1, b"not yours"), None)
        .expect("push to someone else");
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "ids grow in arrival order"
    );

    let page = store
        .list_envelopes_after(&fingerprint, None, Some(2))
        .expect("page 1");
    assert_eq!(page.envelopes.len(), 2);
    assert_eq!(page.envelopes[0].bytes, first);
    assert_eq!(page.envelopes[0].recipient_fingerprint, fingerprint);
    assert_eq!(page.next_after, Some(ids[1]));
    let page2 = store
        .list_envelopes_after(&fingerprint, page.next_after, Some(2))
        .expect("page 2");
    assert_eq!(
        page2.envelopes.iter().map(|e| e.id).collect::<Vec<_>>(),
        ids[2..]
    );
    assert_eq!(page2.next_after, None);
    let all = store
        .list_envelopes_after(&fingerprint, None, None)
        .expect("default page");
    assert_eq!(
        all.envelopes.len(),
        4,
        "another recipient's letter is not listed"
    );
    assert!(matches!(
        store.list_envelopes_after(&fingerprint, None, Some(0)),
        Err(Error::InvalidInboxPage)
    ));
    assert!(matches!(
        store.list_envelopes_after(&fingerprint, None, Some(MAX_INBOX_PAGE + 1)),
        Err(Error::InvalidInboxPage)
    ));
    assert_eq!(store.purge_expired_envelopes().expect("purge"), 0);
}

fn mailbox_refuses_device_letters_and_a_past_expiry(store: &dyn RelayStore) {
    let (_, pk) = keys::generate_encryption_keypair();
    assert!(matches!(
        store.inbox_push(&[], &fake_letter(&pk, 9, b"device copy"), None),
        Err(Error::InvalidBridgePackage)
    ));
    assert!(matches!(
        store.inbox_push(&[], b"KQPB\x02", None),
        Err(Error::InvalidBridgePackage)
    ));
    assert!(matches!(
        store.inbox_push(
            &[],
            &fake_letter(&pk, 1, b"late"),
            Some("2000-01-01 00:00:00")
        ),
        Err(Error::ExpiresAtInPast)
    ));
    let kept = store
        .inbox_push(
            &[],
            &fake_letter(&pk, 1, b"later"),
            Some("2099-01-01 00:00:00"),
        )
        .expect("future expiry");
    let listed = store
        .list_envelopes_after(&keys::fingerprint(&pk), None, None)
        .expect("list");
    assert_eq!(listed.envelopes.len(), 1);
    assert_eq!(listed.envelopes[0].id, kept.id);
    // Trees travel with a push, atomically: a bad tree stores nothing.
    let (_, leaf_pk) = keys::generate_encryption_keypair();
    let good = PublicTree {
        label: "org".into(),
        generation: 1,
        nodes: vec![split("M", None), leaf("M.1", "M", &leaf_pk)],
        whitelist: vec![],
        links: vec![],
    };
    let mut bad = good.clone();
    bad.nodes.push(split("M.1", Some("M")));
    assert!(store
        .inbox_push(
            &[good.clone(), bad],
            &fake_letter(&pk, 1, b"with trees"),
            None
        )
        .is_err());
    assert!(matches!(
        store.get_public_tree("org"),
        Err(Error::TreeNotFound)
    ));
    assert_eq!(
        store
            .list_envelopes_after(&keys::fingerprint(&pk), None, None)
            .expect("list")
            .envelopes
            .len(),
        1,
        "the letter was rolled back with the trees"
    );
    store
        .inbox_push(&[good], &fake_letter(&pk, 1, b"with trees"), None)
        .expect("push with a good tree");
    assert_eq!(store.get_public_tree("org").expect("stored").generation, 1);
}

fn device_mailbox_takes_only_sealed_device_letters(store: &dyn RelayStore) {
    let (_, pk) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&pk);
    assert!(matches!(
        store.store_device_package(&fake_letter(&pk, 1, b"bridge letter")),
        Err(Error::InvalidBridgePackage)
    ));
    assert!(matches!(
        store.store_device_package(b"KQTX raw transfer package"),
        Err(Error::InvalidBridgePackage)
    ));
    let letter = fake_letter(&pk, 9, b"sealed copy");
    let stored = store.store_device_package(&letter).expect("store");
    assert_eq!(stored.recipient_fingerprint, fingerprint);
    assert!(!stored.duplicate);
    let again = store.store_device_package(&letter).expect("again");
    assert_eq!((again.id, again.duplicate), (stored.id, true));
    let ack = store
        .store_device_package(&fake_letter(&pk, 10, b"ack"))
        .expect("ack");
    let page = store
        .list_device_packages_after(&fingerprint, None, Some(1))
        .expect("page");
    assert_eq!(page.packages.len(), 1);
    assert_eq!(page.packages[0].bytes, letter);
    assert_eq!(page.next_after, Some(stored.id));
    let rest = store
        .list_device_packages_after(&fingerprint, page.next_after, None)
        .expect("rest");
    assert_eq!(
        rest.packages.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![ack.id]
    );
    assert_eq!(store.purge_expired_device_packages().expect("purge"), 0);
}

fn public_trees_are_versioned_merged_and_validated(store: &dyn RelayStore) {
    let (_, a1) = keys::generate_encryption_keypair();
    let (_, s1) = keys::generate_encryption_keypair();
    let (_, s2) = keys::generate_encryption_keypair();
    let full = PublicTree {
        label: "org".into(),
        generation: 7,
        nodes: vec![
            split("M", None),
            split("M.A", Some("M")),
            split("M.S", Some("M")),
            leaf("M.A.1", "M.A", &a1),
            leaf("M.S.1", "M.S", &s1),
            leaf("M.S.2", "M.S", &s2),
        ],
        whitelist: vec![PublicEdge {
            from: "M.S.2".into(),
            to: "M.A.1".into(),
        }],
        links: vec![],
    };
    let stored = store.put_public_tree(&full).expect("put");
    assert_eq!(stored.generation, 1, "the relay numbers generations itself");
    let stored = store.put_public_tree(&full).expect("put again");
    assert_eq!(stored.generation, 2);
    assert_eq!(store.get_public_tree("org").expect("get").generation, 2);
    assert_eq!(store.list_public_trees().expect("list").len(), 1);

    // A personal slice merges without erasing what it does not mention.
    let slice = PublicTree {
        label: "org".into(),
        generation: 0,
        nodes: vec![
            split("M", None),
            split("M.S", Some("M")),
            leaf("M.S.1", "M.S", &s1),
        ],
        whitelist: vec![],
        links: vec![],
    };
    let merged = store.merge_public_tree(&slice).expect("merge");
    assert_eq!(merged.generation, 3);
    assert_eq!(merged.nodes.len(), 6);
    assert_eq!(merged.whitelist.len(), 1);

    // Invalid trees are refused and leave the stored document alone.
    let mut cycle = full.clone();
    cycle.nodes = vec![
        split("M", None),
        split("A", Some("B")),
        split("B", Some("A")),
    ];
    cycle.whitelist.clear();
    assert!(matches!(
        store.put_public_tree(&cycle),
        Err(Error::InvalidTreeSpec)
    ));
    let mut unlisted_link = full.clone();
    unlisted_link.links.push(PublicEdge {
        from: "M.S.1".into(),
        to: "M.A.1".into(),
    });
    assert!(matches!(
        store.put_public_tree(&unlisted_link),
        Err(Error::InvalidBridge)
    ));
    let kept = store.get_public_tree("org").expect("kept");
    assert_eq!((kept.generation, kept.nodes.len()), (3, 6));
    assert!(matches!(
        store.get_public_tree("nobody"),
        Err(Error::TreeNotFound)
    ));
}

fn device_descriptors_are_signed_and_keep_their_verify_key(store: &dyn RelayStore) {
    let (device_secret, verify_key) = keys::generate_signing_keypair();
    let (_, enc) = keys::generate_encryption_keypair();
    let (_, sig) = keys::generate_signing_keypair();
    let device_id = [7u8; 16];
    let slots = vec![DeviceSlotDescriptor {
        label: "M".into(),
        encryption_public: hex::encode(enc),
        signing_public: hex::encode(sig),
    }];
    let descriptor =
        sign_descriptor(&device_id, &verify_key, &slots, &device_secret).expect("sign");
    assert!(store
        .get_device_descriptor(&descriptor.device_id)
        .expect("get")
        .is_none());
    let stored = store.put_device_descriptor(&descriptor).expect("put");
    assert_eq!(stored, descriptor);
    let loaded = store
        .get_device_descriptor(&descriptor.device_id.to_ascii_uppercase())
        .expect("get")
        .expect("present");
    assert_eq!(loaded, descriptor);
    assert!(matches!(
        store.get_device_descriptor("not-a-device-id"),
        Err(Error::InvalidDevice)
    ));

    let mut tampered = descriptor.clone();
    tampered.slots[0].label = "N".into();
    assert!(store.put_device_descriptor(&tampered).is_err());

    let (other_secret, other_verify) = keys::generate_signing_keypair();
    let replaced = DeviceDescriptor {
        verify_key: hex::encode(other_verify),
        ..sign_descriptor(&device_id, &other_verify, &slots, &other_secret).expect("resign")
    };
    assert!(matches!(
        store.put_device_descriptor(&replaced),
        Err(Error::InvalidDevice)
    ));
    let still = store
        .get_device_descriptor(&descriptor.device_id)
        .expect("get")
        .expect("present");
    assert_eq!(still.verify_key, descriptor.verify_key);
}

fn audit_trail_is_chained_anchored_and_checkpointed(store: &dyn RelayStore) {
    let (identity, root) = identity();
    let key = store
        .mint_key(&new_key(ApiKeyScope::InboxPush, None))
        .expect("create");
    store
        .rotate_key_with(key.info.id, OldKey::RevokeNow)
        .expect("rotate");
    store
        .record_provider_auth_event(&ProviderAuthEvent {
            operation: "keys.create",
            provider_id: Some("Acme"),
            network_id: None,
            hardware_fingerprints: None,
            success: true,
        })
        .expect("auth event");
    let events = store.key_events(None).expect("events");
    assert_eq!(
        events.len(),
        3,
        "created, revoked (by the rotation), rotated"
    );
    assert!(events.iter().all(|e| e.entry_hash.len() == 64));
    assert_ne!(events[0].entry_hash, events[1].entry_hash);

    let reports = store
        .verify_audit(&root, &empty_revoked(), None)
        .expect("verify before any anchor");
    let api = reports
        .iter()
        .find(|r| r.table == AuditTable::ApiKeyEvents.name())
        .expect("api report");
    assert!(api.is_intact());
    assert_eq!((api.rows, api.pending_rows()), (3, 3));

    assert_eq!(
        store
            .anchor_audit(&identity, "2026-06-01 00:00:00.000")
            .expect("anchor"),
        2,
        "one anchor per table with rows"
    );
    assert_eq!(
        store
            .anchor_audit(&identity, "2026-06-01 00:00:01.000")
            .expect("anchor again"),
        0,
        "the newest anchor already covers the head"
    );
    let reports = store
        .verify_audit(&root, &empty_revoked(), None)
        .expect("verify");
    for report in &reports {
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.pending_rows(), 0, "{report:?}");
        assert_eq!(report.rejected_anchors, 0);
        let anchor = report.trusted.as_ref().expect("trusted anchor");
        assert_eq!(anchor.provider_id, "Acme Security Services");
    }

    let checkpoint = store
        .audit_checkpoint(&identity, "2026-06-01 00:00:02.000")
        .expect("checkpoint");
    assert_eq!(checkpoint.heads.len(), 2);
    let decoded = crate::relay::audit::Checkpoint::decode(&checkpoint.encode().expect("encode"))
        .expect("decode");
    assert_eq!(decoded, checkpoint);
    store
        .revoke_key_by(key.info.id, "admin:1")
        .expect("revoked key already; not an error");
    let reports = store
        .verify_audit(&root, &empty_revoked(), Some(&checkpoint))
        .expect("verify against checkpoint");
    for report in &reports {
        assert!(report.is_intact(), "{report:?}");
        let against = report.checkpoint.as_ref().expect("checked");
        assert!(against.matches);
    }
    let (_, other_root) = keys::generate_signing_keypair();
    assert!(
        store
            .verify_audit(&other_root, &empty_revoked(), Some(&checkpoint))
            .is_err(),
        "a checkpoint signed under another root is refused"
    );
    let under_other_root = store
        .verify_audit(&other_root, &empty_revoked(), None)
        .expect("verify under another root");
    assert!(under_other_root.iter().all(|r| r.trusted.is_none()));
    assert!(under_other_root.iter().all(|r| r.rejected_anchors == 1));
}

fn a_first_key_is_sealed_into_a_bundle_or_not_minted_at_all(store: &dyn RelayStore) {
    let (identity, root) = identity();
    let (secret, public) = keys::generate_encryption_keypair();
    let written = RefCell::new(Vec::new());
    let delivered = store
        .mint_key_as_bundle(
            &identity,
            &new_key(ApiKeyScope::InboxPull, None),
            &recipient(public),
            &mut |bytes| {
                written.borrow_mut().extend_from_slice(bytes);
                Ok(())
            },
        )
        .expect("mint and seal");
    let fingerprint = keys::fingerprint(&public);
    assert_eq!(delivered.recipient_fingerprint, fingerprint);
    assert_eq!(
        delivered.info.recipient_fingerprint.as_deref(),
        Some(fingerprint.as_str())
    );
    let Via::Bundle { sha256 } = &delivered.via else {
        panic!("a first key travels as a bundle");
    };
    assert_eq!(sha256.len(), 64);
    let opened =
        api_key_delivery::open(&written.borrow(), &secret, &root, &now(), &empty_revoked())
            .expect("the recipient opens the bundle");
    assert_eq!(opened.issue.key_id, delivered.info.id);
    assert_eq!(opened.issue.relay_url, "https://relay.example.test");
    assert_eq!(
        opened.issue.licence.as_deref(),
        Some("One key for one customer.")
    );
    let authed = store
        .authenticate(&opened.issue.token, ApiKeyScope::InboxPull)
        .expect("the bearer in the bundle is the live key");
    assert_eq!(authed.id, delivered.info.id);
    let recorded = store
        .delivery_recipient_for(delivered.info.id)
        .expect("recipient_for")
        .expect("recorded");
    assert_eq!(recorded.public_key, public);
    assert_eq!(recorded.relay_url, "https://relay.example.test");
    assert!(store
        .delivery_recipient_for(delivered.info.id + 1)
        .expect("none")
        .is_none());

    // A bundle that cannot be written leaves no key behind.
    let before = store.list_keys().expect("list").len();
    let failed = store.mint_key_as_bundle(
        &identity,
        &new_key(ApiKeyScope::InboxPush, None),
        &recipient(public),
        &mut |_| Err(Error::InvalidPath),
    );
    assert!(matches!(failed, Err(Error::InvalidPath)));
    assert_eq!(store.list_keys().expect("list").len(), before);
    assert_eq!(store.key_events(None).expect("events").len(), 1);

    // A given fingerprint must be the recipient key's own.
    let (_, stranger) = keys::generate_encryption_keypair();
    assert!(matches!(
        store.mint_key_as_bundle(
            &identity,
            &new_key(ApiKeyScope::InboxPull, Some(&keys::fingerprint(&stranger))),
            &recipient(public),
            &mut |_| Ok(()),
        ),
        Err(Error::InvalidApiKeyRequest)
    ));
}

fn a_rotation_by_letter_keeps_the_old_key_for_the_grace_period(store: &dyn RelayStore) {
    let (identity, root) = identity();
    let (secret, public) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&public);
    let first = store
        .mint_key_as_bundle(
            &identity,
            &new_key(ApiKeyScope::InboxPull, None),
            &recipient(public),
            &mut |_| Ok(()),
        )
        .expect("first key");
    let old_token = {
        // The bundle was discarded above; mint a plain key to hold a bearer
        // for the old key's grace-period check.
        store
            .mint_key(&new_key(ApiKeyScope::InboxPull, Some(&fingerprint)))
            .expect("second pull key")
    };
    assert!(matches!(
        store.rotate_key_as_letter(&identity, old_token.info.id, None, 60),
        Err(Error::DeliveryRecipientMissing)
    ));
    assert!(matches!(
        store.rotate_key_as_letter(&identity, old_token.info.id, Some(recipient(public)), 0),
        Err(Error::InvalidApiKeyRequest)
    ));
    let delivered = store
        .rotate_key_as_letter(&identity, old_token.info.id, Some(recipient(public)), 3_600)
        .expect("rotate by letter");
    let Via::Letter {
        id: letter_id,
        until,
    } = &delivered.via
    else {
        panic!("a rotation travels as a letter");
    };
    assert!(until.is_some(), "the old key now expires");
    store
        .authenticate(&old_token.token, ApiKeyScope::InboxPull)
        .expect("the old key still pulls during the grace period");
    let old_info = store.key_info(old_token.info.id).expect("old info");
    assert!(old_info.revoked_at.is_none());
    assert_eq!(old_info.expires_at.as_deref(), until.as_deref());

    let page = store
        .list_envelopes_after(&fingerprint, None, None)
        .expect("mailbox");
    let letter = page
        .envelopes
        .iter()
        .find(|e| e.id == *letter_id)
        .expect("the letter waits in the mailbox");
    let opened = api_key_delivery::open(&letter.bytes, &secret, &root, &now(), &empty_revoked())
        .expect("the recipient opens the letter");
    assert_eq!(opened.carrier, api_key_delivery::Carrier::Letter);
    assert_eq!(opened.issue.key_id, delivered.info.id);
    store
        .authenticate(&opened.issue.token, ApiKeyScope::InboxPull)
        .expect("the replacement is live");
    let recorded = store
        .delivery_recipient_for(delivered.info.id)
        .expect("recipient")
        .expect("recorded");
    assert_eq!(recorded.public_key, public);
    let events: Vec<(String, Option<i64>)> = store
        .key_events(Some(old_token.info.id))
        .expect("events")
        .into_iter()
        .map(|e| (e.event, e.related_key_id))
        .collect();
    assert_eq!(
        events,
        vec![
            ("created".into(), None),
            ("rotated".into(), Some(old_token.info.id))
        ]
    );
    // The next rotation of the replacement needs no recipient: it is recorded.
    let next = store
        .rotate_key_as_letter(&identity, delivered.info.id, None, 60)
        .expect("rotate again");
    assert!(matches!(next.via, Via::Letter { .. }));

    // A key nothing the customer holds can collect a letter with is refused
    // before anything changes.
    let (_, lonely) = keys::generate_encryption_keypair();
    let push = store
        .mint_key_as_bundle(
            &identity,
            &new_key(ApiKeyScope::InboxPush, None),
            &recipient(lonely),
            &mut |_| Ok(()),
        )
        .expect("push key sealed to a recipient with no pull key");
    assert!(matches!(
        store.rotate_key_as_letter(&identity, push.info.id, None, 60),
        Err(Error::DeliveryNotCollectable)
    ));
    let info = store.key_info(push.info.id).expect("info");
    assert!(info.revoked_at.is_none() && info.expires_at.is_none());
    // A bound key is sealed only to the key it is bound to.
    assert!(matches!(
        store.rotate_key_as_letter(&identity, first.info.id, Some(recipient(lonely)), 60),
        Err(Error::InvalidApiKeyRequest)
    ));
}

fn a_rotation_by_bundle_revokes_the_old_key_at_once(store: &dyn RelayStore) {
    let (identity, _) = identity();
    let (_, public) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&public);
    let old = store
        .mint_key(&new_key(ApiKeyScope::InboxPull, Some(&fingerprint)))
        .expect("old key");
    let mut writes = 0;
    let delivered = store
        .rotate_key_as_bundle(&identity, old.info.id, Some(recipient(public)), &mut |_| {
            writes += 1;
            Ok(())
        })
        .expect("rotate by bundle");
    assert_eq!(writes, 1);
    assert!(matches!(delivered.via, Via::Bundle { .. }));
    assert!(matches!(
        store.authenticate(&old.token, ApiKeyScope::InboxPull),
        Err(Error::ApiKeyRevoked)
    ));
    assert_eq!(
        store
            .key_info(delivered.info.id)
            .expect("new")
            .recipient_fingerprint
            .as_deref(),
        Some(fingerprint.as_str())
    );
    // A write that fails rolls the rotation back: the old key stays live.
    let fresh = store
        .mint_key(&new_key(ApiKeyScope::InboxPush, None))
        .expect("another key");
    assert!(store
        .rotate_key_as_bundle(
            &identity,
            fresh.info.id,
            Some(recipient(public)),
            &mut |_| { Err(Error::InvalidPath) }
        )
        .is_err());
    store
        .authenticate(&fresh.token, ApiKeyScope::InboxPush)
        .expect("a failed rotation changes nothing");
    assert_eq!(
        store.key_events(Some(fresh.info.id)).expect("events").len(),
        1
    );
}

fn the_operator_lock_bootstraps_once_and_never_over_a_supplied_key(store: &dyn RelayStore) {
    assert!(matches!(
        store.authorize_licensee_or_bootstrap(Some("kql_whatever")),
        Err(Error::InvalidLicenseeKey)
    ));
    assert!(matches!(
        store.authorize_licensee_or_bootstrap(Some("")),
        Err(Error::InvalidLicenseeKey)
    ));
    let issuer = store
        .authorize_licensee_or_bootstrap(None)
        .expect("bootstrap")
        .expect("minted once");
    assert!(issuer.token.starts_with("kql_"));
    assert!(store
        .authorize_licensee_or_bootstrap(None)
        .expect("no second bootstrap")
        .is_none());
    store
        .authenticate_licensee(&issuer.token)
        .expect("the lock opens");
    assert!(store
        .authorize_licensee_or_bootstrap(Some(&issuer.token))
        .expect("supplied")
        .is_none());
    assert!(matches!(
        store.authenticate_licensee("kql_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Err(Error::InvalidLicenseeKey)
    ));
    assert!(matches!(
        store.authenticate_licensee("kq_not-the-lock"),
        Err(Error::InvalidLicenseeKey)
    ));
}

fn provider_auth_events_are_recorded_without_secrets(store: &dyn RelayStore) {
    let (identity, root) = identity();
    for success in [true, false] {
        store
            .record_provider_auth_event(&ProviderAuthEvent {
                operation: "keys.rotate",
                provider_id: Some("Acme Security Services"),
                network_id: Some("vpn-1"),
                hardware_fingerprints: Some("deadbeef"),
                success,
            })
            .expect("record");
    }
    store
        .anchor_audit(&identity, "2026-06-01 00:00:00.000")
        .expect("anchor");
    let report = store
        .verify_audit(&root, &empty_revoked(), None)
        .expect("verify")
        .into_iter()
        .find(|r| r.table == AuditTable::ProviderAuthEvents.name())
        .expect("report");
    assert!(report.is_intact());
    assert_eq!((report.rows, report.pending_rows()), (2, 0));
}

/// Many writers at once: keys minted and rotated, letters pushed, device
/// letters stored, anchors signed. Afterwards every id is unique, every
/// letter is listed exactly once, the rotation events name the keys they
/// replaced, and both audit chains verify end to end. For a shared backend
/// this is what several relay replicas do to one store.
fn issuance_request(public: [u8; 32], scopes: &[ApiKeyScope]) -> crate::relay::issuance::Issuance {
    use crate::relay::customer::NewCustomer;
    use crate::relay::issuance::{CustomerRef, Issuance, LicenceRef};
    use crate::relay::licence::NewLicence;
    Issuance {
        customer: CustomerRef::New(NewCustomer {
            name: "Conformance Client".into(),
            reference: Some("CF-1".into()),
        }),
        licence: LicenceRef::New(NewLicence {
            terms: "Terms.".into(),
            expires_at: Some("2999-01-01".into()),
            replaces: None,
        }),
        scopes: scopes.to_vec(),
        recipient_public_key: public,
        relay_url: "https://relay.example.test/".to_string(),
        device_id: None,
    }
}

fn a_licence_is_issued_replaced_and_voided_as_one_unit_of_work(store: &dyn RelayStore) {
    use crate::relay::issuance::{CustomerRef, LicenceRef, RotateVia};
    use crate::relay::operator_log::Note;
    let (identity, root) = identity();
    let (secret, public) = keys::generate_encryption_keypair();
    let note = Note {
        operation_id: Some("op-conformance-1"),
        operator: "ops@example.test",
        action: "issue",
        subject: "Conformance Client",
    };
    let issued = store
        .issue_licensed_bundles(
            &identity,
            &issuance_request(public, &[ApiKeyScope::InboxPush, ApiKeyScope::InboxPull]),
            Some(&note),
        )
        .expect("issue");
    assert_eq!(issued.bundles.len(), 2);
    assert_eq!(store.customer_count().expect("count"), 1);
    assert_eq!(
        store
            .licences_of(issued.customer.id)
            .expect("licences")
            .len(),
        1
    );
    assert_eq!(store.key_links().expect("links").len(), 2);
    let records = store.delivery_records().expect("deliveries");
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .all(|r| r.recipient_fingerprint == keys::fingerprint(&public)));
    // The operation is recorded with the change, and found again by its id.
    let recorded = store
        .find_operation("op-conformance-1")
        .expect("find")
        .expect("recorded");
    assert_eq!(recorded.action, "issue");
    assert!(store
        .issue_licensed_bundles(
            &identity,
            &issuance_request(public, &[ApiKeyScope::DevicePush]),
            Some(&note),
        )
        .is_err());
    assert_eq!(
        store.customer_count().expect("count"),
        1,
        "the repeat made nothing"
    );

    let opened = api_key_delivery::open(
        &issued.bundles[0].bundle,
        &secret,
        &root,
        &now(),
        &empty_revoked(),
    )
    .expect("opens");
    store
        .authenticate(&opened.issue.token, ApiKeyScope::InboxPush)
        .expect("live");

    // A replacement keeps the licence; the old key ends at once.
    let replaced = store
        .rotate_licensed_key(
            &identity,
            issued.bundles[0].info.id,
            RotateVia::Bundle,
            None,
        )
        .expect("rotate");
    assert!(store
        .authenticate(&opened.issue.token, ApiKeyScope::InboxPush)
        .is_err());
    assert!(store.key_links().expect("links").iter().any(|l| {
        l.api_key_id == replaced.info.id
            && l.licence_id == issued.licence.id
            && l.replaces_key_id == Some(issued.bundles[0].info.id)
    }));

    // A renewal adds a statement version and leaves the old one as it was.
    let renewed = store
        .renew_licence(issued.licence.id, Some("Renewed terms."), None, None)
        .expect("renew");
    assert_eq!(renewed.version, 2);
    let versions = store.licence_versions(issued.licence.id).expect("versions");
    assert_eq!((versions.len(), versions[0].terms.as_str()), (2, "Terms."));

    // Voiding revokes everything issued under it, once.
    let voided = store
        .void_licence(issued.licence.id, Some("test"), None)
        .expect("void");
    assert!(voided.newly_voided);
    assert_eq!(voided.revoked_keys.len(), 2);
    assert!(
        !store
            .void_licence(issued.licence.id, None, None)
            .expect("again")
            .newly_voided
    );
    assert!(store
        .get_licence(issued.licence.id)
        .expect("licence")
        .voided_at
        .is_some());
    assert!(matches!(
        store.issue_licensed_bundles(
            &identity,
            &{
                let mut again = issuance_request(public, &[ApiKeyScope::DevicePush]);
                again.customer = CustomerRef::Existing(issued.customer.id);
                again.licence = LicenceRef::Existing(issued.licence.id);
                again
            },
            None
        ),
        Err(Error::LicenceNotActive)
    ));
    let live = store
        .list_keys()
        .expect("keys")
        .iter()
        .filter(|k| k.revoked_at.is_none())
        .count();
    assert_eq!(live, 0);
    assert_eq!(store.licence_counts().expect("counts").voided, 1);
}

fn known_keys_activity_is_counted_in_place_and_unknown_bearers_are_not(store: &dyn RelayStore) {
    use crate::relay::activity::{Cost, Filter};
    let created = store
        .mint_key(&new_key(ApiKeyScope::InboxPush, None))
        .expect("create");
    let cost = Cost {
        millis: 5,
        bytes_in: 10,
        bytes_out: 20,
    };
    for _ in 0..3 {
        store
            .record_access(&created.token, "/inbox", 200, cost)
            .expect("record");
    }
    store
        .record_access(&created.token, "/inbox", 403, cost)
        .expect("record");
    store
        .record_access("kq_not-a-key", "/inbox", 401, cost)
        .expect("unknown");
    let window = Filter {
        hours: 24,
        ..Filter::default()
    };
    let summary = store.access_summary(&window).expect("summary");
    assert_eq!(summary.by_key.iter().map(|a| a.count).sum::<i64>(), 4);
    assert!(summary
        .by_key
        .iter()
        .all(|a| a.api_key_id == created.info.id));
    let ok = summary
        .by_key
        .iter()
        .find(|a| a.outcome == "ok")
        .expect("ok row");
    assert_eq!((ok.ms_total, ok.bytes_in, ok.bytes_out), (15, 30, 60));
    assert_eq!(store.purge_old_activity().expect("purge"), 0);
    store
        .revoke_key_by(created.info.id, "host")
        .expect("revoke");
    store
        .record_access(&created.token, "/inbox", 401, cost)
        .expect("record");
    let outcomes: Vec<_> = store
        .access_summary(&window)
        .expect("summary")
        .by_key
        .into_iter()
        .map(|a| a.outcome)
        .collect();
    assert!(outcomes.contains(&"revoked".to_string()));
}

fn the_operator_lock_is_staged_then_confirmed_and_the_old_one_stands_until_then(
    store: &dyn RelayStore,
) {
    assert!(!store.operator_lock_exists().expect("exists"));
    assert!(!store.operator_lock_pending().expect("pending"));
    let first = store.stage_operator_lock().expect("stage");
    assert!(store.operator_lock_pending().expect("pending"));
    // A staged lock is not a lock yet.
    assert!(!store.operator_lock_exists().expect("exists"));
    assert!(store.authenticate_licensee(&first.token).is_err());
    // Staging again replaces the first, so a lost response is recoverable.
    let second = store.stage_operator_lock().expect("stage again");
    assert!(
        store.confirm_operator_lock(&first.token).is_err(),
        "the replaced one is gone"
    );
    store.confirm_operator_lock(&second.token).expect("confirm");
    assert!(store.operator_lock_exists().expect("exists"));
    assert!(!store.operator_lock_pending().expect("pending"));
    store
        .authenticate_licensee(&second.token)
        .expect("the lock");
    assert!(
        store.confirm_operator_lock(&second.token).is_err(),
        "nothing is staged now"
    );

    // A replacement is staged while the current lock keeps working, and takes
    // over only when it is confirmed.
    let next = store.stage_operator_lock().expect("stage a replacement");
    store
        .authenticate_licensee(&second.token)
        .expect("the current lock still stands");
    assert!(store.authenticate_licensee(&next.token).is_err());
    store.confirm_operator_lock(&next.token).expect("confirm");
    assert!(store.authenticate_licensee(&second.token).is_err());
    store
        .authenticate_licensee(&next.token)
        .expect("the new lock");
}

fn the_console_views_hold_no_secret_and_name_only_what_the_relay_holds(store: &dyn RelayStore) {
    store
        .record_operator_action("ops@example.test", "issue", Some("Acme"), false)
        .expect("action");
    let actions = store.operator_actions(10, None).expect("actions");
    assert_eq!(actions.len(), 1);
    assert_eq!(
        (actions[0].operator.as_str(), actions[0].success),
        ("ops@example.test", false)
    );

    store
        .record_provider_auth_event(&ProviderAuthEvent {
            operation: "console.issue",
            provider_id: None,
            network_id: None,
            hardware_fingerprints: None,
            success: false,
        })
        .expect("event");
    let auth = store.provider_auth_events(10, None).expect("auth");
    assert_eq!(
        (auth[0].operation.as_str(), auth[0].success),
        ("console.issue", false)
    );
    assert_eq!(auth[0].entry_hash.len(), 64);

    let (_, public) = keys::generate_encryption_keypair();
    let letter = fake_letter(&public, 15, b"opaque");
    store.inbox_push(&[], &letter, None).expect("push");
    let (total, letters) = store.inbox_letters(10).expect("letters");
    assert_eq!(total, 1);
    assert_eq!(letters[0].kind, Some(15));
    assert_eq!(letters[0].size, letter.len() as i64);
    assert_eq!(letters[0].recipient_fingerprint, keys::fingerprint(&public));
    store
        .store_device_package(&fake_letter(&public, 9, b"d"))
        .expect("device letter");
    let (total, devices) = store.device_letters(10).expect("devices");
    assert_eq!((total, devices[0].kind), (1, Some(9)));

    store
        .put_public_tree(&PublicTree {
            label: "acme".into(),
            generation: 1,
            nodes: vec![split("acme", None)],
            whitelist: Vec::<PublicEdge>::new(),
            links: Vec::<PublicEdge>::new(),
        })
        .expect("tree");
    let trees = store.tree_summaries().expect("trees");
    assert_eq!((trees[0].label.as_str(), trees[0].generation), ("acme", 1));
    assert!(store.expired_key_ids().expect("expired").is_empty());
}

pub(crate) fn concurrent_writers_keep_every_invariant(store: &(impl RelayStore + 'static)) {
    const WRITERS: usize = 6;
    const ROUNDS: usize = 12;
    let (identity, root) = identity();
    let identity = Arc::new(identity);
    let (_, pk) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&pk);
    let letters: Vec<(i64, bool)> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for writer in 0..WRITERS {
            let identity = identity.clone();
            handles.push(scope.spawn(move || {
                let mut pushed = Vec::new();
                for round in 0..ROUNDS {
                    let key = store
                        .mint_key(&new_key(ApiKeyScope::InboxPush, None))
                        .expect("create");
                    let rotated = store
                        .rotate_key_with(key.info.id, OldKey::ExpireAfter(600))
                        .expect("rotate");
                    store
                        .revoke_key_by(rotated.info.id, "host")
                        .expect("revoke");
                    let letter = fake_letter(&pk, 1, &[writer as u8, round as u8]);
                    let stored = store.inbox_push(&[], &letter, None).expect("push");
                    pushed.push((stored.id, stored.duplicate));
                    let twin = store.inbox_push(&[], &letter, None).expect("push twin");
                    assert_eq!(twin.id, stored.id);
                    store
                        .store_device_package(&fake_letter(&pk, 11, &[writer as u8, round as u8]))
                        .expect("device letter");
                    store
                        .record_provider_auth_event(&ProviderAuthEvent {
                            operation: "keys.create",
                            provider_id: Some("Acme Security Services"),
                            network_id: None,
                            hardware_fingerprints: None,
                            success: round % 2 == 0,
                        })
                        .expect("auth event");
                    if round % 4 == 0 {
                        store
                            .anchor_audit(&identity, &format!("2026-06-01 00:00:{round:02}.000"))
                            .expect("anchor");
                    }
                }
                pushed
            }));
        }
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("writer thread"))
            .collect()
    });

    assert_eq!(letters.len(), WRITERS * ROUNDS);
    assert!(letters.iter().all(|(_, duplicate)| !duplicate));
    let mut ids: Vec<i64> = letters.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), WRITERS * ROUNDS, "every letter got its own id");
    let mut listed = Vec::new();
    let mut after = None;
    loop {
        let page = store
            .list_envelopes_after(&fingerprint, after, Some(7))
            .expect("page");
        listed.extend(page.envelopes.iter().map(|e| e.id));
        match page.next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(listed, ids, "paging lists every letter once, in id order");
    let devices = store
        .list_device_packages_after(&fingerprint, None, Some(MAX_INBOX_PAGE))
        .expect("device page");
    assert_eq!(devices.packages.len(), WRITERS * ROUNDS);

    let keys = store.list_keys().expect("list");
    assert_eq!(keys.len(), 2 * WRITERS * ROUNDS);
    let mut key_ids: Vec<i64> = keys.iter().map(|k| k.id).collect();
    key_ids.dedup();
    assert_eq!(key_ids.len(), keys.len(), "every key got its own id");
    let events = store.key_events(None).expect("events");
    assert_eq!(events.len(), 3 * WRITERS * ROUNDS);
    let mut event_ids: Vec<i64> = events.iter().map(|e| e.id).collect();
    event_ids.dedup();
    assert_eq!(event_ids.len(), events.len());
    for window in events.windows(2) {
        assert!(
            window[0].id < window[1].id,
            "events come back in chain order"
        );
    }
    for event in events.iter().filter(|e| e.event == "rotated") {
        let replaced = event.related_key_id.expect("names the key it replaced");
        let old = keys
            .iter()
            .find(|k| k.id == replaced)
            .expect("old key exists");
        assert!(
            old.expires_at.is_some(),
            "the old key was given its grace period"
        );
        let new = keys
            .iter()
            .find(|k| k.id == event.key_id)
            .expect("new key exists");
        assert!(new.revoked_at.is_some(), "then revoked by the same writer");
    }

    store
        .anchor_audit(&identity, "2026-06-01 00:01:00.000")
        .expect("final anchor");
    let reports = store
        .verify_audit(&root, &empty_revoked(), None)
        .expect("verify");
    for report in &reports {
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.pending_rows(), 0, "{report:?}");
        assert_eq!(report.rejected_anchors, 0, "{report:?}");
    }
    let api = reports
        .iter()
        .find(|r| r.table == AuditTable::ApiKeyEvents.name())
        .expect("api report");
    assert_eq!(api.rows, (3 * WRITERS * ROUNDS) as u64);
    let auth = reports
        .iter()
        .find(|r| r.table == AuditTable::ProviderAuthEvents.name())
        .expect("auth report");
    assert_eq!(auth.rows, (WRITERS * ROUNDS) as u64);
}

/// Each recipient and device has its own stream; a generation is never reused.
fn package_generations_rise_per_recipient_and_device(store: &dyn RelayStore) {
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let drive = [3u8; 16];
    assert_eq!(
        store.next_package_generation(&alice, Some(&drive)).unwrap(),
        1
    );
    assert_eq!(
        store.next_package_generation(&alice, Some(&drive)).unwrap(),
        2
    );
    assert_eq!(store.next_package_generation(&alice, None).unwrap(), 1);
    assert_eq!(
        store.next_package_generation(&bob, Some(&drive)).unwrap(),
        1
    );
    assert_eq!(
        store.next_package_generation(&alice, Some(&drive)).unwrap(),
        3
    );
}
