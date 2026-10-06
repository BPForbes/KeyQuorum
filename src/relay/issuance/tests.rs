use super::*;
use crate::api_key_delivery;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay;
use rusqlite::Connection;

struct Setup {
    conn: Connection,
    identity: ProviderIdentity,
    root: [u8; 32],
}

fn setup() -> Setup {
    let issued = issued_identity("2099-01-01 00:00:00");
    Setup {
        conn: relay::open_in_memory().expect("schema"),
        identity: ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
        root: issued.root_public,
    }
}

fn client() -> (zeroize::Zeroizing<[u8; 32]>, [u8; 32]) {
    keys::generate_encryption_keypair()
}

fn request(public: [u8; 32], scopes: &[ApiKeyScope]) -> Issuance {
    Issuance {
        licence: LicenceRef::New(NewLicence {
            client: "Acme Ltd".into(),
            terms: "Five seats.".into(),
            expires_at: Some("2999-01-01".into()),
        }),
        scopes: scopes.to_vec(),
        recipient_public_key: public,
        relay_url: "https://relay.example.test".into(),
        device_id: None,
    }
}

fn open(s: &Setup, secret: &[u8; 32], bundle: &[u8]) -> api_key_delivery::Opened {
    let now = crate::provider::system_now_utc().expect("clock");
    api_key_delivery::open(bundle, secret, &s.root, &now, &empty_revoked()).expect("opens")
}

fn key_count(conn: &Connection) -> usize {
    relay::list_api_keys(conn).expect("list").len()
}

#[test]
fn a_licence_is_issued_as_one_sealed_bundle_per_scope_that_the_client_alone_opens() {
    let s = setup();
    let (secret, public) = client();
    let scopes = [ApiKeyScope::InboxPush, ApiKeyScope::InboxPull];
    let issued = issue(&s.conn, &s.identity, &request(public, &scopes)).expect("issue");
    assert_eq!(issued.licence.client, "Acme Ltd");
    assert_eq!(issued.bundles.len(), 2);
    for (bundle, scope) in issued.bundles.iter().zip(scopes) {
        assert_eq!(bundle.info.scope, scope.as_str());
        assert_eq!(bundle.recipient_fingerprint, keys::fingerprint(&public));
        let opened = open(&s, &secret, &bundle.bundle);
        assert_eq!(opened.issue.key_id, bundle.info.id);
        assert_eq!(opened.issue.relay_url, "https://relay.example.test");
        // The bearer inside is the live key, and it is nowhere else.
        let authed = relay::authenticate(&s.conn, opened.issue.token.as_str(), scope).expect("live");
        assert_eq!(authed.id, bundle.info.id);
        let statement = opened.issue.licence.expect("a signed licence statement");
        assert!(statement.contains("Licensee: Acme Ltd"));
        assert!(statement.contains(&format!("Scope: {}", scope.as_str())));
        assert!(statement.contains("Five seats."));
        // The key ends when the licence does.
        assert_eq!(bundle.info.expires_at, issued.licence.expires_at);
        assert_eq!(licence::licence_of_key(&s.conn, bundle.info.id).expect("link"), Some(issued.licence.id));
    }
    // A stranger cannot open them.
    let (stranger, _) = client();
    let now = crate::provider::system_now_utc().expect("clock");
    assert!(api_key_delivery::open(&issued.bundles[0].bundle, &stranger, &s.root, &now, &empty_revoked()).is_err());
}

#[test]
fn a_pull_key_is_bound_to_the_recipients_fingerprint() {
    let s = setup();
    let (_, public) = client();
    let issued = issue(&s.conn, &s.identity, &request(public, &[ApiKeyScope::InboxPull])).expect("issue");
    assert_eq!(
        issued.bundles[0].info.recipient_fingerprint.as_deref(),
        Some(keys::fingerprint(&public).as_str())
    );
}

#[test]
fn only_the_four_client_scopes_once_each_and_a_sound_recipient_are_accepted() {
    let s = setup();
    let (_, public) = client();
    let bad_requests = [
        request(public, &[]),
        request(public, &[ApiKeyScope::Admin]),
        request(public, &[ApiKeyScope::InboxPush, ApiKeyScope::InboxPush]),
        request([0u8; 32], &[ApiKeyScope::InboxPush]),
        Issuance { relay_url: "not a url".into(), ..request(public, &[ApiKeyScope::InboxPush]) },
    ];
    for bad in &bad_requests {
        assert!(issue(&s.conn, &s.identity, bad).is_err());
    }
    assert_eq!(key_count(&s.conn), 0);
    assert!(licence::list(&s.conn).expect("list").is_empty());
}

#[test]
fn a_second_batch_under_an_existing_licence_adds_keys_to_it() {
    let s = setup();
    let (_, public) = client();
    let first = issue(&s.conn, &s.identity, &request(public, &[ApiKeyScope::InboxPush])).expect("issue");
    let more = Issuance {
        licence: LicenceRef::Existing(first.licence.id),
        ..request(public, &[ApiKeyScope::DevicePush, ApiKeyScope::DevicePull])
    };
    let second = issue(&s.conn, &s.identity, &more).expect("issue more");
    assert_eq!(second.licence.id, first.licence.id);
    assert_eq!(licence::keys_of(&s.conn, first.licence.id).expect("keys").len(), 3);
    assert_eq!(licence::list(&s.conn).expect("list").len(), 1);
}

#[test]
fn nothing_is_issued_under_a_voided_or_missing_licence() {
    let s = setup();
    let (_, public) = client();
    let first = issue(&s.conn, &s.identity, &request(public, &[ApiKeyScope::InboxPush])).expect("issue");
    void(&s.conn, first.licence.id, None).expect("void");
    let before = key_count(&s.conn);
    let again = Issuance {
        licence: LicenceRef::Existing(first.licence.id),
        ..request(public, &[ApiKeyScope::InboxPull])
    };
    assert!(matches!(issue(&s.conn, &s.identity, &again), Err(Error::LicenceNotActive)));
    let missing = Issuance { licence: LicenceRef::Existing(999), ..again };
    assert!(matches!(issue(&s.conn, &s.identity, &missing), Err(Error::LicenceNotFound)));
    assert_eq!(key_count(&s.conn), before);
}

#[test]
fn a_failure_mid_issue_leaves_no_licence_and_no_key() {
    let s = setup();
    let (_, public) = client();
    // Make the second key's insert fail, after the licence and the first key
    // were written inside the same unit of work.
    let dyn_conn: &dyn Sql = &s.conn;
    dyn_conn
        .execute_batch(
            "CREATE TRIGGER fail_second BEFORE INSERT ON api_keys
             WHEN (SELECT COUNT(*) FROM api_keys) >= 1
             BEGIN SELECT RAISE(ABORT, 'forced'); END",
        )
        .expect("trigger");
    let issued = issue(
        &s.conn,
        &s.identity,
        &request(public, &[ApiKeyScope::InboxPush, ApiKeyScope::InboxPull]),
    );
    assert!(issued.is_err());
    assert_eq!(key_count(&s.conn), 0);
    assert!(licence::list(&s.conn).expect("list").is_empty());
    assert!(relay::api_key_events(&s.conn).expect("events").is_empty());
}

#[test]
fn a_rotation_revokes_the_old_key_at_once_and_keeps_the_licence_and_recipient() {
    let s = setup();
    let (secret, public) = client();
    let issued = issue(&s.conn, &s.identity, &request(public, &[ApiKeyScope::InboxPush])).expect("issue");
    let old = &issued.bundles[0];
    let old_token = open(&s, &secret, &old.bundle).issue.token;
    let new = rotate(&s.conn, &s.identity, old.info.id).expect("rotate");
    assert_ne!(new.info.id, old.info.id);
    assert!(relay::authenticate(&s.conn, old_token.as_str(), ApiKeyScope::InboxPush).is_err());
    let opened = open(&s, &secret, &new.bundle);
    assert!(relay::authenticate(&s.conn, opened.issue.token.as_str(), ApiKeyScope::InboxPush).is_ok());
    assert_eq!(
        licence::licence_of_key(&s.conn, new.info.id).expect("link"),
        Some(issued.licence.id)
    );
    assert_eq!(new.info.expires_at, old.info.expires_at);
}

#[test]
fn a_rotation_of_a_key_whose_licence_was_voided_is_refused_and_changes_nothing() {
    let s = setup();
    let (_, public) = client();
    let issued = issue(&s.conn, &s.identity, &request(public, &[ApiKeyScope::InboxPush])).expect("issue");
    let id = issued.bundles[0].info.id;
    // Voiding revokes the key; a rotation of a revoked key is refused too.
    void(&s.conn, issued.licence.id, None).expect("void");
    let before = key_count(&s.conn);
    assert!(rotate(&s.conn, &s.identity, id).is_err());
    assert_eq!(key_count(&s.conn), before);
}

#[test]
fn voiding_a_licence_revokes_its_live_keys_once_and_leaves_others_alone() {
    let s = setup();
    let (secret, public) = client();
    let issued = issue(
        &s.conn,
        &s.identity,
        &request(public, &[ApiKeyScope::InboxPush, ApiKeyScope::InboxPull]),
    )
    .expect("issue");
    let (_, other_public) = client();
    let other = issue(&s.conn, &s.identity, &request(other_public, &[ApiKeyScope::InboxPush])).expect("issue");
    let token = open(&s, &secret, &issued.bundles[0].bundle).issue.token;

    let voided = void(&s.conn, issued.licence.id, Some("unpaid")).expect("void");
    assert!(voided.newly_voided);
    assert_eq!(
        voided.revoked_keys,
        issued.bundles.iter().map(|b| b.info.id).collect::<Vec<_>>()
    );
    assert!(relay::authenticate(&s.conn, token.as_str(), ApiKeyScope::InboxPush).is_err());
    assert!(relay::api_key_info(&s.conn, other.bundles[0].info.id).expect("info").revoked_at.is_none());
    let events = relay::api_key_events(&s.conn).expect("events");
    let revoked: Vec<_> = events.iter().filter(|e| e.event == "revoked").collect();
    assert_eq!(revoked.len(), 2);
    assert!(revoked.iter().all(|e| e.actor == HOST_ACTOR));

    let again = void(&s.conn, issued.licence.id, None).expect("void twice");
    assert!(!again.newly_voided);
    assert!(again.revoked_keys.is_empty());
    assert_eq!(
        relay::api_key_events(&s.conn).expect("events").iter().filter(|e| e.event == "revoked").count(),
        2
    );
    assert!(matches!(void(&s.conn, 999, None), Err(Error::LicenceNotFound)));
}
