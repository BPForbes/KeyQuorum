use super::*;
use crate::api_key_delivery;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::operator_log::{self, Note};
use crate::relay::{self};
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

fn acme() -> CustomerRef {
    CustomerRef::New(NewCustomer {
        name: "Acme Ltd".into(),
        reference: None,
    })
}

fn terms(ends: Option<&str>) -> NewLicence {
    NewLicence {
        terms: "Five seats.".into(),
        expires_at: ends.map(str::to_string),
        replaces: None,
    }
}

fn request(public: [u8; 32], scopes: &[ApiKeyScope]) -> Issuance {
    Issuance {
        customer: acme(),
        licence: LicenceRef::New(terms(Some("2999-01-01"))),
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

fn issue_one(s: &Setup, public: [u8; 32], scopes: &[ApiKeyScope]) -> Issued {
    issue(&s.conn, &s.identity, &request(public, scopes), None).expect("issue")
}

#[test]
fn a_customer_and_licence_are_issued_as_one_sealed_bundle_per_scope_that_the_client_alone_opens() {
    let s = setup();
    let (secret, public) = client();
    let scopes = [ApiKeyScope::InboxPush, ApiKeyScope::InboxPull];
    let issued = issue_one(&s, public, &scopes);
    assert_eq!(
        (issued.customer.name.as_str(), issued.licence.customer_id),
        ("Acme Ltd", issued.customer.id)
    );
    assert_eq!(issued.bundles.len(), 2);
    for (bundle, scope) in issued.bundles.iter().zip(scopes) {
        assert_eq!(bundle.info.scope, scope.as_str());
        assert_eq!(bundle.recipient_fingerprint, keys::fingerprint(&public));
        let opened = open(&s, &secret, &bundle.bundle);
        assert_eq!(opened.issue.key_id, bundle.info.id);
        assert_eq!(opened.issue.relay_url, "https://relay.example.test");
        let authed =
            relay::authenticate(&s.conn, opened.issue.token.as_str(), scope).expect("live");
        assert_eq!(authed.id, bundle.info.id);
        let statement = opened.issue.licence.expect("a signed licence statement");
        assert!(statement.contains("Licensee: Acme Ltd") && statement.contains("(statement 1)"));
        assert!(
            statement.contains(&format!("Scope: {}", scope.as_str()))
                && statement.contains("Five seats.")
        );
        // The key ends when the licence does, and is linked to it and its statement.
        assert_eq!(bundle.info.expires_at, issued.licence.expires_at);
        let link = licence::link_of_key(&s.conn, bundle.info.id)
            .expect("link")
            .expect("linked");
        assert_eq!(
            (link.licence_id, link.licence_version, link.replaces_key_id),
            (issued.licence.id, Some(1), None)
        );
    }
    let (stranger, _) = client();
    let now = crate::provider::system_now_utc().expect("clock");
    assert!(api_key_delivery::open(
        &issued.bundles[0].bundle,
        &stranger,
        &s.root,
        &now,
        &empty_revoked()
    )
    .is_err());
}

#[test]
fn a_pull_key_is_bound_to_the_recipients_fingerprint_and_a_push_key_is_owned_through_its_licence() {
    let s = setup();
    let (_, public) = client();
    let issued = issue_one(
        &s,
        public,
        &[ApiKeyScope::InboxPull, ApiKeyScope::InboxPush],
    );
    assert_eq!(
        issued.bundles[0].info.recipient_fingerprint.as_deref(),
        Some(keys::fingerprint(&public).as_str())
    );
    // A push key has no fingerprint, and is still the customer's.
    assert_eq!(issued.bundles[1].info.recipient_fingerprint, None);
    assert_eq!(
        licence::customer_of(
            &s.conn,
            licence::link_of_key(&s.conn, issued.bundles[1].info.id)
                .expect("link")
                .expect("linked")
                .licence_id
        )
        .expect("owner")
        .id,
        issued.customer.id
    );
}

#[test]
fn only_the_four_client_scopes_once_each_a_sound_recipient_and_a_coherent_request_are_accepted() {
    let s = setup();
    let (_, public) = client();
    let bad = [
        request(public, &[]),
        request(public, &[ApiKeyScope::Admin]),
        request(public, &[ApiKeyScope::InboxPush, ApiKeyScope::InboxPush]),
        request([0u8; 32], &[ApiKeyScope::InboxPush]),
        Issuance {
            relay_url: "not a url".into(),
            ..request(public, &[ApiKeyScope::InboxPush])
        },
        // A customer who does not exist yet cannot already hold a licence.
        Issuance {
            licence: LicenceRef::Existing(1),
            ..request(public, &[ApiKeyScope::InboxPush])
        },
    ];
    for request in &bad {
        assert!(issue(&s.conn, &s.identity, request, None).is_err());
    }
    assert_eq!(key_count(&s.conn), 0);
    assert_eq!(customer::count(&s.conn).expect("count"), 0);
}

#[test]
fn a_second_batch_under_an_existing_licence_adds_keys_to_it_and_only_for_its_own_customer() {
    let s = setup();
    let (_, public) = client();
    let first = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let more = Issuance {
        customer: CustomerRef::Existing(first.customer.id),
        licence: LicenceRef::Existing(first.licence.id),
        ..request(public, &[ApiKeyScope::DevicePush, ApiKeyScope::DevicePull])
    };
    let second = issue(&s.conn, &s.identity, &more, None).expect("issue more");
    assert_eq!(second.licence.id, first.licence.id);
    assert_eq!(
        licence::keys_of(&s.conn, first.licence.id)
            .expect("keys")
            .len(),
        3
    );
    assert_eq!(
        licence::list_for_customer(&s.conn, first.customer.id)
            .expect("list")
            .len(),
        1
    );

    // Another customer cannot be issued keys under this licence.
    let other = customer::create(
        &s.conn,
        &NewCustomer {
            name: "Beta".into(),
            reference: None,
        },
    )
    .expect("customer");
    let wrong = Issuance {
        customer: CustomerRef::Existing(other.id),
        licence: LicenceRef::Existing(first.licence.id),
        ..request(public, &[ApiKeyScope::InboxPull])
    };
    assert!(matches!(
        issue(&s.conn, &s.identity, &wrong, None),
        Err(Error::InvalidLicence)
    ));
    assert_eq!(
        licence::keys_of(&s.conn, first.licence.id)
            .expect("keys")
            .len(),
        3
    );
}

#[test]
fn nothing_is_issued_under_a_voided_or_missing_licence_or_customer() {
    let s = setup();
    let (_, public) = client();
    let first = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    void_licence(&s.conn, first.licence.id, None, None).expect("void");
    let before = key_count(&s.conn);
    let under = |customer: i64, licence: i64| Issuance {
        customer: CustomerRef::Existing(customer),
        licence: LicenceRef::Existing(licence),
        ..request(public, &[ApiKeyScope::InboxPull])
    };
    assert!(matches!(
        issue(
            &s.conn,
            &s.identity,
            &under(first.customer.id, first.licence.id),
            None
        ),
        Err(Error::LicenceNotActive)
    ));
    assert!(matches!(
        issue(&s.conn, &s.identity, &under(first.customer.id, 999), None),
        Err(Error::LicenceNotFound)
    ));
    assert!(matches!(
        issue(&s.conn, &s.identity, &under(999, first.licence.id), None),
        Err(Error::CustomerNotFound)
    ));
    assert_eq!(key_count(&s.conn), before);
}

#[test]
fn a_licence_that_replaces_another_voids_it_and_its_keys_in_the_same_unit_of_work() {
    let s = setup();
    let (_, public) = client();
    let old = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let replacement = Issuance {
        customer: CustomerRef::Existing(old.customer.id),
        licence: LicenceRef::New(NewLicence {
            replaces: Some(old.licence.id),
            ..terms(Some("2999-06-01"))
        }),
        ..request(public, &[ApiKeyScope::InboxPush])
    };
    let issued = issue(&s.conn, &s.identity, &replacement, None).expect("replace");
    assert_eq!(issued.licence.replaces_licence_id, Some(old.licence.id));
    let voided = issued.voided.expect("the old licence is voided");
    assert_eq!(
        (voided.licence_id, voided.newly_voided),
        (old.licence.id, true)
    );
    assert_eq!(voided.revoked_keys, vec![old.bundles[0].info.id]);
    assert!(relay::api_key_info(&s.conn, old.bundles[0].info.id)
        .expect("info")
        .revoked_at
        .is_some());
    assert!(relay::api_key_info(&s.conn, issued.bundles[0].info.id)
        .expect("info")
        .revoked_at
        .is_none());
    // Adding keys later to the replacement never voids the old one again.
    let later = Issuance {
        customer: CustomerRef::Existing(old.customer.id),
        licence: LicenceRef::Existing(issued.licence.id),
        ..request(public, &[ApiKeyScope::InboxPull])
    };
    assert!(issue(&s.conn, &s.identity, &later, None)
        .expect("more")
        .voided
        .is_none());
}

#[test]
fn a_failure_mid_issue_leaves_no_customer_no_licence_no_key_and_no_record() {
    let s = setup();
    let (_, public) = client();
    // Make the second key's insert fail, after the customer, the licence, its
    // statement and the first key were written inside the same unit of work.
    let dyn_conn: &dyn Sql = &s.conn;
    dyn_conn
        .execute_batch(
            "CREATE TRIGGER fail_second BEFORE INSERT ON api_keys
             WHEN (SELECT COUNT(*) FROM api_keys) >= 1
             BEGIN SELECT RAISE(ABORT, 'forced'); END",
        )
        .expect("trigger");
    let note = Note {
        operation_id: Some("op-forced-fail"),
        operator: "ops@example.test",
        action: "issue",
        subject: "Acme",
    };
    let issued = issue(
        &s.conn,
        &s.identity,
        &request(public, &[ApiKeyScope::InboxPush, ApiKeyScope::InboxPull]),
        Some(&note),
    );
    assert!(issued.is_err());
    assert_eq!(key_count(&s.conn), 0);
    assert_eq!(customer::count(&s.conn).expect("count"), 0);
    assert_eq!(
        licence::counts(&s.conn).expect("counts"),
        licence::Counts {
            active: 0,
            voided: 0,
            ended: 0
        }
    );
    assert!(relay::api_key_events(&s.conn).expect("events").is_empty());
    assert!(operator_log::find_operation(&s.conn, "op-forced-fail")
        .expect("find")
        .is_none());
}

#[test]
fn an_issue_records_its_operation_in_the_same_unit_and_the_same_id_cannot_issue_twice() {
    let s = setup();
    let (_, public) = client();
    let note = Note {
        operation_id: Some("op-0123456789"),
        operator: "ops@example.test",
        action: "issue",
        subject: "Acme",
    };
    let issued = issue(
        &s.conn,
        &s.identity,
        &request(public, &[ApiKeyScope::InboxPush]),
        Some(&note),
    )
    .expect("issue");
    let found = operator_log::find_operation(&s.conn, "op-0123456789")
        .expect("find")
        .expect("recorded");
    let result: serde_json::Value =
        serde_json::from_str(found.result.as_deref().expect("result")).expect("json");
    assert_eq!(result["customer_id"], issued.customer.id);
    assert_eq!(result["licence_id"], issued.licence.id);
    assert_eq!(
        result["key_ids"],
        serde_json::json!([issued.bundles[0].info.id])
    );
    assert!(
        !found.result.as_deref().unwrap_or("").contains("kq_"),
        "ids only"
    );

    // The same id again is refused whole: nothing more was made.
    let again = issue(
        &s.conn,
        &s.identity,
        &request(public, &[ApiKeyScope::InboxPull]),
        Some(&note),
    );
    assert!(again.is_err());
    assert_eq!(key_count(&s.conn), 1);
    assert_eq!(customer::count(&s.conn).expect("count"), 1);
}

#[test]
fn a_replacement_by_bundle_revokes_the_old_key_keeps_the_licence_and_recipient_and_links_the_lineage(
) {
    let s = setup();
    let (secret, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let old = &issued.bundles[0];
    let old_token = open(&s, &secret, &old.bundle).issue.token;
    let new = rotate(&s.conn, &s.identity, old.info.id, RotateVia::Bundle, None).expect("rotate");
    assert_ne!(new.info.id, old.info.id);
    assert!(relay::authenticate(&s.conn, old_token.as_str(), ApiKeyScope::InboxPush).is_err());
    let opened = open(&s, &secret, new.bundle.as_deref().expect("a bundle"));
    assert!(
        relay::authenticate(&s.conn, opened.issue.token.as_str(), ApiKeyScope::InboxPush).is_ok()
    );
    let link = licence::link_of_key(&s.conn, new.info.id)
        .expect("link")
        .expect("linked");
    assert_eq!(
        (link.licence_id, link.replaces_key_id),
        (issued.licence.id, Some(old.info.id))
    );
    assert_eq!(new.info.expires_at, old.info.expires_at);
    assert!(new.letter.is_none());
}

#[test]
fn a_replacement_carries_the_licences_current_statement_and_end_after_a_renewal() {
    let s = setup();
    let (secret, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let old = &issued.bundles[0];
    let renewed = renew_licence(
        &s.conn,
        issued.licence.id,
        Some("Ten seats."),
        Some("2999-09-09"),
        None,
    )
    .expect("renew");
    // The key already out keeps the end it was issued with.
    assert_eq!(
        relay::api_key_info(&s.conn, old.info.id)
            .expect("info")
            .expires_at,
        old.info.expires_at
    );
    let new = rotate(&s.conn, &s.identity, old.info.id, RotateVia::Bundle, None).expect("rotate");
    assert_eq!(new.info.expires_at, renewed.expires_at);
    assert_ne!(new.info.expires_at, old.info.expires_at);
    let statement = open(&s, &secret, new.bundle.as_deref().expect("bundle"))
        .issue
        .licence
        .expect("statement");
    assert!(statement.contains("(statement 2)") && statement.contains("Ten seats."));
    // The statement delivered the first time was never rewritten.
    let first = open(&s, &secret, &old.bundle)
        .issue
        .licence
        .expect("statement");
    assert!(first.contains("(statement 1)") && first.contains("Five seats."));
    let link = licence::link_of_key(&s.conn, new.info.id)
        .expect("link")
        .expect("linked");
    assert_eq!(link.licence_version, Some(2));
}

#[test]
fn a_replacement_by_letter_waits_in_the_customers_mailbox_and_the_old_key_ends_after_the_grace() {
    let s = setup();
    let (secret, public) = client();
    // An inbox.pull key can collect its own replacement.
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPull]);
    let old = &issued.bundles[0];
    let new = rotate(
        &s.conn,
        &s.identity,
        old.info.id,
        RotateVia::Letter {
            grace_seconds: 3600,
        },
        None,
    )
    .expect("rotate");
    assert!(new.bundle.is_none());
    let (letter_id, until) = new.letter.clone().expect("a letter");
    assert!(letter_id > 0 && until.is_some());
    let old_token = open(&s, &secret, &old.bundle).issue.token;
    assert!(
        relay::authenticate(&s.conn, old_token.as_str(), ApiKeyScope::InboxPull).is_ok(),
        "usable until the grace ends"
    );
    assert_eq!(
        relay::api_key_info(&s.conn, old.info.id)
            .expect("info")
            .expires_at,
        until
    );
    let link = licence::link_of_key(&s.conn, new.info.id)
        .expect("link")
        .expect("linked");
    assert_eq!(link.replaces_key_id, Some(old.info.id));

    // A push key cannot collect a letter: refused unless a live pull key for the
    // same recipient exists, and nothing changes when it is refused.
    let (_, other) = client();
    let push = issue_one(&s, other, &[ApiKeyScope::InboxPush]);
    let before = key_count(&s.conn);
    assert!(matches!(
        rotate(
            &s.conn,
            &s.identity,
            push.bundles[0].info.id,
            RotateVia::Letter {
                grace_seconds: 3600
            },
            None
        ),
        Err(Error::DeliveryNotCollectable)
    ));
    assert_eq!(key_count(&s.conn), before);
}

#[test]
fn the_grace_period_is_bounded_and_the_key_must_be_assigned_to_an_active_licence() {
    let s = setup();
    let (_, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPull]);
    let id = issued.bundles[0].info.id;
    for grace in [0, -1, MAX_GRACE_SECONDS + 1] {
        assert!(matches!(
            rotate(
                &s.conn,
                &s.identity,
                id,
                RotateVia::Letter {
                    grace_seconds: grace
                },
                None
            ),
            Err(Error::InvalidApiKeyRequest)
        ));
    }
    assert!(rotate(
        &s.conn,
        &s.identity,
        id,
        RotateVia::Letter {
            grace_seconds: MAX_GRACE_SECONDS
        },
        None
    )
    .is_ok());

    // A key issued some other way is unassigned: never guessed into a customer.
    let stray = relay::create_api_key(
        &s.conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: None,
        },
    )
    .expect("key");
    assert!(matches!(
        rotate(&s.conn, &s.identity, stray.info.id, RotateVia::Bundle, None),
        Err(Error::KeyNotAssigned)
    ));
    assert!(relay::api_key_info(&s.conn, stray.info.id)
        .expect("info")
        .revoked_at
        .is_none());
}

#[test]
fn a_rotation_under_a_voided_licence_is_refused_and_changes_nothing() {
    let s = setup();
    let (_, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let id = issued.bundles[0].info.id;
    void_licence(&s.conn, issued.licence.id, None, None).expect("void");
    let before = key_count(&s.conn);
    assert!(rotate(&s.conn, &s.identity, id, RotateVia::Bundle, None).is_err());
    assert_eq!(key_count(&s.conn), before);
}

#[test]
fn a_rotation_is_recorded_with_its_operation_and_the_same_id_does_not_rotate_twice() {
    let s = setup();
    let (_, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let id = issued.bundles[0].info.id;
    let note = Note {
        operation_id: Some("op-rotate-0001"),
        operator: "ops@example.test",
        action: "rotate",
        subject: "key",
    };
    let rotated = rotate(&s.conn, &s.identity, id, RotateVia::Bundle, Some(&note)).expect("rotate");
    let found = operator_log::find_operation(&s.conn, "op-rotate-0001")
        .expect("find")
        .expect("recorded");
    let result: serde_json::Value =
        serde_json::from_str(found.result.as_deref().expect("result")).expect("json");
    assert_eq!(
        (
            result["replaced_key_id"].as_i64(),
            result["key_id"].as_i64()
        ),
        (Some(id), Some(rotated.info.id))
    );
    let keys_now = key_count(&s.conn);
    assert!(rotate(
        &s.conn,
        &s.identity,
        rotated.info.id,
        RotateVia::Bundle,
        Some(&note)
    )
    .is_err());
    assert_eq!(key_count(&s.conn), keys_now);
    assert!(relay::api_key_info(&s.conn, rotated.info.id)
        .expect("info")
        .revoked_at
        .is_none());
}

#[test]
fn voiding_a_licence_revokes_its_live_keys_once_and_leaves_others_alone() {
    let s = setup();
    let (secret, public) = client();
    let issued = issue_one(
        &s,
        public,
        &[ApiKeyScope::InboxPush, ApiKeyScope::InboxPull],
    );
    let (_, other_public) = client();
    let other = issue_one(&s, other_public, &[ApiKeyScope::InboxPush]);
    let token = open(&s, &secret, &issued.bundles[0].bundle).issue.token;

    let voided = void_licence(&s.conn, issued.licence.id, Some("unpaid"), None).expect("void");
    assert!(voided.newly_voided);
    assert_eq!(
        voided.revoked_keys,
        issued.bundles.iter().map(|b| b.info.id).collect::<Vec<_>>()
    );
    assert!(relay::authenticate(&s.conn, token.as_str(), ApiKeyScope::InboxPush).is_err());
    assert!(relay::api_key_info(&s.conn, other.bundles[0].info.id)
        .expect("info")
        .revoked_at
        .is_none());
    let revoked: Vec<_> = relay::api_key_events(&s.conn)
        .expect("events")
        .into_iter()
        .filter(|e| e.event == "revoked")
        .collect();
    assert_eq!(revoked.len(), 2);
    assert!(revoked.iter().all(|e| e.actor == HOST_ACTOR));

    let again = void_licence(&s.conn, issued.licence.id, None, None).expect("void twice");
    assert!(!again.newly_voided && again.revoked_keys.is_empty());
    assert_eq!(
        relay::api_key_events(&s.conn)
            .expect("events")
            .iter()
            .filter(|e| e.event == "revoked")
            .count(),
        2
    );
    assert!(matches!(
        void_licence(&s.conn, 999, None, None),
        Err(Error::LicenceNotFound)
    ));
}

#[test]
fn a_renewal_adds_a_version_and_leaves_the_keys_already_out_alone() {
    let s = setup();
    let (_, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let key = relay::api_key_info(&s.conn, issued.bundles[0].info.id).expect("info");
    let note = Note {
        operation_id: Some("op-renew-0001"),
        operator: "ops@example.test",
        action: "renew_licence",
        subject: "licence",
    };
    let renewed = renew_licence(
        &s.conn,
        issued.licence.id,
        Some("Ten seats."),
        None,
        Some(&note),
    )
    .expect("renew");
    assert_eq!(renewed.version, 2);
    assert_eq!(
        relay::api_key_info(&s.conn, key.id)
            .expect("info")
            .expires_at,
        key.expires_at
    );
    assert_eq!(
        licence::versions(&s.conn, issued.licence.id)
            .expect("versions")
            .len(),
        2
    );
    assert!(operator_log::find_operation(&s.conn, "op-renew-0001")
        .expect("find")
        .is_some());
    // A refused renewal records nothing and adds no version.
    let bad = Note {
        operation_id: Some("op-renew-0002"),
        ..note
    };
    assert!(renew_licence(
        &s.conn,
        issued.licence.id,
        Some("Ten seats."),
        None,
        Some(&bad)
    )
    .is_err());
    assert!(operator_log::find_operation(&s.conn, "op-renew-0002")
        .expect("find")
        .is_none());
    assert_eq!(
        licence::versions(&s.conn, issued.licence.id)
            .expect("versions")
            .len(),
        2
    );
}

#[test]
fn an_unassigned_key_is_assigned_once_by_choice_and_only_a_client_key() {
    let s = setup();
    let (_, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let mint = |scope| {
        relay::create_api_key(
            &s.conn,
            &NewApiKey {
                scope,
                recipient_fingerprint: scope
                    .binds_recipient()
                    .then(|| keys::fingerprint(&[9u8; 32])),
                label: None,
                ttl_seconds: None,
            },
        )
        .expect("key")
        .info
        .id
    };
    let stray = mint(ApiKeyScope::InboxPull);
    assign_key(&s.conn, stray, issued.licence.id, None).expect("assign");
    let link = licence::link_of_key(&s.conn, stray)
        .expect("link")
        .expect("linked");
    assert_eq!(
        (link.licence_id, link.licence_version, link.replaces_key_id),
        (issued.licence.id, None, None)
    );
    // Never rewritten, never an operator key, never a missing key or licence.
    assert!(assign_key(&s.conn, stray, issued.licence.id, None).is_err());
    assert!(assign_key(&s.conn, issued.bundles[0].info.id, issued.licence.id, None).is_err());
    assert!(assign_key(&s.conn, mint(ApiKeyScope::Admin), issued.licence.id, None).is_err());
    assert!(matches!(
        assign_key(&s.conn, 999, issued.licence.id, None),
        Err(Error::ApiKeyNotFound)
    ));
    assert!(matches!(
        assign_key(&s.conn, mint(ApiKeyScope::InboxPush), 999, None),
        Err(Error::LicenceNotFound)
    ));
}

#[test]
fn a_key_is_not_assigned_to_a_voided_licence_and_stays_unassigned_and_live() {
    let s = setup();
    let (_, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let stray = relay::create_api_key(
        &s.conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: None,
        },
    )
    .expect("key");
    void_licence(&s.conn, issued.licence.id, Some("ended"), None).expect("void");

    // The void already ran, so nothing would revoke the key if it were linked
    // now: the assignment is refused and the key is left as it was.
    assert!(matches!(
        assign_key(&s.conn, stray.info.id, issued.licence.id, None),
        Err(Error::LicenceNotActive)
    ));
    assert!(licence::link_of_key(&s.conn, stray.info.id)
        .expect("link")
        .is_none());
    assert!(relay::authenticate(&s.conn, stray.token.as_str(), ApiKeyScope::InboxPush).is_ok());
}

#[test]
fn a_customer_is_recorded_with_its_operation_and_a_revoke_with_its_own() {
    let s = setup();
    let note = Note {
        operation_id: Some("op-customer-01"),
        operator: "ops@example.test",
        action: "create_customer",
        subject: "Acme",
    };
    let made = create_customer(
        &s.conn,
        &NewCustomer {
            name: "Acme".into(),
            reference: None,
        },
        Some(&note),
    )
    .expect("customer");
    let found = operator_log::find_operation(&s.conn, "op-customer-01")
        .expect("find")
        .expect("recorded");
    assert_eq!(
        found.result.as_deref(),
        Some(format!(r#"{{"customer_id":{}}}"#, made.id).as_str())
    );
    assert!(create_customer(
        &s.conn,
        &NewCustomer {
            name: "Other".into(),
            reference: None
        },
        Some(&note)
    )
    .is_err());
    assert_eq!(customer::count(&s.conn).expect("count"), 1);

    let (_, public) = client();
    let issued = issue_one(&s, public, &[ApiKeyScope::InboxPush]);
    let id = issued.bundles[0].info.id;
    let revoke = Note {
        operation_id: Some("op-revoke-0001"),
        operator: "ops@example.test",
        action: "void_key",
        subject: "key",
    };
    revoke_key(&s.conn, id, Some(&revoke)).expect("revoke");
    assert!(relay::api_key_info(&s.conn, id)
        .expect("info")
        .revoked_at
        .is_some());
    assert!(operator_log::find_operation(&s.conn, "op-revoke-0001")
        .expect("find")
        .is_some());
    assert!(matches!(
        revoke_key(&s.conn, 999, None),
        Err(Error::ApiKeyNotFound)
    ));
}
