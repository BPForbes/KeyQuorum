use super::super::test_helpers::*;
use super::{dispatch, ProviderIdentity};
use crate::error::{Error, Result};
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::{self, ApiKeyScope, NewApiKey, RelayHttpRequest, RelayHttpResponse};
use rusqlite::Connection;

/// The relay client talking to [`dispatch`] with no network in between,
/// the way the browser lab reaches its relay.
struct InProcess<'a> {
    conn: &'a Connection,
    identity: Option<&'a ProviderIdentity>,
}

impl relay::RelayTransport for InProcess<'_> {
    fn send(&self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        Ok(dispatch(self.conn, self.identity, &request))
    }
}

const URL: &str = "https://relay.example";

#[test]
fn client_round_trips_an_envelope_through_the_service() {
    let conn = relay::open_in_memory().expect("schema");
    let transport = InProcess {
        conn: &conn,
        identity: None,
    };
    let (envelope, fingerprint) = sample_envelope();
    let push = push_key(&conn);
    let pull = pull_key(&conn, &fingerprint);

    let accepted = relay::push_inbox(&transport, URL, &push, &envelope).expect("push");
    assert_eq!(accepted.recipient_fingerprint, fingerprint);
    let again = relay::push_inbox(&transport, URL, &push, &envelope).expect("duplicate push");
    assert_eq!(again.id, accepted.id);

    let listed = relay::pull_inbox(&transport, URL, &pull, None, None).expect("pull");
    assert_eq!(listed.envelopes.len(), 1);
    assert_eq!(listed.envelopes[0].id, accepted.id);

    let check = relay::check_key(&transport, URL, &pull).expect("keycheck");
    assert!(check.valid);
    assert_eq!(check.scope.as_deref(), Some("inbox.pull"));
}

#[test]
fn scopes_and_bearers_are_enforced_in_process_too() {
    let conn = relay::open_in_memory().expect("schema");
    let transport = InProcess {
        conn: &conn,
        identity: None,
    };
    let (envelope, fingerprint) = sample_envelope();
    let pull = pull_key(&conn, &fingerprint);

    // A pull key cannot push: 403, surfaced by the client as a relay error.
    match relay::push_inbox(&transport, URL, &pull, &envelope) {
        Err(Error::RelayRequest(message)) => assert!(message.starts_with("HTTP 403")),
        other => panic!("expected 403, got {other:?}"),
    }
    // An unknown bearer is 401.
    match relay::pull_inbox(&transport, URL, "kq_not-a-key", None, None) {
        Err(Error::RelayRequest(message)) => assert!(message.starts_with("HTTP 401")),
        other => panic!("expected 401, got {other:?}"),
    }
    // A device.pull key only sees its own fingerprint's letters.
    let device_pull = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::DevicePull,
            recipient_fingerprint: Some(fingerprint),
            label: None,
            ttl_seconds: None,
        },
    )
    .expect("device pull key")
    .token;
    let page = relay::pull_device_packages(&transport, URL, &device_pull, None, None)
        .expect("device pull");
    assert!(page.packages.is_empty());
}

#[test]
fn provider_identity_is_checked_by_the_client_against_its_root() {
    let conn = relay::open_in_memory().expect("schema");
    let issued = issued_identity("2099-01-01 00:00:00");
    let identity = ProviderIdentity {
        certificate: issued.certificate.clone(),
        relay_private_key: issued.relay_private.clone(),
    };
    let transport = InProcess {
        conn: &conn,
        identity: Some(&identity),
    };
    let cert = relay::authenticate_provider(
        &transport,
        URL,
        &issued.root_public,
        "2026-09-27 00:00",
        &empty_revoked(),
    )
    .expect("trusted relay");
    assert_eq!(cert.relay_public_key, issued.relay_public);

    // Another root does not trust it.
    let (_, other_root) = crate::keys::generate_signing_keypair();
    assert!(relay::authenticate_provider(
        &transport,
        URL,
        &other_root,
        "2026-09-27 00:00",
        &empty_revoked(),
    )
    .is_err());

    // No identity at all is an untrusted relay, not a transport failure.
    let bare = InProcess {
        conn: &conn,
        identity: None,
    };
    assert!(matches!(
        relay::authenticate_provider(
            &bare,
            URL,
            &issued.root_public,
            "2026-09-27 00:00",
            &empty_revoked(),
        ),
        Err(Error::UntrustedRelay)
    ));
}
