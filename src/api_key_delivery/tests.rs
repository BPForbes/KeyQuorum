use super::{carrier_of, open, seal_bundle, seal_letter, sign, Carrier, KeyIssue};
use crate::envelope;
use crate::error::Error;
use crate::keys;
use crate::provider::{self, NewCertificate, CAP_PROVIDER};
use crate::relay::ProviderIdentity;
use crate::test_secrets;
use std::collections::HashSet;
use zeroize::Zeroizing;

const NOW: &str = "2026-10-04 12:00:00";
const RELAY_URL: &str = "https://relay.example.test";

struct Relay {
    root_public: [u8; 32],
    identity: ProviderIdentity,
}

fn test_relay(serial: &str, expires_at: &str) -> Relay {
    let (root_private, root_public) = keys::generate_signing_keypair();
    let (relay_private, relay_public) = provider::generate_relay_identity();
    let certificate = provider::issue_certificate(
        &root_private,
        &NewCertificate {
            provider_id: "Test relay",
            serial,
            relay_public_key: &relay_public,
            issued_at: "2026-01-01 00:00:00",
            expires_at,
            capabilities: CAP_PROVIDER,
            issuer_id: "TestRoot",
        },
    )
    .expect("issue_certificate should sign a well-formed certificate");
    Relay {
        root_public,
        identity: ProviderIdentity {
            certificate,
            relay_private_key: relay_private,
        },
    }
}

fn issue(relay: &Relay) -> KeyIssue {
    KeyIssue {
        relay_url: RELAY_URL.to_string(),
        key_id: 7,
        scope: "inbox.pull".to_string(),
        token: Zeroizing::new(format!("kq_{}", test_secrets::passphrase())),
        issued_at: NOW.to_string(),
        expires_at: Some("2026-10-11 12:00:00".to_string()),
        device_id: Some([9u8; 16]),
        certificate: relay.identity.certificate.clone(),
        licence: Some("One pull key for one device until renewed.".to_string()),
    }
}

fn none() -> HashSet<String> {
    HashSet::new()
}

#[test]
fn a_letter_and_a_bundle_round_trip_for_their_recipient() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (secret, public) = keys::generate_encryption_keypair();
    let wanted = issue(&relay);

    let letter = seal_letter(&relay.identity, &public, &wanted).expect("seal_letter");
    let bundle = seal_bundle(&relay.identity, &public, &wanted).expect("seal_bundle");
    assert_eq!(carrier_of(&letter), Some(Carrier::Letter));
    assert_eq!(carrier_of(&bundle), Some(Carrier::Bundle));
    assert_eq!(
        envelope::kind(&letter).unwrap(),
        envelope::KIND_API_KEY_ISSUE
    );
    assert!(bundle.starts_with(b"KQXB"));

    for (bytes, carrier) in [(&letter, Carrier::Letter), (&bundle, Carrier::Bundle)] {
        let opened = open(bytes, &secret, &relay.root_public, NOW, &none())
            .expect("open should accept an issue sealed to this key");
        assert_eq!(opened.carrier, carrier);
        assert_eq!(opened.recipient_public_key, public);
        assert_eq!(opened.certificate.serial, "R-1");
        let got = &opened.issue;
        assert_eq!(got.relay_url, wanted.relay_url);
        assert_eq!(got.key_id, wanted.key_id);
        assert_eq!(got.scope, wanted.scope);
        assert_eq!(got.token.as_str(), wanted.token.as_str());
        assert_eq!(got.issued_at, wanted.issued_at);
        assert_eq!(got.expires_at, wanted.expires_at);
        assert_eq!(got.device_id, wanted.device_id);
        assert_eq!(got.certificate, wanted.certificate);
        assert_eq!(got.licence, wanted.licence);
    }
}

#[test]
fn optional_fields_may_be_absent() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (secret, public) = keys::generate_encryption_keypair();
    let mut wanted = issue(&relay);
    wanted.expires_at = None;
    wanted.device_id = None;
    wanted.licence = None;
    let letter = seal_letter(&relay.identity, &public, &wanted).expect("seal_letter");
    let opened = open(&letter, &secret, &relay.root_public, NOW, &none()).expect("open");
    assert_eq!(opened.issue.expires_at, None);
    assert_eq!(opened.issue.device_id, None);
    assert_eq!(opened.issue.licence, None);
}

#[test]
fn only_the_recipient_opens_it() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (_, public) = keys::generate_encryption_keypair();
    let (other_secret, _) = keys::generate_encryption_keypair();
    let letter = seal_letter(&relay.identity, &public, &issue(&relay)).expect("seal_letter");
    assert!(matches!(
        open(&letter, &other_secret, &relay.root_public, NOW, &none()),
        Err(Error::InvalidKeyIssue)
    ));
}

#[test]
fn a_payload_resealed_to_another_key_fails_the_signature() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (_, public) = keys::generate_encryption_keypair();
    let (other_secret, other_public) = keys::generate_encryption_keypair();
    let payload = sign(&relay.identity, &public, &issue(&relay)).expect("sign");
    // Someone who could read the payload re-seals it for another key: the
    // signature still names the first recipient, so the second is refused.
    let resealed = envelope::seal(
        envelope::PACKAGE,
        envelope::KIND_API_KEY_ISSUE,
        &other_public,
        &payload,
    )
    .expect("seal");
    assert!(matches!(
        open(&resealed, &other_secret, &relay.root_public, NOW, &none()),
        Err(Error::InvalidKeyIssue)
    ));
}

#[test]
fn a_changed_field_fails_the_signature() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (secret, public) = keys::generate_encryption_keypair();
    let mut payload = sign(&relay.identity, &public, &issue(&relay)).expect("sign");
    // version (1) | url len (2) | url | key_id (8): flip the key id.
    let key_id_at = 1 + 2 + RELAY_URL.len() + 7;
    payload[key_id_at] ^= 0x01;
    let letter = envelope::seal(
        envelope::PACKAGE,
        envelope::KIND_API_KEY_ISSUE,
        &public,
        &payload,
    )
    .expect("seal");
    assert!(matches!(
        open(&letter, &secret, &relay.root_public, NOW, &none()),
        Err(Error::InvalidKeyIssue)
    ));
}

#[test]
fn the_certificate_must_be_the_signing_relays_own() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let other = test_relay("R-2", "2999-01-01 00:00:00");
    let (_, public) = keys::generate_encryption_keypair();
    let mut wanted = issue(&relay);
    wanted.certificate = other.identity.certificate.clone();
    assert!(matches!(
        sign(&relay.identity, &public, &wanted),
        Err(Error::InvalidKeyIssue)
    ));
}

#[test]
fn an_untrusted_revoked_or_expired_certificate_is_refused() {
    let relay = test_relay("R-1", "2026-12-31 00:00:00");
    let (secret, public) = keys::generate_encryption_keypair();
    let letter = seal_letter(&relay.identity, &public, &issue(&relay)).expect("seal_letter");

    let other_root = test_relay("R-9", "2999-01-01 00:00:00").root_public;
    assert!(matches!(
        open(&letter, &secret, &other_root, NOW, &none()),
        Err(Error::InvalidProviderCertificate)
    ));

    let revoked: HashSet<String> = ["R-1".to_string()].into_iter().collect();
    assert!(matches!(
        open(&letter, &secret, &relay.root_public, NOW, &revoked),
        Err(Error::ProviderCertificateRevoked)
    ));

    assert!(matches!(
        open(
            &letter,
            &secret,
            &relay.root_public,
            "2027-01-01 00:00:00",
            &none()
        ),
        Err(Error::ProviderCertificateExpired)
    ));
}

#[test]
fn an_expired_issue_is_refused_and_a_live_one_is_not() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (secret, public) = keys::generate_encryption_keypair();
    let mut wanted = issue(&relay);
    wanted.expires_at = Some("2026-10-05 00:00:00".to_string());
    let letter = seal_letter(&relay.identity, &public, &wanted).expect("seal_letter");
    assert!(open(
        &letter,
        &secret,
        &relay.root_public,
        "2026-10-04 23:59:59",
        &none()
    )
    .is_ok());
    assert!(matches!(
        open(
            &letter,
            &secret,
            &relay.root_public,
            "2026-10-05 00:00:00",
            &none()
        ),
        Err(Error::KeyIssueExpired)
    ));
}

#[test]
fn other_letters_and_bundles_are_not_issues() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (secret, public) = keys::generate_encryption_keypair();
    let payload = sign(&relay.identity, &public, &issue(&relay)).expect("sign");
    let other_kind = envelope::seal(
        envelope::PACKAGE,
        envelope::KIND_FILE_REQUEST,
        &public,
        &payload,
    )
    .expect("seal");
    let other_bundle = envelope::seal(envelope::EXPORT_BUNDLE, 1, &public, &payload).expect("seal");
    for bytes in [&other_kind, &other_bundle] {
        assert_eq!(carrier_of(bytes), None);
        assert!(matches!(
            open(bytes, &secret, &relay.root_public, NOW, &none()),
            Err(Error::InvalidKeyIssue)
        ));
    }
    assert_eq!(carrier_of(b"KQ"), None);
    assert!(matches!(
        open(b"not a letter", &secret, &relay.root_public, NOW, &none()),
        Err(Error::InvalidKeyIssue)
    ));
}

#[test]
fn a_licence_past_the_limit_is_refused() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (_, public) = keys::generate_encryption_keypair();
    let mut wanted = issue(&relay);
    wanted.licence = Some("x".repeat(super::MAX_LICENCE_BYTES + 1));
    assert!(matches!(
        sign(&relay.identity, &public, &wanted),
        Err(Error::BundleFieldTooLarge)
    ));
}

#[test]
fn neither_debug_nor_the_sealed_bytes_show_the_bearer() {
    let relay = test_relay("R-1", "2999-01-01 00:00:00");
    let (_, public) = keys::generate_encryption_keypair();
    let wanted = issue(&relay);
    let shown = format!("{wanted:?}");
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains(wanted.token.as_str()));
    let letter = seal_letter(&relay.identity, &public, &wanted).expect("seal_letter");
    let bundle = seal_bundle(&relay.identity, &public, &wanted).expect("seal_bundle");
    let token = wanted.token.as_bytes();
    for bytes in [&letter, &bundle] {
        assert!(!bytes.windows(token.len()).any(|w| w == token));
    }
}
