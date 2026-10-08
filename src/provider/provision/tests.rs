use super::*;
use crate::provider::{self, CAP_PROVIDER, KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY};

fn spec<'a>(expires_at: &'a str) -> Spec<'a> {
    Spec {
        provider_id: "Acme Security Services",
        serial: "KQP-000001",
        issued_at: "2026-10-08 00:00:00",
        expires_at,
        capabilities: CAP_PROVIDER,
        issuer_id: "KeyQuorumRoot",
    }
}

#[test]
fn the_identity_self_checks_under_its_own_root_and_under_no_other() {
    let made = provision(&spec("2099-01-01 00:00:00"), "2026-10-09 00:00:00").expect("provision");
    let checked = provider::self_check(
        &made.root_public_key,
        &made.certificate,
        &made.relay_private_key,
        "2026-10-09 00:00:00",
        &std::collections::HashSet::new(),
    )
    .expect("the certificate names the relay key and is signed by the root");
    assert_eq!(checked.provider_id, "Acme Security Services");
    assert_eq!(checked.serial, "KQP-000001");
    assert_eq!(checked.relay_public_key, made.relay_public_key);
    // The placeholder the repository ships never signs it.
    assert!(provider::verify_certificate(
        &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        &made.certificate,
        "2026-10-09 00:00:00",
        &std::collections::HashSet::new()
    )
    .is_err());
    // Two runs never share a key.
    let again = provision(&spec("2099-01-01 00:00:00"), "2026-10-09 00:00:00").expect("provision");
    assert_ne!(again.root_public_key, made.root_public_key);
    assert_ne!(again.relay_public_key, made.relay_public_key);
}

#[test]
fn the_package_is_the_public_provider_info_one_signed_by_the_relay() {
    let made = provision(&spec("2099-01-01 00:00:00"), "2026-10-09 00:00:00").expect("provision");
    let package = crate::package::decode(&made.package).expect("decode");
    assert_eq!(package.purpose, crate::package::Purpose::ProviderInfo);
    assert_eq!(package.issuer, made.relay_public_key);
    assert_eq!(
        package.expires_at - package.issued_at,
        PACKAGE_VALID_DAYS * 24 * 60 * 60
    );
}

#[test]
fn a_certificate_that_would_already_be_expired_is_refused() {
    assert!(matches!(
        provision(&spec("2020-01-01 00:00:00"), "2026-10-09 00:00:00"),
        Err(crate::error::Error::ProviderCertificateExpired)
    ));
}
