use super::*;
use crate::keys::generate_signing_keypair;
use crate::provider::test_helpers::{empty_revoked, issued_identity};

const NOW: &str = "2026-10-07 00:00:00";
const ISSUED: u64 = 1_000;
const EXPIRES: u64 = 2_000;

fn outer(magic: &[u8; 4], version: u8, kind: u8) -> Vec<u8> {
    let payload = [9u8; 40];
    let mut out = magic.to_vec();
    out.push(version);
    out.push(kind);
    out.extend_from_slice(&[7u8; 32]);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn key_bundle() -> Vec<u8> {
    outer(b"KQXB", 1, export::BUNDLE_TYPE_API_KEY)
}

fn key_letter() -> Vec<u8> {
    outer(b"KQPB", 2, envelope::KIND_API_KEY_ISSUE)
}

fn component(kind: ComponentKind, bytes: Vec<u8>) -> Component {
    Component { kind, bytes }
}

fn client_package(relay_public: [u8; 32], certificate: Vec<u8>) -> Package {
    Package {
        purpose: Purpose::ClientSetup,
        id: [3u8; 16],
        issued_at: ISSUED,
        expires_at: EXPIRES,
        issuer: relay_public,
        components: vec![
            component(ComponentKind::Certificate, certificate),
            component(ComponentKind::ApiKeyBundle, key_bundle()),
        ],
    }
}

#[test]
fn round_trips_a_client_setup_package() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let package = client_package(identity.relay_public, identity.certificate.clone());
    let bytes = encode(&package, &identity.relay_private).expect("encode");
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded, package);
    decoded.check_valid_at(1_500).expect("inside window");
    decoded
        .verify_issuer(&identity.root_public, NOW, &empty_revoked())
        .expect("issuer");
}

#[test]
fn any_changed_byte_is_refused() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let bytes = encode(
        &client_package(identity.relay_public, identity.certificate.clone()),
        &identity.relay_private,
    )
    .expect("encode");
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 0x01;
        assert!(decode(&changed).is_err(), "byte {index} changed");
    }
}

#[test]
fn truncated_trailing_and_oversized_input_is_refused() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let bytes = encode(
        &client_package(identity.relay_public, identity.certificate.clone()),
        &identity.relay_private,
    )
    .expect("encode");
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode(&[]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(decode(&longer).is_err());
    assert!(decode(&vec![0u8; MAX_PACKAGE_BYTES + 1]).is_err());
}

#[test]
fn a_changed_purpose_does_not_verify() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let mut bytes = encode(
        &client_package(identity.relay_public, identity.certificate.clone()),
        &identity.relay_private,
    )
    .expect("encode");
    bytes[5] = Purpose::ProviderRecovery.tag();
    assert!(matches!(decode(&bytes), Err(Error::InvalidKqpkg)));
}

#[test]
fn classify_names_only_what_version_one_handles() {
    let identity = issued_identity("2099-01-01 00:00:00");
    assert_eq!(
        classify(&identity.certificate).expect("kind"),
        ComponentKind::Certificate
    );
    assert_eq!(
        classify(&key_bundle()).expect("kind"),
        ComponentKind::ApiKeyBundle
    );
    assert_eq!(
        classify(&key_letter()).expect("kind"),
        ComponentKind::ApiKeyLetter
    );
    let refused: Vec<Vec<u8>> = vec![
        b"KQTF....".to_vec(),
        b"KQTX....".to_vec(),
        b"KQHS....".to_vec(),
        b"KQBS....".to_vec(),
        b"KQBN....".to_vec(),
        b"KQDV....".to_vec(),
        b"KQST....".to_vec(),
        b"KQPK....".to_vec(),
        b"\x00\x01\x02".to_vec(),
        outer(b"KQXB", 1, 1),
        outer(b"KQXB", 1, 2),
        outer(b"KQXB", 1, 3),
        outer(b"KQXB", 1, 5),
        outer(b"KQPB", 2, envelope::KIND_DEVICE_TRANSFER),
        outer(b"KQPB", 2, envelope::KIND_FILE_DELIVERY),
        outer(b"KQPB", 2, envelope::KIND_INVITE),
        outer(b"KQXB", 2, export::BUNDLE_TYPE_API_KEY),
    ];
    for (index, bytes) in refused.iter().enumerate() {
        assert!(
            matches!(classify(bytes), Err(Error::KqpkgComponentRejected)),
            "refused component {index} was classified"
        );
    }
}

#[test]
fn an_unsupported_component_stops_encoding_and_decoding() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let mut package = client_package(identity.relay_public, identity.certificate.clone());
    package
        .components
        .push(component(ComponentKind::ApiKeyLetter, b"KQTF....".to_vec()));
    assert!(matches!(
        encode(&package, &identity.relay_private),
        Err(Error::KqpkgComponentRejected)
    ));
}

#[test]
fn a_mislabelled_component_is_refused() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let mut package = client_package(identity.relay_public, identity.certificate.clone());
    package.components[1].kind = ComponentKind::ApiKeyLetter;
    assert!(matches!(
        encode(&package, &identity.relay_private),
        Err(Error::KqpkgComponentRejected)
    ));
}

#[test]
fn purposes_carry_only_their_own_components() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let mut info = Package {
        purpose: Purpose::ProviderInfo,
        components: vec![
            component(ComponentKind::Certificate, identity.certificate.clone()),
            component(ComponentKind::ApiKeyBundle, key_bundle()),
        ],
        ..client_package(identity.relay_public, identity.certificate.clone())
    };
    assert!(matches!(
        encode(&info, &identity.relay_private),
        Err(Error::KqpkgComponentRejected)
    ));
    info.components.pop();
    encode(&info, &identity.relay_private).expect("public info alone");

    let mut client = client_package(identity.relay_public, identity.certificate.clone());
    client.components.push(component(
        ComponentKind::RevocationList,
        b"KQRL....".to_vec(),
    ));
    assert!(matches!(
        encode(&client, &identity.relay_private),
        Err(Error::KqpkgComponentRejected)
    ));
}

#[test]
fn a_client_package_needs_a_certificate_and_a_key() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let mut no_key = client_package(identity.relay_public, identity.certificate.clone());
    no_key.components.pop();
    assert!(matches!(
        encode(&no_key, &identity.relay_private),
        Err(Error::KqpkgComponentRejected)
    ));
    let mut no_certificate = client_package(identity.relay_public, identity.certificate.clone());
    no_certificate.components.remove(0);
    assert!(matches!(
        encode(&no_certificate, &identity.relay_private),
        Err(Error::KqpkgComponentRejected)
    ));
    let mut two_certificates = client_package(identity.relay_public, identity.certificate.clone());
    two_certificates.components.push(component(
        ComponentKind::Certificate,
        identity.certificate.clone(),
    ));
    assert!(matches!(
        encode(&two_certificates, &identity.relay_private),
        Err(Error::KqpkgComponentRejected)
    ));
}

#[test]
fn too_many_components_are_refused() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let mut package = client_package(identity.relay_public, identity.certificate.clone());
    for _ in 0..MAX_COMPONENTS {
        package
            .components
            .push(component(ComponentKind::ApiKeyLetter, key_letter()));
    }
    assert!(matches!(
        encode(&package, &identity.relay_private),
        Err(Error::InvalidKqpkg)
    ));
}

#[test]
fn encode_refuses_a_key_that_is_not_the_issuer() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let (other_private, _) = generate_signing_keypair();
    let package = client_package(identity.relay_public, identity.certificate.clone());
    assert!(matches!(
        encode(&package, &other_private),
        Err(Error::InvalidKqpkg)
    ));
}

#[test]
fn the_validity_window_is_enforced() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let package = client_package(identity.relay_public, identity.certificate.clone());
    assert!(matches!(
        package.check_valid_at(ISSUED - 1),
        Err(Error::KqpkgExpired)
    ));
    package.check_valid_at(ISSUED).expect("start");
    assert!(matches!(
        package.check_valid_at(EXPIRES),
        Err(Error::KqpkgExpired)
    ));
    let mut backwards = package.clone();
    backwards.expires_at = backwards.issued_at;
    assert!(matches!(
        encode(&backwards, &identity.relay_private),
        Err(Error::InvalidKqpkg)
    ));
}

#[test]
fn a_relay_purpose_must_be_signed_by_the_certified_relay_key() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let (stranger_private, stranger_public) = generate_signing_keypair();
    let package = client_package(stranger_public, identity.certificate.clone());
    let bytes = encode(&package, &stranger_private).expect("signs under its own key");
    let decoded = decode(&bytes).expect("structurally valid");
    assert!(matches!(
        decoded.verify_issuer(&identity.root_public, NOW, &empty_revoked()),
        Err(Error::KqpkgIssuerUntrusted)
    ));
}

#[test]
fn a_certificate_from_another_root_does_not_verify() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let other = issued_identity("2099-01-01 00:00:00");
    let package = client_package(identity.relay_public, identity.certificate.clone());
    let decoded = decode(&encode(&package, &identity.relay_private).expect("encode")).expect("ok");
    assert!(decoded
        .verify_issuer(&other.root_public, NOW, &empty_revoked())
        .is_err());
}

#[test]
fn a_revoked_or_expired_certificate_does_not_verify() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let package = client_package(identity.relay_public, identity.certificate.clone());
    let decoded = decode(&encode(&package, &identity.relay_private).expect("encode")).expect("ok");
    let revoked: HashSet<String> = ["KQP-000184".to_string()].into();
    assert!(matches!(
        decoded.verify_issuer(&identity.root_public, NOW, &revoked),
        Err(Error::ProviderCertificateRevoked)
    ));
    assert!(decoded
        .verify_issuer(
            &identity.root_public,
            "2100-01-01 00:00:00",
            &empty_revoked()
        )
        .is_err());
}

#[test]
fn a_recovery_package_must_be_signed_by_the_root() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let (root_private, root_public) = generate_signing_keypair();
    let recovery = |issuer: [u8; 32]| Package {
        purpose: Purpose::ProviderRecovery,
        issuer,
        components: vec![component(
            ComponentKind::Certificate,
            identity.certificate.clone(),
        )],
        ..client_package(issuer, identity.certificate.clone())
    };
    let signed_by_root =
        decode(&encode(&recovery(root_public), &root_private).expect("encode")).expect("decode");
    signed_by_root
        .verify_issuer(&root_public, NOW, &empty_revoked())
        .expect("root-signed");
    let by_relay =
        decode(&encode(&recovery(identity.relay_public), &identity.relay_private).expect("encode"))
            .expect("decode");
    assert!(matches!(
        by_relay.verify_issuer(&root_public, NOW, &empty_revoked()),
        Err(Error::KqpkgIssuerUntrusted)
    ));
}

#[test]
fn issue_client_package_signs_the_relays_certificate_and_sealed_key() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let relay = crate::relay::ProviderIdentity {
        certificate: identity.certificate.clone(),
        relay_private_key: identity.relay_private.clone(),
    };
    let bytes = issue_client_package(&relay, &key_bundle(), ISSUED, 30).expect("issue");
    let package = decode(&bytes).expect("decode");
    assert_eq!(package.purpose, Purpose::ClientSetup);
    assert_eq!(package.expires_at, ISSUED + 30 * 86_400);
    assert_eq!(package.components.len(), 2);
    package
        .verify_issuer(&identity.root_public, NOW, &empty_revoked())
        .expect("issuer");
    let again = decode(&issue_client_package(&relay, &key_bundle(), ISSUED, 30).expect("issue"))
        .expect("decode");
    assert_ne!(package.id, again.id, "each package has its own id");
}

#[test]
fn issue_client_package_refuses_a_bad_window_or_an_unsupported_key() {
    let identity = issued_identity("2099-01-01 00:00:00");
    let relay = crate::relay::ProviderIdentity {
        certificate: identity.certificate.clone(),
        relay_private_key: identity.relay_private.clone(),
    };
    for days in [0, 366] {
        assert!(matches!(
            issue_client_package(&relay, &key_bundle(), ISSUED, days),
            Err(Error::InvalidKqpkg)
        ));
    }
    assert!(matches!(
        issue_client_package(&relay, b"KQTF....", ISSUED, 30),
        Err(Error::KqpkgComponentRejected)
    ));
}
