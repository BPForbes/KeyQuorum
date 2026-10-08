use super::*;
use crate::envelope::{self, push_len_prefixed_u32};
use crate::keys::{generate_encryption_keypair, generate_signing_keypair};
use crate::provider::provision::{provision, Identity, Spec};
use crate::provider::CAP_PROVIDER;
use std::path::Path;

const NOW: &str = "2026-10-08 00:00:00";

fn identity() -> Identity {
    provision(
        &Spec {
            provider_id: "Acme Security Services",
            serial: "KQP-000184",
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2099-01-01 00:00:00",
            capabilities: CAP_PROVIDER,
            issuer_id: "KeyQuorumRoot",
        },
        NOW,
    )
    .expect("provision")
}

fn none() -> HashSet<String> {
    HashSet::new()
}

struct Fixture {
    made: Identity,
    operator_secret: Zeroizing<[u8; 32]>,
    operator_public: [u8; 32],
    package: Vec<u8>,
}

fn fixture() -> Fixture {
    let made = identity();
    let (operator_secret, operator_public) = generate_encryption_keypair();
    let package = issue(&Issue {
        root_private_key: &made.root_private_key,
        relay_private_key: &made.relay_private_key,
        certificate: &made.certificate,
        recipient: &operator_public,
        now_utc: NOW,
        valid_days: 1,
        revoked: &none(),
    })
    .expect("issue");
    Fixture {
        made,
        operator_secret,
        operator_public,
        package,
    }
}

fn open_fixture(f: &Fixture) -> Result<Recovered> {
    open(
        &f.package,
        &f.operator_secret,
        &f.made.root_public_key,
        NOW,
        &none(),
    )
}

/// The context `issue` would sign for `f`, to change one field of.
fn context_of(f: &Fixture, package_id: [u8; 16]) -> Context {
    Context {
        version: VERSION,
        purpose: PURPOSE.to_string(),
        package_id: hex::encode(package_id),
        recipient: hex::encode(f.operator_public),
        provider_id: "Acme Security Services".to_string(),
        serial: "KQP-000184".to_string(),
        relay_public_key: hex::encode(f.made.relay_public_key),
        certificate_sha256: sha256_hex(&f.made.certificate),
        issued_at: super::super::unix_from_utc(NOW).expect("time"),
        expires_at: super::super::unix_from_utc(NOW).expect("time") + 86_400,
        operations: OPERATIONS.to_vec(),
    }
}

/// A root-signed recovery package around `payload`, for the refusal tests.
fn package_around(f: &Fixture, id: [u8; 16], payload: Vec<u8>) -> Vec<u8> {
    let issued_at = super::super::unix_from_utc(NOW).expect("time");
    package::encode(
        &Package {
            purpose: Purpose::ProviderRecovery,
            id,
            issued_at,
            expires_at: issued_at + 86_400,
            issuer: f.made.root_public_key,
            components: vec![
                Component {
                    kind: ComponentKind::Certificate,
                    bytes: f.made.certificate.clone(),
                },
                Component {
                    kind: ComponentKind::RecoveryPayload,
                    bytes: payload,
                },
            ],
        },
        &f.made.root_private_key,
    )
    .expect("encode")
}

/// Seals raw context bytes, so a test can sign a context `Context` cannot
/// express (an unknown operation or field).
fn seal_raw(f: &Fixture, json: &[u8], relay_key: &[u8; 32]) -> Vec<u8> {
    let signature = signing::sign(
        &f.made.root_private_key,
        &signing::provider_recovery_preimage(json),
    );
    let mut payload = Vec::new();
    push_len_prefixed_u32(&mut payload, json).expect("len");
    payload.extend_from_slice(relay_key);
    payload.extend_from_slice(&signature);
    envelope::seal(
        envelope::EXPORT_BUNDLE,
        BUNDLE_TYPE_PROVIDER_RECOVERY,
        &f.operator_public,
        &payload,
    )
    .expect("seal")
}

fn is_refused(result: &Result<Recovered>) -> bool {
    matches!(result, Err(Error::KqpkgRefused(_)))
}

#[test]
fn a_recovery_package_opens_with_the_operator_key_and_pinned_root() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open recovery package");
    assert_eq!(recovered.relay_public_key, f.made.relay_public_key);
    assert_eq!(
        recovered.relay_private_key[..],
        f.made.relay_private_key[..]
    );
    assert_eq!(recovered.certificate, f.made.certificate);
    assert_eq!(recovered.provider_id, "Acme Security Services");
    let shown = format!("{recovered:?}");
    assert!(shown.contains("[redacted]"));
    assert!(!shown.contains(&hex::encode(&f.made.relay_private_key[..])));
}

#[test]
fn the_payload_never_holds_the_root_key_in_the_clear_or_sealed() {
    let f = fixture();
    let decoded = package::decode(&f.package).expect("decode");
    let sealed = &decoded
        .components
        .iter()
        .find(|c| c.kind == ComponentKind::RecoveryPayload)
        .expect("payload")
        .bytes;
    let (_, _, plaintext) =
        envelope::open_as(envelope::EXPORT_BUNDLE, sealed, &f.operator_secret).expect("open");
    let root = &f.made.root_private_key[..];
    assert!(!plaintext.windows(32).any(|w| w == root));
    assert!(!f.package.windows(32).any(|w| w == root));
    let relay = &f.made.relay_private_key[..];
    assert!(!f.package.windows(32).any(|w| w == relay));
}

#[test]
fn another_operator_key_cannot_open_it() {
    let f = fixture();
    let (other, _) = generate_encryption_keypair();
    assert!(is_refused(&open(
        &f.package,
        &other,
        &f.made.root_public_key,
        NOW,
        &none()
    )));
}

#[test]
fn a_root_other_than_the_pinned_one_is_refused() {
    let f = fixture();
    let (_, other_root) = generate_signing_keypair();
    assert!(matches!(
        open(&f.package, &f.operator_secret, &other_root, NOW, &none()),
        Err(Error::KqpkgIssuerUntrusted)
    ));
}

#[test]
fn a_changed_byte_is_refused() {
    let f = fixture();
    let mut bytes = f.package.clone();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    assert!(open(
        &bytes,
        &f.operator_secret,
        &f.made.root_public_key,
        NOW,
        &none()
    )
    .is_err());
}

#[test]
fn an_expired_package_or_a_revoked_certificate_is_refused() {
    let f = fixture();
    assert!(matches!(
        open(
            &f.package,
            &f.operator_secret,
            &f.made.root_public_key,
            "2026-10-10 00:00:00",
            &none()
        ),
        Err(Error::KqpkgExpired)
    ));
    let revoked: HashSet<String> = ["KQP-000184".to_string()].into();
    assert!(matches!(
        open(
            &f.package,
            &f.operator_secret,
            &f.made.root_public_key,
            NOW,
            &revoked
        ),
        Err(Error::ProviderCertificateRevoked)
    ));
    assert!(issue(&Issue {
        root_private_key: &f.made.root_private_key,
        relay_private_key: &f.made.relay_private_key,
        certificate: &f.made.certificate,
        recipient: &f.operator_public,
        now_utc: NOW,
        valid_days: 1,
        revoked: &revoked,
    })
    .is_err());
}

#[test]
fn issue_refuses_a_key_that_is_not_the_certificates_and_a_long_lifetime() {
    let f = fixture();
    let (other_relay, _) = crate::provider::generate_relay_identity();
    let revoked = none();
    let spec = |relay, valid_days| Issue {
        root_private_key: &f.made.root_private_key,
        relay_private_key: relay,
        certificate: &f.made.certificate,
        recipient: &f.operator_public,
        now_utc: NOW,
        valid_days,
        revoked: &revoked,
    };
    assert!(matches!(
        issue(&spec(&other_relay, 1)),
        Err(Error::RelayIdentityMismatch)
    ));
    assert!(issue(&spec(&f.made.relay_private_key, MAX_VALID_DAYS + 1)).is_err());
    assert!(issue(&spec(&f.made.relay_private_key, 0)).is_err());
}

#[test]
fn a_secret_that_is_not_the_certificates_key_is_refused() {
    let f = fixture();
    let id = [7u8; 16];
    let (other_relay, _) = crate::provider::generate_relay_identity();
    let payload = seal_context(
        &f.made.root_private_key,
        &f.operator_public,
        &context_of(&f, id),
        &other_relay,
    )
    .expect("seal");
    let bytes = package_around(&f, id, payload);
    assert!(matches!(
        open(
            &bytes,
            &f.operator_secret,
            &f.made.root_public_key,
            NOW,
            &none()
        ),
        Err(Error::RelayIdentityMismatch)
    ));
}

#[test]
fn a_context_that_does_not_match_the_package_is_refused() {
    let f = fixture();
    let id = [7u8; 16];
    let changes: Vec<fn(&mut Context)> = vec![
        |c| c.package_id = hex::encode([8u8; 16]),
        |c| c.purpose = "client_setup".to_string(),
        |c| c.recipient = hex::encode([9u8; 32]),
        |c| c.relay_public_key = hex::encode([9u8; 32]),
        |c| c.certificate_sha256 = hex::encode([0u8; 32]),
        |c| c.provider_id = "Someone Else".to_string(),
        |c| c.expires_at += 1,
        |c| c.version = 2,
    ];
    for change in changes {
        let mut context = context_of(&f, id);
        change(&mut context);
        let payload = seal_context(
            &f.made.root_private_key,
            &f.operator_public,
            &context,
            &f.made.relay_private_key,
        )
        .expect("seal");
        let bytes = package_around(&f, id, payload);
        assert!(is_refused(&open(
            &bytes,
            &f.operator_secret,
            &f.made.root_public_key,
            NOW,
            &none()
        )));
    }
    // The unchanged context opens, so each refusal above is its one change.
    let payload = seal_context(
        &f.made.root_private_key,
        &f.operator_public,
        &context_of(&f, id),
        &f.made.relay_private_key,
    )
    .expect("seal");
    open(
        &package_around(&f, id, payload),
        &f.operator_secret,
        &f.made.root_public_key,
        NOW,
        &none(),
    )
    .expect("open the unchanged recovery context");
}

#[test]
fn a_context_signed_by_another_key_is_refused() {
    let f = fixture();
    let id = [7u8; 16];
    let (other_root, _) = generate_signing_keypair();
    let payload = seal_context(
        &other_root,
        &f.operator_public,
        &context_of(&f, id),
        &f.made.relay_private_key,
    )
    .expect("seal");
    assert!(is_refused(&open(
        &package_around(&f, id, payload),
        &f.operator_secret,
        &f.made.root_public_key,
        NOW,
        &none()
    )));
}

#[test]
fn unsupported_or_unknown_operations_are_refused() {
    let f = fixture();
    let id = [7u8; 16];
    let mut fewer = context_of(&f, id);
    fewer.operations = vec![Operation::InstallRelayKey];
    let mut twice = context_of(&f, id);
    twice.operations = vec![
        Operation::InstallRelayKey,
        Operation::InstallCertificate,
        Operation::InstallCertificate,
    ];
    for context in [fewer, twice] {
        let payload = seal_context(
            &f.made.root_private_key,
            &f.operator_public,
            &context,
            &f.made.relay_private_key,
        )
        .expect("seal");
        assert!(is_refused(&open(
            &package_around(&f, id, payload),
            &f.operator_secret,
            &f.made.root_public_key,
            NOW,
            &none()
        )));
    }
    let mut json = serde_json::to_value(context_of(&f, id)).expect("json");
    json["operations"] = serde_json::json!([{"op": "install_relay_key"}, {"op": "run_shell"}]);
    let unknown_op = serde_json::to_vec(&json).expect("json");
    let mut json = serde_json::to_value(context_of(&f, id)).expect("json");
    json["deploy"] = serde_json::json!(true);
    let unknown_field = serde_json::to_vec(&json).expect("json");
    for raw in [unknown_op, unknown_field] {
        let payload = seal_raw(&f, &raw, &f.made.relay_private_key);
        assert!(is_refused(&open(
            &package_around(&f, id, payload),
            &f.operator_secret,
            &f.made.root_public_key,
            NOW,
            &none()
        )));
    }
}

#[test]
fn purposes_are_not_confused() {
    let f = fixture();
    // A provider information package is never opened as recovery.
    let info = f.made.package.clone();
    assert!(is_refused(&open(
        &info,
        &f.operator_secret,
        &f.made.root_public_key,
        NOW,
        &none()
    )));
    // A recovery payload is refused in any other purpose.
    let payload = package::decode(&f.package)
        .expect("decode")
        .components
        .into_iter()
        .find(|c| c.kind == ComponentKind::RecoveryPayload)
        .expect("payload");
    for purpose in [
        Purpose::ProviderInfo,
        Purpose::ClientSetup,
        Purpose::ClientUpdate,
    ] {
        let issued_at = super::super::unix_from_utc(NOW).expect("time");
        let result = package::encode(
            &Package {
                purpose,
                id: [1; 16],
                issued_at,
                expires_at: issued_at + 60,
                issuer: f.made.relay_public_key,
                components: vec![
                    Component {
                        kind: ComponentKind::Certificate,
                        bytes: f.made.certificate.clone(),
                    },
                    payload.clone(),
                ],
            },
            &f.made.relay_private_key,
        );
        assert!(matches!(result, Err(Error::KqpkgComponentRejected)));
    }
    // A recovery package without its payload is refused.
    let issued_at = super::super::unix_from_utc(NOW).expect("time");
    let bare = package::encode(
        &Package {
            purpose: Purpose::ProviderRecovery,
            id: [1; 16],
            issued_at,
            expires_at: issued_at + 60,
            issuer: f.made.root_public_key,
            components: vec![Component {
                kind: ComponentKind::Certificate,
                bytes: f.made.certificate.clone(),
            }],
        },
        &f.made.root_private_key,
    );
    assert!(matches!(bare, Err(Error::KqpkgComponentRejected)));
}

#[test]
fn the_fingerprint_is_compared_without_spaces_or_case() {
    let (_, public) = generate_encryption_keypair();
    let fingerprint = recipient_fingerprint(&public);
    assert_eq!(fingerprint.split(' ').count(), 8);
    assert!(fingerprint_matches(&public, &fingerprint.to_uppercase()));
    assert!(fingerprint_matches(&public, &fingerprint.replace(' ', "")));
    let (_, other) = generate_encryption_keypair();
    assert!(!fingerprint_matches(&other, &fingerprint));
}

// --- installation -------------------------------------------------------

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("meta").permissions().mode() & 0o777
}

#[cfg(unix)]
fn owner_only_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(path).expect("dir");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
}

fn install_into(f: &Fixture, recovered: &Recovered, dir: &Path) -> Result<InstallPlan> {
    let plan = plan_install(dir, recovered)?;
    install(&plan, recovered, &f.made.root_public_key, NOW, &none())?;
    Ok(plan)
}

#[cfg(unix)]
#[test]
fn install_writes_an_owner_only_identity_the_relay_accepts_and_a_rerun_keeps_it() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open");
    let parent = tempfile::tempdir().expect("tmp");
    let dir = parent.path().join("relay-identity");
    let plan = install_into(&f, &recovered, &dir).expect("install recovered identity");
    assert!(plan.create_dir);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join(RELAY_KEY_FILE)), 0o600);
    assert_eq!(mode(&dir.join(CERTIFICATE_FILE)), 0o600);
    let key = crate::keys::parse_key_32(
        &std::fs::read_to_string(dir.join(RELAY_KEY_FILE)).expect("read key"),
    )
    .expect("parse key");
    crate::provider::self_check(
        &f.made.root_public_key,
        &std::fs::read(dir.join(CERTIFICATE_FILE)).expect("cert"),
        &key,
        NOW,
        &none(),
    )
    .expect("the relay accepts the installed identity");
    let again = plan_install(&dir, &recovered).expect("plan again");
    assert!(again.complete());
    install(&again, &recovered, &f.made.root_public_key, NOW, &none())
        .expect("a rerun keeps the same files");
    let names: Vec<_> = std::fs::read_dir(&dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(names.len(), 2);
}

#[cfg(unix)]
#[test]
fn a_different_file_at_the_destination_is_refused_and_left_alone() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open");
    let parent = tempfile::tempdir().expect("tmp");
    let dir = parent.path().join("relay-identity");
    owner_only_dir(&dir);
    std::fs::write(dir.join(RELAY_KEY_FILE), "00".repeat(32)).expect("write");
    assert!(matches!(
        plan_install(&dir, &recovered),
        Err(Error::KqpkgRefused(_))
    ));
    assert_eq!(
        std::fs::read_to_string(dir.join(RELAY_KEY_FILE)).expect("read"),
        "00".repeat(32)
    );
    assert!(!dir.join(CERTIFICATE_FILE).exists());
    let other = parent.path().join("other");
    owner_only_dir(&other);
    std::fs::write(other.join(CERTIFICATE_FILE), b"not this one").expect("write");
    assert!(matches!(
        plan_install(&other, &recovered),
        Err(Error::KqpkgRefused(_))
    ));
}

#[cfg(unix)]
#[test]
fn a_linked_or_shared_destination_is_refused() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open");
    let parent = tempfile::tempdir().expect("tmp");
    let real = parent.path().join("real");
    owner_only_dir(&real);
    let link = parent.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    assert!(matches!(
        plan_install(&link, &recovered),
        Err(Error::KqpkgRefused(_))
    ));
    let shared = parent.path().join("shared");
    std::fs::create_dir(&shared).expect("dir");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert!(matches!(
        plan_install(&shared, &recovered),
        Err(Error::KqpkgRefused(_))
    ));
    // A link where a file would go is not followed.
    let dir = parent.path().join("dir");
    owner_only_dir(&dir);
    std::os::unix::fs::symlink(parent.path().join("elsewhere"), dir.join(RELAY_KEY_FILE))
        .expect("symlink");
    assert!(matches!(
        plan_install(&dir, &recovered),
        Err(Error::KqpkgRefused(_))
    ));
    assert!(!parent.path().join("elsewhere").exists());
    // A parent that does not exist is not created.
    assert!(plan_install(&parent.path().join("missing/dir"), &recovered).is_err());
}

#[cfg(unix)]
#[test]
fn a_directory_swapped_after_the_plan_is_refused() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open");
    let parent = tempfile::tempdir().expect("tmp");
    let dir = parent.path().join("relay-identity");
    owner_only_dir(&dir);
    let plan = plan_install(&dir, &recovered).expect("plan");
    std::fs::rename(&dir, parent.path().join("moved")).expect("move");
    owner_only_dir(&dir);
    assert!(matches!(
        install(&plan, &recovered, &f.made.root_public_key, NOW, &none()),
        Err(Error::KqpkgRefused(_))
    ));
    assert_eq!(std::fs::read_dir(&dir).expect("list").count(), 0);
    // A directory made after a plan to create one is refused too.
    let fresh = parent.path().join("fresh");
    let plan = plan_install(&fresh, &recovered).expect("plan");
    owner_only_dir(&fresh);
    assert!(matches!(
        install(&plan, &recovered, &f.made.root_public_key, NOW, &none()),
        Err(Error::KqpkgRefused(_))
    ));
}

#[cfg(unix)]
#[test]
fn an_interrupted_install_is_finished_by_running_it_again() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open");
    let parent = tempfile::tempdir().expect("tmp");
    let dir = parent.path().join("relay-identity");
    owner_only_dir(&dir);
    // What a run cut short after the certificate and mid-key leaves.
    crate::locked_files::write_owner_only(&dir.join(CERTIFICATE_FILE), &f.made.certificate)
        .expect("cert");
    crate::locked_files::write_owner_only(&dir.join(".relay.key.part"), b"0123").expect("part");
    let plan = plan_install(&dir, &recovered).expect("plan");
    assert_eq!(plan.certificate, FileAction::Keep);
    assert_eq!(plan.relay_key, FileAction::Write);
    install(&plan, &recovered, &f.made.root_public_key, NOW, &none())
        .expect("finish the interrupted install");
    assert!(!dir.join(".relay.key.part").exists());
    verify_installed(&dir, &recovered, &f.made.root_public_key, NOW, &none())
        .expect("verified recovery");
}

#[cfg(unix)]
#[test]
fn verification_refuses_an_identity_that_does_not_check_out() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open");
    let parent = tempfile::tempdir().expect("tmp");
    let dir = parent.path().join("relay-identity");
    install_into(&f, &recovered, &dir).expect("install");
    let revoked: HashSet<String> = ["KQP-000184".to_string()].into();
    assert!(verify_installed(&dir, &recovered, &f.made.root_public_key, NOW, &revoked).is_err());
    let (_, other_root) = generate_signing_keypair();
    assert!(verify_installed(&dir, &recovered, &other_root, NOW, &none()).is_err());
}

#[cfg(unix)]
#[test]
fn a_successful_install_removes_the_package_and_a_failed_one_keeps_it() {
    let f = fixture();
    let recovered = open_fixture(&f).expect("open");
    let parent = tempfile::tempdir().expect("tmp");
    let package = parent.path().join("recovery.kqpkg");
    crate::locked_files::write_owner_only(&package, &f.package).expect("package");

    // Only shown: planning never touches the package.
    let dir = parent.path().join("relay-identity");
    let plan = plan_install(&dir, &recovered).expect("plan");
    assert!(package.exists(), "a plan keeps the package");

    // A failed install (the target appeared after the plan) keeps it too.
    owner_only_dir(&dir);
    assert!(install_and_dispose(
        &package,
        &plan,
        &recovered,
        &f.made.root_public_key,
        NOW,
        &none()
    )
    .is_err());
    assert!(
        package.exists(),
        "a failed install keeps the package for the retry"
    );

    // A successful install removes it.
    let plan = plan_install(&dir, &recovered).expect("plan again");
    let disposal = install_and_dispose(
        &package,
        &plan,
        &recovered,
        &f.made.root_public_key,
        NOW,
        &none(),
    )
    .expect("install and dispose");
    assert!(matches!(disposal, Disposal::Removed));
    assert!(!package.exists(), "the package is gone once installed");
    verify_installed(&dir, &recovered, &f.made.root_public_key, NOW, &none())
        .expect("verified recovery");

    // A link is never followed or removed.
    let target = parent.path().join("target");
    std::fs::write(&target, b"x").expect("target");
    let link = parent.path().join("link.kqpkg");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert!(dispose_package(&link).is_err());
    assert!(target.exists() && link.exists());
}
