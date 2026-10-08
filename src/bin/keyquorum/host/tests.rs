use super::*;

#[test]
fn a_failed_commit_removes_the_bundle_it_wrote() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("customer.kqkey");
    let result: Result<()> = into_file(&out, |write| {
        write(b"sealed")?;
        Err(Error::Store("rolled back".to_string()))
    });
    assert!(result.is_err());
    assert!(!out.exists(), "a retry must not be refused by a leftover");
}

#[test]
fn an_unknown_commit_keeps_the_bundle_it_wrote() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("customer.kqkey");
    let result: Result<()> = into_file(&out, |write| {
        write(b"sealed")?;
        Err(Error::StoreCommitUnknown)
    });
    assert!(matches!(result, Err(Error::StoreCommitUnknown)));
    assert!(
        out.exists(),
        "the key may exist and this is its only handoff"
    );
}

/// A certificate spec for the provisioning tests, expiring at `expires_at`.
fn provision_spec<'a>(expires_at: &'a str) -> provision::Spec<'a> {
    provision::Spec {
        provider_id: "Acme Security Services",
        serial: "KQP-000001",
        issued_at: "2026-10-08 00:00:00",
        expires_at,
        capabilities: provider::CAP_PROVIDER,
        issuer_id: "KeyQuorumRoot",
    }
}

/// The written files self-check under the written root and under no other.
#[test]
fn provision_makes_an_identity_the_relay_would_trust_under_the_root_it_wrote() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("provider");
    let written = run_provision(&out, &provision_spec("2099-01-01 00:00:00")).expect("provision");

    // The root the build pins is the one the file holds.
    let root_public = host_env::read_key_file(&written.root_public_key).expect("root.pub");
    assert_eq!(*root_public, written.root_public);
    // The certificate and the relay key pass the relay's own check under it.
    let certificate = std::fs::read(&written.identity_file).expect("provider.kqcert");
    let relay_private = host_env::read_key_file(&written.relay_private_key).expect("relay.key");
    let checked = provider::self_check(
        &root_public,
        &certificate,
        &relay_private,
        "2026-10-09 00:00:00",
        &std::collections::HashSet::new(),
    )
    .expect("the written identity must self-check");
    assert_eq!(checked.provider_id, "Acme Security Services");
    assert_eq!(checked.serial, "KQP-000001");
    let relay_public = host_env::read_key_file(&written.relay_public_key).expect("relay.pub");
    assert_eq!(checked.relay_public_key, *relay_public);
    // The package is the public ProviderInfo one, signed by that relay.
    let package = std::fs::read(&written.package).expect("provider-info.kqpkg");
    let package = keyquorum::package::decode(&package).expect("decode");
    assert_eq!(package.purpose, keyquorum::package::Purpose::ProviderInfo);
    assert_eq!(package.issuer, *relay_public);
    // A placeholder root never signs it.
    assert!(provider::verify_certificate(
        &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        &certificate,
        "2026-10-09 00:00:00",
        &std::collections::HashSet::new()
    )
    .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&written.root_private_key, &written.relay_private_key, &out] {
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{} is owner-only", path.display());
        }
    }
}

/// An existing directory, empty or not, and a missing parent are refused.
#[test]
fn provision_refuses_a_directory_that_already_exists_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    // An empty one too: its mode was not this run's to choose.
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).expect("mkdir");
    let err = run_provision(&empty, &provision_spec("2099-01-01 00:00:00"))
        .err()
        .expect("an existing directory must refuse the run");
    assert!(matches!(err, Error::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists));
    assert_eq!(std::fs::read_dir(&empty).expect("read").count(), 0);
    // A parent that does not exist is not created either.
    assert!(run_provision(
        &dir.path().join("no/such/parent"),
        &provision_spec("2099-01-01 00:00:00")
    )
    .is_err());
    assert!(!dir.path().join("no").exists());

    let out = dir.path().join("provider");
    std::fs::create_dir(&out).expect("mkdir");
    std::fs::write(out.join("relay.key"), b"mine").expect("existing");
    let err = run_provision(&out, &provision_spec("2099-01-01 00:00:00"))
        .err()
        .expect("an existing relay.key must refuse the run");
    assert!(matches!(err, Error::Io(_)));
    let mut names: Vec<_> = std::fs::read_dir(&out)
        .expect("read")
        .map(|e| e.expect("entry").file_name())
        .collect();
    names.sort();
    assert_eq!(names, vec![std::ffi::OsString::from("relay.key")]);
    assert_eq!(std::fs::read(out.join("relay.key")).expect("kept"), b"mine");
}

/// A write that fails removes the files this run created and the directory
/// when it is then empty; a file the run did not create keeps both.
#[test]
fn a_failed_write_removes_only_what_the_run_created() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("provider");
    create_owner_only_dir(&out).expect("mkdir");
    let first = out.join("a");
    let second = out.join("b");
    // The third write fails: its parent does not exist.
    let failing = out.join("missing").join("c");
    let files: [(&Path, &[u8]); 3] = [(&first, b"1"), (&second, b"2"), (&failing, b"3")];
    assert!(write_all_new(&out, &files).is_err());
    assert!(
        !out.exists(),
        "the empty directory this run made is removed"
    );

    create_owner_only_dir(&out).expect("mkdir");
    // A file someone else put where the second write goes: it is kept, the
    // first file (this run's) is removed, and the directory stays.
    std::fs::write(&second, b"theirs").expect("foreign");
    let files: [(&Path, &[u8]); 2] = [(&first, b"1"), (&second, b"2")];
    assert!(write_all_new(&out, &files).is_err());
    assert!(!first.exists());
    assert_eq!(std::fs::read(&second).expect("kept"), b"theirs");
    assert!(out.exists());
}

/// The self-check runs before any write, so nothing is left behind.
#[test]
fn provision_refuses_a_certificate_that_would_already_be_expired() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("provider");
    assert!(run_provision(&out, &provision_spec("2020-01-01 00:00:00")).is_err());
    assert!(
        !out.join("root.key").exists(),
        "nothing is written when the check fails"
    );
}

/// `host recovery install --yes` on an otherwise valid recovery package: the
/// placeholder root's private half is held by nobody, so each case pins a root
/// the test holds and changes exactly one input.
mod recovery_install {
    use super::*;
    use keyquorum::package::{Component, ComponentKind, Package, Purpose};
    use std::collections::HashSet;

    const NOW: &str = "2026-10-08 12:00:00";

    struct Fixture {
        dir: tempfile::TempDir,
        made: provision::Identity,
        operator_secret: Zeroizing<[u8; 32]>,
        operator_public: [u8; 32],
        package: PathBuf,
        key_file: PathBuf,
        out: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("dir");
            let made = provision::provision(&provision_spec("2099-01-01 00:00:00"), NOW)
                .expect("provision");
            let (operator_secret, operator_public) = keys::generate_encryption_keypair();
            let bytes = recovery::issue(&recovery::Issue {
                root_private_key: &made.root_private_key,
                relay_private_key: &made.relay_private_key,
                certificate: &made.certificate,
                recipient: &operator_public,
                now_utc: NOW,
                valid_days: 1,
                revoked: &HashSet::new(),
            })
            .expect("issue");
            let package = dir.path().join("recovery.kqpkg");
            std::fs::write(&package, bytes).expect("package");
            let key_file = dir.path().join("operator.key");
            cli::write_hex_file(&key_file, &operator_secret[..]).expect("operator key");
            let out = dir.path().join("restored");
            Fixture {
                dir,
                made,
                operator_secret: Zeroizing::new(*operator_secret),
                operator_public,
                package,
                key_file,
                out,
            }
        }

        fn install(&self, key_file: &Path, root: &[u8; 32]) -> Result<()> {
            recovery_install(
                &self.package,
                key_file,
                &self.out,
                true,
                root,
                NOW,
                &HashSet::new(),
            )
        }

        /// Failed, wrote nothing and kept the package.
        fn assert_refused_with_nothing_written(&self, result: Result<()>, case: &str) {
            assert!(result.is_err(), "host recovery install --yes, {case}");
            assert!(!self.out.exists(), "{case}: the destination stays absent");
            assert!(self.package.exists(), "{case}: the package is kept");
        }
    }

    #[test]
    fn the_unchanged_fixture_installs_and_removes_the_package() {
        let f = Fixture::new();
        f.install(&f.key_file, &f.made.root_public_key)
            .expect("host recovery install --yes on the valid fixture");
        assert!(f.out.join(recovery::RELAY_KEY_FILE).exists());
        assert!(f.out.join(recovery::CERTIFICATE_FILE).exists());
        assert!(
            !f.package.exists(),
            "a verified install removes the package"
        );
    }

    #[test]
    fn a_wrong_root_installs_nothing() {
        let f = Fixture::new();
        let (_, other_root) = keys::generate_signing_keypair();
        let result = f.install(&f.key_file, &other_root);
        f.assert_refused_with_nothing_written(result, "a root the package was not signed by");
    }

    #[test]
    fn a_wrong_recipient_installs_nothing() {
        let f = Fixture::new();
        let (other_secret, _) = keys::generate_encryption_keypair();
        let other_key = f.dir.path().join("other-operator.key");
        cli::write_hex_file(&other_key, &other_secret[..]).expect("other operator key");
        let result = f.install(&other_key, &f.made.root_public_key);
        f.assert_refused_with_nothing_written(
            result,
            "an operator key the package is not sealed to",
        );
    }

    #[test]
    fn a_relay_key_that_is_not_the_certificates_installs_nothing() {
        let f = Fixture::new();
        // The root signs a context for the real certificate, but the sealed
        // relay key belongs to another relay.
        let (other_relay_private, _) = provider::generate_relay_identity();
        let issued_at = provider::unix_from_utc(NOW).expect("time");
        let context = recovery::Context {
            version: recovery::VERSION,
            purpose: "provider_recovery".to_string(),
            package_id: hex::encode([7u8; 16]),
            recipient: hex::encode(f.operator_public),
            provider_id: "Acme Security Services".to_string(),
            serial: "KQP-000001".to_string(),
            relay_public_key: hex::encode(f.made.relay_public_key),
            certificate_sha256: {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&f.made.certificate))
            },
            issued_at,
            expires_at: issued_at + 86_400,
            operations: recovery::OPERATIONS.to_vec(),
        };
        let json = serde_json::to_vec(&context).expect("context");
        let signature = keyquorum::signing::sign(
            &f.made.root_private_key,
            &keyquorum::signing::provider_recovery_preimage(&json),
        );
        let mut payload = Vec::new();
        keyquorum::envelope::push_len_prefixed_u32(&mut payload, &json).expect("length");
        payload.extend_from_slice(&other_relay_private[..]);
        payload.extend_from_slice(&signature);
        let sealed = keyquorum::envelope::seal(
            keyquorum::envelope::EXPORT_BUNDLE,
            keyquorum::export::BUNDLE_TYPE_PROVIDER_RECOVERY,
            &f.operator_public,
            &payload,
        )
        .expect("seal");
        let bytes = keyquorum::package::encode(
            &Package {
                purpose: Purpose::ProviderRecovery,
                id: [7u8; 16],
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
                        bytes: sealed,
                    },
                ],
            },
            &f.made.root_private_key,
        )
        .expect("encode");
        std::fs::write(&f.package, bytes).expect("replace the package");
        // The operator's own key opens it; only the relay key is wrong.
        assert_eq!(
            *f.operator_secret,
            *host_env::read_key_file(&f.key_file).expect("key")
        );
        let result = f.install(&f.key_file, &f.made.root_public_key);
        assert!(
            matches!(result, Err(Error::RelayIdentityMismatch)),
            "host recovery install --yes, a relay key the certificate does not name"
        );
        assert!(!f.out.exists(), "the destination stays absent");
        assert!(f.package.exists(), "the package is kept");
    }
}
