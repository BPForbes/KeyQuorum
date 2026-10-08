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
