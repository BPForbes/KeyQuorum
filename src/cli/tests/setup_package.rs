//! `keyquorum setup <package.kqpkg>`: a provider's package is verified before
//! anything is written, previewed without `--yes`, and installed through the
//! same verified key path `loadkey --bundle` uses.

use super::memory_env::{MemoryEnv, RELAY_URL};
use crate::error::Error;
use crate::keys::{self, KeyType};
use crate::package::{self, Component, ComponentKind, Package, Purpose};
use crate::provider;
use crate::relay::key_delivery::{self, Recipient};
use crate::relay::{ApiKeyScope, NewApiKey};
use crate::storage::Storage;
use crate::{db, test_secrets};
use std::path::Path;

const DB: &str = "/home/alice/keyquorum.sqlite";
const ALICE: &str = "keyquorum --db /home/alice/keyquorum.sqlite";
const PACKAGE: &str = "/home/alice/provider.kqpkg";
const SETUP: &str =
    "keyquorum --db /home/alice/keyquorum.sqlite setup /home/alice/provider.kqpkg --device /usb/alice --label alice";
const CERTIFICATE: &str = "/usb/alice/provider.kqcert";

/// Alice has her identity (the recipient a provider seals to is her public
/// key); the relay has issued nothing yet.
fn alice() -> MemoryEnv {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-04 12:00".into());
    env.keyquorum(&format!("{ALICE} setup --device /usb/alice --label alice"))
        .0
        .expect("alice's identity");
    env
}

fn unix(text: &str) -> u64 {
    provider::unix_from_utc(text).expect("a time")
}

fn alice_recipient(env: &MemoryEnv) -> Recipient {
    let public_key = keys::active_keys_for(env.store(DB), "alice", KeyType::Encryption)
        .unwrap()
        .remove(0)
        .public_key
        .try_into()
        .expect("an X25519 public key");
    let device_id = *crate::device::open_in(&env.fs, Path::new("/usb/alice"))
        .expect("alice's container")
        .device_id();
    Recipient {
        public_key,
        relay_url: format!("{RELAY_URL}/"),
        device_id: Some(device_id),
        licence: Some(format!("Licence {}", test_secrets::pin())),
    }
}

/// The relay mints a pull key sealed to alice, as the console would.
fn sealed_key(env: &MemoryEnv) -> Vec<u8> {
    let relay = env.relay.as_ref().expect("a relay");
    let mut bytes = Vec::new();
    key_delivery::create_as_bundle(
        &*relay.store.connection(),
        &relay.identity,
        &NewApiKey {
            scope: ApiKeyScope::InboxPull,
            recipient_fingerprint: None,
            label: Some("alice".into()),
            ttl_seconds: None,
        },
        &alice_recipient(env),
        |sealed| {
            bytes = sealed.to_vec();
            Ok(())
        },
    )
    .expect("create_as_bundle");
    bytes
}

fn package_for(env: &MemoryEnv, purpose: Purpose, components: Vec<Component>) -> Vec<u8> {
    let relay = env.relay.as_ref().expect("a relay");
    let certificate = relay.identity.certificate.clone();
    let issuer = provider::parse_certificate(&certificate)
        .expect("certificate")
        .relay_public_key;
    let mut all = vec![Component {
        kind: ComponentKind::Certificate,
        bytes: certificate,
    }];
    all.extend(components);
    package::encode(
        &Package {
            purpose,
            id: [5u8; 16],
            issued_at: unix("2026-10-01 00:00"),
            expires_at: unix("2026-11-01 00:00"),
            issuer,
            components: all,
        },
        &relay.identity.relay_private_key,
    )
    .expect("encode")
}

fn key_component(env: &MemoryEnv) -> Component {
    Component {
        kind: ComponentKind::ApiKeyBundle,
        bytes: sealed_key(env),
    }
}

fn put_package(env: &mut MemoryEnv, bytes: &[u8]) {
    env.fs
        .write_new(Path::new(PACKAGE), bytes)
        .expect("write package");
}

fn stored_key(env: &MemoryEnv) -> Option<db::relay_credential::StoredRelayKey> {
    db::relay_credential::get(env.store(DB), RELAY_URL, "inbox.pull").expect("query")
}

#[test]
fn without_yes_the_package_is_shown_and_nothing_changes() {
    let mut env = alice();
    let bytes = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    put_package(&mut env, &bytes);

    let (result, out) = env.keyquorum(SETUP);
    assert!(result.is_ok(), "setup <package> without --yes");
    assert!(out.contains("client setup"), "{out}");
    assert!(out.contains("sealed API key (.kqkey)"), "{out}");
    assert!(out.contains("Nothing was changed"), "{out}");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
    assert_eq!(env.relay.as_ref().expect("a relay").key_checks, 0);
}

#[test]
fn yes_installs_the_certificate_and_the_key_and_prints_no_bearer() {
    let mut env = alice();
    let bytes = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    put_package(&mut env, &bytes);

    let (result, out) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "setup <package> --yes");
    assert!(out.contains("Wrote relay certificate"), "{out}");
    assert!(
        out.contains("from a sealed bundle"),
        "the key goes through the verified install path: {out}"
    );
    assert!(out.contains("Setup from the package is complete."), "{out}");
    assert!(!out.contains("kq_"), "a bearer reached stdout");
    assert!(env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_some());
    assert_eq!(env.relay.as_ref().expect("a relay").key_checks, 1);
}

#[test]
fn running_it_again_keeps_the_certificate_and_finishes_cleanly() {
    let mut env = alice();
    let bytes = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    put_package(&mut env, &bytes);
    env.keyquorum(&format!("{SETUP} --yes")).0.expect("first");

    let (result, out) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "the second run");
    assert!(!out.contains("Wrote relay certificate"), "{out}");
    assert!(out.contains("Setup from the package is complete."), "{out}");
}

#[test]
fn a_changed_package_is_refused_before_anything_is_written() {
    let mut env = alice();
    let mut bytes = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(matches!(result, Err(Error::InvalidKqpkg)));
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn a_package_signed_by_a_key_the_certificate_does_not_name_is_refused() {
    let mut env = alice();
    let relay = env.relay.as_ref().expect("a relay");
    let (stranger_private, stranger_public) = keys::generate_signing_keypair();
    let bytes = package::encode(
        &Package {
            purpose: Purpose::ClientSetup,
            id: [5u8; 16],
            issued_at: unix("2026-10-01 00:00"),
            expires_at: unix("2026-11-01 00:00"),
            issuer: stranger_public,
            components: vec![
                Component {
                    kind: ComponentKind::Certificate,
                    bytes: relay.identity.certificate.clone(),
                },
                key_component(&env),
            ],
        },
        &stranger_private,
    )
    .expect("encode");
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(matches!(result, Err(Error::KqpkgIssuerUntrusted)));
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn an_expired_or_not_yet_valid_package_is_refused() {
    let mut env = alice();
    let bytes = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    put_package(&mut env, &bytes);
    for now in ["2026-12-01 00:00", "2026-09-01 00:00"] {
        env.now = Some(now.into());
        let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
        assert!(matches!(result, Err(Error::KqpkgExpired)), "at {now}");
    }
    assert!(stored_key(&env).is_none());
}

#[test]
fn a_different_certificate_already_on_the_drive_is_never_replaced() {
    let mut env = alice();
    env.fs
        .write_new(Path::new(CERTIFICATE), b"not the same certificate")
        .expect("pre-existing file");
    let bytes = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_err(), "a conflicting certificate is refused");
    assert_eq!(
        env.fs.read(Path::new(CERTIFICATE)).expect("file"),
        b"not the same certificate"
    );
    assert!(stored_key(&env).is_none());
}

#[test]
fn a_key_sealed_to_someone_else_installs_nothing() {
    let mut env = alice();
    let relay = env.relay.as_ref().expect("a relay");
    let mut elsewhere = alice_recipient(&env);
    elsewhere.public_key = crate::keys::generate_encryption_keypair().1;
    let mut sealed = Vec::new();
    key_delivery::create_as_bundle(
        &*relay.store.connection(),
        &relay.identity,
        &NewApiKey {
            scope: ApiKeyScope::InboxPull,
            recipient_fingerprint: None,
            label: Some("bob".into()),
            ttl_seconds: None,
        },
        &elsewhere,
        |bytes| {
            sealed = bytes.to_vec();
            Ok(())
        },
    )
    .expect("create_as_bundle");
    let bytes = package_for(
        &env,
        Purpose::ClientSetup,
        vec![Component {
            kind: ComponentKind::ApiKeyBundle,
            bytes: sealed,
        }],
    );
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_err(), "a key for another recipient is refused");
    assert!(stored_key(&env).is_none());
}

#[test]
fn an_information_package_installs_nothing_even_with_yes() {
    let mut env = alice();
    let bytes = package_for(&env, Purpose::ProviderInfo, vec![]);
    put_package(&mut env, &bytes);

    let (result, out) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "an information package opens");
    assert!(out.contains("information only"), "{out}");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
}

#[test]
fn enroll_out_writes_a_signed_public_request_and_the_provider_can_read_it() {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-04 12:00".into());
    let line = format!(
        "{ALICE} setup --device /usb/alice --label alice --enroll-out /home/alice/alice.kqreq"
    );
    let (result, out) = env.keyquorum(&line);
    assert!(result.is_ok(), "setup --enroll-out");
    assert!(out.contains("Fingerprint (tell your provider"), "{out}");
    let bytes = env
        .fs
        .read(Path::new("/home/alice/alice.kqreq"))
        .expect("file");
    let request = crate::enrollment::decode(&bytes).expect("a valid request");
    assert_eq!(request.label, "alice");
    let recipient = alice_recipient(&env);
    assert_eq!(request.encryption_public, recipient.public_key);
    assert_eq!(Some(request.device_id), recipient.device_id);
    assert!(
        out.contains(&request.fingerprint().expect("fingerprint")),
        "the printed fingerprint is the request's"
    );

    // A package sealed to what the request says installs, end to end.
    let relay = env.relay.as_ref().expect("a relay");
    let mut sealed = Vec::new();
    key_delivery::create_as_bundle(
        &*relay.store.connection(),
        &relay.identity,
        &NewApiKey {
            scope: ApiKeyScope::InboxPull,
            recipient_fingerprint: None,
            label: Some("alice".into()),
            ttl_seconds: None,
        },
        &Recipient {
            public_key: request.encryption_public,
            relay_url: format!("{RELAY_URL}/"),
            device_id: Some(request.device_id),
            licence: None,
        },
        |bytes| {
            sealed = bytes.to_vec();
            Ok(())
        },
    )
    .expect("create_as_bundle");
    let package = package_for(
        &env,
        Purpose::ClientSetup,
        vec![Component {
            kind: ComponentKind::ApiKeyBundle,
            bytes: sealed,
        }],
    );
    put_package(&mut env, &package);
    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "setup <package> --yes");
    assert!(stored_key(&env).is_some());
}

#[test]
fn enroll_out_never_overwrites_a_file() {
    let mut env = MemoryEnv::default();
    env.fs
        .write_new(Path::new("/home/alice/alice.kqreq"), b"mine")
        .expect("pre-existing file");
    let line = format!(
        "{ALICE} setup --device /usb/alice --label alice --enroll-out /home/alice/alice.kqreq"
    );
    let (result, _) = env.keyquorum(&line);
    assert!(result.is_err());
    assert_eq!(
        env.fs
            .read(Path::new("/home/alice/alice.kqreq"))
            .expect("file"),
        b"mine"
    );
    assert!(
        !env.fs.exists(Path::new("/usb/alice")),
        "nothing else was done"
    );
}

/// A package the way the console issues it: the relay signs the setup manifest
/// and seals it, with the key, to alice's slot and drive.
fn manifest_package(env: &MemoryEnv) -> Vec<u8> {
    let relay = env.relay.as_ref().expect("a relay");
    let recipient = alice_recipient(env);
    let key = sealed_key(env);
    package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &recipient.public_key,
        recipient.device_id,
        unix("2026-10-01 00:00"),
        30,
    )
    .expect("issue_client_package")
}

#[test]
fn a_package_with_a_manifest_runs_its_steps_in_order() {
    let mut env = alice();
    let bytes = manifest_package(&env);
    put_package(&mut env, &bytes);

    let (result, preview) = env.keyquorum(SETUP);
    assert!(result.is_ok(), "setup <package> without --yes");
    assert!(preview.contains("in this order"), "{preview}");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));

    let (result, out) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "setup <package> --yes");
    let first = out.find("Step 1/").expect("step 1");
    let second = out.find("Step 2/").expect("step 2");
    assert!(first < second, "{out}");
    assert!(out.contains("Setup from the package is complete."), "{out}");
    assert!(!out.contains("kq_"), "a bearer reached stdout");
    assert!(env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_some());
}

#[test]
fn a_manifest_sealed_for_another_drive_writes_nothing() {
    let mut env = alice();
    let relay = env.relay.as_ref().expect("a relay");
    let recipient = alice_recipient(&env);
    let key = sealed_key(&env);
    let bytes = package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &recipient.public_key,
        Some([9u8; 16]),
        unix("2026-10-01 00:00"),
        30,
    )
    .expect("issue_client_package");
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_err(), "a manifest bound to another drive");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn a_manifest_for_someone_else_is_refused_before_any_write() {
    let mut env = alice();
    let relay = env.relay.as_ref().expect("a relay");
    let key = sealed_key(&env);
    let bytes = package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &[7u8; 32],
        None,
        unix("2026-10-01 00:00"),
        30,
    )
    .expect("issue_client_package");
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_err(), "a manifest sealed to another person");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn a_part_no_step_uses_is_refused_before_any_write() {
    let mut env = alice();
    let good = package::decode(&manifest_package(&env)).expect("decode");
    let mut package = good;
    package.components.push(key_component(&env));
    let relay = env.relay.as_ref().expect("a relay");
    let bytes = package::encode(&package, &relay.identity.relay_private_key).expect("encode");
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_err(), "an unreferenced key");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn two_manifests_or_one_in_an_information_package_are_refused() {
    let env = alice();
    let relay = env.relay.as_ref().expect("a relay");
    let mut doubled = package::decode(&manifest_package(&env)).expect("decode");
    let manifest = doubled
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::SetupManifest)
        .expect("manifest")
        .clone();
    doubled.components.push(manifest.clone());
    assert!(package::encode(&doubled, &relay.identity.relay_private_key)
        .and_then(|bytes| package::decode(&bytes))
        .is_err());

    let mut info = package::decode(&package_for(&env, Purpose::ProviderInfo, vec![])).unwrap();
    info.components.push(manifest);
    assert!(package::encode(&info, &relay.identity.relay_private_key).is_err());
}

#[test]
fn a_key_bound_to_another_drive_stops_a_manifest_setup_before_any_write() {
    let mut env = alice();
    let relay = env.relay.as_ref().expect("a relay");
    let mut recipient = alice_recipient(&env);
    let manifest_recipient = recipient.public_key;
    let manifest_device = recipient.device_id;
    recipient.device_id = Some([9u8; 16]);
    let mut key = Vec::new();
    key_delivery::create_as_bundle(
        &*relay.store.connection(),
        &relay.identity,
        &NewApiKey {
            scope: ApiKeyScope::InboxPull,
            recipient_fingerprint: None,
            label: Some("alice".into()),
            ttl_seconds: None,
        },
        &recipient,
        |sealed| {
            key = sealed.to_vec();
            Ok(())
        },
    )
    .expect("create_as_bundle");
    let bytes = package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &manifest_recipient,
        manifest_device,
        unix("2026-10-01 00:00"),
        30,
    )
    .expect("issue_client_package");
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_err(), "a key for another drive");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}
