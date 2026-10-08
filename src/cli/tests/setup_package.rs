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
    sealed_key_for(env, alice_recipient(env))
}

/// [`sealed_key`] for a recipient whose relay URL a test chose.
fn sealed_key_for(env: &MemoryEnv, recipient: Recipient) -> Vec<u8> {
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
        &recipient,
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

/// The spec of a first-delivery package, generation 1, as the relay issues it.
fn setup_spec() -> package::ClientPackage {
    package::ClientPackage {
        purpose: Purpose::ClientSetup,
        generation: 1,
        issued_at: unix("2026-10-01 00:00"),
        valid_days: 30,
    }
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
    assert!(out.contains("client setup"), "setup provider.kqpkg");
    assert!(
        out.contains("sealed API key (.kqkey)"),
        "setup provider.kqpkg"
    );
    assert!(out.contains("Nothing was changed"), "setup provider.kqpkg");
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
    assert!(
        out.contains("Wrote relay certificate"),
        "setup provider.kqpkg --yes"
    );
    assert!(
        out.contains("from a sealed bundle"),
        "setup provider.kqpkg --yes: the key goes through the verified install path"
    );
    assert!(
        out.contains("Setup from the package is complete."),
        "setup provider.kqpkg --yes"
    );
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

    let checks = env.relay.as_ref().expect("a relay").key_checks;
    let (result, out) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "the second run");
    assert!(
        !out.contains("Wrote relay certificate"),
        "setup provider.kqpkg --yes, run again"
    );
    assert!(
        out.contains("already installed"),
        "setup provider.kqpkg --yes, run again"
    );
    assert_eq!(
        env.relay.as_ref().expect("a relay").key_checks,
        checks,
        "a complete package is not run again"
    );
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
    assert!(
        out.contains("information only"),
        "setup provider.kqpkg --yes (provider information)"
    );
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
    assert!(
        out.contains("Fingerprint (tell your provider"),
        "setup --enroll-out"
    );
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

/// A package with a signed manifest of `purpose` and `generation`, carrying a
/// fresh key sealed to alice's slot and drive.
fn manifest_package_with(env: &MemoryEnv, purpose: Purpose, generation: u64) -> Vec<u8> {
    let relay = env.relay.as_ref().expect("a relay");
    let recipient = alice_recipient(env);
    let key = sealed_key(env);
    package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &recipient.public_key,
        recipient.device_id,
        &package::ClientPackage {
            purpose,
            generation,
            ..setup_spec()
        },
    )
    .expect("issue_client_package")
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
        &setup_spec(),
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
    assert!(preview.contains("in this order"), "setup provider.kqpkg");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));

    let (result, out) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "setup <package> --yes");
    let first = out.find("Step 1/").expect("step 1");
    let second = out.find("Step 2/").expect("step 2");
    assert!(first < second, "setup provider.kqpkg --yes");
    assert!(
        out.contains("Setup from the package is complete."),
        "setup provider.kqpkg --yes"
    );
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
        &setup_spec(),
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
        &setup_spec(),
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
        &setup_spec(),
    )
    .expect("issue_client_package");
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(
        matches!(result, Err(Error::KeyIssueDeviceMismatch)),
        "a key for another drive is refused"
    );
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn a_key_from_another_relay_than_the_package_signer_is_refused_before_any_write() {
    let mut env = alice();
    let relay = env.relay.as_ref().expect("a relay");
    // A second relay the same root vouches for issues the key; the first relay
    // signs the package around it.
    let other = env.other_relay_identity();
    let recipient = alice_recipient(&env);
    let mut key = Vec::new();
    key_delivery::create_as_bundle(
        &*relay.store.connection(),
        &other,
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
        &recipient.public_key,
        recipient.device_id,
        &setup_spec(),
    )
    .expect("issue_client_package");
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(
        matches!(result, Err(Error::KeyIssueRelayMismatch)),
        "a key from a different relay than the signer"
    );
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn the_preview_names_each_keys_scope_relay_and_expiry_and_no_bearer() {
    let mut env = alice();
    let bytes = manifest_package(&env);
    put_package(&mut env, &bytes);
    let (result, out) = env.keyquorum(SETUP);
    assert!(result.is_ok(), "setup <package> without --yes");
    assert!(out.contains("inbox.pull scope"), "setup provider.kqpkg");
    assert!(out.contains(RELAY_URL), "setup provider.kqpkg");
    assert!(out.contains("licence: Licence"), "setup provider.kqpkg");
    assert!(!out.contains("kq_"), "a bearer reached stdout");
}

#[test]
fn a_package_file_over_the_cap_is_refused_unread() {
    let mut env = alice();
    let big = vec![0u8; package::MAX_PACKAGE_BYTES + 1];
    put_package(&mut env, &big);
    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(
        matches!(result, Err(Error::InvalidKqpkg)),
        "a package over the size cap"
    );
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
}

#[test]
fn an_update_package_without_a_signed_generation_is_refused_before_any_write() {
    let mut env = alice();
    let bytes = package_for(&env, Purpose::ClientUpdate, vec![key_component(&env)]);
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(
        matches!(result, Err(Error::KqpkgRefused(_))),
        "setup <update package without a manifest> --yes"
    );
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

#[test]
fn a_package_never_replaces_a_different_stored_key_but_accepts_the_same_one() {
    let mut env = alice();
    let first = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    put_package(&mut env, &first);
    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "first setup");
    let before = stored_key(&env).expect("a stored key").key_hash;

    // The same package again is the same key: installed again, nothing changes.
    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_ok(), "the same package again");
    assert_eq!(stored_key(&env).expect("still stored").key_hash, before);

    // A newer package carrying a different key for the same relay and scope.
    let second = package_for(&env, Purpose::ClientSetup, vec![key_component(&env)]);
    env.fs
        .write_new(Path::new("/home/alice/second.kqpkg"), &second)
        .expect("write the second package");
    let (result, _) = env.keyquorum(&format!(
        "{ALICE} setup /home/alice/second.kqpkg --device /usb/alice --label alice --yes"
    ));
    assert!(
        result.is_err(),
        "a different key for the same relay and scope"
    );
    assert_eq!(stored_key(&env).expect("kept").key_hash, before);
}

#[test]
fn setup_with_a_package_needs_the_slot_to_exist_and_creates_no_identity() {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-04 12:00".into());
    // Alice's slot is made on another drive so a key can be sealed to her, and
    // the drive the package is applied to has no slot at all.
    let sealed = {
        let mut other = alice();
        std::mem::swap(&mut other.relay, &mut env.relay);
        let key = key_component(&other);
        std::mem::swap(&mut other.relay, &mut env.relay);
        key
    };
    let bytes = package_for(&env, Purpose::ClientSetup, vec![sealed]);
    put_package(&mut env, &bytes);

    let (result, _) = env.keyquorum(&format!("{SETUP} --yes"));
    assert!(result.is_err(), "no slot on this drive");
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(!env.fs.exists(Path::new("/usb/alice/device.kq")));
}

/// Writes `bytes` as another package file and runs setup on it.
fn setup_file(env: &mut MemoryEnv, name: &str, bytes: &[u8], yes: bool) -> Result<String, Error> {
    let path = format!("/home/alice/{name}.kqpkg");
    if !env.fs.exists(Path::new(&path)) {
        env.fs
            .write_new(Path::new(&path), bytes)
            .expect("write package");
    }
    let (result, out) = env.keyquorum(&format!(
        "{ALICE} setup {path} --device /usb/alice --label alice{}",
        if yes { " --yes" } else { "" }
    ));
    result.map(|_| out)
}

fn ledger_state(env: &MemoryEnv, package: &[u8]) -> Option<String> {
    let id = hex::encode(package::decode(package).expect("decode").id);
    db::package_ledger::record(env.store(DB), &id)
        .expect("ledger")
        .map(|record| record.state)
}

#[test]
fn a_newer_update_replaces_the_stored_key_and_an_older_package_never_comes_back() {
    let mut env = alice();
    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "setup", &setup, true).expect("first package");
    let first = stored_key(&env).expect("stored").key_hash;
    assert_eq!(ledger_state(&env, &setup).as_deref(), Some("complete"));

    let update = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    let preview = setup_file(&mut env, "update", &update, false).expect("preview");
    assert!(
        preview.contains("replaces the key stored now"),
        "setup update.kqpkg"
    );
    assert!(preview.contains("generation: 2"), "setup update.kqpkg");
    setup_file(&mut env, "update", &update, true).expect("the update");
    let second = stored_key(&env).expect("stored").key_hash;
    assert_ne!(first, second, "the update replaced the key");

    // An older or equal generation is stale, even as an update.
    let stale = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    assert!(matches!(
        setup_file(&mut env, "stale", &stale, true),
        Err(Error::KqpkgRefused(_))
    ));
    assert_eq!(stored_key(&env).expect("kept").key_hash, second);
    // The first package, run again, is complete and changes nothing.
    let again = setup_file(&mut env, "setup", &setup, true).expect("rerun");
    assert!(
        again.contains("already installed"),
        "setup setup.kqpkg --yes, run again"
    );
    assert_eq!(stored_key(&env).expect("kept").key_hash, second);
}

#[test]
fn a_setup_package_never_replaces_a_key_however_new_its_generation() {
    let mut env = alice();
    let first = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "first", &first, true).expect("first");
    let before = stored_key(&env).expect("stored").key_hash;
    let newer = manifest_package_with(&env, Purpose::ClientSetup, 9);
    assert!(setup_file(&mut env, "newer", &newer, true).is_err());
    assert_eq!(stored_key(&env).expect("kept").key_hash, before);
}

#[test]
fn an_interrupted_setup_resumes_where_it_stopped_and_redoes_nothing() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    // The relay is unreachable: the identity and certificate steps run, the
    // key step cannot, and the package stays pending.
    env.relay.as_mut().expect("a relay").unreachable = true;
    let out = setup_file(&mut env, "interrupted", &bytes, true);
    assert!(out.is_err(), "the relay is down");
    assert!(env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("pending"));

    env.relay.as_mut().expect("a relay").unreachable = false;
    let preview = setup_file(&mut env, "interrupted", &bytes, false).expect("preview");
    assert!(
        preview.contains("did not finish"),
        "setup interrupted.kqpkg"
    );
    let out = setup_file(&mut env, "interrupted", &bytes, true).expect("resumed");
    assert!(
        !out.contains("Wrote relay certificate"),
        "setup interrupted.kqpkg --yes keeps the certificate"
    );
    assert!(stored_key(&env).is_some());
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
}

#[test]
fn a_key_check_whose_answer_is_lost_stores_nothing_and_running_again_finishes() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    // The relay checked the key and answered, but the answer never reached
    // us: setup cannot tell whether the key was accepted, so it stores nothing.
    env.relay.as_mut().expect("a relay").lose_keycheck_response = true;
    let out = setup_file(&mut env, "lost-answer", &bytes, true);
    assert!(out.is_err(), "setup lost-answer.kqpkg --yes");
    assert!(stored_key(&env).is_none());
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("pending"));

    setup_file(&mut env, "lost-answer", &bytes, true).expect("setup lost-answer.kqpkg --yes again");
    assert!(stored_key(&env).is_some());
    let count: i64 = env
        .store(DB)
        .query_row("SELECT COUNT(*) FROM relay_credentials", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(count, 1, "one relay credential after the rerun");
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
}

/// Every stored value in the ledger tables, as bytes, for the secrecy check.
fn ledger_bytes(env: &MemoryEnv) -> Vec<u8> {
    use rusqlite::types::Value;
    let conn = env.store(DB);
    let mut dump = Vec::new();
    for table in [
        "package_installs",
        "package_baselines",
        "package_retired_keys",
    ] {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM {table}"))
            .expect("prepare");
        let columns = stmt.column_count();
        let rows = stmt
            .query_map([], |row| {
                (0..columns)
                    .map(|i| row.get::<_, Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .expect("query");
        for row in rows {
            for value in row.expect("row") {
                match value {
                    Value::Text(text) => dump.extend_from_slice(text.as_bytes()),
                    Value::Blob(bytes) => dump.extend_from_slice(&bytes),
                    Value::Integer(number) => dump.extend_from_slice(number.to_string().as_bytes()),
                    Value::Real(_) | Value::Null => {}
                }
                dump.push(b'\n');
            }
        }
    }
    dump
}

#[test]
fn the_ledger_keeps_no_bearer_and_no_passphrase() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "secrecy", &bytes, true).expect("setup secrecy.kqpkg --yes");
    let dump = ledger_bytes(&env);
    assert!(!dump.is_empty(), "the install left ledger rows");
    assert!(
        !dump.windows(3).any(|window| window == b"kq_"),
        "a bearer reached the install ledger"
    );
    let passphrase = test_secrets::passphrase();
    assert!(
        !dump
            .windows(passphrase.len())
            .any(|window| window == passphrase.as_bytes()),
        "a passphrase reached the install ledger"
    );
}

#[test]
fn a_crash_after_a_step_took_effect_is_finished_without_doing_it_twice() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "crash", &bytes, true).expect("installed");
    // As if the process stopped after the key was stored but before its step,
    // and the rest, were marked: the ledger says pending with one step done.
    let id = hex::encode(package::decode(&bytes).unwrap().id);
    env.store(DB)
        .execute(
            "UPDATE package_installs SET state = 'pending', steps_done = 'identity'
             WHERE package_id = ?1",
            [&id],
        )
        .unwrap();
    let checks = env.relay.as_ref().expect("a relay").key_checks;
    setup_file(&mut env, "crash", &bytes, true).expect("finished");
    assert_eq!(
        env.relay.as_ref().expect("a relay").key_checks,
        checks,
        "the stored key was found in place; the relay was not asked again"
    );
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
}

#[test]
fn a_pending_package_blocks_another_in_its_stream_until_abandoned() {
    let mut env = alice();
    let stuck = manifest_package_with(&env, Purpose::ClientSetup, 1);
    env.relay.as_mut().expect("a relay").unreachable = true;
    assert!(setup_file(&mut env, "stuck", &stuck, true).is_err());
    env.relay.as_mut().expect("a relay").unreachable = false;
    let next = manifest_package_with(&env, Purpose::ClientSetup, 2);
    assert!(matches!(
        setup_file(&mut env, "next", &next, true),
        Err(Error::KqpkgRefused(_))
    ));
    let id = hex::encode(package::decode(&stuck).unwrap().id);
    let (result, out) = env.keyquorum(&format!("{ALICE} setup --abandon {id}"));
    assert!(result.is_ok(), "setup --abandon");
    assert!(out.contains("Abandoned package"), "setup --abandon ID");
    assert_eq!(ledger_state(&env, &stuck).as_deref(), Some("failed"));
    // The abandoned one never resumes; the next one installs.
    assert!(setup_file(&mut env, "stuck", &stuck, true).is_err());
    setup_file(&mut env, "next", &next, true).expect("the next package");
    assert!(stored_key(&env).is_some());
}

#[test]
fn a_key_an_update_replaced_is_never_installed_again() {
    let mut env = alice();
    let first = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "first", &first, true).expect("first");
    let update = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    setup_file(&mut env, "update", &update, true).expect("update");
    // A newer package from the relay that carries the first, replaced key.
    let relay = env.relay.as_ref().expect("a relay");
    let old_key = package::decode(&first)
        .unwrap()
        .components
        .into_iter()
        .find(|c| c.kind == ComponentKind::ApiKeyBundle)
        .unwrap()
        .bytes;
    let recipient = alice_recipient(&env);
    let replay = package::issue_client_package(
        &relay.identity,
        &[old_key.as_slice()],
        &recipient.public_key,
        recipient.device_id,
        &package::ClientPackage {
            purpose: Purpose::ClientUpdate,
            generation: 7,
            ..setup_spec()
        },
    )
    .expect("issue");
    let before = stored_key(&env).expect("stored").key_hash;
    assert!(matches!(
        setup_file(&mut env, "replay", &replay, true),
        Err(Error::KqpkgRefused(_))
    ));
    assert_eq!(stored_key(&env).expect("kept").key_hash, before);
}

// --- several packages at once (issue #108) -------------------------------

/// Writes each `(name, bytes)` as a package file (once) and runs one setup over
/// them all, in the order given.
fn setup_batch(
    env: &mut MemoryEnv,
    files: &[(&str, &[u8])],
    yes: bool,
) -> (Result<(), Error>, String) {
    let mut paths = Vec::new();
    for (name, bytes) in files {
        let path = format!("/home/alice/{name}.kqpkg");
        if !env.fs.exists(Path::new(&path)) {
            env.fs
                .write_new(Path::new(&path), bytes)
                .expect("write package");
        }
        paths.push(path);
    }
    env.keyquorum(&format!(
        "{ALICE} setup {} --device /usb/alice --label alice{}",
        paths.join(" "),
        if yes { " --yes" } else { "" }
    ))
}

/// Nothing at all was written: no certificate, no key and no ledger row.
fn untouched(env: &MemoryEnv, packages: &[&[u8]]) {
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(env).is_none());
    for bytes in packages {
        assert_eq!(ledger_state(env, bytes), None);
    }
}

fn key_hash_of(env: &MemoryEnv, package_bytes: &[u8]) -> String {
    let sealed = package::decode(package_bytes)
        .expect("decode")
        .components
        .into_iter()
        .find(|c| c.kind == ComponentKind::ApiKeyBundle)
        .expect("a key")
        .bytes;
    let _ = env;
    crate::setup_manifest::hash_of(&sealed)
}

#[test]
fn several_packages_install_in_generation_order_whatever_order_they_are_given() {
    let mut env = alice();
    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let update = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    let files: [(&str, &[u8]); 2] = [("b-update", &update), ("a-setup", &setup)];

    let (result, preview) = setup_batch(&mut env, &files, false);
    assert!(result.is_ok(), "setup b-update.kqpkg a-setup.kqpkg");
    let first = preview
        .find("[1/2] /home/alice/a-setup.kqpkg")
        .expect("setup first");
    let second = preview
        .find("[2/2] /home/alice/b-update.kqpkg")
        .expect("update second");
    assert!(first < second);
    untouched(&env, &[&setup, &update]);

    let (result, out) = setup_batch(&mut env, &files, true);
    assert!(result.is_ok(), "setup b-update.kqpkg a-setup.kqpkg --yes");
    assert_eq!(ledger_state(&env, &setup).as_deref(), Some("complete"));
    assert_eq!(ledger_state(&env, &update).as_deref(), Some("complete"));
    assert!(
        out.contains("Results:"),
        "setup b-update.kqpkg a-setup.kqpkg --yes"
    );
    assert_eq!(
        out.matches(": installed").count(),
        2,
        "setup b-update.kqpkg a-setup.kqpkg --yes"
    );
    // The update's key is the one stored; the setup's was retired by it.
    let stored = stored_key(&env).expect("stored").key_hash;
    assert_ne!(stored, key_hash_of(&env, &setup));

    let (result, again) = setup_batch(&mut env, &files, true);
    assert!(result.is_ok(), "setup again");
    assert_eq!(
        again.matches(": already installed").count(),
        2,
        "setup b-update.kqpkg a-setup.kqpkg --yes, again"
    );
    assert_eq!(stored_key(&env).expect("kept").key_hash, stored);
}

#[test]
fn the_same_file_given_twice_counts_once() {
    let mut env = alice();
    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let files: [(&str, &[u8]); 2] = [("one", &setup), ("copy", &setup)];
    let (result, out) = setup_batch(&mut env, &files, true);
    assert!(result.is_ok(), "setup one.kqpkg copy.kqpkg --yes");
    assert!(
        out.contains("counts once"),
        "setup one.kqpkg copy.kqpkg --yes"
    );
    assert_eq!(ledger_state(&env, &setup).as_deref(), Some("complete"));
}

#[test]
fn a_later_invalid_package_stops_the_batch_before_any_write() {
    let mut env = alice();
    let good = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let mut broken = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    let middle = broken.len() / 2;
    broken[middle] ^= 1;
    let files: [(&str, &[u8]); 2] = [("good", &good), ("broken", &broken)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(result.is_err(), "a changed byte in the second package");
    untouched(&env, &[&good]);

    // A package sealed for someone else's drive stops it the same way.
    let relay = env.relay.as_ref().expect("a relay");
    let recipient = alice_recipient(&env);
    let key = sealed_key(&env);
    let elsewhere = package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &recipient.public_key,
        Some([3u8; 16]),
        &package::ClientPackage {
            purpose: Purpose::ClientUpdate,
            generation: 2,
            ..setup_spec()
        },
    )
    .expect("issue");
    let files: [(&str, &[u8]); 2] = [("good", &good), ("elsewhere", &elsewhere)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(result.is_err(), "a package for another drive");
    untouched(&env, &[&good]);
}

#[test]
fn a_later_package_sealed_to_another_recipient_stops_the_batch_before_any_write() {
    let mut env = alice();
    let good = manifest_package_with(&env, Purpose::ClientSetup, 1);
    // An otherwise valid generation-2 update whose key and manifest are sealed
    // to some other recipient's public key, not alice's slot.
    let mut stranger = alice_recipient(&env);
    stranger.public_key = crate::keys::generate_encryption_keypair().1;
    let key = sealed_key_for(&env, stranger.clone());
    let relay = env.relay.as_ref().expect("a relay");
    let foreign = package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &stranger.public_key,
        stranger.device_id,
        &package::ClientPackage {
            purpose: Purpose::ClientUpdate,
            generation: 2,
            ..setup_spec()
        },
    )
    .expect("issue_client_package");
    let files: [(&str, &[u8]); 2] = [("good", &good), ("foreign", &foreign)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(
        result.is_err(),
        "setup good.kqpkg foreign.kqpkg --yes with the second sealed to another recipient"
    );
    untouched(&env, &[&good, &foreign]);
}

#[test]
fn packages_over_the_aggregate_limit_are_refused_before_any_write() {
    let mut env = alice();
    let each = package::MAX_PACKAGE_BYTES;
    let count = super::super::setup_package::MAX_BATCH_BYTES / each + 1;
    // Each file is within the per-file cap; together they pass the batch cap.
    let blobs: Vec<(String, Vec<u8>)> = (0..count)
        .map(|i| (format!("big{i}"), vec![0u8; each]))
        .collect();
    let files: Vec<(&str, &[u8])> = blobs
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(
        matches!(result, Err(Error::Usage(_))),
        "setup of files totalling more than the batch cap"
    );
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));
    assert!(stored_key(&env).is_none());
}

/// A package refused by the ledger because its generation is not past the
/// baseline (and not for some other reason).
fn is_stale(result: &Result<String, Error>) -> bool {
    matches!(result, Err(Error::KqpkgRefused(why)) if why.contains("not newer than"))
}

#[test]
fn a_renewed_certificate_keeps_the_baseline_through_package_setup() {
    let mut env = alice();
    let first = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "before-renewal", &first, true).expect("setup before-renewal.kqpkg --yes");
    assert_eq!(ledger_state(&env, &first).as_deref(), Some("complete"));

    // The provider renews its certificate and the operator clears the old
    // file from the drive. The stream is the same provider, slot and drive, so
    // the generation already reached still binds.
    env.renew_certificate("TEST-RENEWED");
    env.fs
        .delete(Path::new(CERTIFICATE))
        .expect("remove the old certificate");
    let equal = manifest_package_with(&env, Purpose::ClientUpdate, 1);
    assert!(
        is_stale(&setup_file(&mut env, "renewed-equal", &equal, true)),
        "setup renewed-equal.kqpkg --yes at the generation already reached"
    );
    assert_eq!(ledger_state(&env, &equal), None);
    assert!(!env.fs.exists(Path::new(CERTIFICATE)));

    let newer = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    setup_file(&mut env, "renewed-newer", &newer, true).expect("setup renewed-newer.kqpkg --yes");
    assert_eq!(ledger_state(&env, &newer).as_deref(), Some("complete"));
    assert!(env.fs.exists(Path::new(CERTIFICATE)));

    // Going back to the first generation under the renewed certificate is
    // refused too.
    let older = manifest_package_with(&env, Purpose::ClientUpdate, 1);
    assert!(
        is_stale(&setup_file(&mut env, "renewed-older", &older, true)),
        "setup renewed-older.kqpkg --yes below the baseline"
    );
}

#[test]
fn a_moved_relay_url_keeps_the_baseline_through_package_planning() {
    let mut env = alice();
    let first = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "before-move", &first, true).expect("setup before-move.kqpkg --yes");

    // The relay now answers at another address; its packages name it.
    let moved = |env: &MemoryEnv, generation: u64| {
        let relay = env.relay.as_ref().expect("a relay");
        let mut recipient = alice_recipient(env);
        recipient.relay_url = "https://moved.test/".into();
        let key = sealed_key_for(env, recipient.clone());
        package::issue_client_package(
            &relay.identity,
            &[key.as_slice()],
            &recipient.public_key,
            recipient.device_id,
            &package::ClientPackage {
                purpose: Purpose::ClientUpdate,
                generation,
                ..setup_spec()
            },
        )
        .expect("issue_client_package")
    };
    let equal = moved(&env, 1);
    assert!(
        is_stale(&setup_file(&mut env, "moved-equal", &equal, true)),
        "setup moved-equal.kqpkg --yes at the generation already reached"
    );
    assert_eq!(ledger_state(&env, &equal), None);

    // A newer generation for the moved address passes the ledger and is
    // previewed; the preview writes nothing.
    let newer = moved(&env, 2);
    let preview =
        setup_file(&mut env, "moved-newer", &newer, false).expect("setup moved-newer.kqpkg");
    assert!(preview.contains("moved.test"), "setup moved-newer.kqpkg");
    assert_eq!(ledger_state(&env, &newer), None);
}

#[test]
fn a_stale_package_in_the_batch_stops_the_newer_one_too() {
    let mut env = alice();
    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let update = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    setup_file(&mut env, "setup", &setup, true).expect("setup");
    setup_file(&mut env, "update", &update, true).expect("update");
    let stored = stored_key(&env).expect("stored").key_hash;
    let stale = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    let newer = manifest_package_with(&env, Purpose::ClientUpdate, 3);
    let files: [(&str, &[u8]); 2] = [("newer", &newer), ("stale", &stale)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(matches!(result, Err(Error::KqpkgRefused(_))));
    assert_eq!(ledger_state(&env, &newer), None);
    assert_eq!(stored_key(&env).expect("kept").key_hash, stored);
}

#[test]
fn ambiguous_selections_for_one_slot_are_refused_before_any_write() {
    let mut env = alice();
    let first = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    let second = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    let files: [(&str, &[u8]); 2] = [("first", &first), ("second", &second)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(
        matches!(result, Err(Error::KqpkgRefused(_))),
        "two at one generation"
    );
    untouched(&env, &[&first, &second]);

    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let later_setup = manifest_package_with(&env, Purpose::ClientSetup, 2);
    let files: [(&str, &[u8]); 2] = [("setup", &setup), ("later-setup", &later_setup)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(matches!(result, Err(Error::KqpkgRefused(_))), "two setups");
    untouched(&env, &[&setup, &later_setup]);
}

#[test]
fn packages_that_would_place_different_certificates_are_refused() {
    let mut env = alice();
    let mine = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let relay = env.relay.as_ref().expect("a relay");
    let other = env.other_relay_identity();
    let recipient = alice_recipient(&env);
    let mut key = Vec::new();
    key_delivery::create_as_bundle(
        &*relay.store.connection(),
        &other,
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
    let theirs = package::issue_client_package(
        &other,
        &[key.as_slice()],
        &recipient.public_key,
        recipient.device_id,
        &setup_spec(),
    )
    .expect("issue");
    let files: [(&str, &[u8]); 2] = [("mine", &mine), ("theirs", &theirs)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(matches!(result, Err(Error::KqpkgRefused(_))));
    untouched(&env, &[&mine, &theirs]);
}

#[test]
fn only_client_packages_install_together() {
    let mut env = alice();
    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let info = package_for(&env, Purpose::ProviderInfo, vec![]);
    let files: [(&str, &[u8]); 2] = [("setup", &setup), ("info", &info)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(result.is_err(), "provider information in a batch");
    untouched(&env, &[&setup]);
}

#[test]
fn too_many_packages_are_refused_before_reading_them() {
    let mut env = alice();
    let paths =
        vec!["/home/alice/missing.kqpkg"; super::super::setup_package::MAX_BATCH_PACKAGES + 1];
    let (result, _) = env.keyquorum(&format!(
        "{ALICE} setup {} --device /usb/alice --label alice --yes",
        paths.join(" ")
    ));
    assert!(matches!(result, Err(Error::Usage(_))), "seventeen packages");
}

#[test]
fn a_stopped_batch_reports_each_package_and_running_it_again_finishes() {
    let mut env = alice();
    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let update = manifest_package_with(&env, Purpose::ClientUpdate, 2);
    let files: [(&str, &[u8]); 2] = [("setup", &setup), ("update", &update)];
    env.relay.as_mut().expect("a relay").unreachable = true;
    let (result, out) = setup_batch(&mut env, &files, true);
    assert!(result.is_err(), "the relay is down");
    assert!(
        out.contains("stopped, pending"),
        "setup setup.kqpkg update.kqpkg --yes, relay down"
    );
    assert!(
        out.contains("not started"),
        "setup setup.kqpkg update.kqpkg --yes, relay down"
    );
    assert_eq!(ledger_state(&env, &setup).as_deref(), Some("pending"));
    assert_eq!(ledger_state(&env, &update), None);

    env.relay.as_mut().expect("a relay").unreachable = false;
    let (result, out) = setup_batch(&mut env, &files, true);
    assert!(result.is_ok(), "the same command again");
    assert_eq!(
        out.matches(": installed").count(),
        2,
        "setup setup.kqpkg update.kqpkg --yes, again"
    );
    assert_eq!(ledger_state(&env, &setup).as_deref(), Some("complete"));
    assert_eq!(ledger_state(&env, &update).as_deref(), Some("complete"));
}

#[test]
fn packages_naming_different_default_relays_are_refused_before_any_write() {
    let mut env = alice();
    let setup = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let relay = env.relay.as_ref().expect("a relay");
    let recipient = Recipient {
        relay_url: "https://other-relay.example.test/".into(),
        ..alice_recipient(&env)
    };
    let key = sealed_key_for(&env, recipient.clone());
    let elsewhere = package::issue_client_package(
        &relay.identity,
        &[key.as_slice()],
        &recipient.public_key,
        recipient.device_id,
        &package::ClientPackage {
            purpose: Purpose::ClientUpdate,
            generation: 2,
            ..setup_spec()
        },
    )
    .expect("issue");
    let files: [(&str, &[u8]); 2] = [("setup", &setup), ("elsewhere", &elsewhere)];
    let (result, _) = setup_batch(&mut env, &files, true);
    assert!(
        matches!(&result, Err(Error::KqpkgRefused(reason)) if reason.contains("default relays")),
        "setup setup.kqpkg elsewhere.kqpkg --yes"
    );
    untouched(&env, &[&setup, &elsewhere]);
}

#[test]
fn the_relay_step_runs_again_when_the_profile_names_another_slot() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    setup_file(&mut env, "profile", &bytes, true).expect("setup profile.kqpkg --yes");
    // The profile is moved to another slot on the same relay, and the package
    // is left pending as if the run stopped before its last step was marked.
    db::profile::set(env.store(DB), db::profile::DEFAULT_SLOT_LABEL, "bob").expect("set");
    let id = hex::encode(package::decode(&bytes).unwrap().id);
    env.store(DB)
        .execute(
            "UPDATE package_installs SET state = 'pending', steps_done = '' WHERE package_id = ?1",
            [&id],
        )
        .unwrap();
    setup_file(&mut env, "profile", &bytes, true).expect("setup profile.kqpkg --yes, again");
    assert_eq!(
        db::profile::get(env.store(DB), db::profile::DEFAULT_SLOT_LABEL)
            .expect("profile")
            .as_deref(),
        Some("alice"),
        "setup profile.kqpkg --yes restores the approved slot"
    );
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
}

// --- the database-only relay step is one transaction (issue #106) ---------

/// A failure partway through the default profile's writes (after the relay
/// URL, before the label) rolls the partial write back, and the step is not
/// marked; running the same package again finishes it.
#[test]
fn a_use_step_that_fails_mid_profile_write_rolls_back_and_reruns() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let url_before = db::profile::get(env.store(DB), db::profile::DEFAULT_RELAY_URL).expect("url");
    env.store(DB)
        .execute_batch(
            "CREATE TRIGGER fail_label_insert BEFORE INSERT ON profile
               WHEN NEW.key = 'default_label' BEGIN SELECT RAISE(ABORT, 'injected'); END;
             CREATE TRIGGER fail_label_update BEFORE UPDATE ON profile
               WHEN NEW.key = 'default_label' BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .expect("triggers");
    assert!(
        setup_file(&mut env, "mid-profile", &bytes, true).is_err(),
        "setup profile.kqpkg --yes, the label write fails"
    );
    assert_eq!(
        db::profile::get(env.store(DB), db::profile::DEFAULT_RELAY_URL).expect("url"),
        url_before,
        "the relay URL written before the failure is rolled back"
    );
    let record = db::package_ledger::record(
        env.store(DB),
        &hex::encode(package::decode(&bytes).unwrap().id),
    )
    .expect("ledger")
    .expect("a record");
    assert!(
        !record.steps_done.iter().any(|done| done == "relay"),
        "the use step is not marked done"
    );
    env.store(DB)
        .execute_batch("DROP TRIGGER fail_label_insert; DROP TRIGGER fail_label_update;")
        .expect("drop triggers");
    setup_file(&mut env, "mid-profile", &bytes, true).expect("setup profile.kqpkg --yes, again");
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
    assert!(
        db::profile::get(env.store(DB), db::profile::DEFAULT_RELAY_URL)
            .expect("url")
            .is_some(),
        "the rerun sets the relay URL"
    );
}

/// A failure while recording the use step's completion rolls back the profile
/// change it was made with, so the two are never split.
#[test]
fn a_use_step_whose_completion_mark_fails_leaves_no_profile_change() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    let url_before = db::profile::get(env.store(DB), db::profile::DEFAULT_RELAY_URL).expect("url");
    env.store(DB)
        .execute_batch(
            "CREATE TRIGGER fail_relay_mark BEFORE UPDATE ON package_installs
               WHEN NEW.steps_done LIKE '%relay%' AND OLD.steps_done NOT LIKE '%relay%'
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .expect("trigger");
    assert!(
        setup_file(&mut env, "mark-fails", &bytes, true).is_err(),
        "setup mark-fails.kqpkg --yes, recording the use step fails"
    );
    assert_eq!(
        db::profile::get(env.store(DB), db::profile::DEFAULT_RELAY_URL).expect("url"),
        url_before,
        "the profile change is rolled back with its mark"
    );
    env.store(DB)
        .execute_batch("DROP TRIGGER fail_relay_mark;")
        .expect("drop trigger");
    setup_file(&mut env, "mark-fails", &bytes, true).expect("setup mark-fails.kqpkg --yes, again");
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
}

/// Makes recording `step` fail, as a crash between its verified effect and
/// its completion mark would leave things.
fn fail_marking(env: &MemoryEnv, step: &str) {
    env.store(DB)
        .execute_batch(&format!(
            "CREATE TRIGGER fail_mark BEFORE UPDATE ON package_installs
               WHEN NEW.steps_done LIKE '%{step}%' AND OLD.steps_done NOT LIKE '%{step}%'
             BEGIN SELECT RAISE(ABORT, 'injected'); END;"
        ))
        .expect("trigger");
}

fn steps_done(env: &MemoryEnv, package: &[u8]) -> Vec<String> {
    let id = hex::encode(package::decode(package).expect("decode").id);
    db::package_ledger::record(env.store(DB), &id)
        .expect("ledger")
        .expect("a ledger row")
        .steps_done
}

#[test]
fn a_crash_between_the_certificate_file_and_its_mark_is_finished_without_a_second_write() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    fail_marking(&env, "certificate");
    assert!(
        setup_file(&mut env, "cert-crash", &bytes, true).is_err(),
        "setup cert-crash.kqpkg --yes, recording the certificate step fails"
    );
    // The file is on the drive but the ledger does not say so.
    let written = env
        .fs
        .read(Path::new(CERTIFICATE))
        .expect("the certificate");
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("pending"));
    assert!(!steps_done(&env, &bytes).iter().any(|s| s == "certificate"));
    assert!(stored_key(&env).is_none());

    env.store(DB)
        .execute_batch("DROP TRIGGER fail_mark;")
        .expect("drop trigger");
    let out = setup_file(&mut env, "cert-crash", &bytes, true)
        .expect("setup cert-crash.kqpkg --yes again");
    assert!(
        !out.contains("Wrote relay certificate"),
        "setup cert-crash.kqpkg --yes writes the certificate once"
    );
    assert_eq!(
        env.fs.read(Path::new(CERTIFICATE)).expect("certificate"),
        written
    );
    assert!(steps_done(&env, &bytes).iter().any(|s| s == "certificate"));
    assert!(stored_key(&env).is_some());
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
}

#[test]
fn a_crash_between_the_stored_key_and_its_mark_is_finished_without_a_second_key_check() {
    let mut env = alice();
    let bytes = manifest_package_with(&env, Purpose::ClientSetup, 1);
    fail_marking(&env, "key-1");
    assert!(
        setup_file(&mut env, "key-crash", &bytes, true).is_err(),
        "setup key-crash.kqpkg --yes, recording the key step fails"
    );
    // The relay checked the key and it is stored, but the ledger does not say so.
    assert!(stored_key(&env).is_some());
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("pending"));
    assert!(!steps_done(&env, &bytes).iter().any(|s| s == "key-1"));
    let checks = env.relay.as_ref().expect("a relay").key_checks;

    env.store(DB)
        .execute_batch("DROP TRIGGER fail_mark;")
        .expect("drop trigger");
    setup_file(&mut env, "key-crash", &bytes, true).expect("setup key-crash.kqpkg --yes again");
    assert_eq!(
        env.relay.as_ref().expect("a relay").key_checks,
        checks,
        "the stored key is recognised, not sent to the relay again"
    );
    let count: i64 = env
        .store(DB)
        .query_row("SELECT COUNT(*) FROM relay_credentials", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(count, 1, "one relay credential");
    assert!(steps_done(&env, &bytes).iter().any(|s| s == "key-1"));
    assert_eq!(ledger_state(&env, &bytes).as_deref(), Some("complete"));
}
