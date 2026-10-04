//! A relay key that arrives sealed: `loadkey --bundle` for a first key and
//! `inbox open` for a rotated one, against the in-process relay.

use super::memory_env::{MemoryEnv, RELAY_URL};
use crate::device;
use crate::error::Error;
use crate::keys::{self, KeyType};
use crate::relay::key_delivery::{self, Recipient};
use crate::relay::{self, ApiKeyScope, NewApiKey};
use crate::storage::Storage;
use crate::{db, test_secrets};
use std::path::Path;

const DB: &str = "/home/alice/keyquorum.sqlite";
const ALICE: &str = "keyquorum --db /home/alice/keyquorum.sqlite";
const BUNDLE: &str = "/home/alice/customer.kqkey";

fn run(env: &mut MemoryEnv, line: &str) -> String {
    let (ok, out) = env.keyquorum(line);
    assert!(ok.is_ok(), "{line}: the command failed");
    out
}

/// Alice with her own container registered and chosen, on a relay, with no
/// relay key loaded yet.
fn alice() -> MemoryEnv {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-04 12:00".into());
    env.device("keyquorum-device init /usb/alice").0.unwrap();
    env.device("keyquorum-device provision /usb/alice --label alice")
        .0
        .unwrap();
    for kind in ["encryption", "signing"] {
        run(
            &mut env,
            &format!("{ALICE} device register /usb/alice --slot alice --type {kind}"),
        );
    }
    run(
        &mut env,
        &format!("{ALICE} use --device /usb/alice --slot alice"),
    );
    env
}

fn alice_public_key(env: &MemoryEnv) -> [u8; 32] {
    keys::active_keys_for(env.store(DB), "alice", KeyType::Encryption)
        .unwrap()
        .remove(0)
        .public_key
        .try_into()
        .expect("an X25519 public key")
}

fn alice_device_id(env: &MemoryEnv) -> [u8; 16] {
    *device::open_in(&env.fs, Path::new("/usb/alice"))
        .expect("alice's container")
        .device_id()
}

fn recipient(env: &MemoryEnv, device_id: Option<[u8; 16]>) -> Recipient {
    Recipient {
        public_key: alice_public_key(env),
        relay_url: format!("{RELAY_URL}/"),
        device_id,
        licence: Some(format!(
            "Pull key for alice, licence {}",
            test_secrets::pin()
        )),
    }
}

fn pull_key() -> NewApiKey {
    NewApiKey {
        scope: ApiKeyScope::InboxPull,
        recipient_fingerprint: None,
        label: Some("alice".into()),
        ttl_seconds: None,
    }
}

/// The host writes a bundle for alice into her home; returns the key id.
fn issue_bundle(env: &mut MemoryEnv, recipient: &Recipient, path: &str) -> i64 {
    let relay = env.relay.as_ref().expect("a relay");
    let fs = &mut env.fs;
    key_delivery::create_as_bundle(
        &relay.conn,
        &relay.identity,
        &pull_key(),
        recipient,
        |bytes| fs.write_new(Path::new(path), bytes),
    )
    .expect("create_as_bundle")
    .info
    .id
}

fn stored_pull_key(env: &MemoryEnv) -> db::relay_credential::StoredRelayKey {
    db::relay_credential::get(env.store(DB), RELAY_URL, "inbox.pull")
        .expect("query")
        .expect("a stored inbox.pull key")
}

#[test]
fn a_first_key_loads_from_a_sealed_bundle_and_a_rotated_one_from_the_inbox() {
    let mut env = alice();
    let device_id = alice_device_id(&env);
    let recipient = recipient(&env, Some(device_id));
    let first = issue_bundle(&mut env, &recipient, BUNDLE);

    let out = run(&mut env, &format!("{ALICE} loadkey --bundle {BUNDLE}"));
    assert!(
        out.contains(&format!(
            "Stored inbox.pull API key {first} for {RELAY_URL} from a sealed bundle"
        )),
        "loadkey --bundle should report the stored key"
    );
    assert!(out.contains("Licence: Pull key for alice"));
    assert!(!out.contains("kq_"), "a bearer reached stdout");
    assert_eq!(stored_pull_key(&env).remote_id, Some(first));

    // The host rotates the key: the replacement waits in alice's mailbox.
    let relay = env.relay.as_ref().expect("a relay");
    let rotated = key_delivery::rotate_as_letter(&relay.conn, &relay.identity, first, None, 3_600)
        .expect("rotate_as_letter");
    let second = rotated.info.id;

    let listed = run(&mut env, &format!("{ALICE} inbox"));
    assert!(
        listed.contains("relay API key"),
        "inbox should list the key letter"
    );
    let opened = run(&mut env, &format!("{ALICE} inbox open"));
    assert!(
        opened.contains(&format!(
            "Stored inbox.pull API key {second} for {RELAY_URL} from a sealed letter"
        )),
        "inbox open should load the rotated key"
    );
    assert!(!opened.contains("kq_"), "a bearer reached stdout");
    assert_eq!(stored_pull_key(&env).remote_id, Some(second));

    // Only the new key is stored: with the old one revoked, pulls still work.
    let relay = env.relay.as_ref().expect("a relay");
    relay::revoke_api_key(&relay.conn, first).expect("revoke");
    run(&mut env, &format!("{ALICE} inbox"));
    let again = run(&mut env, &format!("{ALICE} inbox open"));
    assert!(
        !again.contains("from a sealed letter"),
        "a handled key letter is not loaded twice"
    );
}

#[test]
fn a_bundle_for_another_relay_or_device_or_key_is_refused_and_nothing_is_stored() {
    let mut env = alice();
    let device_id = alice_device_id(&env);

    let hers = recipient(&env, Some(device_id));
    issue_bundle(&mut env, &hers, BUNDLE);
    let (result, _) = env.keyquorum(&format!(
        "{ALICE} loadkey --bundle {BUNDLE} --url https://other.test"
    ));
    assert!(matches!(result, Err(Error::KeyIssueRelayMismatch)));

    let other_device = "/home/alice/other-device.kqkey";
    let elsewhere = recipient(&env, Some([7u8; 16]));
    issue_bundle(&mut env, &elsewhere, other_device);
    let (result, _) = env.keyquorum(&format!("{ALICE} loadkey --bundle {other_device}"));
    assert!(matches!(result, Err(Error::KeyIssueDeviceMismatch)));

    let (_, stranger) = keys::generate_encryption_keypair();
    let for_stranger = "/home/alice/stranger.kqkey";
    let mut not_hers = recipient(&env, None);
    not_hers.public_key = stranger;
    issue_bundle(&mut env, &not_hers, for_stranger);
    let (result, _) = env.keyquorum(&format!("{ALICE} loadkey --bundle {for_stranger}"));
    assert!(matches!(result, Err(Error::InvalidKeyIssue)));

    assert!(
        db::relay_credential::get(env.store(DB), RELAY_URL, "inbox.pull")
            .expect("query")
            .is_none(),
        "a refused bundle stores nothing"
    );
}

#[test]
fn a_bundle_signed_by_another_authorized_relay_is_refused_before_any_bearer_is_sent() {
    let mut env = alice();
    let device_id = alice_device_id(&env);
    let hers = recipient(&env, Some(device_id));

    // A second relay the same root vouches for signs the issue; the relay that
    // answers at the URL is the first. Both certificates are valid.
    let other = env.other_relay_identity();
    let relay = env.relay.as_ref().expect("a relay");
    let fs = &mut env.fs;
    key_delivery::create_as_bundle(&relay.conn, &other, &pull_key(), &hers, |bytes| {
        fs.write_new(Path::new(BUNDLE), bytes)
    })
    .expect("create_as_bundle");

    let (result, _) = env.keyquorum(&format!("{ALICE} loadkey --bundle {BUNDLE}"));
    assert!(matches!(result, Err(Error::KeyIssueRelayMismatch)));
    let relay = env.relay.as_ref().expect("a relay");
    assert!(
        relay.identity_challenges >= 1,
        "the relay was challenged first"
    );
    assert_eq!(
        relay.key_checks, 0,
        "no request carrying the bearer was sent"
    );
    assert!(
        db::relay_credential::get(env.store(DB), RELAY_URL, "inbox.pull")
            .expect("query")
            .is_none(),
        "a refused bundle stores nothing"
    );

    // The same recipient's bundle from the relay that answers loads, and only
    // that load sends a key check.
    let right = "/home/alice/right.kqkey";
    let hers = recipient(&env, Some(device_id));
    issue_bundle(&mut env, &hers, right);
    run(&mut env, &format!("{ALICE} loadkey --bundle {right}"));
    assert_eq!(env.relay.as_ref().expect("a relay").key_checks, 1);
}

#[test]
fn a_bundle_sealed_to_a_key_file_loads_without_a_device_when_it_is_not_bound() {
    let mut env = alice();
    let (secret, public) = keys::generate_encryption_keypair();
    env.fs
        .write_new(
            Path::new("/home/alice/laptop.key"),
            hex::encode(*secret).as_bytes(),
        )
        .unwrap();
    let mut recipient = recipient(&env, None);
    recipient.public_key = public;
    recipient.licence = None;
    let relay = env.relay.as_ref().expect("a relay");
    let fs = &mut env.fs;
    let id = key_delivery::create_as_bundle(
        &relay.conn,
        &relay.identity,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: None,
        },
        &recipient,
        |bytes| fs.write_new(Path::new(BUNDLE), bytes),
    )
    .expect("create_as_bundle")
    .info
    .id;

    let out = run(
        &mut env,
        &format!("{ALICE} loadkey --bundle {BUNDLE} --share-file /home/alice/laptop.key"),
    );
    assert!(out.contains(&format!("Stored inbox.push API key {id}")));
    assert!(!out.contains("Licence:"));
    let stored = db::relay_credential::get(env.store(DB), RELAY_URL, "inbox.push")
        .expect("query")
        .expect("a stored inbox.push key");
    assert_eq!(stored.remote_id, Some(id));
}
