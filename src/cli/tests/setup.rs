use super::memory_env::{MemoryEnv, RELAY_URL};
use crate::relay::ApiKeyScope;

const DB: &str = "keyquorum --db /home/alice/keyquorum.sqlite";

fn ok(env: &mut MemoryEnv, line: &str) -> String {
    let (result, out) = env.keyquorum(line);
    assert!(result.is_ok(), "{line}: the command failed");
    out
}

#[test]
fn setup_takes_nothing_to_a_working_identity_in_one_command() {
    let mut env = MemoryEnv::default();
    let out = ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    for step in [
        "Initialized /usb/alice device",
        "Provisioned slot alice",
        "Registered encryption key for alice",
        "Registered signing key for alice",
        "Bound alice to device",
        "default_container = /usb/alice",
        "default_label = alice",
    ] {
        assert!(out.contains(step), "{step}: {out}");
    }
    let doctor = ok(&mut env, &format!("{DB} doctor"));
    assert!(doctor.contains("Everything checks out."), "{doctor}");
    assert!(
        doctor.contains("slot alice is in the container"),
        "{doctor}"
    );
}

#[test]
fn setup_can_be_run_again_and_skips_what_is_done() {
    let mut env = MemoryEnv::default();
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    let again = ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    assert!(
        again.contains("Slot alice already exists; keeping it"),
        "{again}"
    );
    assert!(!again.contains("Registered"), "{again}");
    assert!(!again.contains("Initialized"), "{again}");
    assert!(again.contains("Bound alice"), "{again}");
}

#[test]
fn setup_refuses_to_shadow_a_different_key_registered_for_the_label() {
    let mut env = MemoryEnv::default();
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/one --label alice"),
    );
    let (result, _) = env.keyquorum(&format!("{DB} setup --device /usb/two --label alice"));
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("a different encryption key is already registered"),
        "{message}"
    );
}

#[test]
fn setup_with_a_relay_loads_its_key_and_doctor_asks_for_the_other() {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-02 12:00".into());
    let push = env.relay_key(ApiKeyScope::InboxPush, None);
    let out = ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice --url {RELAY_URL} --api-key {push}"),
    );
    assert!(out.contains("Stored inbox.push API key"), "{out}");
    assert!(
        out.contains(&format!("default_relay_url = {RELAY_URL}")),
        "{out}"
    );
    let (result, doctor) = env.keyquorum(&format!("{DB} doctor"));
    assert!(
        doctor.contains("ok    a inbox.push key is loaded for sending"),
        "{doctor}"
    );
    assert!(
        doctor.contains("FIX   no inbox.pull key is loaded for receiving"),
        "{doctor}"
    );
    assert!(
        doctor.contains(&format!("keyquorum loadkey --url {RELAY_URL}")),
        "{doctor}"
    );
    assert!(result.unwrap_err().to_string().contains("1 problem found"));
}

#[test]
fn doctor_checks_the_relay_the_commands_use() {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-02 12:00".into());
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    ok(&mut env, &format!("{DB} use --url https://profile.test"));
    // Commands prefer KEYQUORUM_RELAY_URL over the stored default; so must doctor.
    env.vars
        .insert("KEYQUORUM_RELAY_URL".into(), "https://env.test".into());
    let (_, out) = env.keyquorum(&format!("{DB} doctor"));
    assert!(out.contains("ok    relay https://env.test"), "{out}");
    assert!(!out.contains("profile.test"), "{out}");
}

#[test]
fn loadkey_uses_the_stored_relay_when_no_url_is_given() {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-02 12:00".into());
    env.vars.remove("KEYQUORUM_RELAY_URL");
    let push = env.relay_key(ApiKeyScope::InboxPush, None);
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    ok(&mut env, &format!("{DB} use --url {RELAY_URL}"));
    let out = ok(&mut env, &format!("{DB} loadkey {push}"));
    assert!(out.contains("Stored inbox.push API key"), "{out}");
    let (result, _) = env.keyquorum(&format!("keyquorum --db /home/none.sqlite loadkey {push}"));
    let message = result.unwrap_err().to_string();
    assert!(message.contains("keyquorum use --url"), "{message}");
}

#[test]
fn an_existing_key_is_reused_only_for_the_same_label_kind_and_when_active() {
    use crate::keys::{self, KeyType};
    let conn = crate::db::open_in_memory().unwrap();
    let public = [7u8; 32];
    let id = keys::register_key(&conn, "alice", KeyType::Encryption, &public).unwrap();
    let ensure =
        |label: &str, kind| super::super::setup::ensure_registered(&conn, label, kind, &public);
    assert!(!ensure("alice", KeyType::Encryption).unwrap(), "reused");
    assert!(ensure("bob", KeyType::Encryption).is_err(), "other label");
    assert!(ensure("alice", KeyType::Signing).is_err(), "other kind");
    keys::revoke_key(&conn, id).unwrap();
    assert!(ensure("alice", KeyType::Encryption).is_err(), "revoked");
}

#[test]
fn doctor_with_nothing_set_says_how_to_start() {
    let mut env = MemoryEnv::default();
    let (result, out) = env.keyquorum(&format!("{DB} doctor"));
    assert!(out.contains("FIX   no default identity is set"), "{out}");
    assert!(
        out.contains("keyquorum setup --device PATH --label LABEL"),
        "{out}"
    );
    assert!(result.is_err());
}

#[test]
fn doctor_finds_an_unregistered_recipient_and_an_unplugged_device() {
    let mut env = MemoryEnv::default();
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    let (result, out) = env.keyquorum(&format!("{DB} doctor --to bob"));
    assert!(result.is_err());
    assert!(
        out.contains("FIX   no encryption key is registered for bob"),
        "{out}"
    );

    // Same store, but the container is gone (the device is not plugged in).
    env.fs = crate::storage::MemoryStorage::default();
    let (result, out) = env.keyquorum(&format!("{DB} doctor"));
    assert!(result.is_err());
    assert!(out.contains("cannot be opened"), "{out}");
    assert!(out.contains("plug the device in"), "{out}");
}

#[test]
fn doctor_does_not_call_a_slot_bound_when_the_placement_is_another_device() {
    let mut env = MemoryEnv::default();
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    let db = DB.trim_start_matches("keyquorum --db ");
    let (_, out) = env.keyquorum(&format!("{DB} doctor --no-cache"));
    assert!(out.contains("the slot is bound to its device"), "{out}");

    env.store(db)
        .execute(
            "UPDATE device_placements SET device_id = x'00000000000000000000000000000001'",
            [],
        )
        .unwrap();
    let (result, out) = env.keyquorum(&format!("{DB} doctor --no-cache"));
    assert!(result.is_err(), "{out}");
    assert!(!out.contains("the slot is bound to its device"), "{out}");
}

#[test]
fn doctor_remembers_a_passed_slot_check_until_the_container_changes() {
    let mut env = MemoryEnv::default();
    env.now = Some("2026-10-02 12:00".into());
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    let first = ok(&mut env, &format!("{DB} doctor"));
    assert!(
        first.contains("slot alice is in the container (checked recently)"),
        "setup recorded it: {first}"
    );

    env.now = Some("2026-10-02 12:20".into());
    let stale = ok(&mut env, &format!("{DB} doctor"));
    assert!(!stale.contains("checked recently"), "{stale}");
    let fresh = ok(&mut env, &format!("{DB} doctor"));
    assert!(fresh.contains("checked recently"), "{fresh}");

    // A second slot rewrites the container descriptor, so the old note is void.
    env.device("keyquorum-device provision /usb/alice --label other")
        .0
        .unwrap();
    let changed = ok(&mut env, &format!("{DB} doctor"));
    assert!(!changed.contains("checked recently"), "{changed}");

    let off = ok(&mut env, &format!("{DB} --no-cache doctor"));
    assert!(!off.contains("checked recently"), "{off}");
    assert!(off.contains("caching is off"), "{off}");
}

#[test]
fn device_provision_register_replaces_provision_register_and_bind() {
    let mut env = MemoryEnv::default();
    env.device("keyquorum-device init /usb/alice").0.unwrap();
    let out = ok(
        &mut env,
        &format!("{DB} device provision /usb/alice --label alice --register"),
    );
    assert!(out.contains("Registered encryption key for alice"), "{out}");
    assert!(out.contains("Registered signing key for alice"), "{out}");
    assert!(out.contains("Bound alice to device"), "{out}");
    ok(
        &mut env,
        &format!("{DB} use --device /usb/alice --slot alice"),
    );
    let doctor = ok(&mut env, &format!("{DB} doctor"));
    assert!(
        doctor.contains("the slot is bound to its device"),
        "{doctor}"
    );

    // Without the flag nothing is registered, exactly as before.
    env.device("keyquorum-device init /usb/bob").0.unwrap();
    let plain = ok(
        &mut env,
        &format!("{DB} device provision /usb/bob --label bob"),
    );
    assert!(!plain.contains("Registered"), "{plain}");
}

#[test]
fn relay_finalize_finds_its_destination_or_says_why_it_cannot() {
    let mut env = MemoryEnv::default();
    ok(
        &mut env,
        &format!("{DB} setup --device /usb/alice --label alice"),
    );
    let finalize = format!(
        "{DB} transfer relay-finalize --from-device /usb/alice --from-db /home/alice/keyquorum.sqlite --slot alice"
    );
    let (result, _) = env.keyquorum(&finalize);
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("no transfer is waiting"));

    let conn = env.store("/home/alice/keyquorum.sqlite");
    for (id, peer) in [(1u8, 7u8), (2, 9)] {
        conn.execute(
            "INSERT INTO transfer_transactions
                (id, operation, role, state, peer_device_id, root_label,
                 descendant_mode, package_hash, detail)
             VALUES (?1, 'move', 'source', 'prepared', ?2, 'alice', 'key-only', ?3, '')",
            rusqlite::params![vec![id; 16], vec![peer; 16], vec![0u8; 32]],
        )
        .unwrap();
    }
    let (result, _) = env.keyquorum(&finalize);
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("transfers are waiting on 2 destinations"),
        "{message}"
    );
    assert!(message.contains(&hex::encode([7u8; 16])), "{message}");

    env.store("/home/alice/keyquorum.sqlite")
        .execute(
            "DELETE FROM transfer_transactions WHERE id = ?1",
            [vec![2u8; 16]],
        )
        .unwrap();
    let (result, _) = env.keyquorum(&finalize);
    // One candidate: it is used, and the next thing to fail is the relay.
    let message = result.unwrap_err().to_string();
    assert!(!message.contains("waiting"), "{message}");
}
