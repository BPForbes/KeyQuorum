use super::memory_env::{MemoryEnv, RELAY_URL};
use crate::keys::{self, KeyType};
use crate::relay::ApiKeyScope;
use crate::storage::Storage;
use std::path::Path;

const ALICE: &str = "keyquorum --db /home/alice/keyquorum.sqlite";
const BOB: &str = "keyquorum --db /home/bob/keyquorum.sqlite";

fn run(env: &mut MemoryEnv, line: &str) -> String {
    let (ok, out) = env.keyquorum(line);
    assert!(ok.is_ok(), "{line}: {ok:?}");
    out
}

fn fingerprint_of(env: &MemoryEnv, db: &str, label: &str) -> String {
    let key = keys::active_keys_for(env.store(db), label, KeyType::Encryption)
        .unwrap()
        .remove(0);
    keys::fingerprint(&key.public_key)
}

/// Alice and Bob: containers, each other's keys registered, defaults set,
/// and relay keys loaded (push for both; pull bound to each one's own key).
fn two_people_on_a_relay() -> MemoryEnv {
    let mut env = MemoryEnv::with_relay();
    env.now = Some("2026-10-02 12:00".into());
    for who in ["alice", "bob"] {
        env.device(&format!("keyquorum-device init /usb/{who}"))
            .0
            .unwrap();
        env.device(&format!(
            "keyquorum-device provision /usb/{who} --label {who}"
        ))
        .0
        .unwrap();
    }
    for (store, db) in [("alice", ALICE), ("bob", BOB)] {
        for owner in ["alice", "bob"] {
            for kind in ["encryption", "signing"] {
                run(
                    &mut env,
                    &format!("{db} device register /usb/{owner} --slot {owner} --type {kind}"),
                );
            }
        }
        run(
            &mut env,
            &format!("{db} use --device /usb/{store} --slot {store}"),
        );
    }
    for (db, who) in [(ALICE, "alice"), (BOB, "bob")] {
        let push = env.relay_key(ApiKeyScope::InboxPush, None);
        run(&mut env, &format!("{db} loadkey {push} --url {RELAY_URL}"));
        let fingerprint = fingerprint_of(&env, &db["keyquorum --db ".len()..], who);
        let pull = env.relay_key(ApiKeyScope::InboxPull, Some(fingerprint));
        run(&mut env, &format!("{db} loadkey {pull} --url {RELAY_URL}"));
    }
    env.fs
        .write_new(Path::new("/home/alice/note.txt"), b"lunch at noon")
        .unwrap();
    env
}

fn stderr(env: &MemoryEnv) -> String {
    String::from_utf8_lossy(&env.stderr).to_string()
}

#[test]
fn send_then_inbox_open_delivers_the_file_and_the_answer_comes_back() {
    let mut env = two_people_on_a_relay();
    let out = run(
        &mut env,
        &format!("{ALICE} send /home/alice/note.txt --to bob"),
    );
    assert!(out.contains("Sealed note.txt to bob"), "{out}");
    assert!(out.contains("Relay stored letter"), "{out}");

    let listed = run(&mut env, &format!("{BOB} inbox"));
    assert!(listed.contains("file delivery"), "{listed}");
    assert!(listed.contains("keyquorum inbox open"), "{listed}");

    let opened = run(&mut env, &format!("{BOB} inbox open"));
    assert!(
        opened.contains("Saved note.txt to received/note.txt"),
        "{opened}"
    );
    assert!(
        opened.contains("Relay stored letter"),
        "the answer is posted: {opened}"
    );
    assert_eq!(
        env.fs.read(Path::new("received/note.txt")).unwrap(),
        b"lunch at noon"
    );

    let answered = run(&mut env, &format!("{ALICE} inbox open"));
    assert!(answered.contains(" accepted by bob"), "{answered}");
}

#[test]
fn a_letter_is_opened_once_and_a_later_pull_resumes_after_it() {
    let mut env = two_people_on_a_relay();
    run(
        &mut env,
        &format!("{ALICE} send /home/alice/note.txt --to bob"),
    );
    run(&mut env, &format!("{BOB} inbox open"));
    let again = run(&mut env, &format!("{BOB} inbox open"));
    assert!(again.contains("(nothing waiting)"), "{again}");
    let listed = run(&mut env, &format!("{BOB} inbox"));
    assert!(listed.contains("(nothing waiting)"), "{listed}");

    env.fs
        .write_new(Path::new("/home/alice/two.txt"), b"second")
        .unwrap();
    run(
        &mut env,
        &format!("{ALICE} send /home/alice/two.txt --to bob"),
    );
    let next = run(&mut env, &format!("{BOB} inbox open"));
    assert!(next.contains("Saved two.txt to received/two.txt"), "{next}");
    assert!(
        !next.contains("note.txt"),
        "the first letter is not opened again: {next}"
    );
}

#[test]
fn reject_refuses_the_file_and_says_so_in_the_answer() {
    let mut env = two_people_on_a_relay();
    run(
        &mut env,
        &format!("{ALICE} send /home/alice/note.txt --to bob"),
    );
    run(&mut env, &format!("{BOB} inbox open --reject"));
    assert!(!env.fs.exists(Path::new("received/note.txt")));
    let answered = run(&mut env, &format!("{ALICE} inbox open"));
    assert!(answered.contains(" rejected by bob"), "{answered}");
}

#[test]
fn answers_can_go_to_a_directory_instead_of_the_relay() {
    let mut env = two_people_on_a_relay();
    run(
        &mut env,
        &format!("{ALICE} send /home/alice/note.txt --to bob"),
    );
    let opened = run(&mut env, &format!("{BOB} inbox open --ack-dir /acks"));
    assert!(opened.contains("Wrote /acks/"), "{opened}");
    assert!(!opened.contains("Relay stored letter"), "{opened}");
}

#[test]
fn send_without_a_relay_writes_to_the_outbox_and_offline_forces_it() {
    let mut env = two_people_on_a_relay();
    let out = run(
        &mut env,
        &format!("{ALICE} send /home/alice/note.txt --to bob --offline"),
    );
    assert!(out.contains("Wrote outbox/"), "{out}");
    assert!(!out.contains("Relay stored letter"), "{out}");

    // A person with no relay at all gets the outbox, and a note saying why.
    let mut bare = MemoryEnv::default();
    for who in ["alice", "bob"] {
        bare.device(&format!("keyquorum-device init /usb/{who}"))
            .0
            .unwrap();
        bare.device(&format!(
            "keyquorum-device provision /usb/{who} --label {who}"
        ))
        .0
        .unwrap();
    }
    for (owner, kind) in [
        ("alice", "signing"),
        ("alice", "encryption"),
        ("bob", "encryption"),
    ] {
        run(
            &mut bare,
            &format!("{ALICE} device register /usb/{owner} --slot {owner} --type {kind}"),
        );
    }
    run(
        &mut bare,
        &format!("{ALICE} use --device /usb/alice --slot alice"),
    );
    bare.fs
        .write_new(Path::new("/home/alice/note.txt"), b"x")
        .unwrap();
    let out = run(
        &mut bare,
        &format!("{ALICE} send /home/alice/note.txt --to bob"),
    );
    assert!(out.contains("Wrote outbox/"), "{out}");
    assert!(
        stderr(&bare).contains("no relay is set up"),
        "{}",
        stderr(&bare)
    );
}

#[test]
fn send_reports_invalid_relay_configuration_instead_of_going_offline() {
    let mut env = two_people_on_a_relay();
    let (result, out) = env.keyquorum(&format!(
        "{ALICE} send /home/alice/note.txt --to bob --url not-a-url"
    ));
    assert!(result.is_err());
    assert!(!out.contains("Wrote outbox/"), "{out}");
    assert!(!stderr(&env).contains("no relay is set up"));
}

#[test]
fn the_profile_relay_wins_over_a_single_credential_for_another_relay() {
    let mut env = two_people_on_a_relay();
    run(
        &mut env,
        &format!("{ALICE} use --url https://preferred.test"),
    );
    let conn = env.store("/home/alice/keyquorum.sqlite");
    assert_eq!(
        super::super::configured_relay_url(conn, None, ApiKeyScope::InboxPush).unwrap(),
        Some("https://preferred.test".into())
    );
}

#[test]
fn letter_paths_are_namespaced_by_relay() {
    let dir = Path::new("inbox");
    let first = super::super::inbox::letter_path(dir, "https://one.test", 1);
    let second = super::super::inbox::letter_path(dir, "https://two.test", 1);
    assert_ne!(first, second);
    assert_eq!(first.file_name().unwrap(), "1.kqpb");
    assert_eq!(second.file_name().unwrap(), "1.kqpb");
}

#[test]
fn a_tracked_file_goes_through_file_share_not_deliver() {
    let mut env = two_people_on_a_relay();
    // The magic is what picks the sender; this is not a valid container, so
    // file share is the one that refuses it.
    env.fs
        .write_new(Path::new("/home/alice/not-really.kqtf"), b"KQTFjunk")
        .unwrap();
    let (ok, out) = env.keyquorum(&format!(
        "{ALICE} send /home/alice/not-really.kqtf --to bob --offline"
    ));
    assert!(ok.is_err());
    assert!(!out.contains("Sealed"), "{out}");
    let (ok, _) = env.keyquorum(&format!(
        "{ALICE} send /home/alice/not-really.kqtf --to bob --offline --name x"
    ));
    assert!(ok
        .unwrap_err()
        .to_string()
        .contains("--name does not apply"));
    let (ok, _) = env.keyquorum(&format!(
        "{ALICE} send /home/alice/note.txt --to bob --offline --revision abc"
    ));
    assert!(ok
        .unwrap_err()
        .to_string()
        .contains("--revision applies only"));
}

#[test]
fn legacy_commands_say_what_replaces_them_on_stderr_only() {
    let mut env = two_people_on_a_relay();
    let out = run(
        &mut env,
        &format!("{ALICE} deliver send --file /home/alice/note.txt --to bob --push"),
    );
    assert!(!out.contains("legacy"), "stdout is unchanged: {out}");
    let err = stderr(&env);
    assert!(
        err.contains("`keyquorum deliver send` is a legacy command")
            && err.contains("keyquorum send <file> --to <label>"),
        "{err}"
    );

    env.stderr.clear();
    run(&mut env, &format!("{BOB} inbox open"));
    run(
        &mut env,
        &format!("{ALICE} send /home/alice/note.txt --to bob"),
    );
    assert!(
        !stderr(&env).contains("legacy"),
        "the new commands never call themselves legacy: {}",
        stderr(&env)
    );
    run(&mut env, &format!("{BOB} relay pull --output-dir /mail"));
    assert!(stderr(&env).contains("`keyquorum relay pull` is a legacy command"));
}

/// Reaches the test relay without going through the environment.
struct Direct<'a>(&'a crate::relay::ProviderIdentity, &'a rusqlite::Connection);

impl crate::relay::RelayTransport for Direct<'_> {
    fn send(
        &self,
        request: crate::relay::RelayHttpRequest,
    ) -> crate::error::Result<crate::relay::RelayHttpResponse> {
        Ok(crate::relay::service::dispatch(
            self.1,
            Some(self.0),
            &request,
        ))
    }
}

#[test]
fn a_letter_that_asks_for_a_decision_is_listed_and_left_for_a_person() {
    let mut env = two_people_on_a_relay();
    let bob_key = keys::active_keys_for(
        env.store(&BOB["keyquorum --db ".len()..]),
        "bob",
        KeyType::Encryption,
    )
    .unwrap()
    .remove(0);
    let mut letter = Vec::new();
    letter.extend_from_slice(b"KQPB");
    letter.push(2);
    letter.push(crate::envelope::KIND_FILE_REQUEST);
    letter.extend_from_slice(&bob_key.public_key);
    letter.extend_from_slice(&4u32.to_be_bytes());
    letter.extend_from_slice(b"junk");
    let push = env.relay_key(ApiKeyScope::InboxPush, None);
    let relay = env.relay.as_ref().unwrap();
    crate::relay::push_inbox(
        &Direct(&relay.identity, &relay.conn),
        RELAY_URL,
        &push,
        &letter,
    )
    .expect("the relay stores the letter");

    let listed = run(&mut env, &format!("{BOB} inbox"));
    assert!(listed.contains("file or change request"), "{listed}");
    assert!(listed.contains("keyquorum inbox open"), "{listed}");
    assert!(listed.contains("--accept"), "{listed}");

    let opened = run(&mut env, &format!("{BOB} inbox open"));
    assert!(opened.contains("--accept"), "{opened}");
    // Left for a person, so it is still waiting afterwards.
    let again = run(&mut env, &format!("{BOB} inbox"));
    assert!(again.contains("file or change request"), "{again}");
}
