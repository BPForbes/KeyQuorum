use super::super::memory_env::MemoryEnv;
use crate::storage::Storage;
use clap::Parser;
use std::path::Path;

/// Alice and Bob each have their own container and store. Each store
/// registers the other's public keys through `keyquorum device register`.
fn two_people() -> MemoryEnv {
    let mut env = MemoryEnv::default();
    for (who, peer) in [("alice", "bob"), ("bob", "alice")] {
        assert!(env
            .device(&format!("keyquorum-device init /usb/{who}"))
            .0
            .is_ok());
        let (ok, out) = env.device(&format!(
            "keyquorum-device provision /usb/{who} --label {who}"
        ));
        assert!(ok.is_ok(), "the command failed");
        assert!(out.starts_with(&format!("slot {who}")));
        let _ = peer;
    }
    for (store, owner) in [
        ("alice", "alice"),
        ("alice", "bob"),
        ("bob", "bob"),
        ("bob", "alice"),
    ] {
        for kind in ["encryption", "signing"] {
            let (ok, _) = env.keyquorum(&format!(
                "keyquorum --db /home/{store}/keyquorum.sqlite device register /usb/{owner} --slot {owner} --type {kind}"
            ));
            assert!(ok.is_ok(), "the command failed");
        }
    }
    env.fs
        .write_new(Path::new("/home/alice/note.txt"), b"lunch at noon")
        .unwrap();
    env
}

fn only_file(env: &MemoryEnv, dir: &str) -> String {
    let files = env.fs.list(Path::new(dir)).unwrap_or_default();
    assert_eq!(files.len(), 1, "{dir}: {files:?}");
    files[0].display().to_string()
}

#[test]
fn send_open_and_acknowledge_a_letter() {
    let mut env = two_people();
    let (ok, out) = env.keyquorum(
        "keyquorum --db /home/alice/keyquorum.sqlite deliver send --file /home/alice/note.txt \
         --to bob --as alice --slot /usb/alice=alice --output-dir /outbox",
    );
    assert!(ok.is_ok(), "the command failed");
    assert!(out.starts_with("Sealed note.txt to bob (delivery "));
    let letter = only_file(&env, "/outbox");

    let (ok, out) = env.keyquorum(&format!(
        "keyquorum --db /home/bob/keyquorum.sqlite deliver open --file {letter} \
         --slot /usb/bob=bob --save /home/bob/note.txt --ack-dir /acks"
    ));
    assert!(ok.is_ok(), "the command failed");
    assert!(out.starts_with("Saved note.txt to /home/bob/note.txt"));
    assert_eq!(
        env.fs.read(Path::new("/home/bob/note.txt")).unwrap(),
        b"lunch at noon"
    );
    let ack = only_file(&env, "/acks");
    assert!(ack.ends_with("-ack.kqpb"));

    let (ok, out) = env.keyquorum(&format!(
        "keyquorum --db /home/alice/keyquorum.sqlite deliver ack --file {ack} --slot /usb/alice=alice"
    ));
    assert!(ok.is_ok(), "the command failed");
    assert!(out.contains(" accepted by bob"), "{out}");
}

#[test]
fn a_rejection_is_signed_and_reported() {
    let mut env = two_people();
    env.keyquorum(
        "keyquorum --db /home/alice/keyquorum.sqlite deliver send --file /home/alice/note.txt \
         --to bob --as alice --slot /usb/alice=alice --output-dir /outbox",
    )
    .0
    .unwrap();
    let letter = only_file(&env, "/outbox");
    let (ok, _) = env.keyquorum(&format!(
        "keyquorum --db /home/bob/keyquorum.sqlite deliver open --file {letter} \
         --slot /usb/bob=bob --reject --ack-dir /acks"
    ));
    assert!(ok.is_ok(), "the command failed");
    assert!(!env.fs.exists(Path::new("/home/bob/note.txt")));
    let ack = only_file(&env, "/acks");
    let (_, out) = env.keyquorum(&format!(
        "keyquorum --db /home/alice/keyquorum.sqlite deliver ack --file {ack} --slot /usb/alice=alice"
    ));
    assert!(out.contains(" rejected by bob"), "{out}");
}

#[test]
fn a_letter_from_an_unregistered_sender_does_not_open() {
    let mut env = two_people();
    // Carol exists only in Alice's store; Bob has never registered her.
    env.device("keyquorum-device init /usb/carol").0.unwrap();
    env.device("keyquorum-device provision /usb/carol --label carol")
        .0
        .unwrap();
    env.fs
        .write_new(Path::new("/home/carol/x.txt"), b"hello")
        .unwrap();
    for kind in ["encryption", "signing"] {
        env.keyquorum(&format!(
            "keyquorum --db /home/carol/keyquorum.sqlite device register /usb/bob --slot bob --type {kind}"
        ))
        .0
        .unwrap();
        env.keyquorum(&format!(
            "keyquorum --db /home/carol/keyquorum.sqlite device register /usb/carol --slot carol --type {kind}"
        ))
        .0
        .unwrap();
    }
    env.keyquorum(
        "keyquorum --db /home/carol/keyquorum.sqlite deliver send --file /home/carol/x.txt \
         --to bob --as carol --slot /usb/carol=carol --output-dir /outbox",
    )
    .0
    .unwrap();
    let letter = only_file(&env, "/outbox");
    let (ok, _) = env.keyquorum(&format!(
        "keyquorum --db /home/bob/keyquorum.sqlite deliver open --file {letter} \
         --slot /usb/bob=bob --save /home/bob/x.txt --ack-dir /acks"
    ));
    assert!(ok.is_err());
    assert!(!env.fs.exists(Path::new("/home/bob/x.txt")));
    assert!(env
        .fs
        .list(Path::new("/acks"))
        .unwrap_or_default()
        .is_empty());
}

const ALICE_DB: &str = "keyquorum --db /home/alice/keyquorum.sqlite";
const BOB_DB: &str = "keyquorum --db /home/bob/keyquorum.sqlite";

fn use_defaults(env: &mut MemoryEnv) {
    for (db, who) in [(ALICE_DB, "alice"), (BOB_DB, "bob")] {
        let (ok, _) = env.keyquorum(&format!("{db} use --device /usb/{who} --slot {who}"));
        assert!(ok.is_ok(), "the command failed");
    }
}

#[test]
fn stored_defaults_replace_as_and_slot() {
    let mut env = two_people();
    use_defaults(&mut env);
    let (ok, out) = env.keyquorum(&format!(
        "{ALICE_DB} deliver send --file /home/alice/note.txt --to bob --output-dir /outbox"
    ));
    assert!(ok.is_ok(), "the command failed");
    assert!(out.starts_with("Sealed note.txt to bob (delivery "));
    let letter = only_file(&env, "/outbox");
    let (ok, out) = env.keyquorum(&format!(
        "{BOB_DB} deliver open --file {letter} --save /home/bob/note.txt --ack-dir /acks"
    ));
    assert!(ok.is_ok(), "the command failed");
    assert!(out.starts_with("Saved note.txt"), "{out}");
    let ack = only_file(&env, "/acks");
    let (ok, out) = env.keyquorum(&format!("{ALICE_DB} deliver ack --file {ack}"));
    assert!(ok.is_ok(), "the command failed");
    assert!(out.contains(" accepted by bob"), "{out}");
}

#[test]
fn as_that_disagrees_with_the_slot_is_refused() {
    let mut env = two_people();
    let (ok, _) = env.keyquorum(&format!(
        "{ALICE_DB} deliver send --file /home/alice/note.txt --to bob --as bob \
         --slot /usb/alice=alice --output-dir /outbox"
    ));
    assert!(ok.unwrap_err().to_string().contains("does not match"));
    assert!(env
        .fs
        .list(Path::new("/outbox"))
        .unwrap_or_default()
        .is_empty());
}

#[test]
fn no_flags_and_no_defaults_asks_for_an_identity() {
    let mut env = two_people();
    let (ok, _) = env.keyquorum(&format!(
        "{ALICE_DB} deliver send --file /home/alice/note.txt --to bob --output-dir /outbox"
    ));
    assert!(ok.unwrap_err().to_string().contains("no identity"));
}

#[test]
fn a_recent_letter_is_reused_for_the_same_command_until_it_goes_stale() {
    let mut env = two_people();
    use_defaults(&mut env);
    env.keyquorum(&format!(
        "{ALICE_DB} deliver send --file /home/alice/note.txt --to bob --output-dir /outbox"
    ))
    .0
    .unwrap();
    let letter = only_file(&env, "/outbox");
    env.now = Some("2026-09-27 00:00".into());
    let (ok, _) = env.keyquorum(&format!(
        "{BOB_DB} deliver open --file {letter} --reject --ack-dir /acks"
    ));
    assert!(ok.is_ok(), "the command failed");

    env.now = Some("2026-09-27 00:10".into());
    let (ok, _) = env.keyquorum(&format!("{BOB_DB} deliver open --reject --ack-dir /acks2"));
    assert!(ok.is_ok(), "the command failed");
    let stderr = String::from_utf8_lossy(&env.stderr).to_string();
    assert!(
        stderr.contains(&format!("using --file {letter} from 10m ago")),
        "{stderr}"
    );

    env.now = Some("2026-09-27 00:20".into());
    let (ok, _) = env.keyquorum(&format!("{BOB_DB} deliver open --reject --ack-dir /acks3"));
    assert!(ok.unwrap_err().to_string().contains("--file is required"));
}

#[test]
fn pushing_an_acknowledgement_never_reuses_a_recent_letter() {
    let mut env = two_people();
    use_defaults(&mut env);
    env.keyquorum(&format!(
        "{ALICE_DB} deliver send --file /home/alice/note.txt --to bob --output-dir /outbox"
    ))
    .0
    .unwrap();
    let letter = only_file(&env, "/outbox");
    env.keyquorum(&format!(
        "{BOB_DB} deliver open --file {letter} --reject --ack-dir /acks"
    ))
    .0
    .unwrap();

    let (result, _) = env.keyquorum(&format!("{BOB_DB} deliver open --reject --push-ack"));
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("--file is required"));
}

#[test]
fn no_cache_ignores_a_recent_letter() {
    let mut env = two_people();
    use_defaults(&mut env);
    env.keyquorum(&format!(
        "{ALICE_DB} deliver send --file /home/alice/note.txt --to bob --output-dir /outbox"
    ))
    .0
    .unwrap();
    let letter = only_file(&env, "/outbox");
    env.keyquorum(&format!(
        "{BOB_DB} deliver open --file {letter} --reject --ack-dir /acks"
    ))
    .0
    .unwrap();
    let (ok, _) = env.keyquorum(&format!(
        "{BOB_DB} --no-cache deliver open --reject --ack-dir /acks2"
    ));
    assert!(ok.unwrap_err().to_string().contains("--file is required"));
}

#[test]
fn a_recipient_is_never_filled_in_from_a_recent_use() {
    let mut env = two_people();
    use_defaults(&mut env);
    env.keyquorum(&format!(
        "{ALICE_DB} deliver send --file /home/alice/note.txt --to bob --output-dir /outbox"
    ))
    .0
    .unwrap();
    // `--to` is required by the command line itself, so a send cannot go to
    // whoever was addressed last.
    assert!(crate::cli::Cli::try_parse_from(
        "keyquorum deliver send --file x --output-dir /o".split_whitespace()
    )
    .is_err());
}
