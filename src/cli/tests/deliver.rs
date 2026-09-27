use super::memory_env::MemoryEnv;
use crate::storage::Storage;
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
        assert!(ok.is_ok(), "{ok:?}");
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
            assert!(ok.is_ok(), "{ok:?}");
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
    assert!(ok.is_ok(), "{ok:?}");
    assert!(out.starts_with("Sealed note.txt to bob (delivery "));
    let letter = only_file(&env, "/outbox");

    let (ok, out) = env.keyquorum(&format!(
        "keyquorum --db /home/bob/keyquorum.sqlite deliver open --file {letter} \
         --slot /usb/bob=bob --save /home/bob/note.txt --ack-dir /acks"
    ));
    assert!(ok.is_ok(), "{ok:?}");
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
    assert!(ok.is_ok(), "{ok:?}");
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
    assert!(ok.is_ok(), "{ok:?}");
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
