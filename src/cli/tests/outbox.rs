//! `keyquorum outbox`: queue sealed letters in your ring buffer and send them
//! oldest first, only to the recipient they are sealed to.

use super::inbox::{two_people_on_a_relay, ALICE, BOB};
use super::memory_env::MemoryEnv;
use crate::envelope;
use crate::storage::Storage;
use std::path::Path;

fn run(env: &mut MemoryEnv, line: &str) -> String {
    let (ok, out) = env.keyquorum(line);
    assert!(ok.is_ok(), "{line}: {ok:?}\n{out}");
    out
}

fn fails(env: &mut MemoryEnv, line: &str) -> String {
    let (result, _) = env.keyquorum(line);
    result.expect_err(line).to_string()
}

fn only_file(env: &MemoryEnv, dir: &str) -> String {
    let files = env.fs.list(Path::new(dir)).unwrap_or_default();
    assert_eq!(files.len(), 1, "{files:?}");
    files[0].display().to_string()
}

/// Alice seals a note to Bob into a directory, as `send --output-dir` does.
fn alice_letter_for_bob(env: &mut MemoryEnv) -> String {
    run(
        env,
        &format!("{ALICE} send /home/alice/note.txt --to bob --output-dir /home/alice/letters"),
    );
    only_file(env, "/home/alice/letters")
}

#[test]
fn a_queued_letter_is_sent_from_the_read_pointer_and_opened_by_its_recipient() {
    let mut env = two_people_on_a_relay();
    let letter = alice_letter_for_bob(&mut env);

    let empty = run(&mut env, &format!("{ALICE} outbox"));
    assert!(
        empty.contains("Outbox for alice: 0 of 32 slots held, 32 free (empty)"),
        "{empty}"
    );

    let queued = run(&mut env, &format!("{ALICE} outbox add {letter} --to bob"));
    assert!(queued.contains("slot 0: KQPB to bob"), "{queued}");
    assert!(
        queued.contains("1 of 32 slots held, 31 free (partial)"),
        "{queued}"
    );
    assert!(queued.contains("read index 0, write index 1"), "{queued}");

    let sent = run(&mut env, &format!("{ALICE} outbox send"));
    assert!(sent.contains("Relay stored letter"), "{sent}");
    assert!(sent.contains("Sent slot 0: KQPB to bob"), "{sent}");
    assert!(
        sent.contains("(empty); read index 1, write index 1; 1 sent"),
        "{sent}"
    );

    let opened = run(&mut env, &format!("{BOB} inbox open"));
    assert!(opened.contains("note.txt"), "{opened}");

    let again = run(&mut env, &format!("{ALICE} outbox send"));
    assert!(again.contains("nothing to send"), "{again}");
}

#[test]
fn a_letter_goes_only_to_the_person_it_is_sealed_to() {
    let mut env = two_people_on_a_relay();
    let letter = alice_letter_for_bob(&mut env);
    let message = fails(&mut env, &format!("{ALICE} outbox add {letter} --to alice"));
    assert!(message.contains("not trusted for this item"), "{message}");
    let message = fails(
        &mut env,
        &format!("{ALICE} outbox add {letter} --to nobody"),
    );
    assert!(message.contains("not trusted for this item"), "{message}");
    // A tracked or plain file is not an outbox item.
    let message = fails(
        &mut env,
        &format!("{ALICE} outbox add /home/alice/note.txt --to bob"),
    );
    assert!(message.contains("the outbox carries only"), "{message}");
    let status = run(&mut env, &format!("{ALICE} outbox"));
    assert!(status.contains("(empty)"), "{status}");
}

#[test]
fn a_full_ring_refuses_new_items_and_other_kinds_need_a_directory() {
    let mut env = two_people_on_a_relay();
    run(&mut env, &format!("{ALICE} outbox capacity 1"));
    let letter = alice_letter_for_bob(&mut env);
    run(&mut env, &format!("{ALICE} outbox add {letter} --to bob"));
    let message = fails(&mut env, &format!("{ALICE} outbox add {letter} --to bob"));
    assert!(message.contains("outbox is full"), "{message}");
    let message = fails(&mut env, &format!("{ALICE} outbox capacity 4"));
    assert!(
        message.contains("only an empty outbox can be resized"),
        "{message}"
    );
    run(&mut env, &format!("{ALICE} outbox send"));

    // An eviction notice naming bob: not a letter, so not for the relay.
    let mut notice = b"KQBN".to_vec();
    notice.extend_from_slice(&[2, 1]);
    for field in [&b"bridge-uid"[..], b"carol"] {
        envelope::push_len_prefixed(&mut notice, field).unwrap();
    }
    notice.extend_from_slice(&1u16.to_be_bytes());
    envelope::push_len_prefixed(&mut notice, b"bob").unwrap();
    notice.extend_from_slice(&0u16.to_be_bytes());
    env.fs
        .write_new(Path::new("/home/alice/evicted.kqbn"), &notice)
        .unwrap();
    run(
        &mut env,
        &format!("{ALICE} outbox add /home/alice/evicted.kqbn --to bob"),
    );
    let message = fails(&mut env, &format!("{ALICE} outbox send"));
    assert!(message.contains("pass --output-dir"), "{message}");
    let held = run(&mut env, &format!("{ALICE} outbox"));
    assert!(held.contains("1 of 1 slots held, 0 free (full)"), "{held}");

    let written = run(&mut env, &format!("{ALICE} outbox send --output-dir /out"));
    assert!(written.contains("Sent slot 0: KQBN to bob"), "{written}");
    assert_eq!(
        env.fs.read(Path::new(&only_file(&env, "/out"))).unwrap(),
        notice
    );
}

#[test]
fn drop_discards_the_oldest_item_without_sending_it() {
    let mut env = two_people_on_a_relay();
    let letter = alice_letter_for_bob(&mut env);
    run(&mut env, &format!("{ALICE} outbox add {letter} --to bob"));
    let dropped = run(&mut env, &format!("{ALICE} outbox drop"));
    assert!(dropped.contains("Dropped slot 0: KQPB to bob"), "{dropped}");
    let status = run(&mut env, &format!("{ALICE} outbox"));
    assert!(
        status.contains("(empty)") && status.contains("0 sent"),
        "{status}"
    );
    let listed = run(&mut env, &format!("{BOB} inbox"));
    assert!(!listed.contains("file delivery"), "{listed}");
}
