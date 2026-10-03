//! `keyquorum outbox`: queue sealed letters in your ring buffer and send them
//! oldest first, only to the recipient they are sealed to, and a tracked
//! file's letters only in their exchange's order.

use super::file::{ok as file_ok, slot, DB, KQTF};
use super::inbox::{two_people_on_a_relay, ALICE, BOB};
use super::memory_env::MemoryEnv;
use super::request::{holder_and_requester, only};
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
    assert!(queued.contains("slot 0: file delivery to bob"), "{queued}");
    assert!(
        queued.contains("1 of 32 slots held, 31 free (partial)"),
        "{queued}"
    );
    assert!(queued.contains("read index 0, write index 1"), "{queued}");

    let sent = run(&mut env, &format!("{ALICE} outbox send"));
    assert!(sent.contains("Relay stored letter"), "{sent}");
    assert!(sent.contains("Sent slot 0: file delivery to bob"), "{sent}");
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
    // A plain file is not a letter: it travels inside one, via `send`.
    let message = fails(
        &mut env,
        &format!("{ALICE} outbox add /home/alice/note.txt --to bob"),
    );
    assert!(
        message.contains("the outbox carries only sealed letters"),
        "{message}"
    );
    let status = run(&mut env, &format!("{ALICE} outbox"));
    assert!(status.contains("(empty)"), "{status}");
}

#[test]
fn a_full_ring_refuses_new_letters_and_only_an_empty_one_is_resized() {
    let mut env = two_people_on_a_relay();
    run(&mut env, &format!("{ALICE} outbox capacity 1"));
    let letter = alice_letter_for_bob(&mut env);
    run(&mut env, &format!("{ALICE} outbox add {letter} --to bob"));
    let message = fails(&mut env, &format!("{ALICE} outbox add {letter} --to bob"));
    assert!(message.contains("outbox is full"), "{message}");
    let held = run(&mut env, &format!("{ALICE} outbox"));
    assert!(held.contains("1 of 1 slots held, 0 free (full)"), "{held}");
    let message = fails(&mut env, &format!("{ALICE} outbox capacity 4"));
    assert!(
        message.contains("only an empty outbox can be resized"),
        "{message}"
    );

    let written = run(&mut env, &format!("{ALICE} outbox send --output-dir /out"));
    assert!(
        written.contains("Sent slot 0: file delivery to bob"),
        "{written}"
    );
    assert_eq!(
        env.fs.read(Path::new(&only_file(&env, "/out"))).unwrap(),
        env.fs.read(Path::new(&letter)).unwrap()
    );
    run(&mut env, &format!("{ALICE} outbox capacity 4"));
}

#[test]
fn drop_discards_the_oldest_item_without_sending_it() {
    let mut env = two_people_on_a_relay();
    let letter = alice_letter_for_bob(&mut env);
    run(&mut env, &format!("{ALICE} outbox add {letter} --to bob"));
    let dropped = run(&mut env, &format!("{ALICE} outbox drop"));
    assert!(
        dropped.contains("Dropped slot 0: file delivery to bob"),
        "{dropped}"
    );
    let status = run(&mut env, &format!("{ALICE} outbox"));
    assert!(
        status.contains("(empty)") && status.contains("0 sent"),
        "{status}"
    );
    let listed = run(&mut env, &format!("{BOB} inbox"));
    assert!(!listed.contains("file delivery"), "{listed}");
}

/// `keyquorum --db DB outbox ...` in the one store the `file` tests share.
fn outbox(env: &mut MemoryEnv, args: &str) -> crate::error::Result<String> {
    let (result, out) = env.keyquorum(&format!("keyquorum {DB} outbox {args}"));
    result.map(|()| out)
}

/// Queue the one letter in `dir` and send it from the ring into `wire`.
fn through_ring(env: &mut MemoryEnv, who: &str, to: &str, dir: &str, file: &str, wire: &str) {
    let letter = only(env, dir);
    outbox(env, &format!("add {letter} --to {to} --as {who} {file}"))
        .unwrap_or_else(|e| panic!("{who} queues {letter}: {e}"));
    let sent = outbox(env, &format!("send --as {who} --output-dir {wire}")).unwrap();
    assert!(sent.contains("Sent slot"), "{sent}");
}

#[test]
fn a_tracked_file_crosses_rings_only_in_its_exchange_order() {
    let mut env = holder_and_requester();
    let id = hex::encode(
        crate::file_history::TrackedFile::decode(&env.fs.read(Path::new(KQTF)).unwrap())
            .unwrap()
            .file_id,
    );
    let holder_copy = format!("--file {KQTF}");

    // The holder cannot push the file into the exchange unasked: sharing it
    // outside the ring still works, but the ring refuses the letter.
    file_ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /early",
            slot("M.A")
        ),
    );
    let early = only(&env, "/early");
    let refused = outbox(
        &mut env,
        &format!("add {early} --to M.B --as M.A {holder_copy}"),
    )
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("out of order: first a file request from M.B that you accepted"),
        "{refused}"
    );
    // A later step without the copy that shows its order is refused too.
    let refused = outbox(&mut env, &format!("add {early} --to M.B --as M.A"))
        .unwrap_err()
        .to_string();
    assert!(refused.contains("needs your copy of the file"), "{refused}");

    // 1. Passport: the requester's request needs nothing before it.
    file_ok(
        &mut env,
        &format!(
            "request --file-id {id} --name report.txt --to M.A --as M.B --slot {} --output-dir /req",
            slot("M.B")
        ),
    );
    through_ring(&mut env, "M.B", "M.A", "/req", "", "/wire1");

    // 2. Agreement: the holder opens the request and answers it, signed.
    let request = only(&env, "/wire1");
    file_ok(
        &mut env,
        &format!(
            "open-request --letter {request} --slot {} --file {KQTF}",
            slot("M.A")
        ),
    );
    file_ok(
        &mut env,
        &format!(
            "answer-request --letter {request} --decision accept --slot {} --file {KQTF} --ack-dir /ans",
            slot("M.A")
        ),
    );
    through_ring(&mut env, "M.A", "M.B", "/ans", &holder_copy, "/wire2");
    let answer = only(&env, "/wire2");
    assert!(file_ok(
        &mut env,
        &format!("open-answer --answer {answer} --slot {}", slot("M.B"))
    )
    .contains("accepted by M.A"));

    // 3. The tracked file itself, now that a request was accepted.
    file_ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    through_ring(&mut env, "M.A", "M.B", "/out", &holder_copy, "/wire3");

    // 4. Receipt: only for a file the requester received from the holder.
    let delivery = only(&env, "/wire3");
    file_ok(
        &mut env,
        &format!(
            "receive --letter {delivery} --slot {} --ack-dir /ack --out /work/b.kqtf",
            slot("M.B")
        ),
    );
    through_ring(
        &mut env,
        "M.B",
        "M.A",
        "/ack",
        "--file /work/b.kqtf",
        "/wire4",
    );

    // 5. History: once the holder has recorded the receipt, a snapshot.
    let receipt = only(&env, "/wire4");
    file_ok(
        &mut env,
        &format!("ack {KQTF} --ack {receipt} --slot {}", slot("M.A")),
    );
    file_ok(
        &mut env,
        &format!(
            "send-history {KQTF} --to M.B --as M.A --slot {} --output-dir /snap",
            slot("M.A")
        ),
    );
    through_ring(&mut env, "M.A", "M.B", "/snap", &holder_copy, "/wire5");
    let snapshot = only(&env, "/wire5");
    let compared = file_ok(
        &mut env,
        &format!(
            "open-history --letter {snapshot} --slot {} --against /work/b.kqtf",
            slot("M.B")
        ),
    );
    // The snapshot is signed and compared with the receiver's copy. Each
    // side has recorded its own events since the delivery (the holder the
    // request, answer and receipt; the receiver its receipt), so the two
    // chains are reported as they are, not forced to agree.
    assert!(compared.contains("sender signature verified"), "{compared}");
    assert!(
        compared.contains("Compared with /work/b.kqtf"),
        "{compared}"
    );
}

const ALICE_STORE: &str = "/home/alice/keyquorum.sqlite";

/// Queue a letter for `label`, whose key is registered only in Alice's store.
fn queue_for(env: &mut MemoryEnv, label: &str) -> Vec<u8> {
    run(env, &format!("{ALICE} outbox"));
    let conn = env.store(ALICE_STORE);
    let (_, public) = crate::keys::generate_encryption_keypair();
    crate::keys::register_key(conn, label, crate::keys::KeyType::Encryption, &public).unwrap();
    let letter = crate::envelope::seal(
        crate::envelope::PACKAGE,
        crate::envelope::KIND_FILE_DELIVERY,
        &public,
        b"sealed",
    )
    .unwrap();
    crate::outbox::push(conn, "alice", label, &letter, None).unwrap();
    letter
}

#[test]
fn an_offline_send_keeps_every_letter_inside_its_directory() {
    let mut env = two_people_on_a_relay();
    let letter = queue_for(&mut env, "../evil");
    let sent = run(
        &mut env,
        &format!("{ALICE} outbox send --output-dir /out/letters"),
    );
    assert!(sent.contains("Wrote /out/letters/.._evil-"), "{sent}");
    let written = only_file(&env, "/out/letters");
    assert_eq!(env.fs.read(Path::new(&written)).unwrap(), letter);
    let outside = env.fs.list(Path::new("/out")).unwrap_or_default();
    assert_eq!(outside, vec![Path::new("/out/letters").to_path_buf()]);
}

#[test]
fn a_failed_dequeue_takes_the_written_letter_back_and_the_retry_sends_it() {
    let mut env = two_people_on_a_relay();
    let letter = queue_for(&mut env, "carol");
    // The letter is written, then freeing the slot fails (a full disk, say).
    env.store(ALICE_STORE)
        .execute_batch(
            "CREATE TRIGGER full_disk BEFORE DELETE ON outbox_slots
             BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
    let message = fails(&mut env, &format!("{ALICE} outbox send --output-dir /out"));
    assert!(message.contains("disk full"), "{message}");
    assert!(
        env.fs
            .list(Path::new("/out"))
            .unwrap_or_default()
            .is_empty(),
        "the letter written for the failed send is removed"
    );
    let status = run(&mut env, &format!("{ALICE} outbox"));
    assert!(status.contains("1 of 32 slots held"), "{status}");
    assert!(status.contains("0 sent"), "{status}");

    env.store(ALICE_STORE)
        .execute_batch("DROP TRIGGER full_disk;")
        .unwrap();
    let sent = run(&mut env, &format!("{ALICE} outbox send --output-dir /out"));
    assert!(sent.contains("Sent slot 0"), "{sent}");
    assert_eq!(
        env.fs.read(Path::new(&only_file(&env, "/out"))).unwrap(),
        letter
    );
}

#[test]
fn a_letter_already_written_with_the_same_bytes_counts_as_sent() {
    use sha2::{Digest, Sha256};
    let mut env = two_people_on_a_relay();
    let letter = queue_for(&mut env, "carol");
    // A crash between writing the letter and committing the dequeue leaves
    // the file behind; the retry must not be blocked by it.
    let name = format!(
        "/out/carol-{}.kqpb",
        &hex::encode(Sha256::digest(&letter))[..16]
    );
    env.fs.write(Path::new(&name), &letter).unwrap();
    let sent = run(&mut env, &format!("{ALICE} outbox send --output-dir /out"));
    assert!(sent.contains(&format!("Already written {name}")), "{sent}");
    assert!(sent.contains("Sent slot 0"), "{sent}");

    // A different file at that name is never overwritten, and nothing moves.
    let letter = queue_for(&mut env, "dave");
    let name = format!(
        "/out/dave-{}.kqpb",
        &hex::encode(Sha256::digest(&letter))[..16]
    );
    env.fs
        .write(Path::new(&name), b"someone else's file")
        .unwrap();
    fails(&mut env, &format!("{ALICE} outbox send --output-dir /out"));
    assert_eq!(
        env.fs.read(Path::new(&name)).unwrap(),
        b"someone else's file"
    );
    let status = run(&mut env, &format!("{ALICE} outbox"));
    assert!(status.contains("1 of 32 slots held"), "{status}");
}
