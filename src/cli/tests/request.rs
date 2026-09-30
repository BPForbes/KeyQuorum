//! `file request`, `open-request`, `answer-request` and `open-answer`: a
//! request asks, the holder answers, and neither delivers or changes anything.

use super::file::{ok, org, run, slot, track, KQTF};
use super::memory_env::MemoryEnv;
use crate::file_history::TrackedFile;
use crate::storage::Storage;
use std::path::Path;

/// M.A holds a tracked `report.txt`; M.A and M.B can both receive letters.
fn holder_and_requester() -> MemoryEnv {
    let mut env = org();
    for dir in ["ma", "mb"] {
        let label = dir.to_uppercase().replacen('M', "M.", 1);
        let (result, out) = env.keyquorum(&format!(
            "keyquorum --db /home/org/keyquorum.sqlite device register /usb/{dir} --slot {label} --type encryption"
        ));
        assert!(result.is_ok(), "{out}");
    }
    track(&mut env, "M.A", "M.A");
    env
}

fn file_id_hex(env: &MemoryEnv) -> String {
    let file = TrackedFile::decode(&env.fs.read(Path::new(KQTF)).unwrap()).unwrap();
    hex::encode(file.file_id)
}

fn only(env: &MemoryEnv, dir: &str) -> String {
    let files = env.fs.list(Path::new(dir)).unwrap_or_default();
    assert_eq!(files.len(), 1, "{dir}: {files:?}");
    files[0].display().to_string()
}

#[test]
fn a_file_request_is_read_answered_and_then_served_by_the_normal_share() {
    let mut env = holder_and_requester();
    let id = file_id_hex(&env);

    // M.B holds no copy: the request names the file by id and name.
    let out = ok(
        &mut env,
        &format!(
            "request --file-id {id} --name report.txt --to M.A --as M.B --slot {} --output-dir /req",
            slot("M.B")
        ),
    );
    assert!(out.contains("Sealed a file request"), "{out}");
    let letter = only(&env, "/req");
    assert!(letter.ends_with("-request.kqpb"));

    // The holder reads it and records it once in their copy.
    let opened = ok(
        &mut env,
        &format!(
            "open-request --letter {letter} --slot {} --file {KQTF}",
            slot("M.A")
        ),
    );
    assert!(opened.contains("file request"), "{opened}");
    assert!(opened.contains("from M.B to M.A"), "{opened}");
    assert!(opened.contains("signature verified"), "{opened}");
    assert!(opened.contains("Recorded in"), "{opened}");
    let again = ok(
        &mut env,
        &format!(
            "open-request --letter {letter} --slot {} --file {KQTF}",
            slot("M.A")
        ),
    );
    assert!(again.contains("Already recorded"), "{again}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert_eq!(history.matches("FileRequested").count(), 1, "{history}");
    assert!(
        history.contains("FileRequested Success by M.B"),
        "{history}"
    );

    // Accepting says yes and points at the share; it delivers nothing itself.
    let answered = ok(
        &mut env,
        &format!(
            "answer-request --letter {letter} --decision accept --slot {} --file {KQTF} --ack-dir /ans",
            slot("M.A")
        ),
    );
    assert!(answered.contains("Accepted file request"), "{answered}");
    assert!(answered.contains("file share"), "{answered}");
    assert!(!env.fs.exists(Path::new("/out")), "nothing was delivered");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("RequestAnswered"), "{history}");
    assert!(history.contains("decision=accepted"), "{history}");
    // The same answer again records nothing new; the opposite one is refused.
    let repeat = ok(
        &mut env,
        &format!(
            "answer-request --letter {letter} --decision accept --slot {} --file {KQTF} --ack-dir /ans2",
            slot("M.A")
        ),
    );
    assert!(repeat.contains("Already recorded"), "{repeat}");
    let (result, _) = run(
        &mut env,
        &format!(
            "answer-request --letter {letter} --decision decline --slot {} --file {KQTF} --ack-dir /ans3",
            slot("M.A")
        ),
    );
    assert!(result.unwrap_err().to_string().contains("already answered"));
    assert_eq!(
        ok(&mut env, &format!("history {KQTF}"))
            .matches("RequestAnswered")
            .count(),
        1
    );

    // The requester reads the answer; with no copy there is nothing to record.
    let answer = only(&env, "/ans");
    assert!(answer.ends_with("-answer.kqpb"));
    let seen = ok(
        &mut env,
        &format!("open-answer --answer {answer} --slot {}", slot("M.B")),
    );
    assert!(seen.contains("accepted by M.A"), "{seen}");

    // Then the holder serves it with the ordinary, trust-checked share.
    ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    let delivery = only(&env, "/out");
    ok(
        &mut env,
        &format!(
            "receive --letter {delivery} --slot {} --ack-dir /acks --out /work/b.kqtf",
            slot("M.B")
        ),
    );
    assert!(ok(&mut env, "verify /work/b.kqtf").contains("TRUSTED"));
}

#[test]
fn a_change_request_carries_a_message_that_history_never_records() {
    let mut env = holder_and_requester();
    // M.B has a copy of the file (a stand-in for one received earlier).
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write_new(Path::new("/work/b.kqtf"), &bytes).unwrap();
    // A third copy that will never send or see the request.
    env.fs.write_new(Path::new("/work/c.kqtf"), &bytes).unwrap();

    let out = ok(
        &mut env,
        &format!(
            "request /work/b.kqtf --change --message secret-total-is-wrong --to M.A --as M.B --slot {} --output-dir /req",
            slot("M.B")
        ),
    );
    assert!(out.contains("Sealed a change request"), "{out}");
    let letter = only(&env, "/req");
    // The message is inside the sealed letter, not readable in it.
    let sealed = env.fs.read(Path::new(&letter)).unwrap();
    assert!(!sealed
        .windows(b"secret-total-is-wrong".len())
        .any(|w| w == b"secret-total-is-wrong"));
    let sent = ok(&mut env, "history /work/b.kqtf");
    assert!(sent.contains("ChangeRequested"), "{sent}");

    // The holder sees the message, and the history still does not.
    let opened = ok(
        &mut env,
        &format!(
            "open-request --letter {letter} --slot {} --file {KQTF}",
            slot("M.A")
        ),
    );
    assert!(
        opened.contains("message: secret-total-is-wrong"),
        "{opened}"
    );
    assert!(opened.contains("about revision"), "{opened}");
    for history in [
        ok(&mut env, &format!("history {KQTF}")),
        ok(&mut env, "history /work/b.kqtf"),
    ] {
        assert!(!history.contains("secret-total-is-wrong"), "{history}");
        assert!(history.contains("request_kind=change"), "{history}");
    }

    // The holder declines; the requester records the answer against their request.
    ok(
        &mut env,
        &format!(
            "answer-request --letter {letter} --decision decline --slot {} --file {KQTF} --ack-dir /ans",
            slot("M.A")
        ),
    );
    let answer = only(&env, "/ans");
    let seen = ok(
        &mut env,
        &format!(
            "open-answer --answer {answer} --slot {} --file /work/b.kqtf",
            slot("M.B")
        ),
    );
    assert!(seen.contains("declined by M.A"), "{seen}");
    assert!(seen.contains("Recorded in"), "{seen}");
    assert!(ok(&mut env, "history /work/b.kqtf").contains("decision=declined"));
    let again = ok(
        &mut env,
        &format!(
            "open-answer --answer {answer} --slot {} --file /work/b.kqtf",
            slot("M.B")
        ),
    );
    assert!(again.contains("Already recorded"), "{again}");

    // A copy that never sent the request will not record an answer to it.
    let (result, _) = run(
        &mut env,
        &format!(
            "open-answer --answer {answer} --slot {} --file /work/c.kqtf",
            slot("M.B")
        ),
    );
    assert!(result.unwrap_err().to_string().contains("no request"));
}

#[test]
fn requests_are_refused_when_they_are_not_addressed_signed_or_sized_properly() {
    let mut env = holder_and_requester();
    let id = file_id_hex(&env);
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write_new(Path::new("/work/b.kqtf"), &bytes).unwrap();

    // Nobody registered an encryption key for M.S.1 here.
    let (result, _) = run(
        &mut env,
        &format!(
            "request --file-id {id} --name report.txt --to M.S.1 --as M.B --slot {} --output-dir /req0",
            slot("M.B")
        ),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("no encryption key"));
    // A message has a limit.
    let long = "x".repeat(1025);
    let (result, _) = run(
        &mut env,
        &format!(
            "request /work/b.kqtf --change --message {long} --to M.A --as M.B --slot {} --output-dir /req1",
            slot("M.B")
        ),
    );
    assert!(result.unwrap_err().to_string().contains("longer than"));
    // Another file's copy cannot record this request.
    ok(
        &mut env,
        &format!(
            "request --file-id {id} --name report.txt --to M.A --as M.B --slot {} --output-dir /req",
            slot("M.B")
        ),
    );
    let letter = only(&env, "/req");
    env.fs
        .write_new(Path::new("/work/other.txt"), b"other\n")
        .unwrap();
    track_other(&mut env);
    let (result, _) = run(
        &mut env,
        &format!(
            "open-request --letter {letter} --slot {} --file /work/other.txt.kqtf",
            slot("M.A")
        ),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not a copy of the file"));
    // Only the holder's key opens a request: M.B's own slot cannot.
    let (result, _) = run(
        &mut env,
        &format!("open-request --letter {letter} --slot {}", slot("M.B")),
    );
    assert!(result.is_err());
    // A request never opens as a delivery letter, or the other way round.
    let (result, _) = run(
        &mut env,
        &format!(
            "receive --letter {letter} --slot {} --ack-dir /acks --out /work/x.kqtf",
            slot("M.A")
        ),
    );
    assert!(result.is_err());
}

fn track_other(env: &mut MemoryEnv) {
    ok(
        env,
        &format!(
            "track /work/other.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
}
