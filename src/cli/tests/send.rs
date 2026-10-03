//! `send --quorum-file`: a quorum-protected file goes out without ever being
//! written to disk, under the same unlock rules as `access quorum --state 1`.

use super::file::DB;
use super::gate_link::{gated, SECRET};
use super::memory_env::MemoryEnv;
use crate::storage::Storage;
use clap::Parser;
use std::path::Path;

const RECIPIENT_DB: &str = "--db /home/ma1/keyquorum.sqlite";
const SEND: &str = "send --quorum-file 1 --to M.A.1 --as M.A --slot /usb/ma=M.A";
const BOTH: &str = "--unlock-slot /usb/qa=Q.A --unlock-slot /usb/qb=Q.B";

fn ok(env: &mut MemoryEnv, line: &str) -> String {
    let (result, out) = env.keyquorum(line);
    assert!(result.is_ok(), "{line}: the command failed");
    out
}

/// The quorum file of the gate tests, plus a recipient M.A.1 who can open
/// what M.A sends.
fn with_recipient() -> MemoryEnv {
    let mut env = gated();
    ok(
        &mut env,
        &format!("keyquorum {DB} device register /usb/ma1 --slot M.A.1 --type encryption"),
    );
    for (owner, dir, kind) in [
        ("M.A", "ma", "signing"),
        ("M.A.1", "ma1", "encryption"),
        ("M.A.1", "ma1", "signing"),
    ] {
        ok(
            &mut env,
            &format!(
                "keyquorum {RECIPIENT_DB} device register /usb/{dir} --slot {owner} --type {kind}"
            ),
        );
    }
    env
}

fn files_under(env: &MemoryEnv, dir: &str) -> Vec<String> {
    env.fs
        .list(Path::new(dir))
        .unwrap_or_default()
        .iter()
        .map(|p| p.display().to_string())
        .collect()
}

#[test]
fn an_unregistered_recipient_is_refused_before_anything_is_unlocked() {
    let mut env = with_recipient();
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} send --quorum-file 1 --to NOBODY --as M.A --slot /usb/ma=M.A {BOTH} --output-dir /out"
    ));
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("no encryption key is registered for NOBODY"),
        "{message}"
    );
    assert!(files_under(&env, "/out").is_empty());
}

#[test]
fn a_quorum_file_is_unlocked_in_memory_sealed_and_opened_by_the_recipient() {
    let mut env = with_recipient();
    let before = files_under(&env, "/work");
    let out = ok(
        &mut env,
        &format!("keyquorum {DB} {SEND} {BOTH} --output-dir /out"),
    );
    assert!(out.contains("Sealed secret.txt to M.A.1"), "{out}");
    assert_eq!(
        files_under(&env, "/work"),
        before,
        "no plaintext was written"
    );
    let letters = files_under(&env, "/out");
    assert_eq!(letters.len(), 1, "{letters:?}");
    assert!(
        !env.fs
            .read(Path::new(&letters[0]))
            .unwrap()
            .windows(SECRET.len())
            .any(|w| w == SECRET),
        "the letter is sealed"
    );

    let opened = ok(
        &mut env,
        &format!(
            "keyquorum {RECIPIENT_DB} deliver open --file {} --slot /usb/ma1=M.A.1 \
             --save /home/ma1/secret.txt --ack-dir /acks",
            letters[0]
        ),
    );
    assert!(opened.contains("Saved secret.txt"), "{opened}");
    assert_eq!(
        env.fs.read(Path::new("/home/ma1/secret.txt")).unwrap(),
        SECRET
    );
}

#[test]
fn a_short_quorum_sends_nothing() {
    let mut env = with_recipient();
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} {SEND} --unlock-slot /usb/qa=Q.A --output-dir /out"
    ));
    assert!(result.is_err());
    assert!(files_under(&env, "/out").is_empty());
}

#[test]
fn the_name_can_be_overridden_and_the_unlock_is_recorded_like_any_other() {
    let mut env = with_recipient();
    let out = ok(
        &mut env,
        &format!("keyquorum {DB} {SEND} {BOTH} --name renamed.txt --output-dir /out"),
    );
    assert!(out.contains("Sealed renamed.txt to M.A.1"), "{out}");
    // The same unlock `access quorum` runs: the file's failed-attempt count
    // and gate history are its own, so a later unlock still works.
    ok(
        &mut env,
        &format!("keyquorum {DB} access quorum --state 1 --id 1 --slot /usb/qa=Q.A --slot /usb/qb=Q.B --output /work/out.txt"),
    );
    assert_eq!(env.fs.read(Path::new("/work/out.txt")).unwrap(), SECRET);
}

#[test]
fn a_path_and_a_quorum_file_exclude_each_other_and_unlock_flags_need_one() {
    let parse = |line: &str| crate::cli::Cli::try_parse_from(line.split_whitespace());
    assert!(parse("keyquorum send --to M.A.1").is_err());
    assert!(parse("keyquorum send a.txt --quorum-file 1 --to M.A.1").is_err());
    assert!(parse("keyquorum send --quorum-file 1 --unlock-slot /usb/q=Q --to M.A.1").is_ok());
    assert!(parse("keyquorum send a.txt --to M.A.1").is_ok());
}

#[test]
fn unlock_flags_without_a_quorum_file_are_refused() {
    let mut env = with_recipient();
    env.fs.write_new(Path::new("/work/a.txt"), b"x").unwrap();
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} send /work/a.txt --to M.A.1 --as M.A --slot /usb/ma=M.A --unlock-slot /usb/qa=Q.A --offline"
    ));
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("apply only with --quorum-file"));
}

#[cfg(feature = "legacy-tests")]
#[test]
fn legacy_snapshot_spellings_point_to_the_one_shot_verbs() {
    use super::file::{ok as file_ok, org, track, KQTF};
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    file_ok(
        &mut env,
        &format!("history export {KQTF} --out /work/one.kqhs"),
    );
    file_ok(&mut env, "history verify /work/one.kqhs");
    let quiet = String::from_utf8_lossy(&env.stderr).to_string();
    assert!(
        !quiet.contains("legacy"),
        "the new spelling is not legacy: {quiet}"
    );

    file_ok(&mut env, "verify-snapshot /work/one.kqhs");
    file_ok(&mut env, &format!("history {KQTF} --export /work/two.kqhs"));
    let notes = String::from_utf8_lossy(&env.stderr).to_string();
    assert!(
        notes.contains("`keyquorum file verify-snapshot` is a legacy command")
            && notes.contains("keyquorum file history verify <snapshot>"),
        "{notes}"
    );
    assert!(
        notes.contains("`keyquorum file history --export` is a legacy command")
            && notes.contains("keyquorum file history export <file> --out <snapshot>"),
        "{notes}"
    );
    assert!(env.fs.exists(Path::new("/work/two.kqhs")), "it still works");
}
