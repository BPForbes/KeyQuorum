//! `inbox open ID` for the tracked-file letters: a file, its acknowledgement,
//! a request and its answer, and a history snapshot. The copy a letter
//! concerns is always named by the person; a letter never picks it.

use super::file::{ok as file_ok, org, slot, track, DB, KQTF};
use super::memory_env::{MemoryEnv, RELAY_URL};
use crate::file_history::TrackedFile;
use crate::keys::{self, KeyType};
use crate::relay::ApiKeyScope;
use crate::storage::Storage;
use std::path::Path;

fn cli(env: &mut MemoryEnv, line: &str) -> String {
    let (result, out) = env.keyquorum(&format!("keyquorum {DB} {line}"));
    assert!(result.is_ok(), "{line}: {result:?}\n{out}");
    out
}

fn cli_err(env: &mut MemoryEnv, line: &str) -> String {
    let (result, _) = env.keyquorum(&format!("keyquorum {DB} {line}"));
    result.expect_err(line).to_string()
}

fn fingerprint(env: &MemoryEnv, label: &str) -> String {
    let key = keys::active_keys_for(
        env.store("/home/org/keyquorum.sqlite"),
        label,
        KeyType::Encryption,
    )
    .unwrap()
    .remove(0);
    keys::fingerprint(&key.public_key)
}

struct Org {
    env: MemoryEnv,
    /// M.A's and M.B's inbox options: slot, pull key and where letters are kept.
    a: String,
    b: String,
}

/// M.A holds a tracked report.txt; M.A and M.B can receive. All five people
/// share one store here (as in the `file` tests), so each person's pull key
/// is passed with `--api-key`.
fn org_on_a_relay() -> Org {
    let mut env = org();
    env.attach_relay();
    env.now = Some("2026-10-02 12:00".into());
    for (dir, label) in [("ma", "M.A"), ("mb", "M.B")] {
        cli(
            &mut env,
            &format!("device register /usb/{dir} --slot {label} --type encryption"),
        );
    }
    let push = env.relay_key(ApiKeyScope::InboxPush, None);
    cli(&mut env, &format!("loadkey {push} --url {RELAY_URL}"));
    track(&mut env, "M.A", "M.A");
    let (fa, fb) = (fingerprint(&env, "M.A"), fingerprint(&env, "M.B"));
    let pull_a = env.relay_key(ApiKeyScope::InboxPull, Some(fa));
    let pull_b = env.relay_key(ApiKeyScope::InboxPull, Some(fb));
    Org {
        env,
        a: format!("--slot {} --api-key {pull_a} --dir /mail/a", slot("M.A")),
        b: format!("--slot {} --api-key {pull_b} --dir /mail/b", slot("M.B")),
    }
}

impl Org {
    /// Relay id of the one waiting letter of `kind` for this person.
    fn letter(&mut self, who: &str) -> i64 {
        let opts = if who == "a" {
            self.a.clone()
        } else {
            self.b.clone()
        };
        let out = cli(&mut self.env, &format!("inbox list {opts}"));
        out.lines()
            .find_map(|line| line.split_whitespace().next()?.parse().ok())
            .unwrap_or_else(|| panic!("a waiting letter: {out}"))
    }
}

fn share_to_b(o: &mut Org) {
    let out = cli(
        &mut o.env,
        &format!("send {KQTF} --to M.B --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("Relay stored letter"), "{out}");
}

#[test]
fn a_tracked_file_opens_as_a_new_copy_at_the_path_you_name_and_is_answered() {
    let mut o = org_on_a_relay();
    share_to_b(&mut o);
    let id = o.letter("b");
    let out = cli(
        &mut o.env,
        &format!("inbox open {id} {} --out /b/copy.kqtf", o.b),
    );
    assert!(
        out.contains("Relay stored letter"),
        "the answer is posted: {out}"
    );
    assert!(o.env.fs.exists(Path::new("/b/copy.kqtf")));
    // Opened once: a second sweep finds nothing and writes no second copy.
    let again = cli(&mut o.env, &format!("inbox open {}", o.b));
    assert!(again.contains("(nothing waiting)"), "{again}");
    assert_eq!(o.env.fs.list(Path::new("/b")).unwrap().len(), 1);
}

#[test]
fn a_tracked_file_merges_into_the_copy_you_name_and_not_into_another_file() {
    let mut o = org_on_a_relay();
    share_to_b(&mut o);
    let first = o.letter("b");
    cli(
        &mut o.env,
        &format!("inbox open {first} {} --out /b/copy.kqtf", o.b),
    );

    // A second, unrelated tracked file: a letter must never be merged into it.
    o.env
        .fs
        .write_new(Path::new("/work/other.txt"), b"other\n")
        .unwrap();
    file_ok(
        &mut o.env,
        &format!(
            "track /work/other.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );

    o.env
        .fs
        .write_new(Path::new("/work/edited.txt"), b"totals: 101\n")
        .unwrap();
    file_ok(
        &mut o.env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    share_to_b(&mut o);
    let second = o.letter("b");
    assert_ne!(first, second);
    let wrong = cli_err(
        &mut o.env,
        &format!("inbox open {second} {} --into /work/other.txt.kqtf", o.b),
    );
    assert!(wrong.contains("could not be opened"), "{wrong}");
    let still_waiting = cli(&mut o.env, &format!("inbox list {}", o.b));
    assert!(still_waiting.contains("tracked file"), "{still_waiting}");

    let merged = cli(
        &mut o.env,
        &format!("inbox open {second} {} --into /b/copy.kqtf", o.b),
    );
    assert!(merged.contains("Relay stored letter"), "{merged}");
    let copy = TrackedFile::decode(&o.env.fs.read(Path::new("/b/copy.kqtf")).unwrap()).unwrap();
    assert!(copy.revisions().len() >= 2, "the new revision arrived");
}

#[test]
fn an_acknowledgement_is_recorded_in_the_copy_you_name_and_refused_in_another() {
    let mut o = org_on_a_relay();
    share_to_b(&mut o);
    let id = o.letter("b");
    cli(
        &mut o.env,
        &format!("inbox open {id} {} --out /b/copy.kqtf", o.b),
    );
    let ack = o.letter("a");

    // With no file named the letter is listed and left, even for the sweep.
    let sweep = cli(&mut o.env, &format!("inbox open {}", o.a));
    assert!(sweep.contains("--file"), "{sweep}");
    assert!(cli(&mut o.env, &format!("inbox list {}", o.a)).contains("answer to your tracked file"));

    o.env
        .fs
        .write_new(Path::new("/work/other.txt"), b"other\n")
        .unwrap();
    file_ok(
        &mut o.env,
        &format!(
            "track /work/other.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let wrong = cli_err(
        &mut o.env,
        &format!("inbox open {ack} {} --file /work/other.txt.kqtf", o.a),
    );
    assert!(wrong.contains("could not be opened"), "{wrong}");

    let out = cli(
        &mut o.env,
        &format!("inbox open {ack} {} --file {KQTF}", o.a),
    );
    assert!(out.contains("accepted by M.B"), "{out}");
    let history = file_ok(&mut o.env, &format!("history {KQTF}"));
    assert!(history.contains("ShareDelivered"), "{history}");
}

#[test]
fn a_request_needs_a_decision_and_the_answer_is_recorded_where_you_say() {
    let mut o = org_on_a_relay();
    // M.B asks M.A for a change to the file, naming it by id (M.B holds no copy).
    let file = TrackedFile::decode(&o.env.fs.read(Path::new(KQTF)).unwrap()).unwrap();
    let id_hex = hex::encode(file.file_id);
    let out = cli(
        &mut o.env,
        &format!(
            "file request --file-id {id_hex} --name report.txt --to M.A --as M.B --slot {} --push",
            slot("M.B")
        ),
    );
    assert!(
        out.contains("Relay stored letter") || out.contains("Sealed"),
        "{out}"
    );
    let req = o.letter("a");

    // No decision: listed, never guessed, and still waiting after the sweep.
    let sweep = cli(&mut o.env, &format!("inbox open {}", o.a));
    assert!(sweep.contains("--accept"), "{sweep}");
    let listed = cli(&mut o.env, &format!("inbox list {}", o.a));
    assert!(listed.contains("request"), "{listed}");

    let answered = cli(
        &mut o.env,
        &format!("inbox open {req} {} --accept --file {KQTF}", o.a),
    );
    assert!(answered.contains("Accepted file request"), "{answered}");
    let history = file_ok(&mut o.env, &format!("history {KQTF}"));
    assert!(history.contains("FileRequested"), "{history}");

    // M.B reads the answer by naming the letter; the sweep alone leaves it.
    let answer = o.letter("b");
    let sweep = cli(&mut o.env, &format!("inbox open {}", o.b));
    assert!(sweep.contains("inbox open"), "{sweep}");
    let read = cli(&mut o.env, &format!("inbox open {answer} {}", o.b));
    assert!(read.to_lowercase().contains("accepted"), "{read}");
}

#[test]
fn a_history_snapshot_is_checked_against_a_copy_when_one_is_named() {
    let mut o = org_on_a_relay();
    let out = cli(
        &mut o.env,
        &format!(
            "file send-history {KQTF} --to M.B --as M.A --slot {} --push",
            slot("M.A")
        ),
    );
    assert!(
        out.contains("Relay stored letter") || out.contains("Sealed"),
        "{out}"
    );
    let id = o.letter("b");
    let out = cli(
        &mut o.env,
        &format!("inbox open {id} {} --file {KQTF}", o.b),
    );
    assert!(
        ["SAME", "LOCAL_AHEAD", "REMOTE_AHEAD", "DIVERGED"]
            .iter()
            .any(|w| out.contains(w)),
        "{out}"
    );
}

#[test]
fn the_file_and_decision_options_name_one_letter() {
    let mut o = org_on_a_relay();
    for flags in [
        "--into /b/x.kqtf",
        "--out /b/x.kqtf",
        "--file /work/report.txt.kqtf",
        "--accept",
        "--decline",
    ] {
        let message = cli_err(&mut o.env, &format!("inbox open {} {flags}", o.b));
        assert!(
            message.contains("give the letter's id"),
            "{flags}: {message}"
        );
    }
    let parse = |line: &str| {
        use clap::Parser;
        crate::cli::Cli::try_parse_from(line.split_whitespace())
    };
    assert!(parse("keyquorum inbox open 3 --accept --decline").is_err());
    assert!(parse("keyquorum inbox open 3 --into a --out b").is_err());
    assert!(parse("keyquorum inbox open 3 --accept --file x").is_ok());
}
