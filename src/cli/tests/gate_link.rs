use super::file::{ok, org, run, slot, track, DB, KQTF};
use super::memory_env::MemoryEnv;
use crate::storage::Storage;
use std::path::Path;

const SECRET: &[u8] = b"the launch code is 0000";

/// A two-of-two quorum file (`Q.A`, `Q.B`) as file 1, next to a tracked
/// `report.txt` owned by M.A.
fn gated() -> MemoryEnv {
    let mut env = org();
    for (dir, label) in [("qa", "Q.A"), ("qb", "Q.B")] {
        env.device(&format!("keyquorum-device init /usb/{dir}"))
            .0
            .unwrap();
        let (result, _) = env.device(&format!(
            "keyquorum-device provision /usb/{dir} --label {label}"
        ));
        assert!(result.is_ok(), "{result:?}");
        let (result, out) = env.device(&format!(
            "keyquorum-device public /usb/{dir} --label {label}"
        ));
        assert!(result.is_ok(), "{out}");
        let key = out
            .lines()
            .find_map(|line| line.trim().strip_prefix("encryption "))
            .expect("an encryption key");
        env.fs
            .write(Path::new(&format!("/keys/{dir}.pub")), key.as_bytes())
            .unwrap();
        let (result, out) = env.keyquorum(&format!(
            "keyquorum {DB} device register /usb/{dir} --slot {label} --type encryption"
        ));
        assert!(result.is_ok(), "{out}");
    }
    env.fs.write(Path::new("/work/secret.txt"), SECRET).unwrap();
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {DB} access quorum --state 0 --source /work/secret.txt \
         --encrypted-path /work/secret.kqenc --name secret.txt --root Q --threshold 2 \
         --leaf Q.A=/keys/qa.pub --leaf Q.B=/keys/qb.pub"
    ));
    assert!(result.is_ok(), "{out}");
    track(&mut env, "M.A", "M.A");
    env
}

fn unlock(env: &mut MemoryEnv, slots: &str) -> (crate::error::Result<()>, String) {
    env.keyquorum(&format!(
        "keyquorum {DB} access quorum --state 1 --id 1 {slots} --output /work/out.txt"
    ))
}

const BOTH: &str = "--slot /usb/qa=Q.A --slot /usb/qb=Q.B";

fn history(env: &mut MemoryEnv) -> String {
    ok(env, &format!("history {KQTF}"))
}

#[test]
fn linking_records_the_link_and_refuses_unknown_gates_and_repeat_unlinks() {
    let mut env = gated();
    let (result, _) = run(&mut env, &format!("link {KQTF} --quorum-file 99"));
    assert!(result.is_err());
    let out = ok(&mut env, &format!("link {KQTF} --quorum-file 1"));
    assert!(out.contains("Linked quorum file 1"), "{out}");
    assert!(ok(&mut env, &format!("link {KQTF} --quorum-file 1")).contains("Already linked"));
    assert_eq!(history(&mut env).matches("GateLinked").count(), 1);
    ok(&mut env, &format!("unlink {KQTF} --quorum-file 1"));
    let (result, _) = run(&mut env, &format!("unlink {KQTF} --quorum-file 1"));
    assert!(result.is_err());
}

#[test]
fn quorum_unlocks_are_recorded_with_the_gates_own_answer_and_no_secrets() {
    let mut env = gated();
    ok(&mut env, &format!("link {KQTF} --quorum-file 1"));

    // One share never reaches the gate (shares are collected first), so
    // neither the gate's audit nor history hears of it.
    let (result, _) = unlock(&mut env, "--slot /usb/qa=Q.A");
    assert!(result.is_err());
    assert!(!env.fs.exists(Path::new("/work/out.txt")));
    let (result, out) = unlock(&mut env, BOTH);
    assert!(result.is_ok(), "{out}");
    assert_eq!(env.fs.read(Path::new("/work/out.txt")).unwrap(), SECRET);

    let history = history(&mut env);
    let lines: Vec<&str> = history
        .lines()
        .filter(|l| l.contains("QuorumUnlockAttempted"))
        .collect();
    assert_eq!(lines.len(), 1, "{history}");
    assert!(
        lines[0].contains("Success") && lines[0].contains("presented=Q.A,Q.B"),
        "{history}"
    );
    assert!(!history.contains("launch code"));
    // The gate's own audit row is still written, once per attempt.
    let audited: i64 = env
        .store("/home/org/keyquorum.sqlite")
        .query_row(
            "SELECT COUNT(*) FROM unlock_events WHERE file_id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audited, 1);
    assert!(ok(&mut env, &format!("verify {KQTF}")).contains("verify"));
}

#[test]
fn an_unlinked_file_is_untouched_and_a_missing_container_never_blocks_the_gate() {
    let mut env = gated();
    let (result, _) = unlock(&mut env, BOTH);
    assert!(result.is_ok());
    assert!(!history(&mut env).contains("QuorumUnlockAttempted"));

    ok(&mut env, &format!("link {KQTF} --quorum-file 1"));
    env.fs.delete(Path::new(KQTF)).ok();
    env.fs.delete(Path::new("/work/out.txt")).ok();
    let (result, out) = unlock(&mut env, BOTH);
    assert!(result.is_ok(), "{out}");
    assert_eq!(env.fs.read(Path::new("/work/out.txt")).unwrap(), SECRET);
}

#[test]
fn expiry_leaves_a_tombstone_and_later_attempts_are_recorded() {
    let mut env = gated();
    ok(&mut env, &format!("link {KQTF} --quorum-file 1"));
    env.store("/home/org/keyquorum.sqlite")
        .execute(
            "UPDATE files SET expires_at = '2000-01-01 00:00:00' WHERE id = 1",
            [],
        )
        .unwrap();

    let (result, _) = unlock(&mut env, BOTH);
    assert!(
        matches!(result, Err(crate::error::Error::FileExpired)),
        "{result:?}"
    );
    assert!(!env.fs.exists(Path::new("/work/secret.kqenc")));
    let text = history(&mut env);
    for kind in ["FileExpired", "ContentDestroyed", "ExpiredAccessAttempt"] {
        assert_eq!(text.matches(kind).count(), 1, "{kind}\n{text}");
    }
    assert!(!text.contains("QuorumUnlockAttempted"));

    // The file is gone, so the next attempt fails, and is still noted.
    let (result, _) = unlock(&mut env, BOTH);
    assert!(result.is_err());
    assert_eq!(history(&mut env).matches("ExpiredAccessAttempt").count(), 2);
}

#[test]
fn a_refusal_by_the_gate_is_recorded_as_a_failure_and_the_gate_still_refuses() {
    let mut env = gated();
    ok(&mut env, &format!("link {KQTF} --quorum-file 1"));
    // Two devices present, three required: the gate refuses after the
    // shares combine.
    env.store("/home/org/keyquorum.sqlite")
        .execute(
            "UPDATE keys SET minimum_physical_devices = 3
             WHERE id = (SELECT key_id FROM files WHERE id = 1)",
            [],
        )
        .unwrap();
    let (result, _) = unlock(&mut env, BOTH);
    assert!(result.is_err());
    assert!(!env.fs.exists(Path::new("/work/out.txt")));
    let text = history(&mut env);
    let line = text
        .lines()
        .find(|l| l.contains("QuorumUnlockAttempted"))
        .expect("a recorded attempt");
    assert!(
        line.contains("Failure") && line.contains("result=failed"),
        "{text}"
    );
    assert!(!text.contains("presented="), "{text}");
}
