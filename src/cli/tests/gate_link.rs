use super::file::{ok, org, run, track, DB, KQTF};
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

// ---- password-locked files -------------------------------------------------

/// `secret.txt` locked with a password as password file 1.
fn password_gated() -> MemoryEnv {
    let mut env = org();
    env.fs.write(Path::new("/work/secret.txt"), SECRET).unwrap();
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {DB} access password --state 0 --source /work/secret.txt \
         --encrypted-path /work/secret.kqenc"
    ));
    assert!(result.is_ok(), "{out}");
    track(&mut env, "M.A", "M.A");
    env
}

fn unlock_password(env: &mut MemoryEnv) -> (crate::error::Result<()>, String) {
    env.keyquorum(&format!(
        "keyquorum {DB} access password --state 1 --id 1 --output /work/out.txt"
    ))
}

#[test]
fn password_unlocks_are_recorded_and_the_password_never_is() {
    let mut env = password_gated();
    let out = ok(&mut env, &format!("link {KQTF} --locked-file 1"));
    assert!(out.contains("Linked password file 1"), "{out}");
    let (result, _) = run(&mut env, &format!("link {KQTF} --locked-file 9"));
    assert!(result.is_err());

    let (result, out) = unlock_password(&mut env);
    assert!(result.is_ok(), "{out}");
    assert_eq!(env.fs.read(Path::new("/work/out.txt")).unwrap(), SECRET);
    let text = history(&mut env);
    let line = text
        .lines()
        .find(|l| l.contains("PasswordUnlockAttempted"))
        .expect("a recorded attempt");
    assert!(
        line.contains("Success") && line.contains("gate=password"),
        "{text}"
    );
    assert!(!text.contains(super::memory_env::PASSPHRASE));
    assert!(!text.contains("launch code"));

    // A gate failure (its ciphertext is gone) is a recorded failure and
    // the gate's error still reaches the caller.
    env.fs.delete(Path::new("/work/secret.kqenc")).unwrap();
    let (result, _) = unlock_password(&mut env);
    assert!(result.is_err());
    let text = history(&mut env);
    assert_eq!(text.matches("PasswordUnlockAttempted").count(), 2, "{text}");
    assert!(text
        .lines()
        .any(|l| l.contains("PasswordUnlockAttempted") && l.contains("Failure")));
}

#[test]
fn a_password_files_expiry_leaves_a_tombstone() {
    let mut env = password_gated();
    ok(&mut env, &format!("link {KQTF} --locked-file 1"));
    env.store("/home/org/keyquorum.sqlite")
        .execute(
            "UPDATE password_locked_files SET expires_at = '2000-01-01 00:00:00' WHERE id = 1",
            [],
        )
        .unwrap();
    let (result, _) = unlock_password(&mut env);
    assert!(
        matches!(result, Err(crate::error::Error::FileExpired)),
        "{result:?}"
    );
    let text = history(&mut env);
    for kind in ["FileExpired", "ContentDestroyed", "ExpiredAccessAttempt"] {
        assert_eq!(text.matches(kind).count(), 1, "{kind}\n{text}");
    }
    let (result, _) = unlock_password(&mut env);
    assert!(result.is_err());
    assert_eq!(history(&mut env).matches("ExpiredAccessAttempt").count(), 2);
    ok(&mut env, &format!("unlink {KQTF} --locked-file 1"));
}

#[test]
fn a_reused_gate_id_is_not_mistaken_for_the_file_that_was_linked() {
    let mut env = gated();
    ok(&mut env, &format!("link {KQTF} --quorum-file 1"));
    env.store("/home/org/keyquorum.sqlite")
        .execute(
            "UPDATE files SET expires_at = '2000-01-01 00:00:00' WHERE id = 1",
            [],
        )
        .unwrap();
    let (result, _) = unlock(&mut env, BOTH);
    assert!(matches!(result, Err(crate::error::Error::FileExpired)));
    let before = history(&mut env);

    // SQLite hands the freed id to the next file.
    env.fs
        .write(Path::new("/work/second.txt"), b"unrelated")
        .unwrap();
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {DB} access quorum --state 0 --source /work/second.txt \
         --encrypted-path /work/second.kqenc --name second.txt --root Q --threshold 2 \
         --leaf Q.A=/keys/qa.pub --leaf Q.B=/keys/qb.pub"
    ));
    assert!(result.is_ok(), "{out}");
    let id: i64 = env
        .store("/home/org/keyquorum.sqlite")
        .query_row("SELECT id FROM files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(id, 1, "the id was reused");
    let (result, out) = unlock(&mut env, BOTH);
    assert!(result.is_ok(), "{out}");
    assert_eq!(
        history(&mut env),
        before,
        "the new file wrote into the old history"
    );
}

#[test]
fn a_different_tracked_file_at_the_linked_path_is_never_written_to() {
    let mut env = gated();
    ok(&mut env, &format!("link {KQTF} --quorum-file 1"));
    // Replace the container with another file's history at the same path.
    env.fs
        .write(Path::new("/work/other.txt"), b"other")
        .unwrap();
    ok(
        &mut env,
        &format!(
            "track /work/other.txt --scope M.A --as M.A --slot {} --out /work/other.kqtf",
            super::file::slot("M.A")
        ),
    );
    let other = env.fs.read(Path::new("/work/other.kqtf")).unwrap();
    env.fs.write(Path::new(KQTF), &other).unwrap();
    let (result, out) = unlock(&mut env, BOTH);
    assert!(result.is_ok(), "{out}");
    assert!(!history(&mut env).contains("QuorumUnlockAttempted"));
}

#[test]
fn linking_a_copy_moves_the_recording_to_it() {
    let mut env = gated();
    ok(&mut env, &format!("link {KQTF} --quorum-file 1"));
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new("/work/copy.kqtf"), &bytes).unwrap();
    let out = ok(&mut env, "link /work/copy.kqtf --quorum-file 1");
    assert!(out.contains("now recording to /work/copy.kqtf"), "{out}");
    let (result, _) = unlock(&mut env, BOTH);
    assert!(result.is_ok());
    assert!(ok(&mut env, "history /work/copy.kqtf").contains("QuorumUnlockAttempted"));
    assert!(!history(&mut env).contains("QuorumUnlockAttempted"));
}

#[test]
fn a_reused_password_file_id_is_not_mistaken_for_the_file_that_was_linked() {
    let mut env = password_gated();
    ok(&mut env, &format!("link {KQTF} --locked-file 1"));
    env.store("/home/org/keyquorum.sqlite")
        .execute(
            "UPDATE password_locked_files SET expires_at = '2000-01-01 00:00:00' WHERE id = 1",
            [],
        )
        .unwrap();
    let (result, _) = unlock_password(&mut env);
    assert!(matches!(result, Err(crate::error::Error::FileExpired)));
    let before = history(&mut env);

    env.fs
        .write(Path::new("/work/second.txt"), b"unrelated")
        .unwrap();
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {DB} access password --state 0 --source /work/second.txt \
         --encrypted-path /work/second.kqenc"
    ));
    assert!(result.is_ok(), "{out}");
    let id: i64 = env
        .store("/home/org/keyquorum.sqlite")
        .query_row("SELECT id FROM password_locked_files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(id, 1, "the id was reused");
    let (result, out) = unlock_password(&mut env);
    assert!(result.is_ok(), "{out}");
    assert_eq!(
        history(&mut env),
        before,
        "the new file wrote into the old history"
    );
    // Linking the tracked file to the new file is a fresh link, not "Already linked".
    let out = ok(&mut env, &format!("link {KQTF} --locked-file 1"));
    assert!(out.contains("Linked password file 1"), "{out}");
}

// ---- shares ----------------------------------------------------------------

fn share_line(env: &mut MemoryEnv, args: &str) -> (crate::error::Result<()>, String) {
    env.keyquorum(&format!("keyquorum {DB} share {args}"))
}

fn token_of(out: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix("Token:"))
        .map(|t| t.trim().to_string())
        .expect("a token")
}

#[test]
fn share_create_redeem_and_revoke_are_recorded_without_the_token() {
    let mut env = password_gated();
    ok(&mut env, &format!("link {KQTF} --locked-file 1"));

    let (result, out) = share_line(&mut env, "create-file 1 --max-uses 1");
    assert!(result.is_ok(), "{out}");
    let token = token_of(&out);
    env.prompts.push_back(token.clone());
    let (result, out) = share_line(&mut env, "redeem-file");
    assert!(result.is_ok(), "{out}");
    // The single use is spent, so a second redemption is refused and noted.
    env.prompts.push_back(token.clone());
    let (result, _) = share_line(&mut env, "redeem-file");
    assert!(result.is_err());
    let (result, _) = share_line(&mut env, "revoke-file 1");
    assert!(result.is_ok());

    let text = history(&mut env);
    assert_eq!(text.matches("ShareLinkCreated").count(), 1, "{text}");
    assert_eq!(text.matches("ShareLinkRedeemed").count(), 2, "{text}");
    assert_eq!(text.matches("ShareLinkRevoked").count(), 1, "{text}");
    assert!(text
        .lines()
        .any(|l| l.contains("ShareLinkRedeemed") && l.contains("Failure")));
    assert!(!text.contains(&token), "the bearer token reached history");
    // Nothing proves who held the token, so history says exactly that.
    assert!(
        text.lines()
            .filter(|l| l.contains("ShareLinkRedeemed"))
            .all(|l| l.contains("redeemer=UNKNOWN_BEARER")),
        "{text}"
    );
    assert!(
        !text
            .lines()
            .any(|l| l.contains("ShareLinkCreated") && l.contains("redeemer=")),
        "{text}"
    );
}

#[test]
fn a_pin_check_at_the_password_gate_records_only_its_outcome() {
    let mut env = org();
    env.fs.write(Path::new("/work/secret.txt"), SECRET).unwrap();
    // The lock password is asked first, then the PIN to set.
    env.prompts
        .push_back(super::memory_env::PASSPHRASE.to_string());
    env.prompts.push_back("4321".to_string());
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {DB} access password --state 0 --source /work/secret.txt \
         --encrypted-path /work/secret.kqenc --pin"
    ));
    assert!(result.is_ok(), "{out}");
    track(&mut env, "M.A", "M.A");
    ok(&mut env, &format!("link {KQTF} --locked-file 1"));

    // A wrong PIN, then the right one.
    env.prompts.push_back("0000".to_string());
    let (result, _) = unlock_password(&mut env);
    assert!(result.is_err());
    env.prompts.push_back("4321".to_string());
    let (result, out) = unlock_password(&mut env);
    assert!(result.is_ok(), "{out}");

    let text = history(&mut env);
    let attempts: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("PasswordUnlockAttempted"))
        .collect();
    assert_eq!(attempts.len(), 2, "{text}");
    assert!(attempts[0].contains("pin=mismatch"), "{text}");
    assert!(attempts[1].contains("pin=verified"), "{text}");
    assert!(!text.contains("4321"), "{text}");
}

#[test]
fn an_unlock_with_no_pin_records_no_pin_detail() {
    let mut env = password_gated();
    ok(&mut env, &format!("link {KQTF} --locked-file 1"));
    let (result, out) = unlock_password(&mut env);
    assert!(result.is_ok(), "{out}");
    let text = history(&mut env);
    assert!(!text.contains("pin="), "{text}");
}

#[test]
fn an_unknown_share_token_and_an_unlinked_file_record_nothing() {
    let mut env = password_gated();
    let (result, out) = share_line(&mut env, "create-file 1");
    assert!(result.is_ok(), "{out}");
    assert!(!history(&mut env).contains("ShareLink"));

    ok(&mut env, &format!("link {KQTF} --locked-file 1"));
    env.prompts.push_back("00".repeat(32));
    let (result, _) = share_line(&mut env, "redeem-file");
    assert!(result.is_err());
    assert!(!history(&mut env).contains("ShareLink"));
}

#[test]
fn redeeming_a_share_of_an_expired_file_leaves_the_tombstone() {
    let mut env = password_gated();
    ok(&mut env, &format!("link {KQTF} --locked-file 1"));
    let (result, out) = share_line(&mut env, "create-file 1 --max-uses 3");
    assert!(result.is_ok(), "{out}");
    let token = token_of(&out);
    env.store("/home/org/keyquorum.sqlite")
        .execute(
            "UPDATE password_locked_files SET expires_at = '2000-01-01 00:00:00' WHERE id = 1",
            [],
        )
        .unwrap();
    env.prompts.push_back(token);
    let (result, _) = share_line(&mut env, "redeem-file");
    assert!(
        matches!(result, Err(crate::error::Error::FileExpired)),
        "{result:?}"
    );
    let text = history(&mut env);
    for kind in ["FileExpired", "ContentDestroyed", "ExpiredAccessAttempt"] {
        assert_eq!(text.matches(kind).count(), 1, "{kind}\n{text}");
    }
}
