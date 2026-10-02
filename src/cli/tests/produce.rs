//! The commands that write sealed envelopes (`bridge private create`, ...)
//! can upload them themselves: change saved first, upload last.

use super::file::{org, DB};
use super::memory_env::{MemoryEnv, RELAY_URL};
use crate::relay::ApiKeyScope;
use crate::storage::Storage;
use clap::Parser;
use std::path::Path;

fn ok(env: &mut MemoryEnv, args: &str) -> String {
    let (result, out) = env.keyquorum(&format!("keyquorum {DB} {args}"));
    assert!(result.is_ok(), "{args}: {result:?}\n{out}");
    out
}

/// The org of `file` tests, a split tree, and a relay with a push key loaded.
fn org_on_a_relay() -> MemoryEnv {
    let mut env = org();
    env.attach_relay();
    env.now = Some("2026-10-02 12:00".into());
    for (dir, label) in [("m", "M"), ("ms1", "M.S.1"), ("ma", "M.A"), ("mb", "M.B")] {
        ok(
            &mut env,
            &format!("device register /usb/{dir} --slot {label} --type encryption"),
        );
    }
    ok(
        &mut env,
        "split --label M --leaf M.S=/keys/ms.pub --leaf M.A=/keys/ma.pub --generate-keys --register",
    );
    let push = env.relay_key(ApiKeyScope::InboxPush, None);
    ok(&mut env, &format!("loadkey {push} --url {RELAY_URL}"));
    env
}

const CREATE: &str = "bridge private create 1 --member M.S.1 --member M.A \
                      --supervisor M.S=/keys/ms.pub --self M.S.1";

fn bridges(env: &mut MemoryEnv) -> String {
    ok(env, "bridge private list")
}

fn staged(env: &MemoryEnv) -> Vec<std::path::PathBuf> {
    env.fs.list(Path::new("outbox")).unwrap_or_default()
}

#[test]
fn push_uploads_after_the_change_is_saved_and_leaves_no_files_behind() {
    let mut env = org_on_a_relay();
    let out = ok(&mut env, &format!("{CREATE} --push"));
    assert!(out.contains("Created private bridge"), "{out}");
    assert!(out.contains("-> uploaded to https://relay.test"), "{out}");
    assert!(
        out.contains("Uploaded 4 envelopes to https://relay.test"),
        "{out}"
    );
    assert!(
        !out.contains("Wrote "),
        "staged files are not advertised: {out}"
    );
    assert!(staged(&env).is_empty(), "{:?}", staged(&env));
    assert!(!bridges(&mut env).contains("(no private bridges)"));
}

#[test]
fn an_output_dir_with_push_keeps_the_files_and_uploads() {
    let mut env = org_on_a_relay();
    let out = ok(&mut env, &format!("{CREATE} --push --output-dir /pb"));
    assert!(out.contains("-> /pb/M.A.kqpb"), "{out}");
    assert!(out.contains("Uploaded 4 envelopes"), "{out}");
    assert_eq!(env.fs.list(Path::new("/pb")).unwrap().len(), 4);
}

#[test]
fn without_push_nothing_is_uploaded() {
    let mut env = org_on_a_relay();
    let out = ok(&mut env, &format!("{CREATE} --output-dir /pb"));
    assert!(out.contains("-> /pb/M.A.kqpb"), "{out}");
    assert!(!out.contains("Uploaded"), "{out}");
}

#[test]
fn a_failed_upload_leaves_the_change_saved_the_files_in_place_and_says_how_to_finish() {
    let mut env = org_on_a_relay();
    env.fs
        .write_new(Path::new("outbox/unrelated.kqpb"), b"unrelated")
        .unwrap();
    env.relay.as_mut().unwrap().fail_uploads = true;
    let (result, _) = env.keyquorum(&format!("keyquorum {DB} {CREATE} --push"));
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("the change is saved, but the upload failed"),
        "{message}"
    );
    assert!(
        message.contains("keyquorum relay push --dir outbox/retry-"),
        "{message}"
    );
    assert!(!bridges(&mut env).contains("(no private bridges)"), "saved");
    assert!(env.fs.exists(Path::new("outbox/unrelated.kqpb")));

    let retry_dir = message
        .split("keyquorum relay push --dir ")
        .nth(1)
        .and_then(|tail| tail.split('`').next())
        .expect("retry directory in error");
    assert_eq!(
        env.fs.list(Path::new(retry_dir)).unwrap().len(),
        4,
        "only this operation is kept for the retry"
    );

    env.relay.as_mut().unwrap().fail_uploads = false;
    let out = ok(&mut env, &format!("relay push --dir {retry_dir}"));
    assert!(out.contains("-> id"), "{out}");
    assert!(env.fs.exists(Path::new("outbox/unrelated.kqpb")));
}

#[test]
fn a_partial_upload_failure_does_not_resend_what_the_relay_already_accepted() {
    let mut env = org_on_a_relay();
    env.relay.as_mut().unwrap().fail_uploads_after = Some(1);
    let (result, _) = env.keyquorum(&format!("keyquorum {DB} {CREATE} --push"));
    let message = result.unwrap_err().to_string();
    let retry_dir = message
        .split("keyquorum relay push --dir ")
        .nth(1)
        .and_then(|tail| tail.split('`').next())
        .expect("retry directory in error");
    assert_eq!(
        env.fs.list(Path::new(retry_dir)).unwrap().len(),
        3,
        "the one the relay accepted is gone, so a retry cannot send it twice"
    );

    env.relay.as_mut().unwrap().fail_uploads_after = None;
    let out = ok(&mut env, &format!("relay push --dir {retry_dir}"));
    assert_eq!(out.matches("-> id").count(), 3, "{out}");
}

#[test]
fn a_named_output_dir_is_kept_and_the_error_lists_what_is_left() {
    let mut env = org_on_a_relay();
    env.relay.as_mut().unwrap().fail_uploads_after = Some(1);
    let (result, _) = env.keyquorum(&format!("keyquorum {DB} {CREATE} --push --output-dir /out"));
    let message = result.unwrap_err().to_string();
    assert!(message.contains("still to send"), "{message}");
    assert_eq!(env.fs.list(Path::new("/out")).unwrap().len(), 4, "kept");
}

#[test]
fn a_relay_that_cannot_be_trusted_stops_the_command_before_anything_changes() {
    let mut env = org_on_a_relay();
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} {CREATE} --push --api-key kq_not-a-real-key"
    ));
    assert!(result.is_err());
    assert!(
        bridges(&mut env).contains("(no private bridges)"),
        "nothing committed"
    );
    assert!(staged(&env).is_empty(), "nothing written");
}

#[test]
fn a_destination_is_still_required_and_upload_flags_need_push() {
    let parse = |line: &str| crate::cli::Cli::try_parse_from(line.split_whitespace());
    assert!(parse("keyquorum bridge private create 1 --member M.S.1").is_err());
    assert!(parse("keyquorum bridge private create 1 --member M.S.1 --push").is_ok());
    assert!(parse(
        "keyquorum bridge private create 1 --member M.S.1 --output-dir /o --url https://r.test"
    )
    .is_err());
    assert!(parse(
        "keyquorum reissue --node M.S --as M --encryption-public-key-file a --output-dir /o"
    )
    .is_ok());
    assert!(parse("keyquorum tree restructure 1 --as M --push").is_ok());
}

#[test]
fn tree_publish_with_no_id_publishes_every_tree() {
    let mut env = org_on_a_relay();
    let admin = env.relay_key(ApiKeyScope::Admin, None);
    ok(&mut env, &format!("loadkey {admin} --url {RELAY_URL}"));
    let out = ok(&mut env, "tree publish");
    assert!(out.contains("Published M"), "{out}");
}

#[test]
fn tree_publish_with_nothing_to_publish_says_so() {
    let mut env = org_on_a_relay();
    env.keyquorum(&format!("keyquorum {DB} remove 1")).0.ok();
    let (result, _) = env.keyquorum("keyquorum --db /home/empty/keyquorum.sqlite tree publish");
    assert!(result.unwrap_err().to_string().contains("no split tree"));
}

#[test]
fn a_slot_signs_for_a_restructure_without_a_key_file() {
    let mut env = org_on_a_relay();
    let out = ok(
        &mut env,
        "tree restructure 1 --as M --slot /usb/m=M --output-dir /re",
    );
    assert!(out.contains("is now at public generation"), "{out}");
    assert!(!env.fs.list(Path::new("/re")).unwrap().is_empty());
}

#[test]
fn the_profile_device_signs_when_neither_a_key_file_nor_a_slot_is_given() {
    let mut env = org_on_a_relay();
    ok(&mut env, "use --device /usb/m --slot M");
    // The profile names M's device; --as M opens that container as M.
    let out = ok(&mut env, "tree restructure 1 --as M --push");
    assert!(out.contains("is now at public generation"), "{out}");
    assert!(out.contains("Uploaded"), "{out}");
}

#[test]
fn a_slot_for_another_label_is_refused() {
    let mut env = org_on_a_relay();
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} tree restructure 1 --as M --slot /usb/ms1=M.S.1 --output-dir /re"
    ));
    assert!(result.unwrap_err().to_string().contains("does not match"));
}

#[test]
fn tree_fetch_with_no_id_needs_exactly_one_tree() {
    let mut env = org_on_a_relay();
    let pull = env.relay_key(ApiKeyScope::InboxPull, Some("0".repeat(64)));
    ok(&mut env, &format!("loadkey {pull} --url {RELAY_URL}"));
    // One tree: it is chosen, and the relay (which holds no such tree yet)
    // is the one that answers.
    let (result, _) = env.keyquorum(&format!("keyquorum {DB} tree fetch"));
    let message = result.unwrap_err().to_string();
    assert!(!message.contains("exactly one tree"), "{message}");
    // No tree at all: the store cannot say which one is meant.
    let (result, _) = env.keyquorum("keyquorum --db /home/empty/keyquorum.sqlite tree fetch");
    assert!(result.unwrap_err().to_string().contains("exactly one tree"));
}
