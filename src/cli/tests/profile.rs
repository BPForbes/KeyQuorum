use super::memory_env::MemoryEnv;
use crate::db::{cache, profile};

fn alice() -> MemoryEnv {
    let mut env = MemoryEnv::default();
    assert!(env.device("keyquorum-device init /usb/alice").0.is_ok());
    assert!(env
        .device("keyquorum-device provision /usb/alice --label alice")
        .0
        .is_ok());
    env
}

/// Run a command that must succeed.
fn run(env: &mut MemoryEnv, line: &str) -> String {
    let (ok, out) = env.keyquorum(line);
    assert!(ok.is_ok(), "{line}: {ok:?}");
    out
}

const DB: &str = "/home/alice/keyquorum.sqlite";

#[test]
fn use_stores_pointers_and_shows_them() {
    let mut env = alice();
    let (ok, out) = env.keyquorum(&format!(
        "keyquorum --db {DB} use --device /usb/alice --slot alice"
    ));
    assert!(ok.is_ok(), "{ok:?}");
    assert!(out.contains("default_container = /usb/alice"), "{out}");
    assert!(out.contains("default_slot_label = alice"), "{out}");
    assert!(out.contains("default_label = alice"), "{out}");
    assert!(out.contains("caching = on"), "{out}");
    let (_, shown) = env.keyquorum(&format!("keyquorum --db {DB} use --show"));
    assert_eq!(out, shown);
}

#[test]
fn use_refuses_a_slot_the_container_does_not_hold() {
    let mut env = alice();
    let (ok, _) = env.keyquorum(&format!(
        "keyquorum --db {DB} use --device /usb/alice --slot nobody"
    ));
    assert!(ok.unwrap_err().to_string().contains("no slot nobody"));
    let (_, shown) = env.keyquorum(&format!("keyquorum --db {DB} use --show"));
    assert!(shown.contains("No defaults set"), "{shown}");
}

#[test]
fn use_stores_no_secret_and_only_known_keys() {
    let mut env = alice();
    run(
        &mut env,
        &format!("keyquorum --db {DB} use --device /usb/alice --slot alice"),
    );
    let conn = env.store(DB);
    let rows = profile::all(conn).unwrap();
    let keys: Vec<_> = rows.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        ["default_container", "default_label", "default_slot_label"]
    );
    assert!(rows.iter().all(|(_, v)| !v.contains("correct horse")));
}

#[test]
fn use_clear_forgets_the_defaults() {
    let mut env = alice();
    run(
        &mut env,
        &format!("keyquorum --db {DB} use --device /usb/alice --slot alice"),
    );
    let (ok, _) = env.keyquorum(&format!("keyquorum --db {DB} use --clear"));
    assert!(ok.is_ok());
    assert!(profile::all(env.store(DB)).unwrap().is_empty());
}

#[test]
fn keyquorum_db_selects_the_database_and_the_flag_overrides_it() {
    let mut env = alice();
    env.vars
        .insert("KEYQUORUM_DB".into(), "/home/alice/from-env.sqlite".into());
    run(&mut env, "keyquorum use --device /usb/alice --slot alice");
    assert!(!profile::all(env.store("/home/alice/from-env.sqlite"))
        .unwrap()
        .is_empty());
    run(
        &mut env,
        &format!("keyquorum --db {DB} use --label explicit"),
    );
    assert_eq!(
        profile::get(env.store(DB), profile::DEFAULT_LABEL)
            .unwrap()
            .as_deref(),
        Some("explicit")
    );
}

#[test]
fn cache_off_empties_and_disables_the_caches() {
    let mut env = alice();
    run(&mut env, &format!("keyquorum --db {DB} use --cache on"));
    cache::remember(env.store(DB), "to", "M.A", "2026-09-27 00:00").unwrap();
    let (_, status) = env.keyquorum(&format!("keyquorum --db {DB} cache status"));
    assert!(status.contains("recent parameters: 1"), "{status}");
    run(&mut env, &format!("keyquorum --db {DB} use --cache off"));
    let (_, status) = env.keyquorum(&format!("keyquorum --db {DB} cache status"));
    assert!(status.contains("caching off"), "{status}");
    assert!(status.contains("recent parameters: 0"), "{status}");
}

#[test]
fn no_cache_flag_and_variable_turn_caching_off_for_one_command() {
    let mut env = alice();
    let (_, status) = env.keyquorum(&format!("keyquorum --db {DB} --no-cache cache status"));
    assert!(status.contains("caching off"), "{status}");
    let (_, status) = env.keyquorum(&format!("keyquorum --db {DB} cache status"));
    assert!(status.contains("caching on"), "{status}");
    env.vars.insert("KEYQUORUM_NO_CACHE".into(), "1".into());
    let (_, status) = env.keyquorum(&format!("keyquorum --db {DB} cache status"));
    assert!(status.contains("caching off"), "{status}");
}

#[test]
fn cache_clear_keeps_the_profile() {
    let mut env = alice();
    run(
        &mut env,
        &format!("keyquorum --db {DB} use --device /usb/alice --slot alice"),
    );
    cache::remember(env.store(DB), "to", "M.A", "2026-09-27 00:00").unwrap();
    let (ok, _) = env.keyquorum(&format!("keyquorum --db {DB} cache clear"));
    assert!(ok.is_ok());
    assert_eq!(
        cache::recall(env.store(DB), "to", "2026-09-27 00:00").unwrap(),
        None
    );
    assert!(!profile::all(env.store(DB)).unwrap().is_empty());
}

mod relay_trust {
    use super::*;
    use crate::cli::tests::memory_env::RELAY_URL;
    use crate::relay::ApiKeyScope;
    use std::path::Path;

    const ALICE: &str = "keyquorum --db /home/alice/keyquorum.sqlite";

    /// Alice has a container, a stored push key, and a note to send.
    fn alice_with_a_relay() -> MemoryEnv {
        let mut env = MemoryEnv::with_relay();
        env.device("keyquorum-device init /usb/alice").0.unwrap();
        env.device("keyquorum-device provision /usb/alice --label alice")
            .0
            .unwrap();
        env.device("keyquorum-device init /usb/bob").0.unwrap();
        env.device("keyquorum-device provision /usb/bob --label bob")
            .0
            .unwrap();
        for (owner, kind) in [
            ("alice", "encryption"),
            ("alice", "signing"),
            ("bob", "encryption"),
        ] {
            run(
                &mut env,
                &format!("{ALICE} device register /usb/{owner} --slot {owner} --type {kind}"),
            );
        }
        run(
            &mut env,
            &format!("{ALICE} use --device /usb/alice --slot alice"),
        );
        use crate::storage::Storage;
        env.fs
            .write_new(Path::new("/home/alice/note.txt"), b"hi")
            .unwrap();
        env.now = Some("2026-10-02 12:00".into());
        let key = env.relay_key(ApiKeyScope::InboxPush, None);
        run(
            &mut env,
            &format!("{ALICE} loadkey {key} --url {RELAY_URL}"),
        );
        env
    }

    fn send(env: &mut MemoryEnv, extra: &str) {
        let line =
            format!("{ALICE} {extra} deliver send --file /home/alice/note.txt --to bob --push");
        let (ok, _) = env.keyquorum(&line);
        assert!(ok.is_ok(), "{line}: {ok:?}");
    }

    fn challenges(env: &MemoryEnv) -> usize {
        env.relay.as_ref().unwrap().identity_challenges
    }

    #[test]
    fn a_passed_check_is_reused_for_fifteen_minutes_then_repeated() {
        let mut env = alice_with_a_relay();
        let after_loadkey = challenges(&env);
        assert_eq!(after_loadkey, 1, "loadkey always runs the full challenge");

        send(&mut env, "");
        assert_eq!(challenges(&env), after_loadkey + 1, "first send checks");
        send(&mut env, "");
        assert_eq!(challenges(&env), after_loadkey + 1, "second send reuses it");

        env.now = Some("2026-10-02 12:14".into());
        send(&mut env, "");
        assert_eq!(challenges(&env), after_loadkey + 1, "still fresh at 14m");

        env.now = Some("2026-10-02 12:15".into());
        send(&mut env, "");
        assert_eq!(challenges(&env), after_loadkey + 2, "stale at 15m");
    }

    #[test]
    fn no_cache_and_cache_off_repeat_the_challenge_every_time() {
        let mut env = alice_with_a_relay();
        send(&mut env, "");
        let base = challenges(&env);
        send(&mut env, "--no-cache");
        send(&mut env, "--no-cache");
        assert_eq!(challenges(&env), base + 2);

        run(&mut env, &format!("{ALICE} use --cache off"));
        send(&mut env, "");
        send(&mut env, "");
        assert_eq!(challenges(&env), base + 4);
        let conn = env.store("/home/alice/keyquorum.sqlite");
        let held: i64 = conn
            .query_row("SELECT count(*) FROM relay_trust_cache", [], |r| r.get(0))
            .unwrap();
        assert_eq!(held, 0, "nothing is written while caching is off");
    }

    #[test]
    fn loadkey_forgets_a_cached_pass_and_challenges_again() {
        let mut env = alice_with_a_relay();
        send(&mut env, "");
        let base = challenges(&env);
        let key = env.relay_key(ApiKeyScope::InboxPush, None);
        run(
            &mut env,
            &format!("{ALICE} loadkey {key} --url {RELAY_URL}"),
        );
        assert_eq!(challenges(&env), base + 1);
        send(&mut env, "");
        assert_eq!(challenges(&env), base + 2, "the pass was dropped");
    }

    #[test]
    fn the_cache_holds_no_bearer_and_no_failure() {
        let mut env = alice_with_a_relay();
        send(&mut env, "");
        let conn = env.store("/home/alice/keyquorum.sqlite");
        let (hash, valid_until): (String, String) = conn
            .query_row(
                "SELECT key_hash, valid_until FROM relay_trust_cache",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(hash.len(), 64, "a hash, not a bearer");
        assert_eq!(valid_until, "2026-10-02 12:15:00");
    }
}
