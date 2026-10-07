use super::super::*;

#[test]
fn share_options_reject_unusable_limits() {
    for args in [
        [
            "keyquorum",
            "share",
            "create-file",
            "1",
            "--ttl-seconds",
            "0",
        ],
        ["keyquorum", "share", "create-file", "1", "--max-uses", "-1"],
        [
            "keyquorum",
            "share",
            "create-file",
            "1",
            "--expires",
            "2026-12-31",
        ],
        [
            "keyquorum",
            "share",
            "create-file",
            "1",
            "--expires",
            "2026-13-01 00:00",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }

    assert!(Cli::try_parse_from([
        "keyquorum",
        "share",
        "create-file",
        "1",
        "--expires",
        "2026-12-31 23:59",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "password",
        "--state",
        "0",
        "--source",
        "secret.txt",
        "--encrypted-path",
        "secret.txt.kqenc",
        "--expires",
        "2026-12-31 23:59",
    ])
    .is_ok());
}

#[test]
fn pin_every_use_requires_enabling_a_pin() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "share",
        "create-credential",
        "1",
        "--pin-required-every-use",
    ])
    .is_err());
}

#[test]
fn quorum_status_rejects_mutating_options() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "quorum",
        "--status",
        "--id",
        "1",
        "--output",
        "plaintext",
    ])
    .is_err());
}

#[test]
fn access_modes_require_and_reject_mode_specific_options() {
    for args in [
        vec!["keyquorum", "access", "password", "--state", "0"],
        vec![
            "keyquorum",
            "access",
            "password",
            "--state",
            "1",
            "--id",
            "1",
            "--source",
            "plaintext",
        ],
        vec![
            "keyquorum",
            "access",
            "quorum",
            "--state",
            "0",
            "--source",
            "plaintext",
            "--encrypted-path",
            "ciphertext",
            "--tree-spec",
            "tree.json",
            "--leaf",
            "a=a.pub",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }

    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "password",
        "--state",
        "1",
        "--id",
        "1",
        "--output",
        "plaintext",
    ])
    .is_ok());
}

#[test]
fn top_level_tree_and_bridge_parse() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bridge",
        "allow",
        "1",
        "--node",
        "M.A.1",
        "--peer",
        "M.B",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bridge",
        "add",
        "1",
        "--from",
        "M.A.1",
        "--to",
        "M.B",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bridge",
        "remove",
        "1",
        "--from",
        "M.A.1",
        "--to",
        "M.B",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "lca", "1", "--node", "M.A.1", "M.A.2"]).is_err());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "1", "--node", "M.A.1", "M.A.2",]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "1", "--node", "only-one"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "reconstruct",
        "1",
        "--node",
        "M.A.1",
        "M.A.2",
        "--share-file",
        "alice.pub",
        "--output",
        "master.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "split",
        "--tree-spec",
        "team.json",
        "--label",
        "master pub",
        "--source",
        "master.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "split",
        "--label",
        "master",
        "--threshold",
        "2",
        "--leaf",
        "M.S=SoftwareDepartment.pub",
        "--leaf",
        "M.A=AccountingDepartment.pub",
        "--source",
        "master.pub",
        "--generate-keys",
        "--register",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "split",
        "--tree-spec",
        "org.json",
        "--label",
        "master",
        "--leaf",
        "M.S=SoftwareDepartment.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "spec", "--label", "M"]).is_err());
    assert!(
        Cli::try_parse_from(["keyquorum", "bind", "1", "--node", "M.S", "--peer", "M.A",]).is_ok()
    );
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bind",
        "1",
        "--node",
        "M.S",
        "--public-key-file",
        "NewSoftware.pub",
        "--share-file",
        "SoftwareDepartment.key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bind",
        "1",
        "--node",
        "M.S",
        "--peer",
        "M.A",
        "--public-key-file",
        "NewSoftware.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "add",
        "1",
        "--parent",
        "M",
        "--node",
        "M.F",
        "--public-key-file",
        "FinanceDepartment.pub",
        "--share-file",
        "SoftwareDepartment.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "1", "--output", "org.json",]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "tree",
        "1",
        "--node",
        "M.S",
        "M.A",
        "--output",
        "org.json",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "evict", "1", "--node-id", "5"]).is_err());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "revoke",
        "3",
        "--key-id",
        "1",
        "--node",
        "carol",
        "--evict",
        "--share-file",
        "alice.key",
        "--deny-peer",
        "it",
        "--remove-peer",
        "bob",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3", "--evict"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "publish", "1"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "fetch", "1"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "fetch", "--label", "master"]).is_ok());
    // With no id and no label, `fetch` uses the one tree the store holds
    // (and says so if it holds none or several), decided when it runs.
    assert!(Cli::try_parse_from(["keyquorum", "tree", "fetch"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "publish"]).is_ok());
    assert!(
        Cli::try_parse_from(["keyquorum", "tree", "project", "1", "--as-node", "M.S.2"]).is_err()
    );
    assert!(Cli::try_parse_from([
        "keyquorum",
        "generate",
        "--type",
        "encryption",
        "--public-key-out",
        "alice.pub",
        "--label",
        "alice",
        "--register",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "generate",
        "--type",
        "encryption",
        "--public-key-out",
        "alice.pub",
        "--register",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "quorum",
        "--state",
        "0",
        "--source",
        "secret.txt",
        "--encrypted-path",
        "secret.txt.kqenc",
        "--leaf",
        "alice=alice.pub",
        "--leaf",
        "bob=bob.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "key",
        "split",
        "--label",
        "master",
        "--leaf",
        "a=a.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3", "--key-id", "1", "--evict"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "revoke",
        "3",
        "--key-id",
        "1",
        "--node",
        "carol",
        "--share-file",
        "alice.key",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3", "--deny-peer", "it"]).is_err());
}

#[test]
fn infer_root_label_from_dotted_leaves_or_fallback() {
    assert_eq!(
        infer_root_label(&["M.S".into(), "M.A".into()], None, "master").unwrap(),
        "M"
    );
    assert_eq!(
        infer_root_label(&["alice".into(), "bob".into()], None, "team").unwrap(),
        "team"
    );
    assert_eq!(
        infer_root_label(&["M.S".into(), "M.A".into()], Some("org"), "master").unwrap(),
        "org"
    );
}

#[test]
fn relay_push_requires_dir() {
    assert!(Cli::try_parse_from(["keyquorum", "relay", "push"]).is_err());
}

#[test]
fn relay_pull_requires_output_or_import() {
    assert!(Cli::try_parse_from(["keyquorum", "relay", "pull"]).is_err());
}

#[test]
fn relay_pull_import_requires_share_file() {
    assert!(Cli::try_parse_from(["keyquorum", "relay", "pull", "--import"]).is_err());
}

#[test]
fn loadkey_bundle_excludes_a_typed_key_and_takes_a_slot_or_key_file() {
    assert!(Cli::try_parse_from(["keyquorum", "loadkey", "--bundle", "customer.kqkey"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "loadkey",
        "--bundle",
        "customer.kqkey",
        "--slot",
        "/usb/alice=alice",
        "--url",
        "https://relay.example.com",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "loadkey",
        "kq_example",
        "--bundle",
        "customer.kqkey"
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "loadkey", "--slot", "/usb/alice=alice"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "loadkey",
        "--bundle",
        "customer.kqkey",
        "--slot",
        "/usb/alice=alice",
        "--share-file",
        "alice.key"
    ])
    .is_err());
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_store_and_credential_file_flags_parse() {
    // The mailbox file may be named, and the MongoDB flags are gone.
    assert!(
        Cli::try_parse_from(["keyquorum", "host", "--mailbox-db", "relay.sqlite", "serve",])
            .is_ok()
    );
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "--mongodb-uri-file",
        "/run/secrets/mongodb-uri",
        "serve",
    ])
    .is_err());
    // The operator lock may come from a file; a file and a value together
    // are refused rather than guessed.
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "create",
        "--scope",
        "inbox.push",
        "--licensee-key-file",
        "/run/credentials/keyquorum-keys/licensee-key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "create",
        "--scope",
        "inbox.push",
        "--licensee-key-file",
        "lock",
        "--licensee-key",
        "kql_x",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "rotate",
        "3",
        "--licensee-key-file",
        "lock",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "rotate",
        "3",
        "--licensee-key-file",
        "lock",
        "--licensee-key",
        "kql_x",
    ])
    .is_err());
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_keys_list_parses() {
    assert!(Cli::try_parse_from(["keyquorum", "host", "keys", "list"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "--mailbox-db",
        "mailbox.sqlite",
        "serve",
        "--bind",
        "127.0.0.1:0",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "serve",
        "--scan-db",
        "org.sqlite",
        "--scan-interval-seconds",
        "15",
    ])
    .is_ok());
    assert!(
        Cli::try_parse_from(["keyquorum", "host", "serve", "--scan-interval-seconds", "0",])
            .is_err()
    );
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "serve",
        "--bind",
        "0.0.0.0:8787",
        "--behind-tls-proxy",
        "--rate-limit-per-minute",
        "0",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "events",
        "--key",
        "3",
        "--verify",
    ])
    .is_ok());
    assert!(
        Cli::try_parse_from(["keyquorum", "host", "keys", "events", "--krl", "x.kqrl"]).is_err()
    );
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "events",
        "--verify",
        "--checkpoint",
        "audit.checkpoint",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "events",
        "--checkpoint",
        "audit.checkpoint",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "checkpoint",
        "--out",
        "audit.checkpoint",
        "--cert",
        "provider.kqcert",
        "--relay-key",
        "relay.key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "host", "keys", "checkpoint"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "revoke",
        "3",
        "--cert",
        "provider.kqcert",
        "--relay-key",
        "relay.key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "host", "keys", "events"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "create",
        "--scope",
        "inbox.push",
        "--cert",
        "provider.kqcert",
        "--relay-key",
        "relay.key",
    ])
    .is_ok());
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_identity_and_certify_parse() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "identity",
        "generate",
        "--public-key-out",
        "relay.pub",
        "--private-key-out",
        "relay.key",
    ])
    .is_ok());
    // The private key has nowhere to go but an owner-only file.
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "identity",
        "generate",
        "--public-key-out",
        "relay.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "root",
        "generate",
        "--public-key-out",
        "root.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "certify",
        "--relay-public-key",
        "relay.pub",
        "--provider-id",
        "acme",
        "--serial",
        "KQP-1",
        "--expires-at",
        "2027-09-02 00:00:00",
        "--out",
        "provider.kqcert",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "krl",
        "--serial",
        "KQP-1",
        "--out",
        "revocations.kqrl",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "serve",
        "--cert",
        "provider.kqcert",
        "--relay-key",
        "relay.key",
        "--krl",
        "revocations.kqrl",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "root",
        "generate",
        "--public-key-out",
        "provider-root.pub",
        "--private-key-out",
        "provider-root.key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "root",
        "generate",
        "--public-key-out",
        "provider-root.pub",
        "--private-key-out",
        "provider-root.key",
        "--network",
        "10.8.0.0/24",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "root",
        "generate",
        "--public-key-out",
        "provider-root.pub",
        "--private-key-out",
        "provider-root.key",
        "--ssid",
        "Office",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "policy",
        "issue",
        "--relay-public-key",
        "relay.pub",
        "--provider-id",
        "acme",
        "--policy-id",
        "KQP-POL-1",
        "--expires-at",
        "2027-09-02 00:00:00",
        "--hardware-fingerprint",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--out",
        "provider.kqpolicy",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "policy",
        "issue",
        "--relay-public-key",
        "relay.pub",
        "--provider-id",
        "acme",
        "--policy-id",
        "KQP-POL-1",
        "--expires-at",
        "2027-09-02 00:00:00",
        "--hardware-fingerprint",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--corporate-network",
        "corp-vpn:10.8.0.0/24",
        "--out",
        "provider.kqpolicy",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "relay",
        "register",
        "--url",
        "http://127.0.0.1:8787",
        "--provider-id",
        "acme",
        "--hardware-key",
        "hw.key",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "create",
        "--scope",
        "inbox.push",
        "--cert",
        "provider.kqcert",
        "--relay-key",
        "relay.key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "rotate",
        "1",
        "--cert",
        "provider.kqcert",
        "--relay-key",
        "relay.key",
    ])
    .is_ok());
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_is_omitted_from_top_level_help() {
    use clap::CommandFactory;
    let help = Cli::command().render_long_help().to_string();
    assert!(
        !help
            .lines()
            .any(|line| line.split_whitespace().next() == Some("host")),
        "hidden host command leaked into --help:\n{help}"
    );
}

#[test]
fn reissue_needs_a_new_key_an_authority_and_an_output_dir() {
    // At least one of the two key files.
    assert!(Cli::try_parse_from([
        "keyquorum",
        "reissue",
        "--node",
        "M.S.2",
        "--as",
        "M",
        "--signing-key-file",
        "M.sign.key",
        "--output-dir",
        "./updates",
    ])
    .is_err());

    assert!(Cli::try_parse_from([
        "keyquorum",
        "reissue",
        "--node",
        "M.S.2",
        "--key-id",
        "1",
        "--encryption-public-key-file",
        "M.S.2.new.pub",
        "--as",
        "M",
        "--signing-key-file",
        "M.sign.key",
        "--revoke-previous",
        "--output-dir",
        "./updates",
    ])
    .is_ok());

    // A signing-only reissue needs no encryption key and no tree.
    assert!(Cli::try_parse_from([
        "keyquorum",
        "reissue",
        "--node",
        "M.S.2",
        "--signing-public-key-file",
        "M.S.2.new.sign.pub",
        "--as",
        "M.S",
        "--signing-key-file",
        "M.S.sign.key",
        "--output-dir",
        "./updates",
    ])
    .is_ok());
}

#[test]
fn tree_restructure_and_updates_parse() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "tree",
        "restructure",
        "1",
        "--as",
        "M",
        "--signing-key-file",
        "M.sign.key",
        "--output-dir",
        "./updates",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "restructure", "1"]).is_err());
    assert!(Cli::try_parse_from(["keyquorum", "updates"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "updates", "--since", "4"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "tree",
        "1",
        "--custody",
        "logical",
        "--minimum-physical-devices",
        "2",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "--custody", "hardware"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "reconstruct",
        "1",
        "--slot",
        "/mnt/usb=M.S.1",
        "--share-file",
        "alice.key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "relay",
        "pull",
        "--import",
        "--slot",
        "/mnt/usb=M.S.1",
        "--url",
        "http://127.0.0.1:8787",
    ])
    .is_ok());
}

#[test]
fn transfer_commands_parse_without_opening_a_database() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "transfer",
        "copy",
        "--from-device",
        "usb-a",
        "--from-db",
        "a.sqlite",
        "--to-device",
        "usb-c",
        "--to-db",
        "c.sqlite",
        "--label",
        "M.S.2",
        "--descendants",
        "all-descendants",
        "--as",
        "M.S",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "transfer",
        "move",
        "--from-device",
        "usb-a",
        "--from-db",
        "a.sqlite",
        "--to-device",
        "usb-b",
        "--to-db",
        "b.sqlite",
        "--label",
        "M.A",
        "--descendants",
        "key-only",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "transfer",
        "recover",
        "--from-device",
        "usb-a",
        "--from-db",
        "a.sqlite",
        "--to-device",
        "usb-b",
        "--to-db",
        "b.sqlite",
        "--transaction",
        "00112233445566778899aabbccddeeff",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "transfer", "copy", "--label", "M"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "transfer",
        "relay-send",
        "--operation",
        "move",
        "--from-device",
        "usb-a",
        "--from-db",
        "a.sqlite",
        "--label",
        "M.S",
        "--to-device-id",
        "00112233445566778899aabbccddeeff",
        "--recipient-key-file",
        "bob.pub",
        "--url",
        "https://relay.example.com",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "transfer",
        "relay-collect",
        "--to-device",
        "usb-b",
        "--to-db",
        "b.sqlite",
        "--slot",
        "recv",
        "--from-device-id",
        "00112233445566778899aabbccddeeff",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "transfer",
        "relay-collect",
        "--to-device",
        "usb-b",
        "--to-db",
        "b.sqlite",
        "--slot",
        "recv",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "device",
        "publish",
        "./usb",
        "--url",
        "https://relay.example.com",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "device",
        "relay-relocate",
        "--from",
        "./usb",
        "--label",
        "M.S",
        "--to-device-id",
        "00112233445566778899aabbccddeeff",
        "--recipient-key-file",
        "bob.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "device",
        "relay-accept",
        "./usb",
        "--slot",
        "recv",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "device",
        "relay-drop",
        "./usb",
        "--label",
        "M.S",
        "--to-device-id",
        "00112233445566778899aabbccddeeff",
        "--relocate-id",
        "ffeeddccbbaa99887766554433221100",
    ])
    .is_ok());
    // Without the relocate id, any acknowledgement for the slot could match.
    assert!(Cli::try_parse_from([
        "keyquorum",
        "device",
        "relay-drop",
        "./usb",
        "--label",
        "M.S",
        "--to-device-id",
        "00112233445566778899aabbccddeeff",
    ])
    .is_err());
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_keys_create_from_an_enrollment_needs_its_whole_set_and_no_other_recipient() {
    let base = [
        "keyquorum",
        "host",
        "keys",
        "create",
        "--scope",
        "inbox.pull",
        "--enrollment",
        "alice.kqreq",
    ];
    let with = |extra: &[&'static str]| {
        let mut line = base.to_vec();
        line.extend_from_slice(extra);
        Cli::try_parse_from(line)
    };
    let whole = [
        "--package-out",
        "alice.kqpkg",
        "--confirm-fingerprint",
        "0123abcd",
        "--package-relay-url",
        "https://relay.example.com",
    ];
    assert!(with(&whole).is_ok());
    assert!(with(&[&whole[..], &["--package-valid-days", "7"]].concat()).is_ok());
    // Each of the three the provider must supply is required.
    for skip in 0..3 {
        let partial: Vec<&'static str> = whole
            .chunks(2)
            .enumerate()
            .filter(|(index, _)| *index != skip)
            .flat_map(|(_, pair)| pair.iter().copied())
            .collect();
        assert!(with(&partial).is_err(), "without pair {skip}");
    }
    // An enrollment is the recipient: a second one is refused.
    assert!(with(&[&whole[..], &["--recipient-key", "00"]].concat()).is_err());
    assert!(with(&[&whole[..], &["--device-id", "00"]].concat()).is_err());
    // The package flags mean nothing without an enrollment.
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "create",
        "--scope",
        "inbox.pull",
        "--package-out",
        "alice.kqpkg",
    ])
    .is_err());
}
