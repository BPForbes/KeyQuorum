use super::*;
use crate::api_key_delivery;
use crate::keys;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::store::conformance::fake_letter;
use crate::relay::{ApiKeyScope, SqliteRelayStore};
use serde_json::Value;

const OPERATOR: &str = "ops@provider.test";

struct Console {
    store: SqliteRelayStore,
    identity: ProviderIdentity,
    root: [u8; 32],
}

fn console() -> Console {
    let issued = issued_identity("2099-01-01 00:00:00");
    Console {
        store: SqliteRelayStore::open_in_memory().expect("schema"),
        identity: ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
        root: issued.root_public,
    }
}

impl Console {
    fn ask(&self, request: Value, lock: Option<&str>) -> (u16, Value) {
        self.ask_as(OPERATOR, request, lock, true)
    }

    fn ask_as(&self, operator: &str, request: Value, lock: Option<&str>, identity: bool) -> (u16, Value) {
        let body = serde_json::to_vec(&request).expect("json");
        let reply = operate(
            &self.store,
            identity.then_some(&self.identity),
            &body,
            &Context { operator, lock },
            "2026-10-06 12:00:00.000",
        );
        (reply.status, serde_json::from_slice(&reply.body).unwrap_or(Value::Null))
    }

    fn bootstrap(&self) -> String {
        let (status, body) = self.ask(json!({ "op": "bootstrap" }), None);
        assert_eq!(status, 200);
        body["operator_lock"].as_str().expect("lock").to_string()
    }

    fn issue(&self, lock: &str, public: &[u8; 32], scopes: &[&str]) -> (u16, Value) {
        self.ask(
            json!({
                "op": "issue", "client": "Acme Ltd", "terms": "Five seats.",
                "expires_at": "2999-01-01", "scopes": scopes,
                "recipient_public_key": hex::encode(public),
                "relay_url": "https://relay.example.test",
            }),
            Some(lock),
        )
    }
}

fn open_bundle(c: &Console, secret: &[u8; 32], bundle_b64: &str) -> api_key_delivery::Opened {
    let bytes = STANDARD.decode(bundle_b64).expect("base64");
    let now = crate::provider::system_now_utc().expect("clock");
    api_key_delivery::open(&bytes, secret, &c.root, &now, &empty_revoked()).expect("opens")
}

#[test]
fn nothing_is_answered_without_a_verified_operator_or_for_a_malformed_request() {
    let c = console();
    assert_eq!(c.ask_as("  ", json!({ "op": "overview" }), None, true).0, 401);
    assert_eq!(c.ask(json!({ "op": "no_such_thing" }), None).0, 400);
    assert_eq!(c.ask(json!({ "op": "overview", "extra": 1 }), None).0, 400);
    assert_eq!(c.ask(json!(["overview"]), None).0, 400);
    assert_eq!(c.ask(json!({ "op": "keys", "extra": 1 }), None).0, 400);
    assert_eq!(c.ask(json!({ "op": "activity", "hours": 1, "extra": 1 }), None).0, 400);
    assert_eq!(c.ask(json!({ "op": "void_key", "key_id": 1, "reason": "x" }), None).0, 400);
    let big = vec![b'{'; MAX_REQUEST_BYTES + 1];
    let reply = operate(&c.store, Some(&c.identity), &big, &Context { operator: OPERATOR, lock: None }, "now");
    assert_eq!(reply.status, 413);
}

#[test]
fn the_operator_lock_is_created_once_shown_once_and_only_on_a_relay_with_an_identity() {
    let c = console();
    let (status, body) = c.ask_as(OPERATOR, json!({ "op": "bootstrap" }), None, false);
    assert_eq!((status, body["code"].as_str()), (503, Some("no_identity")));
    assert!(!c.store.operator_lock_exists().expect("exists"));

    let lock = c.bootstrap();
    assert!(lock.starts_with("kql_"));
    let (status, body) = c.ask(json!({ "op": "bootstrap" }), None);
    assert_eq!((status, body["code"].as_str()), (409, Some("lock_exists")));
    assert!(!body.to_string().contains(&lock));
    c.store.authenticate_licensee(&lock).expect("the lock works");
}

#[test]
fn changing_anything_needs_the_lock_and_a_wrong_one_is_recorded_and_refused() {
    let c = console();
    let (_, public) = keys::generate_encryption_keypair();
    // No lock exists yet.
    let (status, body) = c.issue("kql_whatever", &public, &["inbox.push"]);
    assert_eq!((status, body["code"].as_str()), (409, Some("no_lock")));

    let lock = c.bootstrap();
    let (status, body) = c.ask(
        json!({ "op": "issue", "client": "Acme", "scopes": ["inbox.push"],
                "recipient_public_key": hex::encode(public),
                "relay_url": "https://relay.example.test" }),
        None,
    );
    assert_eq!((status, body["code"].as_str()), (401, Some("lock_required")));

    let wrong = c.issue("kql_not-the-lock", &public, &["inbox.push"]);
    assert_eq!((wrong.0, wrong.1["code"].as_str()), (401, Some("lock_refused")));
    assert!(c.store.list_keys().expect("keys").is_empty());
    assert!(c.store.list_licences().expect("licences").is_empty());

    // The refusal is in the audit chain and under the operator's name.
    let auth = c.store.provider_auth_events(10).expect("auth");
    assert!(auth.iter().any(|e| e.operation == "console.issue" && !e.success));
    let actions = c.store.operator_actions(10).expect("actions");
    assert!(actions.iter().any(|a| a.action == "issue" && !a.success && a.operator == OPERATOR));
    // And the right lock still works.
    assert_eq!(c.issue(&lock, &public, &["inbox.push"]).0, 200);
}

#[test]
fn issuing_returns_bundles_sealed_to_the_client_and_never_a_bearer() {
    let c = console();
    let lock = c.bootstrap();
    let (secret, public) = keys::generate_encryption_keypair();
    let (status, body) = c.issue(&lock, &public, &["inbox.push", "inbox.pull"]);
    assert_eq!(status, 200, "issue");
    assert_eq!(body["licence"]["client"], "Acme Ltd");
    assert_eq!(body["licence"]["status"], "active");
    let bundles = body["bundles"].as_array().expect("bundles");
    assert_eq!(bundles.len(), 2);
    let text = body.to_string();
    for bundle in bundles {
        let opened = open_bundle(&c, &secret, bundle["bundle_base64"].as_str().expect("b64"));
        let scope = ApiKeyScope::parse(bundle["scope"].as_str().expect("scope")).expect("scope");
        c.store.authenticate(opened.issue.token.as_str(), scope).expect("live");
        assert!(!text.contains(opened.issue.token.as_str()), "the bearer is only inside the sealed bundle");
        assert_eq!(bundle["recipient_fingerprint"], keys::fingerprint(&public));
        let name = bundle["filename"].as_str().expect("filename");
        assert!(name.starts_with("acme-ltd-inbox-") && name.ends_with(".kqkey"), "{name}");
    }
    let actions = c.store.operator_actions(10).expect("actions");
    assert!(actions.iter().any(|a| a.action == "issue" && a.success));
    let auth = c.store.provider_auth_events(10).expect("auth");
    assert!(auth.iter().any(|e| e.operation == "console.issue" && e.success));
}

#[test]
fn a_bad_issue_request_is_a_400_and_issues_nothing() {
    let c = console();
    let lock = c.bootstrap();
    let (_, public) = keys::generate_encryption_keypair();
    let base = |patch: Value| {
        let mut request = json!({
            "op": "issue", "client": "Acme", "scopes": ["inbox.push"],
            "recipient_public_key": hex::encode(public),
            "relay_url": "https://relay.example.test",
        });
        for (key, value) in patch.as_object().expect("object") {
            request[key] = value.clone();
        }
        request
    };
    for patch in [
        json!({ "scopes": ["admin"] }),
        json!({ "scopes": [] }),
        json!({ "scopes": ["inbox.push", "inbox.push"] }),
        json!({ "scopes": ["bogus"] }),
        json!({ "recipient_public_key": "abcd" }),
        json!({ "recipient_public_key": "zz".repeat(32) }),
        json!({ "relay_url": "ftp://x" }),
        json!({ "device_id": "00ff" }),
        json!({ "client": "  " }),
        json!({ "expires_at": "2000-01-01" }),
        json!({ "licence_id": 1 }),
    ] {
        let (status, body) = c.ask(base(patch.clone()), Some(&lock));
        assert!(matches!(status, 400 | 404), "{patch}: {status}");
        assert!(body["error"].is_string());
    }
    assert!(c.store.list_keys().expect("keys").is_empty());
    assert!(c.store.list_licences().expect("licences").is_empty());
}

#[test]
fn voiding_a_licence_ends_its_keys_and_voiding_a_key_ends_only_that_key() {
    let c = console();
    let lock = c.bootstrap();
    let (secret, public) = keys::generate_encryption_keypair();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push", "device.push"]);
    let licence_id = issued["licence"]["id"].as_i64().expect("id");
    let tokens: Vec<_> = issued["bundles"]
        .as_array()
        .expect("bundles")
        .iter()
        .map(|b| open_bundle(&c, &secret, b["bundle_base64"].as_str().expect("b64")).issue.token)
        .collect();
    let first = issued["bundles"][0]["key_id"].as_i64().expect("key");

    let (status, _) = c.ask(json!({ "op": "void_key", "key_id": first }), None);
    assert_eq!(status, 401);
    let (status, body) = c.ask(json!({ "op": "void_key", "key_id": first }), Some(&lock));
    assert_eq!((status, body["revoked"].as_bool()), (200, Some(true)));
    assert!(c.store.authenticate(tokens[0].as_str(), ApiKeyScope::InboxPush).is_err());
    assert!(c.store.authenticate(tokens[1].as_str(), ApiKeyScope::DevicePush).is_ok());
    assert_eq!(c.ask(json!({ "op": "void_key", "key_id": 999 }), Some(&lock)).0, 404);

    let (status, body) = c.ask(
        json!({ "op": "void_licence", "licence_id": licence_id, "reason": "unpaid" }),
        Some(&lock),
    );
    assert_eq!(status, 200);
    assert_eq!(body["newly_voided"], true);
    assert_eq!(body["revoked_keys"].as_array().expect("revoked").len(), 1);
    assert!(c.store.authenticate(tokens[1].as_str(), ApiKeyScope::DevicePush).is_err());
    let (_, licences) = c.ask(json!({ "op": "licences" }), None);
    assert_eq!(licences["licences"][0]["status"], "voided");
    assert_eq!(licences["licences"][0]["live_keys"], 0);
    assert_eq!(c.ask(json!({ "op": "void_licence", "licence_id": 999 }), Some(&lock)).0, 404);
    // Nothing more can be issued under it.
    let again = c.ask(
        json!({ "op": "issue", "licence_id": licence_id, "scopes": ["inbox.pull"],
                "recipient_public_key": hex::encode(public),
                "relay_url": "https://relay.example.test" }),
        Some(&lock),
    );
    assert_eq!(again.0, 409);
}

#[test]
fn rotating_replaces_a_key_and_hands_back_a_new_sealed_bundle() {
    let c = console();
    let lock = c.bootstrap();
    let (secret, public) = keys::generate_encryption_keypair();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push"]);
    let old = issued["bundles"][0]["key_id"].as_i64().expect("key");
    let old_token = open_bundle(&c, &secret, issued["bundles"][0]["bundle_base64"].as_str().expect("b64")).issue.token;
    assert_eq!(c.ask(json!({ "op": "rotate", "key_id": old }), None).0, 401);
    let (status, body) = c.ask(json!({ "op": "rotate", "key_id": old }), Some(&lock));
    assert_eq!(status, 200);
    assert_eq!(body["replaced_key_id"], old);
    let new = open_bundle(&c, &secret, body["bundle"]["bundle_base64"].as_str().expect("b64"));
    assert!(c.store.authenticate(old_token.as_str(), ApiKeyScope::InboxPush).is_err());
    assert!(c.store.authenticate(new.issue.token.as_str(), ApiKeyScope::InboxPush).is_ok());
    assert!(body["bundle"]["filename"].as_str().expect("name").starts_with("acme-ltd-"));
}

#[test]
fn the_views_name_the_client_and_the_state_of_each_key() {
    let c = console();
    let lock = c.bootstrap();
    let (_, public) = keys::generate_encryption_keypair();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push", "inbox.pull"]);
    let revoked = issued["bundles"][0]["key_id"].as_i64().expect("key");
    c.ask(json!({ "op": "void_key", "key_id": revoked }), Some(&lock));

    let (status, keys_view) = c.ask(json!({ "op": "keys" }), None);
    assert_eq!(status, 200);
    let keys_list = keys_view["keys"].as_array().expect("keys");
    assert_eq!(keys_list.len(), 2);
    let by_id = |id: i64| keys_list.iter().find(|k| k["id"] == id).expect("key");
    assert_eq!(by_id(revoked)["state"], "revoked");
    let live = issued["bundles"][1]["key_id"].as_i64().expect("key");
    assert_eq!(by_id(live)["state"], "live");
    assert_eq!(by_id(live)["client"], "Acme Ltd");
    assert_eq!(by_id(live)["delivery"]["recipient_fingerprint"], keys::fingerprint(&public));
    assert_eq!(by_id(live)["delivery"]["via"], "bundle");
    assert!(!keys_view.to_string().contains("kq_"));

    let (_, overview) = c.ask(json!({ "op": "overview" }), None);
    assert_eq!(overview["operator_lock"], true);
    assert_eq!(overview["keys"], json!({ "live": 1, "revoked": 1, "expired": 0 }));
    assert_eq!(overview["licences"]["active"], 1);
    assert_eq!(overview["identity_configured"], true);
}

#[test]
fn activity_counts_what_each_clients_keys_did_and_what_was_blocked() {
    let c = console();
    let lock = c.bootstrap();
    let (secret, public) = keys::generate_encryption_keypair();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push"]);
    let key = issued["bundles"][0]["key_id"].as_i64().expect("key");
    let token = open_bundle(&c, &secret, issued["bundles"][0]["bundle_base64"].as_str().expect("b64")).issue.token;
    for _ in 0..4 {
        c.store.record_access(token.as_str(), "/inbox", 200).expect("record");
    }
    c.store.record_access(token.as_str(), "/inbox", 403).expect("record");
    c.ask(json!({ "op": "void_key", "key_id": key }), Some(&lock));
    c.store.record_access(token.as_str(), "/inbox", 401).expect("record");

    let (status, view) = c.ask(json!({ "op": "activity", "hours": 24 }), None);
    assert_eq!(status, 200);
    let clients = view["clients"].as_array().expect("clients");
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0]["client"], "Acme Ltd");
    assert_eq!((clients[0]["ok"].as_i64(), clients[0]["scope"].as_i64(), clients[0]["revoked"].as_i64()), (Some(4), Some(1), Some(1)));
    assert_eq!(clients[0]["live_keys"], 0);
    let (_, overview) = c.ask(json!({ "op": "overview" }), None);
    assert_eq!(overview["last_24h"], json!({ "served": 4, "blocked": 2 }));
}

#[test]
fn the_letter_view_shows_kind_size_and_client_but_never_the_letters_contents() {
    let c = console();
    let lock = c.bootstrap();
    let (_, public) = keys::generate_encryption_keypair();
    let (_, issued) = c.issue(&lock, &public, &["inbox.pull"]);
    let _ = issued;
    let secret_payload = b"the-sealed-contents-the-relay-cannot-read";
    let letter = fake_letter(&public, crate::envelope::KIND_FILE_HISTORY, secret_payload);
    c.store.inbox_push(&[], &letter, None).expect("push");
    let device_letter = fake_letter(&public, crate::envelope::KIND_DEVICE_TRANSFER, b"x");
    c.store.store_device_package(&device_letter).expect("device letter");

    let (status, view) = c.ask(json!({ "op": "letters" }), None);
    assert_eq!(status, 200);
    let inbox = &view["inbox"];
    assert_eq!(inbox["total"], 1);
    let row = &inbox["newest"][0];
    assert_eq!(row["kind_name"], "tracked file");
    assert_eq!(row["client"], "Acme Ltd");
    assert_eq!(row["size"], letter.len());
    assert_eq!(view["devices"]["newest"][0]["kind_name"], "device transfer");
    assert!(!view.to_string().contains("sealed-contents"));
}

#[test]
fn events_trees_and_the_audit_checkpoint_are_readable_with_only_the_operator_identity() {
    let c = console();
    let lock = c.bootstrap();
    let (_, public) = keys::generate_encryption_keypair();
    c.issue(&lock, &public, &["inbox.push"]);
    c.issue("kql_wrong", &public, &["inbox.push"]);

    let (status, events) = c.ask(json!({ "op": "events" }), None);
    assert_eq!(status, 200);
    assert_eq!(events["key_events"][0]["event"], "created");
    assert_eq!(events["key_events"][0]["actor"], "host");
    assert_eq!(events["key_events"][0]["entry_hash"].as_str().map(str::len), Some(64));
    assert!(events["operator_actions"].as_array().expect("actions").len() >= 2);
    assert!(events["auth_events"].as_array().expect("auth").iter().any(|e| e["success"] == false));
    assert!(!events.to_string().contains(&lock));

    let (status, trees) = c.ask(json!({ "op": "trees" }), None);
    assert_eq!((status, trees["trees"].as_array().map(Vec::len)), (200, Some(0)));

    let (status, checkpoint) = c.ask(json!({ "op": "checkpoint" }), None);
    assert_eq!(status, 200);
    let bytes = STANDARD.decode(checkpoint["content_base64"].as_str().expect("b64")).expect("base64");
    let decoded = crate::relay::audit::Checkpoint::decode(&bytes).expect("a checkpoint");
    assert!(decoded.heads.iter().any(|h| h.table == "api_key_events" && h.row_count >= 1));
    assert!(checkpoint["filename"].as_str().expect("name").ends_with(".json"));
    let (status, _) = c.ask_as(OPERATOR, json!({ "op": "checkpoint" }), None, false);
    assert_eq!(status, 503);
}

#[test]
fn a_store_failure_is_reported_in_fixed_words_not_the_stores() {
    let reply = failure(&Error::Store("SELECT secret FROM somewhere".into()));
    assert_eq!(reply.status, 500);
    let text = String::from_utf8(reply.body).expect("utf8");
    assert!(!text.contains("SELECT"));
    let unknown = failure(&Error::StoreCommitUnknown);
    assert!(String::from_utf8(unknown.body).expect("utf8").contains("check the keys list"));
    assert_eq!(failure(&Error::RelayRequest("secret detail".into())).status, 400);
}

#[test]
fn the_operator_lock_is_replaced_with_the_current_one_and_the_old_one_stops_working() {
    let c = console();
    let old = c.bootstrap();
    // Nothing to replace without a lock to prove, and a wrong one is refused.
    assert_eq!(c.ask(json!({ "op": "rotate_lock" }), None).1["code"], "lock_required");
    let wrong = c.ask(json!({ "op": "rotate_lock" }), Some("kql_not-the-lock"));
    assert_eq!((wrong.0, wrong.1["code"].as_str()), (401, Some("lock_refused")));
    c.store.authenticate_licensee(&old).expect("still the old one");

    let (status, body) = c.ask(json!({ "op": "rotate_lock" }), Some(&old));
    assert_eq!(status, 200);
    let new = body["operator_lock"].as_str().expect("new lock").to_string();
    assert!(new.starts_with("kql_") && new != old);
    assert!(c.store.authenticate_licensee(&old).is_err());
    c.store.authenticate_licensee(&new).expect("the new lock works");

    // The old lock now buys nothing; the new one does.
    let (_, public) = keys::generate_encryption_keypair();
    assert_eq!(c.issue(&old, &public, &["inbox.push"]).1["code"], "lock_refused");
    assert_eq!(c.issue(&new, &public, &["inbox.push"]).0, 200);
    let actions = c.store.operator_actions(20).expect("actions");
    assert!(actions.iter().any(|a| a.action == "rotate_lock" && a.success));
    let auth = c.store.provider_auth_events(20).expect("auth");
    assert!(auth.iter().any(|e| e.operation == "console.rotate_lock" && e.success));
    assert!(!c.ask(json!({ "op": "events" }), None).1.to_string().contains(&new));
}

#[test]
fn replacing_the_lock_needs_an_identity_and_an_existing_lock() {
    let c = console();
    let (status, body) = c.ask_as(OPERATOR, json!({ "op": "rotate_lock" }), Some("kql_x"), false);
    assert_eq!((status, body["code"].as_str()), (503, Some("no_identity")));
    let (status, body) = c.ask(json!({ "op": "rotate_lock" }), Some("kql_x"));
    assert_eq!((status, body["code"].as_str()), (409, Some("no_lock")));
}
