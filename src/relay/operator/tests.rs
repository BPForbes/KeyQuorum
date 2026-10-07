use super::*;
use crate::api_key_delivery;
use crate::keys;
use crate::provider::test_helpers::{empty_revoked, issued_identity};
use crate::relay::activity::Cost;
use crate::relay::store::conformance::fake_letter;
use crate::relay::{ApiKeyScope, SqliteRelayStore};
use serde_json::Value;
use std::cell::Cell;

const OPERATOR: &str = "ops@provider.test";

struct Console {
    store: SqliteRelayStore,
    identity: ProviderIdentity,
    root: [u8; 32],
    counter: Cell<u32>,
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
        counter: Cell::new(0),
    }
}

impl Console {
    fn ask(&self, request: Value, lock: Option<&str>) -> (u16, Value) {
        self.ask_as(OPERATOR, request, lock, true)
    }

    fn ask_as(
        &self,
        operator: &str,
        request: Value,
        lock: Option<&str>,
        identity: bool,
    ) -> (u16, Value) {
        let body = serde_json::to_vec(&request).expect("json");
        let reply = operate(
            &self.store,
            identity.then_some(&self.identity),
            &body,
            &Context { operator, lock },
            "2026-10-06 12:00:00.000",
        );
        (
            reply.status,
            serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
        )
    }

    /// A fresh operation id, as the page would make.
    fn op(&self) -> String {
        self.counter.set(self.counter.get() + 1);
        format!("op-test-{:08}", self.counter.get())
    }

    /// A change request with a fresh operation id.
    fn change(&self, mut request: Value, lock: &str) -> (u16, Value) {
        request["operation_id"] = Value::String(self.op());
        self.ask(request, Some(lock))
    }

    /// The operator lock, made and confirmed.
    fn lock(&self) -> String {
        let (status, body) = self.ask(json!({ "op": "bootstrap" }), None);
        assert_eq!(status, 200);
        let lock = body["operator_lock"].as_str().expect("lock").to_string();
        let (status, _) = self.ask(json!({ "op": "confirm_lock" }), Some(&lock));
        assert_eq!(status, 200);
        lock
    }

    fn issue(&self, lock: &str, public: &[u8; 32], scopes: &[&str]) -> (u16, Value) {
        self.change(
            json!({
                "op": "issue", "name": "Acme Ltd", "terms": "Five seats.",
                "expires_at": "2999-01-01", "scopes": scopes,
                "recipient_public_key": hex::encode(public),
                "relay_url": "https://relay.example.test",
            }),
            lock,
        )
    }
}

fn open_bundle(c: &Console, secret: &[u8; 32], bundle_b64: &str) -> api_key_delivery::Opened {
    let bytes = STANDARD.decode(bundle_b64).expect("base64");
    let now = crate::provider::system_now_utc().expect("clock");
    api_key_delivery::open(&bytes, secret, &c.root, &now, &empty_revoked()).expect("opens")
}

fn client() -> (zeroize::Zeroizing<[u8; 32]>, [u8; 32]) {
    keys::generate_encryption_keypair()
}

#[test]
fn nothing_is_answered_without_a_verified_operator_or_for_a_malformed_request() {
    let c = console();
    assert_eq!(
        c.ask_as("  ", json!({ "op": "overview" }), None, true).0,
        401
    );
    assert_eq!(c.ask(json!({ "op": "no_such_thing" }), None).0, 400);
    assert_eq!(c.ask(json!({ "op": "overview", "extra": 1 }), None).0, 400);
    assert_eq!(c.ask(json!({ "op": "keys", "extra": 1 }), None).0, 400);
    assert_eq!(
        c.ask(json!({ "op": "activity", "hours": 1, "extra": 1 }), None)
            .0,
        400
    );
    assert_eq!(
        c.ask(
            json!({ "op": "void_key", "key_id": 1, "reason": "x" }),
            None
        )
        .0,
        400
    );
    assert_eq!(c.ask(json!(["overview"]), None).0, 400);
    let big = vec![b'{'; MAX_REQUEST_BYTES + 1];
    let reply = operate(
        &c.store,
        Some(&c.identity),
        &big,
        &Context {
            operator: OPERATOR,
            lock: None,
        },
        "now",
    );
    assert_eq!(reply.status, 413);
}

#[test]
fn the_operator_lock_is_staged_shown_once_and_only_a_confirmed_lock_authorises_anything() {
    let c = console();
    // No identity, no lock.
    let (status, body) = c.ask_as(OPERATOR, json!({ "op": "bootstrap" }), None, false);
    assert_eq!((status, body["code"].as_str()), (503, Some("no_identity")));
    assert!(!c.store.operator_lock_pending().expect("pending"));

    let (status, body) = c.ask(json!({ "op": "bootstrap" }), None);
    assert_eq!((status, body["pending"].as_bool()), (200, Some(true)));
    let staged = body["operator_lock"].as_str().expect("lock").to_string();
    assert!(staged.starts_with("kql_"));
    // Staged is not confirmed: it authorises nothing, and says why.
    assert!(!c.store.operator_lock_exists().expect("exists"));
    let (_, public) = client();
    let (status, body) = c.issue(&staged, &public, &["inbox.push"]);
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("lock_unconfirmed"))
    );

    // A lost response: ask again, and only the new lock confirms.
    let (_, again) = c.ask(json!({ "op": "bootstrap" }), None);
    let second = again["operator_lock"].as_str().expect("lock").to_string();
    assert_ne!(second, staged);
    let (status, body) = c.ask(json!({ "op": "confirm_lock" }), Some(&staged));
    assert_eq!((status, body["code"].as_str()), (401, Some("lock_refused")));
    assert_eq!(
        c.ask(json!({ "op": "confirm_lock" }), None).1["code"],
        "lock_required"
    );
    let (status, _) = c.ask(json!({ "op": "confirm_lock" }), Some(&second));
    assert_eq!(status, 200);
    c.store
        .authenticate_licensee(&second)
        .expect("the lock works");
    assert!(!c.store.operator_lock_pending().expect("pending"));

    // Once confirmed it is not shown again, and bootstrap cannot be repeated.
    let (status, body) = c.ask(json!({ "op": "bootstrap" }), None);
    assert_eq!((status, body["code"].as_str()), (409, Some("lock_exists")));
    assert!(!body.to_string().contains(&second));
    assert_eq!(
        c.ask(json!({ "op": "confirm_lock" }), Some(&second)).0,
        401,
        "nothing is waiting"
    );
    // Every step is in the audit chain and under the operator's name.
    let auth = c.store.provider_auth_events(20, None).expect("auth");
    for (operation, success) in [
        ("console.bootstrap", true),
        ("console.confirm_lock", true),
        ("console.confirm_lock", false),
    ] {
        assert!(
            auth.iter()
                .any(|e| e.operation == operation && e.success == success),
            "{operation} {success}"
        );
    }
}

#[test]
fn the_lock_is_replaced_in_two_steps_and_the_current_one_stands_until_the_new_is_confirmed() {
    let c = console();
    let old = c.lock();
    assert_eq!(
        c.ask(json!({ "op": "rotate_lock" }), None).1["code"],
        "lock_required"
    );
    assert_eq!(
        c.ask(json!({ "op": "rotate_lock" }), Some("kql_not-the-lock"))
            .1["code"],
        "lock_refused"
    );
    let (status, body) = c.ask(json!({ "op": "rotate_lock" }), Some(&old));
    assert_eq!((status, body["pending"].as_bool()), (200, Some(true)));
    let next = body["operator_lock"]
        .as_str()
        .expect("new lock")
        .to_string();
    assert!(next.starts_with("kql_") && next != old);
    // A lost response here costs nothing: the old lock still works.
    let (_, public) = client();
    assert_eq!(c.issue(&old, &public, &["inbox.push"]).0, 200);
    assert_eq!(
        c.issue(&next, &public, &["inbox.pull"]).1["code"],
        "lock_refused"
    );
    assert_eq!(c.ask(json!({ "op": "confirm_lock" }), Some(&next)).0, 200);
    assert_eq!(
        c.issue(&old, &public, &["inbox.pull"]).1["code"],
        "lock_refused"
    );
    assert_eq!(c.issue(&next, &public, &["inbox.pull"]).0, 200);
    assert!(!c
        .ask(json!({ "op": "audit", "feed": "actions" }), None)
        .1
        .to_string()
        .contains(&next));
}

#[test]
fn replacing_the_lock_needs_an_identity_and_an_existing_lock() {
    let c = console();
    let (status, body) = c.ask_as(
        OPERATOR,
        json!({ "op": "rotate_lock" }),
        Some("kql_x"),
        false,
    );
    assert_eq!((status, body["code"].as_str()), (503, Some("no_identity")));
    let (status, body) = c.ask(json!({ "op": "rotate_lock" }), Some("kql_x"));
    assert_eq!((status, body["code"].as_str()), (409, Some("no_lock")));
}

#[test]
fn a_change_needs_the_lock_and_an_operation_id_and_a_wrong_lock_is_recorded_and_refused() {
    let c = console();
    let (_, public) = client();
    let (status, body) = c.issue("kql_whatever", &public, &["inbox.push"]);
    assert_eq!((status, body["code"].as_str()), (409, Some("no_lock")));
    let lock = c.lock();

    let request = |extra: Value| {
        let mut base = json!({
            "op": "issue", "name": "Acme", "scopes": ["inbox.push"],
            "recipient_public_key": hex::encode(public), "relay_url": "https://relay.example.test",
        });
        for (k, v) in extra.as_object().expect("object") {
            base[k] = v.clone();
        }
        base
    };
    // No operation id: refused before anything, even with the right lock.
    let (status, body) = c.ask(request(json!({})), Some(&lock));
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("operation_id_required"))
    );
    let (status, body) = c.ask(request(json!({ "operation_id": "short" })), Some(&lock));
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("operation_id_required"))
    );
    // No lock, then a wrong one.
    let (status, body) = c.ask(request(json!({ "operation_id": "op-0000000001" })), None);
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("lock_required"))
    );
    let (status, body) = c.ask(
        request(json!({ "operation_id": "op-0000000002" })),
        Some("kql_not-the-lock"),
    );
    assert_eq!((status, body["code"].as_str()), (401, Some("lock_refused")));
    assert!(c.store.list_keys().expect("keys").is_empty());
    assert_eq!(c.store.customer_count().expect("count"), 0);

    let auth = c.store.provider_auth_events(10, None).expect("auth");
    assert!(auth
        .iter()
        .any(|e| e.operation == "console.issue" && !e.success));
    let actions = c.store.operator_actions(10, None).expect("actions");
    assert!(actions
        .iter()
        .any(|a| a.action == "issue" && !a.success && a.operator == OPERATOR));
    // The right lock and a fresh id go through.
    assert_eq!(
        c.ask(
            request(json!({ "operation_id": "op-0000000003" })),
            Some(&lock)
        )
        .0,
        200
    );
}

#[test]
fn issuing_returns_bundles_sealed_to_the_client_and_never_a_bearer() {
    let c = console();
    let lock = c.lock();
    let (secret, public) = client();
    let (status, body) = c.issue(&lock, &public, &["inbox.push", "inbox.pull"]);
    assert_eq!(status, 200, "issue");
    assert_eq!(body["customer"]["name"], "Acme Ltd");
    assert_eq!(body["licence"]["status"], "active");
    assert_eq!(body["licence"]["customer_id"], body["customer"]["id"]);
    let bundles = body["bundles"].as_array().expect("bundles");
    assert_eq!(bundles.len(), 2);
    let text = body.to_string();
    for bundle in bundles {
        let opened = open_bundle(&c, &secret, bundle["bundle_base64"].as_str().expect("b64"));
        let scope = ApiKeyScope::parse(bundle["scope"].as_str().expect("scope")).expect("scope");
        c.store
            .authenticate(opened.issue.token.as_str(), scope)
            .expect("live");
        assert!(
            !text.contains(opened.issue.token.as_str()),
            "the bearer is only inside the sealed bundle"
        );
        assert_eq!(bundle["recipient_fingerprint"], keys::fingerprint(&public));
        let name = bundle["filename"].as_str().expect("filename");
        assert!(
            name.starts_with("acme-ltd-inbox-") && name.ends_with(".kqkey"),
            "{name}"
        );
    }
    let actions = c.store.operator_actions(10, None).expect("actions");
    let done = actions
        .iter()
        .find(|a| a.action == "issue" && a.success)
        .expect("recorded");
    assert!(done.operation_id.is_some());
    assert!(c
        .store
        .provider_auth_events(10, None)
        .expect("auth")
        .iter()
        .any(|e| e.operation == "console.issue" && e.success));
}

#[test]
fn the_same_operation_id_is_told_it_is_done_with_its_ids_and_is_never_done_twice() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    let request = json!({
        "op": "issue", "operation_id": "op-reconcile-01", "name": "Acme Ltd",
        "scopes": ["inbox.push"], "recipient_public_key": hex::encode(public),
        "relay_url": "https://relay.example.test",
    });
    let (status, first) = c.ask(request.clone(), Some(&lock));
    assert_eq!(status, 200);
    // The response is lost; the page sends the same id again.
    let (status, again) = c.ask(request, Some(&lock));
    assert_eq!(
        (status, again["code"].as_str()),
        (409, Some("already_done"))
    );
    let result = &again["operation"]["result"];
    assert_eq!(result["customer_id"], first["customer"]["id"]);
    assert_eq!(result["licence_id"], first["licence"]["id"]);
    assert_eq!(result["key_ids"], json!([first["bundles"][0]["key_id"]]));
    assert_eq!(again["operation"]["operator"], OPERATOR);
    assert!(
        !again.to_string().contains("bundle_base64"),
        "sealed bytes are not kept"
    );
    assert_eq!(c.store.customer_count().expect("count"), 1);
    assert_eq!(c.store.list_keys().expect("keys").len(), 1);
    // It is still behind the lock: the record is not shown to a caller without it.
    let (status, body) = c.ask(
        json!({ "op": "issue", "operation_id": "op-reconcile-01", "name": "Acme Ltd", "scopes": ["inbox.push"],
                "recipient_public_key": hex::encode(public), "relay_url": "https://relay.example.test" }),
        Some("kql_not-the-lock"),
    );
    assert_eq!((status, body["code"].as_str()), (401, Some("lock_refused")));
    assert!(body.get("operation").is_none());
}

#[test]
fn a_bad_issue_request_is_refused_and_issues_nothing() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    let base = |patch: Value| {
        let mut request = json!({
            "op": "issue", "name": "Acme", "scopes": ["inbox.push"],
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
        json!({ "name": "  " }),
        json!({ "expires_at": "2000-01-01" }),
        json!({ "licence_id": 1 }),
        json!({ "customer_id": 1 }),
        json!({ "name": null }),
        json!({ "name": null, "customer_id": 99, "licence_id": 99 }),
    ] {
        let (status, body) = c.change(base(patch.clone()), &lock);
        assert!(matches!(status, 400 | 404), "{patch}: {status}");
        assert!(body["error"].is_string());
    }
    assert!(c.store.list_keys().expect("keys").is_empty());
    assert_eq!(c.store.customer_count().expect("count"), 0);
}

#[test]
fn customers_are_listed_searched_filtered_and_paged_and_one_is_shown_whole() {
    let c = console();
    let lock = c.lock();
    for name in ["Acme Ltd", "Beta Corp", "Gamma 100%"] {
        let (status, _) = c.change(json!({ "op": "create_customer", "name": name }), &lock);
        assert_eq!(status, 200);
    }
    assert_eq!(
        c.change(json!({ "op": "create_customer", "name": "  " }), &lock)
            .0,
        400
    );
    let (_, public) = client();
    let (_, issued) = c.change(
        json!({ "op": "issue", "customer_id": 1, "terms": "Five seats.", "expires_at": "2999-01-01",
                "scopes": ["inbox.push"], "recipient_public_key": hex::encode(public),
                "relay_url": "https://relay.example.test" }),
        &lock,
    );
    let licence_id = issued["licence"]["id"].as_i64().expect("licence");

    let (status, page) = c.ask(json!({ "op": "users", "limit": 2 }), None);
    assert_eq!(status, 200);
    let names: Vec<_> = page["users"]
        .as_array()
        .expect("users")
        .iter()
        .map(|u| u["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["Gamma 100%", "Beta Corp"]);
    let next = page["next_before"].as_i64().expect("cursor");
    let (_, rest) = c.ask(json!({ "op": "users", "limit": 2, "before": next }), None);
    assert_eq!(rest["users"][0]["name"], "Acme Ltd");
    assert_eq!(rest["users"][0]["active_licences"], 1);
    assert_eq!(rest["users"][0]["live_keys"], 1);
    assert!(rest["next_before"].is_null());
    let search = |term: &str| {
        c.ask(json!({ "op": "users", "search": term }), None).1["users"]
            .as_array()
            .expect("users")
            .len()
    };
    assert_eq!(
        (
            search("beta"),
            search("100%"),
            search("%"),
            search("nothing")
        ),
        (1, 1, 1, 0)
    );
    let with = c.ask(json!({ "op": "users", "status": "active" }), None).1;
    assert_eq!(with["users"].as_array().expect("users").len(), 1);
    let without = c
        .ask(json!({ "op": "users", "status": "inactive" }), None)
        .1;
    assert_eq!(without["users"].as_array().expect("users").len(), 2);
    assert_eq!(
        c.ask(json!({ "op": "users", "status": "bogus" }), None).0,
        400
    );

    // One customer, whole: licences with every statement version, keys and state.
    c.change(
        json!({ "op": "renew_licence", "licence_id": licence_id, "terms": "Ten seats." }),
        &lock,
    );
    let (status, detail) = c.ask(json!({ "op": "user", "id": 1 }), None);
    assert_eq!(status, 200);
    assert_eq!(detail["customer"]["name"], "Acme Ltd");
    let held = &detail["licences"][0];
    assert_eq!(
        (held["version"].as_i64(), held["status"].as_str()),
        (Some(2), Some("active"))
    );
    assert_eq!(held["versions"].as_array().expect("versions").len(), 2);
    assert_eq!(held["versions"][0]["terms"], "Five seats.");
    assert_eq!(held["live_keys"], 1);
    assert_eq!(detail["keys"].as_array().expect("keys").len(), 1);
    assert_eq!(detail["keys"][0]["customer"], "Acme Ltd");
    assert_eq!(c.ask(json!({ "op": "user", "id": 99 }), None).0, 404);
}

#[test]
fn a_renewal_adds_a_version_and_a_replacement_carries_the_new_statement() {
    let c = console();
    let lock = c.lock();
    let (secret, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push"]);
    let licence_id = issued["licence"]["id"].as_i64().expect("licence");
    let key_id = issued["bundles"][0]["key_id"].as_i64().expect("key");
    assert_eq!(
        c.ask(
            json!({ "op": "renew_licence", "licence_id": licence_id, "terms": "x" }),
            Some(&lock)
        )
        .1["code"],
        "operation_id_required"
    );
    let (status, renewed) = c.change(
        json!({ "op": "renew_licence", "licence_id": licence_id, "terms": "Ten seats.", "expires_at": "2999-09-09" }),
        &lock,
    );
    assert_eq!(status, 200);
    assert_eq!(renewed["licence"]["version"], 2);
    assert!(renewed["note"]
        .as_str()
        .expect("note")
        .contains("Replace them"));
    // Nothing to change, a past date and a missing licence are refused.
    assert_eq!(
        c.change(
            json!({ "op": "renew_licence", "licence_id": licence_id, "terms": "Ten seats." }),
            &lock
        )
        .0,
        400
    );
    assert_eq!(
        c.change(
            json!({ "op": "renew_licence", "licence_id": licence_id, "expires_at": "2000-01-01" }),
            &lock
        )
        .0,
        400
    );
    assert_eq!(
        c.change(
            json!({ "op": "renew_licence", "licence_id": 99, "terms": "x" }),
            &lock
        )
        .0,
        404
    );

    let (status, rotated) = c.change(json!({ "op": "rotate", "key_id": key_id }), &lock);
    assert_eq!(status, 200);
    assert_eq!(rotated["delivery"], "bundle");
    let opened = open_bundle(
        &c,
        &secret,
        rotated["bundle"]["bundle_base64"].as_str().expect("b64"),
    );
    let statement = opened.issue.licence.expect("statement");
    assert!(statement.contains("(statement 2)") && statement.contains("Ten seats."));
    assert_eq!(rotated["bundle"]["expires_at"], "2999-09-09 00:00:00");
}

#[test]
fn a_replacement_by_letter_is_bounded_and_refused_when_the_customer_cannot_collect_it() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.pull", "inbox.push"]);
    let pull = issued["bundles"][0]["key_id"].as_i64().expect("key");
    let push = issued["bundles"][1]["key_id"].as_i64().expect("key");
    let (status, body) = c.change(
        json!({ "op": "rotate", "key_id": pull, "via": "letter", "grace_seconds": 3600 }),
        &lock,
    );
    assert_eq!(status, 200);
    assert_eq!(body["delivery"], "letter");
    assert!(body["letter"]["letter_id"].as_i64().expect("letter") > 0);
    assert!(body["letter"]["old_key_ends"].is_string());
    assert!(
        body.get("bundle").is_none(),
        "a letter carries no bundle through the console"
    );
    // A push key can be collected through the live pull key of the same recipient.
    assert_eq!(
        c.change(
            json!({ "op": "rotate", "key_id": push, "via": "letter" }),
            &lock
        )
        .0,
        200
    );
    // Bounds and combinations.
    for patch in [
        json!({ "via": "letter", "grace_seconds": 0 }),
        json!({ "via": "letter", "grace_seconds": MAX_GRACE_SECONDS + 1 }),
        json!({ "via": "bundle", "grace_seconds": 60 }),
        json!({ "via": "carrier-pigeon" }),
    ] {
        let mut request = json!({ "op": "rotate", "key_id": pull });
        for (k, v) in patch.as_object().expect("object") {
            request[k] = v.clone();
        }
        let before = c.store.list_keys().expect("keys").len();
        assert_eq!(c.change(request, &lock).0, 400, "{patch}");
        assert_eq!(c.store.list_keys().expect("keys").len(), before);
    }
}

#[test]
fn a_customer_who_cannot_collect_a_letter_is_told_so_and_nothing_changes() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push"]);
    let push = issued["bundles"][0]["key_id"].as_i64().expect("key");
    let before = c.store.list_keys().expect("keys").len();
    let (status, body) = c.change(
        json!({ "op": "rotate", "key_id": push, "via": "letter" }),
        &lock,
    );
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
    assert_eq!(c.store.list_keys().expect("keys").len(), before);
    // The refused attempt is on the operator's record, with no operation id.
    let actions = c.store.operator_actions(10, None).expect("actions");
    assert!(actions
        .iter()
        .any(|a| a.action == "rotate" && !a.success && a.operation_id.is_none()));
}

#[test]
fn voiding_a_licence_ends_its_keys_and_voiding_a_key_ends_only_that_key() {
    let c = console();
    let lock = c.lock();
    let (secret, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push", "device.push"]);
    let licence_id = issued["licence"]["id"].as_i64().expect("id");
    let tokens: Vec<_> = issued["bundles"]
        .as_array()
        .expect("bundles")
        .iter()
        .map(|b| {
            open_bundle(&c, &secret, b["bundle_base64"].as_str().expect("b64"))
                .issue
                .token
        })
        .collect();
    let first = issued["bundles"][0]["key_id"].as_i64().expect("key");

    assert_eq!(
        c.ask(
            json!({ "op": "void_key", "key_id": first, "operation_id": "op-void-key-01" }),
            None
        )
        .0,
        401
    );
    let (status, body) = c.change(json!({ "op": "void_key", "key_id": first }), &lock);
    assert_eq!((status, body["revoked"].as_bool()), (200, Some(true)));
    assert!(c
        .store
        .authenticate(tokens[0].as_str(), ApiKeyScope::InboxPush)
        .is_err());
    assert!(c
        .store
        .authenticate(tokens[1].as_str(), ApiKeyScope::DevicePush)
        .is_ok());
    assert_eq!(
        c.change(json!({ "op": "void_key", "key_id": 999 }), &lock)
            .0,
        404
    );

    let (status, body) = c.change(
        json!({ "op": "void_licence", "licence_id": licence_id, "reason": "unpaid" }),
        &lock,
    );
    assert_eq!(status, 200);
    assert_eq!(
        (
            body["newly_voided"].as_bool(),
            body["revoked_keys"].as_array().map(Vec::len)
        ),
        (Some(true), Some(1))
    );
    assert!(c
        .store
        .authenticate(tokens[1].as_str(), ApiKeyScope::DevicePush)
        .is_err());
    let (_, detail) = c.ask(json!({ "op": "user", "id": 1 }), None);
    assert_eq!(detail["licences"][0]["status"], "voided");
    assert_eq!(detail["licences"][0]["void_reason"], "unpaid");
    assert_eq!(detail["licences"][0]["live_keys"], 0);
    assert_eq!(
        c.change(json!({ "op": "void_licence", "licence_id": 999 }), &lock)
            .0,
        404
    );
    // Nothing more can be issued under it, or renewed.
    let (status, _) = c.change(
        json!({ "op": "issue", "customer_id": 1, "licence_id": licence_id, "scopes": ["inbox.pull"],
                "recipient_public_key": hex::encode(public), "relay_url": "https://relay.example.test" }),
        &lock,
    );
    assert_eq!(status, 409);
    assert_eq!(
        c.change(
            json!({ "op": "renew_licence", "licence_id": licence_id, "terms": "late" }),
            &lock
        )
        .0,
        409
    );
}

#[test]
fn an_unassigned_key_is_listed_as_such_and_assigned_only_by_the_operators_choice() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push"]);
    let licence_id = issued["licence"]["id"].as_i64().expect("licence");
    // A key made some other way (the host CLI) has no owner here.
    let stray = c
        .store
        .mint_key(&crate::relay::NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: Some("made elsewhere".into()),
            ttl_seconds: None,
        })
        .expect("key")
        .info
        .id;
    let (_, overview) = c.ask(json!({ "op": "overview" }), None);
    assert_eq!(overview["keys"]["unassigned"], 1);
    let (_, view) = c.ask(json!({ "op": "keys", "assignment": "unassigned" }), None);
    assert_eq!(view["keys"].as_array().expect("keys").len(), 1);
    assert_eq!(view["keys"][0]["assigned"], false);
    assert!(view["keys"][0]["customer"].is_null());
    // It cannot be replaced until it is assigned.
    let (status, body) = c.change(json!({ "op": "rotate", "key_id": stray }), &lock);
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
    let (status, _) = c.change(
        json!({ "op": "assign_key", "key_id": stray, "licence_id": licence_id }),
        &lock,
    );
    assert_eq!(status, 200);
    let (_, view) = c.ask(json!({ "op": "keys", "customer_id": 1 }), None);
    assert_eq!(view["keys"].as_array().expect("keys").len(), 2);
    assert_eq!(
        c.ask(json!({ "op": "keys", "assignment": "unassigned" }), None)
            .1["keys"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    // Never twice.
    assert_eq!(
        c.change(
            json!({ "op": "assign_key", "key_id": stray, "licence_id": licence_id }),
            &lock
        )
        .0,
        400
    );
    assert_eq!(
        c.change(
            json!({ "op": "assign_key", "key_id": 999, "licence_id": licence_id }),
            &lock
        )
        .0,
        404
    );
}

#[test]
fn keys_are_paged_and_filtered_by_state_and_customer() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push", "inbox.pull", "device.push"]);
    let revoke = issued["bundles"][0]["key_id"].as_i64().expect("key");
    c.change(json!({ "op": "void_key", "key_id": revoke }), &lock);
    let (status, page) = c.ask(json!({ "op": "keys", "limit": 2 }), None);
    assert_eq!(status, 200);
    assert_eq!(page["keys"].as_array().expect("keys").len(), 2);
    let cursor = page["next_before"].as_i64().expect("cursor");
    let (_, rest) = c.ask(json!({ "op": "keys", "limit": 2, "before": cursor }), None);
    assert_eq!(rest["keys"].as_array().expect("keys").len(), 1);
    assert!(rest["next_before"].is_null());
    let by_state = |state: &str| {
        c.ask(json!({ "op": "keys", "state": state }), None).1["keys"]
            .as_array()
            .expect("keys")
            .len()
    };
    assert_eq!(
        (
            by_state("live"),
            by_state("revoked"),
            by_state("expired"),
            by_state("all")
        ),
        (2, 1, 0, 3)
    );
    assert_eq!(
        c.ask(json!({ "op": "keys", "state": "bogus" }), None).0,
        400
    );
    assert_eq!(
        c.ask(json!({ "op": "keys", "assignment": "bogus" }), None)
            .0,
        400
    );
    assert!(!c
        .ask(json!({ "op": "keys" }), None)
        .1
        .to_string()
        .contains("kq_"));
}

#[test]
fn activity_is_attributed_through_the_key_to_the_customer_and_unknown_bearers_to_nobody() {
    let c = console();
    let lock = c.lock();
    let (secret, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push", "inbox.pull"]);
    let push = open_bundle(
        &c,
        &secret,
        issued["bundles"][0]["bundle_base64"].as_str().expect("b64"),
    )
    .issue
    .token;
    let push_id = issued["bundles"][0]["key_id"].as_i64().expect("key");
    let cost = |millis| Cost {
        millis,
        bytes_in: 100,
        bytes_out: 10,
    };
    for ms in [10, 30] {
        c.store
            .record_access(push.as_str(), "/inbox", 200, cost(ms))
            .expect("record");
    }
    c.store
        .record_access(push.as_str(), "/inbox", 403, cost(5))
        .expect("record");
    c.store
        .record_access(push.as_str(), "/devices/packages", 500, cost(7))
        .expect("record");
    c.store
        .record_access("kq_never-issued-to-anyone", "/inbox", 401, cost(1))
        .expect("unknown");
    // A key made elsewhere is counted, under nobody.
    let stray = c
        .store
        .mint_key(&crate::relay::NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: None,
        })
        .expect("key");
    c.store
        .record_access(stray.token.as_str(), "/inbox", 200, cost(2))
        .expect("record");

    let (status, view) = c.ask(json!({ "op": "activity", "hours": 24 }), None);
    assert_eq!(status, 200);
    assert_eq!(
        view["totals"]["requests"], 5,
        "the unknown bearer is not counted"
    );
    assert_eq!(
        (
            view["totals"]["ok"].as_i64(),
            view["totals"]["blocked"].as_i64(),
            view["totals"]["server_error"].as_i64()
        ),
        (Some(3), Some(1), Some(1))
    );
    assert_eq!(view["totals"]["max_ms"], 30);
    assert_eq!(view["totals"]["bytes_in"], 500);
    let users = view["users"].as_array().expect("users");
    let acme = users
        .iter()
        .find(|u| u["customer"] == "Acme Ltd")
        .expect("acme");
    assert_eq!(
        (
            acme["requests"].as_i64(),
            acme["ok"].as_i64(),
            acme["blocked"].as_i64(),
            acme["avg_ms"].as_i64()
        ),
        (Some(4), Some(2), Some(1), Some(13))
    );
    assert!(acme["last_used_at"].is_null() || acme["last_used_at"].is_string());
    let nobody = users
        .iter()
        .find(|u| u["customer_id"].is_null())
        .expect("unassigned bucket");
    assert_eq!(nobody["requests"], 1);
    assert!(view["note"]
        .as_str()
        .expect("note")
        .contains("not seen here"));

    // Filters narrow it: by customer, key, route and outcome.
    let narrow = |patch: Value| {
        let mut request = json!({ "op": "activity", "hours": 24 });
        for (k, v) in patch.as_object().expect("object") {
            request[k] = v.clone();
        }
        c.ask(request, None).1["totals"]["requests"]
            .as_i64()
            .expect("requests")
    };
    assert_eq!(narrow(json!({ "customer_id": 1 })), 4);
    assert_eq!(narrow(json!({ "key_id": push_id })), 4);
    assert_eq!(narrow(json!({ "route": "devices" })), 1);
    assert_eq!(narrow(json!({ "outcome": "scope" })), 1);
    assert_eq!(
        narrow(json!({ "customer_id": 1, "outcome": "ok", "route": "inbox" })),
        2
    );
    assert_eq!(
        c.ask(json!({ "op": "activity", "route": "keys" }), None).0,
        400
    );
    assert_eq!(
        c.ask(json!({ "op": "activity", "outcome": "bad" }), None).0,
        400
    );
    let (_, overview) = c.ask(json!({ "op": "overview" }), None);
    assert_eq!(overview["last_24h"], json!({ "served": 3, "blocked": 1 }));
}

#[test]
fn the_letter_view_shows_kind_size_and_customer_but_never_the_letters_contents() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    c.issue(&lock, &public, &["inbox.pull"]);
    let secret_payload = b"the-sealed-contents-the-relay-cannot-read";
    let letter = fake_letter(&public, crate::envelope::KIND_FILE_HISTORY, secret_payload);
    c.store.inbox_push(&[], &letter, None).expect("push");
    c.store
        .store_device_package(&fake_letter(
            &public,
            crate::envelope::KIND_DEVICE_TRANSFER,
            b"x",
        ))
        .expect("device letter");

    let (status, view) = c.ask(json!({ "op": "letters" }), None);
    assert_eq!(status, 200);
    let row = &view["inbox"]["newest"][0];
    assert_eq!(
        (
            view["inbox"]["total"].as_i64(),
            row["kind_name"].as_str(),
            row["customer"].as_str()
        ),
        (Some(1), Some("tracked file"), Some("Acme Ltd"))
    );
    assert_eq!(row["size"], letter.len());
    assert_eq!(view["devices"]["newest"][0]["kind_name"], "device transfer");
    assert!(!view.to_string().contains("sealed-contents"));
}

#[test]
fn the_lock_check_feed_pages_back_through_every_row_without_skipping() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    for _ in 0..3 {
        c.issue(&lock, &public, &["inbox.push"]);
    }
    c.issue("kql_wrong", &public, &["inbox.push"]);
    c.issue("kql_wrong_too", &public, &["inbox.push"]);
    let all: Vec<i64> = c
        .store
        .provider_auth_events(500, None)
        .expect("auth")
        .iter()
        .map(|e| e.id)
        .collect();
    assert!(all.len() > 4, "enough rows for several pages");

    let mut seen_ids = Vec::new();
    let mut before = None;
    for _ in 0..all.len() {
        let mut request = json!({ "op": "audit", "feed": "auth", "limit": 2 });
        if let Some(cursor) = before {
            request["before"] = json!(cursor);
        }
        let (status, page) = c.ask(request, None);
        assert_eq!(status, 200);
        let rows = page["rows"].as_array().expect("rows");
        assert!(rows.len() <= 2);
        seen_ids.extend(rows.iter().map(|r| r["id"].as_i64().expect("id")));
        match page["next_before"].as_i64() {
            Some(next) => before = Some(next),
            None => break,
        }
    }
    assert_eq!(seen_ids, all, "every attempt is reachable, newest first");
}

#[test]
fn a_letter_for_a_recipient_two_customers_hold_keys_for_names_neither() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    for name in ["Acme Ltd", "Beta Ltd"] {
        let (status, _) = c.change(
            json!({
                "op": "issue", "name": name, "terms": "Five seats.",
                "expires_at": "2999-01-01", "scopes": ["inbox.pull"],
                "recipient_public_key": hex::encode(public),
                "relay_url": "https://relay.example.test",
            }),
            &lock,
        );
        assert_eq!(status, 200);
    }
    let letter = fake_letter(&public, crate::envelope::KIND_FILE_HISTORY, b"x");
    c.store.inbox_push(&[], &letter, None).expect("push");

    let (_, view) = c.ask(json!({ "op": "letters" }), None);
    let row = &view["inbox"]["newest"][0];
    assert!(row["customer"].is_null(), "no owner is picked");
    let mut names: Vec<&str> = row["customers"]
        .as_array()
        .expect("customers")
        .iter()
        .filter_map(|n| n.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["Acme Ltd", "Beta Ltd"]);
}

#[test]
fn the_audit_feeds_are_paged_and_hold_no_secret() {
    let c = console();
    let lock = c.lock();
    let (_, public) = client();
    for _ in 0..3 {
        c.issue(&lock, &public, &["inbox.push"]);
    }
    c.issue("kql_wrong", &public, &["inbox.push"]);

    let (status, keys_feed) = c.ask(json!({ "op": "audit", "feed": "keys", "limit": 2 }), None);
    assert_eq!(status, 200);
    assert_eq!(keys_feed["rows"][0]["event"], "created");
    assert_eq!(keys_feed["rows"][0]["actor"], "host");
    assert_eq!(
        keys_feed["rows"][0]["entry_hash"].as_str().map(str::len),
        Some(64)
    );
    let cursor = keys_feed["next_before"].as_i64().expect("more");
    let (_, older) = c.ask(
        json!({ "op": "audit", "feed": "keys", "limit": 2, "before": cursor }),
        None,
    );
    assert_eq!(older["rows"].as_array().expect("rows").len(), 1);
    assert!(older["next_before"].is_null());

    let (_, actions) = c.ask(json!({ "op": "audit", "feed": "actions" }), None);
    let rows = actions["rows"].as_array().expect("rows");
    assert!(rows
        .iter()
        .any(|r| r["success"] == false && r["action"] == "issue"));
    assert!(rows.iter().any(|r| r["operation_id"].is_string()));
    let (_, auth) = c.ask(json!({ "op": "audit", "feed": "auth" }), None);
    assert!(auth["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .any(|r| r["success"] == false));
    for feed in [&keys_feed, &actions, &auth] {
        assert!(!feed.to_string().contains(&lock));
    }
    assert_eq!(
        c.ask(json!({ "op": "audit", "feed": "everything" }), None)
            .0,
        400
    );
    assert_eq!(c.ask(json!({ "op": "audit" }), None).0, 400);
}

#[test]
fn trees_the_checkpoint_and_status_are_readable_with_only_the_operator_identity() {
    let c = console();
    let (status, trees) = c.ask(json!({ "op": "trees" }), None);
    assert_eq!(
        (status, trees["trees"].as_array().map(Vec::len)),
        (200, Some(0))
    );

    let (status, checkpoint) = c.ask(json!({ "op": "checkpoint" }), None);
    assert_eq!(status, 200);
    let bytes = STANDARD
        .decode(checkpoint["content_base64"].as_str().expect("b64"))
        .expect("base64");
    assert!(crate::relay::audit::Checkpoint::decode(&bytes).is_ok());
    assert!(checkpoint["filename"]
        .as_str()
        .expect("name")
        .ends_with(".json"));
    assert_eq!(
        c.ask_as(OPERATOR, json!({ "op": "checkpoint" }), None, false)
            .0,
        503
    );

    let (status, view) = c.ask(json!({ "op": "status" }), None);
    assert_eq!(status, 200);
    assert_eq!(view["ready"], true);
    assert_eq!(view["identity"]["configured"], true);
    assert!(
        view["identity"]["serial"].is_string() || view["identity"]["certificate_readable"] == false
    );
    assert_eq!(
        view["operator_lock"],
        json!({ "exists": false, "pending": false })
    );
    assert_eq!(view["counts"], json!({ "customers": 0, "keys": 0 }));
    let (_, bare) = c.ask_as(OPERATOR, json!({ "op": "status" }), None, false);
    assert_eq!(bare["identity"], json!({ "configured": false }));
    c.ask(json!({ "op": "bootstrap" }), None);
    assert_eq!(
        c.ask(json!({ "op": "status" }), None).1["operator_lock"],
        json!({ "exists": false, "pending": true })
    );
}

#[test]
fn the_overview_counts_customers_keys_licences_and_the_lock() {
    let c = console();
    let (_, before) = c.ask(json!({ "op": "overview" }), None);
    assert_eq!(
        (
            before["operator_lock"].as_bool(),
            before["identity_configured"].as_bool()
        ),
        (Some(false), Some(true))
    );
    let lock = c.lock();
    let (_, public) = client();
    let (_, issued) = c.issue(&lock, &public, &["inbox.push", "inbox.pull"]);
    c.change(
        json!({ "op": "void_key", "key_id": issued["bundles"][0]["key_id"] }),
        &lock,
    );
    let (_, overview) = c.ask(json!({ "op": "overview" }), None);
    assert_eq!(overview["operator_lock"], true);
    assert_eq!(overview["customers"], 1);
    assert_eq!(
        overview["keys"],
        json!({ "live": 1, "revoked": 1, "expired": 0, "unassigned": 0 })
    );
    assert_eq!(
        overview["licences"],
        json!({ "active": 1, "voided": 0, "ended": 0 })
    );
    assert_eq!(overview["max_grace_seconds"], MAX_GRACE_SECONDS);
}

#[test]
fn a_store_failure_is_reported_in_fixed_words_not_the_stores() {
    let reply = failure(&Error::Store("SELECT secret FROM somewhere".into()));
    assert_eq!(reply.status, 500);
    assert!(!String::from_utf8(reply.body)
        .expect("utf8")
        .contains("SELECT"));
    let unknown = failure(&Error::StoreCommitUnknown);
    assert!(String::from_utf8(unknown.body)
        .expect("utf8")
        .contains("same operation id"));
    assert_eq!(
        failure(&Error::RelayRequest("secret detail".into())).status,
        400
    );
    assert_eq!(failure(&Error::CustomerNotFound).status, 404);
    assert_eq!(failure(&Error::KeyNotAssigned).status, 409);
    assert_eq!(failure(&Error::DeliveryNotCollectable).status, 409);
}

#[test]
fn a_licence_is_recorded_for_a_customer_without_keys_and_a_replacement_voids_the_old_one() {
    let c = console();
    let lock = c.lock();
    let (_, made) = c.change(
        json!({ "op": "create_customer", "name": "Acme", "reference": "C-9" }),
        &lock,
    );
    let customer_id = made["customer"]["id"].as_i64().expect("customer");
    assert_eq!(made["customer"]["reference"], "C-9");
    // The same reference is refused.
    assert_eq!(
        c.change(
            json!({ "op": "create_customer", "name": "Other", "reference": "C-9" }),
            &lock
        )
        .0,
        400
    );

    let (status, first) = c.change(
        json!({ "op": "create_licence", "customer_id": customer_id, "terms": "Five seats.", "expires_at": "2999-01-01" }),
        &lock,
    );
    assert_eq!(status, 200);
    assert_eq!(
        (
            first["licence"]["status"].as_str(),
            first["licence"]["version"].as_i64()
        ),
        (Some("active"), Some(1))
    );
    assert!(
        c.store.list_keys().expect("keys").is_empty(),
        "a licence record carries no keys"
    );
    let first_id = first["licence"]["id"].as_i64().expect("licence");

    let (status, second) = c.change(
        json!({ "op": "create_licence", "customer_id": customer_id, "terms": "Ten seats.", "replaces_licence_id": first_id }),
        &lock,
    );
    assert_eq!(status, 200);
    assert_eq!(second["voided_licence_id"], first_id);
    assert_eq!(second["licence"]["replaces_licence_id"], first_id);
    let (_, detail) = c.ask(json!({ "op": "user", "id": customer_id }), None);
    let statuses: Vec<_> = detail["licences"]
        .as_array()
        .expect("licences")
        .iter()
        .map(|l| l["status"].as_str().expect("status"))
        .collect();
    assert_eq!(statuses, ["active", "voided"]);
    assert_eq!(
        c.change(json!({ "op": "create_licence", "customer_id": 99 }), &lock)
            .0,
        404
    );
    assert_eq!(c.change(json!({ "op": "create_licence", "customer_id": customer_id, "expires_at": "2000-01-01" }), &lock).0, 400);
}

// What the relay says about its own identity is whether an official client
// would trust it, not whether two secrets are present.
mod identity_trust {
    use super::*;
    use crate::provider::test_helpers::issued_identity_with_caps;
    use crate::provider::{CAP_PROVIDER, CAP_RELAY, KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY};

    const BEFORE_EXPIRY: &str = "2026-10-07 03:00:00.000";

    fn identity_of(
        issued: crate::provider::test_helpers::IssuedIdentity,
    ) -> (ProviderIdentity, [u8; 32]) {
        (
            ProviderIdentity {
                certificate: issued.certificate,
                relay_private_key: issued.relay_private,
            },
            issued.root_public,
        )
    }

    #[test]
    fn a_certificate_from_the_pinned_root_for_the_held_key_is_trusted() {
        let (identity, root) = identity_of(issued_identity_with_caps(
            "2099-01-01 00:00:00",
            CAP_PROVIDER,
        ));
        let check = identity_check(Some(&identity), &root, BEFORE_EXPIRY);
        assert_eq!(check["state"], "trusted");
        assert_eq!(check["pinned_root"], hex::encode(root));
        assert!(check.get("reason").is_none());
    }

    #[test]
    fn no_identity_is_missing_and_still_names_the_pinned_root() {
        let check = identity_check(None, &[7u8; 32], BEFORE_EXPIRY);
        assert_eq!(
            check,
            json!({ "state": "missing", "pinned_root": hex::encode([7u8; 32]) })
        );
    }

    #[test]
    fn each_way_an_identity_is_configured_but_untrusted_names_its_own_reason() {
        let (identity, root) = identity_of(issued_identity_with_caps(
            "2099-01-01 00:00:00",
            CAP_PROVIDER,
        ));
        let reason = |identity: &ProviderIdentity, root: &[u8; 32], now: &str| {
            let check = identity_check(Some(identity), root, now);
            assert_eq!(check["state"], "untrusted");
            check["reason"].as_str().expect("a reason").to_string()
        };
        // Signed by some other root than the one pinned.
        assert_eq!(
            reason(&identity, &[9u8; 32], BEFORE_EXPIRY),
            "certificate_not_signed_by_pinned_root"
        );
        // Not a certificate at all.
        let garbage = ProviderIdentity {
            certificate: vec![1, 2, 3],
            relay_private_key: identity.relay_private_key.clone(),
        };
        assert_eq!(
            reason(&garbage, &root, BEFORE_EXPIRY),
            "certificate_not_signed_by_pinned_root"
        );
        // Past its expiry.
        assert_eq!(
            reason(&identity, &root, "2100-01-01 00:00:00.000"),
            "certificate_expired"
        );
        // A key that is not the one the certificate names.
        let other = issued_identity_with_caps("2099-01-01 00:00:00", CAP_PROVIDER);
        let swapped = ProviderIdentity {
            certificate: identity.certificate.clone(),
            relay_private_key: other.relay_private,
        };
        assert_eq!(
            reason(&swapped, &root, BEFORE_EXPIRY),
            "key_does_not_match_certificate"
        );
        // A certificate that does not grant what a provider relay needs.
        let (thin, thin_root) =
            identity_of(issued_identity_with_caps("2099-01-01 00:00:00", CAP_RELAY));
        assert_eq!(
            reason(&thin, &thin_root, BEFORE_EXPIRY),
            "capabilities_missing"
        );
    }

    #[test]
    fn the_overview_and_status_report_the_check_and_leak_no_secret() {
        // The console's test identity is signed by a throwaway root, not the one
        // compiled in, which is exactly an operator who has not pinned theirs.
        let c = console();
        let key_hex = hex::encode(*c.identity.relay_private_key);
        let (_, overview) = c.ask(json!({ "op": "overview" }), None);
        assert_eq!(overview["identity_configured"], true);
        assert_eq!(overview["identity_check"]["state"], "untrusted");
        assert_eq!(
            overview["identity_check"]["reason"],
            "certificate_not_signed_by_pinned_root"
        );
        assert_eq!(
            overview["identity_check"]["pinned_root"],
            hex::encode(KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY)
        );
        let (_, status) = c.ask(json!({ "op": "status" }), None);
        assert_eq!(status["identity_check"], overview["identity_check"]);
        for reply in [&overview, &status] {
            let text = reply.to_string();
            assert!(
                !text.contains(&key_hex),
                "the relay key never appears in a reply"
            );
        }
    }
}
