use super::super::test_helpers::*;
use super::{router, AppState, ProviderIdentity, MAX_ENVELOPE_BYTES};
use crate::key_tree::PublicTree;
use crate::keys;
use crate::provider::test_helpers::issued_identity;
use crate::relay::{self, ApiKeyScope, NewApiKey};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tower::ServiceExt;

async fn body_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn router_health_and_openapi_are_public() {
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::new(conn));
    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let spec = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spec.status(), StatusCode::OK);
    let json = body_json(spec).await;
    assert!(json["paths"]["/inbox"].is_object());
    assert!(json["paths"]["/api-keys"].is_object());
    assert!(json["paths"]["/keycheck"].is_object());
    assert!(json["paths"]["/keycheck"]["post"].get("security").is_none());
    assert!(json["paths"]["/api/v1/{provider_id}/register"].is_null());
    assert!(json["paths"]["/provider-identity"].is_object());
    assert!(json["paths"]["/provider-identity"]["post"]
        .get("security")
        .is_none());
    assert!(json["components"]["securitySchemes"]["api_key"].is_object());
}

#[tokio::test]
async fn router_enforces_scopes_and_returns_opaque_bytes() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, fingerprint) = sample_envelope();
    let push = push_key(&conn);
    let pull = pull_key(&conn, &fingerprint);
    let other_fp = keys::fingerprint(&[9u8; 32]);
    let other_pull = pull_key(&conn, &other_fp);
    let admin = admin_key(&conn);
    let app = router(AppState::new(conn));

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .header("Content-Type", "application/octet-stream")
                .body(Body::from(envelope.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let stored = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .header("Content-Type", "application/octet-stream")
                .body(Body::from(envelope.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stored.status(), StatusCode::CREATED);

    let again = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .header("Content-Type", "application/octet-stream")
                .body(Body::from(envelope.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::OK);

    let pull_denied_as_push = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_denied_as_push.status(), StatusCode::FORBIDDEN);

    let got = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    let json = body_json(got).await;
    let encoded = json["envelopes"][0]["bytes"].as_str().unwrap();
    let decoded = STANDARD.decode(encoded).expect("base64");
    assert_eq!(decoded, envelope);

    let empty = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("X-Api-Key", &other_pull)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    let empty_json = body_json(empty).await;
    assert_eq!(empty_json["envelopes"].as_array().unwrap().len(), 0);
    assert_eq!(empty_json["trees"].as_array().unwrap().len(), 0);

    let unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api-keys")
                .header("Authorization", format!("Bearer {push}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::FORBIDDEN);

    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api-keys")
                .header("Authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);

    let mint_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api-keys")
                .header("Authorization", format!("Bearer {admin}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"scope":"inbox.push","label":"stolen"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mint_denied.status(), StatusCode::METHOD_NOT_ALLOWED);

    let rotate_gone = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api-keys/1/rotate")
                .header("Authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotate_gone.status(), StatusCode::NOT_FOUND);
}

#[test]
fn max_envelope_constant_is_one_mib() {
    assert_eq!(MAX_ENVELOPE_BYTES, 1024 * 1024);
}

#[tokio::test]
async fn inbox_get_rejects_invalid_page_sizes() {
    let conn = relay::open_in_memory().expect("schema");
    let pull = pull_key(&conn, &keys::fingerprint(&[1u8; 32]));
    let app = router(AppState::new(conn));
    for uri in ["/inbox?limit=0", "/inbox?limit=501"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("Authorization", format!("Bearer {pull}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn push_rolls_back_trees_and_envelope_when_a_later_tree_is_invalid() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, mailbox_fp) = sample_envelope();
    let (good, s2) = example_org_tree();
    let s2_fp = keys::fingerprint(&s2);
    let push = push_key(&conn);
    let pull_s2 = pull_key(&conn, &s2_fp);
    let pull_mailbox = pull_key(&conn, &mailbox_fp);
    let cyclic = PublicTree {
        label: "other".into(),
        generation: 1,
        nodes: vec![
            split_node("M", None),
            split_node("A", Some("B")),
            split_node("B", Some("A")),
        ],
        whitelist: vec![],
        links: vec![],
    };
    let body = serde_json::to_vec(&relay::InboxPush {
        bytes: STANDARD.encode(&envelope),
        trees: vec![good, cyclic],
        expires_at: None,
    })
    .unwrap();
    let app = router(AppState::new(conn));

    let stored = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stored.status(), StatusCode::BAD_REQUEST);

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/trees/org/context")
                .header("Authorization", format!("Bearer {pull_s2}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let listed = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull_mailbox}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let json = body_json(listed).await;
    assert_eq!(json["envelopes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn router_publish_and_fetch_tree_context() {
    let conn = relay::open_in_memory().expect("schema");
    let (tree, s2) = example_org_tree();
    let fp = keys::fingerprint(&s2);
    let admin = admin_key(&conn);
    let pull = pull_key(&conn, &fp);
    let push = push_key(&conn);
    let app = router(AppState::new(conn));

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/trees")
                .header("Authorization", format!("Bearer {pull}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&tree).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let published = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/trees")
                .header("Authorization", format!("Bearer {admin}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&tree).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(published.status(), StatusCode::OK);
    let json = body_json(published).await;
    assert_eq!(json["generation"], 1);

    let push_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/trees/org/context")
                .header("Authorization", format!("Bearer {push}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(push_denied.status(), StatusCode::FORBIDDEN);

    let got = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/trees/org/context")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    let json = body_json(got).await;
    let labels: Vec<&str> = json["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["label"].as_str().unwrap())
        .collect();
    assert!(labels.contains(&"M.A.2"));
    assert!(!labels.contains(&"M.A.1"));

    let inbox = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inbox.status(), StatusCode::OK);
    let inbox_json = body_json(inbox).await;
    assert_eq!(inbox_json["envelopes"].as_array().unwrap().len(), 0);
    let inbox_labels: Vec<&str> = inbox_json["trees"][0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["label"].as_str().unwrap())
        .collect();
    assert!(inbox_labels.contains(&"M.A.2"));
    assert!(!inbox_labels.contains(&"M.A.1"));

    let mut with_ma1 = tree.clone();
    link_ma1(&mut with_ma1);
    let republished = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/trees")
                .header("Authorization", format!("Bearer {admin}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&with_ma1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(republished.status(), StatusCode::OK);

    let expanded = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expanded.status(), StatusCode::OK);
    let expanded_json = body_json(expanded).await;
    let expanded_labels: Vec<&str> = expanded_json["trees"][0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["label"].as_str().unwrap())
        .collect();
    assert!(expanded_labels.contains(&"M.A.1"));

    let spec = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let spec_json = body_json(spec).await;
    assert!(spec_json["paths"]["/trees"].is_object());
    assert!(spec_json["paths"]["/trees/{label}/context"].is_object());
    assert!(spec_json["components"]["schemas"]["InboxList"]["properties"]["trees"].is_object());
}

#[tokio::test]
async fn keycheck_route_is_public() {
    let conn = relay::open_in_memory().expect("schema");
    let created = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: Some("ops".into()),
            ttl_seconds: None,
        },
    )
    .expect("create");
    let hash = relay::hash_bearer(&created.token).expect("hash");
    let app = router(AppState::new(conn));

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"token":"{}"}}"#,
                    created.token.as_str()
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let json = body_json(ok).await;
    assert_eq!(json["valid"], true);
    assert_eq!(json["scope"], "inbox.push");

    let by_hash = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(r#"{{"key_hash":"{hash}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(by_hash.status(), StatusCode::OK);
    assert_eq!(body_json(by_hash).await["valid"], true);

    let unknown = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"token":"kq_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::OK);
    assert_eq!(body_json(unknown).await["valid"], false);
}

#[tokio::test]
async fn inbox_pull_drops_expired_envelopes() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, fingerprint) = sample_envelope();
    relay::store_until(&conn, &envelope, Some("2099-12-31 23:59:00")).expect("store");
    conn.execute(
        "UPDATE mailbox SET expires_at = datetime('now', '-1 minutes')",
        [],
    )
    .expect("expire");
    let pull = pull_key(&conn, &fingerprint);
    let app = router(AppState::new(conn));
    let got = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    let json = body_json(got).await;
    assert_eq!(json["envelopes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn inbox_push_rejects_a_past_expires() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, _) = sample_envelope();
    let push = push_key(&conn);
    let app = router(AppState::new(conn));
    let body = serde_json::to_vec(&relay::InboxPush {
        bytes: STANDARD.encode(&envelope),
        trees: vec![],
        expires_at: Some("2000-01-01 00:00:00".into()),
    })
    .unwrap();
    let denied = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn provider_identity_is_unavailable_without_configured_identity() {
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::new(conn));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/provider-identity")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn provider_identity_signs_a_valid_challenge() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::with_identity(
        conn,
        ProviderIdentity {
            certificate: issued.certificate.clone(),
            relay_private_key: issued.relay_private.clone(),
        },
    ));
    let challenge = crate::provider::random_challenge();
    let body = serde_json::json!({
        "challenge": STANDARD.encode(challenge)
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/provider-identity")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let cert = STANDARD
        .decode(json["certificate"].as_str().expect("cert"))
        .expect("cert b64");
    let signature: [u8; 64] = STANDARD
        .decode(json["signature"].as_str().expect("sig"))
        .expect("sig b64")
        .try_into()
        .expect("64");
    let parsed = crate::provider::parse_certificate(&cert).expect("parse");
    crate::provider::verify_challenge(&parsed, &challenge, &signature).expect("sig");
}

#[tokio::test]
async fn provider_identity_rejects_a_short_challenge() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::with_identity(
        conn,
        ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
    ));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/provider-identity")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"challenge":"AAAA"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn device_routes_are_api_blocked_and_keep_packages_opaque() {
    let conn = relay::open_in_memory().expect("schema");
    let (_secret, public) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&public);
    let device_push = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::DevicePush,
            recipient_fingerprint: None,
            label: Some("device-push".into()),
            ttl_seconds: None,
        },
    )
    .expect("device push")
    .token
    .as_str()
    .to_owned();
    let device_pull = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::DevicePull,
            recipient_fingerprint: Some(fingerprint),
            label: Some("device-pull".into()),
            ttl_seconds: None,
        },
    )
    .expect("device pull")
    .token
    .as_str()
    .to_owned();
    let inbox_push = push_key(&conn);
    let letter = crate::envelope::seal(
        crate::envelope::PACKAGE,
        crate::envelope::KIND_DEVICE_TRANSFER,
        &public,
        b"sealed-letter",
    )
    .expect("seal");
    let app = router(AppState::new(conn));

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/packages")
                .body(Body::from(letter.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let spec = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(spec).await;
    assert!(json["paths"]["/devices/packages"]["post"]["security"].is_array());
    assert!(json["paths"]["/devices/{device_id}"]["get"]["security"].is_array());

    let wrong_scope = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/packages")
                .header("Authorization", format!("Bearer {inbox_push}"))
                .body(Body::from(letter.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

    let raw = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/packages")
                .header("Authorization", format!("Bearer {device_push}"))
                .body(Body::from(b"KQTX".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(raw.status(), StatusCode::BAD_REQUEST);

    let stored = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/packages")
                .header("Authorization", format!("Bearer {device_push}"))
                .body(Body::from(letter.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stored.status(), StatusCode::CREATED);

    let pull_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/devices/packages")
                .header("Authorization", format!("Bearer {device_push}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_denied.status(), StatusCode::FORBIDDEN);

    let pulled = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/devices/packages")
                .header("Authorization", format!("Bearer {device_pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pulled.status(), StatusCode::OK);
    let body = body_json(pulled).await;
    let encoded = body["packages"][0]["bytes"].as_str().expect("bytes");
    let returned = STANDARD.decode(encoded).expect("b64");
    assert_eq!(returned, letter);
    assert!(!returned
        .windows(b"sealed-letter".len())
        .any(|window| window == b"sealed-letter"));

    let directory = app
        .oneshot(
            Request::builder()
                .uri("/devices/00112233445566778899aabbccddeeff")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(directory.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn plain_http_binds_only_to_loopback_unless_tls_terminates_in_front() {
    let parse = |s: &str| s.parse::<std::net::SocketAddr>().expect("addr");
    for loopback in ["127.0.0.1:8787", "[::1]:8787"] {
        super::check_bind(&parse(loopback), false).expect("loopback is allowed");
    }
    for public in ["0.0.0.0:8787", "192.0.2.10:443", "[::]:8787"] {
        assert!(matches!(
            super::check_bind(&parse(public), false),
            Err(crate::error::Error::RelayRequest(_))
        ));
        super::check_bind(&parse(public), true).expect("operator states TLS terminates upstream");
    }
}

async fn audit_events_for(app: &axum::Router, token: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/audit/api-keys")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let json = if status == StatusCode::OK {
        body_json(response).await
    } else {
        serde_json::Value::Null
    };
    (status, json)
}

#[tokio::test]
async fn audit_events_are_scoped_to_the_caller_and_revocations_are_signed_at_once() {
    let issued = issued_identity("2099-01-01 00:00:00");
    let conn = relay::open_in_memory().expect("schema");
    let admin = admin_key(&conn);
    let push = push_key(&conn);
    let other = push_key(&conn);
    let state = AppState::with_identity(
        conn,
        ProviderIdentity {
            certificate: issued.certificate.clone(),
            relay_private_key: issued.relay_private.clone(),
        },
    );
    let db = state.db.clone();
    let app = router(state);

    // A push key sees only the event about itself, never another key's.
    let (status, mine) = audit_events_for(&app, &push).await;
    assert_eq!(status, StatusCode::OK);
    let mine = mine.as_array().expect("array");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0]["api_key_id"], 2);
    assert_eq!(mine[0]["event"], "created");
    assert_eq!(mine[0]["entry_hash"].as_str().expect("hash").len(), 64);
    // An admin key sees the whole trail.
    let (_, all) = audit_events_for(&app, &admin).await;
    assert_eq!(all.as_array().expect("array").len(), 3);
    // No bearer, no access.
    let (status, _) = audit_events_for(&app, "kq_not-a-key").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An admin revokes `other` over HTTP; the relay signs the new head.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api-keys/3/revoke")
                .header("Authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // The revoked key can no longer read even its own events.
    let (status, _) = audit_events_for(&app, &other).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, all) = audit_events_for(&app, &admin).await;
    let last = all
        .as_array()
        .expect("array")
        .last()
        .cloned()
        .expect("event");
    assert_eq!(last["event"], "revoked");
    assert_eq!(last["actor"], "admin:1");

    // The revocation is already vouched for by this relay's key.
    let conn = db.lock().expect("db");
    let reports =
        relay::audit::verify(&conn, &issued.root_public, &Default::default()).expect("verify");
    let events = reports
        .iter()
        .find(|r| r.table == "api_key_events")
        .expect("report");
    assert!(events.is_intact(), "{events:?}");
    assert_eq!((events.rows, events.pending_rows()), (4, 0));
}

#[test]
fn rate_limiter_counts_per_client_and_resets_each_minute() {
    use std::net::IpAddr;
    use std::time::{Duration, Instant};
    let limiter = super::RateLimiter::new(2, false);
    let a: IpAddr = [192, 0, 2, 1].into();
    let b: IpAddr = [192, 0, 2, 2].into();
    let t0 = Instant::now();
    assert!(limiter.check(a, t0).is_ok());
    assert!(limiter.check(a, t0).is_ok());
    let wait = limiter
        .check(a, t0 + Duration::from_secs(20))
        .expect_err("third is refused");
    assert_eq!(wait, Duration::from_secs(40));
    // Another client has its own allowance.
    assert!(limiter.check(b, t0).is_ok());
    // A new window starts a minute later.
    assert!(limiter.check(a, t0 + Duration::from_secs(60)).is_ok());
}

#[test]
fn rate_limiter_memory_stays_bounded_under_many_addresses() {
    use std::net::IpAddr;
    use std::time::Instant;
    let limiter = super::RateLimiter::new(1, false);
    let now = Instant::now();
    for i in 0..(super::MAX_RATE_LIMITED_CLIENTS as u32 + 10) {
        let ip: IpAddr = std::net::Ipv4Addr::from(i).into();
        let _ = limiter.check(ip, now);
    }
    assert!(limiter.clients.lock().unwrap().len() <= super::MAX_RATE_LIMITED_CLIENTS + 1);
}

async fn health_from(app: &axum::Router, forwarded: Option<&str>) -> axum::http::Response<Body> {
    let mut request = Request::builder().uri("/health");
    if let Some(value) = forwarded {
        request = request.header("X-Forwarded-For", value);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn rate_limited_requests_get_429_with_retry_after() {
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::new(conn).with_rate_limit(2, false));
    assert_eq!(health_from(&app, None).await.status(), StatusCode::OK);
    assert_eq!(health_from(&app, None).await.status(), StatusCode::OK);
    let refused = health_from(&app, None).await;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = refused.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry));
    // Without a trusted proxy, a client cannot dodge the limit by claiming
    // another address.
    assert_eq!(
        health_from(&app, Some("198.51.100.7")).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn behind_a_proxy_the_last_forwarded_address_is_the_client() {
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::new(conn).with_rate_limit(1, true));
    assert_eq!(
        health_from(&app, Some("203.0.113.9, 198.51.100.1"))
            .await
            .status(),
        StatusCode::OK
    );
    // A spoofed first entry does not make a new client: the proxy's last
    // entry is the same.
    assert_eq!(
        health_from(&app, Some("203.0.113.200, 198.51.100.1"))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        health_from(&app, Some("198.51.100.2")).await.status(),
        StatusCode::OK
    );
}
