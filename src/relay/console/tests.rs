use super::{asset, asset_paths, content_type, BUILT, CONTENT_SECURITY_POLICY_VALUE};
use crate::relay::{self, router, AppState};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

fn app() -> axum::Router {
    router(AppState::new(relay::open_in_memory().expect("schema")))
}

async fn send(app: &axum::Router, method: Method, uri: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn text(response: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

fn header<'a>(response: &'a axum::http::Response<Body>, name: &str) -> &'a str {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("header {name} is set"))
}

#[tokio::test]
async fn console_page_is_public_and_served_with_its_security_headers() {
    let app = app();
    let response = send(&app, Method::GET, "/console/").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header(&response, "content-type"),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        header(&response, "content-security-policy"),
        CONTENT_SECURITY_POLICY_VALUE
    );
    assert_eq!(header(&response, "cache-control"), "no-store");
    assert_eq!(header(&response, "x-content-type-options"), "nosniff");
    assert_eq!(header(&response, "x-frame-options"), "DENY");
    assert_eq!(header(&response, "referrer-policy"), "no-referrer");
    let body = text(response).await;
    assert!(body.contains("KeyQuorum Relay Console"));
    // The policy forbids inline script and style, so the page carries none.
    assert!(!body.contains("<script>"));
    assert!(!body.contains("<style"));
    assert!(!body.contains(" onload="));
}

#[tokio::test]
async fn console_root_redirects_to_the_directory() {
    let app = app();
    let response = send(&app, Method::GET, "/console").await;
    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&response, "location"), "/console/");
}

#[tokio::test]
async fn console_serves_only_the_embedded_table() {
    let app = app();
    for uri in [
        "/console/missing.js",
        "/console/assets/",
        "/console/%2e%2e/Cargo.toml",
        "/console/../Cargo.toml",
        "/console/src/relay/console/placeholder.html",
    ] {
        let response = send(&app, Method::GET, uri).await;
        assert!(
            response.status() == StatusCode::NOT_FOUND
                || response.status() == StatusCode::BAD_REQUEST,
            "{uri} is not served"
        );
    }
    // Only GET: the console never takes a body.
    let response = send(&app, Method::POST, "/console/").await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let response = send(&app, Method::PUT, "/console/index.html").await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn console_can_be_left_out() {
    let state = AppState::new(relay::open_in_memory().expect("schema")).without_console();
    let app = router(state);
    for uri in ["/console", "/console/", "/console/index.html"] {
        let response = send(&app, Method::GET, uri).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{uri} is not served"
        );
    }
    // The API is unchanged.
    let response = send(&app, Method::GET, "/health").await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// The built bundle references hashed files under `assets/`, each of which
/// is served immutable. Without a build only the placeholder is embedded;
/// CI sets `KEYQUORUM_CONSOLE_EXPECT_BUILT` after `npm run build` so the
/// provider binary it tests is the one with the console in it.
#[tokio::test]
async fn built_console_references_only_embedded_hashed_assets() {
    let expect_built = std::env::var_os("KEYQUORUM_CONSOLE_EXPECT_BUILT").is_some();
    if expect_built && !BUILT {
        panic!("KEYQUORUM_CONSOLE_EXPECT_BUILT is set, but this binary carries the placeholder");
    }
    if !BUILT {
        assert_eq!(asset_paths().collect::<Vec<_>>(), vec!["index.html"]);
        return;
    }
    let app = app();
    let index = text(send(&app, Method::GET, "/console/").await).await;
    let referenced: Vec<&str> = index
        .split('"')
        .filter(|part| part.starts_with("/console/assets/"))
        .collect();
    assert!(!referenced.is_empty(), "index.html names its bundle");
    for reference in referenced {
        let path = &reference["/console/".len()..];
        assert!(asset(path).is_some(), "{path} is embedded");
        let response = send(&app, Method::GET, reference).await;
        assert_eq!(response.status(), StatusCode::OK, "{reference} is served");
        assert_eq!(
            header(&response, "cache-control"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            header(&response, "content-security-policy"),
            CONTENT_SECURITY_POLICY_VALUE
        );
    }
    // Nothing but the bundle is embedded: no source map, no dotfile.
    for path in asset_paths() {
        assert!(!path.ends_with(".map"), "{path} is not a source map");
        assert!(
            !path.split('/').any(|part| part.starts_with('.')),
            "{path} is not hidden"
        );
    }
}

#[test]
fn content_types_follow_the_extension() {
    assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
    assert_eq!(
        content_type("assets/index-abc.js"),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        content_type("assets/index-abc.css"),
        "text/css; charset=utf-8"
    );
    assert_eq!(content_type("favicon.svg"), "image/svg+xml");
    assert_eq!(content_type("unknown.bin"), "application/octet-stream");
    assert_eq!(content_type("noext"), "application/octet-stream");
}
