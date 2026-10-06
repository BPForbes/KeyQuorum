//! The relay operator console: the browser page `keyquorum host serve`
//! serves at `/console/`, built from `relay-console/` in the lab's style
//! and embedded into the provider binary by `build.rs` (the Vite bundle in
//! `relay-console/dist`, or `placeholder.html` when none was built).
//!
//! It is a page, not a privilege. Its files are public like the OpenAPI
//! document, and everything the page then does is an ordinary request to
//! the routes in `server.rs` with the API key the operator typed into it,
//! so the console can do exactly what that key's scope allows and nothing
//! more: it cannot mint or rotate a key, read a letter, or reach the store.
//! The page is served with a Content-Security-Policy that lets it load
//! only its own bundle and talk only to its own origin, and `index.html`
//! is never cached, so a relay upgrade is a page reload. Requests are
//! matched against the embedded table only, never a filesystem path.
//!
//! `--no-console` on `host serve` leaves these routes out
//! (`AppState::without_console`).

use axum::extract::Path;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

/// One embedded file of the console bundle.
pub struct Asset {
    /// Path relative to the bundle root, with `/` separators (`index.html`,
    /// `assets/index-abc123.js`).
    pub path: &'static str,
    pub bytes: &'static [u8],
}

mod assets {
    use super::Asset;
    include!(concat!(env!("OUT_DIR"), "/relay_console_assets.rs"));
}

/// Whether this binary carries the built console rather than the
/// placeholder page.
pub const BUILT: bool = assets::BUILT;

/// What the console page may load and reach: its own bundle, and this
/// relay. No inline script or style, no other origin, never framed.
pub const CONTENT_SECURITY_POLICY_VALUE: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; \
     base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The embedded file at `path`, if the bundle holds one.
pub fn asset(path: &str) -> Option<&'static Asset> {
    assets::ASSETS.iter().find(|asset| asset.path == path)
}

/// Every embedded path, for tests and diagnostics.
pub fn asset_paths() -> impl Iterator<Item = &'static str> {
    assets::ASSETS.iter().map(|asset| asset.path)
}

/// The media type a bundle file is served as, by its extension.
pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Vite names bundle files under `assets/` by content hash, so they can be
/// cached for good; `index.html` names the current ones and never is.
fn cache_control(path: &str) -> &'static str {
    if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    }
}

fn respond(asset: &'static Asset) -> Response {
    let headers = [
        (
            CONTENT_TYPE,
            HeaderValue::from_static(content_type(asset.path)),
        ),
        (
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY_VALUE),
        ),
        (
            CACHE_CONTROL,
            HeaderValue::from_static(cache_control(asset.path)),
        ),
        (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
        (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
        (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ),
    ];
    (StatusCode::OK, headers, asset.bytes).into_response()
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn redirect_to_directory() -> Redirect {
    Redirect::permanent("/console/")
}

async fn index() -> Response {
    asset("index.html").map_or_else(not_found, respond)
}

async fn file(Path(path): Path<String>) -> Response {
    asset(&path).map_or_else(not_found, respond)
}

/// The console's routes, to merge into the relay router. Generic over the
/// router's state because the handlers need none.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/console", get(redirect_to_directory))
        .route("/console/", get(index))
        .route("/console/{*path}", get(file))
}

#[cfg(test)]
#[path = "console/tests.rs"]
mod tests;
