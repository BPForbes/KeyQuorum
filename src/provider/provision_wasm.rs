//! The operator console's exports (`console` feature, wasm32 only): make a
//! provider identity, and the backup keypair, in the browser with the crate's
//! own code, so the console can offer the files for download without the
//! operator running a command; and check a package against the pinned root
//! (`verify_package`) with the same code the native commands use. A result goes back as JSON holding the
//! same bytes the files would: the private keys as the hex text `root.key`,
//! `relay.key` and `backup.key` hold, the certificate and the package as
//! base64. The page downloads them and keeps nothing; nothing here reaches
//! a Worker, the relay or any network.

use super::provision::{provision, Spec};
use super::CAP_PROVIDER;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// `now_utc` is `YYYY-MM-DD HH:MM:SS`, from the page's clock.
#[wasm_bindgen]
pub fn provision_identity(
    provider_id: &str,
    serial: &str,
    expires_at: &str,
    now_utc: &str,
) -> Result<String, JsError> {
    let spec = Spec {
        provider_id,
        serial,
        issued_at: now_utc,
        expires_at,
        capabilities: CAP_PROVIDER,
        issuer_id: "KeyQuorumRoot",
    };
    let made = provision(&spec, now_utc).map_err(|err| JsError::new(&err.to_string()))?;
    let root_key = Zeroizing::new(hex::encode(&made.root_private_key[..]));
    let relay_key = Zeroizing::new(hex::encode(&made.relay_private_key[..]));
    let root_pub = hex::encode(made.root_public_key);
    let relay_pub = hex::encode(made.relay_public_key);
    let certificate_base64 = STANDARD.encode(&made.certificate);
    let package_base64 = STANDARD.encode(&made.package);
    to_json(&IdentityResult {
        root_key: &root_key,
        root_pub: &root_pub,
        relay_key: &relay_key,
        relay_pub: &relay_pub,
        certificate_base64: &certificate_base64,
        package_base64: &package_base64,
    })
}

/// The backup keypair `host backup keygen` makes: the public half is the
/// `BACKUP_RECIPIENT` deploy variable, the private half the only way to read
/// a backup (`host backup inspect|restore`), kept offline by the operator.
#[wasm_bindgen]
pub fn backup_keygen() -> Result<String, JsError> {
    let (secret, public) = crate::keys::generate_encryption_keypair();
    let backup_key = Zeroizing::new(hex::encode(&secret[..]));
    let backup_pub = hex::encode(public);
    to_json(&BackupResult {
        backup_key: &backup_key,
        backup_pub: &backup_pub,
    })
}

/// Checks a `.kqpkg` against the root this relay pins (`root_hex`, the
/// `pinned_root` the relay reports) at `now_utc` (`YYYY-MM-DD HH:MM:SS`), with
/// `package::public::verify`: signature, hashes, purpose, validity window,
/// signer and certificate, and that every sealed part is sealed to one
/// recipient. Nothing sealed is opened (the page holds no recipient key) and
/// no revocation list is applied here; the native command that installs the
/// package checks both. The result is public JSON.
#[wasm_bindgen]
pub fn verify_package(bytes: &[u8], root_hex: &str, now_utc: &str) -> Result<String, JsError> {
    let root: [u8; 32] = hex::decode(root_hex)
        .ok()
        .and_then(|raw| raw.try_into().ok())
        .ok_or_else(|| JsError::new("the pinned root is not a 64-character hex key"))?;
    let checked =
        crate::package::public::verify(bytes, &root, now_utc, &std::collections::HashSet::new())
            .map_err(|err| JsError::new(&err.to_string()))?;
    to_json(&checked)
}

/// The identity as the page receives it. The fields borrow the zeroized hex
/// strings, so serializing makes no owned copy of a private key besides the
/// returned JSON, which crosses into JavaScript and is out of this crate's
/// reach (the page wipes the byte buffers it makes from it on Clear).
#[derive(serde::Serialize)]
struct IdentityResult<'a> {
    root_key: &'a str,
    root_pub: &'a str,
    relay_key: &'a str,
    relay_pub: &'a str,
    certificate_base64: &'a str,
    package_base64: &'a str,
}

/// The backup keypair as the page receives it; see [`IdentityResult`].
#[derive(serde::Serialize)]
struct BackupResult<'a> {
    backup_key: &'a str,
    backup_pub: &'a str,
}

/// Serializes a result for the page; an error becomes a thrown JavaScript error.
fn to_json(value: &impl serde::Serialize) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(|err| JsError::new(&err.to_string()))
}
