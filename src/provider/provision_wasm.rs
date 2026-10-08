//! The operator console's two exports (`console` feature, wasm32 only): make
//! a provider identity, and the backup keypair, in the browser with the
//! crate's own code, so the console can offer the files for download without
//! the operator running a command. A result goes back as JSON holding the
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
    let json = serde_json::json!({
        "root_key": *root_key,
        "root_pub": hex::encode(made.root_public_key),
        "relay_key": *relay_key,
        "relay_pub": hex::encode(made.relay_public_key),
        "certificate_base64": STANDARD.encode(&made.certificate),
        "package_base64": STANDARD.encode(&made.package),
    });
    Ok(json.to_string())
}

/// The backup keypair `host backup keygen` makes: the public half is the
/// `BACKUP_RECIPIENT` deploy variable, the private half the only way to read
/// a backup (`host backup inspect|restore`), kept offline by the operator.
#[wasm_bindgen]
pub fn backup_keygen() -> String {
    let (secret, public) = crate::keys::generate_encryption_keypair();
    let backup_key = Zeroizing::new(hex::encode(&secret[..]));
    serde_json::json!({
        "backup_key": *backup_key,
        "backup_pub": hex::encode(public),
    })
    .to_string()
}
