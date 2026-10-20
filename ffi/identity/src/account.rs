//! Account keys for Flinstone: one Ed25519 signing key per account, kept
//! sealed under the account's password, and the bridge signatures made with
//! it.
//!
//! The primitives are KeyQuorum's own: Argon2id and AES-256-GCM from
//! [`keyquorum::crypto`], Ed25519 and the domain-separated bridge preimage
//! from [`keyquorum::signing`]. This module adds only the sealed-key layout
//! (`KQAK`, version 1), which is a password-wrapped key, not a sealed
//! envelope:
//!
//! ```text
//! "KQAK" | version (1) | salt (16) | nonce (12) | AES-256-GCM(secret) (48)
//! ```

use crate::heritage::{self, Relation};
use keyquorum::crypto::{self, NONCE_LEN, SALT_LEN};
use keyquorum::signing::{self, AccountBridgeRole};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"KQAK";
const VERSION: u8 = 1;
const SECRET_LEN: usize = 32;
/// AES-GCM adds a 16-byte tag to the 32-byte secret.
const CIPHERTEXT_LEN: usize = SECRET_LEN + 16;
/// Length of a sealed account key.
pub const SEALED_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;

/// Why a sealed key could not be opened.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Not a sealed account key of a known version.
    Malformed,
    /// The password is wrong, or the sealed key was changed.
    WrongPassword,
}

/// A new random signing key and its public key.
pub fn generate() -> (Zeroizing<[u8; SECRET_LEN]>, [u8; 32]) {
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    crypto::fill_random(&mut secret[..]);
    let public = signing::public_key(&secret);
    (secret, public)
}

/// The public key for `secret`.
pub fn public_key(secret: &[u8; SECRET_LEN]) -> [u8; 32] {
    signing::public_key(secret)
}

/// A new random X25519 box key and its public key: what senders seal file
/// letters to. Sealed under the password the same way as the signing key.
pub fn generate_box() -> (Zeroizing<[u8; SECRET_LEN]>, [u8; 32]) {
    keyquorum::keys::generate_encryption_keypair()
}

/// The X25519 public key for a box `secret`.
pub fn box_public_key(secret: &[u8; SECRET_LEN]) -> [u8; 32] {
    keyquorum::keys::encryption_public_from_secret(secret)
}

/// Seals `secret` under `password`. Fails only if key derivation fails.
pub fn seal(password: &str, secret: &[u8; SECRET_LEN]) -> Option<Vec<u8>> {
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(password, &salt).ok()?;
    let ciphertext = crypto::encrypt(&key, &nonce, secret);
    let mut out = Vec::with_capacity(SEALED_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), SEALED_LEN);
    Some(out)
}

/// Opens a sealed key with `password`.
pub fn open(password: &str, sealed: &[u8]) -> Result<Zeroizing<[u8; SECRET_LEN]>, OpenError> {
    if sealed.len() != SEALED_LEN || &sealed[..4] != MAGIC || sealed[4] != VERSION {
        return Err(OpenError::Malformed);
    }
    let salt = &sealed[5..5 + SALT_LEN];
    let nonce: &[u8; NONCE_LEN] = sealed[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| OpenError::Malformed)?;
    let ciphertext = &sealed[5 + SALT_LEN + NONCE_LEN..];
    let key = crypto::derive_key(password, salt).map_err(|_| OpenError::Malformed)?;
    let plain = crypto::decrypt(&key, nonce, ciphertext).map_err(|_| OpenError::WrongPassword)?;
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    if plain.len() != SECRET_LEN {
        return Err(OpenError::Malformed);
    }
    secret.copy_from_slice(&plain);
    Ok(secret)
}

/// Whether `signer` may sign this half of a bridge between `from` and `to`:
/// all three are valid key ids, `from` and `to` are on different branches
/// (one line never needs a bridge), a request is signed by `from` itself, and
/// an acceptance by `to` or an ancestor of it.
pub fn signer_may_sign(role: AccountBridgeRole, from: &str, to: &str, signer: &str) -> bool {
    if !heritage::key_valid(from) || !heritage::key_valid(to) || !heritage::key_valid(signer) {
        return false;
    }
    if !matches!(
        heritage::relation(from, to),
        Relation::Sibling | Relation::OtherBranch
    ) {
        return false;
    }
    match role {
        AccountBridgeRole::Request => signer == from,
        AccountBridgeRole::Accept => heritage::is_ancestor_or_self(signer, to),
    }
}

/// Signs one half of a bridge between account labels `from` (who asked) and
/// `to` (who was asked), as `signer`, for the bridge identified by `nonce`.
/// `None` when `signer` may not sign that half ([`signer_may_sign`]) or a
/// label is too long to encode.
pub fn sign_bridge(
    role: AccountBridgeRole,
    from: &str,
    to: &str,
    signer: &str,
    nonce: &[u8; 16],
    secret: &[u8; SECRET_LEN],
) -> Option<[u8; 64]> {
    if !signer_may_sign(role, from, to, signer) {
        return None;
    }
    let digest = signing::account_bridge_preimage(role, from, to, signer, nonce).ok()?;
    Some(signing::sign(secret, &digest))
}

/// Whether `signature` is `signer`'s, under `public`, for that half of the
/// bridge, and `signer` may sign it ([`signer_may_sign`]). A valid signature
/// from an account that holds no such role never verifies.
pub fn verify_bridge(
    role: AccountBridgeRole,
    from: &str,
    to: &str,
    signer: &str,
    nonce: &[u8; 16],
    public: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    if !signer_may_sign(role, from, to, signer) {
        return false;
    }
    match signing::account_bridge_preimage(role, from, to, signer, nonce) {
        Ok(digest) => signing::verify_signature(public, &digest, signature).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
#[path = "account/tests.rs"]
mod tests;
