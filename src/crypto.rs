//! Password-based key derivation and symmetric encryption primitives shared
//! by the password vault and password-locked-file features, and the keyed
//! commitment that stands in for a hash of sensitive content.

use crate::error::Error;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::{Rng, RngExt};
use sha2::Sha256;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// AES-GCM authentication failure: either the key was wrong or the
/// ciphertext was tampered with. Deliberately carries no further detail.
#[derive(Debug)]
pub struct DecryptError;

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decryption failed: wrong key or corrupted ciphertext")
    }
}

impl std::error::Error for DecryptError {}

/// The operating system's random source. Panics if it fails, as `rand` 0.8's
/// `OsRng` did. Libraries that take a `rand_core` 0.6 RNG (`ed25519-dalek`,
/// `crypto_box`, the Shamir dealer) are given `rand_core::OsRng` instead,
/// which reads the same source.
fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Fills `dest` from the operating system's random source.
pub fn fill_random(dest: &mut [u8]) {
    os_rng().fill_bytes(dest);
}

/// A fresh salt from the operating system's random source. Drawn directly into
/// the array, with no zero-filled buffer, so a scanner cannot mistake the
/// buffer's initial value for a hard-coded salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    os_rng().random()
}

/// A fresh AES-GCM nonce from the operating system's random source (see
/// [`random_salt`]). Never reused: every encryption draws its own.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    os_rng().random()
}

/// Generates a random 256-bit data key for hardware-key-quorum file
/// encryption (as opposed to `derive_key`, which is password-based). The
/// returned buffer is zeroed on drop.
pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    fill_random(&mut key[..]);
    key
}

/// Argon2id parameters, pinned explicitly rather than via `Argon2::default()`
/// (they currently match that default) so a future upgrade of the `argon2`
/// crate can't silently change the parameters out from under
/// already-encrypted records.
fn argon2id() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("hard-coded Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Derives a 256-bit key from `password` and `salt` using Argon2id. The
/// returned buffer is zeroed on drop.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2id()
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(key)
}

/// Encrypts `plaintext` with AES-256-GCM under `key`/`nonce`. Infallible in
/// practice: with a correctly sized key and nonce the only failure mode is
/// a plaintext exceeding AES-GCM's ~64GiB limit, far beyond anything this
/// project encrypts in one call.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(<&Key<Aes256Gcm>>::from(key));
    cipher
        .encrypt(<&Nonce<_>>::from(nonce), plaintext)
        .expect("AES-256-GCM encryption should not fail for in-memory plaintext")
}

/// Decrypts `ciphertext` with AES-256-GCM under `key`/`nonce`. Fails (and
/// must be allowed to fail) whenever the key is wrong or the ciphertext
/// has been tampered with — the AEAD authentication tag is what actually
/// detects an incorrect password. The plaintext is zeroed when dropped.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    let cipher = Aes256Gcm::new(<&Key<Aes256Gcm>>::from(key));
    cipher
        .decrypt(<&Nonce<_>>::from(nonce), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| DecryptError)
}

/// A keyed commitment to sensitive content: HMAC-SHA256 under `key`, over
/// the length-prefixed `domain` and then `data`.
///
/// Protected content (a file's plaintext, a tracked container that holds it)
/// is never hashed bare: a plain SHA-256 of it is a fingerprint anyone holding
/// the digest could confirm a guess against. Under a random key that travels
/// only inside the sealed letter, the commitment proves to the two parties
/// that they hold the same bytes and tells anyone else nothing. Compare two
/// commitments only with [`commitments_match`].
pub fn commit(key: &[u8; KEY_LEN], domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(
        &u32::try_from(domain.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    mac.update(domain);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Whether two commitments are the same, in constant time. This is the only
/// answer a caller gets about committed content: a yes or a no.
pub fn commitments_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
#[path = "crypto/tests.rs"]
mod tests;
