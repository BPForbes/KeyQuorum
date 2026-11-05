//! Password-based key derivation and symmetric encryption primitives shared
//! by the password vault and password-locked-file features, and the keyed
//! commitment that stands in for a hash of sensitive content.

use crate::error::Error;
#[allow(unused_imports)]
use crate::nostd::*;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use core::fmt;
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;
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

impl core::error::Error for DecryptError {}

/// Fills `dest` from the platform's random source, which is the one place this crate
/// reads entropy. Everything that needs randomness (salts, nonces, data keys, the
/// Shamir dealer, `ed25519-dalek` and `crypto_box` key generation) goes through it,
/// by [`fill_random`] or by [`os_rng`], which wraps it.
///
/// With the `host` feature it is the operating system's random source and panics if
/// that fails, as `rand` 0.8's `OsRng` did. Without it (a kernel build) the embedder
/// supplies the bytes through the C function `kq_platform_random` (see
/// `include/keyquorum_identity.h` in `ffi/identity` for its contract).
#[cfg(feature = "host")]
pub fn fill_random(dest: &mut [u8]) {
    use rand::rand_core::UnwrapErr;
    use rand::rngs::SysRng;
    use rand::Rng;
    UnwrapErr(SysRng).fill_bytes(dest);
}

#[cfg(not(feature = "host"))]
extern "C" {
    /// Supplied by the embedder. Writes `len` random bytes at `buf` and returns 0, or
    /// returns non-zero if it cannot. There is no fallback in this crate.
    fn kq_platform_random(buf: *mut u8, len: usize) -> core::ffi::c_int;
}

/// Without `host`: the embedder's entropy through `kq_platform_random`. Fails closed:
/// if the platform cannot supply entropy this panics rather than return weak bytes. In
/// the `ffi/identity` kernel build the panic handler runs (it calls the embedder's
/// `kq_platform_panic`, which never returns), so the call never returns to its caller.
#[cfg(not(feature = "host"))]
pub fn fill_random(dest: &mut [u8]) {
    if dest.is_empty() {
        return;
    }
    // SAFETY: `dest` is a valid, writable slice of exactly `dest.len()` bytes.
    let status = unsafe { kq_platform_random(dest.as_mut_ptr(), dest.len()) };
    assert!(status == 0, "the platform could not supply entropy");
}

/// [`fill_random`] as an RNG object, for the crates that take one: the Shamir dealer
/// (`blahaj` 0.7 takes a `rand` 0.10 `CryptoRng`), `ed25519-dalek` 3 (`rand_core` 0.10)
/// and `crypto_box` (`rand_core` 0.6). Infallible, like `fill_random`.
pub struct PlatformRng;

impl rand::rand_core::TryRng for PlatformRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        fill_random(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        fill_random(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        fill_random(dst);
        Ok(())
    }
}

impl rand::rand_core::TryCryptoRng for PlatformRng {}

impl rand_core::RngCore for PlatformRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        fill_random(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        fill_random(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill_random(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for PlatformRng {}

/// The platform's random source as an RNG object (see [`PlatformRng`]).
pub(crate) fn os_rng() -> PlatformRng {
    PlatformRng
}

/// Drawn directly into the array, with no zero-filled buffer, so a scanner
/// cannot mistake the buffer's initial value for a hard-coded salt.
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

#[cfg(all(test, feature = "host"))]
#[path = "crypto/tests.rs"]
mod tests;
