//! `KQST`: a slot token, the passphrase-wrapped secret keys of one identity. This is the
//! store-free part of `device`: sealing a token, and opening one with only the passphrase
//! and what the caller already knows about the slot (its label, its device id and its two
//! public keys). `device` reads and writes the token files and takes those expectations
//! from the container's signed `device.kq`; a caller with its own registry (an operating
//! system's public record per account) passes them directly, so `KQST` plus a passphrase
//! is enough, with no container, directory or database.
//!
//! The token is sealed to its device id, so a token whose id the caller does not know
//! cannot be opened. Layout: `magic(4) | version(1) | salt(16) | nonce(12) | AES-GCM(
//! label(len16) | device_id(16) | encryption_secret(32) | signing_secret(32))` under an
//! Argon2id key. It is not a sealed envelope: it has its own magic and version.

use crate::crypto::{self, NONCE_LEN, SALT_LEN};
use crate::envelope::{push_len_prefixed, take_array, take_len_prefixed, take_u8, utf8};
use crate::error::{Error, Result};
use crate::keys;
#[allow(unused_imports)]
use crate::nostd::*;
use crate::signing;
use zeroize::Zeroizing;

const TOKEN_MAGIC: &[u8; 4] = b"KQST";
const TOKEN_VERSION: u8 = 2;
pub const DEVICE_ID_LEN: usize = 16;

/// Secrets unwrapped from one slot. Dropped values are zeroized.
pub struct SlotSecrets {
    pub label: String,
    pub encryption_secret: Zeroizing<[u8; 32]>,
    pub signing_secret: Zeroizing<[u8; 32]>,
    pub encryption_public: [u8; 32],
    pub signing_public: [u8; 32],
}

pub fn seal_token(
    label: &str,
    device_id: &[u8; DEVICE_ID_LEN],
    encryption_secret: &[u8; 32],
    signing_secret: &[u8; 32],
    passphrase: &str,
) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(encode_token_plain(
        label,
        device_id,
        encryption_secret,
        signing_secret,
    )?);
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(passphrase, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plain);
    let mut bytes = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    bytes.extend_from_slice(TOKEN_MAGIC);
    bytes.push(TOKEN_VERSION);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}

/// Open a token: the passphrase must be right (`InvalidPassword` otherwise), and the label
/// and device id inside must be the expected ones and the public keys derived from the
/// secrets the expected ones (`InvalidSlot` otherwise). The one rule `device::open_slot_in`
/// and the C export share.
pub fn open_slot_token(
    token: &[u8],
    label: &str,
    passphrase: &str,
    expected_device_id: &[u8; DEVICE_ID_LEN],
    expected_signing_public: &[u8; 32],
    expected_encryption_public: &[u8; 32],
) -> Result<SlotSecrets> {
    let plain = decrypt_token(token, passphrase)?;
    let (token_label, token_device, encryption_secret, signing_secret) =
        decode_token_plain(&plain)?;
    if token_label != label || token_device != *expected_device_id {
        return Err(Error::InvalidSlot);
    }
    let encryption_public = keys::encryption_public_from_secret(&encryption_secret);
    let signing_public = signing::public_key(&signing_secret);
    if encryption_public != *expected_encryption_public
        || signing_public != *expected_signing_public
    {
        return Err(Error::InvalidSlot);
    }
    Ok(SlotSecrets {
        label: label.to_string(),
        encryption_secret,
        signing_secret,
        encryption_public,
        signing_public,
    })
}

fn decrypt_token(bytes: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < 4 + 1 + SALT_LEN + NONCE_LEN + 16 || &bytes[..4] != TOKEN_MAGIC {
        return Err(Error::InvalidDevice);
    }
    let mut data = &bytes[4..];
    let version = take_u8(&mut data)?;
    if version != TOKEN_VERSION {
        return Err(Error::InvalidDevice);
    }
    let salt: [u8; SALT_LEN] = take_array(&mut data)?;
    let nonce: [u8; NONCE_LEN] = take_array(&mut data)?;
    let key = crypto::derive_key(passphrase, &salt)?;
    crypto::decrypt(&key, &nonce, data).map_err(|_| Error::InvalidPassword)
}

fn encode_token_plain(
    label: &str,
    device_id: &[u8; DEVICE_ID_LEN],
    encryption: &[u8; 32],
    signing: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, label.as_bytes())?;
    out.extend_from_slice(device_id);
    out.extend_from_slice(encryption);
    out.extend_from_slice(signing);
    Ok(out)
}

type TokenPlain = (
    String,
    [u8; DEVICE_ID_LEN],
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

fn decode_token_plain(bytes: &[u8]) -> Result<TokenPlain> {
    let mut data = bytes;
    let label = utf8(take_len_prefixed(&mut data)?)?;
    let device_id = take_array(&mut data)?;
    let encryption = Zeroizing::new(take_array(&mut data)?);
    let signing = Zeroizing::new(take_array(&mut data)?);
    if !data.is_empty() {
        return Err(Error::InvalidDevice);
    }
    Ok((label, device_id, encryption, signing))
}

#[cfg(all(test, feature = "host"))]
#[path = "slot_token/tests.rs"]
mod tests;
