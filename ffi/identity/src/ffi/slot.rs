//! C exports for sealing a slot token (`KQST`) and opening one with only its passphrase and
//! the facts the caller's own registry holds (`include/keyquorum_slots.h`). The rules are
//! `keyquorum::slot_token::seal_token` and `open_slot_token`, the same functions
//! `keyquorum-device` uses.

use super::{
    bytes_in, bytes_out, input, KQ_ACCOUNT_INVALID, KQ_ACCOUNT_NO_ROOM, KQ_ACCOUNT_OK,
    KQ_ACCOUNT_WRONG_PASSWORD,
};
use crate::heritage;
#[allow(unused_imports)]
use crate::nostd::*;
use core::ffi::{c_char, c_int};
use keyquorum::error::Error;
use keyquorum::{keys, signing, slot_token};
use zeroize::Zeroizing;

/// Opens the token `kqst` (`klen` bytes) for slot `label` with `passphrase`, expecting the
/// device id and the signing and encryption public keys `expected_*` (from the caller's
/// registry, never from the token). Writes the signing secret to `signing_secret_out` and
/// the encryption secret to `encryption_secret_out` (32 bytes each; the caller wipes them).
/// `KQ_ACCOUNT_OK`; `KQ_ACCOUNT_WRONG_PASSWORD` for a wrong passphrase;
/// `KQ_ACCOUNT_INVALID` for anything else (a malformed token, or a label, device id or
/// public key that does not match). Nothing is written unless it returns OK.
///
/// # Safety
/// `kqst` readable for `klen`; `label` and `passphrase` NUL-terminated; `expected_device_id`
/// readable for 16 bytes, the other `expected_*` and the `*_out` for 32.
#[no_mangle]
pub unsafe extern "C" fn kq_slot_open(
    kqst: *const u8,
    klen: usize,
    label: *const c_char,
    passphrase: *const c_char,
    expected_device_id: *const u8,
    expected_signing_pub: *const u8,
    expected_encryption_pub: *const u8,
    signing_secret_out: *mut u8,
    encryption_secret_out: *mut u8,
) -> c_int {
    let (Some(token), Some(label), Some(passphrase), Some(device), Some(signing), Some(encryption)) = (
        if kqst.is_null() {
            None
        } else {
            Some(core::slice::from_raw_parts(kqst, klen))
        },
        input(label),
        input(passphrase),
        bytes_in::<16>(expected_device_id),
        bytes_in::<32>(expected_signing_pub),
        bytes_in::<32>(expected_encryption_pub),
    ) else {
        return KQ_ACCOUNT_INVALID;
    };
    if signing_secret_out.is_null() || encryption_secret_out.is_null() {
        return KQ_ACCOUNT_INVALID;
    }
    // Overlapping 32-byte outs would let the second write clobber the first
    // while still returning OK.
    let sign_addr = signing_secret_out as usize;
    let enc_addr = encryption_secret_out as usize;
    if sign_addr < enc_addr.wrapping_add(32) && enc_addr < sign_addr.wrapping_add(32) {
        return KQ_ACCOUNT_INVALID;
    }
    match slot_token::open_slot_token(token, label, passphrase, &device, &signing, &encryption) {
        Ok(secrets) => {
            bytes_out(&*secrets.signing_secret, signing_secret_out);
            bytes_out(&*secrets.encryption_secret, encryption_secret_out);
            KQ_ACCOUNT_OK
        }
        Err(Error::InvalidPassword) => KQ_ACCOUNT_WRONG_PASSWORD,
        Err(_) => KQ_ACCOUNT_INVALID,
    }
}

/// Size of the token `kq_slot_seal` makes for a label of `label_len` bytes: the header
/// (magic, version, salt, nonce), the GCM tag and the sealed body (a `u16`-prefixed label,
/// the device id and the two 32-byte secrets).
pub const fn slot_token_len(label_len: usize) -> usize {
    4 + 1
        + keyquorum::crypto::SALT_LEN
        + keyquorum::crypto::NONCE_LEN
        + 16
        + 2
        + label_len
        + slot_token::DEVICE_ID_LEN
        + 32
        + 32
}

/// Seals an account's own keys into a slot token, so an embedder can give an account its
/// `KQST` without the `keyquorum-device` CLI and without changing the account's keys: the
/// 32-byte Ed25519 `signing_secret` and X25519 `encryption_secret` of the account `label`
/// (a valid key id), sealed with `passphrase` to the device `device_id`, written to
/// `token_out` (its length to `*token_len`), with the two public keys derived from the
/// secrets, which the caller records in its own registry and later passes to
/// `kq_slot_open`. `KQ_ACCOUNT_NO_ROOM` when `cap` is too small (`*token_len` then holds
/// the size needed); `KQ_ACCOUNT_INVALID` for an invalid label, an empty passphrase or a
/// null pointer. Nothing but `*token_len` is written unless it returns OK. The caller
/// wipes the secrets it passed.
///
/// # Safety
/// `label` and `passphrase` must be null or NUL-terminated; `device_id` must be null or
/// readable for 16 bytes and the two secrets for 32; `token_out` must be null or writable
/// for `cap` bytes; `token_len` must be null or writable; the two `*_public_out` must be
/// null or writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_slot_seal(
    label: *const c_char,
    passphrase: *const c_char,
    device_id: *const u8,
    signing_secret: *const u8,
    encryption_secret: *const u8,
    token_out: *mut u8,
    cap: usize,
    token_len: *mut usize,
    signing_public_out: *mut u8,
    encryption_public_out: *mut u8,
) -> c_int {
    let (Some(label), Some(passphrase), Some(device), Some(signing), Some(encryption)) = (
        input(label),
        input(passphrase),
        bytes_in::<16>(device_id),
        bytes_in::<32>(signing_secret).map(Zeroizing::new),
        bytes_in::<32>(encryption_secret).map(Zeroizing::new),
    ) else {
        return KQ_ACCOUNT_INVALID;
    };
    if !heritage::key_valid(label)
        || passphrase.is_empty()
        || token_out.is_null()
        || token_len.is_null()
        || signing_public_out.is_null()
        || encryption_public_out.is_null()
    {
        return KQ_ACCOUNT_INVALID;
    }
    let need = slot_token_len(label.len());
    if cap < need {
        *token_len = need;
        return KQ_ACCOUNT_NO_ROOM;
    }
    let Ok(token) = slot_token::seal_token(label, &device, &encryption, &signing, passphrase)
    else {
        return KQ_ACCOUNT_INVALID;
    };
    if token.len() != need {
        return KQ_ACCOUNT_INVALID;
    }
    bytes_out(&token, token_out);
    *token_len = token.len();
    bytes_out(&signing::public_key(&signing), signing_public_out);
    bytes_out(
        &keys::encryption_public_from_secret(&encryption),
        encryption_public_out,
    );
    KQ_ACCOUNT_OK
}

#[cfg(test)]
#[path = "slot/tests.rs"]
mod tests;
