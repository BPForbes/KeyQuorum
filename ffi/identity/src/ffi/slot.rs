//! C export for opening a slot token (`KQST`) with only its passphrase and the
//! facts the caller's own registry holds (`include/keyquorum_slots.h`). The
//! rule is `keyquorum::slot_token::open_slot_token`, the same function
//! `keyquorum-device` uses.

use super::{
    bytes_in, bytes_out, input, KQ_ACCOUNT_INVALID, KQ_ACCOUNT_OK, KQ_ACCOUNT_WRONG_PASSWORD,
};
#[allow(unused_imports)]
use crate::nostd::*;
use core::ffi::{c_char, c_int};
use keyquorum::error::Error;
use keyquorum::slot_token;

/// Opens the token `kqst` (`klen` bytes) for slot `label` with `passphrase`,
/// expecting the device id and the signing and encryption public keys
/// `expected_*` (from the caller's registry, never from the token). Writes the
/// signing secret to `signing_secret_out` and the encryption secret to
/// `encryption_secret_out` (32 bytes each; the caller wipes them).
/// `KQ_ACCOUNT_OK`; `KQ_ACCOUNT_WRONG_PASSWORD` for a wrong passphrase;
/// `KQ_ACCOUNT_INVALID` for anything else (a malformed token, or a label,
/// device id or public key that does not match). Nothing is written unless it
/// returns OK.
///
/// # Safety
/// `kqst` readable for `klen`; `label` and `passphrase` NUL-terminated;
/// `expected_device_id` readable for 16 bytes, the other `expected_*` and the
/// `*_out` for 32.
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

#[cfg(test)]
#[path = "slot/tests.rs"]
mod tests;
