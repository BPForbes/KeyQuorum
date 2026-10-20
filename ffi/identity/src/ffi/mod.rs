//! C ABI over [`crate::heritage`] and [`crate::account`]. See
//! `include/keyquorum_identity.h`.
//!
//! Return codes are shared by the functions that write a key id into a
//! caller buffer. Anything that is not valid UTF-8, or is a null pointer,
//! counts as an invalid key id.

use crate::account;
use crate::heritage::{self, ChildError, Relation};
use keyquorum::signing::AccountBridgeRole;
use std::ffi::{c_char, c_int, CStr};
use zeroize::Zeroizing;

/// The key id was written.
pub const KQ_HERITAGE_OK: c_int = 0;
/// An input is not a valid key id or name, or there is no parent.
pub const KQ_HERITAGE_INVALID: c_int = -1;
/// The result would be deeper than `KQ_HERITAGE_MAX_DEPTH`.
pub const KQ_HERITAGE_TOO_DEEP: c_int = -2;
/// The output buffer is null, zero-sized, or too small for the result.
pub const KQ_HERITAGE_NO_ROOM: c_int = -3;

/// Reads a NUL-terminated C string; `None` for null or invalid UTF-8.
///
/// # Safety
/// `p` must be null or point to a NUL-terminated string that stays valid
/// for the call.
unsafe fn input<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

/// Writes `value` and a terminator into `out` when it fits.
///
/// # Safety
/// `out` must be null or writable for `cap` bytes.
unsafe fn output(value: &str, out: *mut c_char, cap: usize) -> c_int {
    if out.is_null() || cap == 0 {
        return KQ_HERITAGE_NO_ROOM;
    }
    if value.len() >= cap {
        *out = 0;
        return KQ_HERITAGE_NO_ROOM;
    }
    std::ptr::copy_nonoverlapping(value.as_ptr(), out.cast::<u8>(), value.len());
    *out.add(value.len()) = 0;
    KQ_HERITAGE_OK
}

/// 1 when `name` is a valid segment (`[A-Za-z0-9_-]`, 1 to 31 characters).
///
/// # Safety
/// `name` must be null or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_segment_valid(name: *const c_char) -> c_int {
    input(name).is_some_and(heritage::segment_valid) as c_int
}

/// 1 when `name` may be given to a new account (a valid segment, not `Root`).
///
/// # Safety
/// `name` must be null or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_name_available(name: *const c_char) -> c_int {
    input(name).is_some_and(heritage::name_available) as c_int
}

/// 1 when `key` is `Root` or `Root` plus valid segments, at most eight deep.
///
/// # Safety
/// `key` must be null or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_key_valid(key: *const c_char) -> c_int {
    input(key).is_some_and(heritage::key_valid) as c_int
}

/// Number of segments in `key` (`Root` is 1); 0 for an invalid key id.
///
/// # Safety
/// `key` must be null or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_depth(key: *const c_char) -> usize {
    input(key).map_or(0, heritage::depth)
}

/// Writes `parent` + `.` + `name` into `out`.
///
/// # Safety
/// `parent` and `name` must be null or valid NUL-terminated strings; `out`
/// must be null or writable for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_child(
    parent: *const c_char,
    name: *const c_char,
    out: *mut c_char,
    cap: usize,
) -> c_int {
    let (Some(parent), Some(name)) = (input(parent), input(name)) else {
        return KQ_HERITAGE_INVALID;
    };
    match heritage::child(parent, name) {
        Ok(key) => output(&key, out, cap),
        Err(ChildError::Invalid) => KQ_HERITAGE_INVALID,
        Err(ChildError::TooDeep) => KQ_HERITAGE_TOO_DEEP,
    }
}

/// Writes the key id one level up into `out`. `KQ_HERITAGE_INVALID` for
/// `Root` or an invalid key id.
///
/// # Safety
/// `key` must be null or a valid NUL-terminated string; `out` must be null
/// or writable for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_parent(
    key: *const c_char,
    out: *mut c_char,
    cap: usize,
) -> c_int {
    match input(key).and_then(heritage::parent) {
        Some(parent) => output(&parent, out, cap),
        None => KQ_HERITAGE_INVALID,
    }
}

/// 1 when `a` is `b` or an ancestor of `b`.
///
/// # Safety
/// `a` and `b` must be null or valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_is_ancestor_or_self(
    a: *const c_char,
    b: *const c_char,
) -> c_int {
    match (input(a), input(b)) {
        (Some(a), Some(b)) => heritage::is_ancestor_or_self(a, b) as c_int,
        _ => 0,
    }
}

/// How `b` stands relative to `a`, as `fl_heritage_relation_t`
/// (`0` invalid, `1` self, `2` ancestor, `3` descendant, `4` sibling,
/// `5` other branch).
///
/// # Safety
/// `a` and `b` must be null or valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_relation(a: *const c_char, b: *const c_char) -> c_int {
    match (input(a), input(b)) {
        (Some(a), Some(b)) => heritage::relation(a, b) as u32 as c_int,
        _ => Relation::Invalid as u32 as c_int,
    }
}

/// Writes the home directory relative to the jail root: `home` for `Root`,
/// `home/Flinstone/Bob` for `Root.Flinstone.Bob`.
///
/// # Safety
/// `key` must be null or a valid NUL-terminated string; `out` must be null
/// or writable for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_heritage_home_rel(
    key: *const c_char,
    out: *mut c_char,
    cap: usize,
) -> c_int {
    match input(key).and_then(heritage::home_rel) {
        Some(home) => output(&home, out, cap),
        None => KQ_HERITAGE_INVALID,
    }
}

/// The account key call succeeded.
pub const KQ_ACCOUNT_OK: c_int = 0;
/// A pointer is null, a label is not valid UTF-8, or a sealed key is malformed.
pub const KQ_ACCOUNT_INVALID: c_int = -1;
/// The output buffer is too small for a sealed key.
pub const KQ_ACCOUNT_NO_ROOM: c_int = -3;
/// The password does not open the sealed key (or the sealed key was changed).
pub const KQ_ACCOUNT_WRONG_PASSWORD: c_int = -4;
/// Bridge signature role: the requesting account.
pub const KQ_ACCOUNT_BRIDGE_REQUEST: c_int = 1;
/// Bridge signature role: the account (or an ancestor of it) that accepts.
pub const KQ_ACCOUNT_BRIDGE_ACCEPT: c_int = 2;

fn bridge_role(role: c_int) -> Option<AccountBridgeRole> {
    match role {
        KQ_ACCOUNT_BRIDGE_REQUEST => Some(AccountBridgeRole::Request),
        KQ_ACCOUNT_BRIDGE_ACCEPT => Some(AccountBridgeRole::Accept),
        _ => None,
    }
}

/// Reads `N` bytes from `p`; `None` for null.
///
/// # Safety
/// `p` must be null or readable for `N` bytes.
unsafe fn bytes_in<const N: usize>(p: *const u8) -> Option<[u8; N]> {
    if p.is_null() {
        return None;
    }
    // Copied straight from the caller's bytes: no placeholder value is ever
    // created, so nothing constant can stand in for a key or nonce.
    std::slice::from_raw_parts(p, N).try_into().ok()
}

/// Writes `value` to `out`; false for null.
///
/// # Safety
/// `out` must be null or writable for `value.len()` bytes.
unsafe fn bytes_out(value: &[u8], out: *mut u8) -> bool {
    if out.is_null() {
        return false;
    }
    std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
    true
}

/// Generates an account signing key: 32 secret bytes into `secret_out` and
/// the 32-byte public key into `public_out`. The caller wipes `secret_out`.
///
/// # Safety
/// `secret_out` and `public_out` must be null or writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_account_keygen(secret_out: *mut u8, public_out: *mut u8) -> c_int {
    if secret_out.is_null() || public_out.is_null() {
        return KQ_ACCOUNT_INVALID;
    }
    let (secret, public) = account::generate();
    bytes_out(&secret[..], secret_out);
    bytes_out(&public, public_out);
    KQ_ACCOUNT_OK
}

/// Generates an account box key (X25519, what file letters are sealed to):
/// 32 secret bytes into `secret_out`, the public key into `public_out`. Seal
/// the secret with `kq_account_seal`; the caller wipes `secret_out`.
///
/// # Safety
/// `secret_out` and `public_out` must be null or writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_account_box_keygen(secret_out: *mut u8, public_out: *mut u8) -> c_int {
    if secret_out.is_null() || public_out.is_null() {
        return KQ_ACCOUNT_INVALID;
    }
    let (secret, public) = account::generate_box();
    bytes_out(&secret[..], secret_out);
    bytes_out(&public, public_out);
    KQ_ACCOUNT_OK
}

/// Writes the box public key for a 32-byte box secret into `public_out`.
///
/// # Safety
/// `secret` must be null or readable for 32 bytes; `public_out` must be null
/// or writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_account_box_public(secret: *const u8, public_out: *mut u8) -> c_int {
    let Some(secret) = bytes_in::<32>(secret).map(Zeroizing::new) else {
        return KQ_ACCOUNT_INVALID;
    };
    if bytes_out(&account::box_public_key(&secret), public_out) {
        KQ_ACCOUNT_OK
    } else {
        KQ_ACCOUNT_INVALID
    }
}

/// Writes the public key for a 32-byte secret into `public_out`.
///
/// # Safety
/// `secret` must be null or readable for 32 bytes; `public_out` must be null
/// or writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_account_public(secret: *const u8, public_out: *mut u8) -> c_int {
    let Some(secret) = bytes_in::<32>(secret).map(Zeroizing::new) else {
        return KQ_ACCOUNT_INVALID;
    };
    if bytes_out(&account::public_key(&secret), public_out) {
        KQ_ACCOUNT_OK
    } else {
        KQ_ACCOUNT_INVALID
    }
}

/// Seals a 32-byte secret under `password` into `out` (`KQ_ACCOUNT_SEALED_LEN`
/// bytes) and writes the length to `out_len`.
///
/// # Safety
/// `password` must be null or a valid NUL-terminated string; `secret` must be
/// null or readable for 32 bytes; `out` must be null or writable for `cap`
/// bytes; `out_len` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn kq_account_seal(
    password: *const c_char,
    secret: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(password), Some(secret)) = (input(password), bytes_in::<32>(secret)) else {
        return KQ_ACCOUNT_INVALID;
    };
    let secret = Zeroizing::new(secret);
    if out.is_null() || out_len.is_null() {
        return KQ_ACCOUNT_INVALID;
    }
    if cap < account::SEALED_LEN {
        return KQ_ACCOUNT_NO_ROOM;
    }
    let Some(sealed) = account::seal(password, &secret) else {
        return KQ_ACCOUNT_INVALID;
    };
    bytes_out(&sealed, out);
    *out_len = sealed.len();
    KQ_ACCOUNT_OK
}

/// Opens a sealed key with `password` and writes the 32-byte secret into
/// `secret_out`. The caller wipes `secret_out`.
///
/// # Safety
/// `password` must be null or a valid NUL-terminated string; `sealed` must be
/// null or readable for `len` bytes; `secret_out` must be null or writable for
/// 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_account_open(
    password: *const c_char,
    sealed: *const u8,
    len: usize,
    secret_out: *mut u8,
) -> c_int {
    let Some(password) = input(password) else {
        return KQ_ACCOUNT_INVALID;
    };
    if sealed.is_null() || secret_out.is_null() {
        return KQ_ACCOUNT_INVALID;
    }
    let sealed = std::slice::from_raw_parts(sealed, len);
    match account::open(password, sealed) {
        Ok(secret) => {
            bytes_out(&secret[..], secret_out);
            KQ_ACCOUNT_OK
        }
        Err(account::OpenError::WrongPassword) => KQ_ACCOUNT_WRONG_PASSWORD,
        Err(account::OpenError::Malformed) => KQ_ACCOUNT_INVALID,
    }
}

/// Signs one half of the bridge between `from` (who asked) and `to` (who was
/// asked), as `signer`, for the bridge with the 16-byte `nonce`; writes the
/// 64-byte signature into `sig_out`.
///
/// # Safety
/// The labels must be null or valid NUL-terminated strings; `nonce` must be
/// null or readable for 16 bytes, `secret` for 32; `sig_out` must be null or
/// writable for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_account_bridge_sign(
    role: c_int,
    from: *const c_char,
    to: *const c_char,
    signer: *const c_char,
    nonce: *const u8,
    secret: *const u8,
    sig_out: *mut u8,
) -> c_int {
    let (Some(role), Some(from), Some(to), Some(signer), Some(nonce), Some(secret)) = (
        bridge_role(role),
        input(from),
        input(to),
        input(signer),
        bytes_in::<16>(nonce),
        bytes_in::<32>(secret).map(Zeroizing::new),
    ) else {
        return KQ_ACCOUNT_INVALID;
    };
    match account::sign_bridge(role, from, to, signer, &nonce, &secret) {
        Some(sig) if bytes_out(&sig, sig_out) => KQ_ACCOUNT_OK,
        _ => KQ_ACCOUNT_INVALID,
    }
}

/// 1 when `sig` is `signer`'s signature, under the 32-byte `public` key, for
/// that half of the bridge; 0 otherwise (including any invalid input).
///
/// # Safety
/// The labels must be null or valid NUL-terminated strings; `nonce` must be
/// null or readable for 16 bytes, `public` for 32 and `sig` for 64.
#[no_mangle]
pub unsafe extern "C" fn kq_account_bridge_verify(
    role: c_int,
    from: *const c_char,
    to: *const c_char,
    signer: *const c_char,
    nonce: *const u8,
    public: *const u8,
    sig: *const u8,
) -> c_int {
    let (Some(role), Some(from), Some(to), Some(signer), Some(nonce), Some(public), Some(sig)) = (
        bridge_role(role),
        input(from),
        input(to),
        input(signer),
        bytes_in::<16>(nonce),
        bytes_in::<32>(public),
        bytes_in::<64>(sig),
    ) else {
        return 0;
    };
    account::verify_bridge(role, from, to, signer, &nonce, &public, &sig) as c_int
}

pub mod files;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
