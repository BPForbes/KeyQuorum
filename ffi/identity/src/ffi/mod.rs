//! C ABI over [`crate::heritage`]. See `include/keyquorum_identity.h`.
//!
//! Return codes are shared by the functions that write a key id into a
//! caller buffer. Anything that is not valid UTF-8, or is a null pointer,
//! counts as an invalid key id.

use crate::heritage::{self, ChildError, Relation};
use std::ffi::{c_char, c_int, CStr};

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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
