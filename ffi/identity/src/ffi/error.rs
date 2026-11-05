//! C exports for `KQER` error reports (`include/keyquorum_error.h`): the
//! static names of the closed code and class sets, signing a report, and
//! verifying a sidecar and appending its `ErrorReported` event to a tracked
//! file. The rules live in `keyquorum::error_report`; nothing here judges
//! anything.

use super::files::{buf_out, container_in, file_out, slice_in, KQ_FILE_INVALID};
use super::{bytes_in, input};
#[allow(unused_imports)]
use crate::nostd::*;
use core::ffi::{c_char, c_int};
use keyquorum::error_report::{self, Class, ErrorCode, Report};
use zeroize::Zeroizing;

/// The name of error code `code` ("Integrity", ...), a static NUL-terminated
/// string the caller never frees, or null for a code this build does not know.
#[no_mangle]
pub extern "C" fn kq_error_name(code: u16) -> *const c_char {
    ErrorCode::name_of(code).map_or(core::ptr::null(), |name| name.as_ptr())
}

/// The fixed word of error class `class` ("integrity", ...; the `error_class`
/// a history event records), or null for a class this build does not know.
#[no_mangle]
pub extern "C" fn kq_error_class_name(class: u8) -> *const c_char {
    Class::from_u8(class).map_or(core::ptr::null(), |class| {
        match class {
            Class::Framing => c"framing",
            Class::Auth => c"auth",
            Class::Integrity => c"integrity",
            Class::Freshness => c"freshness",
            Class::Policy => c"policy",
            Class::Storage => c"storage",
            Class::Resource => c"resource",
            Class::Internal => c"internal",
        }
        .as_ptr()
    })
}

/// The optional detail pair: none when both are null, `None` when only one is
/// usable.
///
/// # Safety
/// Each pointer must be null or a valid NUL-terminated string.
unsafe fn detail_in(key: *const c_char, value: *const c_char) -> Option<Vec<(String, String)>> {
    match (input(key), input(value)) {
        (Some(key), Some(value)) => Some(vec![(key.to_string(), value.to_string())]),
        _ if key.is_null() && value.is_null() => Some(Vec::new()),
        _ => None,
    }
}

/// Writes a signed `KQER` sidecar for a refused artifact. `object_ref` is the
/// SHA-256 of the artifact; `actor_label` the reporter's label; `occurred_at`
/// UTC text. `detail_key` and `detail_value` are one optional detail pair
/// (both null for none); the key must be one of `shares`, `threshold`,
/// `devices`, `minimum_devices`. Returns KQ_FILE_INVALID for anything
/// `keyquorum::error_report` refuses (free text, an unknown code or class).
///
/// # Safety
/// Pointers as documented in the header; `signing_secret` and `object_ref`
/// read 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_error_sign(
    code: u16,
    class: u8,
    step: u8,
    object_ref: *const u8,
    actor_label: *const c_char,
    occurred_at: *const c_char,
    detail_key: *const c_char,
    detail_value: *const c_char,
    signing_secret: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(object_ref), Some(secret), Some(label), Some(time)) = (
        bytes_in::<32>(object_ref),
        bytes_in::<32>(signing_secret).map(Zeroizing::new),
        input(actor_label),
        input(occurred_at),
    ) else {
        return KQ_FILE_INVALID;
    };
    let Some(detail) = detail_in(detail_key, detail_value) else {
        return KQ_FILE_INVALID;
    };
    let (Ok(code), Ok(class)) = (ErrorCode::from_u16(code), Class::from_u8(class)) else {
        return KQ_FILE_INVALID;
    };
    let report = Report {
        code,
        class,
        step,
        object_ref,
        actor_label: label.to_string(),
        occurred_at: time.to_string(),
        detail,
    };
    match error_report::encode_signed(&report, &secret) {
        Ok(bytes) => buf_out(&bytes, out, cap, out_len),
        Err(_) => KQ_FILE_INVALID,
    }
}

/// Verifies a `KQER` sidecar (the reporter's signature, and that it names the
/// package whose SHA-256 is `pkg_sha256`) and appends an `ErrorReported` event
/// to the tracked file, writing the changed container to `out`. KQ_FILE_OK, or
/// KQ_FILE_INVALID when the container, the sidecar, the signature or the
/// reference does not check out (nothing is written then).
///
/// # Safety
/// Pointers as documented in the header; `reporter_public` and `pkg_sha256`
/// read 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_error_inject(
    kqtf: *const u8,
    klen: usize,
    kqer: *const u8,
    elen: usize,
    reporter_public: *const u8,
    pkg_sha256: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(mut file), Some(sidecar), Some(public), Some(object_ref)) = (
        container_in(kqtf, klen),
        slice_in(kqer, elen),
        bytes_in::<32>(reporter_public),
        bytes_in::<32>(pkg_sha256),
    ) else {
        return KQ_FILE_INVALID;
    };
    if error_report::inject(&mut file, sidecar, &public, &object_ref).is_err() {
        return KQ_FILE_INVALID;
    }
    file_out(&file, out, cap, out_len)
}

#[cfg(test)]
#[path = "error/tests.rs"]
mod tests;
