//! C exports for parent-key assembly (`include/keyquorum_assembly.h`): split a parent
//! account's signing seed among its children (`kq_assembly_split`) and assemble it again
//! from the children that are unlocked now (`kq_assembly_assemble`). The rules are
//! `keyquorum::assembly`, the same functions a host would call; this file only reads the
//! caller's arrays, bounds them and maps the errors to return codes.
//!
//! `keyquorum::assembly` needs `blahaj`, which the freestanding build does not link, so
//! this module exists in the hosted (`std`) build only (see `lib.rs`).

use super::files::{buf_out, slice_in};
use super::{bytes_in, input_bounded};
#[allow(unused_imports)]
use crate::nostd::*;
use core::ffi::{c_char, c_int, c_uint};
use keyquorum::assembly::{
    self, Assembly, ChildHolder, UnlockedChild, DEVICE_ID_LEN, MAX_HOLDERS, MAX_LABEL_LEN,
};
use keyquorum::error::Error;
use zeroize::Zeroizing;

/// Split or assembled.
pub const KQ_ASSEMBLY_OK: c_int = 0;
/// A bad argument, an assembly that does not decode, or children that cannot hold shares.
pub const KQ_ASSEMBLY_INVALID: c_int = -1;
/// The output buffer is too small; `*out_len` is the size needed.
pub const KQ_ASSEMBLY_NO_ROOM: c_int = -3;
/// Too few usable shares, or too few distinct devices.
pub const KQ_ASSEMBLY_QUORUM: c_int = -5;
/// The recovered seed is not the parent's.
pub const KQ_ASSEMBLY_MISMATCH: c_int = -6;
/// Split: no children, so no assembly (nothing written).
pub const KQ_ASSEMBLY_NONE: c_int = 1;

/// Largest assembly accepted from a caller: 255 holders, each a label and a sealed
/// share, with headroom for the header.
const MAX_ASSEMBLY_BYTES: usize = 8 + MAX_HOLDERS * (2 + MAX_LABEL_LEN + 2 + 33 + 48);

fn overlaps(a: *const u8, alen: usize, b: *const u8, blen: usize) -> bool {
    let (a, b) = (a as usize, b as usize);
    a < b.wrapping_add(blen) && b < a.wrapping_add(alen)
}

/// The threshold for `holders` children (1, 2, 2, 3, 3, 4, 5, 5, 6, 7 ... for 1, 2, 3 ...);
/// 0 for no holders or more than 255.
#[no_mangle]
pub extern "C" fn kq_assembly_threshold(holders: c_uint) -> c_uint {
    assembly::assembly_threshold(holders as usize).map_or(0, |t| t as c_uint)
}

/// Deals `seed` among `nchildren` children at `generation` and writes the `KQAS` bytes to
/// `out` when they fit; `*out_len` always gets the size. `KQ_ASSEMBLY_NONE` for no children
/// (nothing written). `KQ_ASSEMBLY_INVALID` for a null or overlapping pointer, more than
/// 255 children, a repeated or empty label, or a weak public key.
///
/// # Safety
/// `seed` readable for 32 bytes; `child_labels` for `nchildren` pointers to NUL-terminated
/// strings; `child_box_public` for `nchildren * 32` bytes; `out` writable for `cap` bytes;
/// `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_assembly_split(
    seed: *const u8,
    generation: c_uint,
    child_labels: *const *const c_char,
    child_box_public: *const [u8; 32],
    nchildren: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    if seed.is_null() || out_len.is_null() || nchildren > MAX_HOLDERS {
        return KQ_ASSEMBLY_INVALID;
    }
    if nchildren == 0 {
        return KQ_ASSEMBLY_NONE;
    }
    if child_labels.is_null() || child_box_public.is_null() {
        return KQ_ASSEMBLY_INVALID;
    }
    if overlaps(out_len.cast(), core::mem::size_of::<usize>(), seed, 32)
        || (!out.is_null()
            && (overlaps(out, cap, seed, 32)
                || overlaps(out, cap, child_box_public.cast(), nchildren * 32)
                || overlaps(out, cap, out_len.cast(), core::mem::size_of::<usize>())))
    {
        return KQ_ASSEMBLY_INVALID;
    }
    let Some(seed) = bytes_in::<32>(seed).map(Zeroizing::new) else {
        return KQ_ASSEMBLY_INVALID;
    };
    let mut children = Vec::with_capacity(nchildren);
    for n in 0..nchildren {
        let Some(label) = input_bounded(*child_labels.add(n), MAX_LABEL_LEN) else {
            return KQ_ASSEMBLY_INVALID;
        };
        children.push(ChildHolder {
            label,
            encryption_public: *child_box_public.add(n),
        });
    }
    match assembly::split_parent_key(&seed, &children, generation).and_then(|a| match a {
        Some(a) => a.encode().map(Some),
        None => Ok(None),
    }) {
        Ok(Some(bytes)) => match buf_out(&bytes, out, cap, out_len) {
            0 => KQ_ASSEMBLY_OK,
            -3 => KQ_ASSEMBLY_NO_ROOM,
            _ => KQ_ASSEMBLY_INVALID,
        },
        Ok(None) => KQ_ASSEMBLY_NONE,
        Err(_) => KQ_ASSEMBLY_INVALID,
    }
}

/// Reads the generation of an encoded assembly into `*generation_out`.
///
/// # Safety
/// `assembly` readable for `alen` bytes; `generation_out` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_assembly_generation(
    assembly: *const u8,
    alen: usize,
    generation_out: *mut c_uint,
) -> c_int {
    if generation_out.is_null() {
        return KQ_ASSEMBLY_INVALID;
    }
    match assembly_in(assembly, alen) {
        Some(a) => {
            *generation_out = a.generation;
            KQ_ASSEMBLY_OK
        }
        None => KQ_ASSEMBLY_INVALID,
    }
}

/// # Safety
/// `p` null or readable for `len` bytes.
unsafe fn assembly_in(p: *const u8, len: usize) -> Option<Assembly> {
    if p.is_null() || len > MAX_ASSEMBLY_BYTES {
        return None;
    }
    Assembly::decode(slice_in(p, len)?).ok()
}

/// Assembles the parent's seed from the children unlocked now. Each child is its label, the
/// X25519 secret that opens its share and the 16-byte id of the device it sits on. The
/// threshold must be met from at least `minimum_devices` distinct devices (0 or 1 adds no
/// rule), and the seed must derive `parent_signing_public`. Writes 32 bytes to `seed_out`
/// (the caller wipes them) and nothing unless `KQ_ASSEMBLY_OK`.
///
/// # Safety
/// `assembly` readable for `alen`; `parent_signing_public` and `seed_out` for 32 bytes;
/// `unlocked_labels` for `nunlocked` pointers to NUL-terminated strings;
/// `unlocked_box_secret` for `nunlocked * 32` bytes; `unlocked_device_id` for
/// `nunlocked * 16` bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_assembly_assemble(
    assembly: *const u8,
    alen: usize,
    parent_signing_public: *const u8,
    unlocked_labels: *const *const c_char,
    unlocked_box_secret: *const [u8; 32],
    unlocked_device_id: *const [u8; DEVICE_ID_LEN],
    nunlocked: usize,
    minimum_devices: usize,
    seed_out: *mut u8,
) -> c_int {
    if seed_out.is_null()
        || nunlocked > MAX_HOLDERS
        || (nunlocked > 0
            && (unlocked_labels.is_null()
                || unlocked_box_secret.is_null()
                || unlocked_device_id.is_null()))
        || overlaps(seed_out, 32, assembly, alen)
        || overlaps(seed_out, 32, parent_signing_public, 32)
        || overlaps(seed_out, 32, unlocked_box_secret.cast(), nunlocked * 32)
        || overlaps(
            seed_out,
            32,
            unlocked_device_id.cast(),
            nunlocked * DEVICE_ID_LEN,
        )
    {
        return KQ_ASSEMBLY_INVALID;
    }
    let (Some(assembly), Some(expected)) = (
        assembly_in(assembly, alen),
        bytes_in::<32>(parent_signing_public),
    ) else {
        return KQ_ASSEMBLY_INVALID;
    };
    let mut unlocked = Vec::with_capacity(nunlocked);
    for n in 0..nunlocked {
        let Some(label) = input_bounded(*unlocked_labels.add(n), MAX_LABEL_LEN) else {
            return KQ_ASSEMBLY_INVALID;
        };
        unlocked.push(UnlockedChild {
            label,
            // Borrowed in place: no copy of the secret is made here.
            encryption_secret: &*unlocked_box_secret.add(n),
            device_id: *unlocked_device_id.add(n),
        });
    }
    match assembly::assemble_parent_key(&assembly, &unlocked, minimum_devices, &expected) {
        Ok(seed) => {
            core::ptr::copy_nonoverlapping(seed.as_ptr(), seed_out, 32);
            KQ_ASSEMBLY_OK
        }
        Err(Error::QuorumNotMet) => KQ_ASSEMBLY_QUORUM,
        Err(Error::IntegrityCheckFailed) => KQ_ASSEMBLY_MISMATCH,
        Err(_) => KQ_ASSEMBLY_INVALID,
    }
}

#[cfg(test)]
#[path = "assembly/tests.rs"]
mod tests;
