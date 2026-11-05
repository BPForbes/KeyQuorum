//! C export for the login / `su` / `sudo` access policy (`include/keyquorum_access.h`):
//! `kq_access_requirement`, over `keyquorum::access::requirement`. The rule is there; this
//! only reads the caller's strings and live bridges. Added in ABI version 4.

use super::input;
#[allow(unused_imports)]
use crate::nostd::*;
use core::ffi::{c_char, c_int};
use keyquorum::access::{self, AccessPolicy, BridgeFact, Factor};

/// A live private bridge, as the caller's store lists it: its uid and its Member labels.
#[repr(C)]
pub struct KqBridge {
    pub uid: *const c_char,
    pub members: *const *const c_char,
    pub nmembers: usize,
}

pub const KQ_ACCESS_NONE: c_int = Factor::None as c_int;
pub const KQ_ACCESS_PASSWORD: c_int = Factor::Password as c_int;
pub const KQ_ACCESS_KQST_PASSWORD: c_int = Factor::KqstAndPassword as c_int;
pub const KQ_ACCESS_PASSWORD_BRIDGE_KQST: c_int = Factor::PasswordAndBridgeKqst as c_int;
pub const KQ_ACCESS_REFUSED: c_int = Factor::Refused as c_int;
/// A bad argument (null, not UTF-8, too many bridges or members). Treat as refused.
pub const KQ_ACCESS_INVALID: c_int = -1;

const MAX_BRIDGES: usize = 64;
const MAX_MEMBERS: usize = 256;

/// What a switch from `current` to `target` demands, as one of the `KQ_ACCESS_*` factors, or
/// `KQ_ACCESS_INVALID` for a bad argument (nothing is granted by a bad call: both outputs
/// are set to their refusing values, -1 and 0). `sudo` non-zero asks for Root's key.
/// `live_bridges` are the `nbridges` private bridges the caller has checked live, Member
/// labels only. `*bridge_index_out` is the index of the bridge to cross when the factor is
/// `KQ_ACCESS_PASSWORD_BRIDGE_KQST`, else -1; `*needs_parent_grant_out` is 1 when
/// `parent_approval` is on and the switch asks for a factor under the same-branch or
/// cross-branch rules (never for `NONE`, `REFUSED`, Root or `sudo`).
///
/// # Safety
/// `current` and `target` NUL-terminated; `live_bridges` readable for `nbridges` structs
/// (null when 0), each with `members` readable for `nmembers` NUL-terminated strings;
/// both outputs null or writable.
#[no_mangle]
pub unsafe extern "C" fn kq_access_requirement(
    current: *const c_char,
    target: *const c_char,
    sudo: c_int,
    live_bridges: *const KqBridge,
    nbridges: usize,
    parent_approval: c_int,
    bridge_index_out: *mut c_int,
    needs_parent_grant_out: *mut c_int,
) -> c_int {
    let refuse = || {
        if !bridge_index_out.is_null() {
            *bridge_index_out = -1;
        }
        if !needs_parent_grant_out.is_null() {
            *needs_parent_grant_out = 0;
        }
        KQ_ACCESS_INVALID
    };
    let (Some(current), Some(target)) = (input(current), input(target)) else {
        return refuse();
    };
    if nbridges > MAX_BRIDGES || (nbridges > 0 && live_bridges.is_null()) {
        return refuse();
    }
    // Labels are borrowed from the caller's strings; the slices of them are ours.
    let mut label_lists: Vec<Vec<&str>> = Vec::new();
    let mut uids: Vec<&str> = Vec::new();
    for n in 0..nbridges {
        let bridge = &*live_bridges.add(n);
        let Some(uid) = input(bridge.uid) else {
            return refuse();
        };
        if bridge.nmembers > MAX_MEMBERS || (bridge.nmembers > 0 && bridge.members.is_null()) {
            return refuse();
        }
        let mut labels = Vec::new();
        for m in 0..bridge.nmembers {
            let Some(label) = input(*bridge.members.add(m)) else {
                return refuse();
            };
            labels.push(label);
        }
        uids.push(uid);
        label_lists.push(labels);
    }
    let facts: Vec<BridgeFact<'_>> = uids
        .iter()
        .zip(&label_lists)
        .map(|(uid, members)| BridgeFact { uid, members })
        .collect();
    let required = access::requirement(
        current,
        target,
        sudo != 0,
        &facts,
        &AccessPolicy {
            parent_approval: parent_approval != 0,
        },
    );
    if !bridge_index_out.is_null() {
        *bridge_index_out = required.bridge_index.map_or(-1, |i| i as c_int);
    }
    if !needs_parent_grant_out.is_null() {
        *needs_parent_grant_out = c_int::from(required.needs_parent_grant);
    }
    required.factor as c_int
}

#[cfg(test)]
#[path = "access/tests.rs"]
mod tests;
