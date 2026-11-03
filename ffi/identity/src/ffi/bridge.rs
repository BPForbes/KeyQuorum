//! C exports for a private-bridge proof without a database (`include/keyquorum_bridge.h`):
//! `kq_bridge_prove` (a bridge member signs a challenge) and `kq_bridge_verify` (check it
//! against the live bridge's facts the caller holds). The rules are
//! `keyquorum::bridge_proof`, the same functions the host's `sign_message` and
//! `verify_message` call. Whether a bridge's ends reach an actor and a scope is
//! `kq_bridge_connects`, in `keyquorum_identity.h`.

use super::files::{buf_out, slice_in};
use super::{bytes_in, input};
#[allow(unused_imports)]
use crate::nostd::*;
use core::ffi::{c_char, c_int};
use keyquorum::bridge_proof::{self, BridgeFacts, LocalMember, MemberFact, SealedBridgeKey};
use keyquorum::error::Error;
use keyquorum::signing;
use zeroize::Zeroizing;

/// The proof was produced, or verified.
pub const KQ_BRIDGE_OK: c_int = 0;
/// A bad argument or an artifact that does not decode.
pub const KQ_BRIDGE_INVALID: c_int = -1;
/// The output buffer is too small; `*artifact_len` is the size needed.
pub const KQ_BRIDGE_NO_ROOM: c_int = -3;
/// Refused: not a member, a key or signature that does not match.
pub const KQ_BRIDGE_REFUSED: c_int = -5;
/// Refused: the artifact is from another generation, salt or bridge, or the bridge is gone.
pub const KQ_BRIDGE_STALE: c_int = -6;

const MAX_MEMBERS: usize = 256;

fn refusal(err: &Error) -> c_int {
    match err {
        Error::BridgeGenerationMismatch | Error::BridgeDestroyed => KQ_BRIDGE_STALE,
        _ => KQ_BRIDGE_REFUSED,
    }
}

fn status_of_buf(rc: c_int) -> c_int {
    match rc {
        0 => KQ_BRIDGE_OK,
        -3 => KQ_BRIDGE_NO_ROOM,
        _ => KQ_BRIDGE_INVALID,
    }
}

/// Signs `challenge` as bridge member `local_label`: unseals the member's bridge key
/// (`sealed_bridge_key` with its `wrap_salt`) with `encryption_sk`, and signs with it and
/// `signing_sk`. The roster facts of a prover are its own keys, so what is checked is that
/// the sealed key opens with this encryption secret, that the secret it holds is the
/// bridge's (`bridge_public`), and that the bridge is live. The artifact
/// (`signing::encode_bridge_signature`) goes to `artifact_out`.
///
/// # Safety
/// `uid`, `local_label` NUL-terminated; `salt` and `wrap_salt` readable for 16 bytes;
/// `bridge_public`, `encryption_sk`, `signing_sk` for 32; `sealed_bridge_key` for `slen`;
/// `challenge` for `clen`; `artifact_out` null or writable for `cap`; `artifact_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_bridge_prove(
    uid: *const c_char,
    generation: u32,
    salt: *const u8,
    bridge_public: *const u8,
    local_label: *const c_char,
    sealed_bridge_key: *const u8,
    slen: usize,
    wrap_salt: *const u8,
    encryption_sk: *const u8,
    signing_sk: *const u8,
    challenge: *const u8,
    clen: usize,
    artifact_out: *mut u8,
    cap: usize,
    artifact_len: *mut usize,
) -> c_int {
    let (
        Some(uid),
        Some(salt),
        Some(bridge_public),
        Some(label),
        Some(sealed),
        Some(wrap_salt),
        Some(encryption_sk),
        Some(signing_sk),
        Some(challenge),
    ) = (
        input(uid),
        bytes_in::<16>(salt),
        bytes_in::<32>(bridge_public),
        input(local_label),
        slice_in(sealed_bridge_key, slen),
        bytes_in::<16>(wrap_salt),
        bytes_in::<32>(encryption_sk).map(Zeroizing::new),
        bytes_in::<32>(signing_sk).map(Zeroizing::new),
        slice_in(challenge, clen),
    )
    else {
        return KQ_BRIDGE_INVALID;
    };
    let members = [MemberFact {
        label,
        signing_public: Some(signing::public_key(&signing_sk)),
    }];
    let facts = BridgeFacts {
        uid,
        generation,
        salt,
        bridge_public,
        destroyed: false,
        members: &members,
    };
    let local = LocalMember {
        encryption_public: keyquorum::keys::encryption_public_from_secret(&encryption_sk),
        holds_sealed_key: true,
    };
    let held = SealedBridgeKey {
        sealed: sealed.to_vec(),
        wrap_salt,
    };
    let proof = match bridge_proof::prove(
        &facts,
        label,
        &local,
        held,
        &encryption_sk,
        &signing_sk,
        challenge,
    ) {
        Ok(proof) => proof,
        Err(err) => return refusal(&err),
    };
    match signing::encode_bridge_signature(&proof) {
        Ok(bytes) => status_of_buf(buf_out(&bytes, artifact_out, cap, artifact_len)),
        Err(_) => KQ_BRIDGE_INVALID,
    }
}

/// Verifies `artifact` against the live bridge `uid`, `generation`, `salt`, `bridge_public`
/// (`destroyed` non-zero for a bridge that is gone) whose Member roster is `nmembers`
/// labels (`member_labels`, NUL-terminated strings) with their signing keys
/// (`member_signing_pubs`, 32 bytes each, in the same order): the artifact must be from
/// this generation and salt, its signer and `verifier_label` must be members, and both
/// signatures must verify over `challenge`. `KQ_BRIDGE_OK`, `KQ_BRIDGE_STALE` or
/// `KQ_BRIDGE_REFUSED`; `KQ_BRIDGE_INVALID` for a bad argument or an undecodable artifact.
///
/// # Safety
/// Strings NUL-terminated; `salt` readable for 16 bytes; `bridge_public` for 32;
/// `member_labels` for `nmembers` pointers and `member_signing_pubs` for `nmembers * 32`;
/// `challenge` for `clen`; `artifact` for `alen`.
#[no_mangle]
pub unsafe extern "C" fn kq_bridge_verify(
    uid: *const c_char,
    generation: u32,
    salt: *const u8,
    bridge_public: *const u8,
    destroyed: c_int,
    member_labels: *const *const c_char,
    member_signing_pubs: *const u8,
    nmembers: usize,
    verifier_label: *const c_char,
    challenge: *const u8,
    clen: usize,
    artifact: *const u8,
    alen: usize,
) -> c_int {
    let (
        Some(uid),
        Some(salt),
        Some(bridge_public),
        Some(verifier),
        Some(challenge),
        Some(artifact),
    ) = (
        input(uid),
        bytes_in::<16>(salt),
        bytes_in::<32>(bridge_public),
        input(verifier_label),
        slice_in(challenge, clen),
        slice_in(artifact, alen),
    )
    else {
        return KQ_BRIDGE_INVALID;
    };
    if nmembers > MAX_MEMBERS
        || (nmembers > 0 && (member_labels.is_null() || member_signing_pubs.is_null()))
    {
        return KQ_BRIDGE_INVALID;
    }
    let mut members = Vec::new();
    for n in 0..nmembers {
        let (Some(label), Some(public)) = (
            input(*member_labels.add(n)),
            bytes_in::<32>(member_signing_pubs.add(n * 32)),
        ) else {
            return KQ_BRIDGE_INVALID;
        };
        members.push(MemberFact {
            label,
            signing_public: Some(public),
        });
    }
    let Ok(artifact) = signing::decode_bridge_signature(artifact) else {
        return KQ_BRIDGE_INVALID;
    };
    let facts = BridgeFacts {
        uid,
        generation,
        salt,
        bridge_public,
        destroyed: destroyed != 0,
        members: &members,
    };
    match bridge_proof::verify(&facts, verifier, challenge, &artifact) {
        Ok(()) => KQ_BRIDGE_OK,
        Err(err) => refusal(&err),
    }
}

#[cfg(test)]
#[path = "bridge/tests.rs"]
mod tests;
