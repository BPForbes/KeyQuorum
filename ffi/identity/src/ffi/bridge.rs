//! C exports for a private-bridge proof without a database
//! (`include/keyquorum_bridge.h`): `kq_bridge_prove` (a bridge member signs a
//! challenge) and `kq_bridge_verify` (check it against the live bridge's facts
//! the caller holds). The rules are `keyquorum::bridge_proof`, the same
//! functions the host's `sign_message` and `verify_message` call. Whether a
//! bridge's ends reach an actor and a scope is `kq_bridge_connects`, in
//! `keyquorum_identity.h`.

use super::files::{buf_out, slice_in};
use super::{bytes_in, input};
#[allow(unused_imports)]
use crate::nostd::*;
use core::ffi::{c_char, c_int};
use keyquorum::bridge_proof::{self, BridgeFacts, LocalMember, MemberFact, SealedBridgeKey};
use keyquorum::error::Error;
use keyquorum::signing::{self, BridgeSignature};
use zeroize::Zeroizing;

/// The proof was produced, or verified.
pub const KQ_BRIDGE_OK: c_int = 0;
/// A bad argument or an artifact that does not decode.
pub const KQ_BRIDGE_INVALID: c_int = -1;
/// The output buffer is too small; `*artifact_len` is the size needed.
pub const KQ_BRIDGE_NO_ROOM: c_int = -3;
/// Refused: not a member, a key or signature that does not match.
pub const KQ_BRIDGE_REFUSED: c_int = -5;
/// Refused: the artifact is from another generation, salt or bridge, or the
/// bridge is gone.
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

/// The roster the caller passed: `nmembers` labels with their 32-byte signing
/// keys.
///
/// # Safety
/// `member_labels` must be null or readable for `nmembers` pointers to
/// NUL-terminated strings, and `member_signing_pubs` null or readable for
/// `nmembers * 32` bytes.
unsafe fn members_in<'a>(
    member_labels: *const *const c_char,
    member_signing_pubs: *const u8,
    nmembers: usize,
) -> Option<Vec<MemberFact<'a>>> {
    if nmembers > MAX_MEMBERS
        || (nmembers > 0 && (member_labels.is_null() || member_signing_pubs.is_null()))
    {
        return None;
    }
    (0..nmembers)
        .map(|n| {
            Some(MemberFact {
                label: input(*member_labels.add(n))?,
                signing_public: Some(bytes_in::<32>(member_signing_pubs.add(n * 32))?),
            })
        })
        .collect()
}

struct Prover<'a> {
    uid: &'a str,
    generation: u32,
    salt: [u8; 16],
    bridge_public: [u8; 32],
    label: &'a str,
    sealed: &'a [u8],
    wrap_salt: [u8; 16],
    encryption_sk: &'a [u8; 32],
    signing_sk: &'a [u8; 32],
    challenge: &'a [u8],
}

impl Prover<'_> {
    fn proof(&self) -> Result<BridgeSignature, Error> {
        let members = [MemberFact {
            label: self.label,
            signing_public: Some(signing::public_key(self.signing_sk)),
        }];
        let facts = BridgeFacts {
            uid: self.uid,
            generation: self.generation,
            salt: self.salt,
            bridge_public: self.bridge_public,
            destroyed: false,
            members: &members,
        };
        let local = LocalMember {
            encryption_public: keyquorum::keys::encryption_public_from_secret(self.encryption_sk),
            holds_sealed_key: true,
        };
        let held = SealedBridgeKey {
            sealed: self.sealed.to_vec(),
            wrap_salt: self.wrap_salt,
        };
        bridge_proof::prove(
            &facts,
            self.label,
            &local,
            held,
            self.encryption_sk,
            self.signing_sk,
            self.challenge,
        )
    }
}

type Secret = Zeroizing<[u8; 32]>;

/// The prover's two 32-byte secrets, zeroized on drop.
///
/// # Safety
/// Each pointer must be null or readable for 32 bytes.
unsafe fn secrets_in(encryption_sk: *const u8, signing_sk: *const u8) -> Option<(Secret, Secret)> {
    Some((
        bytes_in::<32>(encryption_sk).map(Zeroizing::new)?,
        bytes_in::<32>(signing_sk).map(Zeroizing::new)?,
    ))
}

/// # Safety
/// `artifact_out` must be null or writable for `cap`; `artifact_len` writable.
unsafe fn artifact_out_of(
    proof: Result<BridgeSignature, Error>,
    artifact_out: *mut u8,
    cap: usize,
    artifact_len: *mut usize,
) -> c_int {
    let proof = match proof {
        Ok(proof) => proof,
        Err(err) => return refusal(&err),
    };
    match signing::encode_bridge_signature(&proof) {
        Ok(bytes) => status_of_buf(buf_out(&bytes, artifact_out, cap, artifact_len)),
        Err(_) => KQ_BRIDGE_INVALID,
    }
}

/// Signs `challenge` as bridge member `local_label`; the artifact
/// (`signing::encode_bridge_signature`) goes to `artifact_out`. See
/// `keyquorum_bridge.h`.
///
/// # Safety
/// `uid`, `local_label` NUL-terminated; `salt` and `wrap_salt` readable for 16
/// bytes; `bridge_public`, `encryption_sk`, `signing_sk` for 32;
/// `sealed_bridge_key` for `slen`; `challenge` for `clen`; `artifact_out` null
/// or writable for `cap`; `artifact_len` writable.
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
        Some((encryption_sk, signing_sk)),
        Some(challenge),
    ) = (
        input(uid),
        bytes_in::<16>(salt),
        bytes_in::<32>(bridge_public),
        input(local_label),
        slice_in(sealed_bridge_key, slen),
        bytes_in::<16>(wrap_salt),
        secrets_in(encryption_sk, signing_sk),
        slice_in(challenge, clen),
    )
    else {
        return KQ_BRIDGE_INVALID;
    };
    let prover = Prover {
        uid,
        generation,
        salt,
        bridge_public,
        label,
        sealed,
        wrap_salt,
        encryption_sk: &encryption_sk,
        signing_sk: &signing_sk,
        challenge,
    };
    artifact_out_of(prover.proof(), artifact_out, cap, artifact_len)
}

fn verify_status(
    facts: &BridgeFacts<'_>,
    verifier: &str,
    challenge: &[u8],
    artifact: &[u8],
) -> c_int {
    let Ok(artifact) = signing::decode_bridge_signature(artifact) else {
        return KQ_BRIDGE_INVALID;
    };
    match bridge_proof::verify(facts, verifier, challenge, &artifact) {
        Ok(()) => KQ_BRIDGE_OK,
        Err(err) => refusal(&err),
    }
}

/// Verifies `artifact` against the live bridge facts the caller passes
/// (`destroyed` non-zero for a bridge that is gone; the roster is `nmembers`
/// labels with 32-byte signing keys in the same order). See
/// `keyquorum_bridge.h`.
///
/// # Safety
/// Strings NUL-terminated; `salt` readable for 16 bytes; `bridge_public` for
/// 32; `member_labels` for `nmembers` pointers and `member_signing_pubs` for
/// `nmembers * 32`; `challenge` for `clen`; `artifact` for `alen`.
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
    let Some(members) = members_in(member_labels, member_signing_pubs, nmembers) else {
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
    verify_status(&facts, verifier, challenge, artifact)
}

#[cfg(test)]
#[path = "bridge/tests.rs"]
mod tests;
