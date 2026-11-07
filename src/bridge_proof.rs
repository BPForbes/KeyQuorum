//! A private-bridge proof without a database: what
//! `private_bridge::sign_message` and `verify_message` decide, with the facts
//! they read from SQLite passed in. `prove` shows that the holder of a bridge
//! member's keys is that member: it signs a challenge with the bridge secret
//! (unsealed from the member's sealed key) and the member's own signing key.
//! `verify` checks such an artifact against the live bridge. A caller with its
//! own account store (an operating system's) builds [`BridgeFacts`] from it;
//! the host functions in `private_bridge` build the same facts from the bridge
//! tables and call these, so there is one rule.
//!
//! Liveness is in the facts: `verify` refuses an artifact from another
//! generation or salt, a destroyed bridge, a signer or verifier that is not a
//! member, and a roster key that disagrees with the signature. Removing a
//! member bumps the generation, so crossing ends at once with no revocation
//! list. Whether two bridge ends reach an actor and a scope is
//! `authority::bridge_connects`, which judges the shape of the hierarchy only.

use crate::crypto::SALT_LEN;
use crate::envelope::is_weak_x25519_public_key;
use crate::error::{Error, Result};
use crate::keys;
#[allow(unused_imports)]
use crate::nostd::*;
use crate::signing::{self, BridgeSignature};
use zeroize::Zeroizing;

/// One member of the bridge's roster (Member role only; supervisors never
/// prove or verify).
#[derive(Clone, Copy, Debug)]
pub struct MemberFact<'a> {
    pub label: &'a str,
    /// The signing key the roster holds for this member, if it holds one.
    pub signing_public: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug)]
pub struct BridgeFacts<'a> {
    pub uid: &'a str,
    pub generation: u32,
    pub salt: [u8; SALT_LEN],
    pub bridge_public: [u8; 32],
    pub destroyed: bool,
    pub members: &'a [MemberFact<'a>],
}

#[derive(Clone, Copy, Debug)]
pub struct LocalMember {
    /// The X25519 public key the roster holds for the local member.
    pub encryption_public: [u8; 32],
    /// Whether this store holds that member's sealed bridge key.
    pub holds_sealed_key: bool,
}

pub struct SealedBridgeKey {
    pub sealed: Vec<u8>,
    pub wrap_salt: [u8; SALT_LEN],
}

/// Byte length of [`seal_bridge_secret`]: wrap salt + bridge secret, then the
/// `crypto_box` seal overhead. Anything else is refused before decrypt.
pub const SEALED_BRIDGE_KEY_LEN: usize = SALT_LEN + 32 + crypto_box::SEALBYTES;

/// Open a member's sealed bridge key with their X25519 secret: the plaintext
/// is the wrap salt followed by the bridge's secret key, and the salt must be
/// the stored one.
pub fn unseal_bridge_secret(
    sealed: &[u8],
    wrap_salt: &[u8; SALT_LEN],
    encryption_sk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    if sealed.len() != SEALED_BRIDGE_KEY_LEN {
        return Err(Error::IntegrityCheckFailed);
    }
    let secret_key = crypto_box::SecretKey::from(*encryption_sk);
    let plain = Zeroizing::new(
        secret_key
            .unseal(sealed)
            .map_err(|_| Error::IntegrityCheckFailed)?,
    );
    if plain.len() != SALT_LEN + 32 || plain[..SALT_LEN] != *wrap_salt {
        return Err(Error::IntegrityCheckFailed);
    }
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&plain[SALT_LEN..]);
    Ok(sk)
}

pub fn seal_bridge_secret(
    recipient_pub: &[u8; 32],
    wrap_salt: &[u8; SALT_LEN],
    secret: &[u8; 32],
) -> Result<Vec<u8>> {
    if is_weak_x25519_public_key(recipient_pub) {
        return Err(Error::InvalidPublicKey);
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(SALT_LEN + 32));
    plain.extend_from_slice(wrap_salt);
    plain.extend_from_slice(secret);
    Ok(crypto_box::PublicKey::from_bytes(*recipient_pub)
        .seal(&mut crate::crypto::os_rng(), &plain)
        .expect("crypto_box sealing should not fail for an in-memory secret"))
}

fn member<'a>(facts: &'a BridgeFacts<'_>, label: &str) -> Option<&'a MemberFact<'a>> {
    facts.members.iter().find(|m| m.label == label)
}

/// What `sign_message` does: the same checks, with the sealed bridge key
/// supplied instead of read from a table. `local_registry_check` is the
/// caller's extra check of the roster key against its own registry
/// (`private_bridge` compares with the registered key for the label), called
/// with the label and the roster key.
#[allow(clippy::too_many_arguments)]
pub fn prove_with(
    facts: &BridgeFacts<'_>,
    local_label: &str,
    local: &LocalMember,
    encryption_sk: &[u8; 32],
    signing_sk: &[u8; 32],
    challenge: &[u8],
    local_registry_check: impl FnOnce(&str, &[u8; 32]) -> Result<()>,
    load_sealed: impl FnOnce() -> Result<SealedBridgeKey>,
) -> Result<BridgeSignature> {
    if facts.destroyed {
        return Err(Error::BridgeDestroyed);
    }
    let roster = member(facts, local_label).ok_or(Error::NotBridgeMember)?;
    if !local.holds_sealed_key {
        return Err(Error::SealedKeyNotHeld);
    }
    if keys::encryption_public_from_secret(encryption_sk) != local.encryption_public {
        return Err(Error::IntegrityCheckFailed);
    }
    let roster_signing = roster.signing_public.ok_or(Error::InvalidBridge)?;
    if signing::public_key(signing_sk) != roster_signing {
        return Err(Error::IntegrityCheckFailed);
    }
    local_registry_check(local_label, &roster_signing)?;
    let held = load_sealed()?;
    let bridge_sk = unseal_bridge_secret(&held.sealed, &held.wrap_salt, encryption_sk)?;
    // The secret that was sealed to this member must be this bridge's.
    if signing::public_key(&bridge_sk) != facts.bridge_public {
        return Err(Error::IntegrityCheckFailed);
    }
    signing::sign_with_bridge(
        facts.uid,
        facts.generation,
        &facts.salt,
        local_label,
        &bridge_sk,
        signing_sk,
        challenge,
    )
}

pub fn prove(
    facts: &BridgeFacts<'_>,
    local_label: &str,
    local: &LocalMember,
    sealed: SealedBridgeKey,
    encryption_sk: &[u8; 32],
    signing_sk: &[u8; 32],
    challenge: &[u8],
) -> Result<BridgeSignature> {
    prove_with(
        facts,
        local_label,
        local,
        encryption_sk,
        signing_sk,
        challenge,
        |_, _| Ok(()),
        || Ok(sealed),
    )
}

/// What `verify_message` does: uid, generation and salt must be the LIVE
/// bridge's, the signer and the verifier must be members, the roster key must
/// verify the artifact. `signer_registry_check` is the same optional registry
/// comparison as in [`prove_with`].
pub fn verify_with(
    facts: &BridgeFacts<'_>,
    verifier_label: &str,
    challenge: &[u8],
    artifact: &BridgeSignature,
    signer_registry_check: impl FnOnce(&str, &[u8; 32]) -> Result<()>,
) -> Result<()> {
    if facts.destroyed {
        return Err(Error::BridgeDestroyed);
    }
    if artifact.uid != facts.uid
        || artifact.generation != facts.generation
        || artifact.bridge_salt != facts.salt
    {
        return Err(Error::BridgeGenerationMismatch);
    }
    let signer = member(facts, &artifact.signer_label).ok_or(Error::NotBridgeMember)?;
    if member(facts, verifier_label).is_none() {
        return Err(Error::NotBridgeMember);
    }
    let roster_signing = signer.signing_public.ok_or(Error::InvalidBridge)?;
    signer_registry_check(&artifact.signer_label, &roster_signing)?;
    signing::verify_bridge_signature(artifact, &facts.bridge_public, &roster_signing, challenge)
}

pub fn verify(
    facts: &BridgeFacts<'_>,
    verifier_label: &str,
    challenge: &[u8],
    artifact: &BridgeSignature,
) -> Result<()> {
    verify_with(facts, verifier_label, challenge, artifact, |_, _| Ok(()))
}

#[cfg(all(test, feature = "host"))]
#[path = "bridge_proof/tests.rs"]
mod tests;
