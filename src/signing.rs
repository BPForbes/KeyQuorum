//! Ed25519 signatures. `verify_signature` is standalone. Producing a
//! signature still takes a private key the caller already holds (a file
//! or stdin) — this crate does not persist signing secrets.
//!
//! Private-bridge artifacts (`KQBS`) bind a bridge salt, a per-signature
//! salt, and both a shared bridge key and the signer's personal key.

use crate::crypto::{random_salt, SALT_LEN};
use crate::envelope::{
    hash_len_prefixed, push_len_prefixed, take_array, take_len_prefixed, take_n, take_u8, utf8,
};
use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const ARTIFACT_MAGIC: &[u8; 4] = b"KQBS";
const ARTIFACT_VERSION: u8 = 1;
const SIGN_DOMAIN: &[u8] = b"KQBRIDGE-SIGN-v1";
const FILE_REVISION_DOMAIN: &[u8] = b"KQ-FILE-REVISION-v1";
const FILE_COUNTERSIGN_DOMAIN: &[u8] = b"KQ-FILE-COUNTERSIGN-v1";
const FILE_FINALIZE_DOMAIN: &[u8] = b"KQ-FILE-FINALIZE-v1";
const FILE_HISTORY_EVENT_DOMAIN: &[u8] = b"KQ-FILE-HISTORY-EVENT-v1";
const FILE_BRIDGE_APPROVAL_DOMAIN: &[u8] = b"KQ-FILE-BRIDGE-APPROVAL-v1";
const RELAY_AUDIT_ANCHOR_DOMAIN: &[u8] = b"KQ-RELAY-AUDIT-ANCHOR-v1";
const RELAY_AUDIT_CHECKPOINT_DOMAIN: &[u8] = b"KQ-RELAY-AUDIT-CHECKPOINT-v1";
const RELAY_API_KEY_ISSUE_DOMAIN: &[u8] = b"KQ-RELAY-API-KEY-ISSUE-v1";

/// Verifies `signature` over `message` under `public_key`. Uses
/// `verify_strict` rather than `verify` — it rejects the non-canonical
/// signature malleability `verify` allows.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| Error::SignatureVerificationFailed)
}

/// Ed25519-sign `message` with a 32-byte seed. The caller supplies the
/// private key; nothing here writes it to disk.
pub fn sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(private_key);
    signing_key.sign(message).to_bytes()
}

/// Fields carried in a private-bridge signature artifact. Salts and the
/// signer pub are public; verification recomputes the domain-separated
/// preimage from them plus the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeSignature {
    pub uid: String,
    pub generation: u32,
    pub bridge_salt: [u8; SALT_LEN],
    pub signature_salt: [u8; SALT_LEN],
    pub signer_label: String,
    pub signer_public_key: [u8; 32],
    pub bridge_signature: [u8; 64],
    pub personal_signature: [u8; 64],
}

pub fn bridge_sign_preimage(
    uid: &str,
    generation: u32,
    bridge_salt: &[u8; SALT_LEN],
    signature_salt: &[u8; SALT_LEN],
    signer_label: &str,
    signer_public_key: &[u8; 32],
    message: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGN_DOMAIN);
    hasher.update(uid.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(bridge_salt);
    hasher.update(signature_salt);
    hasher.update(signer_label.as_bytes());
    hasher.update(signer_public_key);
    hasher.update(message);
    hasher.finalize().into()
}

/// Content signature over one tracked-file revision. Every field is fixed
/// width, so no field boundary can be read two ways. Sign the digest with
/// [`sign`] and check it with [`verify_signature`]; this only builds the
/// domain-separated preimage.
pub fn file_revision_preimage(
    file_id: &[u8; 16],
    revision_id: &[u8; 32],
    content_commitment: &[u8; 32],
    signer_identity: &[u8; 16],
    topology_generation: u64,
    policy_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FILE_REVISION_DOMAIN);
    hasher.update(file_id);
    hasher.update(revision_id);
    hasher.update(content_commitment);
    hasher.update(signer_identity);
    hasher.update(topology_generation.to_be_bytes());
    hasher.update(policy_hash);
    hasher.finalize().into()
}

/// Supervisor countersignature over a revision the author already signed.
/// `author_signature_hash` ties it to that exact author signature. The
/// supervisor's label is bound as well as the identity, because what makes a
/// countersignature acceptable is the label the supervisor holds; a proof
/// cannot be relabelled onto a different position without re-signing.
#[allow(clippy::too_many_arguments)] // every argument is a distinct signed field
pub fn file_countersign_preimage(
    file_id: &[u8; 16],
    revision_id: &[u8; 32],
    author: &[u8; 16],
    author_signature_hash: &[u8; 32],
    supervisor: &[u8; 16],
    supervisor_label: &str,
    topology_generation: u64,
    policy_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(FILE_COUNTERSIGN_DOMAIN);
    hasher.update(file_id);
    hasher.update(revision_id);
    hasher.update(author);
    hasher.update(author_signature_hash);
    hasher.update(supervisor);
    hash_len_prefixed(&mut hasher, supervisor_label.as_bytes())?;
    hasher.update(topology_generation.to_be_bytes());
    hasher.update(policy_hash);
    Ok(hasher.finalize().into())
}

/// Finalization of a revision by the scope owner or an ancestor: a
/// deliberate act, separate from the revision being trusted. The finalizer's
/// label is bound as well as the identity, for the same reason as in a
/// countersignature.
pub fn file_finalize_preimage(
    file_id: &[u8; 16],
    revision_id: &[u8; 32],
    finalizer: &[u8; 16],
    finalizer_label: &str,
    topology_generation: u64,
    policy_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(FILE_FINALIZE_DOMAIN);
    hasher.update(file_id);
    hasher.update(revision_id);
    hasher.update(finalizer);
    hash_len_prefixed(&mut hasher, finalizer_label.as_bytes())?;
    hasher.update(topology_generation.to_be_bytes());
    hasher.update(policy_hash);
    Ok(hasher.finalize().into())
}

/// What a private bridge signs to approve one tracked revision: the file,
/// the revision, its author, the scope it is judged under, and the
/// generation and policy it was made under. Signed with
/// [`sign_with_bridge`], so the artifact names the bridge and never travels
/// in the file.
pub fn file_bridge_approval_preimage(
    file_id: &[u8; 16],
    revision_id: &[u8; 32],
    author_label: &str,
    scope_root: &str,
    topology_generation: u64,
    policy_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(FILE_BRIDGE_APPROVAL_DOMAIN);
    hasher.update(file_id);
    hasher.update(revision_id);
    hash_len_prefixed(&mut hasher, author_label.as_bytes())?;
    hash_len_prefixed(&mut hasher, scope_root.as_bytes())?;
    hasher.update(topology_generation.to_be_bytes());
    hasher.update(policy_hash);
    Ok(hasher.finalize().into())
}

/// Optional signature on a security-relevant history event. A missing
/// revision id is encoded as a `0` tag and a present one as `1 || id`, so
/// "no revision" can never collide with any revision id.
pub fn file_history_event_preimage(
    file_id: &[u8; 16],
    revision_id: Option<&[u8; 32]>,
    sequence: u64,
    previous_event_hash: &[u8; 32],
    event_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FILE_HISTORY_EVENT_DOMAIN);
    hasher.update(file_id);
    match revision_id {
        Some(id) => {
            hasher.update([1u8]);
            hasher.update(id);
        }
        None => hasher.update([0u8]),
    }
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_event_hash);
    hasher.update(event_hash);
    hasher.finalize().into()
}

/// What a relay signs to vouch for an audit chain: the table, how many rows
/// it covers, the chain head at that row, when it was signed, and the
/// certificate that names the signing key (so a key cannot be moved under
/// another certificate). Domain-separated from every other preimage.
pub fn relay_audit_anchor_preimage(
    table: &str,
    row_count: u64,
    head_hash: &[u8; 32],
    signed_at: &str,
    certificate: &[u8],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_AUDIT_ANCHOR_DOMAIN);
    hash_len_prefixed(&mut hasher, table.as_bytes())?;
    hasher.update(row_count.to_be_bytes());
    hasher.update(head_hash);
    hash_len_prefixed(&mut hasher, signed_at.as_bytes())?;
    hasher.update(Sha256::digest(certificate));
    Ok(hasher.finalize().into())
}

/// What a relay signs when it issues a customer API key sealed to that
/// customer (`api_key_delivery`): every field of the sealed payload, with
/// the certificate by digest as the audit anchors bind it, plus the
/// recipient's own X25519 public key, so a payload re-sealed to anyone else
/// fails. Absent optional fields hash as a zero presence byte, so no value
/// of one can pass for the absence of another.
#[allow(clippy::too_many_arguments)]
pub fn relay_api_key_issue_preimage(
    recipient_public_key: &[u8; 32],
    relay_url: &str,
    key_id: i64,
    scope: &str,
    token: &str,
    issued_at: &str,
    expires_at: Option<&str>,
    device_id: Option<&[u8; 16]>,
    certificate: &[u8],
    licence: Option<&str>,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_API_KEY_ISSUE_DOMAIN);
    hasher.update(recipient_public_key);
    hash_len_prefixed(&mut hasher, relay_url.as_bytes())?;
    hasher.update(key_id.to_be_bytes());
    hash_len_prefixed(&mut hasher, scope.as_bytes())?;
    hash_len_prefixed(&mut hasher, token.as_bytes())?;
    hash_len_prefixed(&mut hasher, issued_at.as_bytes())?;
    hash_optional(&mut hasher, expires_at.map(str::as_bytes))?;
    hash_optional(&mut hasher, device_id.map(|id| &id[..]))?;
    hasher.update(Sha256::digest(certificate));
    hash_optional(&mut hasher, licence.map(str::as_bytes))?;
    Ok(hasher.finalize().into())
}

fn hash_optional(hasher: &mut Sha256, field: Option<&[u8]>) -> Result<()> {
    match field {
        Some(bytes) => {
            hasher.update([1u8]);
            hash_len_prefixed(hasher, bytes)
        }
        None => {
            hasher.update([0u8]);
            Ok(())
        }
    }
}

/// What a relay signs for an audit checkpoint the operator keeps off the
/// relay: every table's row count and chain head, when it was taken, and
/// the certificate that names the signing key. Domain-separated from the
/// per-table anchor, so one can never pass for the other.
pub fn relay_audit_checkpoint_preimage(
    heads: &[(&str, u64, [u8; 32])],
    taken_at: &str,
    certificate: &[u8],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_AUDIT_CHECKPOINT_DOMAIN);
    hasher.update(
        u32::try_from(heads.len())
            .map_err(|_| Error::BundleFieldTooLarge)?
            .to_be_bytes(),
    );
    for (table, row_count, head_hash) in heads {
        hash_len_prefixed(&mut hasher, table.as_bytes())?;
        hasher.update(row_count.to_be_bytes());
        hasher.update(head_hash);
    }
    hash_len_prefixed(&mut hasher, taken_at.as_bytes())?;
    hasher.update(Sha256::digest(certificate));
    Ok(hasher.finalize().into())
}

pub fn sign_with_bridge(
    uid: &str,
    generation: u32,
    bridge_salt: &[u8; SALT_LEN],
    signer_label: &str,
    bridge_private_key: &[u8; 32],
    personal_private_key: &[u8; 32],
    message: &[u8],
) -> Result<BridgeSignature> {
    let signing_key = SigningKey::from_bytes(personal_private_key);
    let signer_public_key = signing_key.verifying_key().to_bytes();
    let signature_salt = random_salt();
    let preimage = bridge_sign_preimage(
        uid,
        generation,
        bridge_salt,
        &signature_salt,
        signer_label,
        &signer_public_key,
        message,
    );
    Ok(BridgeSignature {
        uid: uid.to_string(),
        generation,
        bridge_salt: *bridge_salt,
        signature_salt,
        signer_label: signer_label.to_string(),
        signer_public_key,
        bridge_signature: sign(bridge_private_key, &preimage),
        personal_signature: sign(personal_private_key, &preimage),
    })
}

pub fn verify_bridge_signature(
    artifact: &BridgeSignature,
    bridge_public_key: &[u8; 32],
    signer_public_key: &[u8; 32],
    message: &[u8],
) -> Result<()> {
    if artifact.signer_public_key != *signer_public_key {
        return Err(Error::SignatureVerificationFailed);
    }
    let preimage = bridge_sign_preimage(
        &artifact.uid,
        artifact.generation,
        &artifact.bridge_salt,
        &artifact.signature_salt,
        &artifact.signer_label,
        signer_public_key,
        message,
    );
    verify_signature(bridge_public_key, &preimage, &artifact.bridge_signature)?;
    verify_signature(signer_public_key, &preimage, &artifact.personal_signature)
}

pub fn encode_bridge_signature(artifact: &BridgeSignature) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(ARTIFACT_MAGIC);
    out.push(ARTIFACT_VERSION);
    push_len_prefixed(&mut out, artifact.uid.as_bytes())?;
    out.extend_from_slice(&artifact.generation.to_be_bytes());
    out.extend_from_slice(&artifact.bridge_salt);
    out.extend_from_slice(&artifact.signature_salt);
    push_len_prefixed(&mut out, artifact.signer_label.as_bytes())?;
    out.extend_from_slice(&artifact.signer_public_key);
    out.extend_from_slice(&artifact.bridge_signature);
    out.extend_from_slice(&artifact.personal_signature);
    Ok(out)
}

pub fn decode_bridge_signature(bytes: &[u8]) -> Result<BridgeSignature> {
    let mut data = bytes;
    if take_n(&mut data, 4)? != ARTIFACT_MAGIC {
        return Err(Error::InvalidBridgePackage);
    }
    if take_u8(&mut data)? != ARTIFACT_VERSION {
        return Err(Error::InvalidBridgePackage);
    }
    let uid = utf8(take_len_prefixed(&mut data)?)?;
    let generation = u32::from_be_bytes(take_array(&mut data)?);
    let bridge_salt = take_array(&mut data)?;
    let signature_salt = take_array(&mut data)?;
    let signer_label = utf8(take_len_prefixed(&mut data)?)?;
    let signer_public_key = take_array(&mut data)?;
    let bridge_signature = take_array(&mut data)?;
    let personal_signature = take_array(&mut data)?;
    if !data.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    Ok(BridgeSignature {
        uid,
        generation,
        bridge_salt,
        signature_salt,
        signer_label,
        signer_public_key,
        bridge_signature,
        personal_signature,
    })
}

#[cfg(test)]
#[path = "signing/tests.rs"]
mod tests;
