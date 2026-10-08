//! `.kqreq`, the enrollment request (`KQRQ` v1): the public half of a client's
//! identity, signed, for a provider to seal a package to (issue #104).
//!
//! A client who has no key from a provider yet cannot be sent one sealed,
//! because sealing needs the recipient's public key and device id first.
//! `keyquorum setup --enroll-out` writes this file once the drive identity
//! exists: the container's device id, the slot's label and its encryption and
//! signing public keys, signed with the slot's signing key. It holds no
//! secret, a bearer or a passphrase, so it may travel by any channel; what it
//! cannot do is prove *who* sent it, so the provider compares its
//! [`Request::fingerprint`] with the client out of band before issuing.
//!
//! The signature shows the sender holds the signing key whose public half is
//! in the file, and that the file was not altered; nothing more. It is not a
//! sealed envelope and has its own magic. Layout, big-endian: `"KQRQ" version
//! device_id[16] created_at(u64) label(u16 len) encryption_public[32]
//! signing_public[32] signature[64]`; the signature covers [`DOMAIN`] and the
//! SHA-256 of every byte before it.

use crate::envelope::{push_len_prefixed, take_array, take_len_prefixed, take_u8, utf8};
use crate::error::{Error, Result};
use crate::signing;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"KQRQ";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"KQ-ENROLLMENT-v1";
const SIG_LEN: usize = 64;
/// The most a request may hold, so a pasted or downloaded file is bounded.
pub const MAX_REQUEST_BYTES: usize = 1024;
const MAX_LABEL_BYTES: usize = 128;

/// A decoded request whose signature verified under its own signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub device_id: [u8; 16],
    pub created_at: u64,
    pub label: String,
    pub encryption_public: [u8; 32],
    pub signing_public: [u8; 32],
}

fn digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&digest(body));
    message
}

fn body_of(request: &Request) -> Result<Vec<u8>> {
    if request.label.is_empty() || request.label.len() > MAX_LABEL_BYTES {
        return Err(Error::InvalidEnrollment);
    }
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.push(VERSION);
    body.extend_from_slice(&request.device_id);
    body.extend_from_slice(&request.created_at.to_be_bytes());
    push_len_prefixed(&mut body, request.label.as_bytes()).map_err(|_| Error::InvalidEnrollment)?;
    body.extend_from_slice(&request.encryption_public);
    body.extend_from_slice(&request.signing_public);
    Ok(body)
}

/// Encodes `request` and signs it with the slot's signing key, which must be
/// the private half of `request.signing_public`.
pub fn encode(request: &Request, signing_secret: &[u8; 32]) -> Result<Vec<u8>> {
    let public = ed25519_dalek::SigningKey::from_bytes(signing_secret)
        .verifying_key()
        .to_bytes();
    if public != request.signing_public {
        return Err(Error::InvalidEnrollment);
    }
    let mut out = body_of(request)?;
    let signature = signing::sign(signing_secret, &signed_message(&out));
    out.extend_from_slice(&signature);
    Ok(out)
}

/// Decodes and verifies a request. Refuses anything oversized, truncated,
/// padded, altered, signed by a different key than it names, or carrying a
/// weak encryption key a provider must never seal to.
pub fn decode(bytes: &[u8]) -> Result<Request> {
    let bad = |_| Error::InvalidEnrollment;
    if bytes.len() > MAX_REQUEST_BYTES || bytes.len() <= SIG_LEN {
        return Err(Error::InvalidEnrollment);
    }
    let (body, signature) = bytes.split_at(bytes.len() - SIG_LEN);
    let mut data = body;
    if take_array::<4>(&mut data).map_err(bad)? != *MAGIC
        || take_u8(&mut data).map_err(bad)? != VERSION
    {
        return Err(Error::InvalidEnrollment);
    }
    let device_id = take_array::<16>(&mut data).map_err(bad)?;
    let created_at = u64::from_be_bytes(take_array(&mut data).map_err(bad)?);
    let label = utf8(take_len_prefixed(&mut data).map_err(bad)?).map_err(bad)?;
    let encryption_public = take_array::<32>(&mut data).map_err(bad)?;
    let signing_public = take_array::<32>(&mut data).map_err(bad)?;
    if !data.is_empty() || label.is_empty() || label.len() > MAX_LABEL_BYTES {
        return Err(Error::InvalidEnrollment);
    }
    if crate::envelope::is_weak_x25519_public_key(&encryption_public) {
        return Err(Error::InvalidEnrollment);
    }
    let signature: [u8; SIG_LEN] = signature.try_into().map_err(|_| Error::InvalidEnrollment)?;
    signing::verify_signature(&signing_public, &signed_message(body), &signature)
        .map_err(|_| Error::InvalidEnrollment)?;
    Ok(Request {
        device_id,
        created_at,
        label,
        encryption_public,
        signing_public,
    })
}

/// Reads and verifies a request from `path`, never reading more than a
/// request can be.
pub fn decode_file(path: &std::path::Path) -> Result<Request> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::open(path)?, MAX_REQUEST_BYTES as u64 + 1),
        &mut bytes,
    )?;
    decode(&bytes)
}

impl Request {
    /// The provider's check that the file in hand is the one the client
    /// meant: `typed` is the fingerprint the client read out, in any case
    /// and spacing.
    pub fn confirm_fingerprint(&self, typed: &str) -> Result<()> {
        let want = hex::encode(digest(&body_of(self)?));
        let got: String = typed
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if got == want {
            Ok(())
        } else {
            Err(Error::EnrollmentFingerprintMismatch)
        }
    }

    /// What the provider and the client compare out of band: the SHA-256 of
    /// the request's body, in lowercase hex groups of eight.
    pub fn fingerprint(&self) -> Result<String> {
        let hash = hex::encode(digest(&body_of(self)?));
        Ok(hash
            .as_bytes()
            .chunks(8)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(" "))
    }
}

#[cfg(test)]
#[path = "enrollment/tests.rs"]
mod tests;
