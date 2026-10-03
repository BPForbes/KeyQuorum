//! Requests for a file or for a change to it, and the holder's answers.
//!
//! A request letter is a [`PACKAGE`] envelope of kind
//! [`envelope::KIND_FILE_REQUEST`], sealed to the holder's registered
//! encryption key and signed by the requester's registered signing key. It
//! names the file (id and name), says whether the requester wants the file
//! itself ([`RequestKind::File`]) or a change to it ([`RequestKind::Change`],
//! with a short message and, optionally, the revision the message is about),
//! and carries the encryption key the answer is sealed back to.
//!
//! The holder answers with [`envelope::KIND_FILE_REQUEST_ANSWER`]: accept or
//! decline, signed by the holder and bound to the exact request by its
//! signed preimage hash. An answer does not deliver anything. Accepting a
//! file request is followed by `file share`, and accepting a change request
//! by the requester's revision reaching the holder as a merge proposal; a
//! request only asks.
//!
//! Like every other letter, both open functions check the signature against
//! the signing key *this store* has registered for the claimed label, never a
//! key the letter carries. The message is shown to the holder and never
//! recorded in a history.

use super::{open_kind, push_head, take_accepted, take_head, take_signature, verify_signed_by};
use crate::envelope::{
    self, hash_len_prefixed, push_len_prefixed, push_len_prefixed_u32, take_array,
    take_len_prefixed, take_len_prefixed_u32, take_u8, utf8, PACKAGE,
};
use crate::error::{Error, Result};
use crate::signing;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const REQUEST_DOMAIN: &[u8] = b"KQ-FILE-REQUEST-v1";
const ANSWER_DOMAIN: &[u8] = b"KQ-FILE-REQUEST-ANSWER-v1";

/// The longest message a change request may carry, in bytes.
pub const MAX_REQUEST_MESSAGE: usize = 1024;

/// What is being asked for. Codes are wire format: append, never renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestKind {
    /// "Send me the latest version."
    File = 1,
    /// "Please change this file."
    Change = 2,
}

impl RequestKind {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::File),
            2 => Some(Self::Change),
            _ => None,
        }
    }

    /// The word history and the command line use.
    pub fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Change => "change",
        }
    }
}

/// What the requester needs to seal one request.
pub struct OutgoingRequest<'a> {
    pub sender_label: &'a str,
    pub sender_signing_secret: &'a [u8; 32],
    pub sender_encryption_public: &'a [u8; 32],
    pub recipient_label: &'a str,
    pub recipient_encryption_public: &'a [u8; 32],
    pub file_name: &'a str,
    pub file_id: [u8; 16],
    pub kind: RequestKind,
    /// The revision a change request is about; none for "the latest".
    pub base_revision: Option<[u8; 32]>,
    /// Why, in the requester's words. Empty for a file request.
    pub message: &'a str,
}

pub struct SealedRequest {
    pub request_id: [u8; 16],
    pub bytes: Vec<u8>,
}

/// An opened, signature-checked request. It asks; nothing in it is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRequest {
    pub request_id: [u8; 16],
    pub requester_label: String,
    pub holder_label: String,
    pub return_public: [u8; 32],
    pub file_name: String,
    pub file_id: [u8; 16],
    pub kind: RequestKind,
    pub base_revision: Option<[u8; 32]>,
    pub message: String,
    /// The hash the requester signed; an answer names it.
    pub request_hash: [u8; 32],
}

/// An opened, signature-checked answer to a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestAnswer {
    pub request_id: [u8; 16],
    pub holder_label: String,
    pub file_id: [u8; 16],
    pub kind: RequestKind,
    pub accepted: bool,
    pub request_hash: [u8; 32],
}

pub fn seal_request(outgoing: &OutgoingRequest<'_>) -> Result<SealedRequest> {
    if outgoing.message.len() > MAX_REQUEST_MESSAGE
        || (outgoing.kind == RequestKind::File && !outgoing.message.is_empty())
    {
        return Err(Error::BundleFieldTooLarge);
    }
    let mut request_id = [0u8; 16];
    crate::crypto::fill_random(&mut request_id);
    let base = outgoing.base_revision.unwrap_or([0u8; 32]);
    let preimage = request_preimage(
        outgoing.recipient_encryption_public,
        &request_id,
        outgoing.sender_label,
        outgoing.recipient_label,
        outgoing.sender_encryption_public,
        outgoing.file_name,
        &outgoing.file_id,
        outgoing.kind,
        &base,
        outgoing.message,
    )?;
    let signature = signing::sign(outgoing.sender_signing_secret, &preimage);
    let mut plain = Vec::new();
    push_head(
        &mut plain,
        &request_id,
        outgoing.sender_label,
        outgoing.recipient_label,
        outgoing.sender_encryption_public,
        outgoing.file_name,
    )?;
    plain.extend_from_slice(&outgoing.file_id);
    plain.push(outgoing.kind as u8);
    plain.extend_from_slice(&base);
    push_len_prefixed_u32(&mut plain, outgoing.message.as_bytes())?;
    plain.extend_from_slice(&signature);
    let bytes = envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_REQUEST,
        outgoing.recipient_encryption_public,
        &plain,
    )?;
    Ok(SealedRequest { request_id, bytes })
}

/// Unseal a request and check the requester's signature against the signing
/// key `conn` has registered for that label.
pub fn open_request(
    conn: &Connection,
    holder_secret: &[u8; 32],
    bytes: &[u8],
) -> Result<FileRequest> {
    let (holder_public, payload) = open_kind(bytes, holder_secret, envelope::KIND_FILE_REQUEST)?;
    let mut data = payload.as_slice();
    let head = take_head(&mut data)?;
    let file_id: [u8; 16] = take_array(&mut data)?;
    let kind = RequestKind::from_code(take_u8(&mut data)?).ok_or(Error::InvalidBridgePackage)?;
    let base: [u8; 32] = take_array(&mut data)?;
    let message = utf8(take_len_prefixed_u32(&mut data)?)?;
    let signature = take_signature(&mut data)?;
    if message.len() > MAX_REQUEST_MESSAGE || (kind == RequestKind::File && !message.is_empty()) {
        return Err(Error::InvalidBridgePackage);
    }
    let request_hash = request_preimage(
        &holder_public,
        &head.delivery_id,
        &head.sender_label,
        &head.recipient_label,
        &head.return_public,
        &head.file_name,
        &file_id,
        kind,
        &base,
        &message,
    )?;
    verify_signed_by(conn, &head.sender_label, &request_hash, &signature)?;
    Ok(FileRequest {
        request_id: head.delivery_id,
        requester_label: head.sender_label,
        holder_label: head.recipient_label,
        return_public: head.return_public,
        file_name: head.file_name,
        file_id,
        kind,
        base_revision: (base != [0u8; 32]).then_some(base),
        message,
        request_hash,
    })
}

/// Seal the holder's answer back to the requester.
pub fn seal_request_answer(
    request: &FileRequest,
    holder_signing_secret: &[u8; 32],
    accepted: bool,
) -> Result<Vec<u8>> {
    let answer = RequestAnswer {
        request_id: request.request_id,
        holder_label: request.holder_label.clone(),
        file_id: request.file_id,
        kind: request.kind,
        accepted,
        request_hash: request.request_hash,
    };
    let preimage = answer_preimage(&answer, &request.return_public)?;
    let signature = signing::sign(holder_signing_secret, &preimage);
    let mut plain = Vec::new();
    plain.extend_from_slice(&answer.request_id);
    push_len_prefixed(&mut plain, answer.holder_label.as_bytes())?;
    plain.extend_from_slice(&answer.file_id);
    plain.push(answer.kind as u8);
    plain.extend_from_slice(&answer.request_hash);
    plain.push(u8::from(accepted));
    plain.extend_from_slice(&signature);
    envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_REQUEST_ANSWER,
        &request.return_public,
        &plain,
    )
}

/// Unseal with the requester's encryption secret and check the holder's
/// signature against the signing key `conn` has registered for that label.
pub fn open_request_answer(
    conn: &Connection,
    requester_secret: &[u8; 32],
    bytes: &[u8],
) -> Result<RequestAnswer> {
    let (return_public, payload) =
        open_kind(bytes, requester_secret, envelope::KIND_FILE_REQUEST_ANSWER)?;
    let mut data = payload.as_slice();
    let request_id: [u8; 16] = take_array(&mut data)?;
    let holder_label = utf8(take_len_prefixed(&mut data)?)?;
    let file_id: [u8; 16] = take_array(&mut data)?;
    let kind = RequestKind::from_code(take_u8(&mut data)?).ok_or(Error::InvalidBridgePackage)?;
    let request_hash: [u8; 32] = take_array(&mut data)?;
    let accepted = take_accepted(&mut data)?;
    let signature = take_signature(&mut data)?;
    let answer = RequestAnswer {
        request_id,
        holder_label,
        file_id,
        kind,
        accepted,
        request_hash,
    };
    let preimage = answer_preimage(&answer, &return_public)?;
    verify_signed_by(conn, &answer.holder_label, &preimage, &signature)?;
    Ok(answer)
}

#[allow(clippy::too_many_arguments)]
fn request_preimage(
    holder_public: &[u8; 32],
    request_id: &[u8; 16],
    requester_label: &str,
    holder_label: &str,
    return_public: &[u8; 32],
    file_name: &str,
    file_id: &[u8; 16],
    kind: RequestKind,
    base_revision: &[u8; 32],
    message: &str,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN);
    hasher.update(holder_public);
    hasher.update(request_id);
    hash_len_prefixed(&mut hasher, requester_label.as_bytes())?;
    hash_len_prefixed(&mut hasher, holder_label.as_bytes())?;
    hasher.update(return_public);
    hash_len_prefixed(&mut hasher, file_name.as_bytes())?;
    hasher.update(file_id);
    hasher.update([kind as u8]);
    hasher.update(base_revision);
    hash_len_prefixed(&mut hasher, message.as_bytes())?;
    Ok(hasher.finalize().into())
}

fn answer_preimage(answer: &RequestAnswer, return_public: &[u8; 32]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(ANSWER_DOMAIN);
    hasher.update(return_public);
    hasher.update(answer.request_id);
    hash_len_prefixed(&mut hasher, answer.holder_label.as_bytes())?;
    hasher.update(answer.file_id);
    hasher.update([answer.kind as u8]);
    hasher.update(answer.request_hash);
    hasher.update([u8::from(answer.accepted)]);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
#[path = "request/tests.rs"]
mod tests;
