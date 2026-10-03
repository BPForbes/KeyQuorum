//! Sealed file delivery between two labels, carried by the mailbox relay.
//!
//! A delivery letter is a [`PACKAGE`] envelope of kind
//! [`envelope::KIND_FILE_DELIVERY`], sealed to the recipient's registered
//! encryption key. Inside: a random delivery id, both labels, the sender's
//! encryption key for the reply, the file name, and the contents, signed by
//! the sender's registered signing key over a domain-separated preimage
//! that also covers the recipient key the letter was sealed to. The relay
//! routes on that recipient key only; it never sees the name or contents.
//!
//! The recipient answers with [`envelope::KIND_FILE_DELIVERY_ACK`], sealed
//! back to the sender and signed by the recipient, echoing the delivery id
//! and a hash of the contents, and saying whether it accepted the file.
//!
//! Both open functions check the signature against the signing key *this
//! store* has registered for the claimed label, never a key the letter
//! carries, so a letter cannot vouch for itself.
//!
//! A tracked file travels the same way as [`envelope::KIND_FILE_HISTORY`]:
//! the sealed payload is a `KQTF` container, and the signed header names the
//! file id, the revision being delivered, the container's history root,
//! the sender's delivery decision and the delivered revision's proof
//! descriptor (which the receiver recomputes from the container). That signature is *transport*
//! authentication only. Whether the delivered revision is trusted is decided
//! by the receiver from the container's own proofs and policy, never by the
//! letter. Its acknowledgement is [`envelope::KIND_FILE_HISTORY_ACK`].

use crate::envelope::{
    self, hash_len_prefixed, push_len_prefixed, push_len_prefixed_u32, take_array,
    take_len_prefixed, take_len_prefixed_u32, take_u8, utf8, PACKAGE,
};
use crate::error::{Error, Result};
use crate::private_bridge;
use crate::signing;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const LETTER_DOMAIN: &[u8] = b"KQ-FILE-DELIVERY-v1";
const ACK_DOMAIN: &[u8] = b"KQ-FILE-DELIVERY-ACK-v1";
const HISTORY_LETTER_DOMAIN: &[u8] = b"KQ-FILE-HISTORY-DELIVERY-v1";
const HISTORY_ACK_DOMAIN: &[u8] = b"KQ-FILE-HISTORY-DELIVERY-ACK-v1";
const SNAPSHOT_DOMAIN: &[u8] = b"KQ-FILE-HISTORY-SNAPSHOT-v1";

pub mod exchange;
mod request;
pub use request::{
    open_request, open_request_answer, seal_request, seal_request_answer, FileRequest,
    OutgoingRequest, RequestAnswer, RequestKind, SealedRequest, MAX_REQUEST_MESSAGE,
};

/// What the sender needs to seal one letter.
pub struct Outgoing<'a> {
    pub sender_label: &'a str,
    pub sender_signing_secret: &'a [u8; 32],
    /// Where the acknowledgement is sealed to: the sender's encryption key.
    pub sender_encryption_public: &'a [u8; 32],
    pub recipient_label: &'a str,
    pub recipient_encryption_public: &'a [u8; 32],
    pub file_name: &'a str,
    pub contents: &'a [u8],
}

pub struct SealedLetter {
    pub delivery_id: [u8; 16],
    pub content_hash: [u8; 32],
    pub bytes: Vec<u8>,
}

/// An opened, signature-checked delivery letter.
pub struct FileLetter {
    pub delivery_id: [u8; 16],
    pub sender_label: String,
    pub recipient_label: String,
    pub return_public: [u8; 32],
    pub file_name: String,
    pub contents: Vec<u8>,
    pub content_hash: [u8; 32],
}

/// An opened, signature-checked acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryAck {
    pub delivery_id: [u8; 16],
    pub recipient_label: String,
    pub content_hash: [u8; 32],
    pub accepted: bool,
}

pub fn seal_letter(outgoing: &Outgoing<'_>) -> Result<SealedLetter> {
    let mut delivery_id = [0u8; 16];
    OsRng.fill_bytes(&mut delivery_id);
    let content_hash: [u8; 32] = Sha256::digest(outgoing.contents).into();
    let preimage = letter_preimage(
        outgoing.recipient_encryption_public,
        &delivery_id,
        outgoing.sender_label,
        outgoing.recipient_label,
        outgoing.sender_encryption_public,
        outgoing.file_name,
        &content_hash,
    )?;
    let signature = signing::sign(outgoing.sender_signing_secret, &preimage);

    let mut plain = Vec::new();
    push_head(
        &mut plain,
        &delivery_id,
        outgoing.sender_label,
        outgoing.recipient_label,
        outgoing.sender_encryption_public,
        outgoing.file_name,
    )?;
    push_len_prefixed_u32(&mut plain, outgoing.contents)?;
    plain.extend_from_slice(&signature);
    let bytes = envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_DELIVERY,
        outgoing.recipient_encryption_public,
        &plain,
    )?;
    Ok(SealedLetter {
        delivery_id,
        content_hash,
        bytes,
    })
}

/// Unseal with the recipient's encryption secret and check the sender's
/// signature against the signing key `conn` has registered for that label.
pub fn open_letter(
    conn: &Connection,
    recipient_secret: &[u8; 32],
    bytes: &[u8],
) -> Result<FileLetter> {
    let (recipient_public, payload) =
        open_kind(bytes, recipient_secret, envelope::KIND_FILE_DELIVERY)?;
    let mut data = payload.as_slice();
    let head = take_head(&mut data)?;
    let contents = take_len_prefixed_u32(&mut data)?.to_vec();
    let signature = take_signature(&mut data)?;
    let content_hash: [u8; 32] = Sha256::digest(&contents).into();
    let preimage = letter_preimage(
        &recipient_public,
        &head.delivery_id,
        &head.sender_label,
        &head.recipient_label,
        &head.return_public,
        &head.file_name,
        &content_hash,
    )?;
    verify_signed_by(conn, &head.sender_label, &preimage, &signature)?;
    Ok(FileLetter {
        delivery_id: head.delivery_id,
        sender_label: head.sender_label,
        recipient_label: head.recipient_label,
        return_public: head.return_public,
        file_name: head.file_name,
        contents,
        content_hash,
    })
}

/// Seal the recipient's answer back to the sender.
pub fn seal_ack(
    letter: &FileLetter,
    recipient_signing_secret: &[u8; 32],
    accepted: bool,
) -> Result<Vec<u8>> {
    let preimage = ack_preimage(
        &letter.return_public,
        &letter.delivery_id,
        &letter.recipient_label,
        &letter.content_hash,
        accepted,
    )?;
    let signature = signing::sign(recipient_signing_secret, &preimage);
    let mut plain = Vec::new();
    plain.extend_from_slice(&letter.delivery_id);
    push_len_prefixed(&mut plain, letter.recipient_label.as_bytes())?;
    plain.extend_from_slice(&letter.content_hash);
    plain.push(u8::from(accepted));
    plain.extend_from_slice(&signature);
    envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_DELIVERY_ACK,
        &letter.return_public,
        &plain,
    )
}

/// Unseal with the sender's encryption secret and check the recipient's
/// signature against the signing key `conn` has registered for that label.
pub fn open_ack(conn: &Connection, sender_secret: &[u8; 32], bytes: &[u8]) -> Result<DeliveryAck> {
    let (return_public, payload) =
        open_kind(bytes, sender_secret, envelope::KIND_FILE_DELIVERY_ACK)?;
    let mut data = payload.as_slice();
    let delivery_id: [u8; 16] = take_array(&mut data)?;
    let recipient_label = utf8(take_len_prefixed(&mut data)?)?;
    let content_hash: [u8; 32] = take_array(&mut data)?;
    let accepted = take_accepted(&mut data)?;
    let signature = take_signature(&mut data)?;
    let preimage = ack_preimage(
        &return_public,
        &delivery_id,
        &recipient_label,
        &content_hash,
        accepted,
    )?;
    verify_signed_by(conn, &recipient_label, &preimage, &signature)?;
    Ok(DeliveryAck {
        delivery_id,
        recipient_label,
        content_hash,
        accepted,
    })
}

fn letter_preimage(
    recipient_public: &[u8; 32],
    delivery_id: &[u8; 16],
    sender_label: &str,
    recipient_label: &str,
    return_public: &[u8; 32],
    file_name: &str,
    content_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(LETTER_DOMAIN);
    hasher.update(recipient_public);
    hasher.update(delivery_id);
    hash_len_prefixed(&mut hasher, sender_label.as_bytes())?;
    hash_len_prefixed(&mut hasher, recipient_label.as_bytes())?;
    hasher.update(return_public);
    hash_len_prefixed(&mut hasher, file_name.as_bytes())?;
    hasher.update(content_hash);
    Ok(hasher.finalize().into())
}

fn ack_preimage(
    return_public: &[u8; 32],
    delivery_id: &[u8; 16],
    recipient_label: &str,
    content_hash: &[u8; 32],
    accepted: bool,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(ACK_DOMAIN);
    hasher.update(return_public);
    hasher.update(delivery_id);
    hash_len_prefixed(&mut hasher, recipient_label.as_bytes())?;
    hasher.update(content_hash);
    hasher.update([u8::from(accepted)]);
    Ok(hasher.finalize().into())
}

/// What the sender needs to seal one tracked-file letter. `container` is the
/// encoded `KQTF` to deliver; the caller has already pruned it to what may be
/// shared and named its history root.
pub struct OutgoingHistory<'a> {
    pub sender_label: &'a str,
    pub sender_signing_secret: &'a [u8; 32],
    pub sender_encryption_public: &'a [u8; 32],
    pub recipient_label: &'a str,
    pub recipient_encryption_public: &'a [u8; 32],
    pub file_name: &'a str,
    pub file_id: [u8; 16],
    /// The revision being delivered.
    pub revision_id: [u8; 32],
    pub history_root: [u8; 32],
    /// The sender's delivery decision, as `file_history` codes it.
    pub decision: u8,
    /// `file_history::proof_descriptor` of the delivered revision.
    pub content_proof: [u8; 32],
    pub container: &'a [u8],
}

pub struct SealedHistoryLetter {
    pub delivery_id: [u8; 16],
    pub container_hash: [u8; 32],
    pub bytes: Vec<u8>,
}

/// An opened, transport-checked tracked-file letter. Nothing in it is
/// trusted content yet.
pub struct HistoryLetter {
    pub delivery_id: [u8; 16],
    pub sender_label: String,
    pub recipient_label: String,
    pub return_public: [u8; 32],
    pub file_name: String,
    pub file_id: [u8; 16],
    pub revision_id: [u8; 32],
    pub history_root: [u8; 32],
    pub decision: u8,
    /// The proof descriptor the sender signed; the receiver recomputes it
    /// from `container` before relying on the letter.
    pub content_proof: [u8; 32],
    pub container: Vec<u8>,
    pub container_hash: [u8; 32],
}

/// An opened, signature-checked answer to a tracked-file letter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryAck {
    pub delivery_id: [u8; 16],
    pub recipient_label: String,
    pub file_id: [u8; 16],
    pub revision_id: [u8; 32],
    pub container_hash: [u8; 32],
    pub accepted: bool,
}

pub fn seal_history_letter(outgoing: &OutgoingHistory<'_>) -> Result<SealedHistoryLetter> {
    let mut delivery_id = [0u8; 16];
    OsRng.fill_bytes(&mut delivery_id);
    let container_hash: [u8; 32] = Sha256::digest(outgoing.container).into();
    let preimage = history_letter_preimage(&HistoryHeader {
        recipient_public: outgoing.recipient_encryption_public,
        delivery_id: &delivery_id,
        sender_label: outgoing.sender_label,
        recipient_label: outgoing.recipient_label,
        return_public: outgoing.sender_encryption_public,
        file_name: outgoing.file_name,
        file_id: &outgoing.file_id,
        revision_id: &outgoing.revision_id,
        history_root: &outgoing.history_root,
        decision: outgoing.decision,
        content_proof: &outgoing.content_proof,
        container_hash: &container_hash,
    })?;
    let signature = signing::sign(outgoing.sender_signing_secret, &preimage);

    let mut plain = Vec::new();
    push_head(
        &mut plain,
        &delivery_id,
        outgoing.sender_label,
        outgoing.recipient_label,
        outgoing.sender_encryption_public,
        outgoing.file_name,
    )?;
    plain.extend_from_slice(&outgoing.file_id);
    plain.extend_from_slice(&outgoing.revision_id);
    plain.extend_from_slice(&outgoing.history_root);
    plain.push(outgoing.decision);
    plain.extend_from_slice(&outgoing.content_proof);
    push_len_prefixed_u32(&mut plain, outgoing.container)?;
    plain.extend_from_slice(&signature);
    let bytes = envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_HISTORY,
        outgoing.recipient_encryption_public,
        &plain,
    )?;
    Ok(SealedHistoryLetter {
        delivery_id,
        container_hash,
        bytes,
    })
}

/// Unseal with the recipient's encryption secret and check the sender's
/// signature against the signing key `conn` has registered for that label.
pub fn open_history_letter(
    conn: &Connection,
    recipient_secret: &[u8; 32],
    bytes: &[u8],
) -> Result<HistoryLetter> {
    let (recipient_public, payload) =
        open_kind(bytes, recipient_secret, envelope::KIND_FILE_HISTORY)?;
    let mut data = payload.as_slice();
    let LetterHead {
        delivery_id,
        sender_label,
        recipient_label,
        return_public,
        file_name,
    } = take_head(&mut data)?;
    let file_id: [u8; 16] = take_array(&mut data)?;
    let revision_id: [u8; 32] = take_array(&mut data)?;
    let history_root: [u8; 32] = take_array(&mut data)?;
    let decision = take_u8(&mut data)?;
    let content_proof: [u8; 32] = take_array(&mut data)?;
    let container = take_len_prefixed_u32(&mut data)?.to_vec();
    let signature = take_signature(&mut data)?;
    let container_hash: [u8; 32] = Sha256::digest(&container).into();
    let preimage = history_letter_preimage(&HistoryHeader {
        recipient_public: &recipient_public,
        delivery_id: &delivery_id,
        sender_label: &sender_label,
        recipient_label: &recipient_label,
        return_public: &return_public,
        file_name: &file_name,
        file_id: &file_id,
        revision_id: &revision_id,
        history_root: &history_root,
        decision,
        content_proof: &content_proof,
        container_hash: &container_hash,
    })?;
    verify_signed_by(conn, &sender_label, &preimage, &signature)?;
    Ok(HistoryLetter {
        delivery_id,
        sender_label,
        recipient_label,
        return_public,
        file_name,
        file_id,
        revision_id,
        history_root,
        decision,
        content_proof,
        container,
        container_hash,
    })
}

/// Seal the recipient's answer back to the sender.
pub fn seal_history_ack(
    letter: &HistoryLetter,
    recipient_signing_secret: &[u8; 32],
    accepted: bool,
) -> Result<Vec<u8>> {
    let preimage = history_ack_preimage(
        &HistoryAck {
            delivery_id: letter.delivery_id,
            recipient_label: letter.recipient_label.clone(),
            file_id: letter.file_id,
            revision_id: letter.revision_id,
            container_hash: letter.container_hash,
            accepted,
        },
        &letter.return_public,
    )?;
    let signature = signing::sign(recipient_signing_secret, &preimage);
    let mut plain = Vec::new();
    plain.extend_from_slice(&letter.delivery_id);
    push_len_prefixed(&mut plain, letter.recipient_label.as_bytes())?;
    plain.extend_from_slice(&letter.file_id);
    plain.extend_from_slice(&letter.revision_id);
    plain.extend_from_slice(&letter.container_hash);
    plain.push(u8::from(accepted));
    plain.extend_from_slice(&signature);
    envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_HISTORY_ACK,
        &letter.return_public,
        &plain,
    )
}

/// Unseal with the sender's encryption secret and check the recipient's
/// signature against the signing key `conn` has registered for that label.
pub fn open_history_ack(
    conn: &Connection,
    sender_secret: &[u8; 32],
    bytes: &[u8],
) -> Result<HistoryAck> {
    let (return_public, payload) =
        open_kind(bytes, sender_secret, envelope::KIND_FILE_HISTORY_ACK)?;
    let mut data = payload.as_slice();
    let delivery_id: [u8; 16] = take_array(&mut data)?;
    let recipient_label = utf8(take_len_prefixed(&mut data)?)?;
    let file_id: [u8; 16] = take_array(&mut data)?;
    let revision_id: [u8; 32] = take_array(&mut data)?;
    let container_hash: [u8; 32] = take_array(&mut data)?;
    let accepted = take_accepted(&mut data)?;
    let signature = take_signature(&mut data)?;
    let ack = HistoryAck {
        delivery_id,
        recipient_label,
        file_id,
        revision_id,
        container_hash,
        accepted,
    };
    let preimage = history_ack_preimage(&ack, &return_public)?;
    verify_signed_by(conn, &ack.recipient_label, &preimage, &signature)?;
    Ok(ack)
}

/// The start every letter kind shares, after the delivery id: who sends,
/// to whom, where the answer is sealed, and the file's name.
struct LetterHead {
    delivery_id: [u8; 16],
    sender_label: String,
    recipient_label: String,
    return_public: [u8; 32],
    file_name: String,
}

fn push_head(
    out: &mut Vec<u8>,
    delivery_id: &[u8; 16],
    sender_label: &str,
    recipient_label: &str,
    return_public: &[u8; 32],
    file_name: &str,
) -> Result<()> {
    out.extend_from_slice(delivery_id);
    push_len_prefixed(out, sender_label.as_bytes())?;
    push_len_prefixed(out, recipient_label.as_bytes())?;
    out.extend_from_slice(return_public);
    push_len_prefixed(out, file_name.as_bytes())?;
    Ok(())
}

fn take_head(data: &mut &[u8]) -> Result<LetterHead> {
    Ok(LetterHead {
        delivery_id: take_array(data)?,
        sender_label: utf8(take_len_prefixed(data)?)?,
        recipient_label: utf8(take_len_prefixed(data)?)?,
        return_public: take_array(data)?,
        file_name: utf8(take_len_prefixed(data)?)?,
    })
}

/// Unseal `bytes` as `kind` with `secret`: the key the envelope was sealed
/// to, and its plaintext. Any other kind is refused, so the kinds never mix.
fn open_kind(
    bytes: &[u8],
    secret: &[u8; 32],
    kind: u8,
) -> Result<([u8; 32], zeroize::Zeroizing<Vec<u8>>)> {
    let (found, sealed_to, payload) = envelope::open(bytes, secret)?;
    if found != kind {
        return Err(Error::InvalidBridgePackage);
    }
    Ok((sealed_to, payload))
}

/// The trailing signature, and nothing after it.
fn take_signature(data: &mut &[u8]) -> Result<[u8; 64]> {
    let signature: [u8; 64] = take_array(data)?;
    if !data.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    Ok(signature)
}

/// An answer's accept flag: exactly 0 or 1.
fn take_accepted(data: &mut &[u8]) -> Result<bool> {
    match take_u8(data)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::InvalidBridgePackage),
    }
}

/// Every letter and answer is checked against the signing key *this store*
/// has registered for the label it claims, never a key it carries.
fn verify_signed_by(
    conn: &Connection,
    label: &str,
    preimage: &[u8; 32],
    signature: &[u8; 64],
) -> Result<()> {
    let key = private_bridge::signing_public_for_label(conn, label)?;
    signing::verify_signature(&key, preimage, signature)
}

/// Whether the key that opened a letter is an active encryption key this
/// store has registered for the letter's claimed recipient label. The
/// sender chooses and signs that label, so a letter sealed to one key must
/// not be recorded as received by another label. Both letter kinds use it.
pub fn recipient_owns_key(
    conn: &Connection,
    recipient_label: &str,
    opened_with: &[u8; 32],
) -> Result<bool> {
    let public = crate::keys::encryption_public_from_secret(opened_with);
    crate::keys::is_active_key(
        conn,
        recipient_label,
        crate::keys::KeyType::Encryption,
        &public,
    )
}

/// What the sender needs to seal one history snapshot (`KQHS`).
pub struct OutgoingSnapshot<'a> {
    pub sender_label: &'a str,
    pub sender_signing_secret: &'a [u8; 32],
    pub sender_encryption_public: &'a [u8; 32],
    pub recipient_label: &'a str,
    pub recipient_encryption_public: &'a [u8; 32],
    pub file_name: &'a str,
    pub file_id: [u8; 16],
    /// The snapshot's own root and event count, signed in the header.
    pub history_root: [u8; 32],
    pub event_count: u32,
    pub snapshot: &'a [u8],
}

/// An opened, signature-checked snapshot letter: the sender vouches that
/// `history_root` was their file's history. Nothing in it is trusted
/// content; the receiver decodes and compares the snapshot itself.
pub struct SnapshotLetter {
    pub delivery_id: [u8; 16],
    pub sender_label: String,
    pub recipient_label: String,
    pub file_name: String,
    pub file_id: [u8; 16],
    pub history_root: [u8; 32],
    pub event_count: u32,
    pub snapshot: Vec<u8>,
}

pub fn seal_history_snapshot(outgoing: &OutgoingSnapshot<'_>) -> Result<([u8; 16], Vec<u8>)> {
    let mut delivery_id = [0u8; 16];
    OsRng.fill_bytes(&mut delivery_id);
    let preimage = snapshot_preimage(
        outgoing.recipient_encryption_public,
        &delivery_id,
        outgoing.sender_label,
        outgoing.recipient_label,
        outgoing.sender_encryption_public,
        outgoing.file_name,
        &outgoing.file_id,
        &outgoing.history_root,
        outgoing.event_count,
        outgoing.snapshot,
    )?;
    let signature = signing::sign(outgoing.sender_signing_secret, &preimage);
    let mut plain = Vec::new();
    push_head(
        &mut plain,
        &delivery_id,
        outgoing.sender_label,
        outgoing.recipient_label,
        outgoing.sender_encryption_public,
        outgoing.file_name,
    )?;
    plain.extend_from_slice(&outgoing.file_id);
    plain.extend_from_slice(&outgoing.history_root);
    plain.extend_from_slice(&outgoing.event_count.to_be_bytes());
    push_len_prefixed_u32(&mut plain, outgoing.snapshot)?;
    plain.extend_from_slice(&signature);
    let bytes = envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_HISTORY_SNAPSHOT,
        outgoing.recipient_encryption_public,
        &plain,
    )?;
    Ok((delivery_id, bytes))
}

/// Unseal a snapshot letter and check the sender's signature against the
/// signing key `conn` has registered for that label.
pub fn open_history_snapshot(
    conn: &Connection,
    recipient_secret: &[u8; 32],
    bytes: &[u8],
) -> Result<SnapshotLetter> {
    let (recipient_public, payload) = open_kind(
        bytes,
        recipient_secret,
        envelope::KIND_FILE_HISTORY_SNAPSHOT,
    )?;
    let mut data = payload.as_slice();
    let head = take_head(&mut data)?;
    let file_id: [u8; 16] = take_array(&mut data)?;
    let history_root: [u8; 32] = take_array(&mut data)?;
    let event_count = u32::from_be_bytes(take_array(&mut data)?);
    let snapshot = take_len_prefixed_u32(&mut data)?.to_vec();
    let signature = take_signature(&mut data)?;
    let preimage = snapshot_preimage(
        &recipient_public,
        &head.delivery_id,
        &head.sender_label,
        &head.recipient_label,
        &head.return_public,
        &head.file_name,
        &file_id,
        &history_root,
        event_count,
        &snapshot,
    )?;
    verify_signed_by(conn, &head.sender_label, &preimage, &signature)?;
    Ok(SnapshotLetter {
        delivery_id: head.delivery_id,
        sender_label: head.sender_label,
        recipient_label: head.recipient_label,
        file_name: head.file_name,
        file_id,
        history_root,
        event_count,
        snapshot,
    })
}

#[allow(clippy::too_many_arguments)]
fn snapshot_preimage(
    recipient_public: &[u8; 32],
    delivery_id: &[u8; 16],
    sender_label: &str,
    recipient_label: &str,
    return_public: &[u8; 32],
    file_name: &str,
    file_id: &[u8; 16],
    history_root: &[u8; 32],
    event_count: u32,
    snapshot: &[u8],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(recipient_public);
    hasher.update(delivery_id);
    hash_len_prefixed(&mut hasher, sender_label.as_bytes())?;
    hash_len_prefixed(&mut hasher, recipient_label.as_bytes())?;
    hasher.update(return_public);
    hash_len_prefixed(&mut hasher, file_name.as_bytes())?;
    hasher.update(file_id);
    hasher.update(history_root);
    hasher.update(event_count.to_be_bytes());
    hasher.update(Sha256::digest(snapshot));
    Ok(hasher.finalize().into())
}

/// How a letter's history compares with what this store has already
/// authenticated for the same file (from earlier accepted letters).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Nothing from this file was authenticated here before.
    First,
    /// The same revision and history root were accepted before (a replay or
    /// a retry).
    Replayed,
    /// The letter's event chain passes through every history root accepted
    /// here before, holds every revision accepted with them, and adds a
    /// revision: it extends everything this store has authenticated.
    Newer,
    /// The same revision as before, or a history missing something accepted
    /// here before (an older copy, another branch, or the same revisions
    /// under a different event chain). Not newer.
    NotNewer,
}

impl Freshness {
    pub fn name(self) -> &'static str {
        match self {
            Self::First => "FIRST",
            Self::Replayed => "REPLAYED",
            Self::Newer => "NEWER",
            Self::NotNewer => "NOT_NEWER",
        }
    }
}

/// Compare a letter's authenticated history with what this store accepted
/// before for the same file. `holds` answers whether the letter's container
/// includes a revision id, and `passes_through` whether its event chain
/// contains a history root; the caller supplies both from the decoded
/// container, so this module never decodes one.
pub fn freshness(
    conn: &Connection,
    letter: &HistoryLetter,
    holds: impl Fn(&[u8; 32]) -> bool,
    passes_through: impl Fn(&[u8; 32]) -> bool,
) -> Result<Freshness> {
    let mut seen = conn
        .prepare("SELECT revision_id, history_root FROM tracked_seen_roots WHERE file_id = ?1")?;
    let rows = seen
        .query_map(rusqlite::params![letter.file_id.as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Ok(Freshness::First);
    }
    let mut revisions = Vec::new();
    let mut roots = Vec::new();
    for (revision, root) in rows {
        let revision: [u8; 32] = revision.try_into().map_err(|_| Error::InvalidTrackedFile)?;
        let root: [u8; 32] = root.try_into().map_err(|_| Error::InvalidTrackedFile)?;
        if revision == letter.revision_id && root == letter.history_root {
            return Ok(Freshness::Replayed);
        }
        revisions.push(revision);
        roots.push(root);
    }
    let covers_all = revisions.iter().all(&holds);
    let extends_all = roots.iter().all(&passes_through);
    let adds = !revisions.contains(&letter.revision_id);
    Ok(if covers_all && extends_all && adds {
        Freshness::Newer
    } else {
        Freshness::NotNewer
    })
}

/// Remember that this store accepted `letter`'s history, for later
/// [`freshness`] checks. Recording the same one twice is harmless.
pub fn record_seen_root(conn: &Connection, letter: &HistoryLetter) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO tracked_seen_roots
             (file_id, revision_id, history_root, sender_label)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            letter.file_id.as_slice(),
            letter.revision_id.as_slice(),
            letter.history_root.as_slice(),
            letter.sender_label
        ],
    )?;
    Ok(())
}

/// Every field the transport signature covers.
struct HistoryHeader<'a> {
    recipient_public: &'a [u8; 32],
    delivery_id: &'a [u8; 16],
    sender_label: &'a str,
    recipient_label: &'a str,
    return_public: &'a [u8; 32],
    file_name: &'a str,
    file_id: &'a [u8; 16],
    revision_id: &'a [u8; 32],
    history_root: &'a [u8; 32],
    decision: u8,
    content_proof: &'a [u8; 32],
    container_hash: &'a [u8; 32],
}

fn history_letter_preimage(header: &HistoryHeader<'_>) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(HISTORY_LETTER_DOMAIN);
    hasher.update(header.recipient_public);
    hasher.update(header.delivery_id);
    hash_len_prefixed(&mut hasher, header.sender_label.as_bytes())?;
    hash_len_prefixed(&mut hasher, header.recipient_label.as_bytes())?;
    hasher.update(header.return_public);
    hash_len_prefixed(&mut hasher, header.file_name.as_bytes())?;
    hasher.update(header.file_id);
    hasher.update(header.revision_id);
    hasher.update(header.history_root);
    hasher.update([header.decision]);
    hasher.update(header.content_proof);
    hasher.update(header.container_hash);
    Ok(hasher.finalize().into())
}

fn history_ack_preimage(ack: &HistoryAck, return_public: &[u8; 32]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(HISTORY_ACK_DOMAIN);
    hasher.update(return_public);
    hasher.update(ack.delivery_id);
    hash_len_prefixed(&mut hasher, ack.recipient_label.as_bytes())?;
    hasher.update(ack.file_id);
    hasher.update(ack.revision_id);
    hasher.update(ack.container_hash);
    hasher.update([u8::from(ack.accepted)]);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
#[path = "file_delivery/tests.rs"]
mod tests;
