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
    plain.extend_from_slice(&delivery_id);
    push_len_prefixed(&mut plain, outgoing.sender_label.as_bytes())?;
    push_len_prefixed(&mut plain, outgoing.recipient_label.as_bytes())?;
    plain.extend_from_slice(outgoing.sender_encryption_public);
    push_len_prefixed(&mut plain, outgoing.file_name.as_bytes())?;
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
    let (kind, recipient_public, payload) = envelope::open(bytes, recipient_secret)?;
    if kind != envelope::KIND_FILE_DELIVERY {
        return Err(Error::InvalidBridgePackage);
    }
    let mut data = payload.as_slice();
    let delivery_id: [u8; 16] = take_array(&mut data)?;
    let sender_label = utf8(take_len_prefixed(&mut data)?)?;
    let recipient_label = utf8(take_len_prefixed(&mut data)?)?;
    let return_public: [u8; 32] = take_array(&mut data)?;
    let file_name = utf8(take_len_prefixed(&mut data)?)?;
    let contents = take_len_prefixed_u32(&mut data)?.to_vec();
    let signature: [u8; 64] = take_array(&mut data)?;
    if !data.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    let content_hash: [u8; 32] = Sha256::digest(&contents).into();
    let preimage = letter_preimage(
        &recipient_public,
        &delivery_id,
        &sender_label,
        &recipient_label,
        &return_public,
        &file_name,
        &content_hash,
    )?;
    let sender_key = private_bridge::signing_public_for_label(conn, &sender_label)?;
    signing::verify_signature(&sender_key, &preimage, &signature)?;
    Ok(FileLetter {
        delivery_id,
        sender_label,
        recipient_label,
        return_public,
        file_name,
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
    let (kind, return_public, payload) = envelope::open(bytes, sender_secret)?;
    if kind != envelope::KIND_FILE_DELIVERY_ACK {
        return Err(Error::InvalidBridgePackage);
    }
    let mut data = payload.as_slice();
    let delivery_id: [u8; 16] = take_array(&mut data)?;
    let recipient_label = utf8(take_len_prefixed(&mut data)?)?;
    let content_hash: [u8; 32] = take_array(&mut data)?;
    let accepted = match take_u8(&mut data)? {
        0 => false,
        1 => true,
        _ => return Err(Error::InvalidBridgePackage),
    };
    let signature: [u8; 64] = take_array(&mut data)?;
    if !data.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    let preimage = ack_preimage(
        &return_public,
        &delivery_id,
        &recipient_label,
        &content_hash,
        accepted,
    )?;
    let recipient_key = private_bridge::signing_public_for_label(conn, &recipient_label)?;
    signing::verify_signature(&recipient_key, &preimage, &signature)?;
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

#[cfg(test)]
#[path = "file_delivery/tests.rs"]
mod tests;
