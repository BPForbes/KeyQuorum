//! The `.kqpb` outer envelope shared by every authenticated update this
//! project delivers, plus the byte codec its letters are written in.
//!
//! The outside is a routing slip: magic, format version, a kind byte, the
//! recipient's X25519 public key, and the sealed length. A carrier — the
//! mailbox relay, a USB drop, an email — indexes on the public key and
//! never opens the letter. The inside is `crypto_box`-sealed to that key,
//! so only the store holding the matching private key can read it.
//!
//! The kind byte selects the letter's schema. Private-bridge invites,
//! rotations and destroys ([`KIND_INVITE`] … [`KIND_SUPERVISOR`]) are
//! written by `private_bridge`; hardware-key reissue and key-tree
//! restructure ([`KIND_KEY_REISSUE`], [`KIND_TREE_UPDATE`]) by
//! `org_update`. Keeping one outer format means the relay routes every
//! kind with the same code path and learns nothing new about any of them.

use crate::error::{Error, Result};

pub const PACKAGE_MAGIC: &[u8; 4] = b"KQPB";
pub const FORMAT_VERSION: u8 = 2;

/// Private-bridge invite: roster plus the sealed shared signing secret.
pub const KIND_INVITE: u8 = 1;
/// Private-bridge rotation to a new generation of the shared secret.
pub const KIND_ROTATE: u8 = 2;
/// Private-bridge destruction notice.
pub const KIND_DESTROY: u8 = 3;
/// Private-bridge roster metadata for a supervisor (no shared secret).
pub const KIND_SUPERVISOR: u8 = 4;
/// Hardware-key reissue: one person's encryption and/or signing key is
/// replaced, and every store that holds the old public key must follow.
pub const KIND_KEY_REISSUE: u8 = 5;
/// Key-tree restructure: the slice of the public split tree this
/// recipient is allowed to see, at a new public generation.
pub const KIND_TREE_UPDATE: u8 = 6;

/// A sealed envelope addressed to one recipient, ready to be written to a
/// `.kqpb` file or pushed to the mailbox relay.
#[derive(Clone, Debug)]
pub struct Addressed {
    pub label: String,
    pub recipient_public_key: [u8; 32],
    pub bytes: Vec<u8>,
}

/// Seal `payload` to `recipient_public_key` under `kind`.
pub fn seal(kind: u8, recipient_public_key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    if is_weak_x25519_public_key(recipient_public_key) {
        return Err(Error::InvalidPublicKey);
    }
    let sealed = crypto_box::PublicKey::from_bytes(*recipient_public_key)
        .seal(&mut rand::rngs::OsRng, payload)
        .expect("crypto_box sealing should not fail for an in-memory payload");
    let payload_len = u32::try_from(sealed.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    let mut out = Vec::with_capacity(42 + sealed.len());
    out.extend_from_slice(PACKAGE_MAGIC);
    out.push(FORMAT_VERSION);
    out.push(kind);
    out.extend_from_slice(recipient_public_key);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Reads only the outer header: magic, version, kind, recipient public
/// key, and the declared sealed length. Does not unseal the letter.
pub fn parse_outer(bytes: &[u8]) -> Result<(u8, [u8; 32], &[u8])> {
    let mut data = bytes;
    if take_n(&mut data, 4)? != PACKAGE_MAGIC {
        return Err(Error::InvalidBridgePackage);
    }
    if take_u8(&mut data)? != FORMAT_VERSION {
        return Err(Error::InvalidBridgePackage);
    }
    let kind = take_u8(&mut data)?;
    let recipient_public_key = take_array::<32>(&mut data)?;
    let payload_len = u32::from_be_bytes(take_array(&mut data)?) as usize;
    let sealed = take_n(&mut data, payload_len)?;
    if !data.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    Ok((kind, recipient_public_key, sealed))
}

/// The recipient X25519 public key the carrier routes on. Used by the
/// relay, which never holds a private key and so never unseals anything.
pub fn routing_public_key(bytes: &[u8]) -> Result<[u8; 32]> {
    let (_, recipient_public_key, _) = parse_outer(bytes)?;
    Ok(recipient_public_key)
}

/// The kind byte, without unsealing. Lets an importer dispatch on the
/// letter's schema before it has the private key in hand.
pub fn kind(bytes: &[u8]) -> Result<u8> {
    let (kind, _, _) = parse_outer(bytes)?;
    Ok(kind)
}

/// Unseal an envelope with the recipient's X25519 private key. Returns the
/// kind byte, the header's recipient public key, and the letter.
pub fn open(bytes: &[u8], recipient_secret: &[u8; 32]) -> Result<(u8, [u8; 32], Vec<u8>)> {
    let (kind, recipient_public_key, sealed) = parse_outer(bytes)?;
    let secret_key = crypto_box::SecretKey::from(*recipient_secret);
    let payload = secret_key
        .unseal(sealed)
        .map_err(|_| Error::InvalidBridgePackage)?;
    Ok((kind, recipient_public_key, payload))
}

/// X25519 public keys of small order: a shared secret with one of these is
/// all zeroes whatever the private key, so sealing to one seals to nobody.
pub fn is_weak_x25519_public_key(public_key: &[u8; 32]) -> bool {
    x25519_dalek::x25519([1u8; 32], *public_key) == [0u8; 32]
}

pub fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Length-prefixed field for payloads that can exceed 64 KiB — a public
/// tree slice for a large organization does.
pub fn push_len_prefixed_u32(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub fn take_u8(data: &mut &[u8]) -> Result<u8> {
    let (b, rest) = data.split_first().ok_or(Error::InvalidBridgePackage)?;
    *data = rest;
    Ok(*b)
}

pub fn take_n<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if data.len() < n {
        return Err(Error::InvalidBridgePackage);
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Ok(head)
}

pub fn take_array<const N: usize>(data: &mut &[u8]) -> Result<[u8; N]> {
    take_n(data, N)?
        .try_into()
        .map_err(|_| Error::InvalidBridgePackage)
}

pub fn take_u32(data: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(take_array(data)?))
}

pub fn take_len_prefixed<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u16::from_be_bytes(take_array(data)?) as usize;
    take_n(data, len)
}

pub fn take_len_prefixed_u32<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = take_u32(data)? as usize;
    take_n(data, len)
}

pub fn utf8(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| Error::InvalidBridgePackage)
}

#[cfg(test)]
#[path = "envelope/tests.rs"]
mod tests;
