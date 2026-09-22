//! The sealed outer envelope every recipient-addressed artifact in this
//! project shares, plus the byte codec their letters are written in.
//!
//! The outside is a routing slip: magic, format version, a kind byte, the
//! recipient's X25519 public key, and the sealed length. A carrier — the
//! mailbox relay, a USB drop, an email — indexes on the public key and
//! never opens the letter. The inside is `crypto_box`-sealed to that key,
//! so only the holder of the matching private key can read it.
//!
//! ```text
//! magic (4) | format_version (1) | kind (1) | recipient_public_key (32)
//!   | payload_len (4) | sealed_payload (payload_len)
//! ```
//!
//! Two formats use that framing, distinguished only by their magic and
//! version, so [`Format`] names them rather than each module rolling its
//! own copy:
//!
//! - [`PACKAGE`] (`KQPB`) — private-bridge invites, rotations and
//!   destroys ([`KIND_INVITE`] … [`KIND_SUPERVISOR`]) from
//!   `private_bridge`, and the authenticated organization updates
//!   ([`KIND_KEY_REISSUE`], [`KIND_TREE_UPDATE`]) from `org_update`. One
//!   outer format means the relay routes every kind through the same code
//!   path and learns nothing new about any of them.
//! - [`EXPORT_BUNDLE`] (`KQXB`) — the portable credential and file
//!   bundles in `export`, where the kind byte is the bundle type.
//!
//! Only `KQPB` has a decoder today; `export`'s `import` is still open (see
//! README's Roadmap). The parsing side below is therefore `KQPB`-only and
//! reports [`Error::InvalidBridgePackage`] on a malformed frame. A future
//! bundle decoder should take a [`Format`] and its own error rather than
//! borrowing that one, whose message names private bridges.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

/// Magic and version identifying one framing of the envelope above. The
/// bytes are wire format: changing either field of a existing constant
/// breaks every artifact already written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    magic: &'static [u8; 4],
    version: u8,
}

/// Private-bridge packages and organization updates: the `.kqpb` files
/// the mailbox relay carries.
pub const PACKAGE: Format = Format {
    magic: b"KQPB",
    version: 2,
};

/// Portable export bundles (`export::export_credential` / `export_file`).
pub const EXPORT_BUNDLE: Format = Format {
    magic: b"KQXB",
    version: 1,
};

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
/// A restructure signed by a delegated authorizer. Stores record it as
/// pending and do not change the tree until [`KIND_COUNTERSIGNED_TREE`].
pub const KIND_TREE_PROPOSAL: u8 = 7;
/// A [`KIND_TREE_PROPOSAL`] letter plus the parent label's countersignature.
/// Applying it is what makes a delegated restructure effective.
pub const KIND_COUNTERSIGNED_TREE: u8 = 8;

/// A sealed envelope addressed to one recipient, ready to be written to a
/// `.kqpb` file or pushed to the mailbox relay.
#[derive(Clone, Debug)]
pub struct Addressed {
    pub label: String,
    pub recipient_public_key: [u8; 32],
    pub bytes: Vec<u8>,
}

/// Seal `payload` to `recipient_public_key` under `kind`, framed as
/// `format`. The header is written in the clear; nothing but the kind byte
/// and the recipient's own public key is legible to a carrier, so any
/// name or label that is sensitive on its own belongs in `payload`.
pub fn seal(
    format: Format,
    kind: u8,
    recipient_public_key: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if is_weak_x25519_public_key(recipient_public_key) {
        return Err(Error::InvalidPublicKey);
    }
    let sealed = crypto_box::PublicKey::from_bytes(*recipient_public_key)
        .seal(&mut rand::rngs::OsRng, payload)
        .expect("crypto_box sealing should not fail for an in-memory payload");
    let payload_len = u32::try_from(sealed.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    let mut out = Vec::with_capacity(42 + sealed.len());
    out.extend_from_slice(format.magic);
    out.push(format.version);
    out.push(kind);
    out.extend_from_slice(recipient_public_key);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Reads only the outer header of a [`PACKAGE`] envelope: magic, version,
/// kind, recipient public key, and the declared sealed length. Does not
/// unseal the letter.
pub fn parse_outer(bytes: &[u8]) -> Result<(u8, [u8; 32], &[u8])> {
    let mut data = bytes;
    if take_n(&mut data, 4)? != PACKAGE.magic {
        return Err(Error::InvalidBridgePackage);
    }
    if take_u8(&mut data)? != PACKAGE.version {
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

/// A handful of X25519 curve points have small order and, under
/// Diffie-Hellman with *any* scalar, always yield an all-zero shared
/// secret (RFC 7748) — the trivial case is 32 zero bytes. Sealing to one
/// of these would produce an envelope anyone could open without any
/// private key at all. Detecting this needs only one clamped scalar
/// (clamping forces it to be a multiple of the curve's cofactor, so every
/// low-order point collapses to zero the same way regardless of which one
/// is used); the probe scalar's value is otherwise irrelevant and is never
/// used for real encryption.
pub fn is_weak_x25519_public_key(public_key: &[u8; 32]) -> bool {
    x25519_dalek::x25519([1u8; 32], *public_key) == [0u8; 32]
}

/// Appends `bytes` to `out` with a `u16` length prefix. Fails, without
/// writing anything to `out`, if `bytes` exceeds what a `u16` length can
/// encode — silently truncating the cast instead would corrupt the
/// framing of everything downstream of this field.
pub fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Length-prefixed field for payloads that can exceed 64 KiB — a public
/// tree slice for a large organization does.
/// The hashing twin of [`push_len_prefixed`]: a signature preimage feeds
/// a field the same length prefix the encoder writes, so a field boundary
/// can never be read one way and signed another. Kept beside it for that
/// reason — the two must stay in step.
pub fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

/// A u16 element count in a preimage, matching the count the map encoders
/// write ahead of their entries.
pub fn hash_u16_count(hasher: &mut Sha256, n: usize) -> Result<()> {
    let n = u16::try_from(n).map_err(|_| Error::BundleFieldTooLarge)?;
    hasher.update(n.to_be_bytes());
    Ok(())
}

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
