//! Portable, self-contained export bundles: re-encrypts a credential's or
//! file's plaintext (which the exporter already has via their own local
//! master/lock password) to a recipient's public key, so it can be handed
//! to someone with no access to this database. Opening a bundle
//! (`import`) needs the recipient's private key, which this project has
//! no custody story for yet — see README's Roadmap.
//!
//! The bundle format is a small hand-rolled, length-prefixed binary
//! framing rather than serde+serde_json, even though the crate carries
//! serde for the relay's public-tree documents: `import`'s future decoder
//! will parse bytes from an untrusted sender, and a small, fixed-width,
//! hand-checked parser keeps that attack surface much smaller than a
//! general JSON parser over attacker-controlled input would.
//!
//! The outer framing is [`crate::envelope`]'s, under the
//! [`crate::envelope::EXPORT_BUNDLE`] magic, with the bundle type as its
//! kind byte: 1 = credential, 2 = unlocked file, 3 = tracked file,
//! 4 = a relay-issued API key ([`BUNDLE_TYPE_API_KEY`], whose signed
//! payload `api_key_delivery` builds and opens). The
//! recipient's name/label stays inside the sealed payload rather than the
//! outer header — a credential label or file name can be sensitive on its
//! own, and the outer header is the one part of a bundle that's never encrypted.
//! The sealed payload's plaintext (before sealing) is, for a credential:
//!   label_len (2) | label (label_len) | username_len (2) | username (username_len)
//!   | password_len (2) | password (password_len)
//! (username_len = 0 means no username) and for a file:
//!   name_len (2) | name (name_len) | file_bytes (remainder)
//! A tracked-file bundle uses the same payload shape, but kind 3 keeps it
//! distinguishable from an unlocked password-file export. Its remainder is
//! the complete binary KQTF container, not a UTF-8 representation of it.

use crate::envelope::{self, push_len_prefixed};
use crate::error::Result;
use crate::storage::{NativeStorage, Storage};
use crate::{file_history::TrackedFile, locked_files, vault};
use rusqlite::{params, Connection};

const BUNDLE_TYPE_CREDENTIAL: u8 = 1;
const BUNDLE_TYPE_FILE: u8 = 2;
const BUNDLE_TYPE_TRACKED_FILE: u8 = 3;
/// A customer API key issued by a relay, handed over as a file for a first
/// key (`.kqkey`): the same relay-signed payload a rotated key carries as
/// `envelope::KIND_API_KEY_ISSUE` through the mailbox. Appended after the
/// tracked-file bundle; the bundle type byte is wire format.
pub const BUNDLE_TYPE_API_KEY: u8 = 4;
/// A package's setup manifest (`setup_manifest`): the typed, signed list of
/// steps `keyquorum setup` runs, sealed to the one recipient and bound to one
/// `.kqpkg`.
pub const BUNDLE_TYPE_SETUP_MANIFEST: u8 = 6;
/// A provider-recovery payload (`provider::recovery`): a relay identity's
/// private key and its root-signed context, sealed to an enrolled operator key
/// and carried only in a root-signed `ProviderRecovery` `.kqpkg`.
pub const BUNDLE_TYPE_PROVIDER_RECOVERY: u8 = 5;
/// One sealed chunk of a relay database backup (`relay::backup`), sealed to the
/// operator's backup key and held in R2. Never a `.kqpkg` component.
pub const BUNDLE_TYPE_BACKUP_CHUNK: u8 = 7;
/// The sealed, relay-signed manifest of a relay database backup, naming every
/// chunk by its SHA-256. Written last, so a backup without one is incomplete.
pub const BUNDLE_TYPE_BACKUP_MANIFEST: u8 = 8;

pub fn export_credential(
    conn: &Connection,
    credential_id: i64,
    master_password: &str,
    recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let credential = vault::get_credential(conn, credential_id, master_password)?;

    let mut payload = Vec::new();
    push_len_prefixed(&mut payload, credential.label.as_bytes())?;
    push_len_prefixed(
        &mut payload,
        credential.username.as_deref().unwrap_or("").as_bytes(),
    )?;
    push_len_prefixed(&mut payload, credential.password.as_bytes())?;

    encode_bundle(BUNDLE_TYPE_CREDENTIAL, recipient_public_key, &payload)
}

pub fn export_file(
    conn: &Connection,
    file_id: i64,
    password: &str,
    recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    export_file_in(
        &mut NativeStorage,
        conn,
        file_id,
        password,
        recipient_public_key,
    )
}

/// [`export_file`], reading the locked file's ciphertext through `storage`.
pub fn export_file_in(
    storage: &mut dyn Storage,
    conn: &Connection,
    file_id: i64,
    password: &str,
    recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let name: String = conn.query_row(
        "SELECT name FROM password_locked_files WHERE id = ?1",
        params![file_id],
        |row| row.get(0),
    )?;
    let plaintext = locked_files::unlock_file_in(storage, conn, file_id, password)?;

    let mut payload = Vec::new();
    push_len_prefixed(&mut payload, name.as_bytes())?;
    payload.extend_from_slice(&plaintext);

    encode_bundle(BUNDLE_TYPE_FILE, recipient_public_key, &payload)
}

/// Structurally verify and seal a complete KQTF container for portable
/// transport. Structure is not signatures or trust: every retained revision,
/// pending ones included, travels, and the recipient's store judges them.
///
/// `container` is deliberately bytes: KQTF contains payloads, signatures,
/// and hashes and is not UTF-8 text. The logical name is read from that
/// verified container so the bundle cannot describe it under another name.
pub fn export_tracked_file(container: &[u8], recipient_public_key: &[u8; 32]) -> Result<Vec<u8>> {
    let tracked = TrackedFile::decode(container)?;
    let mut payload = Vec::new();
    push_len_prefixed(&mut payload, tracked.logical_name.as_bytes())?;
    payload.extend_from_slice(container);
    encode_bundle(BUNDLE_TYPE_TRACKED_FILE, recipient_public_key, &payload)
}

/// Seal an already signed API key issue (`api_key_delivery::sign`) as a
/// portable `KQXB` file for `recipient_public_key`. The payload is signed
/// before it is sealed, so this adds no trust: it only chooses the carrier.
pub fn export_key_issue(signed_payload: &[u8], recipient_public_key: &[u8; 32]) -> Result<Vec<u8>> {
    encode_bundle(BUNDLE_TYPE_API_KEY, recipient_public_key, signed_payload)
}

fn encode_bundle(
    bundle_type: u8,
    recipient_public_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    envelope::seal(
        envelope::EXPORT_BUNDLE,
        bundle_type,
        recipient_public_key,
        plaintext,
    )
}

#[cfg(test)]
#[path = "export/tests.rs"]
mod tests;
