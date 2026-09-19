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
//! kind byte: 1 = credential, 2 = file. The recipient's name/label stays
//! inside the sealed payload rather than the outer header — a credential
//! label or file name can be sensitive on its own, and the outer header is
//! the one part of a bundle that's never encrypted.
//! The sealed payload's plaintext (before sealing) is, for a credential:
//!   label_len (2) | label (label_len) | username_len (2) | username (username_len)
//!   | password_len (2) | password (password_len)
//! (username_len = 0 means no username) and for a file:
//!   name_len (2) | name (name_len) | file_bytes (remainder)

use crate::envelope::{self, push_len_prefixed};
use crate::error::Result;
use crate::{locked_files, vault};
use rusqlite::{params, Connection};

const BUNDLE_TYPE_CREDENTIAL: u8 = 1;
const BUNDLE_TYPE_FILE: u8 = 2;

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
    let name: String = conn.query_row(
        "SELECT name FROM password_locked_files WHERE id = ?1",
        params![file_id],
        |row| row.get(0),
    )?;
    let plaintext = locked_files::unlock_file(conn, file_id, password)?;

    let mut payload = Vec::new();
    push_len_prefixed(&mut payload, name.as_bytes())?;
    payload.extend_from_slice(&plaintext);

    encode_bundle(BUNDLE_TYPE_FILE, recipient_public_key, &payload)
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
