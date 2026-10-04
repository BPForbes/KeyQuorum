//! `keyquorum deliver`: sealed file delivery between labels
//! ([`crate::file_delivery`]). A letter is signed by the sender, sealed to
//! the recipient's registered encryption key, and carried by `relay push`
//! (or `--push`) like any other `.kqpb`; the recipient opens it, which
//! verifies the sender against the signing key this store has registered,
//! and answers with a signed accept/reject sealed back to the sender.

use super::env::{self, errln, outln};
use super::profile;
use super::{read_key_array_32, resolve_relay_auth, usage, write_delivery_packages, Envelope};
use crate::device::SlotSecrets;
use crate::error::{Error, Result};
use crate::keys::{self, KeyType};
use crate::relay::{self, ApiKeyScope};
use crate::{file_delivery, private_bridge};
use clap::Subcommand;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum DeliverCommand {
    /// Seal a file to a registered label. Signed with your signing key and
    /// sealed to the recipient's encryption key; answers come back to your
    /// registered encryption key.
    Send {
        /// File to send
        #[arg(long)]
        file: PathBuf,
        /// Recipient label (its encryption key must be registered here)
        #[arg(long)]
        to: String,
        /// Your label (default: from `keyquorum use`)
        #[arg(long = "as")]
        as_label: Option<String>,
        /// Your identity slot, container=label (signs the letter; default:
        /// from `keyquorum use`)
        #[arg(long = "slot", conflicts_with = "signing_key_file")]
        slot: Option<String>,
        /// Your signing private key file, instead of --slot
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        /// Name the recipient sees (defaults to the file's name)
        #[arg(long)]
        name: Option<String>,
        /// Write the sealed letter to this directory
        #[arg(long, required_unless_present = "push")]
        output_dir: Option<PathBuf>,
        /// Upload the letter to the relay (inbox.push key)
        #[arg(long)]
        push: bool,
        #[arg(long, requires = "push")]
        url: Option<String>,
        #[arg(long, requires = "push")]
        api_key: Option<String>,
        /// Set by `keyquorum send`: queue the letter in the sender's outbox
        /// ring and send it from there. Never a flag of `deliver send`.
        #[arg(skip)]
        via_outbox: bool,
    },
    /// Open a letter addressed to you: verify the sender, keep the file, and
    /// seal a signed acknowledgement back to them
    Open {
        /// The delivery letter (.kqpb); default: the one opened a moment ago
        #[arg(long)]
        file: Option<PathBuf>,
        /// Your identity slot, container=label (unseals and signs the answer;
        /// default: from `keyquorum use`)
        #[arg(long = "slot", conflicts_with_all = ["share_file", "signing_key_file"])]
        slot: Option<String>,
        /// Your encryption private key file, instead of --slot
        #[arg(long, requires = "signing_key_file")]
        share_file: Option<String>,
        /// Your signing private key file, with --share-file
        #[arg(long, requires = "share_file")]
        signing_key_file: Option<PathBuf>,
        /// Write the file here instead of stdout
        #[arg(long, conflicts_with_all = ["reject", "save_dir"])]
        save: Option<PathBuf>,
        /// Write the file into this directory under the name the sender gave it
        #[arg(long, conflicts_with = "reject")]
        save_dir: Option<PathBuf>,
        /// Refuse the file and say so in the acknowledgement
        #[arg(long)]
        reject: bool,
        /// Write the sealed acknowledgement to this directory
        #[arg(long, required_unless_present = "push_ack")]
        ack_dir: Option<PathBuf>,
        /// Upload the acknowledgement to the relay (inbox.push key)
        #[arg(long)]
        push_ack: bool,
        #[arg(long, requires = "push_ack")]
        url: Option<String>,
        #[arg(long, requires = "push_ack")]
        api_key: Option<String>,
    },
    /// Check an acknowledgement sealed back to you
    Ack {
        /// The acknowledgement (.kqpb); default: the one checked a moment ago
        #[arg(long)]
        file: Option<PathBuf>,
        /// Your identity slot, container=label (default: from `keyquorum use`)
        #[arg(long = "slot", conflicts_with = "share_file")]
        slot: Option<String>,
        /// Your encryption private key file, instead of --slot
        #[arg(long)]
        share_file: Option<String>,
    },
}

pub fn run(conn: &Connection, command: DeliverCommand) -> Result<()> {
    match command {
        DeliverCommand::Send {
            file,
            to,
            as_label,
            slot,
            signing_key_file,
            name,
            output_dir,
            push,
            url,
            api_key,
            via_outbox,
        } => {
            let contents = env::read(&file)?;
            let file_name = match name {
                Some(name) => name,
                None => file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .ok_or_else(|| usage("--file has no file name; pass --name"))?,
            };
            seal_and_carry(
                conn,
                Outbound {
                    contents: &contents,
                    file_name: &file_name,
                    to: &to,
                    as_label,
                    slot,
                    signing_key_file,
                    output_dir,
                    push,
                    url,
                    api_key,
                    via_outbox,
                },
            )?;
        }
        DeliverCommand::Open {
            file,
            slot,
            share_file,
            signing_key_file,
            save,
            save_dir,
            reject,
            ack_dir,
            push_ack,
            url,
            api_key,
        } => {
            let typed = file.is_some();
            let file = profile::recent_or(
                conn,
                "deliver-open:file",
                file.map(|f| f.display().to_string()),
                push_ack,
            )?
            .map(PathBuf::from)
            .ok_or_else(|| usage("--file is required"))?;
            let slot = match share_file {
                Some(_) => slot,
                None => Some(profile::resolve_identity(conn, None, slot.as_deref())?.slot),
            };
            let bytes = env::read(&file)?;
            let secrets = recipient_secrets(slot, share_file, signing_key_file)?;
            let letter = file_delivery::open_letter(conn, &secrets.encryption, &bytes)?;
            require_recipient_key(conn, &letter.recipient_label, &secrets.encryption)?;
            errln!(
                "From {} to {}: {} ({} bytes), signature verified",
                letter.sender_label,
                letter.recipient_label,
                letter.file_name,
                letter.contents.len()
            );
            let accepted = !reject;
            if accepted {
                let target = match (save, save_dir) {
                    (Some(path), _) => Some(path),
                    (None, Some(dir)) => {
                        env::create_dir_all(&dir)?;
                        Some(dir.join(super::sanitize_label(&letter.file_name)?))
                    }
                    (None, None) => None,
                };
                match target {
                    Some(path) => {
                        // A retry after a failed answer upload finds the file
                        // it saved the first time; the same bytes are not a
                        // conflict, anything else still refuses.
                        if env::exists(&path) && env::read(&path)? == letter.contents {
                            outln!("Already saved {} to {}", letter.file_name, path.display());
                        } else {
                            env::write_new(&path, &letter.contents)?;
                            outln!("Saved {} to {}", letter.file_name, path.display());
                        }
                    }
                    None => env::stdout_bytes(&letter.contents)?,
                }
            } else {
                errln!("Rejected {}", letter.file_name);
            }
            let ack = Letter {
                name: format!("{}-ack", hex::encode(letter.delivery_id)),
                bytes: file_delivery::seal_ack(&letter, &secrets.signing, accepted)?,
            };
            carry(conn, &ack, ack_dir.as_deref(), push_ack, url, api_key)?;
            if typed {
                profile::remember(conn, "deliver-open:file", &file.display().to_string());
            }
        }
        DeliverCommand::Ack {
            file,
            slot,
            share_file,
        } => {
            let typed = file.is_some();
            let file = profile::recent_or(
                conn,
                "deliver-ack:file",
                file.map(|f| f.display().to_string()),
                false,
            )?
            .map(PathBuf::from)
            .ok_or_else(|| usage("--file is required"))?;
            let slot = match share_file {
                Some(_) => slot,
                None => Some(profile::resolve_identity(conn, None, slot.as_deref())?.slot),
            };
            let bytes = env::read(&file)?;
            let secret = super::encryption_secret_from(share_file.as_deref(), slot.as_deref())?;
            let ack = file_delivery::open_ack(conn, &secret, &bytes)?;
            outln!(
                "Delivery {} {} by {}",
                hex::encode(ack.delivery_id),
                if ack.accepted { "accepted" } else { "rejected" },
                ack.recipient_label
            );
            if typed {
                profile::remember(conn, "deliver-ack:file", &file.display().to_string());
            }
        }
    }
    Ok(())
}

/// One file, sealed to one label and carried: written to a directory,
/// uploaded, or both. `deliver send` reads the file and `send --quorum-file`
/// unlocks it; either way the bytes arrive here and nothing touches disk.
pub(super) struct Outbound<'a> {
    pub(super) contents: &'a [u8],
    pub(super) file_name: &'a str,
    pub(super) to: &'a str,
    pub(super) as_label: Option<String>,
    pub(super) slot: Option<String>,
    pub(super) signing_key_file: Option<PathBuf>,
    pub(super) output_dir: Option<PathBuf>,
    pub(super) push: bool,
    pub(super) url: Option<String>,
    pub(super) api_key: Option<String>,
    /// Queue in the sender's outbox ring and send from it (`keyquorum send`).
    pub(super) via_outbox: bool,
}

#[inline(never)]
pub(super) fn seal_and_carry(conn: &Connection, out: Outbound<'_>) -> Result<()> {
    let Outbound {
        contents,
        file_name,
        to,
        as_label,
        slot,
        signing_key_file,
        output_dir,
        push,
        url,
        api_key,
        via_outbox,
    } = out;
    let (as_label, slot) =
        profile::resolve_signer(conn, as_label, slot, signing_key_file.as_deref())?;
    let (signing_secret, encryption_public) = sender_keys(conn, slot, signing_key_file, &as_label)?;
    let recipient = registered_encryption_key(conn, to)?;
    let sealed = file_delivery::seal_letter(&file_delivery::Outgoing {
        sender_label: &as_label,
        sender_signing_secret: &signing_secret,
        sender_encryption_public: &encryption_public,
        recipient_label: to,
        recipient_encryption_public: &recipient,
        file_name,
        contents,
    })?;
    let letter = Letter {
        name: hex::encode(sealed.delivery_id),
        bytes: sealed.bytes,
    };
    outln!(
        "Sealed {file_name} to {to} (delivery {})",
        hex::encode(sealed.delivery_id)
    );
    if via_outbox {
        let transport = (output_dir.as_deref(), url, api_key);
        return super::outbox_cmd::carry_via_outbox(
            conn,
            &as_label,
            to,
            &letter.bytes,
            None,
            transport,
        );
    }
    carry(conn, &letter, output_dir.as_deref(), push, url, api_key)
}

/// The sender's signing secret and the encryption key answers come back to.
pub(super) fn sender_keys(
    conn: &Connection,
    slot: Option<String>,
    signing_key_file: Option<PathBuf>,
    as_label: &str,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    match (slot, signing_key_file) {
        (Some(slot), None) => {
            let secrets = super::open_slot_secrets(&slot)?;
            Ok((secrets.signing_secret, secrets.encryption_public))
        }
        (None, Some(path)) => Ok((
            Zeroizing::new(read_key_array_32(&path)?),
            private_bridge::encryption_public_for_label(conn, None, as_label)?,
        )),
        _ => Err(usage("pass --slot or --signing-key-file")),
    }
}

/// A sealed `.kqpb` addressed by its delivery id.
pub(super) struct Letter {
    pub(super) name: String,
    pub(super) bytes: Vec<u8>,
}

impl Envelope for Letter {
    fn label(&self) -> &str {
        &self.name
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Write the letter to `output_dir`, upload it, or both.
pub(super) fn carry(
    conn: &Connection,
    letter: &Letter,
    output_dir: Option<&Path>,
    push: bool,
    url: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    if let Some(dir) = output_dir {
        env::create_dir_all(dir)?;
        let written = write_delivery_packages(dir, std::slice::from_ref(letter))?.keep();
        for path in written {
            outln!("Wrote {}", path.display());
        }
    }
    if push {
        let (url, api_key) = resolve_relay_auth(conn, url, api_key, ApiKeyScope::InboxPush)?;
        let accepted = relay::push_inbox(&env::EnvRelay, &url, &api_key, &letter.bytes)?;
        outln!(
            "Relay stored letter {} for {}",
            accepted.id,
            accepted.recipient_fingerprint
        );
    }
    Ok(())
}

/// The recipient label in a letter is the sender's claim. It must name the
/// key that opened the letter, or a delivery, and the answer to it, would be
/// credited to a label that took no part.
pub(super) fn require_recipient_key(
    conn: &Connection,
    recipient_label: &str,
    opened_with: &[u8; 32],
) -> Result<()> {
    if crate::file_delivery::recipient_owns_key(conn, recipient_label, opened_with)? {
        Ok(())
    } else {
        Err(usage(&format!(
            "the letter names {recipient_label} as recipient, but this store has no encryption key for that label matching the key that opened it"
        )))
    }
}

pub(super) fn registered_encryption_key(conn: &Connection, label: &str) -> Result<[u8; 32]> {
    let key = keys::active_keys_for(conn, label, KeyType::Encryption)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            usage(&format!(
                "no encryption key is registered for {label} in this store; register one first"
            ))
        })?;
    key.public_key
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

pub(super) struct RecipientSecrets {
    pub(super) encryption: Zeroizing<[u8; 32]>,
    pub(super) signing: Zeroizing<[u8; 32]>,
}

pub(super) fn recipient_secrets(
    slot: Option<String>,
    share_file: Option<String>,
    signing_key_file: Option<PathBuf>,
) -> Result<RecipientSecrets> {
    match (slot, share_file, signing_key_file) {
        (Some(slot), None, None) => {
            let SlotSecrets {
                encryption_secret,
                signing_secret,
                ..
            } = super::open_slot_secrets(&slot)?;
            Ok(RecipientSecrets {
                encryption: encryption_secret,
                signing: signing_secret,
            })
        }
        (None, Some(share_file), Some(signing_key_file)) => Ok(RecipientSecrets {
            encryption: Zeroizing::new(read_key_array_32(Path::new(&share_file))?),
            signing: Zeroizing::new(read_key_array_32(&signing_key_file)?),
        }),
        _ => Err(usage(
            "pass --slot, or --share-file with --signing-key-file",
        )),
    }
}
