//! Physical containers and the device count a quorum has to satisfy.
//!
//! Two custody stories share one check:
//!
//! - **One key, one device.** A hardware key with no placement row is its
//!   own device. Distinct key files — the original exchange — count as
//!   distinct devices, including when `minimum_physical_devices` is more
//!   than one. Presenting the same key twice still counts once.
//! - **One container, many slots.** `keyquorum-device` stores several
//!   identities under one `device.kq`. A placement row, written only from
//!   a container this process opened, ties those keys to that container's
//!   id. They are not separate devices.
//!
//! The directory layout is an index. Each slot's secret keys live in an
//! Argon2id-wrapped token, and the label inside that token has to match
//! the slot being opened. Logical mode lets several of those slots satisfy
//! Shamir together; it does not make them count as several devices.

use crate::crypto::{self, NONCE_LEN, SALT_LEN};
use crate::envelope::{push_len_prefixed, take_array, take_len_prefixed, take_u8, utf8};
use crate::error::{Error, Result};
use crate::keys::{self, KeyType};
use crate::locked_files;
use crate::signing;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEVICE_MAGIC: &[u8; 4] = b"KQDV";
const DEVICE_VERSION: u8 = 2;
const TOKEN_MAGIC: &[u8; 4] = b"KQST";
const TOKEN_VERSION: u8 = 2;
const DESC_DOMAIN: &[u8] = b"KQ-DEVICE-DESC-v2";
const DEVICE_ID_LEN: usize = 16;
const SOLO_DOMAIN: &[u8] = b"KQ-SOLO-DEVICE-v1";

/// How a split treats keys that share a physical device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyMode {
    /// One key per device. The original exchange is this mode with no
    /// placement rows: each key file is a device.
    Hardware,
    /// Several slot identities on one container may meet a Shamir threshold.
    /// They still contribute a single `device_id` to the physical count.
    Logical,
}

/// Extra signature required at unlock, on top of Shamir and the device count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockApproval {
    None,
    /// Each leaf that contributed a share needs its direct parent's signature.
    Parent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyPolicy {
    pub mode: CustodyMode,
    pub minimum_physical_devices: u8,
    pub unlock_approval: UnlockApproval,
}

impl Default for CustodyPolicy {
    fn default() -> Self {
        Self {
            mode: CustodyMode::Hardware,
            minimum_physical_devices: 1,
            unlock_approval: UnlockApproval::None,
        }
    }
}

/// A leaf share that actually went into a successful reconstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsedLeaf {
    pub hardware_key_id: i64,
    pub leaf_label: String,
}

/// One physical device among the shares that reconstructed a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedDevice {
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Set when a placement binds this key to a container slot.
    /// `None` is the original one-key one-device exchange.
    pub slot_label: Option<String>,
    pub hardware_key_ids: Vec<i64>,
    pub leaf_labels: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SlotRecord {
    pub label: String,
    pub encryption_public: [u8; 32],
    pub signing_public: [u8; 32],
}

/// A container directory this process opened. `device_id` is the id inside
/// the signed `device.kq`, and each slot token seals that same id. The
/// directory path is not the device identity.
#[derive(Clone, Debug)]
pub struct Container {
    path: PathBuf,
    device_id: [u8; DEVICE_ID_LEN],
    verify_key: [u8; 32],
    slots: Vec<SlotRecord>,
}

impl Container {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn device_id(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.device_id
    }

    /// Ed25519 public key that signs `device.kq`. The id is whatever this
    /// signature covers, not the directory path.
    pub fn verify_key(&self) -> &[u8; 32] {
        &self.verify_key
    }

    pub fn slots(&self) -> &[SlotRecord] {
        &self.slots
    }

    pub fn slot(&self, label: &str) -> Option<&SlotRecord> {
        self.slots.iter().find(|slot| slot.label == label)
    }
}

/// Secrets unwrapped from one slot. Dropped values are zeroized.
pub struct SlotSecrets {
    pub label: String,
    pub encryption_secret: Zeroizing<[u8; 32]>,
    pub signing_secret: Zeroizing<[u8; 32]>,
    pub encryption_public: [u8; 32],
    pub signing_public: [u8; 32],
}

/// What [`provision`] minted. The CLI prints only the public halves.
pub struct ProvisionedSlot {
    pub label: String,
    pub encryption_public: [u8; 32],
    pub signing_public: [u8; 32],
    pub encryption_secret: Zeroizing<[u8; 32]>,
    pub signing_secret: Zeroizing<[u8; 32]>,
}

/// Create an empty container at `path` (a directory, or a mounted USB).
pub fn init(path: &Path) -> Result<Container> {
    fs::create_dir_all(path)?;
    fs::create_dir_all(path.join("vault"))?;
    let descriptor = path.join("device.kq");
    if descriptor.exists() {
        return Err(Error::InvalidDevice);
    }
    let mut device_id = [0u8; DEVICE_ID_LEN];
    OsRng.fill_bytes(&mut device_id);
    let (secret, verify_key) = keys::generate_signing_keypair();
    locked_files::write_owner_only(&path.join("device.skey"), secret.as_slice())?;
    let container = Container {
        path: path.to_path_buf(),
        device_id,
        verify_key,
        slots: Vec::new(),
    };
    store_descriptor(&container)?;
    Ok(container)
}

/// A container that only carries a device id and verify key. It has no
/// directory and no slot tokens, so it can check a signed package without
/// the source device's secrets.
pub fn verification_container(device_id: [u8; DEVICE_ID_LEN], verify_key: [u8; 32]) -> Container {
    Container {
        path: PathBuf::new(),
        device_id,
        verify_key,
        slots: Vec::new(),
    }
}

/// Read `device.kq`. Does not decrypt any slot.
pub fn open(path: &Path) -> Result<Container> {
    let bytes = fs::read(path.join("device.kq"))?;
    let (device_id, verify_key, slots) = decode_descriptor(&bytes)?;
    Ok(Container {
        path: path.to_path_buf(),
        device_id,
        verify_key,
        slots,
    })
}

/// Mint a new encryption key and signing key, seal them under `passphrase`,
/// and index the slot in `device.kq`.
pub fn provision(
    container: &mut Container,
    label: &str,
    passphrase: &str,
) -> Result<ProvisionedSlot> {
    validate_slot_label(label)?;
    if passphrase.is_empty() {
        return Err(Error::InvalidPassword);
    }
    if container.slot(label).is_some() {
        return Err(Error::InvalidSlot);
    }
    let (encryption_secret, encryption_public) = keys::generate_encryption_keypair();
    let (signing_secret, signing_public) = keys::generate_signing_keypair();
    write_token(
        container,
        label,
        passphrase,
        &encryption_secret,
        &signing_secret,
    )?;
    container.slots.push(SlotRecord {
        label: label.to_string(),
        encryption_public,
        signing_public,
    });
    store_descriptor(container)?;
    Ok(ProvisionedSlot {
        label: label.to_string(),
        encryption_public,
        signing_public,
        encryption_secret,
        signing_secret,
    })
}

/// Decrypt one slot. The label inside the token must match `label`, and
/// the derived public keys must match `device.kq`.
pub fn open_slot(container: &Container, label: &str, passphrase: &str) -> Result<SlotSecrets> {
    let record = container.slot(label).ok_or(Error::InvalidSlot)?;
    let bytes = fs::read(token_path(container, label)?)?;
    let plain = decrypt_token(&bytes, passphrase)?;
    let (token_label, token_device, encryption_secret, signing_secret) =
        decode_token_plain(&plain)?;
    if token_label != label || token_device != container.device_id {
        return Err(Error::InvalidSlot);
    }
    let encryption_public = keys::encryption_public_from_secret(&encryption_secret);
    let signing_public = signing_public_from_secret(&signing_secret);
    if encryption_public != record.encryption_public || signing_public != record.signing_public {
        return Err(Error::InvalidSlot);
    }
    Ok(SlotSecrets {
        label: label.to_string(),
        encryption_secret,
        signing_secret,
        encryption_public,
        signing_public,
    })
}

/// Move a slot onto another container. The keypair does not change; the
/// destination container's `device_id` is what a later [`bind_slot`] records.
pub fn relocate_slot(
    from: &mut Container,
    to: &mut Container,
    label: &str,
    passphrase: &str,
) -> Result<()> {
    if from.device_id == to.device_id {
        return Err(Error::InvalidDevice);
    }
    if to.slot(label).is_some() {
        return Err(Error::InvalidSlot);
    }
    let secrets = open_slot(from, label, passphrase)?;
    write_token(
        to,
        label,
        passphrase,
        &secrets.encryption_secret,
        &secrets.signing_secret,
    )?;
    to.slots.push(SlotRecord {
        label: label.to_string(),
        encryption_public: secrets.encryption_public,
        signing_public: secrets.signing_public,
    });
    store_descriptor(to)?;
    let source = token_path(from, label)?;
    fs::remove_file(&source)?;
    let slot_dir = source
        .parent()
        .map(Path::to_path_buf)
        .ok_or(Error::InvalidPath)?;
    let _ = fs::remove_dir(&slot_dir);
    from.slots.retain(|slot| slot.label != label);
    store_descriptor(from)?;
    Ok(())
}

/// Record placements for the slot's registered keys. The passphrase opens
/// the token, and the device id sealed inside that token has to match the
/// signed `device.kq`. A rewritten descriptor id cannot bind the slot.
pub fn bind_slot(
    conn: &Connection,
    container: &Container,
    slot_label: &str,
    passphrase: &str,
) -> Result<()> {
    let secrets = open_slot(container, slot_label, passphrase)?;
    let slot = container.slot(slot_label).ok_or(Error::InvalidSlot)?;
    if secrets.encryption_public != slot.encryption_public {
        return Err(Error::InvalidSlot);
    }
    let encryption = keys::get_key_by_public_key(conn, &slot.encryption_public)?;
    if encryption.key_type != KeyType::Encryption {
        return Err(Error::WrongKeyType);
    }
    upsert_placement(conn, encryption.id, &container.device_id, slot_label)?;
    if let Ok(signing) = keys::get_key_by_public_key(conn, &slot.signing_public) {
        if signing.key_type != KeyType::Signing {
            return Err(Error::WrongKeyType);
        }
        upsert_placement(conn, signing.id, &container.device_id, slot_label)?;
    }
    Ok(())
}

/// Install an existing keypair into a slot. Used when a transfer commits
/// possession on the destination. The token is sealed to this container's
/// device id.
pub fn install_slot(
    container: &mut Container,
    label: &str,
    passphrase: &str,
    encryption_secret: &[u8; 32],
    signing_secret: &[u8; 32],
) -> Result<SlotRecord> {
    validate_slot_label(label)?;
    if passphrase.is_empty() {
        return Err(Error::InvalidPassword);
    }
    if container.slot(label).is_some() {
        return Err(Error::InvalidSlot);
    }
    write_token(
        container,
        label,
        passphrase,
        encryption_secret,
        signing_secret,
    )?;
    let record = SlotRecord {
        label: label.to_string(),
        encryption_public: keys::encryption_public_from_secret(encryption_secret),
        signing_public: signing_public_from_secret(signing_secret),
    };
    container.slots.push(record.clone());
    store_descriptor(container)?;
    Ok(record)
}

/// Delete a slot's token and drop it from the descriptor. Hierarchy code
/// may keep a ghost row; this function only removes usable key material.
pub fn remove_slot(container: &mut Container, label: &str) -> Result<()> {
    let source = token_path(container, label)?;
    if source.exists() {
        fs::remove_file(&source)?;
    }
    if let Some(dir) = source.parent() {
        let _ = fs::remove_dir(dir);
    }
    let before = container.slots.len();
    container.slots.retain(|slot| slot.label != label);
    if container.slots.len() == before && !source.exists() {
        return Err(Error::InvalidSlot);
    }
    store_descriptor(container)?;
    Ok(())
}

pub(crate) fn device_signing_secret(container: &Container) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = fs::read(container.path.join("device.skey"))?;
    let secret: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidDevice)?;
    Ok(Zeroizing::new(secret))
}

/// Prompt twice and refuse an empty or mismatched passphrase.
pub fn confirm_passphrase(first_prompt: &str, second_prompt: &str) -> Result<String> {
    let passphrase = prompt_passphrase(first_prompt)?;
    let again = prompt_passphrase(second_prompt)?;
    if passphrase != again {
        return Err(Error::InvalidPassword);
    }
    Ok(passphrase)
}

pub fn set_custody_policy(conn: &Connection, key_id: i64, policy: &CustodyPolicy) -> Result<()> {
    if policy.minimum_physical_devices < 1 {
        return Err(Error::InvalidQuorumThreshold);
    }
    let updated = conn.execute(
        "UPDATE keys
         SET custody_mode = ?1, minimum_physical_devices = ?2, unlock_approval = ?3
         WHERE id = ?4",
        params![
            policy.mode.as_str(),
            i64::from(policy.minimum_physical_devices),
            policy.unlock_approval.as_str(),
            key_id,
        ],
    )?;
    if updated != 1 {
        return Err(Error::TreeNotFound);
    }
    Ok(())
}

pub fn custody_policy(conn: &Connection, key_id: i64) -> Result<CustodyPolicy> {
    let (mode, minimum, approval): (String, i64, String) = conn
        .query_row(
            "SELECT custody_mode, minimum_physical_devices, unlock_approval
             FROM keys WHERE id = ?1",
            params![key_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(Error::TreeNotFound)?;
    let minimum = u8::try_from(minimum).map_err(|_| Error::InvalidDevice)?;
    Ok(CustodyPolicy {
        mode: CustodyMode::parse(&mode)?,
        minimum_physical_devices: minimum,
        unlock_approval: UnlockApproval::parse(&approval)?,
    })
}

/// Device id for a key that was never placed on a container: the key is
/// the device. Stable for a given public key, distinct across keys.
pub fn solo_device_id(public_key: &[u8]) -> [u8; DEVICE_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(SOLO_DOMAIN);
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut id = [0u8; DEVICE_ID_LEN];
    id.copy_from_slice(&digest[..DEVICE_ID_LEN]);
    id
}

/// Group `used` by physical device and apply the tree's custody policy.
/// A placement wins over [`solo_device_id`]. Keys with no placement stay
/// on the one-key one-device path. A ghost possession cannot contribute.
pub fn enforce_devices(
    conn: &Connection,
    key_id: i64,
    used: &[UsedLeaf],
) -> Result<Vec<PresentedDevice>> {
    let groups = classify_devices(conn, key_id, used)?;
    let policy = custody_policy(conn, key_id)?;
    if groups.len() < usize::from(policy.minimum_physical_devices) {
        return Err(Error::PhysicalDevicesNotMet);
    }
    Ok(groups)
}

/// Device groups for `used`, including the hardware-mode custody check.
/// Does not apply `minimum_physical_devices`.
pub(crate) fn classify_devices(
    conn: &Connection,
    key_id: i64,
    used: &[UsedLeaf],
) -> Result<Vec<PresentedDevice>> {
    if used.is_empty() {
        return Err(Error::QuorumNotMet);
    }
    let policy = custody_policy(conn, key_id)?;
    let mut groups: Vec<PresentedDevice> = Vec::new();
    for leaf in used {
        if leaf_is_ghost(conn, leaf.hardware_key_id)? {
            return Err(Error::GhostDenied);
        }
        let key = keys::get_key(conn, leaf.hardware_key_id)?;
        let (device_id, slot_label) = device_for_key(conn, &key)?;
        if let Some(group) = groups.iter_mut().find(|group| group.device_id == device_id) {
            if !group.hardware_key_ids.contains(&leaf.hardware_key_id) {
                group.hardware_key_ids.push(leaf.hardware_key_id);
            }
            group.leaf_labels.push(leaf.leaf_label.clone());
            if group.slot_label.is_none() {
                group.slot_label.clone_from(&slot_label);
            }
        } else {
            groups.push(PresentedDevice {
                device_id,
                slot_label,
                hardware_key_ids: vec![leaf.hardware_key_id],
                leaf_labels: vec![leaf.leaf_label.clone()],
            });
        }
    }
    if policy.mode == CustodyMode::Hardware {
        for group in &groups {
            let distinct: HashSet<i64> = group.hardware_key_ids.iter().copied().collect();
            if distinct.len() > 1 {
                return Err(Error::CustodyViolation);
            }
        }
    }
    Ok(groups)
}

/// True when this hardware key is a ghost identity on this store.
/// Keys with no possession row stay on the original exchange.
pub(crate) fn leaf_is_ghost(conn: &Connection, hardware_key_id: i64) -> Result<bool> {
    let state: Option<String> = conn
        .query_row(
            "SELECT p.state
             FROM key_possession p
             JOIN key_identities i ON i.id = p.identity_id
             JOIN hardware_keys h ON h.public_key = i.enc_public
             WHERE h.id = ?1",
            params![hardware_key_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(state.as_deref() == Some("ghost"))
}

pub fn format_presentation(devices: &[PresentedDevice]) -> String {
    let mut parts = Vec::with_capacity(devices.len());
    for device in devices {
        let id = hex::encode(device.device_id);
        let leaves = device.leaf_labels.join(",");
        let part = match &device.slot_label {
            Some(slot) => format!("device {id} slot {slot} ({leaves})"),
            None => format!("device {id} key ({leaves})"),
        };
        parts.push(part);
    }
    if parts.is_empty() {
        "no device".to_string()
    } else {
        parts.join("; ")
    }
}

pub fn unwrap_share(secrets: &SlotSecrets, wrapped: &[u8]) -> Result<Vec<u8>> {
    let secret = crypto_box::SecretKey::from(*secrets.encryption_secret);
    secret
        .unseal(wrapped)
        .map_err(|_| Error::IntegrityCheckFailed)
}

pub fn sign_message(secrets: &SlotSecrets, message: &[u8]) -> [u8; 64] {
    signing::sign(&secrets.signing_secret, message)
}

pub fn prompt_passphrase(prompt: &str) -> Result<String> {
    let passphrase = rpassword::prompt_password(prompt)?;
    if passphrase.is_empty() {
        return Err(Error::InvalidPassword);
    }
    Ok(passphrase)
}

impl CustodyMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hardware => "hardware",
            Self::Logical => "logical",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "hardware" => Ok(Self::Hardware),
            "logical" => Ok(Self::Logical),
            _ => Err(Error::InvalidDevice),
        }
    }
}

impl UnlockApproval {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Parent => "parent",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "parent" => Ok(Self::Parent),
            _ => Err(Error::InvalidDevice),
        }
    }
}

fn device_for_key(
    conn: &Connection,
    key: &keys::HardwareKey,
) -> Result<([u8; DEVICE_ID_LEN], Option<String>)> {
    let placed: Option<(Vec<u8>, String)> = conn
        .query_row(
            "SELECT device_id, slot_label FROM device_placements WHERE hardware_key_id = ?1",
            params![key.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((device_id, slot_label)) = placed {
        let id: [u8; DEVICE_ID_LEN] = device_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidDevice)?;
        return Ok((id, Some(slot_label)));
    }
    Ok((solo_device_id(&key.public_key), None))
}

fn upsert_placement(
    conn: &Connection,
    hardware_key_id: i64,
    device_id: &[u8; DEVICE_ID_LEN],
    slot_label: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO device_placements (hardware_key_id, device_id, slot_label)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(hardware_key_id) DO UPDATE SET
            device_id = excluded.device_id,
            slot_label = excluded.slot_label",
        params![hardware_key_id, device_id.as_slice(), slot_label],
    )?;
    Ok(())
}

pub(crate) fn validate_slot_label(label: &str) -> Result<()> {
    if label.is_empty()
        || label.len() > 128
        || label.contains("..")
        || !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err(Error::InvalidSlot);
    }
    Ok(())
}

fn token_path(container: &Container, label: &str) -> Result<PathBuf> {
    validate_slot_label(label)?;
    Ok(container
        .path
        .join("vault")
        .join(format!("slot-{label}"))
        .join("token.kqst"))
}

fn write_token(
    container: &Container,
    label: &str,
    passphrase: &str,
    encryption_secret: &[u8; 32],
    signing_secret: &[u8; 32],
) -> Result<()> {
    let path = token_path(container, label)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let plain = encode_token_plain(
        label,
        &container.device_id,
        encryption_secret,
        signing_secret,
    )?;
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(passphrase, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plain);
    let mut bytes = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    bytes.extend_from_slice(TOKEN_MAGIC);
    bytes.push(TOKEN_VERSION);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    locked_files::write_owner_only(&path, &bytes)
}

fn decrypt_token(bytes: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if bytes.len() < 4 + 1 + SALT_LEN + NONCE_LEN + 16 || &bytes[..4] != TOKEN_MAGIC {
        return Err(Error::InvalidDevice);
    }
    let mut data = &bytes[4..];
    let version = take_u8(&mut data)?;
    if version != TOKEN_VERSION {
        return Err(Error::InvalidDevice);
    }
    let salt: [u8; SALT_LEN] = take_array(&mut data)?;
    let nonce: [u8; NONCE_LEN] = take_array(&mut data)?;
    let key = crypto::derive_key(passphrase, &salt)?;
    crypto::decrypt(&key, &nonce, data).map_err(|_| Error::InvalidPassword)
}

fn encode_token_plain(
    label: &str,
    device_id: &[u8; DEVICE_ID_LEN],
    encryption: &[u8; 32],
    signing: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, label.as_bytes())?;
    out.extend_from_slice(device_id);
    out.extend_from_slice(encryption);
    out.extend_from_slice(signing);
    Ok(out)
}

type TokenPlain = (
    String,
    [u8; DEVICE_ID_LEN],
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

fn decode_token_plain(bytes: &[u8]) -> Result<TokenPlain> {
    let mut data = bytes;
    let label = utf8(take_len_prefixed(&mut data)?)?;
    let device_id = take_array(&mut data)?;
    let encryption = Zeroizing::new(take_array(&mut data)?);
    let signing = Zeroizing::new(take_array(&mut data)?);
    if !data.is_empty() {
        return Err(Error::InvalidDevice);
    }
    Ok((label, device_id, encryption, signing))
}

fn store_descriptor(container: &Container) -> Result<()> {
    let secret = device_signing_secret(container)?;
    let preimage = descriptor_preimage(
        &container.device_id,
        &container.verify_key,
        &container.slots,
    )?;
    let signature = crate::signing::sign(&secret, &preimage);
    let bytes = encode_descriptor(
        &container.device_id,
        &container.verify_key,
        &signature,
        &container.slots,
    )?;
    let path = container.path.join("device.kq");
    let tmp = container.path.join(".device.kq.tmp");
    if tmp.exists() {
        fs::remove_file(&tmp)?;
    }
    locked_files::write_owner_only(&tmp, &bytes)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn descriptor_preimage(
    device_id: &[u8; DEVICE_ID_LEN],
    verify_key: &[u8; 32],
    slots: &[SlotRecord],
) -> Result<Vec<u8>> {
    let count = u16::try_from(slots.len()).map_err(|_| Error::InvalidDevice)?;
    let mut out = Vec::new();
    out.extend_from_slice(DESC_DOMAIN);
    out.extend_from_slice(device_id);
    out.extend_from_slice(verify_key);
    out.extend_from_slice(&count.to_be_bytes());
    for slot in slots {
        push_len_prefixed(&mut out, slot.label.as_bytes())?;
        out.extend_from_slice(&slot.encryption_public);
        out.extend_from_slice(&slot.signing_public);
    }
    Ok(out)
}

fn encode_descriptor(
    device_id: &[u8; DEVICE_ID_LEN],
    verify_key: &[u8; 32],
    signature: &[u8; 64],
    slots: &[SlotRecord],
) -> Result<Vec<u8>> {
    let count = u16::try_from(slots.len()).map_err(|_| Error::InvalidDevice)?;
    let mut out = Vec::new();
    out.extend_from_slice(DEVICE_MAGIC);
    out.push(DEVICE_VERSION);
    out.extend_from_slice(device_id);
    out.extend_from_slice(verify_key);
    out.extend_from_slice(signature);
    out.extend_from_slice(&count.to_be_bytes());
    for slot in slots {
        push_len_prefixed(&mut out, slot.label.as_bytes())?;
        out.extend_from_slice(&slot.encryption_public);
        out.extend_from_slice(&slot.signing_public);
    }
    Ok(out)
}

fn decode_descriptor(bytes: &[u8]) -> Result<([u8; DEVICE_ID_LEN], [u8; 32], Vec<SlotRecord>)> {
    if bytes.len() < 4 + 1 + DEVICE_ID_LEN + 32 + 64 + 2 || &bytes[..4] != DEVICE_MAGIC {
        return Err(Error::InvalidDevice);
    }
    let mut data = &bytes[4..];
    let version = take_u8(&mut data)?;
    if version != DEVICE_VERSION {
        return Err(Error::InvalidDevice);
    }
    let device_id = take_array(&mut data)?;
    let verify_key = take_array(&mut data)?;
    let signature = take_array::<64>(&mut data)?;
    let count = u16::from_be_bytes(take_array(&mut data)?) as usize;
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        let label = utf8(take_len_prefixed(&mut data)?)?;
        validate_slot_label(&label)?;
        let encryption_public = take_array(&mut data)?;
        let signing_public = take_array(&mut data)?;
        slots.push(SlotRecord {
            label,
            encryption_public,
            signing_public,
        });
    }
    if !data.is_empty() {
        return Err(Error::InvalidDevice);
    }
    let preimage = descriptor_preimage(&device_id, &verify_key, &slots)?;
    crate::signing::verify_signature(&verify_key, &preimage, &signature)?;
    Ok((device_id, verify_key, slots))
}

fn signing_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(secret)
        .verifying_key()
        .to_bytes()
}

#[cfg(test)]
#[path = "device/tests.rs"]
mod tests;
