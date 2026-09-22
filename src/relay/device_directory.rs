//! Public device descriptor. The relay checks the device signature and
//! stores the document. It never stores a slot secret.

use crate::device;
use crate::envelope::{self, push_len_prefixed};
use crate::error::{Error, Result};
use crate::signing;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

const DIRECTORY_DOMAIN: &[u8] = b"KQ-DEVICE-DIR-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceSlotDescriptor {
    pub label: String,
    pub encryption_public: String,
    pub signing_public: String,
}

/// Public facts about one device. `signature` is Ed25519 over the canonical
/// encoding of the other fields, under `verify_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceDescriptor {
    pub device_id: String,
    pub verify_key: String,
    pub slots: Vec<DeviceSlotDescriptor>,
    pub signature: String,
}

pub fn sign_descriptor(
    device_id: &[u8; 16],
    verify_key: &[u8; 32],
    slots: &[DeviceSlotDescriptor],
    device_secret: &[u8; 32],
) -> Result<DeviceDescriptor> {
    let mut descriptor = DeviceDescriptor {
        device_id: hex::encode(device_id),
        verify_key: hex::encode(verify_key),
        slots: slots.to_vec(),
        signature: String::new(),
    };
    normalize_fields(&mut descriptor)?;
    let message = directory_message(&descriptor)?;
    descriptor.signature = hex::encode(signing::sign(device_secret, &message));
    verify_descriptor(&descriptor)?;
    Ok(descriptor)
}

pub fn verify_descriptor(descriptor: &DeviceDescriptor) -> Result<()> {
    let mut normalized = descriptor.clone();
    normalize_fields(&mut normalized)?;
    let verify_key = decode_key(&normalized.verify_key)?;
    let signature = decode_signature(&normalized.signature)?;
    let message = directory_message(&normalized)?;
    signing::verify_signature(&verify_key, &message, &signature)
}

pub fn put(conn: &Connection, descriptor: &DeviceDescriptor) -> Result<DeviceDescriptor> {
    let mut stored = descriptor.clone();
    normalize_fields(&mut stored)?;
    verify_descriptor(&stored)?;
    if let Some(existing) = get(conn, &stored.device_id)? {
        if existing.verify_key != stored.verify_key {
            return Err(Error::InvalidDevice);
        }
    }
    let document = serde_json::to_string(&stored).map_err(|_| Error::InvalidDevice)?;
    conn.execute(
        "INSERT INTO device_directory (device_id, document, updated_at)
         VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         ON CONFLICT(device_id) DO UPDATE SET
            document = excluded.document,
            updated_at = excluded.updated_at",
        params![stored.device_id, document],
    )?;
    Ok(stored)
}

pub fn get(conn: &Connection, device_id: &str) -> Result<Option<DeviceDescriptor>> {
    let device_id = normalize_device_id(device_id)?;
    let document: Option<String> = conn
        .query_row(
            "SELECT document FROM device_directory WHERE device_id = ?1",
            params![device_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(document) = document else {
        return Ok(None);
    };
    let descriptor: DeviceDescriptor =
        serde_json::from_str(&document).map_err(|_| Error::InvalidDevice)?;
    verify_descriptor(&descriptor)?;
    Ok(Some(descriptor))
}

pub fn require(conn: &Connection, device_id: &str) -> Result<DeviceDescriptor> {
    get(conn, device_id)?.ok_or(Error::DeviceNotFound)
}

fn normalize_fields(descriptor: &mut DeviceDescriptor) -> Result<()> {
    descriptor.device_id = normalize_device_id(&descriptor.device_id)?;
    descriptor.verify_key = normalize_key(&descriptor.verify_key)?;
    let _ = decode_verify_key(&descriptor.verify_key)?;
    let mut seen = Vec::new();
    for slot in &mut descriptor.slots {
        device::validate_slot_label(&slot.label)?;
        if seen.iter().any(|label: &String| label == &slot.label) {
            return Err(Error::InvalidSlot);
        }
        seen.push(slot.label.clone());
        slot.encryption_public = normalize_key(&slot.encryption_public)?;
        slot.signing_public = normalize_key(&slot.signing_public)?;
        let encryption = decode_key(&slot.encryption_public)?;
        if envelope::is_weak_x25519_public_key(&encryption) {
            return Err(Error::InvalidPublicKey);
        }
        let _ = decode_verify_key(&slot.signing_public)?;
    }
    Ok(())
}

fn directory_message(descriptor: &DeviceDescriptor) -> Result<Vec<u8>> {
    let device_id = decode_device_id(&descriptor.device_id)?;
    let verify_key = decode_key(&descriptor.verify_key)?;
    let mut slots = descriptor.slots.clone();
    slots.sort_by(|left, right| left.label.cmp(&right.label));
    let mut message = Vec::new();
    message.extend_from_slice(DIRECTORY_DOMAIN);
    message.extend_from_slice(&device_id);
    message.extend_from_slice(&verify_key);
    for slot in &slots {
        push_len_prefixed(&mut message, slot.label.as_bytes())?;
        message.extend_from_slice(&decode_key(&slot.encryption_public)?);
        message.extend_from_slice(&decode_key(&slot.signing_public)?);
    }
    Ok(message)
}

fn normalize_device_id(value: &str) -> Result<String> {
    let bytes = decode_device_id(value)?;
    Ok(hex::encode(bytes))
}

fn normalize_key(value: &str) -> Result<String> {
    let bytes = decode_key(value)?;
    Ok(hex::encode(bytes))
}

fn decode_device_id(value: &str) -> Result<[u8; 16]> {
    decode_fixed(value).ok_or(Error::InvalidDevice)
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    decode_fixed(value).ok_or(Error::InvalidPublicKey)
}

fn decode_verify_key(value: &str) -> Result<[u8; 32]> {
    let bytes = decode_key(value)?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidPublicKey)?;
    Ok(bytes)
}

fn decode_signature(value: &str) -> Result<[u8; 64]> {
    decode_fixed(value).ok_or(Error::SignatureVerificationFailed)
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(value.trim()).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
#[path = "device_directory/tests.rs"]
mod tests;
