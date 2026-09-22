//! Sealed letters for device copy, move, and relocate.
//!
//! The relay carries the outer `KQPB` letter only. `KQTX` and slot secrets
//! stay inside that letter. Acknowledgements are sealed back to the source
//! slot's encryption key so the source can finish the workflow later.

use crate::device::{self, Container};
use crate::envelope::{self, take_array, take_len_prefixed, PACKAGE};
use crate::error::{Error, Result};
use crate::relay::{DeviceDescriptor, DeviceSlotDescriptor};
use crate::signing;
use crate::transfer::{self, AuthenticatedPackage};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

const ACK_DOMAIN: &[u8] = b"KQ-DEVICE-ACK-v1";
const RELOCATE_DOMAIN: &[u8] = b"KQ-DEVICE-RELOCATE-v1";
const RELOCATE_ACK_DOMAIN: &[u8] = b"KQ-DEVICE-RELOCATE-ACK-v1";

pub struct SealedTransfer {
    pub return_public: [u8; 32],
    pub package: Zeroizing<Vec<u8>>,
}

pub struct TransferAck {
    pub tx_id: [u8; 16],
    pub package_hash: [u8; 32],
    pub destination_device_id: [u8; 16],
}

/// A sealed relocate letter and the id the source chose for it. The source
/// keeps the id and hands it to `relay-drop`; only an acknowledgement that
/// echoes it may delete the source slot.
pub struct SealedRelocate {
    pub relocate_id: [u8; 16],
    pub bytes: Vec<u8>,
}

pub struct RelocateLetter {
    pub relocate_id: [u8; 16],
    pub label: String,
    pub source_device_id: [u8; 16],
    pub destination_device_id: [u8; 16],
    pub return_public: [u8; 32],
    pub source_verify_key: [u8; 32],
    pub encryption_secret: Zeroizing<[u8; 32]>,
    pub signing_secret: Zeroizing<[u8; 32]>,
}

pub struct RelocateAck {
    pub relocate_id: [u8; 16],
    pub label: String,
    pub source_device_id: [u8; 16],
    pub destination_device_id: [u8; 16],
}

/// Sign the public descriptor with this container's device key.
pub fn public_descriptor(container: &Container) -> Result<DeviceDescriptor> {
    let slots = container
        .slots()
        .iter()
        .map(|slot| DeviceSlotDescriptor {
            label: slot.label.clone(),
            encryption_public: hex::encode(slot.encryption_public),
            signing_public: hex::encode(slot.signing_public),
        })
        .collect::<Vec<_>>();
    let secret = device::device_signing_secret(container)?;
    crate::relay::sign_device_descriptor(
        container.device_id(),
        container.verify_key(),
        &slots,
        &secret,
    )
}

pub fn seal_transfer(
    recipient_public: &[u8; 32],
    return_public: &[u8; 32],
    package: &[u8],
) -> Result<Vec<u8>> {
    transfer::authenticated_package(package)?;
    let mut plain = Vec::with_capacity(32 + package.len());
    plain.extend_from_slice(return_public);
    plain.extend_from_slice(package);
    envelope::seal(
        PACKAGE,
        envelope::KIND_DEVICE_TRANSFER,
        recipient_public,
        &plain,
    )
}

pub fn open_transfer(recipient_secret: &[u8; 32], bytes: &[u8]) -> Result<SealedTransfer> {
    let (kind, _, payload) = envelope::open(bytes, recipient_secret)?;
    if kind != envelope::KIND_DEVICE_TRANSFER || payload.len() < 32 + 4 {
        return Err(Error::InvalidBridgePackage);
    }
    let mut return_public = [0u8; 32];
    return_public.copy_from_slice(&payload[..32]);
    let package = Zeroizing::new(payload[32..].to_vec());
    transfer::authenticated_package(package.as_slice())?;
    Ok(SealedTransfer {
        return_public,
        package,
    })
}

pub fn seal_transfer_ack(
    destination: &Container,
    return_public: &[u8; 32],
    header: &AuthenticatedPackage,
    package_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    if destination.device_id() != &header.destination_device_id {
        return Err(Error::InvalidDevice);
    }
    let destination_secret = device::device_signing_secret(destination)?;
    let signature = signing::sign(
        &destination_secret,
        &ack_message(&header.id, package_hash, &header.destination_device_id),
    );
    let mut plain = Vec::with_capacity(16 + 32 + 16 + 64);
    plain.extend_from_slice(&header.id);
    plain.extend_from_slice(package_hash);
    plain.extend_from_slice(&header.destination_device_id);
    plain.extend_from_slice(&signature);
    envelope::seal(
        PACKAGE,
        envelope::KIND_DEVICE_TRANSFER_ACK,
        return_public,
        &plain,
    )
}

pub fn open_transfer_ack(
    return_secret: &[u8; 32],
    bytes: &[u8],
    destination_verify_key: &[u8; 32],
) -> Result<TransferAck> {
    let (kind, _, payload) = envelope::open(bytes, return_secret)?;
    if kind != envelope::KIND_DEVICE_TRANSFER_ACK || payload.len() != 16 + 32 + 16 + 64 {
        return Err(Error::InvalidBridgePackage);
    }
    let tx_id: [u8; 16] = payload[..16]
        .try_into()
        .map_err(|_| Error::InvalidBridgePackage)?;
    let package_hash: [u8; 32] = payload[16..48]
        .try_into()
        .map_err(|_| Error::InvalidBridgePackage)?;
    let destination_device_id: [u8; 16] = payload[48..64]
        .try_into()
        .map_err(|_| Error::InvalidBridgePackage)?;
    let signature: [u8; 64] = payload[64..]
        .try_into()
        .map_err(|_| Error::InvalidBridgePackage)?;
    signing::verify_signature(
        destination_verify_key,
        &ack_message(&tx_id, &package_hash, &destination_device_id),
        &signature,
    )?;
    Ok(TransferAck {
        tx_id,
        package_hash,
        destination_device_id,
    })
}

pub fn seal_relocate(
    recipient_public: &[u8; 32],
    source: &Container,
    label: &str,
    destination_device_id: &[u8; 16],
    passphrase: &str,
) -> Result<SealedRelocate> {
    if source.device_id() == destination_device_id {
        return Err(Error::InvalidDevice);
    }
    let secrets = device::open_slot(source, label, passphrase)?;
    let return_public = secrets.encryption_public;
    let mut relocate_id = [0u8; 16];
    OsRng.fill_bytes(&mut relocate_id);
    let mut body = Vec::new();
    body.extend_from_slice(&relocate_id);
    body.extend_from_slice(source.device_id());
    body.extend_from_slice(destination_device_id);
    body.extend_from_slice(&return_public);
    body.extend_from_slice(source.verify_key());
    envelope::push_len_prefixed(&mut body, label.as_bytes())?;
    body.extend_from_slice(secrets.encryption_secret.as_slice());
    body.extend_from_slice(secrets.signing_secret.as_slice());
    let mut message = Vec::with_capacity(RELOCATE_DOMAIN.len() + body.len());
    message.extend_from_slice(RELOCATE_DOMAIN);
    message.extend_from_slice(&body);
    let device_secret = device::device_signing_secret(source)?;
    let signature = signing::sign(&device_secret, &message);
    body.extend_from_slice(&signature);
    let bytes = envelope::seal(
        PACKAGE,
        envelope::KIND_DEVICE_RELOCATE,
        recipient_public,
        &body,
    )?;
    Ok(SealedRelocate { relocate_id, bytes })
}

pub fn open_relocate(recipient_secret: &[u8; 32], bytes: &[u8]) -> Result<RelocateLetter> {
    let (kind, _, payload) = envelope::open(bytes, recipient_secret)?;
    if kind != envelope::KIND_DEVICE_RELOCATE {
        return Err(Error::InvalidBridgePackage);
    }
    let mut data = payload.as_slice();
    let relocate_id = take_array::<16>(&mut data)?;
    let source_device_id = take_array::<16>(&mut data)?;
    let destination_device_id = take_array::<16>(&mut data)?;
    let return_public = take_array::<32>(&mut data)?;
    let source_verify_key = take_array::<32>(&mut data)?;
    let label_bytes = take_len_prefixed(&mut data)?;
    let label = envelope::utf8(label_bytes)?;
    device::validate_slot_label(&label)?;
    let encryption_secret = Zeroizing::new(take_array::<32>(&mut data)?);
    let signing_secret = Zeroizing::new(take_array::<32>(&mut data)?);
    if data.len() != 64 {
        return Err(Error::InvalidBridgePackage);
    }
    let signature = take_array::<64>(&mut data)?;
    let mut message = Vec::new();
    message.extend_from_slice(RELOCATE_DOMAIN);
    let signed_len = payload.len() - 64;
    message.extend_from_slice(&payload[..signed_len]);
    signing::verify_signature(&source_verify_key, &message, &signature)?;
    if crate::keys::encryption_public_from_secret(&encryption_secret) != return_public {
        return Err(Error::IntegrityCheckFailed);
    }
    Ok(RelocateLetter {
        relocate_id,
        label,
        source_device_id,
        destination_device_id,
        return_public,
        source_verify_key,
        encryption_secret,
        signing_secret,
    })
}

pub fn seal_relocate_ack(letter: &RelocateLetter, destination: &Container) -> Result<Vec<u8>> {
    if destination.device_id() != &letter.destination_device_id {
        return Err(Error::InvalidDevice);
    }
    let mut body = Vec::new();
    body.extend_from_slice(&letter.relocate_id);
    envelope::push_len_prefixed(&mut body, letter.label.as_bytes())?;
    body.extend_from_slice(&letter.source_device_id);
    body.extend_from_slice(&letter.destination_device_id);
    let mut message = Vec::with_capacity(RELOCATE_ACK_DOMAIN.len() + body.len());
    message.extend_from_slice(RELOCATE_ACK_DOMAIN);
    message.extend_from_slice(&body);
    let secret = device::device_signing_secret(destination)?;
    let signature = signing::sign(&secret, &message);
    body.extend_from_slice(&signature);
    envelope::seal(
        PACKAGE,
        envelope::KIND_DEVICE_RELOCATE_ACK,
        &letter.return_public,
        &body,
    )
}

pub fn open_relocate_ack(
    return_secret: &[u8; 32],
    bytes: &[u8],
    destination_verify_key: &[u8; 32],
) -> Result<RelocateAck> {
    let (kind, _, payload) = envelope::open(bytes, return_secret)?;
    if kind != envelope::KIND_DEVICE_RELOCATE_ACK {
        return Err(Error::InvalidBridgePackage);
    }
    let mut data = payload.as_slice();
    let relocate_id = take_array::<16>(&mut data)?;
    let label = envelope::utf8(take_len_prefixed(&mut data)?)?;
    device::validate_slot_label(&label)?;
    let source_device_id = take_array::<16>(&mut data)?;
    let destination_device_id = take_array::<16>(&mut data)?;
    if data.len() != 64 {
        return Err(Error::InvalidBridgePackage);
    }
    let signature = take_array::<64>(&mut data)?;
    let mut message = Vec::new();
    message.extend_from_slice(RELOCATE_ACK_DOMAIN);
    message.extend_from_slice(&payload[..payload.len() - 64]);
    signing::verify_signature(destination_verify_key, &message, &signature)?;
    Ok(RelocateAck {
        relocate_id,
        label,
        source_device_id,
        destination_device_id,
    })
}

fn ack_message(
    tx_id: &[u8; 16],
    package_hash: &[u8; 32],
    destination_device_id: &[u8; 16],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(ACK_DOMAIN.len() + 16 + 32 + 16);
    message.extend_from_slice(ACK_DOMAIN);
    message.extend_from_slice(tx_id);
    message.extend_from_slice(package_hash);
    message.extend_from_slice(destination_device_id);
    message
}

#[cfg(test)]
#[path = "device_relay/tests.rs"]
mod tests;
