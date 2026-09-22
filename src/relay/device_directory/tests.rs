use super::*;
use crate::device::{self, Container};
use crate::relay;

fn signed_device() -> (Container, tempfile::TempDir, DeviceDescriptor) {
    let dir = tempfile::tempdir().unwrap();
    let mut container = device::init(dir.path()).unwrap();
    device::provision(&mut container, "M", "slot-passphrase").unwrap();
    let slots = container
        .slots()
        .iter()
        .map(|slot| DeviceSlotDescriptor {
            label: slot.label.clone(),
            encryption_public: hex::encode(slot.encryption_public),
            signing_public: hex::encode(slot.signing_public),
        })
        .collect::<Vec<_>>();
    let secret = device::device_signing_secret(&container).unwrap();
    let descriptor = sign_descriptor(
        container.device_id(),
        container.verify_key(),
        &slots,
        &secret,
    )
    .unwrap();
    (container, dir, descriptor)
}

#[test]
fn put_keeps_a_signed_public_descriptor_and_refuses_a_verify_key_change() {
    let conn = relay::open_in_memory().unwrap();
    let (container, _dir, descriptor) = signed_device();
    let stored = put(&conn, &descriptor).unwrap();
    let loaded = require(&conn, &stored.device_id).unwrap();
    assert_eq!(loaded, stored);
    assert!(!loaded.verify_key.is_empty());
    assert_eq!(loaded.slots.len(), 1);

    let mut replaced = stored.clone();
    let other_dir = tempfile::tempdir().unwrap();
    let other = device::init(other_dir.path()).unwrap();
    replaced.verify_key = hex::encode(other.verify_key());
    let secret = device::device_signing_secret(&other).unwrap();
    let resigned = sign_descriptor(
        container.device_id(),
        other.verify_key(),
        &replaced.slots,
        &secret,
    )
    .unwrap();
    assert!(matches!(
        put(&conn, &resigned),
        Err(crate::error::Error::InvalidDevice)
    ));
}

#[test]
fn unsigned_or_tampered_descriptor_is_refused() {
    let (_container, _dir, mut descriptor) = signed_device();
    descriptor.signature = "ab".repeat(64);
    assert!(verify_descriptor(&descriptor).is_err());
    descriptor.slots[0].label = "other".into();
    descriptor.signature = hex::encode([1u8; 64]);
    assert!(verify_descriptor(&descriptor).is_err());
    assert!(serde_json::from_str::<DeviceDescriptor>(
        r#"{"device_id":"aa","verify_key":"bb","slots":[],"signature":"cc","secret":"no"}"#
    )
    .is_err());
}
