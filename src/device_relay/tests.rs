use super::*;
use crate::device;
use crate::transfer::{self, DescendantMode, TransferAuth, TransferOp};

fn pair() -> (
    device::Container,
    tempfile::TempDir,
    device::Container,
    tempfile::TempDir,
) {
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let mut left = device::init(left_dir.path()).unwrap();
    let mut right = device::init(right_dir.path()).unwrap();
    device::provision(&mut left, "M", "slot-passphrase").unwrap();
    device::provision(&mut right, "recv", "slot-passphrase").unwrap();
    (left, left_dir, right, right_dir)
}

#[test]
fn transfer_letter_round_trips_and_hides_the_package() {
    let (mut source, _source_dir, dest, _dest_dir) = pair();
    let source_conn = crate::db::open_in_memory().unwrap();
    transfer::enroll(&source_conn, &mut source, "M", "slot-passphrase").unwrap();
    let passes =
        std::collections::HashMap::from([("M".to_string(), "slot-passphrase".to_string())]);
    let prepared = transfer::prepare(
        &source_conn,
        &source,
        dest.device_id(),
        "M",
        "M",
        TransferOp::Copy,
        DescendantMode::KeyOnly,
        &passes,
        &TransferAuth::default(),
    )
    .unwrap();
    let recipient = dest.slot("recv").unwrap().encryption_public;
    let return_public = source.slot("M").unwrap().encryption_public;
    let sealed = seal_transfer(&recipient, &return_public, prepared.package()).unwrap();
    assert!(!sealed
        .windows(prepared.package().len())
        .any(|window| window == prepared.package()));
    assert!(!sealed.starts_with(b"KQTX"));
    let opener = device::open_slot(&dest, "recv", "slot-passphrase").unwrap();
    let opened = open_transfer(&opener.encryption_secret, &sealed).unwrap();
    assert_eq!(opened.return_public, return_public);
    assert_eq!(opened.package.as_slice(), prepared.package());
    let header = transfer::authenticated_package(opened.package.as_slice()).unwrap();
    let hash = transfer::package_hash(opened.package.as_slice());
    let ack = seal_transfer_ack(&dest, &opened.return_public, &header, &hash).unwrap();
    let source_slot = device::open_slot(&source, "M", "slot-passphrase").unwrap();
    let parsed =
        open_transfer_ack(&source_slot.encryption_secret, &ack, dest.verify_key()).unwrap();
    assert_eq!(parsed.tx_id, prepared.id);
    assert_eq!(parsed.package_hash, hash);
    assert_eq!(parsed.destination_device_id, *dest.device_id());
}

#[test]
fn relocate_letter_round_trips_without_a_plaintext_secret() {
    let (source, _source_dir, dest, _dest_dir) = pair();
    let recipient = dest.slot("recv").unwrap().encryption_public;
    let sealed = seal_relocate(
        &recipient,
        &source,
        "M",
        dest.device_id(),
        "slot-passphrase",
    )
    .unwrap();
    let plain_secret = device::open_slot(&source, "M", "slot-passphrase").unwrap();
    assert!(!sealed
        .bytes
        .windows(32)
        .any(|window| window == plain_secret.encryption_secret.as_slice()));
    let opener = device::open_slot(&dest, "recv", "slot-passphrase").unwrap();
    let letter = open_relocate(&opener.encryption_secret, &sealed.bytes).unwrap();
    assert_eq!(letter.relocate_id, sealed.relocate_id);
    assert_eq!(letter.label, "M");
    assert_eq!(letter.source_device_id, *source.device_id());
    assert_eq!(
        letter.encryption_secret.as_slice(),
        plain_secret.encryption_secret.as_slice()
    );
    let ack = seal_relocate_ack(&letter, &dest).unwrap();
    let parsed =
        open_relocate_ack(&plain_secret.encryption_secret, &ack, dest.verify_key()).unwrap();
    assert_eq!(parsed.label, "M");
    assert_eq!(parsed.destination_device_id, *dest.device_id());
    assert!(source.slot("M").is_some());
}

#[test]
fn a_relocate_ack_names_the_relocation_it_answers() {
    let (source, _source_dir, dest, _dest_dir) = pair();
    let recipient = dest.slot("recv").unwrap().encryption_public;
    let opener = device::open_slot(&dest, "recv", "slot-passphrase").unwrap();
    let source_slot = device::open_slot(&source, "M", "slot-passphrase").unwrap();
    let relocate = || {
        seal_relocate(
            &recipient,
            &source,
            "M",
            dest.device_id(),
            "slot-passphrase",
        )
        .unwrap()
    };
    let first = relocate();
    let second = relocate();
    // Same slot, same keys, same devices: only the relocate id tells the
    // two relocations apart, so it must differ.
    assert_ne!(first.relocate_id, second.relocate_id);

    let old_letter = open_relocate(&opener.encryption_secret, &first.bytes).unwrap();
    let old_ack = seal_relocate_ack(&old_letter, &dest).unwrap();
    let parsed =
        open_relocate_ack(&source_slot.encryption_secret, &old_ack, dest.verify_key()).unwrap();
    assert_eq!(parsed.relocate_id, first.relocate_id);
    assert_ne!(parsed.relocate_id, second.relocate_id);
    assert_eq!(parsed.label, "M");
}

#[test]
fn a_relocate_ack_with_a_rewritten_id_fails_verification() {
    let (source, _source_dir, dest, _dest_dir) = pair();
    let recipient = dest.slot("recv").unwrap().encryption_public;
    let opener = device::open_slot(&dest, "recv", "slot-passphrase").unwrap();
    let source_slot = device::open_slot(&source, "M", "slot-passphrase").unwrap();
    let sealed = seal_relocate(
        &recipient,
        &source,
        "M",
        dest.device_id(),
        "slot-passphrase",
    )
    .unwrap();
    let letter = open_relocate(&opener.encryption_secret, &sealed.bytes).unwrap();
    let ack = seal_relocate_ack(&letter, &dest).unwrap();
    let (_, _, mut payload) = envelope::open(&ack, &source_slot.encryption_secret).unwrap();
    payload[0] ^= 0x01;
    let forged = envelope::seal(
        PACKAGE,
        envelope::KIND_DEVICE_RELOCATE_ACK,
        &source_slot.encryption_public,
        &payload,
    )
    .unwrap();
    assert!(open_relocate_ack(&source_slot.encryption_secret, &forged, dest.verify_key()).is_err());
    // The genuine ack still opens.
    assert!(open_relocate_ack(&source_slot.encryption_secret, &ack, dest.verify_key()).is_ok());
}
