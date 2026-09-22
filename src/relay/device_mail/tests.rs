use super::*;
use crate::envelope::{self, PACKAGE};
use crate::keys;
use crate::relay;

fn sealed(kind: u8, payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let (_secret, public) = keys::generate_encryption_keypair();
    let bytes = envelope::seal(PACKAGE, kind, &public, payload).expect("seal");
    (bytes, public)
}

#[test]
fn stores_a_device_letter_without_opening_it() {
    let conn = relay::open_in_memory().expect("schema");
    let secret = b"slot-secret-must-stay-sealed";
    let (bytes, public) = sealed(envelope::KIND_DEVICE_TRANSFER, secret);
    let (id, fingerprint, duplicate) = store(&conn, &bytes).expect("store");
    assert!(!duplicate);
    assert_eq!(fingerprint, keys::fingerprint(&public));
    let page = list_after(&conn, &fingerprint, None, None).expect("list");
    assert_eq!(page.packages.len(), 1);
    assert_eq!(page.packages[0].id, id);
    assert_eq!(page.packages[0].bytes, bytes);
    assert!(!page.packages[0]
        .bytes
        .windows(secret.len())
        .any(|window| window == secret));
}

#[test]
fn rejects_raw_kqtx_and_bridge_kinds() {
    let conn = relay::open_in_memory().expect("schema");
    let mut raw = b"KQTX".to_vec();
    raw.extend_from_slice(&[0u8; 64]);
    assert!(matches!(
        store(&conn, &raw),
        Err(crate::error::Error::InvalidBridgePackage)
    ));
    let (bridge, _) = sealed(envelope::KIND_INVITE, b"bridge");
    assert!(matches!(
        store(&conn, &bridge),
        Err(crate::error::Error::InvalidBridgePackage)
    ));
}

#[test]
fn dedupes_the_same_letter() {
    let conn = relay::open_in_memory().expect("schema");
    let (bytes, _) = sealed(envelope::KIND_DEVICE_RELOCATE, b"moved");
    let (first, _, duplicate) = store(&conn, &bytes).expect("first");
    let (second, _, again) = store(&conn, &bytes).expect("second");
    assert!(!duplicate);
    assert!(again);
    assert_eq!(first, second);
}
