use super::*;

fn keypair() -> (crypto_box::SecretKey, [u8; 32]) {
    let secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let public = *secret.public_key().as_bytes();
    (secret, public)
}

#[test]
fn seal_round_trips_under_the_recipient_key() {
    let (secret, public) = keypair();
    let sealed = seal(KIND_TREE_UPDATE, &public, b"letter").expect("seal");

    assert_eq!(&sealed[..4], PACKAGE_MAGIC);
    assert_eq!(sealed[4], FORMAT_VERSION);
    assert_eq!(sealed[5], KIND_TREE_UPDATE);
    assert_eq!(routing_public_key(&sealed).expect("route"), public);
    assert_eq!(kind(&sealed).expect("kind"), KIND_TREE_UPDATE);

    let (k, addressed, payload) = open(&sealed, &secret.to_bytes()).expect("open");
    assert_eq!(k, KIND_TREE_UPDATE);
    assert_eq!(addressed, public);
    assert_eq!(payload, b"letter");
}

#[test]
fn another_recipients_key_cannot_open_the_letter() {
    let (_, public) = keypair();
    let (other, _) = keypair();
    let sealed = seal(KIND_KEY_REISSUE, &public, b"letter").expect("seal");

    assert!(matches!(
        open(&sealed, &other.to_bytes()),
        Err(Error::InvalidBridgePackage)
    ));
}

#[test]
fn outer_header_rejects_truncation_trailing_bytes_and_wrong_magic() {
    let (_, public) = keypair();
    let sealed = seal(KIND_INVITE, &public, b"letter").expect("seal");

    assert!(parse_outer(&sealed[..sealed.len() - 1]).is_err());

    let mut trailing = sealed.clone();
    trailing.push(0);
    assert!(parse_outer(&trailing).is_err());

    let mut wrong_magic = sealed.clone();
    wrong_magic[0] = b'X';
    assert!(parse_outer(&wrong_magic).is_err());

    let mut wrong_version = sealed;
    wrong_version[4] = FORMAT_VERSION + 1;
    assert!(parse_outer(&wrong_version).is_err());
}

#[test]
fn sealing_to_a_small_order_public_key_is_refused() {
    let weak = [0u8; 32];
    assert!(is_weak_x25519_public_key(&weak));
    assert!(matches!(
        seal(KIND_KEY_REISSUE, &weak, b"letter"),
        Err(Error::InvalidPublicKey)
    ));
}

#[test]
fn length_prefixed_fields_round_trip_at_both_widths() {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, b"M.S.2").expect("u16 field");
    push_len_prefixed_u32(&mut out, &vec![7u8; 70_000]).expect("u32 field");

    let mut data = out.as_slice();
    assert_eq!(
        utf8(take_len_prefixed(&mut data).expect("read")).unwrap(),
        "M.S.2"
    );
    assert_eq!(
        take_len_prefixed_u32(&mut data).expect("read").len(),
        70_000
    );
    assert!(data.is_empty());
}

#[test]
fn a_u16_field_refuses_a_payload_it_cannot_describe() {
    let mut out = Vec::new();
    assert!(matches!(
        push_len_prefixed(&mut out, &vec![0u8; 70_000]),
        Err(Error::BundleFieldTooLarge)
    ));
}
