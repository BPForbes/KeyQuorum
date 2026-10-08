use super::*;
use crate::keys::{generate_encryption_keypair, generate_signing_keypair};

fn request() -> (Request, zeroize::Zeroizing<[u8; 32]>) {
    let (signing_secret, signing_public) = generate_signing_keypair();
    let (_, encryption_public) = generate_encryption_keypair();
    (
        Request {
            device_id: [4u8; 16],
            created_at: 1_790_000_000,
            label: "alice".into(),
            encryption_public,
            signing_public,
        },
        signing_secret,
    )
}

#[test]
fn a_request_round_trips_and_has_a_stable_fingerprint() {
    let (request, secret) = request();
    let bytes = encode(&request, &secret).expect("encode");
    assert!(bytes.len() <= MAX_REQUEST_BYTES);
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded, request);
    let fingerprint = decoded.fingerprint().expect("fingerprint");
    assert_eq!(fingerprint, request.fingerprint().expect("fingerprint"));
    assert_eq!(fingerprint.split(' ').count(), 8);
}

#[test]
fn any_changed_byte_is_refused() {
    let (request, secret) = request();
    let bytes = encode(&request, &secret).expect("encode");
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(decode(&changed).is_err(), "byte {index}");
    }
}

#[test]
fn truncated_padded_and_oversized_input_is_refused() {
    let (request, secret) = request();
    let bytes = encode(&request, &secret).expect("encode");
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode(&[]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(decode(&longer).is_err());
    assert!(decode(&vec![0u8; MAX_REQUEST_BYTES + 1]).is_err());
}

#[test]
fn encoding_needs_the_key_the_request_names() {
    let (request, _) = request();
    let (other, _) = generate_signing_keypair();
    assert!(encode(&request, &other).is_err());
}

#[test]
fn an_empty_or_oversized_label_is_refused() {
    let (mut request, secret) = request();
    request.label = String::new();
    assert!(encode(&request, &secret).is_err());
    request.label = "x".repeat(MAX_LABEL_BYTES + 1);
    assert!(encode(&request, &secret).is_err());
}

#[test]
fn a_weak_encryption_key_is_refused() {
    let (mut request, secret) = request();
    request.encryption_public = [0u8; 32];
    let bytes = encode(&request, &secret).expect("signs what it is given");
    assert!(decode(&bytes).is_err());
}

#[test]
fn a_different_signer_changes_the_fingerprint_and_a_swapped_key_does_not_verify() {
    let (request, secret) = request();
    let bytes = encode(&request, &secret).expect("encode");
    let (other_request, _) = self::request();
    assert_ne!(
        request.fingerprint().unwrap(),
        other_request.fingerprint().unwrap()
    );
    // Replace the signing key in the body with another one and keep the
    // signature: the file must not verify.
    let mut swapped = bytes.clone();
    let start = swapped.len() - SIG_LEN - 32;
    swapped[start..start + 32].copy_from_slice(&other_request.signing_public);
    assert!(decode(&swapped).is_err());
}

#[test]
fn the_fingerprint_is_confirmed_in_any_case_and_spacing_and_nothing_else() {
    let (request, _) = request();
    let shown = request.fingerprint().expect("fingerprint");
    request.confirm_fingerprint(&shown).expect("as shown");
    request
        .confirm_fingerprint(&shown.to_uppercase().replace(' ', ""))
        .expect("upper case, no spaces");
    assert!(request.confirm_fingerprint("").is_err());
    let mut wrong = shown.clone();
    wrong.replace_range(0..1, if shown.starts_with('0') { "1" } else { "0" });
    assert!(request.confirm_fingerprint(&wrong).is_err());
    let (other, _) = self::request();
    assert!(request
        .confirm_fingerprint(&other.fingerprint().unwrap())
        .is_err());
}

/// A fixed request, so the console's JavaScript reader and this code are held
/// to the same bytes and the same fingerprint (`workers/admin/src/files.test.mjs`
/// carries the same two values).
const VECTOR: &str = "4b5152510103030303030303030303030303030303000000006ab13b800005616c6963650909090909090909090909090909090909090909090909090909090909090909ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca62aa7c55be83e8a5f1ac1242dfbe358318c44b445d1d2b022bcc3a987d2f4610c3852bee70f88f85ea6ceb087d2ad9e62bdd14cf54841778330a03a42b53002";
const VECTOR_FINGERPRINT: &str =
    "704c1175 74c5821a 1d26faf2 001ba951 b4df212c e32f5e24 52bf7e58 82456c3c";

#[test]
fn the_fixed_vector_decodes_and_has_the_published_fingerprint() {
    let signing_secret = [7u8; 32];
    let signing_public = ed25519_dalek::SigningKey::from_bytes(&signing_secret)
        .verifying_key()
        .to_bytes();
    let request = Request {
        device_id: [3u8; 16],
        created_at: 1_790_000_000,
        label: "alice".into(),
        encryption_public: [9u8; 32],
        signing_public,
    };
    let bytes = hex::decode(VECTOR).expect("hex");
    assert_eq!(encode(&request, &signing_secret).expect("encode"), bytes);
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded, request);
    assert_eq!(
        decoded.fingerprint().expect("fingerprint"),
        VECTOR_FINGERPRINT
    );
}
