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
