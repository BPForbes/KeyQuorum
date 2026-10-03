use super::*;

#[test]
fn derive_key_is_deterministic_for_same_password_and_salt() {
    let salt = random_salt();
    let a = derive_key("correct horse battery staple", &salt).unwrap();
    let b = derive_key("correct horse battery staple", &salt).unwrap();
    assert_eq!(a, b);
}

#[test]
fn random_key_differs_across_calls() {
    let a = random_key();
    let b = random_key();
    assert_ne!(*a, *b);
}

#[test]
fn fill_random_fills_the_whole_buffer_differently_each_call() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    fill_random(&mut a);
    fill_random(&mut b);
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 64]);
    // A 64-byte buffer is filled to its end, not just its first word.
    assert_ne!(a[32..], [0u8; 32]);
}

#[test]
fn derive_key_differs_for_different_passwords() {
    let salt = random_salt();
    let a = derive_key("password-one", &salt).unwrap();
    let b = derive_key("password-two", &salt).unwrap();
    assert_ne!(a, b);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = derive_key("hunter2", &random_salt()).unwrap();
    let nonce = random_nonce();
    let plaintext = b"the quorum has been reached";

    let ciphertext = encrypt(&key, &nonce, plaintext);
    let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn decrypt_fails_with_wrong_key() {
    let salt = random_salt();
    let nonce = random_nonce();
    let key = derive_key("hunter2", &salt).unwrap();
    let wrong_key = derive_key("not-hunter2", &salt).unwrap();

    let ciphertext = encrypt(&key, &nonce, b"top secret");

    assert!(decrypt(&wrong_key, &nonce, &ciphertext).is_err());
}

#[test]
fn salts_and_nonces_are_fresh_random_and_the_right_length() {
    let (a, b) = (random_salt(), random_salt());
    assert_eq!(a.len(), SALT_LEN);
    assert_ne!(a, b, "two salts must differ");
    assert_ne!(a, [0u8; SALT_LEN], "a salt must not be all zero");

    let (a, b) = (random_nonce(), random_nonce());
    assert_eq!(a.len(), NONCE_LEN);
    assert_ne!(a, b, "two nonces must differ");
    assert_ne!(a, [0u8; NONCE_LEN], "a nonce must not be all zero");
}

#[test]
fn decrypted_plaintext_is_zeroed_on_drop() {
    // Pinned by type: the plaintext comes back in a buffer that wipes itself.
    let key = random_key();
    let nonce = random_nonce();
    let ciphertext = encrypt(&key, &nonce, b"secret");
    let plaintext: zeroize::Zeroizing<Vec<u8>> = decrypt(&key, &nonce, &ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), b"secret");
}

#[test]
fn a_commitment_depends_on_its_key_domain_and_content() {
    let key = random_key();
    let other = random_key();
    let base = commit(&key, b"KQ-TEST", b"secret report");
    assert_eq!(base, commit(&key, b"KQ-TEST", b"secret report"));
    assert!(commitments_match(
        &base,
        &commit(&key, b"KQ-TEST", b"secret report")
    ));
    // Without the key, the commitment confirms no guess at the content.
    assert!(!commitments_match(
        &base,
        &commit(&other, b"KQ-TEST", b"secret report")
    ));
    assert!(!commitments_match(
        &base,
        &commit(&key, b"KQ-OTHER", b"secret report")
    ));
    assert!(!commitments_match(
        &base,
        &commit(&key, b"KQ-TEST", b"secret repor")
    ));
    // The domain is length-prefixed, so its boundary with the data is fixed.
    assert!(!commitments_match(
        &commit(&key, b"KQ-TESTs", b"ecret report"),
        &base
    ));
}
