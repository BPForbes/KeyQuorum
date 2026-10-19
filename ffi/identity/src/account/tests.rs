use super::*;

/// A password drawn at run time, so no secret is written as a literal.
fn password() -> String {
    let mut bytes = [0u8; 12];
    crypto::fill_random(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    crypto::fill_random(&mut nonce);
    nonce
}

#[test]
fn sealed_key_opens_only_with_its_password() {
    let (secret, public) = generate();
    let pw = password();
    let sealed = seal(&pw, &secret).unwrap();
    assert_eq!(sealed.len(), SEALED_LEN);
    let opened = open(&pw, &sealed).unwrap();
    assert_eq!(*opened, *secret);
    assert_eq!(public_key(&opened), public);
    assert_eq!(open(&password(), &sealed), Err(OpenError::WrongPassword));
}

#[test]
fn a_changed_or_truncated_sealed_key_is_refused() {
    let (secret, _) = generate();
    let pw = password();
    let mut sealed = seal(&pw, &secret).unwrap();
    assert_eq!(
        open(&pw, &sealed[..SEALED_LEN - 1]),
        Err(OpenError::Malformed)
    );
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    assert_eq!(open(&pw, &sealed), Err(OpenError::WrongPassword));
    sealed[0] = b'X';
    assert_eq!(open(&pw, &sealed), Err(OpenError::Malformed));
}

#[test]
fn two_seals_of_one_key_differ() {
    let (secret, _) = generate();
    let pw = password();
    assert_ne!(seal(&pw, &secret).unwrap(), seal(&pw, &secret).unwrap());
}

#[test]
fn bridge_signature_verifies_only_for_its_bridge() {
    let (secret, public) = generate();
    let (_, other_public) = generate();
    let n = nonce();
    let (from, to) = ("Root.Alternative", "Root.Flinstone.Bob");
    let sig = sign_bridge(AccountBridgeRole::Request, from, to, from, &n, &secret).unwrap();
    assert!(verify_bridge(
        AccountBridgeRole::Request,
        from,
        to,
        from,
        &n,
        &public,
        &sig
    ));
    assert!(!verify_bridge(
        AccountBridgeRole::Accept,
        from,
        to,
        from,
        &n,
        &public,
        &sig
    ));
    assert!(!verify_bridge(
        AccountBridgeRole::Request,
        to,
        from,
        from,
        &n,
        &public,
        &sig
    ));
    assert!(!verify_bridge(
        AccountBridgeRole::Request,
        from,
        to,
        from,
        &nonce(),
        &public,
        &sig
    ));
    assert!(!verify_bridge(
        AccountBridgeRole::Request,
        from,
        to,
        from,
        &n,
        &other_public,
        &sig
    ));
}

#[test]
fn sealed_length_matches_the_c_header() {
    // include/keyquorum_identity.h: KQ_ACCOUNT_SEALED_LEN
    assert_eq!(SEALED_LEN, 81);
}
