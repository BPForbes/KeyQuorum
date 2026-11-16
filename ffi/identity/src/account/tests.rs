use super::*;

/// A password drawn at run time, so no secret is written as a literal.
fn password() -> String {
    crypto::random_salt()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A bridge nonce drawn at run time (16 random bytes, the salt length).
fn nonce() -> [u8; 16] {
    crypto::random_salt()
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
    // Swap the first two magic bytes ("KQ" -> "QK"): no longer a sealed key.
    sealed.swap(0, 1);
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

#[test]
fn only_the_requester_signs_a_request_and_only_the_target_line_accepts() {
    let (secret, public) = generate();
    let n = nonce();
    let (from, to) = ("Root.Alternative.Ann", "Root.Flinstone.Bob");
    // An unrelated account cannot sign either half under its own name, even
    // with its own legitimate key.
    for signer in ["Root.Alternative", "Root.Other", "Root.Flinstone.Bob.Kid"] {
        assert!(sign_bridge(AccountBridgeRole::Request, from, to, signer, &n, &secret).is_none());
    }
    assert!(sign_bridge(
        AccountBridgeRole::Accept,
        from,
        to,
        "Root.Alternative",
        &n,
        &secret
    )
    .is_none());
    assert!(sign_bridge(AccountBridgeRole::Accept, from, to, from, &n, &secret).is_none());
    // The target and its ancestors may accept.
    for signer in [to, "Root.Flinstone", "Root"] {
        let sig = sign_bridge(AccountBridgeRole::Accept, from, to, signer, &n, &secret).unwrap();
        assert!(verify_bridge(
            AccountBridgeRole::Accept,
            from,
            to,
            signer,
            &n,
            &public,
            &sig
        ));
    }
}

#[test]
fn verify_refuses_a_signer_outside_its_role_even_with_a_valid_signature() {
    let (secret, public) = generate();
    let n = nonce();
    let (from, to) = ("Root.Alternative.Ann", "Root.Flinstone.Bob");
    // A signature made directly over the preimage, as an attacker holding
    // their own key could, for an accept naming an unrelated signer.
    let digest = signing::account_bridge_preimage(
        AccountBridgeRole::Accept,
        from,
        to,
        "Root.Alternative",
        &n,
    )
    .unwrap();
    let sig = signing::sign(&secret, &digest);
    assert!(!verify_bridge(
        AccountBridgeRole::Accept,
        from,
        to,
        "Root.Alternative",
        &n,
        &public,
        &sig
    ));
}

#[test]
fn bridges_join_only_different_branches_with_valid_labels() {
    let (secret, _) = generate();
    let n = nonce();
    // One line needs no bridge.
    assert!(sign_bridge(
        AccountBridgeRole::Request,
        "Root.Flinstone",
        "Root.Flinstone.Bob",
        "Root.Flinstone",
        &n,
        &secret
    )
    .is_none());
    assert!(sign_bridge(
        AccountBridgeRole::Request,
        "Root.Flinstone",
        "Root.Flinstone",
        "Root.Flinstone",
        &n,
        &secret
    )
    .is_none());
    // Not key ids.
    assert!(sign_bridge(
        AccountBridgeRole::Request,
        "nobody",
        "Root.Flinstone",
        "nobody",
        &n,
        &secret
    )
    .is_none());
    assert!(sign_bridge(
        AccountBridgeRole::Request,
        "Root.A",
        "Root.B",
        "Root.A",
        &n,
        &secret
    )
    .is_some());
}

#[test]
fn a_sudo_is_co_signed_by_the_invoker_and_the_authority() {
    let (invoker_secret, invoker_public) = generate();
    let (root_secret, root_public) = generate();
    let n = nonce();
    let action = b"sudo -i";
    let mine = sign_sudo(
        SudoCosignRole::Invoker,
        "Root.Flinstone",
        "Root",
        action,
        &n,
        &invoker_secret,
    )
    .unwrap();
    let root = sign_sudo(
        SudoCosignRole::Authority,
        "Root.Flinstone",
        "Root",
        action,
        &n,
        &root_secret,
    )
    .unwrap();
    assert!(verify_sudo(
        "Root.Flinstone",
        "Root",
        action,
        &n,
        &invoker_public,
        &mine,
        &root_public,
        &root
    ));
    // Either half alone, or the two swapped, never verifies.
    assert!(!verify_sudo(
        "Root.Flinstone",
        "Root",
        action,
        &n,
        &invoker_public,
        &mine,
        &root_public,
        &mine
    ));
    assert!(!verify_sudo(
        "Root.Flinstone",
        "Root",
        action,
        &n,
        &root_public,
        &root,
        &invoker_public,
        &mine
    ));
    // Bound to its action, nonce and accounts.
    assert!(!verify_sudo(
        "Root.Flinstone",
        "Root",
        b"sudo",
        &n,
        &invoker_public,
        &mine,
        &root_public,
        &root
    ));
    assert!(!verify_sudo(
        "Root.Flinstone",
        "Root",
        action,
        &nonce(),
        &invoker_public,
        &mine,
        &root_public,
        &root
    ));
    assert!(!verify_sudo(
        "Root.Other",
        "Root",
        action,
        &n,
        &invoker_public,
        &mine,
        &root_public,
        &root
    ));
}

#[test]
fn a_sudo_by_two_accounts_needs_two_keys() {
    // A registry that maps the invoker and its ancestor to one key gets no co-signature:
    // that key's holder could sign both halves alone.
    let (secret, public) = generate();
    let n = nonce();
    let action = b"sudo";
    let sign = |role| sign_sudo(role, "Root.Flinstone", "Root", action, &n, &secret).unwrap();
    let mine = sign(SudoCosignRole::Invoker);
    let root = sign(SudoCosignRole::Authority);
    assert!(!verify_sudo(
        "Root.Flinstone",
        "Root",
        action,
        &n,
        &public,
        &mine,
        &public,
        &root
    ));
    // An account elevating to itself signs both halves with its one key.
    let mine = sign_sudo(SudoCosignRole::Invoker, "Root", "Root", action, &n, &secret).unwrap();
    let root = sign_sudo(
        SudoCosignRole::Authority,
        "Root",
        "Root",
        action,
        &n,
        &secret,
    )
    .unwrap();
    assert!(verify_sudo(
        "Root", "Root", action, &n, &public, &mine, &public, &root
    ));
}

#[test]
fn a_sudo_authority_must_be_the_invoker_or_an_ancestor() {
    let (secret, _) = generate();
    let n = nonce();
    for (invoker, authority) in [
        ("Root", "Root.Flinstone"),
        ("Root.Flinstone", "Root.Other"),
        ("Root.Flinstone", "bad label"),
    ] {
        assert!(!sudo_signer_may_sign(
            SudoCosignRole::Authority,
            invoker,
            authority,
            authority
        ));
        assert!(sign_sudo(
            SudoCosignRole::Invoker,
            invoker,
            authority,
            b"sudo",
            &n,
            &secret
        )
        .is_none());
    }
    assert!(sudo_signer_may_sign(
        SudoCosignRole::Authority,
        "Root.Flinstone.Bob",
        "Root",
        "Root"
    ));
    assert!(!sudo_signer_may_sign(
        SudoCosignRole::Authority,
        "Root.Flinstone.Bob",
        "Root",
        "Root.Flinstone.Bob"
    ));
    assert!(!sudo_signer_may_sign(
        SudoCosignRole::Invoker,
        "Root.Flinstone.Bob",
        "Root",
        "Root"
    ));
}

#[test]
fn a_sudo_action_must_be_present_and_bounded() {
    let (secret, _) = generate();
    let n = nonce();
    let long = vec![b'x'; SUDO_ACTION_MAX + 1];
    for action in [&b""[..], &long[..]] {
        assert!(sign_sudo(
            SudoCosignRole::Invoker,
            "Root.Flinstone",
            "Root",
            action,
            &n,
            &secret
        )
        .is_none());
    }
    assert!(sign_sudo(
        SudoCosignRole::Invoker,
        "Root.Flinstone",
        "Root",
        &long[..SUDO_ACTION_MAX],
        &n,
        &secret
    )
    .is_some());
}
