use super::super::*;
use crate::db;

#[test]
fn keypair_generation_is_distinct_across_calls() {
    let (sk_a, pk_a) = generate_encryption_keypair();
    let (sk_b, pk_b) = generate_encryption_keypair();
    assert_ne!(*sk_a, *sk_b);
    assert_ne!(pk_a, pk_b);

    let (sign_sk_a, sign_pk_a) = generate_signing_keypair();
    let (sign_sk_b, sign_pk_b) = generate_signing_keypair();
    assert_ne!(*sign_sk_a, *sign_sk_b);
    assert_ne!(sign_pk_a, sign_pk_b);
}

#[test]
fn register_and_list_roundtrip() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    let key = get_key(&conn, id).expect("get_key should succeed");
    assert_eq!(key.label, "Alice");
    assert_eq!(key.key_type, KeyType::Encryption);
    assert_eq!(key.public_key, public_key);
    assert_eq!(key.fingerprint, fingerprint(&public_key));
    assert!(key.revoked_at.is_none());

    let keys = list_keys(&conn).expect("list_keys should succeed");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, id);
}

#[test]
fn register_key_rejects_wrong_length_public_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let result = register_key(&conn, "Alice", KeyType::Encryption, &[0u8; 31]);
    assert!(matches!(result, Err(Error::InvalidPublicKey)));

    let keys = list_keys(&conn).expect("list_keys should succeed");
    assert!(keys.is_empty());
}

#[test]
fn duplicate_fingerprint_is_rejected() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("first register_key should succeed");

    let result = register_key(&conn, "Alice (copy)", KeyType::Encryption, &public_key);
    assert!(matches!(result, Err(Error::Db(_))));
}

#[test]
fn revoke_sets_revoked_at() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    revoke_key(&conn, id).expect("revoke_key should succeed");
    let key = get_key(&conn, id).expect("get_key should succeed");
    assert!(key.revoked_at.is_some());
}

#[test]
fn remove_key_succeeds_when_unused() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    remove_key(&conn, id).expect("remove_key should succeed");
    assert!(get_key(&conn, id).is_err());
}

#[test]
fn get_active_encryption_key_rejects_revoked_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");
    revoke_key(&conn, id).expect("revoke_key should succeed");

    let result = get_active_encryption_key(&conn, id);
    assert!(matches!(result, Err(Error::KeyRevoked)));
}

#[test]
fn get_active_encryption_key_rejects_signing_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_signing_keypair();
    let id = register_key(&conn, "Alice", KeyType::Signing, &public_key)
        .expect("register_key should succeed");

    let result = get_active_encryption_key(&conn, id);
    assert!(matches!(result, Err(Error::WrongKeyType)));
}

#[test]
fn get_active_encryption_key_accepts_active_encryption_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    let key = get_active_encryption_key(&conn, id).expect("key should be active");
    assert_eq!(key.id, id);
}

#[test]
fn get_key_by_public_key_finds_the_registered_row() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    let key = get_key_by_public_key(&conn, &public_key).expect("lookup should succeed");
    assert_eq!(key.id, id);
    assert!(get_key_by_public_key(&conn, &[0u8; 32]).is_err());
}

#[test]
fn active_keys_for_lists_only_the_unrevoked_keys_of_that_purpose() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, first) = generate_encryption_keypair();
    let (_, second) = generate_encryption_keypair();
    let (_, signing) = generate_signing_keypair();
    let first_id = register_key(&conn, "M.S.2", KeyType::Encryption, &first).expect("register");
    register_key(&conn, "M.S.2", KeyType::Encryption, &second).expect("register");
    register_key(&conn, "M.S.2", KeyType::Signing, &signing).expect("register");
    register_key(&conn, "M.S.3", KeyType::Encryption, &{
        let (_, other) = generate_encryption_keypair();
        other
    })
    .expect("register");

    let active = active_keys_for(&conn, "M.S.2", KeyType::Encryption).expect("list");
    assert_eq!(active.len(), 2, "another label's key is not this label's");

    revoke_key(&conn, first_id).expect("revoke");
    let active = active_keys_for(&conn, "M.S.2", KeyType::Encryption).expect("list");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].public_key, second.to_vec());

    assert_eq!(
        active_keys_for(&conn, "M.S.2", KeyType::Signing)
            .expect("list")
            .len(),
        1
    );
    assert!(active_keys_for(&conn, "nobody", KeyType::Encryption)
        .expect("list")
        .is_empty());
}

#[test]
fn get_or_register_refuses_bytes_already_registered_for_the_other_purpose() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, signing) = generate_signing_keypair();
    let signing_id = register_key(&conn, "M.S.2", KeyType::Signing, &signing).expect("register");

    // Handing back the signing row would only fail later, at the
    // `key_nodes` trigger, as a raw SQL abort.
    assert!(matches!(
        get_or_register(&conn, "M.S.2", KeyType::Encryption, &signing),
        Err(Error::WrongKeyType)
    ));
    assert_eq!(
        get_or_register(&conn, "M.S.2", KeyType::Signing, &signing).expect("same purpose"),
        signing_id
    );

    let (_, fresh) = generate_encryption_keypair();
    let fresh_id = get_or_register(&conn, "M.S.2", KeyType::Encryption, &fresh).expect("register");
    assert_eq!(
        get_or_register(&conn, "M.S.2", KeyType::Encryption, &fresh).expect("idempotent"),
        fresh_id
    );
}

#[test]
fn revoke_superseded_retires_every_other_key_of_that_purpose() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, old) = generate_encryption_keypair();
    let (_, replacement) = generate_encryption_keypair();
    let (_, signing) = generate_signing_keypair();
    register_key(&conn, "M.S.2", KeyType::Encryption, &old).expect("register");
    register_key(&conn, "M.S.2", KeyType::Encryption, &replacement).expect("register");
    register_key(&conn, "M.S.2", KeyType::Signing, &signing).expect("register");

    revoke_superseded(&conn, "M.S.2", KeyType::Encryption, &replacement).expect("revoke");

    let active = active_keys_for(&conn, "M.S.2", KeyType::Encryption).expect("list");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].public_key, replacement.to_vec());
    // A different purpose is untouched, and re-running changes nothing.
    assert_eq!(
        active_keys_for(&conn, "M.S.2", KeyType::Signing)
            .expect("list")
            .len(),
        1
    );
    revoke_superseded(&conn, "M.S.2", KeyType::Encryption, &replacement).expect("idempotent");
    assert_eq!(
        active_keys_for(&conn, "M.S.2", KeyType::Encryption)
            .expect("list")
            .len(),
        1
    );
}
