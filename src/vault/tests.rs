use super::*;
use crate::db;
use crate::test_secrets::{other_passphrase, passphrase};

#[test]
fn add_and_get_credential_roundtrip() {
    let secret = passphrase();
    let master = passphrase();
    let conn = db::open_in_memory().expect("schema should apply");
    let id = add_credential(
        &conn,
        "Email",
        Some("bailey"),
        secret.as_str(),
        master.as_str(),
    )
    .expect("add_credential should succeed");

    let credential =
        get_credential(&conn, id, master.as_str()).expect("get_credential should succeed");

    assert_eq!(credential.label, "Email");
    assert_eq!(credential.username.as_deref(), Some("bailey"));
    assert_eq!(credential.password.as_str(), secret.as_str());
}

#[test]
fn get_credential_fails_with_wrong_master_password() {
    let secret = passphrase();
    let master = passphrase();
    let wrong_master = other_passphrase(&master);
    let conn = db::open_in_memory().expect("schema should apply");
    let id = add_credential(&conn, "Email", None, secret.as_str(), master.as_str())
        .expect("add_credential should succeed");

    let result = get_credential(&conn, id, wrong_master.as_str());
    assert!(matches!(result, Err(Error::InvalidPassword)));
}
