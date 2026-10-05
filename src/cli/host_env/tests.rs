use super::*;
use crate::test_secrets;
use std::collections::HashMap;

struct MapVars(HashMap<&'static str, String>);

impl Vars for MapVars {
    fn var(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned().filter(|v| !v.is_empty())
    }
}

fn vars(pairs: &[(&'static str, String)]) -> MapVars {
    MapVars(pairs.iter().cloned().collect())
}

fn file_with(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write");
    path
}

#[test]
fn a_credential_file_loses_only_its_trailing_line_ending() {
    let dir = tempfile::tempdir().expect("tempdir");
    let value = test_secrets::passphrase();
    let plain = file_with(&dir, "plain", value.as_bytes());
    assert_eq!(
        read_credential_file(&plain).expect("read").as_str(),
        value.as_str()
    );
    let unix = file_with(&dir, "unix", format!("{}\n", value.as_str()).as_bytes());
    assert_eq!(
        read_credential_file(&unix).expect("read").as_str(),
        value.as_str()
    );
    let dos = file_with(&dir, "dos", format!("{}\r\n", value.as_str()).as_bytes());
    assert_eq!(
        read_credential_file(&dos).expect("read").as_str(),
        value.as_str()
    );
    // Inner whitespace and a second line ending are the file's own.
    let two = file_with(&dir, "two", format!(" {}\n\n", value.as_str()).as_bytes());
    assert_eq!(
        read_credential_file(&two).expect("read").as_str(),
        format!(" {}\n", value.as_str())
    );
}

#[test]
fn a_credential_file_must_be_small_utf8_and_not_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let empty = file_with(&dir, "empty", b"\n");
    assert!(matches!(read_credential_file(&empty), Err(Error::Usage(_))));
    let binary = file_with(&dir, "binary", &[0xff, 0xfe, 0x00]);
    assert!(matches!(
        read_credential_file(&binary),
        Err(Error::Usage(_))
    ));
    let huge = file_with(&dir, "huge", &vec![b'a'; MAX_CREDENTIAL_FILE_BYTES + 1]);
    assert!(matches!(read_credential_file(&huge), Err(Error::Usage(_))));
    let exact = file_with(&dir, "exact", &vec![b'a'; MAX_CREDENTIAL_FILE_BYTES]);
    assert_eq!(
        read_credential_file(&exact).expect("read").len(),
        MAX_CREDENTIAL_FILE_BYTES
    );
    assert!(matches!(
        read_credential_file(&dir.path().join("missing")),
        Err(Error::Io(_))
    ));
}

#[test]
fn an_error_names_the_path_and_never_the_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let value = test_secrets::passphrase();
    let huge = file_with(
        &dir,
        "huge",
        format!(
            "{}{}",
            value.as_str(),
            "x".repeat(MAX_CREDENTIAL_FILE_BYTES)
        )
        .as_bytes(),
    );
    let message = read_credential_file(&huge)
        .expect_err("too large")
        .to_string();
    assert!(message.contains("huge"));
    assert!(!message.contains(value.as_str()));
}

#[test]
fn the_operator_lock_prefers_a_file_and_refuses_two_flags() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from_file = test_secrets::passphrase();
    let from_env_file = test_secrets::other_passphrase(&from_file);
    let file = file_with(&dir, "lock", format!("{}\n", from_file.as_str()).as_bytes());
    let env_file = file_with(&dir, "env-lock", from_env_file.as_bytes());
    let raw = test_secrets::other_passphrase(&from_env_file);

    // The flag's file first.
    let got = licensee_key(
        Some(file.clone()),
        None,
        &vars(&[
            (LICENSEE_KEY_FILE_VAR, env_file.display().to_string()),
            (LICENSEE_KEY_VAR, raw.to_string()),
        ]),
    )
    .expect("resolve")
    .expect("a value");
    assert_eq!(got.as_str(), from_file.as_str());
    // Then the variable's file, even over a raw flag.
    let got = licensee_key(
        None,
        Some(raw.to_string()),
        &vars(&[(LICENSEE_KEY_FILE_VAR, env_file.display().to_string())]),
    )
    .expect("resolve")
    .expect("a value");
    assert_eq!(got.as_str(), from_env_file.as_str());
    // Then the raw flag, then the raw variable, then nothing (prompt).
    let got = licensee_key(
        None,
        Some(raw.to_string()),
        &vars(&[(LICENSEE_KEY_VAR, "other".into())]),
    )
    .expect("resolve")
    .expect("a value");
    assert_eq!(got.as_str(), raw.as_str());
    let got = licensee_key(None, None, &vars(&[(LICENSEE_KEY_VAR, raw.to_string())]))
        .expect("resolve")
        .expect("a value");
    assert_eq!(got.as_str(), raw.as_str());
    assert!(licensee_key(None, None, &vars(&[]))
        .expect("resolve")
        .is_none());
    assert!(licensee_key(None, Some(String::new()), &vars(&[]))
        .expect("resolve")
        .is_none());
    // Both flags: refused, not guessed.
    assert!(matches!(
        licensee_key(Some(file), Some(raw.to_string()), &vars(&[])),
        Err(Error::Usage(_))
    ));
    // A file the variable names but that cannot be read is an error, not a
    // fall-through to the raw value.
    assert!(licensee_key(
        None,
        Some(raw.to_string()),
        &vars(&[(
            LICENSEE_KEY_FILE_VAR,
            dir.path().join("missing").display().to_string()
        )]),
    )
    .is_err());
}

#[test]
fn the_root_key_source_prefers_the_flag_then_the_file_variable() {
    let flag = PathBuf::from("root.key");
    assert_eq!(
        root_key_source(
            Some(flag.clone()),
            &vars(&[(PROVIDER_ROOT_KEY_VAR, "aa".into())])
        ),
        Source::File(flag)
    );
    assert_eq!(
        root_key_source(
            None,
            &vars(&[
                (PROVIDER_ROOT_KEY_FILE_VAR, "/run/root.key".into()),
                (PROVIDER_ROOT_KEY_VAR, "aa".into()),
            ])
        ),
        Source::File(PathBuf::from("/run/root.key"))
    );
    assert_eq!(
        root_key_source(None, &vars(&[(PROVIDER_ROOT_KEY_VAR, "aa".into())])),
        Source::Raw
    );
    assert_eq!(
        root_key_source(Some(PathBuf::new()), &vars(&[])),
        Source::Absent
    );
}

#[test]
fn the_mongodb_uri_comes_from_a_file_before_the_environment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = file_with(
        &dir,
        "uri",
        b"mongodb://relay-user:pw@mongo.internal/?replicaSet=rs0\n",
    );
    let got = mongodb_uri(
        Some(file.clone()),
        &vars(&[(MONGODB_URI_VAR, "mongodb://other".into())]),
    )
    .expect("resolve")
    .expect("a value");
    assert_eq!(
        got.as_str(),
        "mongodb://relay-user:pw@mongo.internal/?replicaSet=rs0"
    );
    let got = mongodb_uri(
        None,
        &vars(&[(MONGODB_URI_FILE_VAR, file.display().to_string())]),
    )
    .expect("resolve")
    .expect("a value");
    assert!(got.starts_with("mongodb://"));
    let got = mongodb_uri(None, &vars(&[(MONGODB_URI_VAR, "mongodb://other".into())]))
        .expect("resolve")
        .expect("a value");
    assert_eq!(got.as_str(), "mongodb://other");
    assert!(mongodb_uri(None, &vars(&[])).expect("resolve").is_none());
    assert_eq!(mongodb_database(None, &vars(&[])), "keyquorum");
    assert_eq!(
        mongodb_database(None, &vars(&[(MONGODB_DATABASE_VAR, "relay".into())])),
        "relay"
    );
    assert_eq!(
        mongodb_database(
            Some("flag".into()),
            &vars(&[(MONGODB_DATABASE_VAR, "relay".into())])
        ),
        "flag"
    );
}
