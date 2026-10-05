use super::*;

#[test]
fn a_failed_commit_removes_the_bundle_it_wrote() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("customer.kqkey");
    let result: Result<()> = into_file(&out, |write| {
        write(b"sealed")?;
        Err(Error::Store("rolled back".to_string()))
    });
    assert!(result.is_err());
    assert!(!out.exists(), "a retry must not be refused by a leftover");
}

#[test]
fn an_unknown_commit_keeps_the_bundle_it_wrote() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("customer.kqkey");
    let result: Result<()> = into_file(&out, |write| {
        write(b"sealed")?;
        Err(Error::StoreCommitUnknown)
    });
    assert!(matches!(result, Err(Error::StoreCommitUnknown)));
    assert!(
        out.exists(),
        "the key may exist and this is its only handoff"
    );
}
