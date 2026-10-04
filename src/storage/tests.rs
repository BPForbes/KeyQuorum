use super::*;

#[test]
fn memory_storage_refuses_to_overwrite_and_lists_children() {
    let mut storage = MemoryStorage::new();
    let root = Path::new("/media/usb");
    storage
        .write_new(&root.join("device.kq"), b"descriptor")
        .unwrap();
    storage
        .write_new(&root.join("vault/slot-M.S/token.kqst"), b"token")
        .unwrap();

    assert!(storage
        .write_new(&root.join("device.kq"), b"again")
        .is_err());
    assert_eq!(
        storage.read(&root.join("device.kq")).unwrap(),
        b"descriptor"
    );
    assert!(storage.exists(&root.join("vault")));
    assert_eq!(
        storage.list(root).unwrap(),
        vec![root.join("device.kq"), root.join("vault")]
    );

    storage
        .rename(&root.join("device.kq"), &root.join("moved.kq"))
        .unwrap();
    assert!(!storage.exists(&root.join("device.kq")));
    storage.delete(&root.join("moved.kq")).unwrap();
    assert!(matches!(
        storage.read(&root.join("moved.kq")),
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound
    ));
}

#[test]
fn native_storage_writes_new_files_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blob");
    let mut storage = NativeStorage;
    storage.write_new(&path, b"one").unwrap();
    assert!(storage.write_new(&path, b"two").is_err());
    assert_eq!(storage.read(&path).unwrap(), b"one");
    assert_eq!(storage.list(dir.path()).unwrap(), vec![path.clone()]);
    storage.delete(&path).unwrap();
    assert!(!storage.exists(&path));
}

fn rename_new_never_replaces(storage: &mut dyn Storage, dir: &Path) {
    let (from, to) = (dir.join("letter.part"), dir.join("letter.kqpb"));
    storage.write_new(&from, b"first").unwrap();
    storage.rename_new(&from, &to).unwrap();
    assert!(!storage.exists(&from));
    assert_eq!(storage.read(&to).unwrap(), b"first");

    storage.write_new(&from, b"second").unwrap();
    assert!(matches!(
        storage.rename_new(&from, &to),
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(storage.read(&to).unwrap(), b"first");
    assert_eq!(storage.read(&from).unwrap(), b"second");
}

#[test]
fn rename_new_moves_a_file_but_never_replaces_one() {
    rename_new_never_replaces(&mut MemoryStorage::new(), Path::new("/out"));
    let dir = tempfile::tempdir().unwrap();
    rename_new_never_replaces(&mut NativeStorage, dir.path());
}

#[test]
fn without_hard_links_a_file_published_meanwhile_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (from, to) = (
        dir.path().join("letter.part"),
        dir.path().join("letter.kqpb"),
    );
    std::fs::write(&from, b"ours").unwrap();
    // The hard link is unsupported, and another writer publishes before the
    // fallback runs.
    let refused = rename_new_with(&from, &to, |_, to| {
        std::fs::write(to, b"theirs").unwrap();
        Err(std::io::ErrorKind::Unsupported.into())
    });
    assert!(matches!(
        refused,
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(std::fs::read(&to).unwrap(), b"theirs");
    assert_eq!(std::fs::read(&from).unwrap(), b"ours");

    // With the name free, the fallback copies the letter in and removes the source.
    std::fs::remove_file(&to).unwrap();
    rename_new_with(&from, &to, |_, _| {
        Err(std::io::ErrorKind::Unsupported.into())
    })
    .unwrap();
    assert_eq!(std::fs::read(&to).unwrap(), b"ours");
    assert!(!from.exists());
}
