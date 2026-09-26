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
