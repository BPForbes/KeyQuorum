//! Where container files and quorum ciphertext live.
//!
//! Native builds keep the original behavior: [`NativeStorage`] is plain
//! `std::fs`, with every new file created owner-only through
//! [`locked_files::write_owner_only`]. The browser lab has no filesystem,
//! so it hands `device` and `quorum` an in-memory implementation instead.
//! Only file placement moves behind this trait; the signed `device.kq`
//! descriptor, Argon2id slot tokens, and AES-GCM ciphertext are produced
//! and checked by the same code either way.

use crate::error::{Error, Result};
use crate::locked_files;
use std::fs;
use std::path::{Path, PathBuf};

pub trait Storage {
    fn exists(&self, path: &Path) -> bool;
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    /// Create `path` with `contents`. Refuses to replace an existing file.
    fn write_new(&mut self, path: &Path, contents: &[u8]) -> Result<()>;
    /// Replace `to` with `from`, removing `from`.
    fn rename(&mut self, from: &Path, to: &Path) -> Result<()>;
    /// Move `from` to `to` without ever replacing an existing `to`: an
    /// `AlreadyExists` error instead. The default checks, then renames, which
    /// is whole for a store only one command touches at a time (the in-memory
    /// ones); [`NativeStorage`] makes it atomic.
    fn rename_new(&mut self, from: &Path, to: &Path) -> Result<()> {
        if self.exists(to) {
            return Err(already_exists(to));
        }
        self.rename(from, to)
    }
    fn delete(&mut self, path: &Path) -> Result<()>;
    fn create_dir_all(&mut self, path: &Path) -> Result<()>;
    /// Best effort: remove `path` if it is an empty directory.
    fn remove_empty_dir(&mut self, path: &Path);
    /// Direct children of `path`, sorted.
    fn list(&self, path: &Path) -> Result<Vec<PathBuf>>;
    /// A regular file, not a directory.
    fn is_file(&self, path: &Path) -> bool {
        self.exists(path) && self.read(path).is_ok()
    }
    /// Create or replace `path`, like `std::fs::write` (no owner-only
    /// guarantee; use [`Storage::write_new`] for secrets).
    fn write(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        if self.exists(path) {
            self.delete(path)?;
        }
        self.write_new(path, contents)
    }
}

/// The real filesystem, as every native command has always used it.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeStorage;

impl Storage for NativeStorage {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(fs::read(path)?)
    }

    fn write_new(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        locked_files::write_owner_only(path, contents)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        Ok(fs::rename(from, to)?)
    }

    fn rename_new(&mut self, from: &Path, to: &Path) -> Result<()> {
        rename_new_with(from, to, |from, to| fs::hard_link(from, to))
    }

    fn delete(&mut self, path: &Path) -> Result<()> {
        Ok(fs::remove_file(path)?)
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<()> {
        Ok(fs::create_dir_all(path)?)
    }

    fn remove_empty_dir(&mut self, path: &Path) {
        let _ = fs::remove_dir(path);
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn write(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        Ok(fs::write(path, contents)?)
    }

    fn list(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut entries = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        Ok(entries)
    }
}

/// Files held in memory, keyed by path. Directories are implicit: a
/// directory exists while some file sits under it. Used by the browser lab
/// and by tests that should not touch a disk.
#[derive(Clone, Debug, Default)]
pub struct MemoryStorage {
    files: std::collections::BTreeMap<PathBuf, Vec<u8>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every stored path under `prefix`, for display.
    pub fn paths_under(&self, prefix: &Path) -> Vec<PathBuf> {
        self.files
            .keys()
            .filter(|path| path.starts_with(prefix))
            .cloned()
            .collect()
    }
}

/// [`Storage::rename_new`] on the real filesystem, with the hard link passed
/// in so a test can make it fail. A hard link fails if `to` exists, so no
/// other writer's file is ever replaced; the source name is then removed. A
/// filesystem without hard links (FAT, say) creates `to` with `create_new`
/// instead, which also never replaces a file, and copies the bytes in. A copy
/// cut short leaves `to` holding a prefix of `from`, which the caller can
/// recognise as its own; it is never a different file replaced.
pub(crate) fn rename_new_with(
    from: &Path,
    to: &Path,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    match link(from, to) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Err(err.into()),
        Err(_) => locked_files::write_owner_only(to, &fs::read(from)?)?,
    }
    let _ = fs::remove_file(from);
    Ok(())
}

fn already_exists(path: &Path) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("{} already exists", path.display()),
    ))
}

fn not_found(path: &Path) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{} does not exist", path.display()),
    ))
}

impl Storage for MemoryStorage {
    fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(path) || self.files.keys().any(|key| key.starts_with(path))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        self.files.get(path).cloned().ok_or_else(|| not_found(path))
    }

    fn write_new(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        if self.files.contains_key(path) {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            )));
        }
        self.files.insert(path.to_path_buf(), contents.to_vec());
        Ok(())
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        let contents = self.files.remove(from).ok_or_else(|| not_found(from))?;
        self.files.insert(to.to_path_buf(), contents);
        Ok(())
    }

    fn delete(&mut self, path: &Path) -> Result<()> {
        self.files
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| not_found(path))
    }

    fn create_dir_all(&mut self, _path: &Path) -> Result<()> {
        Ok(())
    }

    fn remove_empty_dir(&mut self, _path: &Path) {}

    fn list(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut children: Vec<PathBuf> = self
            .files
            .keys()
            .filter_map(|key| {
                let rest = key.strip_prefix(path).ok()?;
                let first = rest.components().next()?;
                Some(path.join(first))
            })
            .collect();
        children.dedup();
        if children.is_empty() && !self.exists(path) {
            return Err(not_found(path));
        }
        Ok(children)
    }
}

#[cfg(test)]
#[path = "storage/tests.rs"]
mod tests;
