//! Mock USB drives. Each drive is a real `device` container — signed
//! `device.kq`, device signing key, Argon2id slot tokens — held in memory
//! under its mount path. [`DriveBay`] is the [`Storage`] the lab hands to
//! `device::*_in`: reads under an ejected drive's mount fail exactly as a
//! missing mount point would, so ejecting a drive removes its slots from
//! every quorum evaluation without any lab-side special casing.

use crate::device;
use crate::error::{Error, Result};
use crate::storage::{MemoryStorage, Storage};
use std::path::{Path, PathBuf};

pub struct MockDrive {
    pub id: String,
    pub name: String,
    pub mount: PathBuf,
    pub connected: bool,
    storage: MemoryStorage,
}

impl MockDrive {
    pub fn new(id: &str, name: &str, mount: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            mount: PathBuf::from(mount),
            connected: true,
            storage: MemoryStorage::new(),
        }
    }

    /// Files on the drive, relative to its mount, for display.
    pub fn listing(&self) -> Vec<String> {
        self.storage
            .paths_under(&self.mount)
            .into_iter()
            .filter_map(|path| {
                path.strip_prefix(&self.mount)
                    .ok()
                    .map(|rest| rest.display().to_string())
            })
            .collect()
    }

    /// The drive's signed `device.kq`, read whether or not it is inserted:
    /// what is on a drive does not change when it is unplugged.
    fn container(&self) -> Option<device::Container> {
        device::open_in(&self.storage, &self.mount).ok()
    }

    /// Slot labels its `device.kq` lists.
    pub fn slots(&self) -> Vec<String> {
        self.container()
            .map(|container| {
                container
                    .slots()
                    .iter()
                    .map(|slot| slot.label.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The device id inside its `device.kq`, once initialized.
    pub fn device_id(&self) -> Option<[u8; 16]> {
        self.container().map(|container| *container.device_id())
    }
}

#[derive(Default)]
pub struct DriveBay {
    pub drives: Vec<MockDrive>,
}

impl DriveBay {
    pub fn get(&self, id: &str) -> Option<&MockDrive> {
        self.drives.iter().find(|drive| drive.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut MockDrive> {
        self.drives.iter_mut().find(|drive| drive.id == id)
    }

    /// The drive carrying `slot_label`, inserted or not.
    pub fn holding(&self, slot_label: &str) -> Option<&MockDrive> {
        self.drives
            .iter()
            .find(|drive| drive.slots().iter().any(|slot| slot == slot_label))
    }

    fn mounted(&self, path: &Path) -> Result<&MockDrive> {
        let drive = self
            .drives
            .iter()
            .find(|drive| path.starts_with(&drive.mount))
            .ok_or_else(|| unmounted(path))?;
        if drive.connected {
            Ok(drive)
        } else {
            Err(unmounted(path))
        }
    }

    fn mounted_mut(&mut self, path: &Path) -> Result<&mut MockDrive> {
        let drive = self
            .drives
            .iter_mut()
            .find(|drive| path.starts_with(&drive.mount))
            .ok_or_else(|| unmounted(path))?;
        if drive.connected {
            Ok(drive)
        } else {
            Err(unmounted(path))
        }
    }
}

fn unmounted(path: &Path) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("no drive is inserted at {}", path.display()),
    ))
}

impl Storage for DriveBay {
    fn exists(&self, path: &Path) -> bool {
        self.mounted(path)
            .map(|drive| drive.storage.exists(path))
            .unwrap_or(false)
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        self.mounted(path)?.storage.read(path)
    }

    fn write_new(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        self.mounted_mut(path)?.storage.write_new(path, contents)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        let drive = self.mounted_mut(from)?;
        if !to.starts_with(&drive.mount) {
            return Err(Error::InvalidPath);
        }
        drive.storage.rename(from, to)
    }

    fn delete(&mut self, path: &Path) -> Result<()> {
        self.mounted_mut(path)?.storage.delete(path)
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<()> {
        self.mounted_mut(path).map(|_| ())
    }

    fn remove_empty_dir(&mut self, _path: &Path) {}

    fn list(&self, path: &Path) -> Result<Vec<PathBuf>> {
        self.mounted(path)?.storage.list(path)
    }
}
