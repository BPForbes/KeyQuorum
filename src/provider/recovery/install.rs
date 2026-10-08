//! Writing a recovered identity (native only). The operator names the
//! directory; nothing is chosen for them. It may not exist yet (its parent
//! must, and it is created owner-only) or be an owner-only directory that is
//! not a link. Each file is written under a private `.part` name and linked
//! into place, which never replaces a file: a file already there is kept
//! only when it holds exactly what would be written, and any other file at
//! that name is refused and left alone. The directory is re-checked before
//! every write, so a directory swapped for another (or a link) after the
//! plan is refused. A run cut short leaves at most a `.part` file, which the
//! next run removes, and files it can keep, so running the same command
//! again finishes it. The written files are read back and checked as the
//! relay checks its identity before success is reported.

use super::Recovered;
use crate::error::{Error, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The relay key's file name, as `host serve` and the runbook expect it.
pub const RELAY_KEY_FILE: &str = "relay.key";
/// The certificate's file name.
pub const CERTIFICATE_FILE: &str = "provider.kqcert";

/// The most of an existing file that is read to compare it: both files are
/// far smaller, so a larger one is simply not ours.
const MAX_EXISTING_BYTES: u64 = 64 * 1024;

/// Reads at most [`MAX_EXISTING_BYTES`] of `path`, zeroized when dropped.
fn read_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(MAX_EXISTING_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EXISTING_BYTES {
        return Err(refused(format!(
            "{} is larger than an identity file",
            path.display()
        )));
    }
    Ok(bytes)
}

/// What happens to one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAction {
    /// It is not there and will be written.
    Write,
    /// It is there with exactly these contents and is kept.
    Keep,
}

/// What [`install`] will do, decided before anything is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallPlan {
    pub dir: PathBuf,
    pub create_dir: bool,
    pub relay_key: FileAction,
    pub certificate: FileAction,
    /// The directory's identity when it already existed, re-checked before
    /// each write.
    identity: Option<DirIdentity>,
}

impl InstallPlan {
    /// Nothing is left to write.
    pub fn complete(&self) -> bool {
        !self.create_dir
            && self.relay_key == FileAction::Keep
            && self.certificate == FileAction::Keep
    }
}

fn refused(reason: String) -> Error {
    Error::KqpkgRefused(format!("provider recovery: {reason}"))
}

/// The relay key as written: lowercase hex, the form `host serve` reads.
fn relay_key_text(recovered: &Recovered) -> Zeroizing<String> {
    Zeroizing::new(hex::encode(&recovered.relay_private_key[..]))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirIdentity {
    dev: u64,
    ino: u64,
}

/// The directory as it is now: a real directory, not a link, owner-only.
fn check_dir(dir: &Path) -> Result<DirIdentity> {
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(refused(format!(
            "{} is not a directory (a link is refused)",
            dir.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            return Err(refused(format!(
                "{} is readable by others; use an owner-only (0700) directory",
                dir.display()
            )));
        }
        Ok(DirIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(DirIdentity { dev: 0, ino: 0 })
    }
}

/// What one existing file means: absent is written, the same bytes are
/// kept, anything else (other bytes, a link, a directory) is refused.
fn existing(path: &Path, matches: impl Fn(&[u8]) -> bool) -> Result<FileAction> {
    let meta = match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(FileAction::Write),
        Err(err) => return Err(err.into()),
        Ok(meta) => meta,
    };
    if !meta.is_file() {
        return Err(refused(format!(
            "{} is not a regular file; it is left alone",
            path.display()
        )));
    }
    let contents = read_bounded(path)?;
    if matches(&contents) {
        Ok(FileAction::Keep)
    } else {
        Err(refused(format!(
            "{} already holds something else; it is never replaced",
            path.display()
        )))
    }
}

fn key_matches(recovered: &Recovered) -> impl Fn(&[u8]) -> bool + '_ {
    move |contents| {
        std::str::from_utf8(contents)
            .ok()
            .and_then(|text| crate::keys::parse_key_32(text).ok())
            .is_some_and(|key| key[..] == recovered.relay_private_key[..])
    }
}

/// Decides what [`install`] would do in `dir`, refusing any conflict.
/// Writes nothing.
pub fn plan_install(dir: &Path, recovered: &Recovered) -> Result<InstallPlan> {
    match fs::symlink_metadata(dir) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let parent = dir
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if !parent.is_dir() {
                return Err(refused(format!(
                    "{} does not exist; its parent must",
                    dir.display()
                )));
            }
            Ok(InstallPlan {
                dir: dir.to_path_buf(),
                create_dir: true,
                relay_key: FileAction::Write,
                certificate: FileAction::Write,
                identity: None,
            })
        }
        Err(err) => Err(err.into()),
        Ok(_) => {
            let identity = check_dir(dir)?;
            Ok(InstallPlan {
                dir: dir.to_path_buf(),
                create_dir: false,
                relay_key: existing(&dir.join(RELAY_KEY_FILE), key_matches(recovered))?,
                certificate: existing(&dir.join(CERTIFICATE_FILE), |c| {
                    c == recovered.certificate.as_slice()
                })?,
                identity: Some(identity),
            })
        }
    }
}

/// Carries out `plan` (from [`plan_install`] for the same `recovered`), then
/// reads both files back and checks them against `root` as the relay checks
/// its identity. A plan made when nothing needed writing still runs that
/// check.
pub fn install(
    plan: &InstallPlan,
    recovered: &Recovered,
    root: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<()> {
    let dir = plan.dir.as_path();
    let identity = if plan.create_dir {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                refused(format!(
                    "{} appeared after the plan; run the command again",
                    dir.display()
                ))
            } else {
                err.into()
            }
        })?;
        check_dir(dir)?
    } else {
        let now = check_dir(dir)?;
        if Some(now) != plan.identity {
            return Err(refused(format!(
                "{} changed after the plan; run the command again",
                dir.display()
            )));
        }
        now
    };
    if plan.relay_key == FileAction::Write {
        let text = relay_key_text(recovered);
        place(
            dir,
            identity,
            RELAY_KEY_FILE,
            text.as_bytes(),
            key_matches(recovered),
        )?;
    }
    if plan.certificate == FileAction::Write {
        place(
            dir,
            identity,
            CERTIFICATE_FILE,
            &recovered.certificate,
            |c| c == recovered.certificate.as_slice(),
        )?;
    }
    verify_installed(dir, recovered, root, now_utc, revoked)
}

/// Writes `name` new: a private `.part` sibling (a leftover from a cut-short
/// run is removed first), the directory re-checked, then a hard link to the
/// final name, which fails rather than replace a file. A file that appeared
/// at that name meanwhile counts only when it holds the same contents.
fn place(
    dir: &Path,
    identity: DirIdentity,
    name: &str,
    contents: &[u8],
    matches: impl Fn(&[u8]) -> bool,
) -> Result<()> {
    let part = dir.join(format!(".{name}.part"));
    let target = dir.join(name);
    if fs::symlink_metadata(&part).is_ok() {
        fs::remove_file(&part)?;
    }
    crate::locked_files::write_owner_only(&part, contents)?;
    let linked = (|| {
        if check_dir(dir)? != identity {
            return Err(refused(format!(
                "{} changed while writing; run the command again",
                dir.display()
            )));
        }
        match fs::hard_link(&part, &target) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                match existing(&target, &matches)? {
                    FileAction::Keep => Ok(()),
                    FileAction::Write => Err(refused(format!(
                        "{} changed while writing; run the command again",
                        target.display()
                    ))),
                }
            }
            Err(err) => Err(err.into()),
        }
    })();
    let _ = fs::remove_file(&part);
    linked
}

/// Reads the installed files back and checks them as `host serve` does:
/// the certificate verifies against `root`, unrevoked and valid now, and
/// names the key in `relay.key`, which is the recovered one.
pub fn verify_installed(
    dir: &Path,
    recovered: &Recovered,
    root: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<()> {
    check_dir(dir)?;
    let key_path = dir.join(RELAY_KEY_FILE);
    let cert_path = dir.join(CERTIFICATE_FILE);
    for path in [&key_path, &cert_path] {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(refused(format!("{} is not a regular file", path.display())));
        }
    }
    let text = read_bounded(&key_path)?;
    let key = crate::keys::parse_key_32(
        std::str::from_utf8(&text)
            .map_err(|_| refused(format!("{} is not a key", key_path.display())))?,
    )?;
    let certificate = read_bounded(&cert_path)?.to_vec();
    let checked = crate::provider::self_check(root, &certificate, &key, now_utc, revoked)?;
    if checked.relay_public_key != recovered.relay_public_key
        || certificate != recovered.certificate
    {
        return Err(refused(format!(
            "{} does not hold the recovered identity",
            dir.display()
        )));
    }
    Ok(())
}
