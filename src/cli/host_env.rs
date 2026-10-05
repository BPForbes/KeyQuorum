//! Where the provider host's credentials and settings come from, resolved
//! once so every `host` command reads them the same way and never from a
//! command-line argument that `ps` could show.
//!
//! The order, for each value, is: a file named by a flag, a file named by
//! an environment variable, then (for compatibility) the raw value from a
//! flag or an environment variable, then a prompt where one makes sense.
//! A file is the preferred source for a long-lived secret: systemd hands a
//! credential to the service as a file in `$CREDENTIALS_DIRECTORY`, and a
//! Kubernetes secret is mounted as one, so the value never sits in the
//! process environment, in a unit file or in a shell history. The raw
//! sources stay for existing deployments.
//!
//! Files are read with a bound, only a trailing line ending is removed,
//! the value is zeroized when dropped, and no error names what was read.

use crate::error::{Error, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The most a credential or settings file may hold. A `kql_…` lock is 47
/// bytes, a hex key 64, a MongoDB URI a few hundred; anything larger is
/// not the file the operator meant.
pub const MAX_CREDENTIAL_FILE_BYTES: usize = 8 * 1024;

/// The internal operator lock (`kql_…`) for `host keys create|rotate`.
pub const LICENSEE_KEY_VAR: &str = "KEYQUORUM_LICENSEE_KEY";
/// A file holding that lock.
pub const LICENSEE_KEY_FILE_VAR: &str = "KEYQUORUM_LICENSEE_KEY_FILE";
/// The offline provider root private key, as key text (legacy).
pub const PROVIDER_ROOT_KEY_VAR: &str = "KEYQUORUM_PROVIDER_ROOT_KEY";
/// A file holding that key, as `root generate --private-key-out` wrote it.
pub const PROVIDER_ROOT_KEY_FILE_VAR: &str = "KEYQUORUM_PROVIDER_ROOT_KEY_FILE";
/// The hosted relay's MongoDB connection string, raw.
pub const MONGODB_URI_VAR: &str = "KEYQUORUM_MONGODB_URI";
/// A file holding that connection string.
pub const MONGODB_URI_FILE_VAR: &str = "KEYQUORUM_MONGODB_URI_FILE";
/// The database within the deployment (`keyquorum` when unset).
pub const MONGODB_DATABASE_VAR: &str = "KEYQUORUM_MONGODB_DB";

/// Read a credential file: at most [`MAX_CREDENTIAL_FILE_BYTES`], UTF-8,
/// with one trailing line ending (`\n` or `\r\n`) removed and nothing else
/// touched. An empty file is an error. The error never carries the
/// contents, only the path.
pub fn read_credential_file(path: &Path) -> Result<Zeroizing<String>> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(256));
    file.by_ref()
        .take(MAX_CREDENTIAL_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(Error::Usage(format!(
            "{} is larger than a credential file can be ({} bytes)",
            path.display(),
            MAX_CREDENTIAL_FILE_BYTES
        )));
    }
    let mut text = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes))
            .map_err(|_| Error::Usage(format!("{} is not UTF-8 text", path.display())))?,
    );
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    if text.is_empty() {
        return Err(Error::Usage(format!("{} is empty", path.display())));
    }
    Ok(text)
}

/// A 32-byte key file (a relay or provider-root private key, a relay public
/// key) as `host identity generate` and `host root generate` write it: hex
/// text. It is read with the same bound and the same line-ending rule as any
/// other credential file, so a misnamed large file cannot exhaust memory, and
/// the key is zeroized when dropped.
pub fn read_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let text = read_credential_file(path)?;
    crate::keys::parse_key_32(&text)
}

/// A value's source, in the order it is looked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A file, from a flag or the `*_FILE` variable.
    File(PathBuf),
    /// The value itself, from a flag or the legacy variable.
    Raw,
    /// Nothing was given; the command prompts or refuses.
    Absent,
}

/// What the environment says, as the resolver reads it (so tests can hand
/// it a map instead of the process environment).
pub trait Vars {
    fn var(&self, name: &str) -> Option<String>;
}

/// The process environment.
pub struct ProcessVars;

impl Vars for ProcessVars {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }
}

fn non_empty_path(path: Option<PathBuf>) -> Option<PathBuf> {
    path.filter(|p| !p.as_os_str().is_empty())
}

/// The operator lock, resolved as the module documentation says:
/// `--licensee-key-file`, `KEYQUORUM_LICENSEE_KEY_FILE`, `--licensee-key`,
/// `KEYQUORUM_LICENSEE_KEY`; `None` means prompt. Both flags at once is a
/// usage error rather than a guess.
pub fn licensee_key(
    file_flag: Option<PathBuf>,
    raw_flag: Option<String>,
    vars: &dyn Vars,
) -> Result<Option<Zeroizing<String>>> {
    let raw_flag = raw_flag.map(Zeroizing::new).filter(|s| !s.is_empty());
    let file_flag = non_empty_path(file_flag);
    if file_flag.is_some() && raw_flag.is_some() {
        return Err(Error::Usage(
            "--licensee-key and --licensee-key-file both name the operator lock; pass one".into(),
        ));
    }
    if let Some(path) = file_flag {
        return read_credential_file(&path).map(Some);
    }
    if let Some(path) = vars.var(LICENSEE_KEY_FILE_VAR) {
        return read_credential_file(Path::new(&path)).map(Some);
    }
    if let Some(raw) = raw_flag {
        return Ok(Some(raw));
    }
    Ok(vars.var(LICENSEE_KEY_VAR).map(Zeroizing::new))
}

/// Where the offline provider root key comes from: `--root-key`,
/// `KEYQUORUM_PROVIDER_ROOT_KEY_FILE`, then the raw
/// `KEYQUORUM_PROVIDER_ROOT_KEY` text. The key itself is read by the
/// caller's key reader, so this names the source only.
pub fn root_key_source(flag: Option<PathBuf>, vars: &dyn Vars) -> Source {
    if let Some(path) = non_empty_path(flag) {
        return Source::File(path);
    }
    if let Some(path) = vars.var(PROVIDER_ROOT_KEY_FILE_VAR) {
        return Source::File(PathBuf::from(path));
    }
    if vars.var(PROVIDER_ROOT_KEY_VAR).is_some() {
        return Source::Raw;
    }
    Source::Absent
}

/// The hosted relay's MongoDB settings when one is configured:
/// `--mongodb-uri-file`, `KEYQUORUM_MONGODB_URI_FILE`, then the raw
/// `KEYQUORUM_MONGODB_URI`. `None` means the relay keeps its SQLite file.
/// The connection string may carry a password, so it is zeroized and never
/// taken from a flag.
pub fn mongodb_uri(
    file_flag: Option<PathBuf>,
    vars: &dyn Vars,
) -> Result<Option<Zeroizing<String>>> {
    if let Some(path) = non_empty_path(file_flag) {
        return read_credential_file(&path).map(Some);
    }
    if let Some(path) = vars.var(MONGODB_URI_FILE_VAR) {
        return read_credential_file(Path::new(&path)).map(Some);
    }
    Ok(vars.var(MONGODB_URI_VAR).map(Zeroizing::new))
}

/// The database name: `--mongodb-db`, `KEYQUORUM_MONGODB_DB`, else the
/// default.
pub fn mongodb_database(flag: Option<String>, vars: &dyn Vars) -> String {
    flag.filter(|name| !name.is_empty())
        .or_else(|| vars.var(MONGODB_DATABASE_VAR))
        .unwrap_or_else(|| "keyquorum".to_string())
}

#[cfg(test)]
#[path = "host_env/tests.rs"]
mod tests;
