//! The process environment a CLI command runs in: stdout, stderr, the
//! filesystem, the terminal it prompts on, environment variables, and the
//! SQLite store behind `--db`.
//!
//! Command code reaches these through the free functions and the
//! `outln!`/`errln!` macros here, the way a process reaches its own stdout
//! and disk, so the handlers read like ordinary CLI code. By default that
//! is [`NativeEnv`]: the real terminal and `std::fs`, exactly what the
//! `keyquorum` binary always used. [`scoped`] installs a different
//! environment for the duration of one call; the browser lab uses it to
//! run the same commands against its in-memory filesystem, mock drives,
//! and per-person stores.

use crate::error::{Error, Result};
use crate::relay::{RelayHttpRequest, RelayHttpResponse, RelayTransport};
use crate::storage::{NativeStorage, Storage};
use rusqlite::Connection;
use std::any::Any;
use std::cell::RefCell;
use std::fmt;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

pub trait Env: Any {
    fn stdout(&mut self) -> &mut dyn Write;
    fn stderr(&mut self) -> &mut dyn Write;
    fn fs(&mut self) -> &mut dyn Storage;
    /// Everything on standard input.
    fn read_stdin(&mut self) -> Result<Vec<u8>>;
    /// Read a secret from the terminal without echoing it.
    fn prompt_secret(&mut self, prompt: &str) -> Result<String>;
    fn var(&self, name: &str) -> Option<String>;
    /// Deliver one relay request (HTTPS natively; the lab's relay runs in
    /// process).
    fn relay_send(&mut self, request: RelayHttpRequest) -> Result<RelayHttpResponse>;
    /// The root key a relay's provider certificate must chain to.
    fn provider_root(&self) -> [u8; 32] {
        crate::provider::KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY
    }
    /// The current UTC time, as `provider::system_now_utc` formats it, for
    /// certificate checks.
    fn now_utc(&self) -> Result<String>;
    /// Open (creating if needed) the organization store at `path`.
    fn open_db(&mut self, path: &Path) -> Result<Connection>;
    /// Hand a store opened by [`Env::open_db`] back when the command ends.
    fn close_db(&mut self, path: &Path, conn: Connection);
}

/// The real process: terminal, `std::fs`, and SQLite files on disk.
#[derive(Default)]
pub struct NativeEnv {
    stdout: NativeStdout,
    stderr: NativeStderr,
    fs: NativeStorage,
}

#[derive(Default)]
struct NativeStdout;

impl Write for NativeStdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

#[derive(Default)]
struct NativeStderr;

impl Write for NativeStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stderr().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

impl Env for NativeEnv {
    fn stdout(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }

    fn fs(&mut self) -> &mut dyn Storage {
        &mut self.fs
    }

    fn read_stdin(&mut self) -> Result<Vec<u8>> {
        let mut input = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut input)?;
        Ok(input)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn prompt_secret(&mut self, prompt: &str) -> Result<String> {
        rpassword::prompt_password(prompt).map_err(Error::from)
    }

    #[cfg(target_arch = "wasm32")]
    fn prompt_secret(&mut self, _prompt: &str) -> Result<String> {
        Err(Error::InvalidPassword)
    }

    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn relay_send(&mut self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        crate::relay::UreqTransport.send(request)
    }

    #[cfg(target_arch = "wasm32")]
    fn relay_send(&mut self, _request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        Err(Error::RelayRequest(
            "no relay is reachable from this environment".into(),
        ))
    }

    fn now_utc(&self) -> Result<String> {
        crate::provider::system_now_utc()
    }

    fn open_db(&mut self, path: &Path) -> Result<Connection> {
        crate::db::open(path.to_str().ok_or(Error::InvalidPath)?)
    }

    fn close_db(&mut self, _path: &Path, conn: Connection) {
        drop(conn);
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Box<dyn Env>>> = const { RefCell::new(None) };
}

/// Run `f` with `env` installed as the process environment, then hand
/// `env` back. Calls nest: the previous environment is restored after.
pub fn scoped<E: Env, R>(env: E, f: impl FnOnce() -> R) -> (R, E) {
    let previous = CURRENT.with(|current| current.replace(Some(Box::new(env))));
    let result = f();
    let installed = CURRENT
        .with(|current| current.replace(previous))
        .expect("scoped environment is still installed");
    let installed: Box<dyn Any> = installed;
    let env = installed
        .downcast::<E>()
        .expect("scoped environment has the type it was installed with");
    (result, *env)
}

/// Borrow the current environment. Keep the closure short: it must not
/// call back into another accessor.
fn with<R>(f: impl FnOnce(&mut dyn Env) -> R) -> R {
    CURRENT.with(|current| match current.borrow_mut().as_mut() {
        Some(env) => f(env.as_mut()),
        None => f(&mut NativeEnv::default()),
    })
}

#[doc(hidden)]
pub fn write_stdout(args: fmt::Arguments) {
    with(|env| {
        let _ = env.stdout().write_fmt(args);
    });
}

#[doc(hidden)]
pub fn write_stderr(args: fmt::Arguments) {
    with(|env| {
        let _ = env.stderr().write_fmt(args);
    });
}

/// Raw bytes to stdout (e.g. a decrypted file), reporting write failures.
pub fn stdout_bytes(bytes: &[u8]) -> Result<()> {
    with(|env| env.stdout().write_all(bytes).map_err(Error::from))
}

/// Run `f` against the environment's filesystem.
pub fn fs<R>(f: impl FnOnce(&mut dyn Storage) -> R) -> R {
    with(|env| f(env.fs()))
}

pub fn read(path: &Path) -> Result<Vec<u8>> {
    fs(|fs| fs.read(path))
}

pub fn exists(path: &Path) -> bool {
    fs(|fs| fs.exists(path))
}

pub fn is_file(path: &Path) -> bool {
    fs(|fs| fs.is_file(path))
}

pub fn read_to_string(path: &Path) -> Result<String> {
    String::from_utf8(read(path)?).map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        ))
    })
}

/// Create or replace `path`, like `std::fs::write`.
pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    fs(|fs| fs.write(path, contents))
}

pub fn create_dir_all(path: &Path) -> Result<()> {
    fs(|fs| fs.create_dir_all(path))
}

pub fn remove_file(path: &Path) -> Result<()> {
    fs(|fs| fs.delete(path))
}

/// Direct children of `path`, sorted.
pub fn read_dir(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    fs(|fs| fs.list(path))
}

/// Create `path` owner-only; refuses to replace an existing file, like
/// `locked_files::write_owner_only`.
pub fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    fs(|fs| fs.write_new(path, contents))
}

pub fn read_stdin() -> Result<Vec<u8>> {
    with(|env| env.read_stdin())
}

pub fn prompt_secret(prompt: &str) -> Result<String> {
    with(|env| env.prompt_secret(prompt))
}

/// Prompt for a device passphrase and refuse an empty one.
pub fn prompt_passphrase(prompt: &str) -> Result<String> {
    let passphrase = prompt_secret(prompt)?;
    if passphrase.is_empty() {
        return Err(Error::InvalidPassword);
    }
    Ok(passphrase)
}

/// Prompt twice and refuse an empty or mismatched passphrase.
pub fn confirm_passphrase(first_prompt: &str, second_prompt: &str) -> Result<String> {
    let passphrase = prompt_passphrase(first_prompt)?;
    let again = prompt_passphrase(second_prompt)?;
    if passphrase != again {
        return Err(Error::InvalidPassword);
    }
    Ok(passphrase)
}

/// `std::env::var` for the current environment.
pub fn var(name: &str) -> std::result::Result<String, std::env::VarError> {
    with(|env| env.var(name)).ok_or(std::env::VarError::NotPresent)
}

pub fn open_db(path: &Path) -> Result<Connection> {
    with(|env| env.open_db(path))
}

pub fn close_db(path: &Path, conn: Connection) {
    with(|env| env.close_db(path, conn));
}

/// Open the store at `path`, run `f` on it, and hand it back to the
/// environment whether or not `f` succeeded.
pub fn with_db<R>(path: &Path, f: impl FnOnce(&mut Connection) -> Result<R>) -> Result<R> {
    let mut conn = open_db(path)?;
    let result = f(&mut conn);
    close_db(path, conn);
    result
}

/// An open organization store that goes back to the environment when it
/// is dropped, for commands that hold more than one store at a time.
pub struct Store {
    path: PathBuf,
    conn: Option<Connection>,
}

pub fn open_store(path: &Path) -> Result<Store> {
    Ok(Store {
        path: path.to_path_buf(),
        conn: Some(open_db(path)?),
    })
}

impl Deref for Store {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("store is open until dropped")
    }
}

impl DerefMut for Store {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("store is open until dropped")
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            close_db(&self.path, conn);
        }
    }
}

/// A [`Storage`] handle onto the current environment's filesystem. Like
/// `NativeStorage` it carries no state, so a caller that needs two
/// storages (a transfer's source and destination) can pass two of them;
/// each call borrows the environment only for its own duration.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvStorage;

impl Storage for EnvStorage {
    fn exists(&self, path: &Path) -> bool {
        fs(|fs| fs.exists(path))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        fs(|fs| fs.read(path))
    }

    fn write_new(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        fs(|fs| fs.write_new(path, contents))
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        fs(|fs| fs.rename(from, to))
    }

    fn delete(&mut self, path: &Path) -> Result<()> {
        fs(|fs| fs.delete(path))
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<()> {
        fs(|fs| fs.create_dir_all(path))
    }

    fn remove_empty_dir(&mut self, path: &Path) {
        fs(|fs| fs.remove_empty_dir(path))
    }

    fn list(&self, path: &Path) -> Result<Vec<PathBuf>> {
        fs(|fs| fs.list(path))
    }

    fn is_file(&self, path: &Path) -> bool {
        fs(|fs| fs.is_file(path))
    }

    fn write(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        fs(|fs| fs.write(path, contents))
    }
}

/// A [`RelayTransport`] onto the current environment, so CLI code passes
/// one value to every relay client call.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvRelay;

impl RelayTransport for EnvRelay {
    fn send(&self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        with(|env| env.relay_send(request))
    }
}

pub fn provider_root() -> [u8; 32] {
    with(|env| env.provider_root())
}

pub fn now_utc() -> Result<String> {
    with(|env| env.now_utc())
}

/// Hand `f` the current environment's stdout as a writer.
pub fn with_stdout<R>(f: impl FnOnce(&mut dyn Write) -> R) -> R {
    with(|env| f(env.stdout()))
}

/// `println!` for the current environment's stdout.
macro_rules! outln {
    () => {
        $crate::cli::env::write_stdout(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::cli::env::write_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// `print!` for the current environment's stdout.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::cli::env::write_stdout(format_args!($($arg)*))
    };
}

/// `eprintln!` for the current environment's stderr.
macro_rules! errln {
    () => {
        $crate::cli::env::write_stderr(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::cli::env::write_stderr(format_args!("{}\n", format_args!($($arg)*)))
    };
}

pub(crate) use {errln, out, outln};
