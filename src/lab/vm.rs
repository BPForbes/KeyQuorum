//! The lab's virtual machine: the environment the real `keyquorum` and
//! `keyquorum-device` commands run in when the browser lab drives them.
//!
//! It stands in for the pieces of a real computer the CLI touches, and
//! nothing else:
//! - a filesystem ([`MemoryStorage`]) with the mock USB drives mounted
//!   under `/media` ([`DriveBay`]); an ejected drive is simply unmounted,
//!   so every read through it fails the way a missing mount point does;
//! - one SQLite store per `--db` path, held in memory for the session;
//! - a terminal whose passphrase prompts are answered with the published
//!   demo passphrases (see [`super::seed::demo_passphrase`]) and echoed as
//!   `********`, so the transcript shows every prompt the CLI asked. A GUI
//!   action that lets a person type their own secret stages it first with
//!   [`LabVm::stage_secret`]/[`stage_secrets`](LabVm::stage_secrets), which
//!   the next prompt(s) consume before falling back to the demo answer;
//! - a relay: the crate's own relay request handling
//!   ([`relay::service::dispatch`]) run in process, reachable only at
//!   [`RELAY_URL`], presenting a provider certificate issued for this
//!   session by a lab root that only this VM trusts. The root's private
//!   key is discarded once that certificate exists.
//!
//! Commands are parsed with the CLI's own clap definitions and executed by
//! [`cli::run`] / [`device_tool::run`]; the VM never decides anything a
//! command decides.

use super::drives::DriveBay;
use super::seed;
use crate::cli::env::{self, Env};
use crate::cli::{self, device_tool, Cli};
use crate::error::{Error, Result};
use crate::keys;
use crate::provider::{self, NewCertificate};
use crate::relay::{self, ProviderIdentity, RelayHttpRequest, RelayHttpResponse};
use crate::storage::{MemoryStorage, Storage};
use clap::error::ErrorKind;
use clap::Parser;
use rusqlite::{Connection, OpenFlags};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

/// The organization's shared store: registry, device placements, the org
/// tree and its bridges, and the quorum-locked files.
pub const ORG_DB: &str = "/srv/keyquorum/org.sqlite";

/// The only relay the VM can reach.
pub const RELAY_URL: &str = "https://relay.keyquorum.lab";

/// Stand-in answer for password and PIN prompts (vault, password-locked
/// files) typed at the lab terminal. Public, like every demo secret.
pub const DEMO_PASSWORD: &str = "lab-demo-password";

/// One command line's result, as a terminal would show it.
pub struct CommandRun {
    pub line: String,
    pub ok: bool,
    pub stdout: Vec<u8>,
    /// Prompts (with masked answers), diagnostics, and any `error:` line.
    pub stderr: String,
}

impl CommandRun {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// The error line, without its `error: ` prefix, if the command failed.
    pub fn error(&self) -> Option<&str> {
        self.stderr
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix("error: "))
    }
}

struct RelayHost {
    conn: Connection,
    identity: ProviderIdentity,
    root_public: [u8; 32],
}

pub struct LabVm {
    files: MemoryStorage,
    pub bay: DriveBay,
    stores: HashMap<PathBuf, Connection>,
    /// Distinguishes this VM's shared-cache database names from every other
    /// `LabVm` alive in the same process (see `open_shared_memory_db`), so
    /// two lab sessions (or two tests) that both use `ORG_DB` never share
    /// SQLite's process-wide shared cache with each other.
    db_namespace: u64,
    relay: RelayHost,
    cwd: PathBuf,
    vars: HashMap<String, String>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Answers a GUI action staged for the next command's prompts, consumed
    /// in order (one per `prompt_secret` call) before falling back to the
    /// seeded demo answer. Lets a person type their own passphrase, PIN, or
    /// password instead of always getting the published demo value. Each
    /// answer is zeroized when consumed, cleared or dropped. Held with the
    /// next answer last, so a prompt pops it; nothing is ever moved out from
    /// the front.
    staged_answers: Vec<Zeroizing<String>>,
}

impl LabVm {
    pub fn new(bay: DriveBay) -> Result<Self> {
        let conn = relay::open_in_memory()?;
        let now: String = conn.query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:00', 'now', '-1 minute')",
            [],
            |row| row.get(0),
        )?;
        let (root_private, root_public) = keys::generate_signing_keypair();
        let (relay_private, relay_public) = provider::generate_relay_identity();
        let certificate = provider::issue_certificate(
            &root_private,
            &NewCertificate {
                provider_id: "KeyQuorum Lab relay",
                serial: "LAB-SESSION",
                relay_public_key: &relay_public,
                issued_at: &now,
                expires_at: "2999-12-31 23:59:00",
                capabilities: provider::CAP_PROVIDER,
                issuer_id: "KeyQuorumLabRoot",
            },
        )?;
        drop(root_private);
        let mut vars = HashMap::new();
        vars.insert("KEYQUORUM_RELAY_URL".to_string(), RELAY_URL.to_string());
        static NEXT_NAMESPACE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Ok(Self {
            files: MemoryStorage::new(),
            bay,
            stores: HashMap::new(),
            db_namespace: NEXT_NAMESPACE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            relay: RelayHost {
                conn,
                identity: ProviderIdentity {
                    certificate,
                    relay_private_key: relay_private,
                },
                root_public,
            },
            cwd: PathBuf::from("/"),
            vars,
            stdout: Vec::new(),
            stderr: Vec::new(),
            staged_answers: Vec::new(),
        })
    }

    /// Stage one secret to answer the next `prompt_secret` call instead of
    /// the seeded demo answer. Call this before running a command whose
    /// prompt should be answered with a person's own choice; the value is
    /// consumed by the first matching prompt.
    pub fn stage_secret(&mut self, value: impl Into<String>) {
        self.stage_secrets([value.into()]);
    }

    /// Stage several secrets for a command that prompts more than once
    /// (e.g. a passphrase entered twice, or a password followed by a PIN),
    /// consumed in the order given.
    pub fn stage_secrets(&mut self, values: impl IntoIterator<Item = String>) {
        // The next answer sits last: the new ones go in, reversed, behind
        // whatever is already staged, which is still answered first.
        let mut staged: Vec<Zeroizing<String>> = values.into_iter().map(Zeroizing::new).collect();
        staged.reverse();
        staged.extend(std::mem::take(&mut self.staged_answers));
        self.staged_answers = staged;
    }

    /// Drop any staged secrets that a command did not consume, so a later,
    /// unrelated prompt never accidentally reuses a stale value. Callers
    /// that stage a secret should call this after running the command,
    /// whether or not it succeeded.
    pub fn clear_pending_secrets(&mut self) {
        self.staged_answers.clear();
    }

    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn set_cwd(&mut self, dir: impl Into<PathBuf>) {
        self.cwd = dir.into();
    }

    /// The relay's own database, for the operator steps the provider
    /// performs out of band (issuing API keys).
    pub fn relay_conn(&self) -> &Connection {
        &self.relay.conn
    }

    /// Read-only access to a store for rendering the lab's views.
    pub fn store(&self, path: &str) -> Option<&Connection> {
        self.stores.get(&self.resolve(Path::new(path)))
    }

    /// Mutable access to a store, for seeding only.
    pub fn store_mut(&mut self, path: &str) -> Option<&mut Connection> {
        let path = self.resolve(Path::new(path));
        self.stores.get_mut(&path)
    }

    /// Absolute, `.`/`..`-free form of `path`, relative to the working
    /// directory.
    pub fn resolve(&self, path: &Path) -> PathBuf {
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        };
        let mut out = PathBuf::from("/");
        for component in joined.components() {
            match component {
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(part) => out.push(part),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
        out
    }

    fn is_media(path: &Path) -> bool {
        path.starts_with("/media")
    }

    /// Run one command line: `keyquorum …` or `keyquorum-device …`.
    pub fn exec(mut self, line: &str) -> (CommandRun, Self) {
        self.stdout.clear();
        self.stderr.clear();
        let argv = match split_command_line(line) {
            Ok(argv) if !argv.is_empty() => argv,
            Ok(_) => return (self.finish(line, Ok(())), self),
            Err(message) => {
                let _ = writeln!(self.stderr, "{message}");
                return (self.finish_failed(line), self);
            }
        };
        let ran = match argv[0].as_str() {
            "keyquorum" => match Cli::try_parse_from(&argv) {
                Ok(parsed) => {
                    let (ran, vm) = env::scoped(self, || cli::run_cli(parsed));
                    self = vm;
                    ran
                }
                Err(err) => return self.clap_error(line, err),
            },
            "keyquorum-device" => match device_tool::DeviceToolCli::try_parse_from(&argv) {
                Ok(parsed) => {
                    let (ran, vm) = env::scoped(self, || device_tool::run(parsed));
                    self = vm;
                    ran
                }
                Err(err) => return self.clap_error(line, err),
            },
            other => {
                let _ = writeln!(self.stderr, "{other}: command not found");
                return (self.finish_failed(line), self);
            }
        };
        (self.finish(line, ran), self)
    }

    fn clap_error(mut self, line: &str, err: clap::Error) -> (CommandRun, Self) {
        let rendered = err.render().to_string();
        let ok = matches!(
            err.kind(),
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
        );
        if ok {
            self.stdout.extend_from_slice(rendered.as_bytes());
        } else {
            self.stderr.extend_from_slice(rendered.as_bytes());
        }
        let run = CommandRun {
            line: line.to_string(),
            ok,
            stdout: std::mem::take(&mut self.stdout),
            stderr: String::from_utf8_lossy(&std::mem::take(&mut self.stderr)).into_owned(),
        };
        (run, self)
    }

    fn finish(&mut self, line: &str, ran: Result<()>) -> CommandRun {
        let ok = ran.is_ok();
        if let Err(err) = ran {
            let _ = writeln!(self.stderr, "error: {err}");
        }
        CommandRun {
            line: line.to_string(),
            ok,
            stdout: std::mem::take(&mut self.stdout),
            stderr: String::from_utf8_lossy(&std::mem::take(&mut self.stderr)).into_owned(),
        }
    }

    fn finish_failed(&mut self, line: &str) -> CommandRun {
        CommandRun {
            line: line.to_string(),
            ok: false,
            stdout: std::mem::take(&mut self.stdout),
            stderr: String::from_utf8_lossy(&std::mem::take(&mut self.stderr)).into_owned(),
        }
    }

    /// The answer a person at this terminal would type. Slot prompts get
    /// that slot's published demo passphrase; a "Key for …" prompt (a leaf
    /// the command was not given a key or slot for) is left blank, which
    /// the CLI treats as "skip".
    fn answer(prompt: &str) -> String {
        let label = prompt
            .strip_prefix("Passphrase for ")
            .or_else(|| prompt.strip_prefix("Repeat passphrase for "))
            .and_then(|rest| rest.strip_suffix(": "));
        if let Some(label) = label {
            return seed::demo_passphrase(label);
        }
        if prompt.starts_with("Key for ") {
            return String::new();
        }
        if prompt.contains("PIN") {
            return "0000".to_string();
        }
        DEMO_PASSWORD.to_string()
    }
}

impl Storage for LabVm {
    fn exists(&self, path: &Path) -> bool {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.exists(&path)
        } else {
            self.files.exists(&path)
        }
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.read(&path)
        } else {
            self.files.read(&path)
        }
    }

    fn write_new(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.write_new(&path, contents)
        } else {
            self.files.write_new(&path, contents)
        }
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        let (from, to) = (self.resolve(from), self.resolve(to));
        match (Self::is_media(&from), Self::is_media(&to)) {
            (true, true) => self.bay.rename(&from, &to),
            (false, false) => self.files.rename(&from, &to),
            _ => Err(Error::InvalidPath),
        }
    }

    fn delete(&mut self, path: &Path) -> Result<()> {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.delete(&path)
        } else {
            self.files.delete(&path)
        }
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<()> {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.create_dir_all(&path)
        } else {
            self.files.create_dir_all(&path)
        }
    }

    fn remove_empty_dir(&mut self, path: &Path) {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.remove_empty_dir(&path)
        } else {
            self.files.remove_empty_dir(&path)
        }
    }

    fn list(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.list(&path)
        } else {
            self.files.list(&path)
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        let path = self.resolve(path);
        if Self::is_media(&path) {
            self.bay.is_file(&path)
        } else {
            self.files.is_file(&path)
        }
    }
}

impl Env for LabVm {
    fn stdout(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }

    fn fs(&mut self) -> &mut dyn Storage {
        self
    }

    fn read_stdin(&mut self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn prompt_secret(&mut self, prompt: &str) -> Result<String> {
        let answer = match self.staged_answers.pop() {
            Some(mut staged) => std::mem::take(&mut *staged),
            None => Self::answer(prompt),
        };
        let shown = if answer.is_empty() { "" } else { "********" };
        let _ = writeln!(self.stderr, "{prompt}{shown}");
        Ok(answer)
    }

    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }

    fn relay_send(&mut self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        let reachable = url::Url::parse(RELAY_URL)
            .ok()
            .is_some_and(|relay| relay.host() == request.url.host());
        if !reachable {
            return Err(Error::RelayRequest(format!(
                "could not reach {}: the lab can only reach {RELAY_URL}",
                request.url.host_str().unwrap_or("that host")
            )));
        }
        Ok(relay::service::dispatch(
            &self.relay.conn,
            Some(&self.relay.identity),
            &request,
        ))
    }

    fn provider_root(&self) -> [u8; 32] {
        self.relay.root_public
    }

    fn now_utc(&self) -> Result<String> {
        Ok(self
            .relay
            .conn
            .query_row("SELECT strftime('%Y-%m-%d %H:%M:00', 'now')", [], |row| {
                row.get(0)
            })?)
    }

    fn now_utc_precise(&self) -> Result<String> {
        Ok(self
            .relay
            .conn
            .query_row("SELECT strftime('%Y-%m-%d %H:%M:%f', 'now')", [], |row| {
                row.get(0)
            })?)
    }

    fn open_db(&mut self, path: &Path) -> Result<Connection> {
        let path = self.resolve(path);
        // Every open of the same path attaches to the same named in-memory
        // database (SQLite's memdb VFS), the way multiple connections to one
        // real SQLite *file* all see the same rows. The first open for a
        // path also parks a permanent anchor connection in `stores`: SQLite
        // drops a shared memdb database once its last connection closes,
        // and without the anchor that would happen every time a
        // command finishes and hands its connection back via `close_db`,
        // silently resetting the store on the next open (the bug behind
        // `transfer_copy --from-db PATH --to-db PATH`, where opening the
        // source used to remove it from `stores` and opening the
        // destination would then find nothing and create an unrelated
        // empty database).
        if !self.stores.contains_key(&path) {
            let anchor = open_shared_memory_db(self.db_namespace, &path)?;
            self.stores.insert(path.clone(), anchor);
        }
        open_shared_memory_db(self.db_namespace, &path)
    }

    fn close_db(&mut self, _path: &Path, conn: Connection) {
        // The anchor in `stores` (see `open_db`) is what keeps this path's
        // data alive; the checked-out handle itself can simply close.
        drop(conn);
    }
}

/// Open a fresh connection to the named in-memory database for `path` within
/// `db_namespace` (one `LabVm`'s own database names, distinct from every
/// other `LabVm` alive in the process — named memdb databases are otherwise
/// shared process-wide, which would leak state between separate lab
/// sessions, or between tests running concurrently in the same test binary),
/// creating and schema-initializing it if this is the first connection ever
/// opened for that name. Every connection returned for the same
/// `(db_namespace, path)` shares the same underlying data for as long as any
/// connection to it (including the `LabVm` anchor) stays open.
///
/// This uses the memdb VFS (a `/`-prefixed name is shared between
/// connections), not `cache=shared`: the browser build's SQLite
/// (`sqlite-wasm-rs`) is compiled with `SQLITE_OMIT_SHARED_CACHE`, where
/// `cache=shared` is silently ignored and every connection would get its own
/// private, empty database.
fn open_shared_memory_db(db_namespace: u64, path: &Path) -> Result<Connection> {
    let mut hasher = DefaultHasher::new();
    db_namespace.hash(&mut hasher);
    path.hash(&mut hasher);
    let uri = format!("file:/labdb_{:x}?vfs=memdb", hasher.finish());
    let conn = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    crate::db::init(&conn)?;
    Ok(conn)
}

/// Split a command line into words: whitespace separates, single and
/// double quotes group, and a backslash escapes the next character.
pub fn split_command_line(line: &str) -> std::result::Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => current.push(c),
                        None => return Err("unterminated ' quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c) => current.push(c),
                            None => return Err("unterminated \" quote".into()),
                        },
                        Some(c) => current.push(c),
                        None => return Err("unterminated \" quote".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(c) = chars.next() {
                    current.push(c);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                current.push(c);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

/// Quote `value` for a command line if it needs it.
pub fn quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-=:,+@%>".contains(c))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}
