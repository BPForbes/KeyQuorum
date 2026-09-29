//! An in-memory [`Env`] for running whole CLI commands in tests: files in a
//! `MemoryStorage`, one in-memory store per `--db` path, captured stdout
//! and stderr, and every passphrase prompt answered with [`PASSPHRASE`].

use crate::cli::env::{self, Env};
use crate::cli::{self, device_tool, Cli};
use crate::error::{Error, Result};
use crate::relay::{RelayHttpRequest, RelayHttpResponse};
use crate::storage::{MemoryStorage, Storage};
use clap::Parser;
use rusqlite::Connection;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const PASSPHRASE: &str = "correct horse";

#[derive(Default)]
pub struct MemoryEnv {
    pub fs: MemoryStorage,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    stores: HashMap<PathBuf, Connection>,
}

impl Env for MemoryEnv {
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
        Ok(Vec::new())
    }

    fn prompt_secret(&mut self, _prompt: &str) -> Result<String> {
        Ok(PASSPHRASE.to_string())
    }

    fn var(&self, _name: &str) -> Option<String> {
        None
    }

    fn relay_send(&mut self, _request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        Err(Error::RelayRequest("no relay in this test".into()))
    }

    fn now_utc(&self) -> Result<String> {
        Ok("2026-09-27 00:00".into())
    }

    fn open_db(&mut self, path: &Path) -> Result<Connection> {
        match self.stores.remove(path) {
            Some(conn) => Ok(conn),
            None => Ok(crate::db::open_in_memory()?),
        }
    }

    fn close_db(&mut self, path: &Path, conn: Connection) {
        self.stores.insert(path.to_path_buf(), conn);
    }
}

impl MemoryEnv {
    /// The store at `path`, once a command has opened it.
    pub fn store(&self, path: &str) -> &Connection {
        self.stores
            .get(Path::new(path))
            .expect("a command has opened this store")
    }

    /// Run one `keyquorum` command line; returns its result and stdout.
    pub fn keyquorum(&mut self, line: &str) -> (Result<()>, String) {
        let cli = Cli::try_parse_from(line.split_whitespace()).expect("command line parses");
        self.run(|| cli::run(&cli.db, cli.command))
    }

    /// Run one `keyquorum-device` command line.
    pub fn device(&mut self, line: &str) -> (Result<()>, String) {
        let cli = device_tool::DeviceToolCli::try_parse_from(line.split_whitespace())
            .expect("command line parses");
        self.run(|| device_tool::run(cli))
    }

    fn run(&mut self, f: impl FnOnce() -> Result<()>) -> (Result<()>, String) {
        self.stdout.clear();
        let (result, env) = env::scoped(std::mem::take(self), f);
        *self = env;
        (result, String::from_utf8_lossy(&self.stdout).into_owned())
    }
}
