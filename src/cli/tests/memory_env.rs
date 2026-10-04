//! An in-memory [`Env`] for running whole CLI commands in tests: files in a
//! `MemoryStorage`, one in-memory store per `--db` path, captured stdout
//! and stderr, and every passphrase prompt answered with [`PASSPHRASE`].

use crate::cli::env::{self, Env};
use crate::cli::{self, device_tool, Cli};
use crate::error::{Error, Result};
use crate::relay::{self, ProviderIdentity, RelayHttpRequest, RelayHttpResponse};
use crate::storage::{MemoryStorage, Storage};
use crate::{keys, provider};
use clap::Parser;
use rusqlite::Connection;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const PASSPHRASE: &str = "correct horse";

#[derive(Default)]
pub struct MemoryEnv {
    pub fs: MemoryStorage,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    stores: HashMap<PathBuf, Connection>,
    /// Answers for the next prompts, each zeroized once consumed; after
    /// that, [`PASSPHRASE`]. Tests queue one with [`MemoryEnv::answer_prompt`];
    /// the next answer sits last, so a prompt pops it.
    prompts: Vec<Zeroizing<String>>,
    /// The clock (`yyyy-mm-dd hh:mm`); a fixed default when unset.
    pub now: Option<String>,
    /// Milliseconds the precise clock adds after the seconds (`"482"`);
    /// none by default, so the precise clock equals [`MemoryEnv::now`].
    pub millis: Option<String>,
    /// Environment variables the commands can read.
    pub vars: HashMap<String, String>,
    /// A relay served in process (see [`MemoryEnv::with_relay`]); none by default.
    pub relay: Option<TestRelay>,
}

/// The relay a test environment answers for: the crate's own request handling
/// over an in-memory database, behind a certificate that chains to a test root.
pub struct TestRelay {
    pub conn: Connection,
    pub identity: ProviderIdentity,
    root_public: [u8; 32],
    /// The test root's signing key, kept so a test can certify a second
    /// relay under the same root ([`MemoryEnv::other_relay_identity`]).
    root_private: Zeroizing<[u8; 32]>,
    /// How many `POST /provider-identity` challenges commands have made.
    pub identity_challenges: usize,
    /// How many `POST /keycheck` requests commands have made: the one request
    /// that carries a bearer to the relay.
    pub key_checks: usize,
    /// Make uploads (`POST /inbox`) fail as a dropped connection would.
    pub fail_uploads: bool,
    /// Let this many uploads through, then fail every later one.
    pub fail_uploads_after: Option<usize>,
}

pub const RELAY_URL: &str = "https://relay.test";

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
        Ok(match self.prompts.pop() {
            Some(mut answer) => std::mem::take(&mut *answer),
            None => PASSPHRASE.to_string(),
        })
    }

    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }

    fn relay_send(&mut self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        let Some(relay) = self.relay.as_mut() else {
            return Err(Error::RelayRequest("no relay in this test".into()));
        };
        if request.url.path() == "/provider-identity" {
            relay.identity_challenges += 1;
        }
        if request.url.path() == "/keycheck" {
            relay.key_checks += 1;
        }
        if request.method == "POST" && request.url.path() == "/inbox" {
            let out_of_uploads = match relay.fail_uploads_after.as_mut() {
                Some(0) => true,
                Some(left) => {
                    *left -= 1;
                    false
                }
                None => false,
            };
            if relay.fail_uploads || out_of_uploads {
                return Err(Error::RelayRequest("connection reset".into()));
            }
        }
        Ok(relay::service::dispatch(
            &relay.conn,
            Some(&relay.identity),
            &request,
        ))
    }

    fn provider_root(&self) -> [u8; 32] {
        match &self.relay {
            Some(relay) => relay.root_public,
            None => crate::provider::KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        }
    }

    fn now_utc(&self) -> Result<String> {
        Ok(self
            .now
            .clone()
            .unwrap_or_else(|| "2026-09-27 00:00".into()))
    }

    fn now_utc_precise(&self) -> Result<String> {
        let now = self.now_utc()?;
        Ok(match &self.millis {
            Some(millis) if now.len() == 16 => format!("{now}:00.{millis}"),
            Some(millis) => format!("{now}.{millis}"),
            None => now,
        })
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
    /// Answer the next secret prompt with `answer` instead of [`PASSPHRASE`].
    /// The answer is held zeroized until the prompt consumes it.
    pub fn answer_prompt(&mut self, answer: impl Into<String>) {
        // Answers already queued are asked first, so the new one goes in
        // front of them, at the start of the popped-from-the-end list.
        let mut prompts = vec![Zeroizing::new(answer.into())];
        prompts.extend(std::mem::take(&mut self.prompts));
        self.prompts = prompts;
    }

    /// An environment whose relay is [`RELAY_URL`], answered in process.
    pub fn with_relay() -> Self {
        let mut env = MemoryEnv::default();
        env.attach_relay();
        env
    }

    /// Give this environment a relay at [`RELAY_URL`].
    pub fn attach_relay(&mut self) {
        let conn = relay::open_in_memory().expect("relay database");
        let (root_private, root_public) = keys::generate_signing_keypair();
        let (relay_private, relay_public) = provider::generate_relay_identity();
        let certificate = provider::issue_certificate(
            &root_private,
            &provider::NewCertificate {
                provider_id: "Test relay",
                serial: "TEST-1",
                relay_public_key: &relay_public,
                issued_at: "2026-01-01 00:00:00",
                expires_at: "2999-12-31 23:59:00",
                capabilities: provider::CAP_PROVIDER,
                issuer_id: "TestRoot",
            },
        )
        .expect("test certificate");
        self.vars
            .insert("KEYQUORUM_RELAY_URL".into(), RELAY_URL.into());
        self.relay = Some(TestRelay {
            conn,
            identity: ProviderIdentity {
                certificate,
                relay_private_key: relay_private,
            },
            root_public,
            root_private,
            identity_challenges: 0,
            key_checks: 0,
            fail_uploads: false,
            fail_uploads_after: None,
        });
    }

    /// A second relay identity the same test root certifies: a different relay
    /// key and serial, so the root vouches for both and only the signing key
    /// tells them apart.
    pub fn other_relay_identity(&self) -> ProviderIdentity {
        let relay = self.relay.as_ref().expect("a relay");
        let (relay_private, relay_public) = provider::generate_relay_identity();
        let certificate = provider::issue_certificate(
            &relay.root_private,
            &provider::NewCertificate {
                provider_id: "Other test relay",
                serial: "TEST-2",
                relay_public_key: &relay_public,
                issued_at: "2026-01-01 00:00:00",
                expires_at: "2999-12-31 23:59:00",
                capabilities: provider::CAP_PROVIDER,
                issuer_id: "TestRoot",
            },
        )
        .expect("test certificate");
        ProviderIdentity {
            certificate,
            relay_private_key: relay_private,
        }
    }

    /// Mint a relay key of `scope` (inbox push needs no recipient).
    pub fn relay_key(&self, scope: relay::ApiKeyScope, fingerprint: Option<String>) -> String {
        let relay = self.relay.as_ref().expect("a relay");
        relay::create_api_key(
            &relay.conn,
            &relay::NewApiKey {
                scope,
                recipient_fingerprint: fingerprint,
                label: Some("test".into()),
                ttl_seconds: None,
            },
        )
        .expect("relay key")
        .token
        .as_str()
        .to_owned()
    }

    /// The store at `path`, once a command has opened it.
    pub fn store(&self, path: &str) -> &Connection {
        self.stores
            .get(Path::new(path))
            .expect("a command has opened this store")
    }

    /// Run one `keyquorum` command line; returns its result and stdout.
    pub fn keyquorum(&mut self, line: &str) -> (Result<()>, String) {
        let cli = Cli::try_parse_from(line.split_whitespace()).expect("command line parses");
        self.run(|| cli::run_cli(cli))
    }

    /// Run one `keyquorum-device` command line.
    pub fn device(&mut self, line: &str) -> (Result<()>, String) {
        let cli = device_tool::DeviceToolCli::try_parse_from(line.split_whitespace())
            .expect("command line parses");
        self.run(|| device_tool::run(cli))
    }

    pub(super) fn run(&mut self, f: impl FnOnce() -> Result<()>) -> (Result<()>, String) {
        self.stdout.clear();
        let (result, env) = env::scoped(std::mem::take(self), f);
        *self = env;
        (result, String::from_utf8_lossy(&self.stdout).into_owned())
    }
}
