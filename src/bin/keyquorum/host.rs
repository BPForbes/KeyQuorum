//! Provider-only mailbox host. Compiled only with `--features provider`.
//! Hidden from `keyquorum --help`. Customers use `loadkey` with a URL
//! and bearer they were given.
//!
//! `--features provider` compiles these commands; it does not authorize a
//! host. `serve` and customer-API-key minting require a KeyQuorum-signed
//! `provider.kqcert` and the matching relay private key. Customers never
//! mint keys: they receive a `kq_…` bearer. The `kql_…` issuer is an
//! internal operator lock created only after that identity check.

use keyquorum::api_key_delivery::MAX_LICENCE_BYTES;
use keyquorum::cli;
use keyquorum::cli::host_args::{
    BackupCommand, HostCommand, IdentityCommand, KeysCommand, PolicyCommand, RootCommand,
};
use keyquorum::cli::host_env::{self, ProcessVars};
use keyquorum::db;
use keyquorum::error::{Error, Result};
use keyquorum::keys::{self, KeyType};
use keyquorum::locked_files;
use keyquorum::provider::hardware_auth::HardwareAuthority;
use keyquorum::provider::policy::{self, HardwareAuthorityEntry, NewPolicy};
use keyquorum::provider::provision;
use keyquorum::provider::{self, NewCertificate, KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY};
use keyquorum::relay::key_delivery::{Delivered, Recipient, Via};
use keyquorum::relay::{
    self, ApiKeyScope, AppState, NewApiKey, OldKey, ProviderAuthEvent, ProviderIdentity,
    RelayStore, SqliteRelayStore, HOST_ACTOR,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

/// Where the relay keeps its state, from the `host` command's own flags.
pub struct StoreArgs {
    pub mailbox_db: PathBuf,
}

/// Runs one `keyquorum host` subcommand. The store is opened only by the
/// commands that need it.
pub fn run(store_args: &StoreArgs, org_db: &Path, command: HostCommand) -> Result<()> {
    match command {
        HostCommand::Serve {
            bind,
            cert,
            relay_key,
            krl,
            scan_db,
            scan_interval_seconds,
            behind_tls_proxy,
            rate_limit_per_minute,
        } => {
            // INFO by default (RUST_LOG still overrides), so authentication
            // and scope denials and TTL purges reach the operator's logs
            // without opt-in.
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                )
                .init();
            let addr: SocketAddr = bind
                .parse()
                .map_err(|e| Error::RelayRequest(format!("invalid bind address: {e}")))?;
            relay::check_bind(&addr, behind_tls_proxy)?;
            let (identity, _) = load_serve_identity(cert, relay_key, krl)?;
            // The store is opened, and the first anchor signed, before the
            // async runtime exists: the store blocks (SQLite on its lock),
            // and a blocking call belongs on the blocking pool once the
            // runtime runs (`with_store`, the scan), never on its driver
            // thread.
            let store = open_store(store_args)?;
            tracing::info!("relay store: {}", store.backend());
            // Anything recorded while the relay was down (host `keys`
            // commands run without an identity) is signed now.
            if let Err(err) = relay::anchor_now(store.as_ref(), &identity) {
                tracing::warn!("audit anchor at startup failed: {err}");
            }
            let scan_db = scan_db.or_else(|| org_db.is_file().then(|| org_db.to_path_buf()));
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(Error::Io)?
                .block_on(serve(
                    store,
                    identity,
                    addr,
                    scan_db,
                    scan_interval_seconds,
                    behind_tls_proxy,
                    rate_limit_per_minute,
                ))
        }
        HostCommand::Identity { command } => run_identity(command),
        HostCommand::Backup { command } => run_backup(command),
        HostCommand::Provision {
            out,
            provider_id,
            serial,
            issued_at,
            expires_at,
            capabilities,
            issuer_id,
        } => {
            let issued_at = match issued_at.filter(|s| !s.is_empty()) {
                Some(value) => value,
                None => provider::system_now_utc()?,
            };
            let spec = provision::Spec {
                provider_id: &provider_id,
                serial: &serial,
                issued_at: &issued_at,
                expires_at: &expires_at,
                capabilities: provider::parse_capabilities(&capabilities)?,
                issuer_id: &issuer_id,
            };
            let written = run_provision(&out, &spec)?;
            print_provisioned(&written);
            Ok(())
        }
        HostCommand::Certify {
            root_key,
            relay_public_key,
            provider_id,
            serial,
            issued_at,
            expires_at,
            capabilities,
            issuer_id,
            out,
        } => run_certify(
            root_key,
            &relay_public_key,
            &provider_id,
            &serial,
            issued_at,
            &expires_at,
            &capabilities,
            &issuer_id,
            &out,
        ),
        HostCommand::Krl {
            root_key,
            issued_at,
            serials,
            out,
        } => run_krl(root_key, issued_at, &serials, &out),
        HostCommand::Keys { command } => {
            let store = open_store(store_args)?;
            run_keys(store.as_ref(), command)
        }
        HostCommand::Root { command } => run_root(command),
        HostCommand::Policy { command } => run_policy(command),
    }
}

fn print_new_licensee(issuer: &relay::CreatedLicensee) {
    eprintln!("Created internal operator key (shown once):");
    eprintln!("  {}", issuer.token.as_str());
    eprintln!("This mints customer API keys on this host. It is not a customer credential.");
    eprintln!("Store this; it cannot be recovered from the database.");
}

/// The operator lock, from the sources `host_env::licensee_key` lists, else
/// prompted. Never echoed or logged.
fn licensee_secret(
    file_flag: Option<PathBuf>,
    raw_flag: Option<String>,
) -> Result<Zeroizing<String>> {
    match host_env::licensee_key(file_flag, raw_flag, &ProcessVars)? {
        Some(key) => Ok(key),
        None => rpassword::prompt_password("Licensee key: ")
            .map(Zeroizing::new)
            .map_err(Error::from),
    }
}

/// The relay's state: the owner-only SQLite file at `mailbox_db`. Every host
/// `keys` command and the server open it the same way.
fn open_store(args: &StoreArgs) -> Result<Arc<dyn RelayStore>> {
    let db_path = args.mailbox_db.to_str().ok_or(Error::InvalidPath)?;
    Ok(Arc::new(SqliteRelayStore::open(db_path)?))
}

/// Every mint authorization, granted or refused, lands in
/// `provider_auth_events` with the provider id when the certificate was
/// checked far enough to name one. No key, bearer or challenge is recorded.
/// The operator lock as the `keys create|rotate` flags gave it.
struct LicenseeArgs {
    raw: Option<String>,
    file: Option<PathBuf>,
}

fn authorize_mint(
    store: &dyn RelayStore,
    operation: &str,
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
    licensee: LicenseeArgs,
) -> Result<ProviderIdentity> {
    let mut provider_id = None;
    let result = check_mint(store, &mut provider_id, cert, relay_key, krl, licensee);
    store.record_provider_auth_event(&ProviderAuthEvent {
        operation,
        provider_id: provider_id.as_deref(),
        network_id: None,
        hardware_fingerprints: None,
        success: result.is_ok(),
    })?;
    result
}

fn check_mint(
    store: &dyn RelayStore,
    provider_id: &mut Option<String>,
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
    licensee: LicenseeArgs,
) -> Result<ProviderIdentity> {
    let (identity, id) = load_serve_identity(cert, relay_key, krl)?;
    *provider_id = Some(id);
    let supplied = host_env::licensee_key(licensee.file, licensee.raw, &ProcessVars)?;
    if let Some(issuer) =
        store.authorize_licensee_or_bootstrap(supplied.as_deref().map(String::as_str))?
    {
        print_new_licensee(&issuer);
        return Ok(identity);
    }
    if supplied.is_none() {
        store.authenticate_licensee(&licensee_secret(None, None)?)?;
    }
    Ok(identity)
}

fn run_keys(store: &dyn RelayStore, command: KeysCommand) -> Result<()> {
    match command {
        KeysCommand::Create {
            scope,
            fingerprint,
            label,
            ttl_seconds,
            cert,
            relay_key,
            krl,
            licensee_key,
            licensee_key_file,
            recipient_key,
            out,
            relay_url,
            device_id,
            licence_file,
            enrollment,
            package_out,
            confirm_fingerprint,
            package_relay_url,
            package_licence_file,
            package_valid_days,
        } => {
            let identity = authorize_mint(
                store,
                "keys.create",
                cert,
                relay_key,
                krl,
                LicenseeArgs {
                    raw: licensee_key,
                    file: licensee_key_file,
                },
            )?;
            let new = NewApiKey {
                scope: ApiKeyScope::parse(&scope)?,
                recipient_fingerprint: fingerprint,
                label,
                ttl_seconds,
            };
            match (enrollment, recipient_key, out) {
                (Some(enrollment), _, _) => {
                    let package_out = package_out.ok_or_else(|| {
                        Error::Usage("--package-out is required with --enrollment".into())
                    })?;
                    let typed = confirm_fingerprint.ok_or_else(|| {
                        Error::Usage(
                            "--confirm-fingerprint is required with --enrollment: read it from the client, not from the file".into(),
                        )
                    })?;
                    let request = keyquorum::enrollment::decode_file(&enrollment)?;
                    request.confirm_fingerprint(&typed)?;
                    let recipient = Recipient {
                        public_key: request.encryption_public,
                        device_id: Some(request.device_id),
                        ..recipient_from(
                            &hex::encode(request.encryption_public),
                            package_relay_url,
                            None,
                            package_licence_file,
                        )?
                    };
                    let issued_at = provider::unix_from_utc(&provider::system_now_utc()?)?;
                    // The package is written inside the key's own transaction, so a
                    // package that cannot be built or written leaves no key behind.
                    let delivered = into_file(&package_out, |write| {
                        store.mint_key_as_bundle(&identity, &new, &recipient, &mut |sealed| {
                            let package = keyquorum::package::issue_client_package(
                                &identity,
                                &[sealed],
                                &request.encryption_public,
                                Some(request.device_id),
                                issued_at,
                                package_valid_days,
                            )?;
                            write(&package)
                        })
                    })?;
                    println!("Created API key {}", delivered.info.id);
                    println!("scope: {}", delivered.info.scope);
                    println!("sealed to: {}", delivered.recipient_fingerprint);
                    println!("wrote {}", package_out.display());
                    println!(
                        "hand it to the customer for `keyquorum setup FILE --device DIR --label NAME`; it is never printed"
                    );
                }
                (None, Some(recipient_key), Some(out)) => {
                    let recipient =
                        recipient_from(&recipient_key, relay_url, device_id, licence_file)?;
                    let delivered = into_file(&out, |write| {
                        store.mint_key_as_bundle(&identity, &new, &recipient, write)
                    })?;
                    println!("Created API key {}", delivered.info.id);
                    print_delivered(&delivered, Some(&out));
                }
                _ => {
                    let created = store.mint_key(&new)?;
                    println!("Created API key {}", created.info.id);
                    println!("scope: {}", created.info.scope);
                    if let Some(fp) = &created.info.recipient_fingerprint {
                        println!("fingerprint: {fp}");
                    }
                    if let Some(expires) = &created.info.expires_at {
                        println!("expires: {expires}");
                    }
                    println!("token (shown once): {}", created.token.as_str());
                }
            }
            anchor_audit(store, &identity);
        }
        KeysCommand::List => {
            let keys = store.list_keys()?;
            if keys.is_empty() {
                println!("(no API keys)");
            } else {
                for key in keys {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        key.id,
                        key.scope,
                        key.recipient_fingerprint.as_deref().unwrap_or("-"),
                        key.revoked_at.as_deref().unwrap_or("live"),
                        key.label.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        KeysCommand::Events {
            key,
            verify,
            krl,
            checkpoint,
        } => {
            let events = store.key_events(key)?;
            if events.is_empty() {
                println!("(no API key events)");
            }
            for event in events {
                let related = event
                    .related_key_id
                    .map_or_else(|| "-".to_string(), |id| id.to_string());
                println!(
                    "{}\t{}\t{}\t{}\treplaces={related}\t{}",
                    event.occurred_at, event.key_id, event.event, event.actor, event.entry_hash
                );
            }
            if verify {
                return verify_audit(store, krl, checkpoint);
            }
        }
        KeysCommand::Checkpoint {
            out,
            cert,
            relay_key,
            krl,
        } => {
            let (identity, _) = load_serve_identity(cert, relay_key, krl)?;
            let taken_at = provider::system_now_utc_millis()?;
            let checkpoint = store.audit_checkpoint(&identity, &taken_at)?;
            locked_files::write_owner_only(&out, &checkpoint.encode()?)?;
            for head in &checkpoint.heads {
                println!(
                    "{}: {} rows, head {}",
                    head.table, head.row_count, head.head_hash
                );
            }
            println!(
                "Wrote checkpoint {} (taken {taken_at}); keep it off this relay",
                out.display()
            );
        }
        KeysCommand::Revoke {
            id,
            cert,
            relay_key,
            krl,
        } => {
            store.revoke_key_by(id, HOST_ACTOR)?;
            println!("Revoked API key {id}");
            let configured = path_or_env(cert.clone(), "KEYQUORUM_PROVIDER_CERT").is_some()
                && path_or_env(relay_key.clone(), "KEYQUORUM_RELAY_KEY").is_some();
            if configured {
                let (identity, _) = load_serve_identity(cert, relay_key, krl)?;
                anchor_audit(store, &identity);
            } else {
                eprintln!("note: no relay identity given; the running relay signs this revocation into the audit chain on its next scan");
            }
        }
        KeysCommand::Rotate {
            id,
            cert,
            relay_key,
            krl,
            licensee_key,
            licensee_key_file,
            recipient_key,
            relay_url,
            device_id,
            licence_file,
            out,
            grace_seconds,
        } => {
            let identity = authorize_mint(
                store,
                "keys.rotate",
                cert,
                relay_key,
                krl,
                LicenseeArgs {
                    raw: licensee_key,
                    file: licensee_key_file,
                },
            )?;
            let recorded = store.delivery_recipient_for(id)?;
            let recipient = match recipient_key {
                Some(recipient_key) => {
                    let url = relay_url.or_else(|| recorded.as_ref().map(|r| r.relay_url.clone()));
                    Some(recipient_from(
                        &recipient_key,
                        url,
                        device_id,
                        licence_file,
                    )?)
                }
                None => None,
            };
            if recipient.is_none() && recorded.is_none() && out.is_none() {
                // Never sealed to anyone: handed over as before.
                let created = store.rotate_key_with(id, OldKey::RevokeNow)?;
                println!("Rotated API key {id} -> {}", created.info.id);
                println!("token (shown once): {}", created.token.as_str());
            } else if let Some(out) = out {
                let delivered = into_file(&out, |write| {
                    store.rotate_key_as_bundle(&identity, id, recipient, write)
                })?;
                println!("Rotated API key {id} -> {}", delivered.info.id);
                print_delivered(&delivered, Some(&out));
            } else {
                let delivered =
                    store.rotate_key_as_letter(&identity, id, recipient, grace_seconds)?;
                println!("Rotated API key {id} -> {}", delivered.info.id);
                print_delivered(&delivered, None);
                if let Via::Letter {
                    until: Some(until), ..
                } = &delivered.via
                {
                    println!(
                        "key {id} stays usable until {until} to collect it; `keys revoke {id}` ends it sooner"
                    );
                }
            }
            anchor_audit(store, &identity);
        }
    }
    Ok(())
}

/// Whom `keys create|rotate` seals a key to, from the operator's flags: the
/// customer's public key, the relay URL the issue names, an optional device
/// binding and an optional licence statement read from a file.
fn recipient_from(
    recipient_key: &str,
    relay_url: Option<String>,
    device_id: Option<String>,
    licence_file: Option<PathBuf>,
) -> Result<Recipient> {
    let public_key = *keys::parse_key_32(recipient_key)?;
    let relay_url = relay_url
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| Error::Usage("--relay-url is required with --recipient-key".into()))?;
    relay::validate_relay_url(&relay_url)?;
    let device_id = match device_id {
        None => None,
        Some(hex) => Some(
            hex::decode(hex.trim())
                .ok()
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                .ok_or(Error::InvalidDevice)?,
        ),
    };
    let licence = match licence_file {
        None => None,
        Some(path) => {
            let text = std::fs::read_to_string(path)?;
            if text.len() > MAX_LICENCE_BYTES {
                return Err(Error::BundleFieldTooLarge);
            }
            Some(text)
        }
    };
    Ok(Recipient {
        public_key,
        relay_url,
        device_id,
        licence,
    })
}

/// Run `issue` with a writer that creates `out` owner-only, never
/// overwriting. If `issue` fails after the file was written (the key change
/// did not commit), the file is removed, so a retry is not refused by it.
/// If the store could not say whether it committed
/// ([`Error::StoreCommitUnknown`]) the file is kept: the key may exist, and
/// the bundle is its only handoff. That is compensation, not atomicity: a crash between the write and the
/// commit can leave a bundle for a key that was never created, which the
/// operator removes before retrying (it opens nothing).
fn into_file<T>(
    out: &Path,
    issue: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<()>) -> Result<T>,
) -> Result<T> {
    let mut wrote = false;
    let result = issue(&mut |bytes: &[u8]| {
        locked_files::write_owner_only(out, bytes)?;
        wrote = true;
        Ok(())
    });
    match &result {
        Err(Error::StoreCommitUnknown) if wrote => {
            eprintln!(
                "kept {}: the commit outcome is unknown, so the key may exist",
                out.display()
            );
        }
        Err(_) if wrote => {
            let _ = std::fs::remove_file(out);
        }
        _ => {}
    }
    result
}

/// What the operator sees of a sealed issue: never the bearer.
fn print_delivered(delivered: &Delivered, out: Option<&Path>) {
    println!("scope: {}", delivered.info.scope);
    println!("sealed to: {}", delivered.recipient_fingerprint);
    if let Some(expires) = &delivered.info.expires_at {
        println!("expires: {expires}");
    }
    match (&delivered.via, out) {
        (Via::Bundle { sha256 }, Some(path)) => {
            println!("wrote {} (sha256 {sha256})", path.display());
            println!(
                "hand it to the customer for `keyquorum loadkey --bundle`; it is never printed"
            );
        }
        (Via::Bundle { sha256 }, None) => println!("sealed bundle sha256 {sha256}"),
        (Via::Letter { id, .. }, _) => {
            println!("sealed letter {id} waits in the mailbox; the customer's next `keyquorum inbox open` loads it");
        }
    }
}

/// Sign the audit chains' new heads. The key change itself is already
/// committed, so a failure here is reported, not fatal: the running relay
/// signs any unanchored rows on its next scan.
fn anchor_audit(store: &dyn RelayStore, identity: &ProviderIdentity) {
    if let Err(err) = relay::anchor_now(store, identity) {
        eprintln!("warning: could not sign the audit chain now ({err}); the relay signs it on its next scan");
    }
}

/// `keys events --verify`: every chain re-walked and every anchor checked
/// against the compiled-in provider root. Fails if any chain is broken or
/// any anchor is refused.
fn verify_audit(
    store: &dyn RelayStore,
    krl: Option<PathBuf>,
    checkpoint: Option<PathBuf>,
) -> Result<()> {
    let krl = path_or_env(krl, "KEYQUORUM_PROVIDER_KRL");
    let revoked =
        provider::load_revocation_list(&KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY, krl.as_deref())?;
    let checkpoint = checkpoint
        .map(|path| relay::audit::Checkpoint::decode(&std::fs::read(path)?))
        .transpose()?;
    let reports = store.verify_audit(
        &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        &revoked,
        checkpoint.as_ref(),
    )?;
    let mut intact = true;
    for report in &reports {
        let chain = match report.broken_at {
            None => "chain intact".to_string(),
            Some(id) => format!("chain BROKEN at row {id}"),
        };
        let anchor = match &report.trusted {
            Some(a) => format!(
                "signed through row {} by {} (serial {}) at {}",
                a.row_count, a.provider_id, a.serial, a.signed_at
            ),
            None => "no trusted anchor".to_string(),
        };
        let against = match &report.checkpoint {
            None => String::new(),
            Some(c) if c.matches => format!(
                ", matches checkpoint through row {} ({})",
                c.row_count, c.taken_at
            ),
            Some(c) => format!(
                ", DOES NOT MATCH checkpoint at row {} ({})",
                c.row_count, c.taken_at
            ),
        };
        println!(
            "{}: {} rows, {chain}, {anchor}{against}, {} pending, {} rejected anchor(s)",
            report.table,
            report.rows,
            report.pending_rows(),
            report.rejected_anchors
        );
        intact &= report.is_intact();
    }
    if intact {
        Ok(())
    } else {
        Err(Error::IntegrityCheckFailed)
    }
}

fn run_root(command: RootCommand) -> Result<()> {
    match command {
        RootCommand::Generate {
            public_key_out,
            private_key_out,
        } => write_keypair("Root", &public_key_out, &private_key_out),
    }
}

fn run_policy(command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Issue {
            root_key,
            relay_public_key,
            provider_id,
            policy_id,
            issued_at,
            expires_at,
            capabilities,
            hardware_fingerprints,
            revoked_hardware,
            hardware_threshold,
            permissions,
            out,
        } => run_policy_issue(
            root_key,
            &relay_public_key,
            &provider_id,
            &policy_id,
            issued_at,
            &expires_at,
            &capabilities,
            &hardware_fingerprints,
            &revoked_hardware,
            hardware_threshold,
            &permissions,
            &out,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_policy_issue(
    root_key: Option<PathBuf>,
    relay_public_key: &Path,
    provider_id: &str,
    policy_id: &str,
    issued_at: Option<String>,
    expires_at: &str,
    capabilities: &str,
    hardware_fingerprints: &[String],
    revoked_hardware: &[String],
    hardware_threshold: u8,
    permissions: &[String],
    out: &Path,
) -> Result<()> {
    let root = read_root_key(root_key)?;
    let relay_public = read_key_array_32(relay_public_key)?;
    let issued_at = match issued_at.filter(|s| !s.is_empty()) {
        Some(value) => value,
        None => provider::system_now_utc()?,
    };
    let capabilities = provider::parse_capabilities(capabilities)?;
    let hardware = collect_hardware(hardware_fingerprints, revoked_hardware)?;
    let bytes = policy::issue_policy(
        &root,
        &NewPolicy {
            provider_id,
            policy_id,
            relay_public_key: &relay_public,
            issued_at: &issued_at,
            expires_at,
            capabilities,
            hardware_threshold,
            hardware: &hardware,
            networks: &[],
            permissions,
        },
    )?;
    locked_files::write_owner_only(out, &bytes)?;
    eprintln!("Wrote provider policy to {}", out.display());
    Ok(())
}

fn collect_hardware(
    fingerprints: &[String],
    revoked: &[String],
) -> Result<Vec<HardwareAuthorityEntry>> {
    let revoked: std::collections::HashSet<String> = revoked
        .iter()
        .map(|fp| policy::normalize_fingerprint(fp))
        .collect::<Result<std::collections::HashSet<_>>>()?;
    let mut out = Vec::new();
    for raw in fingerprints {
        let fingerprint = policy::normalize_fingerprint(raw)?;
        let is_revoked = revoked.contains(&fingerprint);
        out.push(HardwareAuthorityEntry {
            fingerprint,
            key_type: KeyType::Signing,
            authority: HardwareAuthority::ProviderApiRoot,
            revoked: is_revoked,
        });
    }
    Ok(out)
}

fn run_identity(command: IdentityCommand) -> Result<()> {
    match command {
        IdentityCommand::Generate {
            public_key_out,
            private_key_out,
        } => write_keypair("Relay", &public_key_out, &private_key_out),
    }
}

/// `host backup`: the operator's side of the sealed database backups. None of it
/// touches a running relay: the keypair is made here, and a backup is read from a
/// directory the operator downloaded it to.
fn run_backup(command: BackupCommand) -> Result<()> {
    // The restore reports through tracing like the rest of the host, so it
    // needs a subscriber of its own (INFO unless RUST_LOG says otherwise).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .try_init();
    match command {
        BackupCommand::Keygen {
            public_key_out,
            private_key_out,
        } => {
            if public_key_out.exists() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} already exists", public_key_out.display()),
                )));
            }
            let (secret, public) = keys::generate_encryption_keypair();
            cli::write_hex_file(&private_key_out, &secret[..])?;
            if let Err(err) = cli::write_hex_file(&public_key_out, &public) {
                let _ = std::fs::remove_file(&private_key_out);
                return Err(err);
            }
            eprintln!(
                "Backup private key written owner-only to {}; keep it offline. Without it no backup can be read.",
                private_key_out.display()
            );
            println!("BACKUP_RECIPIENT={}", hex::encode(public));
            Ok(())
        }
        BackupCommand::Inspect {
            dir,
            backup_key,
            krl,
        } => {
            let secret = host_env::read_key_file(&backup_key)?;
            let revoked = backup_revocations(krl)?;
            let seen = relay::backup::inspect_dir(
                &dir,
                &secret,
                &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
                &revoked,
            )?;
            println!("backup {}, taken {}", seen.backup_id, seen.taken_at);
            for (name, rows) in seen.tables {
                println!("  {name}: {rows} rows");
            }
            Ok(())
        }
        BackupCommand::Restore {
            dir,
            backup_key,
            out,
            krl,
        } => {
            let secret = host_env::read_key_file(&backup_key)?;
            let revoked = backup_revocations(krl)?;
            let restored = relay::backup::restore_dir(
                &dir,
                &out,
                &secret,
                &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
                &revoked,
            )?;
            tracing::info!(
                "restored backup {} (taken {}): {} tables, {} rows into {}",
                restored.backup_id,
                restored.taken_at,
                restored.tables,
                restored.rows,
                out.display()
            );
            if restored.held_skipped > 0 {
                tracing::info!(
                    "{} letters held in object storage were not restored (their objects are not in a backup)",
                    restored.held_skipped
                );
            }
            if restored.audit_intact {
                tracing::info!("audit chains: intact, every anchor verifies");
                Ok(())
            } else {
                eprintln!("audit chains: NOT intact; check `host keys events --verify` before trusting this database");
                Err(Error::IntegrityCheckFailed)
            }
        }
    }
}

fn backup_revocations(krl: Option<PathBuf>) -> Result<std::collections::HashSet<String>> {
    let krl = path_or_env(krl, "KEYQUORUM_PROVIDER_KRL");
    provider::load_revocation_list(&KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY, krl.as_deref())
}

/// Writes a fresh keypair through the CLI's owner-only hex writer: the
/// private key never goes to stdout or a log, so it cannot land in terminal
/// scrollback, CI logs or shell history. Neither file may already exist,
/// and the private key is written first, so a failure leaves no public key
/// without its pair.
fn write_keypair(what: &str, public_key_out: &Path, private_key_out: &Path) -> Result<()> {
    if public_key_out.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", public_key_out.display()),
        )));
    }
    let (secret, public) = provider::generate_relay_identity();
    cli::write_hex_file(private_key_out, &secret[..])?;
    if let Err(err) = cli::write_hex_file(public_key_out, &public) {
        let _ = std::fs::remove_file(private_key_out);
        return Err(err);
    }
    eprintln!(
        "{what} private key written owner-only to {}",
        private_key_out.display()
    );
    eprintln!("Public key written to {}", public_key_out.display());
    Ok(())
}

/// The files `host provision` wrote, by path, and the root it pinned.
struct Provisioned {
    root_public: [u8; 32],
    root_private_key: PathBuf,
    root_public_key: PathBuf,
    relay_private_key: PathBuf,
    relay_public_key: PathBuf,
    identity_file: PathBuf,
    package: PathBuf,
}

/// `host provision`: `provider::provision` (the root ceremony, the relay
/// identity and the certificate in one run, checked as the relay checks
/// them) written into `out`, a directory this run creates owner-only (an
/// existing one, whatever its mode, is refused before anything is made),
/// each file created new; a write that fails removes the files this run
/// created, and only those, so a retry is never refused by a leftover.
/// Neither private key is printed.
fn run_provision(out: &Path, spec: &provision::Spec<'_>) -> Result<Provisioned> {
    let written = Provisioned {
        root_public: [0; 32],
        root_private_key: out.join("root.key"),
        root_public_key: out.join("root.pub"),
        relay_private_key: out.join("relay.key"),
        relay_public_key: out.join("relay.pub"),
        identity_file: out.join("provider.kqcert"),
        package: out.join("provider-info.kqpkg"),
    };
    if out.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; provision into a directory that does not exist yet",
                out.display()
            ),
        )));
    }
    let made = provision::provision(spec, &provider::system_now_utc()?)?;
    let written = Provisioned {
        root_public: made.root_public_key,
        ..written
    };
    create_owner_only_dir(out)?;
    // Only a file this run created is removed on failure: one that appeared
    // in between (its `create_new` write is what fails) is someone else's.
    let root_key = Zeroizing::new(hex::encode(&made.root_private_key[..]));
    let relay_key = Zeroizing::new(hex::encode(&made.relay_private_key[..]));
    let root_pub = hex::encode(made.root_public_key);
    let relay_pub = hex::encode(made.relay_public_key);
    let files: [(&Path, &[u8]); 6] = [
        (&written.root_private_key, root_key.as_bytes()),
        (&written.root_public_key, root_pub.as_bytes()),
        (&written.relay_private_key, relay_key.as_bytes()),
        (&written.relay_public_key, relay_pub.as_bytes()),
        (&written.identity_file, &made.certificate),
        (&written.package, &made.package),
    ];
    let mut created: Vec<&Path> = Vec::new();
    for (path, contents) in files {
        if let Err(err) = locked_files::write_owner_only(path, contents) {
            for path in created {
                let _ = std::fs::remove_file(path);
            }
            return Err(err);
        }
        created.push(path);
    }
    Ok(written)
}

/// The output directory, made owner-only by this run and by nothing else:
/// its parent must exist, and a directory already there (whose mode this
/// run did not choose) is refused by `create`.
fn create_owner_only_dir(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    Ok(builder.create(dir)?)
}

/// What `host provision` prints: every file by path, the public root, and
/// the three steps that follow. No private key is ever among them.
fn print_provisioned(written: &Provisioned) {
    eprintln!(
        "Root private key written owner-only to {} (keep it offline; it signs certificates and revocations, nothing else)",
        written.root_private_key.display()
    );
    eprintln!(
        "Relay private key written owner-only to {} (the relay's RELAY_PRIVATE_KEY secret)",
        written.relay_private_key.display()
    );
    eprintln!(
        "Provider certificate written to {} (the relay's RELAY_CERTIFICATE secret, base64)",
        written.identity_file.display()
    );
    eprintln!(
        "Public keys written to {} and {}; provider package to {}",
        written.root_public_key.display(),
        written.relay_public_key.display(),
        written.package.display()
    );
    eprintln!();
    eprintln!("Next:");
    eprintln!(
        "  1. Pin the root: set the relay's PROVIDER_ROOT deploy variable, and build the clients with KEYQUORUM_PROVIDER_ROOT, to the contents of {} (public, never committed): {}.",
        written.root_public_key.display(),
        hex::encode(written.root_public)
    );
    eprintln!(
        "  2. Set the relay's secrets (in workers/, add --env staging for the staging relay):\n       npx wrangler secret put RELAY_PRIVATE_KEY < {}\n       base64 < {} | tr -d '\\n' | npx wrangler secret put RELAY_CERTIFICATE",
        written.relay_private_key.display(),
        written.identity_file.display()
    );
    eprintln!("  3. Reload the console; the setup guide clears steps 1 and 2 once the relay's identity checks out.");
}

#[allow(clippy::too_many_arguments)]
fn run_certify(
    root_key: Option<PathBuf>,
    relay_public_key: &Path,
    provider_id: &str,
    serial: &str,
    issued_at: Option<String>,
    expires_at: &str,
    capabilities: &str,
    issuer_id: &str,
    out: &Path,
) -> Result<()> {
    let root = read_root_key(root_key)?;
    let relay_public = read_key_array_32(relay_public_key)?;
    let issued_at = match issued_at.filter(|s| !s.is_empty()) {
        Some(value) => value,
        None => provider::system_now_utc()?,
    };
    let capabilities = provider::parse_capabilities(capabilities)?;
    let bytes = provider::issue_certificate(
        &root,
        &NewCertificate {
            provider_id,
            serial,
            relay_public_key: &relay_public,
            issued_at: &issued_at,
            expires_at,
            capabilities,
            issuer_id,
        },
    )?;
    locked_files::write_owner_only(out, &bytes)?;
    eprintln!("Wrote provider certificate to {}", out.display());
    Ok(())
}

fn run_krl(
    root_key: Option<PathBuf>,
    issued_at: Option<String>,
    serials: &[String],
    out: &Path,
) -> Result<()> {
    let root = read_root_key(root_key)?;
    let issued_at = match issued_at.filter(|s| !s.is_empty()) {
        Some(value) => value,
        None => provider::system_now_utc()?,
    };
    let bytes = provider::issue_revocation_list(&root, &issued_at, serials)?;
    locked_files::write_owner_only(out, &bytes)?;
    eprintln!("Wrote provider revocation list to {}", out.display());
    Ok(())
}

fn path_or_env(flag: Option<PathBuf>, env_name: &str) -> Option<PathBuf> {
    flag.filter(|p| !p.as_os_str().is_empty())
        .or_else(|| match std::env::var(env_name) {
            Ok(value) if !value.is_empty() => Some(PathBuf::from(value)),
            _ => None,
        })
}

/// Every key file the host reads (relay private and public keys, the
/// provider-root key) goes through the bounded credential reader.
fn read_key_array_32(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    host_env::read_key_file(path)
}

/// The offline provider root key: `--root-key`, then
/// `KEYQUORUM_PROVIDER_ROOT_KEY_FILE`, then (for existing ceremonies) the
/// raw `KEYQUORUM_PROVIDER_ROOT_KEY` text. It is read here, used, and
/// zeroized; it never reaches a relay.
fn read_root_key(path: Option<PathBuf>) -> Result<Zeroizing<[u8; 32]>> {
    match host_env::root_key_source(path, &ProcessVars) {
        host_env::Source::File(path) => read_key_array_32(&path),
        host_env::Source::Raw => {
            let value = Zeroizing::new(
                std::env::var(host_env::PROVIDER_ROOT_KEY_VAR)
                    .map_err(|_| Error::InvalidProviderCertificate)?,
            );
            keys::parse_key_32(&value)
        }
        host_env::Source::Absent => Err(Error::InvalidProviderCertificate),
    }
}

/// The checked identity and the provider id its certificate names.
fn load_serve_identity(
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
) -> Result<(ProviderIdentity, String)> {
    let cert_path =
        path_or_env(cert, "KEYQUORUM_PROVIDER_CERT").ok_or(Error::ProviderIdentityMissing)?;
    let key_path =
        path_or_env(relay_key, "KEYQUORUM_RELAY_KEY").ok_or(Error::ProviderIdentityMissing)?;
    let krl_path = path_or_env(krl, "KEYQUORUM_PROVIDER_KRL");
    let certificate = std::fs::read(&cert_path)?;
    let relay_private_key = read_key_array_32(&key_path)?;
    let now = provider::system_now_utc()?;
    let revoked =
        provider::load_revocation_list(&KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY, krl_path.as_deref())?;
    let checked = provider::self_check(
        &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        &certificate,
        &relay_private_key,
        &now,
        &revoked,
    )?;
    // Only the public naming fields are logged, through the host's own log
    // like its other operating lines: the same provider id, serial and expiry
    // every client reads from `POST /provider-identity`. The certificate
    // bytes and the relay key never are.
    tracing::info!(
        "provider identity {} serial {} expires {}",
        checked.provider_id,
        checked.serial,
        checked.expires_at
    );
    Ok((
        ProviderIdentity {
            certificate,
            relay_private_key,
        },
        checked.provider_id,
    ))
}

async fn serve(
    store: Arc<dyn RelayStore>,
    identity: ProviderIdentity,
    addr: SocketAddr,
    scan_db: Option<PathBuf>,
    scan_interval_seconds: u64,
    behind_tls_proxy: bool,
    rate_limit_per_minute: u32,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("mailbox listening on http://{local}");
    if !local.ip().is_loopback() {
        tracing::warn!("serving plain HTTP on {local}; TLS must terminate in front of this relay");
    }
    eprintln!("Swagger UI: http://{local}/swagger-ui");
    if let Some(path) = &scan_db {
        eprintln!("TTL file scan: {}", path.display());
    }

    let state = AppState::with_store(store.clone(), Some(identity))
        .with_rate_limit(rate_limit_per_minute, behind_tls_proxy);
    if rate_limit_per_minute == 0 {
        tracing::warn!("rate limiting is off; limit requests in front of this relay");
    }
    spawn_ttl_scan(store, state.identity(), scan_db, scan_interval_seconds);

    axum::serve(
        listener,
        relay::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// The periodic scan: expired letters are purged and the audit chains
/// anchored. Every step blocks on the store, so the whole tick runs on the
/// blocking pool; with a shared store, each replica runs its own scan and
/// every step is idempotent, so two replicas scanning at once do no harm.
fn spawn_ttl_scan(
    store: Arc<dyn RelayStore>,
    identity: Option<Arc<ProviderIdentity>>,
    scan_db: Option<PathBuf>,
    interval_seconds: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
        loop {
            ticker.tick().await;
            let store = store.clone();
            let identity = identity.clone();
            let scanned = tokio::task::spawn_blocking(move || {
                scan_store(store.as_ref(), identity.as_deref())
            })
            .await;
            if scanned.is_err() {
                tracing::warn!("relay scan task did not finish");
            }
            if let Some(path) = scan_db.as_ref().filter(|path| path.is_file()) {
                let Some(path) = path.to_str() else {
                    tracing::warn!("TTL file scan path is not valid UTF-8");
                    continue;
                };
                match db::open(path).and_then(|conn| locked_files::purge_expired(&conn)) {
                    Ok(n) if n > 0 => tracing::info!("purged {n} expired TTL file(s)"),
                    Ok(_) => {}
                    Err(err) => tracing::warn!("TTL file scan failed: {err}"),
                }
            }
        }
    });
}

fn scan_store(store: &dyn RelayStore, identity: Option<&ProviderIdentity>) {
    match store.purge_expired_envelopes() {
        Ok(n) if n > 0 => tracing::info!("purged {n} expired mailbox envelope(s)"),
        Ok(_) => {}
        Err(err) => tracing::warn!("mailbox TTL scan failed: {err}"),
    }
    match store.purge_expired_device_packages() {
        Ok(n) if n > 0 => tracing::info!("purged {n} expired device letter(s)"),
        Ok(_) => {}
        Err(err) => tracing::warn!("device mailbox TTL scan failed: {err}"),
    }
    if let Some(identity) = identity {
        match relay::anchor_now(store, identity) {
            Ok(n) if n > 0 => tracing::info!("signed {n} audit chain head(s)"),
            Ok(_) => {}
            Err(err) => tracing::warn!("audit anchor failed: {err}"),
        }
    }
}

/// Ends the server on SIGINT or, as a container runtime or `systemctl stop`
/// sends it, SIGTERM, so in-flight requests drain before the process exits.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal as unix_signal, SignalKind};
        match unix_signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(err) => {
                tracing::warn!("cannot listen for SIGTERM: {err}");
                let _ = signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

#[cfg(test)]
#[path = "host/tests.rs"]
mod tests;
