//! Provider-only mailbox host. Compiled only with `--features provider`.
//! Hidden from `keyquorum --help`. Customers use `loadkey` with a URL
//! and bearer they were given.
//!
//! `--features provider` compiles these commands; it does not authorize a
//! host. `serve` and customer-API-key minting require a KeyQuorum-signed
//! `provider.kqcert` and the matching relay private key. Customers never
//! mint keys: they receive a `kq_…` bearer. The `kql_…` issuer is an
//! internal operator lock created only after that identity check.

use keyquorum::cli;
use keyquorum::cli::host_args::{
    HostCommand, IdentityCommand, KeysCommand, PolicyCommand, RootCommand,
};
use keyquorum::db;
use keyquorum::error::{Error, Result};
use keyquorum::keys::{self, KeyType};
use keyquorum::locked_files;
use keyquorum::provider::hardware_auth::HardwareAuthority;
use keyquorum::provider::policy::{self, HardwareAuthorityEntry, NewPolicy};
use keyquorum::provider::{self, NewCertificate, KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY};
use keyquorum::relay::{self, ApiKeyScope, AppState, NewApiKey, ProviderIdentity};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

pub fn run(mailbox_db: &Path, org_db: &Path, command: HostCommand) -> Result<()> {
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
            let scan_db = scan_db.or_else(|| org_db.is_file().then(|| org_db.to_path_buf()));
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(Error::Io)?
                .block_on(serve(
                    mailbox_db,
                    &bind,
                    cert,
                    relay_key,
                    krl,
                    scan_db,
                    scan_interval_seconds,
                    behind_tls_proxy,
                    rate_limit_per_minute,
                ))
        }
        HostCommand::Identity { command } => run_identity(command),
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
            let db_path = mailbox_db.to_str().ok_or(Error::InvalidPath)?;
            let conn = relay::open(db_path)?;
            run_keys(&conn, command)
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

fn licensee_secret(explicit: Option<String>) -> Result<Zeroizing<String>> {
    if let Some(key) = explicit.filter(|s| !s.is_empty()) {
        return Ok(Zeroizing::new(key));
    }
    match std::env::var("KEYQUORUM_LICENSEE_KEY") {
        Ok(key) if !key.is_empty() => Ok(Zeroizing::new(key)),
        _ => rpassword::prompt_password("Licensee key: ")
            .map(Zeroizing::new)
            .map_err(Error::from),
    }
}

fn require_licensee(conn: &rusqlite::Connection, explicit: Option<String>) -> Result<()> {
    relay::authenticate_licensee(conn, &licensee_secret(explicit)?)
}

/// Every mint authorization, granted or refused, lands in
/// `provider_auth_events` with the provider id when the certificate was
/// checked far enough to name one. No key, bearer or challenge is recorded.
fn authorize_mint(
    conn: &rusqlite::Connection,
    operation: &str,
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
    licensee_key: Option<String>,
) -> Result<ProviderIdentity> {
    let mut provider_id = None;
    let result = check_mint(conn, &mut provider_id, cert, relay_key, krl, licensee_key);
    relay::record_provider_auth_event(
        conn,
        operation,
        provider_id.as_deref(),
        None,
        None,
        result.is_ok(),
    )?;
    result
}

fn check_mint(
    conn: &rusqlite::Connection,
    provider_id: &mut Option<String>,
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
    licensee_key: Option<String>,
) -> Result<ProviderIdentity> {
    let (identity, id) = load_serve_identity(cert, relay_key, krl)?;
    *provider_id = Some(id);
    let supplied = licensee_key
        .filter(|s| !s.is_empty())
        .or_else(|| match std::env::var("KEYQUORUM_LICENSEE_KEY") {
            Ok(key) if !key.is_empty() => Some(key),
            _ => None,
        })
        .map(Zeroizing::new);
    if let Some(issuer) =
        relay::authorize_licensee_or_bootstrap(conn, supplied.as_deref().map(String::as_str))?
    {
        print_new_licensee(&issuer);
        return Ok(identity);
    }
    if supplied.is_none() {
        require_licensee(conn, None)?;
    }
    Ok(identity)
}

fn run_keys(conn: &rusqlite::Connection, command: KeysCommand) -> Result<()> {
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
        } => {
            let identity = authorize_mint(conn, "keys.create", cert, relay_key, krl, licensee_key)?;
            let created = relay::create_api_key(
                conn,
                &NewApiKey {
                    scope: ApiKeyScope::parse(&scope)?,
                    recipient_fingerprint: fingerprint,
                    label,
                    ttl_seconds,
                },
            )?;
            println!("Created API key {}", created.info.id);
            println!("scope: {}", created.info.scope);
            if let Some(fp) = &created.info.recipient_fingerprint {
                println!("fingerprint: {fp}");
            }
            if let Some(expires) = &created.info.expires_at {
                println!("expires: {expires}");
            }
            println!("token (shown once): {}", created.token.as_str());
            anchor_audit(conn, &identity);
        }
        KeysCommand::List => {
            let keys = relay::list_api_keys(conn)?;
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
            let events = match key {
                Some(id) => relay::api_key_events_for_key(conn, id)?,
                None => relay::api_key_events(conn)?,
            };
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
                return verify_audit(conn, krl, checkpoint);
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
            let checkpoint = relay::audit::checkpoint(conn, &identity, &taken_at)?;
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
            relay::revoke_api_key(conn, id)?;
            println!("Revoked API key {id}");
            let configured = path_or_env(cert.clone(), "KEYQUORUM_PROVIDER_CERT").is_some()
                && path_or_env(relay_key.clone(), "KEYQUORUM_RELAY_KEY").is_some();
            if configured {
                let (identity, _) = load_serve_identity(cert, relay_key, krl)?;
                anchor_audit(conn, &identity);
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
        } => {
            let identity = authorize_mint(conn, "keys.rotate", cert, relay_key, krl, licensee_key)?;
            let created = relay::rotate_api_key(conn, id)?;
            println!("Rotated API key {id} -> {}", created.info.id);
            println!("token (shown once): {}", created.token.as_str());
            anchor_audit(conn, &identity);
        }
    }
    Ok(())
}

/// Sign the audit chains' new heads. The key change itself is already
/// committed, so a failure here is reported, not fatal: the running relay
/// signs any unanchored rows on its next scan.
fn anchor_audit(conn: &rusqlite::Connection, identity: &ProviderIdentity) {
    if let Err(err) = relay::anchor_now(conn, identity) {
        eprintln!("warning: could not sign the audit chain now ({err}); the relay signs it on its next scan");
    }
}

/// `keys events --verify`: every chain re-walked and every anchor checked
/// against the compiled-in provider root. Fails if any chain is broken or
/// any anchor is refused.
fn verify_audit(
    conn: &rusqlite::Connection,
    krl: Option<PathBuf>,
    checkpoint: Option<PathBuf>,
) -> Result<()> {
    let krl = path_or_env(krl, "KEYQUORUM_PROVIDER_KRL");
    let revoked =
        provider::load_revocation_list(&KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY, krl.as_deref())?;
    let checkpoint = checkpoint
        .map(|path| relay::audit::Checkpoint::decode(&std::fs::read(path)?))
        .transpose()?;
    let reports = relay::audit::verify(
        conn,
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

fn read_key_array_32(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    cli::read_key_array_32(path).map(Zeroizing::new)
}

fn read_root_key(path: Option<PathBuf>) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(path) = path {
        return read_key_array_32(&path);
    }
    match std::env::var("KEYQUORUM_PROVIDER_ROOT_KEY").map(Zeroizing::new) {
        Ok(value) if !value.is_empty() => keys::parse_key_32(&value),
        _ => Err(Error::InvalidProviderCertificate),
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
    let cert = provider::self_check(
        &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        &certificate,
        &relay_private_key,
        &now,
        &revoked,
    )?;
    eprintln!(
        "provider identity {} serial {} expires {}",
        cert.provider_id, cert.serial, cert.expires_at
    );
    Ok((
        ProviderIdentity {
            certificate,
            relay_private_key,
        },
        cert.provider_id,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    mailbox_db: &Path,
    bind: &str,
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
    scan_db: Option<PathBuf>,
    scan_interval_seconds: u64,
    behind_tls_proxy: bool,
    rate_limit_per_minute: u32,
) -> Result<()> {
    // INFO by default (RUST_LOG still overrides), so authentication and
    // scope denials and TTL purges reach the operator's logs without opt-in.
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
    let db_path = mailbox_db.to_str().ok_or(Error::InvalidPath)?;
    let conn = relay::open(db_path)?;

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

    // Anything recorded while the relay was down (host `keys` commands run
    // without an identity) is signed now.
    if let Err(err) = relay::anchor_now(&conn, &identity) {
        tracing::warn!("audit anchor at startup failed: {err}");
    }
    let state = AppState::with_identity(conn, identity)
        .with_rate_limit(rate_limit_per_minute, behind_tls_proxy);
    if rate_limit_per_minute == 0 {
        tracing::warn!("rate limiting is off; limit requests in front of this relay");
    }
    spawn_ttl_scan(
        state.db.clone(),
        state.identity(),
        scan_db,
        scan_interval_seconds,
    );

    axum::serve(
        listener,
        relay::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

fn spawn_ttl_scan(
    mailbox: Arc<Mutex<rusqlite::Connection>>,
    identity: Option<Arc<ProviderIdentity>>,
    scan_db: Option<PathBuf>,
    interval_seconds: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
        loop {
            ticker.tick().await;
            let envelopes = {
                let conn = mailbox
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                relay::purge_expired_envelopes(&conn)
            };
            match envelopes {
                Ok(n) if n > 0 => tracing::info!("purged {n} expired mailbox envelope(s)"),
                Ok(_) => {}
                Err(err) => tracing::warn!("mailbox TTL scan failed: {err}"),
            }
            let device_letters = {
                let conn = mailbox
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                relay::purge_expired_device_packages(&conn)
            };
            match device_letters {
                Ok(n) if n > 0 => tracing::info!("purged {n} expired device letter(s)"),
                Ok(_) => {}
                Err(err) => tracing::warn!("device mailbox TTL scan failed: {err}"),
            }
            if let Some(identity) = identity.as_deref() {
                let anchored = {
                    let conn = mailbox
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    relay::anchor_now(&conn, identity)
                };
                match anchored {
                    Ok(n) if n > 0 => tracing::info!("signed {n} audit chain head(s)"),
                    Ok(_) => {}
                    Err(err) => tracing::warn!("audit anchor failed: {err}"),
                }
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

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
