//! Clap definitions for the hidden provider `host` subcommand, compiled
//! only with `--features provider` (never into the lab WASM). The handler
//! that serves a relay lives with the `keyquorum` binary.

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum HostCommand {
    /// Listen for envelope push/pull. Does not mint API keys.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        /// `provider.kqcert` (or KEYQUORUM_PROVIDER_CERT)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Relay Ed25519 private key file (or KEYQUORUM_RELAY_KEY)
        #[arg(long)]
        relay_key: Option<PathBuf>,
        /// Optional signed revocation list (or KEYQUORUM_PROVIDER_KRL)
        #[arg(long)]
        krl: Option<PathBuf>,
        /// Personal/org SQLite to scan for date-based TTL files. Defaults
        /// to the global `--db` when that file already exists.
        #[arg(long)]
        scan_db: Option<PathBuf>,
        /// How often to delete expired mailbox envelopes and TTL files.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
        scan_interval_seconds: u64,
        /// Allow a non-loopback `--bind`: a TLS-terminating proxy forwards to
        /// this address. The relay itself serves plain HTTP.
        #[arg(long)]
        behind_tls_proxy: bool,
        /// Requests each client may make per minute before a 429 (0 turns
        /// the limit off). Behind --behind-tls-proxy the client is the last
        /// X-Forwarded-For address, which the proxy must set.
        #[arg(long, default_value_t = 600)]
        rate_limit_per_minute: u32,
    },
    /// Generate a relay identity keypair (private key written owner-only).
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Issue a `provider.kqcert` with the offline provider-root private key.
    Certify {
        /// Root private key file (or KEYQUORUM_PROVIDER_ROOT_KEY as key text)
        #[arg(long)]
        root_key: Option<PathBuf>,
        #[arg(long)]
        relay_public_key: PathBuf,
        #[arg(long)]
        provider_id: String,
        #[arg(long)]
        serial: String,
        #[arg(long)]
        issued_at: Option<String>,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value = "provider")]
        capabilities: String,
        #[arg(long, default_value = "KeyQuorumRoot")]
        issuer_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Issue a signed provider revocation list (`.kqrl`).
    Krl {
        #[arg(long)]
        root_key: Option<PathBuf>,
        #[arg(long)]
        issued_at: Option<String>,
        #[arg(long = "serial", required = true)]
        serials: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Mint, list, rotate, or revoke API keys on this host (not over HTTP)
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Seller-root keypair.
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
    /// Issue a provider-root-signed hardware policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Subcommand)]
pub enum RootCommand {
    /// Generate the root keypair. The private key goes only to
    /// `--private-key-out` (created owner-only, never overwritten) and is
    /// never printed.
    Generate {
        #[arg(long)]
        public_key_out: PathBuf,
        #[arg(long)]
        private_key_out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Write `provider-policy.kqpolicy` signed by the offline provider root.
    Issue {
        #[arg(long)]
        root_key: Option<PathBuf>,
        #[arg(long)]
        relay_public_key: PathBuf,
        #[arg(long)]
        provider_id: String,
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        issued_at: Option<String>,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value = "provider")]
        capabilities: String,
        /// hex(SHA-256(pubkey)) of an authorized signing token (repeatable)
        #[arg(long = "hardware-fingerprint", required = true)]
        hardware_fingerprints: Vec<String>,
        #[arg(long = "revoked-hardware")]
        revoked_hardware: Vec<String>,
        #[arg(long, default_value_t = 1)]
        hardware_threshold: u8,
        #[arg(long = "permission", default_value = "api-root.generate")]
        permissions: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum IdentityCommand {
    /// Generate the relay keypair. The private key goes only to
    /// `--private-key-out` (created owner-only, never overwritten) and is
    /// never printed.
    Generate {
        #[arg(long)]
        public_key_out: PathBuf,
        #[arg(long)]
        private_key_out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    Create {
        #[arg(long)]
        scope: String,
        /// Required for inbox.pull and device.pull: hex SHA-256 of the recipient X25519 public key
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<i64>,
        /// `provider.kqcert` (or KEYQUORUM_PROVIDER_CERT)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Relay Ed25519 private key file (or KEYQUORUM_RELAY_KEY)
        #[arg(long)]
        relay_key: Option<PathBuf>,
        /// Optional signed revocation list (or KEYQUORUM_PROVIDER_KRL)
        #[arg(long)]
        krl: Option<PathBuf>,
        /// Internal operator lock (`kql_…`). Prompted or KEYQUORUM_LICENSEE_KEY if omitted.
        #[arg(long)]
        licensee_key: Option<String>,
        /// Seal the new key to this X25519 public key (hex, from the customer's
        /// `keyquorum device public`) and write it as a `.kqkey` bundle at --out
        /// instead of printing it. For inbox.pull and device.pull the key is
        /// bound to this key's fingerprint, so --fingerprint may be left out
        #[arg(long, requires = "out", requires = "relay_url")]
        recipient_key: Option<String>,
        /// Where to write the sealed bundle (created owner-only, never overwritten)
        #[arg(long, requires = "recipient_key")]
        out: Option<PathBuf>,
        /// The relay URL the customer loads the key for, carried inside the bundle
        #[arg(long, requires = "recipient_key")]
        relay_url: Option<String>,
        /// Bind the bundle to one container: its device id (hex, 16 bytes)
        #[arg(long, requires = "recipient_key")]
        device_id: Option<String>,
        /// A UTF-8 licence statement to carry inside the sealed bundle
        #[arg(long, requires = "recipient_key")]
        licence_file: Option<PathBuf>,
    },
    List,
    /// Print the API-key lifecycle audit trail (created, rotated, revoked).
    Events {
        /// Only the events that pertain to this key id
        #[arg(long)]
        key: Option<i64>,
        /// Re-walk both audit chains and check every relay-signed anchor
        /// against the provider root and certificate validity
        #[arg(long)]
        verify: bool,
        /// With --verify: signed revocation list (or KEYQUORUM_PROVIDER_KRL)
        #[arg(long, requires = "verify")]
        krl: Option<PathBuf>,
        /// With --verify: the newest checkpoint from `keys checkpoint`, kept
        /// off the relay. The chain must still match it, and no anchor dated
        /// before it may vouch for rows after it
        #[arg(long, requires = "verify")]
        checkpoint: Option<PathBuf>,
    },
    /// Sign every audit table's row count and chain head now into a new
    /// owner-only file, to keep off the relay (write-once storage you
    /// control). `keys events --verify --checkpoint` checks against it.
    Checkpoint {
        /// Where to write the checkpoint (never overwritten)
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        relay_key: Option<PathBuf>,
        #[arg(long)]
        krl: Option<PathBuf>,
    },
    /// Revoke a key now. With the relay identity (flags or environment) the
    /// revocation is also signed into the audit chain at once; without it,
    /// the running relay signs it on its next scan.
    Revoke {
        id: i64,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        relay_key: Option<PathBuf>,
        #[arg(long)]
        krl: Option<PathBuf>,
    },
    /// Replace a key. A key that was sealed to its customer is rotated the
    /// same way: the replacement is stored in the mailbox as a sealed letter
    /// the customer's next pull collects, and the old key stays usable for
    /// --grace-seconds to collect it. With --out the replacement is written
    /// as a sealed bundle and the old key is revoked at once. A key never
    /// sealed to anyone is still printed once, unless --recipient-key says
    /// whom to seal it to from now on.
    Rotate {
        id: i64,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        relay_key: Option<PathBuf>,
        #[arg(long)]
        krl: Option<PathBuf>,
        #[arg(long)]
        licensee_key: Option<String>,
        /// Seal the replacement to this X25519 public key (hex) from now on
        #[arg(long)]
        recipient_key: Option<String>,
        /// The relay URL carried inside the issue (default: the one recorded for the key)
        #[arg(long, requires = "recipient_key")]
        relay_url: Option<String>,
        /// Bind the issue to one container: its device id (hex, 16 bytes)
        #[arg(long, requires = "recipient_key")]
        device_id: Option<String>,
        /// A UTF-8 licence statement to carry inside the sealed issue
        #[arg(long, requires = "recipient_key")]
        licence_file: Option<PathBuf>,
        /// Write the replacement as a sealed `.kqkey` bundle here (never
        /// overwritten) instead of a mailbox letter, revoking the old key now
        #[arg(long)]
        out: Option<PathBuf>,
        /// How long the old key stays usable to collect a mailbox letter
        #[arg(long, default_value_t = crate::relay::key_delivery::DEFAULT_GRACE_SECONDS)]
        grace_seconds: i64,
    },
}
