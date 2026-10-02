//! The `keyquorum` command-line interface, hosted in the library so the
//! native binary and the browser lab run the same commands. The binary
//! parses [`Cli`] and calls [`run`]; the lab does the same against its
//! in-memory environment. Command-line interface over the KeyQuorum library: hardware-key
//! registration, recursive key splitting, the password vault,
//! password-locked and hardware-key-quorum-protected files (unified under
//! `access`), signature verification and private-bridge signing, share
//! links, and export bundles.
//!
//! Producing signatures, importing an export bundle, and turning a stored
//! quorum share back into raw bytes all need a private key this project
//! has no custody story for yet — see README's Roadmap. Nothing here
//! stubs those out; they simply aren't commands.

use crate::error::{Error, Result};
use crate::key_tree::{NodeSpec, TreeNodeSummary};
use crate::keys::KeyType;
use crate::pin::ResourceType;
use crate::{
    bridge_command, db, device, export, key_tree, keys, locked_files, org_update, pin,
    private_bridge, provider, quorum, relay, sharing, signing, vault,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use env::{errln, out, outln};
use rand::RngCore;
use rusqlite::Connection;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

mod deliver_cmd;
mod device_cmd;
pub mod device_tool;
mod doctor;
pub mod env;
pub(crate) mod file_cmd;
mod gate_link;
mod inbox;
mod legacy;
mod profile;
#[cfg(all(feature = "tui", not(target_arch = "wasm32")))]
mod review_tui;
mod review_view;
use crate::file_history::{EventDetails, HistoryEventType, HistoryOutcome};
use gate_link::Gate;
#[cfg(feature = "provider")]
pub mod host_args;
mod send;
mod setup;
mod transfer_cmd;

/// How long a "one-time" PIN unlock stays valid before the PIN is needed
/// again (see `pin.rs`); not configurable via the CLI in this pass.
const PIN_TTL_SECONDS: i64 = 3600;

#[derive(Parser)]
#[command(
    name = "keyquorum",
    about = "KeyQuorum command-line interface",
    version
)]
pub struct Cli {
    /// Path to the KeyQuorum SQLite database (or KEYQUORUM_DB; default
    /// keyquorum.sqlite)
    #[arg(long, global = true)]
    pub db: Option<PathBuf>,

    /// Do not read or write the caches (recent parameters, relay trust
    /// checks, verified facts) for this command; or KEYQUORUM_NO_CACHE
    #[arg(long, global = true)]
    pub no_cache: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage password-vault credentials
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Generate a keypair. The private key is printed to stdout ONCE and
    /// never written to disk by this tool; the public key is written to
    /// --public-key-out.
    Generate {
        #[arg(long = "type")]
        key_type: CliKeyType,
        #[arg(long)]
        public_key_out: PathBuf,
        /// Registry label. Required with --register.
        #[arg(long)]
        label: Option<String>,
        /// Register the new public key in the same step
        #[arg(long, requires = "label")]
        register: bool,
    },
    /// Register a public key
    Register {
        #[arg(long = "type")]
        key_type: CliKeyType,
        #[arg(long)]
        label: String,
        #[arg(long)]
        public_key_file: PathBuf,
    },
    /// List registered hardware keys and live split trees
    List,
    /// Revoke a registered key. Always drops that token's pairings and
    /// private-bridge membership on any live tree. Optional --evict
    /// PSS-refreshes the survivors.
    Revoke {
        /// Hardware key id from `list`
        id: i64,
        /// Split tree containing this key's leaf
        #[arg(long, requires = "node")]
        key_id: Option<i64>,
        /// Leaf label as shown by `tree` (must be backed by this hardware key)
        #[arg(long, requires = "key_id")]
        node: Option<String>,
        /// Evict that leaf and PSS-refresh remaining sibling shares
        #[arg(long)]
        evict: bool,
        /// Survivor key files (repeatable): a `.pub`/`.key`, PEM, or hex
        /// key. Each file unwraps that hardware key's leaf share. Every
        /// remaining active sibling must be supplied here or at the prompt.
        #[arg(long = "share-file", requires = "evict")]
        share_files: Vec<String>,
        /// Survivor slot: container=label (repeatable). Same role as --share-file.
        #[arg(long = "slot", requires = "evict")]
        slots: Vec<String>,
        /// Drop whitelist permission (and any pairing) from --node to this peer
        #[arg(long = "deny-peer", requires_all = ["key_id", "node"])]
        deny_peers: Vec<String>,
        /// Tear down an established pairing between --node and this peer
        #[arg(long = "remove-peer", requires_all = ["key_id", "node"])]
        remove_peers: Vec<String>,
    },
    /// Remove a registered hardware key
    Remove { id: i64 },
    /// Split a secret into the live tree. `--leaf` builds that tree;
    /// `--tree-spec` is only for a nested snapshot. Sibling leaves are
    /// bound automatically when `--leaf` is used.
    Split {
        /// Nested-tree snapshot JSON. Prefer `--leaf` for a new tree.
        #[arg(long, conflicts_with_all = ["leaves", "root", "generate_keys", "register"])]
        tree_spec: Option<PathBuf>,
        /// Label stored on the `keys` row (e.g. master)
        #[arg(long)]
        label: String,
        /// Root node label. Inferred from dotted `--leaf` labels (M.S +
        /// M.A → M), or defaults to --label.
        #[arg(long)]
        root: Option<String>,
        /// Quorum threshold among --leaf children (ignored with --tree-spec)
        #[arg(long)]
        threshold: Option<u8>,
        /// Child leaf as label=path-to-pub (repeatable), e.g.
        /// M.S=SoftwareDepartment.pub
        #[arg(long = "leaf")]
        leaves: Vec<String>,
        /// Extra pairing as label=peer (repeatable). `--leaf` already
        /// binds every sibling pair.
        #[arg(long = "bind")]
        binds: Vec<String>,
        /// `.pub`, `.key`, PEM, or OpenSSH file to escrow. Omit to split
        /// a fresh random secret (printed once as hex).
        #[arg(long)]
        source: Option<PathBuf>,
        /// Generate an encryption keypair for each --leaf pub path
        #[arg(long, requires = "leaves")]
        generate_keys: bool,
        /// Register each --leaf public key (leaf label is the registry label)
        #[arg(long, requires = "leaves")]
        register: bool,
        /// hardware: one key per device. logical: several slots may share one.
        #[arg(long)]
        custody: Option<String>,
        /// Distinct physical devices required at reconstruct. Unplaced key
        /// files each count as one device.
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=255))]
        minimum_physical_devices: Option<u8>,
        /// none, or parent (each used leaf needs its parent's signature)
        #[arg(long)]
        unlock_approval: Option<String>,
    },
    /// Pair two nodes, or reseal a leaf onto a new public key
    Bind {
        key_id: i64,
        #[arg(long)]
        node: String,
        /// Establish `node <-> peer` on the live tree
        #[arg(long, conflicts_with = "public_key_file")]
        peer: Option<String>,
        /// Rebind --node to this public key (node id unchanged)
        #[arg(long, conflicts_with = "peer")]
        public_key_file: Option<PathBuf>,
        /// Old key file that unwraps --node before a rebind
        #[arg(
            long = "share-file",
            requires = "public_key_file",
            conflicts_with = "slot"
        )]
        share_file: Option<String>,
        /// Container slot that unwraps --node: container=label
        #[arg(
            long = "slot",
            requires = "public_key_file",
            conflicts_with = "share_file"
        )]
        slot: Option<String>,
        /// Register --public-key-file if it is not already in the registry
        #[arg(long, requires = "public_key_file")]
        register: bool,
    },
    /// Insert a leaf under a parent split and reshare that parent
    Add {
        key_id: i64,
        #[arg(long)]
        parent: String,
        /// New leaf label (e.g. M.F)
        #[arg(long)]
        node: String,
        #[arg(long)]
        public_key_file: PathBuf,
        /// Key files that recover the parent (repeatable)
        #[arg(long = "share-file")]
        share_files: Vec<String>,
        /// Container slot that recovers the parent: container=label (repeatable).
        /// A `--share-file` key with no placement is its own device.
        #[arg(long = "slot")]
        slots: Vec<String>,
        /// Generate a keypair at --public-key-file (.pub and sibling .key)
        #[arg(long)]
        generate_keys: bool,
        /// Register --public-key-file (uses --node as the registry label)
        #[arg(long)]
        register: bool,
    },
    /// Print live split trees, one tree, the LCA of --node labels, write
    /// the live spec JSON, or publish/fetch a public slice
    Tree(TreeArgs),
    /// Reconstruct a key's secret from raw shares
    Reconstruct {
        key_id: i64,
        /// Start reconstruction at the LCA of these labels or key files
        /// (`M.A` / `AccountingDepartment.pub`). Omit to reconstruct from
        /// the root.
        #[arg(long = "node", num_args = 2..)]
        nodes: Vec<String>,
        /// Key file that unwraps a leaf share (repeatable): `.pub`, `.key`,
        /// PEM, or hex. Any leaf not covered here is prompted for instead.
        #[arg(long = "share-file")]
        share_files: Vec<String>,
        /// Container slot that unwraps a leaf: container=label (repeatable).
        /// A `--share-file` key with no placement is its own device.
        #[arg(long = "slot")]
        slots: Vec<String>,
        /// Write the reassembled secret as raw file bytes (a `.pub` comes
        /// back as the original file). Omit to print hex on stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Manage cross-branch whitelist entries and established pairings
    Bridge {
        #[command(subcommand)]
        command: BridgeCommand,
    },
    /// Announce a replaced hardware key. Writes one authenticated `.kqpb`
    /// per store that holds the old key, then records the change here, so
    /// every recipient converges on the same token. Deliver the envelopes
    /// out of band or with `relay push`.
    Reissue {
        /// Node label whose token is being replaced
        #[arg(long)]
        node: String,
        /// Split tree that scopes this reissue. Omit for a reissue that
        /// only affects private-bridge rosters.
        #[arg(long)]
        key_id: Option<i64>,
        /// New encryption public key for --node (`.pub`, PEM, or hex)
        #[arg(long, required_unless_present = "signing_public_key_file")]
        encryption_public_key_file: Option<PathBuf>,
        /// New signing public key for --node
        #[arg(long)]
        signing_public_key_file: Option<PathBuf>,
        /// Label authorizing the reissue: --node itself (signing with the
        /// key being retired) or one of its ancestors — `M` over `M.S`
        /// over `M.S.2`. Recipients check this against the signing key
        /// they already hold for that label.
        #[arg(long = "as")]
        as_node: String,
        /// Ed25519 private key file for --as (or sign with --slot)
        #[arg(long, conflicts_with = "slot")]
        signing_key_file: Option<PathBuf>,
        /// Container slot that signs for --as: container=label (default: the
        /// device from `keyquorum use`, opened as the --as label)
        #[arg(long)]
        slot: Option<String>,
        /// Also retire the replaced ENCRYPTION key in every store that
        /// applies this. A replaced signing key is always retired,
        /// regardless of this flag — it doubles as an authorization
        /// identity, and leaving two active would make that ambiguous.
        #[arg(long)]
        revoke_previous: bool,
        #[command(flatten)]
        delivery: Box<ProducerDelivery>,
    },
    /// Print the authenticated organization updates this store has applied
    Updates {
        /// Only rows after this id
        #[arg(long)]
        since: Option<i64>,
    },
    /// Lock (encrypt) or unlock (decrypt) a password- or quorum-protected file
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Verify an Ed25519 signature (standalone or private-bridge)
    Verify {
        #[arg(long, required_unless_present = "bridge_uid")]
        public_key_file: Option<PathBuf>,
        #[arg(long)]
        message_file: PathBuf,
        #[arg(long)]
        signature_file: PathBuf,
        /// Private-bridge uid (KQBS artifact + membership check)
        #[arg(long)]
        bridge_uid: Option<String>,
        /// Local member verifying the artifact
        #[arg(long, requires = "bridge_uid")]
        as_node: Option<String>,
    },
    /// Sign a message with a private bridge plus a personal signing key
    Sign {
        #[arg(long)]
        bridge_uid: String,
        /// Local member label
        #[arg(long)]
        node: String,
        /// Your Ed25519 signing private key (not needed with --slot, which
        /// holds it)
        #[arg(long, required_unless_present = "slot")]
        signing_key_file: Option<PathBuf>,
        /// Encryption private key that unwraps this store's sealed bridge secret
        #[arg(long, required_unless_present = "slot", conflicts_with = "slot")]
        share_file: Option<String>,
        /// Container slot that unwraps the sealed bridge secret: container=label
        #[arg(
            long = "slot",
            required_unless_present = "share_file",
            conflicts_with = "share_file"
        )]
        slot: Option<String>,
        #[arg(long)]
        message_file: PathBuf,
        #[arg(long)]
        signature_out: PathBuf,
    },
    /// Export a credential or file as a portable bundle for someone outside this database
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    /// Manage time-limited share links
    Share {
        #[command(subcommand)]
        command: ShareCommand,
    },
    /// Manage PIN unlock windows
    Pin {
        #[command(subcommand)]
        command: PinCommand,
    },
    /// Send files to registered labels as signed, sealed letters
    Deliver {
        #[command(subcommand)]
        command: deliver_cmd::DeliverCommand,
    },
    /// Track files with a signed, hash-chained revision history
    File {
        #[command(subcommand)]
        command: file_cmd::FileCommand,
    },
    /// Push and pull opaque .kqpb envelopes through the mailbox relay
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Check a relay API key with POST /keycheck and store it on this instance.
    /// Later relay commands reuse it after a hash re-check; prefer omitting
    /// the key so it is prompted (stays out of shell history).
    Loadkey {
        /// Raw `kq_…` bearer. Prompted if omitted.
        api_key: Option<String>,
        /// Relay base URL (or KEYQUORUM_RELAY_URL)
        #[arg(long)]
        url: Option<String>,
    },
    /// Copy or move an active key identity between two open devices.
    /// A ghost keeps the hierarchy and cannot be exported.
    Transfer {
        #[command(subcommand)]
        command: transfer_cmd::TransferCommand,
    },
    /// A directory of logical identity slots. A key file with no placement
    /// is still one device; use `register` and `--share-file` for that.
    Device {
        #[command(subcommand)]
        command: device_cmd::DeviceCommand,
    },
    /// Send a file to another label: one command, sealed and signed. A tracked
    /// file goes as `file share` would send it, anything else as `deliver send`
    Send(Box<send::SendOpts>),
    /// Pull what is waiting for you and open it. With no subcommand, list it;
    /// `inbox open` opens each letter and posts the signed answer
    Inbox {
        #[command(subcommand)]
        command: Option<inbox::InboxCommand>,
    },
    /// Set, change or show the defaults commands use when a flag is left out:
    /// who you are, which device holds your slot, which relay. Pointers only;
    /// no passphrase, key or bearer is stored.
    Use(Box<profile::UseOpts>),
    /// Set up an identity in one command: create the device container,
    /// provision your slot, register and bind its keys, optionally load a
    /// relay key, and remember it all as your defaults. Safe to run again.
    Setup(Box<setup::SetupOpts>),
    /// Check what is missing before a task will work, and how to fix each
    /// thing. Reads only; asks for no passphrase and calls no relay.
    Doctor(Box<doctor::DoctorOpts>),
    /// Inspect or empty the short-lived caches
    Cache {
        #[command(subcommand)]
        command: profile::CacheCommand,
    },
    /// Provider mailbox host (capability build). Hidden from --help.
    #[cfg(feature = "provider")]
    #[command(hide = true)]
    Host {
        /// Mailbox SQLite file (not an organization store)
        #[arg(long, default_value = "keyquorum-relay.sqlite")]
        mailbox_db: PathBuf,
        #[command(subcommand)]
        command: host_args::HostCommand,
    },
}

#[derive(Subcommand)]
pub enum VaultCommand {
    /// Store a new credential
    Add {
        label: String,
        #[arg(long)]
        username: Option<String>,
        /// Also protect this credential with a 4-digit PIN
        #[arg(long)]
        pin: bool,
    },
    /// Retrieve a stored credential
    Get { id: i64 },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CliKeyType {
    Encryption,
    Signing,
}

impl From<CliKeyType> for KeyType {
    fn from(value: CliKeyType) -> Self {
        match value {
            CliKeyType::Encryption => KeyType::Encryption,
            CliKeyType::Signing => KeyType::Signing,
        }
    }
}

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct TreeArgs {
    #[command(subcommand)]
    command: Option<TreeCommand>,
    /// Split-tree id from `list` / `split`. Omit to list every tree.
    key_id: Option<i64>,
    /// Two or more node labels or key files: print their lowest
    /// common ancestor instead of the full tree
    #[arg(long = "node", num_args = 2.., requires = "key_id")]
    nodes: Vec<String>,
    /// Write a snapshot of the live tree (active nodes and binds)
    #[arg(long, conflicts_with = "nodes", requires = "key_id")]
    output: Option<PathBuf>,
    /// hardware: one key per device. logical: several slots may share one.
    #[arg(long, requires = "key_id")]
    custody: Option<String>,
    /// Distinct physical devices required at reconstruct. Unplaced key
    /// files each count as one device.
    #[arg(long, requires = "key_id", value_parser = clap::value_parser!(u8).range(1..=255))]
    minimum_physical_devices: Option<u8>,
}

#[derive(Subcommand)]
pub enum TreeCommand {
    /// Upload this store's public topology (no sealed shares) to the relay
    Publish {
        /// Local key id to publish (default: every split tree in this store)
        key_id: Option<i64>,
        /// Relay base URL (or KEYQUORUM_RELAY_URL)
        #[arg(long)]
        url: Option<String>,
        /// Admin-scope API key (or a key from `loadkey`, or KEYQUORUM_RELAY_API_KEY)
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Announce a restructured tree. Writes one authenticated `.kqpb` per
    /// active leaf carrying that leaf's own slice at the next public
    /// generation, then advances this store to it. Unlike `publish`, the
    /// recipient can verify who authorized the change.
    Restructure {
        key_id: i64,
        /// Label authorizing the restructure. Leaves it is not an ancestor
        /// of are reported and left without an envelope.
        #[arg(long = "as")]
        as_node: String,
        /// Ed25519 private key file for --as (or sign with --slot)
        #[arg(long, conflicts_with = "slot")]
        signing_key_file: Option<PathBuf>,
        /// Container slot that signs for --as: container=label (default: the
        /// device from `keyquorum use`, opened as the --as label)
        #[arg(long)]
        slot: Option<String>,
        #[command(flatten)]
        delivery: Box<ProducerDelivery>,
    },
    /// Countersign a pending restructure. Pass a key file, or a container slot.
    Countersign {
        key_id: i64,
        #[arg(long = "as")]
        as_node: String,
        /// Ed25519 private key file. Omit when using --device and --slot.
        #[arg(long, conflicts_with = "device")]
        signing_key_file: Option<PathBuf>,
        #[arg(long, requires = "slot")]
        device: Option<PathBuf>,
        #[arg(long, requires = "device")]
        slot: Option<String>,
        #[command(flatten)]
        delivery: Box<ProducerDelivery>,
    },
    /// Download the slice this pull key is allowed to see and merge it here.
    /// Inbox pull also applies this slice automatically; use fetch to refresh
    /// topology without downloading envelopes.
    Fetch {
        /// Local key id to update. Default: match the published tree label,
        /// or the only split tree this store holds.
        key_id: Option<i64>,
        /// Published `keys.label` when this store has no local key id yet
        /// (default: the only split tree this store holds)
        #[arg(long)]
        label: Option<String>,
        /// Relay base URL (or KEYQUORUM_RELAY_URL)
        #[arg(long)]
        url: Option<String>,
        /// Pull-scope API key (or a key from `loadkey`, or KEYQUORUM_RELAY_API_KEY)
        #[arg(long)]
        api_key: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum BridgeCommand {
    #[command(flatten)]
    Tree(bridge_command::TreeBridgeCommand),
    /// N-member private sign bridges. Each person (and each department
    /// manager parent) has their own store; this command writes per-recipient
    /// packages instead of sharing sealed secrets in one database.
    Private {
        #[command(subcommand)]
        command: PrivateBridgeCommand,
    },
}

#[derive(Subcommand)]
pub enum PrivateBridgeCommand {
    /// Create a private sign bridge. Writes every .kqpb envelope first,
    /// then commits this store. Either both land or neither does, so a
    /// failure at any point can simply be retried.
    Create {
        key_id: i64,
        /// Signing member as LABEL or LABEL=pub-file (repeatable).
        /// Each label must already have a registered signing public key.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
        /// Department/CXO supervisor as LABEL or LABEL=pub-file.
        /// Direct parents of --member are required (M.S.2 implies M.S).
        #[arg(long = "supervisor")]
        supervisors: Vec<String>,
        /// Local node whose sealed copy stays in this database
        #[arg(long = "self")]
        self_node: Option<String>,
        #[command(flatten)]
        delivery: Box<ProducerDelivery>,
        #[arg(long)]
        label: Option<String>,
    },
    /// List private bridges (optionally for one split tree)
    List {
        #[arg(long)]
        key_id: Option<i64>,
    },
    /// Show one private bridge by uid
    Show { uid: String },
    /// Print bridge-change events
    Events {
        #[arg(long)]
        uid: Option<String>,
        #[arg(long)]
        since: Option<i64>,
    },
    /// Import a per-person package into this store
    Import {
        #[arg(long)]
        file: PathBuf,
        /// Encryption private key that opens this package
        #[arg(long, required_unless_present = "slot", conflicts_with = "slot")]
        share_file: Option<String>,
        /// Container slot that opens this package: container=label
        #[arg(
            long = "slot",
            required_unless_present = "share_file",
            conflicts_with = "share_file"
        )]
        slot: Option<String>,
    },
    /// Drop a signing member. Writes rotation/destroy packages first,
    /// then commits. Either both land or neither does, so a failure at
    /// any point can simply be retried.
    RemoveMember {
        uid: String,
        /// Member label to remove
        #[arg(long)]
        member: String,
        /// Local remaining member that holds the sealed bridge secret
        #[arg(long)]
        node: String,
        /// Encryption private key that unwraps this store's sealed bridge secret
        #[arg(long, required_unless_present = "slot", conflicts_with = "slot")]
        share_file: Option<String>,
        /// Container slot that unwraps the sealed bridge secret: container=label
        #[arg(
            long = "slot",
            required_unless_present = "share_file",
            conflicts_with = "share_file"
        )]
        slot: Option<String>,
        #[command(flatten)]
        delivery: Box<ProducerDelivery>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum AccessCommand {
    Password(AccessPasswordArgs),
    Quorum(AccessQuorumArgs),
}

#[derive(Args)]
pub struct AccessPasswordArgs {
    /// 0 = lock (encrypt), 1 = unlock (decrypt)
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=1))]
    state: u8,
    /// state 0 only: file to encrypt
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "output"])]
    source: Option<PathBuf>,
    /// state 0 only: where to write the ciphertext
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "output"])]
    encrypted_path: Option<PathBuf>,
    /// state 1 only: which locked file
    #[arg(long, required_if_eq("state", "1"), conflicts_with_all = ["source", "encrypted_path", "pin"])]
    id: Option<i64>,
    /// state 1 only: write plaintext here instead of stdout
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "pin"])]
    output: Option<PathBuf>,
    /// state 0: also protect with a 4-digit PIN. state 1: this file has a
    /// PIN and it's prompted for automatically — this flag is unused there.
    #[arg(long, conflicts_with_all = ["id", "output"])]
    pin: bool,
    /// state 0 only: UTC expiry as `yyyy-mm-dd hh:mm`. After this instant,
    /// an unlock attempt deletes the ciphertext from disk.
    #[arg(long, conflicts_with_all = ["id", "output"], value_parser = parse_expires_arg)]
    expires: Option<String>,
}

#[derive(Args)]
pub struct AccessQuorumArgs {
    /// 0 = lock (encrypt + split), 1 = unlock (reconstruct + decrypt)
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=1), conflicts_with = "status")]
    state: Option<u8>,
    /// Print the file's row and key-tree summary instead of locking/unlocking
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name", "share_files", "output"])]
    status: bool,
    /// state 0 only: file to encrypt
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "share_files", "output"])]
    source: Option<PathBuf>,
    /// state 0 only: where to write the ciphertext
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "share_files", "output"])]
    encrypted_path: Option<PathBuf>,
    /// state 0 only: nested-tree snapshot JSON. Prefer `--leaf`.
    #[arg(long, conflicts_with_all = ["id", "share_files", "output", "leaves"])]
    tree_spec: Option<PathBuf>,
    /// state 0 only: child leaf as label=path-to-pub (repeatable)
    #[arg(long = "leaf", conflicts_with_all = ["id", "share_files", "output", "tree_spec"])]
    leaves: Vec<String>,
    /// Root node label for `--leaf` (inferred from dotted labels)
    #[arg(long, requires = "leaves")]
    root: Option<String>,
    /// Quorum threshold among `--leaf` children
    #[arg(long, requires = "leaves")]
    threshold: Option<u8>,
    /// Extra pairing as label=peer (repeatable)
    #[arg(long = "bind", requires = "leaves")]
    binds: Vec<String>,
    /// Generate an encryption keypair for each --leaf pub path
    #[arg(long, requires = "leaves")]
    generate_keys: bool,
    /// Register each --leaf public key
    #[arg(long, requires = "leaves")]
    register: bool,
    /// state 0 only: override the stored file name (defaults to source's file name)
    #[arg(long, conflicts_with_all = ["id", "share_files", "output"])]
    name: Option<String>,
    /// state 1 / --status: which quorum-protected file
    #[arg(long, required_if_eq("state", "1"), conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    id: Option<i64>,
    /// state 1 only: key file that unwraps a leaf share (repeatable):
    /// `.pub`, `.key`, PEM, or hex. Any leaf not covered is prompted for.
    #[arg(long = "share-file", conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    share_files: Vec<String>,
    /// state 1 only: write plaintext here instead of stdout
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    output: Option<PathBuf>,
    /// state 1: container=slot (repeatable). Same device id for every slot
    /// in that container. A `--share-file` key with no placement is its own device.
    #[arg(long = "slot", conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    slots: Vec<String>,
    /// state 1: leaf=signing-key-file, or leaf=container>slot, when unlock
    /// approval is `parent`.
    #[arg(long = "approve", conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    approves: Vec<String>,
    /// state 0: hardware (one key per device) or logical
    #[arg(long, conflicts_with_all = ["id", "share_files", "output"])]
    custody: Option<String>,
    /// state 0: distinct physical devices required to unlock
    #[arg(long, conflicts_with_all = ["id", "share_files", "output"], value_parser = clap::value_parser!(u8).range(1..=255))]
    minimum_physical_devices: Option<u8>,
    /// state 0: none, or parent
    #[arg(long, conflicts_with_all = ["id", "share_files", "output"])]
    unlock_approval: Option<String>,
    /// state 0 only: UTC expiry as `yyyy-mm-dd hh:mm`. After this instant,
    /// an unlock attempt deletes the ciphertext and the file's row.
    #[arg(long, conflicts_with_all = ["id", "share_files", "output"], value_parser = parse_expires_arg)]
    expires: Option<String>,
    /// state 1: report the shares presented, the devices counted, and the
    /// approvals checked, on stderr
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    verbose: bool,
}

#[derive(Subcommand)]
pub enum ExportCommand {
    /// Export a credential, sealed to a recipient's public key
    Credential {
        id: i64,
        #[arg(long)]
        recipient_key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export a password-locked file, sealed to a recipient's public key
    File {
        id: i64,
        #[arg(long)]
        recipient_key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export a complete tracked-file container, sealed to a recipient's public key
    TrackedFile {
        file: PathBuf,
        #[arg(long)]
        recipient_key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Record this export in the source file's history
        #[arg(long)]
        record: bool,
        /// With --record: the label to attribute it to (else no one)
        #[arg(long = "as", requires = "record")]
        as_label: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ShareCommand {
    /// Create a share link for a vault credential
    CreateCredential {
        credential_id: i64,
        #[arg(long, default_value_t = 3600, value_parser = parse_positive_i64)]
        ttl_seconds: i64,
        #[arg(long, value_parser = parse_positive_i64)]
        max_uses: Option<i64>,
        /// Also require a 4-digit PIN to redeem this share
        #[arg(long)]
        pin: bool,
        /// Require the PIN on every redemption rather than once per TTL window
        #[arg(long, requires = "pin")]
        pin_required_every_use: bool,
    },
    /// Create a share link for a password-locked file
    CreateFile {
        file_id: i64,
        /// Relative lifetime from now. Default 3600 when `--expires` is omitted.
        #[arg(long, value_parser = parse_positive_i64)]
        ttl_seconds: Option<i64>,
        /// UTC expiry as `yyyy-mm-dd hh:mm`. After this instant, redeem or
        /// unlock deletes the ciphertext from disk.
        #[arg(long, value_parser = parse_expires_arg)]
        expires: Option<String>,
        #[arg(long, value_parser = parse_positive_i64)]
        max_uses: Option<i64>,
        #[arg(long)]
        pin: bool,
        #[arg(long, requires = "pin")]
        pin_required_every_use: bool,
    },
    /// Redeem a credential share token (prompted interactively, never as an argument)
    RedeemCredential,
    /// Redeem a file share token (prompted interactively, never as an argument)
    RedeemFile,
    /// Revoke a credential share
    RevokeCredential { share_id: i64 },
    /// Revoke a file share
    RevokeFile { share_id: i64 },
}

#[derive(Subcommand)]
pub enum RelayCommand {
    /// Upload every `.kqpb` in a directory; also replace relay public-tree
    /// documents from trees stored in --db
    Push {
        /// Directory containing `.kqpb` envelopes
        #[arg(long)]
        dir: PathBuf,
        /// Relay base URL (or KEYQUORUM_RELAY_URL)
        #[arg(long)]
        url: Option<String>,
        /// Push-scope API key (or a key from `loadkey`, or KEYQUORUM_RELAY_API_KEY)
        #[arg(long)]
        api_key: Option<String>,
        /// UTC expiry as `yyyy-mm-dd hh:mm`. After this instant the mailbox
        /// host scan (and inbox pull) delete the envelope.
        #[arg(long, value_parser = parse_expires_arg)]
        expires: Option<String>,
    },
    /// Download envelopes and the public-tree slice for this pull key
    Pull {
        /// Import each envelope into --db using --share-file or --slot
        #[arg(long, requires = "pull_secret")]
        import: bool,
        /// Encryption private key that opens the envelopes
        #[arg(long, requires = "import", group = "pull_secret")]
        share_file: Option<String>,
        /// Container slot that opens the envelopes: container=label
        #[arg(long = "slot", requires = "import", group = "pull_secret")]
        slot: Option<String>,
        /// Write retrieved envelopes here (required unless --import)
        #[arg(long, required_unless_present = "import")]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// Only envelopes with id greater than this
        #[arg(long)]
        after: Option<i64>,
        /// Page size (1–500). Default 100. Pass --after with the printed cursor for more.
        #[arg(long, default_value_t = 100)]
        limit: i64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CliResourceType {
    Credential,
    LockedFile,
    QuorumFile,
    CredentialShare,
    FileShare,
}

impl From<CliResourceType> for ResourceType {
    fn from(value: CliResourceType) -> Self {
        match value {
            CliResourceType::Credential => ResourceType::Credential,
            CliResourceType::LockedFile => ResourceType::LockedFile,
            CliResourceType::QuorumFile => ResourceType::QuorumFile,
            CliResourceType::CredentialShare => ResourceType::CredentialShare,
            CliResourceType::FileShare => ResourceType::FileShare,
        }
    }
}

#[derive(Subcommand)]
pub enum PinCommand {
    /// End a cached one-time PIN unlock window immediately
    Relock {
        #[arg(long, value_enum)]
        resource: CliResourceType,
        #[arg(long)]
        id: i64,
    },
}

/// The personal database to open: `--db`, else `KEYQUORUM_DB`, else
/// `keyquorum.sqlite`. The variable only selects which database; it holds
/// no setting itself.
pub fn resolve_db(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    match env::var("KEYQUORUM_DB") {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from("keyquorum.sqlite"),
    }
}

/// Run one parsed command line: resolve the database (`--db`,
/// `KEYQUORUM_DB`, `keyquorum.sqlite`) and apply `--no-cache`.
pub fn run_cli(cli: Cli) -> Result<()> {
    let db_path = resolve_db(cli.db.as_deref());
    let _scope = profile::RunScope::enter(cli.no_cache);
    run(&db_path, cli.command)
}

/// Run one parsed command against the store at `db_path`. The provider
/// `host` subcommand is served by the binary and never reaches here.
pub fn run(db_path: &Path, command: Command) -> Result<()> {
    match command {
        Command::Relay { command } => return run_relay(db_path, command),
        Command::Loadkey { api_key, url } => return run_loadkey(db_path, api_key, url),
        Command::Transfer { command } => return transfer_cmd::run(command),
        // Dispatched here rather than in `run_in_store`, whose frame is the
        // largest in the crate, so they run with that much more stack to spare.
        command @ (Command::Use { .. }
        | Command::Cache { .. }
        | Command::Send { .. }
        | Command::Setup { .. }
        | Command::Doctor { .. }
        | Command::Inbox { .. }) => {
            return env::with_db(db_path, |conn| run_everyday(conn, command));
        }
        #[cfg(feature = "provider")]
        Command::Host { .. } => {
            unreachable!("the keyquorum binary serves host before calling cli::run")
        }
        _ => {}
    }

    env::with_db(db_path, |conn| run_in_store(conn, command))
}

fn run_in_store(conn: &mut Connection, command: Command) -> Result<()> {
    match command {
        Command::Vault { command } => run_vault(conn, command)?,
        Command::Access { command } => run_access(conn, command)?,
        Command::Use { .. }
        | Command::Cache { .. }
        | Command::Send { .. }
        | Command::Setup { .. }
        | Command::Doctor { .. }
        | Command::Inbox { .. } => {
            unreachable!("the everyday commands are dispatched in run()")
        }
        Command::Generate { .. }
        | Command::Register { .. }
        | Command::List
        | Command::Revoke { .. }
        | Command::Remove { .. }
        | Command::Split { .. }
        | Command::Bind { .. }
        | Command::Add { .. }
        | Command::Tree(_)
        | Command::Reconstruct { .. }
        | Command::Reissue { .. }
        | Command::Updates { .. }
        | Command::Bridge { .. } => run_tree_command(conn, command)?,
        Command::Verify {
            public_key_file,
            message_file,
            signature_file,
            bridge_uid,
            as_node,
        } => {
            let message = env::read(&message_file)?;
            if let Some(uid) = bridge_uid {
                let as_node =
                    as_node.ok_or_else(|| usage("verify --bridge-uid requires --as-node"))?;
                let bytes = env::read(&signature_file)?;
                let artifact = signing::decode_bridge_signature(&bytes)?;
                private_bridge::verify_message(conn, &uid, &as_node, &message, &artifact)?;
                outln!("Private-bridge signature is valid");
            } else {
                let public_key_file = public_key_file
                    .ok_or_else(|| usage("verify requires --public-key-file or --bridge-uid"))?;
                let public_key = read_key_array_32(&public_key_file)?;
                let signature = read_hex_array_64(&signature_file)?;
                signing::verify_signature(&public_key, &message, &signature)?;
                outln!("Signature is valid");
            }
        }
        Command::Sign {
            bridge_uid,
            node,
            signing_key_file,
            share_file,
            slot,
            message_file,
            signature_out,
        } => {
            let encryption_sk = encryption_secret_from(share_file.as_deref(), slot.as_deref())?;
            let signing_sk = match (&signing_key_file, slot.as_deref()) {
                (Some(file), _) => zeroize::Zeroizing::new(read_key_array_32(file)?),
                (None, Some(slot)) => open_slot_secrets(slot)?.signing_secret,
                (None, None) => return Err(usage("pass --signing-key-file or --slot")),
            };
            let message = env::read(&message_file)?;
            let artifact = private_bridge::sign_message(
                conn,
                &bridge_uid,
                &node,
                &encryption_sk,
                &signing_sk,
                &message,
            )?;
            env::write_new(
                &signature_out,
                &signing::encode_bridge_signature(&artifact)?,
            )?;
            outln!("Wrote bridge signature to {}", signature_out.display());
        }
        Command::Export { command } => run_export(conn, command)?,
        Command::Share { command } => run_share(conn, command)?,
        Command::Pin { command } => run_pin(conn, command)?,
        Command::Deliver { command } => run_deliver(conn, command)?,
        Command::File { command } => run_file(conn, command)?,
        Command::Device { command } => device_cmd::run(conn, command)?,
        Command::Transfer { .. } | Command::Relay { .. } | Command::Loadkey { .. } => {
            unreachable!("transfer and relay commands are handled before opening the org db")
        }
        #[cfg(feature = "provider")]
        Command::Host { .. } => {
            unreachable!("host commands are handled before opening the org db")
        }
    }

    Ok(())
}

/// The everyday commands (`use`, `cache`, `send`, `inbox`), kept out of
/// `run_in_store` so that function's frame (one per test thread in a debug
/// build) does not grow with every command.
#[inline(never)]
fn run_everyday(conn: &Connection, command: Command) -> Result<()> {
    match command {
        Command::Use(opts) => profile::run_use(conn, *opts)?,
        Command::Cache { command } => profile::run_cache(conn, command)?,
        Command::Send(opts) => send::run(conn, *opts)?,
        Command::Inbox { command } => inbox::run(conn, command)?,
        Command::Setup(opts) => setup::run(conn, *opts)?,
        Command::Doctor(opts) => doctor::run(conn, *opts)?,
        _ => unreachable!("run_in_store sends only the everyday commands here"),
    }
    Ok(())
}

/// `deliver`, with the legacy notice after it. Out of line for the same
/// reason as [`run_everyday`].
#[inline(never)]
fn run_deliver(conn: &Connection, command: deliver_cmd::DeliverCommand) -> Result<()> {
    let legacy = match &command {
        deliver_cmd::DeliverCommand::Send { .. } => ("deliver send", legacy::SEND),
        deliver_cmd::DeliverCommand::Open { .. } => ("deliver open", legacy::OPEN),
        deliver_cmd::DeliverCommand::Ack { .. } => ("deliver ack", legacy::OPEN),
    };
    deliver_cmd::run(conn, command)?;
    legacy::notice(legacy.0, legacy.1);
    Ok(())
}

/// `file`, with the legacy notice after the three commands `send` and
/// `inbox` replace.
#[inline(never)]
fn run_file(conn: &Connection, command: file_cmd::FileCommand) -> Result<()> {
    let legacy = match &command {
        file_cmd::FileCommand::Share { .. } => Some(("file share", legacy::SEND)),
        file_cmd::FileCommand::Receive { .. } => Some(("file receive", legacy::OPEN)),
        file_cmd::FileCommand::Ack { .. } => Some(("file ack", legacy::OPEN)),
        file_cmd::FileCommand::VerifySnapshot { .. } => Some((
            "file verify-snapshot",
            "keyquorum file history verify <snapshot> [--against FILE]",
        )),
        file_cmd::FileCommand::History {
            export: Some(_), ..
        } => Some((
            "file history --export",
            "keyquorum file history export <file> --out <snapshot>",
        )),
        _ => None,
    };
    file_cmd::run(conn, command)?;
    if let Some((old, instead)) = legacy {
        legacy::notice(old, instead);
    }
    Ok(())
}

/// The signing key for `as_node`: a key file, or the signing half of a slot
/// (`--slot`, else the profile's device opened as that label).
fn signing_secret_for(
    conn: &Connection,
    as_node: &str,
    file: Option<&Path>,
    slot: Option<&str>,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    if let Some(file) = file {
        return Ok(zeroize::Zeroizing::new(read_key_array_32(file)?));
    }
    let identity = profile::resolve_identity(conn, Some(as_node), slot)?;
    Ok(open_slot_secrets(&identity.slot)?.signing_secret)
}

/// Upload sealed packages, attaching this store's public trees to the first
/// so the relay's topology stays current. Prints one line per package.
fn push_packages(
    conn: &Connection,
    url: &str,
    api_key: &str,
    items: &[(String, Vec<u8>)],
    expires: Option<&str>,
    mut on_accepted: impl FnMut(usize),
) -> Result<()> {
    let trees = export_local_public_trees(conn)?;
    for (index, (name, bytes)) in items.iter().enumerate() {
        let attach_trees = !trees.is_empty() && index == 0;
        let accepted = if expires.is_some() || attach_trees {
            let trees = if attach_trees { trees.as_slice() } else { &[] };
            relay::push_inbox_with_trees_until(&env::EnvRelay, url, api_key, bytes, trees, expires)?
        } else {
            relay::push_inbox(&env::EnvRelay, url, api_key, bytes)?
        };
        outln!(
            "{name} -> id {} ({})",
            accepted.id,
            accepted.recipient_fingerprint
        );
        on_accepted(index);
    }
    if !trees.is_empty() {
        outln!(
            "Updated relay public-tree context ({} tree{})",
            trees.len(),
            if trees.len() == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

/// Where a command that writes sealed envelopes sends them: a directory, the
/// relay, or both. A change is always saved before anything is uploaded.
#[derive(Args)]
pub struct ProducerDelivery {
    /// Directory for the per-recipient `.kqpb` envelopes (with --push and no
    /// directory they are staged in ./outbox and removed once uploaded)
    #[arg(long, required_unless_present = "push")]
    output_dir: Option<PathBuf>,
    /// Upload the envelopes to the relay after the change is saved
    /// (inbox.push key), instead of a separate `relay push`
    #[arg(long)]
    push: bool,
    /// Relay base URL (default: `keyquorum use --url`)
    #[arg(long, requires = "push")]
    url: Option<String>,
    /// Push-scope API key (default: a key from `loadkey`)
    #[arg(long, requires = "push")]
    api_key: Option<String>,
    /// Expire uploaded envelopes at UTC `yyyy-mm-dd hh:mm`
    #[arg(long, requires = "push")]
    expires: Option<String>,
}

/// What `deliver_commit_push` did with the envelopes.
pub(crate) struct Delivered {
    paths: Vec<PathBuf>,
    /// The relay they were uploaded to, if they were.
    uploaded_to: Option<String>,
    /// Whether the files are still on disk.
    kept: bool,
}

impl Delivered {
    fn report(&self) {
        if self.kept {
            for path in &self.paths {
                outln!("Wrote {}", path.display());
            }
        }
        self.report_upload();
    }

    /// Only the upload line, for commands that list where each envelope went.
    fn report_upload(&self) {
        if let Some(url) = &self.uploaded_to {
            outln!(
                "Uploaded {} envelope{} to {url}",
                self.paths.len(),
                if self.paths.len() == 1 { "" } else { "s" }
            );
        }
    }

    /// Where package `index` ended up, for a per-recipient listing.
    fn location(&self, index: usize) -> String {
        match (self.kept, self.paths.get(index), &self.uploaded_to) {
            (true, Some(path), _) => path.display().to_string(),
            (_, _, Some(url)) => format!("uploaded to {url}"),
            _ => String::new(),
        }
    }
}

/// Write the envelopes, commit, then upload. The order matters: the files go
/// first so a failed commit takes them away again (the command can simply be
/// run once more), and the upload goes last because it cannot be undone. If
/// the upload fails the change stays saved and the files stay on disk, with
/// the command that finishes the job.
fn deliver_commit_push(
    conn: &Connection,
    delivery: &ProducerDelivery,
    packages: &[impl Envelope],
    commit: impl FnOnce() -> Result<()>,
) -> Result<Delivered> {
    // Prove the relay and the key before anything is written or committed.
    let auth = if delivery.push {
        if let Some(expires) = delivery.expires.as_deref() {
            locked_files::require_future_expires_utc(conn, expires)?;
        }
        Some(resolve_relay_auth(
            conn,
            delivery.url.clone(),
            delivery.api_key.clone(),
            relay::ApiKeyScope::InboxPush,
        )?)
    } else {
        None
    };
    let staged = delivery.output_dir.is_none();
    let dir = match &delivery.output_dir {
        Some(dir) => dir.clone(),
        None => {
            // A failed upload must have a retry target containing only this
            // operation. Reusing the shared outbox could send unrelated
            // offline letters when the person follows the recovery command.
            let mut id = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut id);
            PathBuf::from("outbox").join(format!("retry-{}", hex::encode(id)))
        }
    };
    let paths = deliver_then_commit(&dir, packages, commit)?;
    let Some((url, api_key)) = auth else {
        return Ok(Delivered {
            paths,
            uploaded_to: None,
            kept: true,
        });
    };
    let items: Vec<(String, Vec<u8>)> = paths
        .iter()
        .zip(packages)
        .map(|(path, package)| (path.display().to_string(), package.bytes().to_vec()))
        .collect();
    // Each envelope the relay accepts is dropped from a staged directory at
    // once, so a retry (`relay push --dir`) never sends one twice. A directory
    // the person named is left alone, and the error lists what is still to send.
    let mut accepted = vec![false; paths.len()];
    let pushed = push_packages(
        conn,
        &url,
        &api_key,
        &items,
        delivery.expires.as_deref(),
        |index| {
            accepted[index] = true;
            if staged {
                let _ = env::remove_file(&paths[index]);
            }
        },
    );
    if let Err(err) = pushed {
        let left: Vec<String> = paths
            .iter()
            .zip(&accepted)
            .filter(|(_, done)| !**done)
            .map(|(path, _)| path.display().to_string())
            .collect();
        let retry = if staged {
            format!(
                "the envelopes still to send are in {0}; upload them with `keyquorum relay push --dir {0}`",
                dir.display()
            )
        } else {
            format!(
                "the relay already has the others; still to send: {}",
                left.join(", ")
            )
        };
        return Err(Error::RelayRequest(format!(
            "the change is saved, but the upload failed: {err}. {retry}"
        )));
    }
    Ok(Delivered {
        paths,
        uploaded_to: Some(url),
        kept: !staged,
    })
}

fn run_vault(conn: &Connection, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Add {
            label,
            username,
            pin: set_pin_flag,
        } => {
            let password = prompt_secret("Credential password: ")?;
            let master_password = prompt_secret("Master password: ")?;
            let id = vault::add_credential(
                conn,
                &label,
                username.as_deref(),
                &password,
                &master_password,
            )?;
            if set_pin_flag {
                let pin_value = prompt_secret("Set a 4-digit PIN: ")?;
                set_default_pin(conn, ResourceType::Credential, id, &pin_value)?;
            }
            outln!("Stored credential {id}");
        }
        VaultCommand::Get { id } => {
            if pin::verification_required(conn, ResourceType::Credential, id)? {
                let pin_value = prompt_secret("PIN: ")?;
                pin::verify_pin(conn, ResourceType::Credential, id, &pin_value)?;
            }
            let master_password = prompt_secret("Master password: ")?;
            let credential = vault::get_credential(conn, id, &master_password)?;
            outln!("Label:    {}", credential.label);
            outln!(
                "Username: {}",
                credential.username.as_deref().unwrap_or("-")
            );
            outln!("Password: {}", credential.password);
        }
    }
    Ok(())
}

fn run_tree_command(conn: &mut Connection, command: Command) -> Result<()> {
    match command {
        Command::Generate {
            key_type,
            public_key_out,
            label,
            register,
        } => {
            let (secret_key, public_key) = match key_type {
                CliKeyType::Encryption => keys::generate_encryption_keypair(),
                CliKeyType::Signing => keys::generate_signing_keypair(),
            };
            write_hex_file(&public_key_out, &public_key)?;
            outln!("{}", hex::encode(*secret_key));
            errln!("Public key written to {}", public_key_out.display());
            errln!("Private key printed to stdout above — this tool keeps no copy of it.");
            if register {
                let label = label.expect("--register requires --label");
                let id = keys::register_key(conn, &label, key_type.into(), &public_key)?;
                errln!("Registered {label} as hardware key {id}");
            } else {
                errln!(
                    "Register the public key with: keyquorum register --type <encryption|signing> --label <text> --public-key-file {}",
                    public_key_out.display()
                );
            }
        }
        Command::Register {
            key_type,
            label,
            public_key_file,
        } => {
            let public_key = read_key_bytes(&public_key_file)?;
            let id = keys::register_key(conn, &label, key_type.into(), &public_key)?;
            outln!("Registered key {id}");
        }
        Command::List => {
            outln!("Hardware keys:");
            let hardware = keys::list_keys(conn)?;
            if hardware.is_empty() {
                outln!("  (none)");
            } else {
                for key in hardware {
                    outln!(
                        "  {}\t{}\t{:?}\t{}\t{}",
                        key.id,
                        key.label,
                        key.key_type,
                        key.fingerprint,
                        key.revoked_at.as_deref().unwrap_or("-"),
                    );
                }
            }
            outln!("Split trees:");
            let trees = key_tree::list_trees(conn)?;
            if trees.is_empty() {
                outln!("  (none)");
            } else {
                for tree in trees {
                    outln!("  {}\t{}", tree.key_id, tree.label);
                }
            }
        }
        Command::Revoke {
            id,
            key_id,
            node,
            evict,
            share_files,
            slots,
            deny_peers,
            remove_peers,
        } => {
            apply_hardware_revoke(
                conn,
                HardwareRevokeArgs {
                    hardware_id: id,
                    key_id,
                    node_label: node.as_deref(),
                    evict,
                    share_files: &share_files,
                    slots: &slots,
                    deny_peers: &deny_peers,
                    remove_peers: &remove_peers,
                },
            )?;
        }
        Command::Remove { id } => {
            keys::remove_key(conn, id)?;
            outln!("Removed key {id}");
        }
        Command::Split {
            tree_spec,
            label,
            root,
            threshold,
            leaves,
            binds,
            source,
            generate_keys,
            register,
            custody,
            minimum_physical_devices,
            unlock_approval,
        } => {
            let from_leaves = tree_spec.is_none();
            let spec = match tree_spec {
                Some(path) => parse_tree_spec(conn, &path)?,
                None => {
                    if leaves.is_empty() {
                        return Err(usage(
                            "split requires --leaf label=pub (repeatable) or --tree-spec FILE",
                        ));
                    }
                    build_spec_from_leaves(
                        conn,
                        &label,
                        root.as_deref(),
                        threshold.unwrap_or(2),
                        &leaves,
                        generate_keys,
                        register,
                    )?
                }
            };
            let key_id = match source {
                Some(path) => {
                    let secret = read_key_file_payload(&path)?;
                    let key_id = key_tree::split(conn, &label, &secret, &spec)?;
                    errln!(
                        "Split key {key_id} from {}; reconstruct with --output to write the file back.",
                        path.display()
                    );
                    key_id
                }
                None => {
                    let secret = crate::crypto::random_key();
                    let key_id = key_tree::split(conn, &label, &secret[..], &spec)?;
                    outln!("{}", hex::encode(&secret[..]));
                    errln!("Split key {key_id}; secret printed to stdout above — this tool keeps no copy of it.");
                    key_id
                }
            };
            if from_leaves {
                key_tree::bind_all_sibling_leaf_pairs(conn, key_id)?;
            }
            for (a, b) in parse_bind_pairs(&binds)? {
                key_tree::bind_pair(conn, key_id, &a, &b)?;
            }
            device_cmd::apply_policy(
                conn,
                key_id,
                custody.as_deref(),
                minimum_physical_devices,
                unlock_approval.as_deref(),
            )?;
        }
        Command::Bind {
            key_id,
            node,
            peer,
            public_key_file,
            share_file,
            slot,
            register,
        } => match (peer, public_key_file) {
            (Some(peer), None) => {
                key_tree::bind_pair(conn, key_id, &node, &peer)?;
                outln!("Bound {node} <-> {peer}");
            }
            (None, Some(public_key_file)) => {
                let new_id =
                    resolve_or_register_pub(conn, &node, &public_key_file, false, register)?;
                let old_secret = if let Some(slot) = slot {
                    open_slot_encryption_secret(&slot)?
                } else {
                    let share_file = share_file.ok_or_else(|| {
                        usage("bind --public-key-file requires --share-file or --slot")
                    })?;
                    secret_for_named_leaf(conn, key_id, &node, &share_file)?
                };
                key_tree::rebind_leaf(conn, key_id, &node, new_id, old_secret.as_ref())?;
                outln!("Rebound {node} to hardware key {new_id}");
            }
            _ => return Err(usage("bind requires --peer or --public-key-file")),
        },
        Command::Add {
            key_id,
            parent,
            node,
            public_key_file,
            share_files,
            slots,
            generate_keys,
            register,
        } => {
            let hw_id =
                resolve_or_register_pub(conn, &node, &public_key_file, generate_keys, register)?;
            let summary = key_tree::describe(conn, key_id)?;
            let parent_node = find_tree_node(&summary.root, &parent).ok_or(Error::NodeNotFound)?;
            let shares = collect_shares(conn, parent_node, &share_files, &slots)?;
            let new_id =
                key_tree::add_leaf_and_reshare(conn, key_id, &parent, &node, hw_id, &shares)?;
            key_tree::bind_leaf_to_active_siblings(conn, key_id, &node)?;
            outln!("Added {node} (node {new_id}); parent shares refreshed");
        }
        Command::Tree(args) => run_tree(conn, args)?,
        Command::Reconstruct {
            key_id,
            nodes,
            share_files,
            slots,
            output,
        } => {
            let summary = key_tree::describe(conn, key_id)?;
            let shares = collect_shares(conn, &summary.root, &share_files, &slots)?;
            let secret = if nodes.is_empty() {
                key_tree::reconstruct(conn, key_id, &shares)?
            } else {
                let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
                let mut indices = Vec::with_capacity(nodes.len());
                for token in &nodes {
                    indices.push(resolve_node_index(conn, &tree, token)?);
                }
                let lca_idx = tree.find_lowest_common_ancestor_of(&indices)?;
                key_tree::reconstruct_from_lca(conn, key_id, lca_idx, &shares)?
            };
            write_reassembled_secret(&secret, output.as_deref())?;
        }
        Command::Bridge { command } => run_bridge(conn, command)?,
        Command::Reissue {
            node,
            key_id,
            encryption_public_key_file,
            signing_public_key_file,
            as_node,
            signing_key_file,
            slot,
            revoke_previous,
            delivery,
        } => run_reissue(
            conn,
            ReissueArgs {
                node,
                key_id,
                encryption_public_key_file,
                signing_public_key_file,
                as_node,
                signing_key_file,
                slot,
                revoke_previous,
                delivery,
            },
        )?,
        Command::Updates { since } => {
            let rows = org_update::history(conn, since)?;
            if rows.is_empty() {
                outln!("(no applied updates)");
            }
            for row in rows {
                outln!(
                    "{}\t{}\t{}\t{} {}\tby {}\t{}",
                    row.id,
                    row.applied_at,
                    row.kind,
                    row.subject_label,
                    row.sequence,
                    row.authorizer_label,
                    row.detail
                );
            }
        }
        Command::Vault { .. }
        | Command::Access { .. }
        | Command::Verify { .. }
        | Command::Sign { .. }
        | Command::Export { .. }
        | Command::Share { .. }
        | Command::Pin { .. }
        | Command::Deliver { .. }
        | Command::File { .. }
        | Command::Relay { .. }
        | Command::Loadkey { .. }
        | Command::Device { .. }
        | Command::Use { .. }
        | Command::Send { .. }
        | Command::Inbox { .. }
        | Command::Setup { .. }
        | Command::Doctor { .. }
        | Command::Cache { .. }
        | Command::Transfer { .. } => unreachable!("non-tree commands are dispatched in run()"),
        #[cfg(feature = "provider")]
        Command::Host { .. } => unreachable!("non-tree commands are dispatched in run()"),
    }
    Ok(())
}

fn run_tree(conn: &Connection, args: TreeArgs) -> Result<()> {
    match args.command {
        Some(TreeCommand::Publish {
            key_id,
            url,
            api_key,
        }) => {
            let snapshots = match key_id {
                Some(key_id) => vec![key_tree::export_public_tree(conn, key_id)?],
                None => export_local_public_trees(conn)?,
            };
            if snapshots.is_empty() {
                return Err(usage("no split tree in this store to publish"));
            }
            let (url, api_key) = resolve_relay_auth(conn, url, api_key, relay::ApiKeyScope::Admin)?;
            for snapshot in snapshots {
                let stored = relay::publish_tree(&env::EnvRelay, &url, &api_key, &snapshot)?;
                outln!(
                    "Published {} (generation {}, {} nodes)",
                    stored.label,
                    stored.generation,
                    stored.nodes.len()
                );
            }
        }
        Some(TreeCommand::Restructure {
            key_id,
            as_node,
            signing_key_file,
            slot,
            delivery,
        }) => {
            let signing_sk =
                signing_secret_for(conn, &as_node, signing_key_file.as_deref(), slot.as_deref())?;
            let planned = org_update::plan_tree_restructure(conn, key_id, &as_node, &signing_sk)?;
            let delivered = deliver_commit_push(conn, &delivery, &planned.packages, || {
                org_update::commit_planned_tree_restructure(conn, &planned).map(|_| ())
            })?;
            delivered.report();
            if planned.needs_countersign {
                let parent = planned.countersigner_label.as_deref().unwrap_or("parent");
                outln!(
                    "Proposal for {} at generation {} is waiting for {parent} to countersign ({} envelope{})",
                    planned.tree_label,
                    planned.generation,
                    planned.packages.len(),
                    if planned.packages.len() == 1 { "" } else { "s" }
                );
            } else {
                outln!(
                    "{} is now at public generation {} ({} envelope{})",
                    planned.tree_label,
                    planned.generation,
                    planned.packages.len(),
                    if planned.packages.len() == 1 { "" } else { "s" }
                );
            }
            if !planned.skipped.is_empty() {
                outln!(
                    "No envelope for {} ({as_node} is not an ancestor)",
                    planned.skipped.join(", ")
                );
            }
        }
        Some(TreeCommand::Countersign {
            key_id,
            as_node,
            signing_key_file,
            device,
            slot,
            delivery,
        }) => {
            let signing_sk = zeroize::Zeroizing::new(signing_secret_from(
                signing_key_file.as_deref(),
                device.as_deref(),
                slot.as_deref(),
            )?);
            let planned =
                org_update::plan_restructure_countersign(conn, key_id, &as_node, &signing_sk)?;
            let delivered = deliver_commit_push(conn, &delivery, &planned.packages, || {
                org_update::commit_planned_countersign(conn, &planned).map(|_| ())
            })?;
            delivered.report();
            outln!(
                "{} countersigned generation {}",
                as_node,
                planned.generation
            );
        }
        Some(TreeCommand::Fetch {
            key_id,
            label,
            url,
            api_key,
        }) => {
            let (label, key_id) = match (label, key_id) {
                (Some(label), key_id) => (label, key_id),
                (None, Some(id)) => (key_tree::tree_label(conn, id)?, Some(id)),
                (None, None) => match key_tree::list_trees(conn)?.as_slice() {
                    [only] => (key_tree::tree_label(conn, only.key_id)?, Some(only.key_id)),
                    _ => {
                        return Err(usage(
                            "tree fetch needs a key id or --label (this store does not hold exactly one tree)",
                        ));
                    }
                },
            };
            let (url, api_key) =
                resolve_relay_auth(conn, url, api_key, relay::ApiKeyScope::InboxPull)?;
            let slice = relay::fetch_tree_context(&env::EnvRelay, &url, &api_key, &label)?;
            let applied = key_tree::apply_public_tree(conn, key_id, &slice)?;
            outln!(
                "Merged {} (generation {}, {} nodes) into key {applied}",
                slice.label,
                slice.generation,
                slice.nodes.len()
            );
        }
        None => {
            if args.custody.is_some() || args.minimum_physical_devices.is_some() {
                let key_id = args.key_id.ok_or_else(|| {
                    usage("tree --custody and --minimum-physical-devices require a key id")
                })?;
                device_cmd::apply_policy(
                    conn,
                    key_id,
                    args.custody.as_deref(),
                    args.minimum_physical_devices,
                    None,
                )?;
                outln!("Updated custody for key {key_id}");
            }
            match args.key_id {
                None => {
                    let trees = key_tree::list_trees(conn)?;
                    if trees.is_empty() {
                        outln!("(no split trees)");
                    } else {
                        for tree in trees {
                            outln!("{}\t{}", tree.key_id, tree.label);
                        }
                    }
                }
                Some(key_id) if args.nodes.is_empty() => {
                    let summary = key_tree::describe(conn, key_id)?;
                    outln!("{} (key {})", summary.label, summary.key_id);
                    print_tree_node(&summary.root, 0);
                    if let Some(path) = args.output {
                        write_live_spec(conn, key_id, &path)?;
                    }
                }
                Some(key_id) => print_lca(conn, key_id, &args.nodes)?,
            }
        }
    }
    Ok(())
}

pub struct ReissueArgs {
    node: String,
    key_id: Option<i64>,
    encryption_public_key_file: Option<PathBuf>,
    signing_public_key_file: Option<PathBuf>,
    as_node: String,
    signing_key_file: Option<PathBuf>,
    slot: Option<String>,
    revoke_previous: bool,
    delivery: Box<ProducerDelivery>,
}

fn run_reissue(conn: &Connection, args: ReissueArgs) -> Result<()> {
    let new_encryption = args
        .encryption_public_key_file
        .as_deref()
        .map(read_key_array_32)
        .transpose()?;
    let new_signing = args
        .signing_public_key_file
        .as_deref()
        .map(read_key_array_32)
        .transpose()?;
    let signing_sk = signing_secret_for(
        conn,
        &args.as_node,
        args.signing_key_file.as_deref(),
        args.slot.as_deref(),
    )?;

    let planned = org_update::plan_key_reissue(
        conn,
        args.key_id,
        &args.node,
        new_encryption,
        new_signing,
        args.revoke_previous,
        &args.as_node,
        &signing_sk,
    )?;
    let delivered = deliver_commit_push(conn, &args.delivery, &planned.packages, || {
        org_update::commit_planned_key_reissue(conn, &planned).map(|_| ())
    })?;
    delivered.report();
    outln!(
        "Reissue {} for {} authorized by {} ({} envelope{})",
        planned.sequence(),
        planned.subject_label(),
        args.as_node,
        planned.packages.len(),
        if planned.packages.len() == 1 { "" } else { "s" }
    );
    if planned.packages.is_empty() {
        outln!("No other store in this database holds that key.");
    }
    Ok(())
}

fn run_bridge(conn: &Connection, command: BridgeCommand) -> Result<()> {
    match command {
        BridgeCommand::Tree(command) => {
            env::with_stdout(|out| bridge_command::run(conn, command, out))?
        }
        BridgeCommand::Private { command } => run_private_bridge(conn, command)?,
    }
    Ok(())
}

fn run_private_bridge(conn: &Connection, command: PrivateBridgeCommand) -> Result<()> {
    match command {
        PrivateBridgeCommand::Create {
            key_id,
            members,
            supervisors,
            self_node,
            delivery,
            label,
        } => {
            let member_parties = resolve_parties(conn, Some(key_id), &members, true)?;
            let mut supervisor_parties = resolve_parties(conn, Some(key_id), &supervisors, false)?;
            let member_labels: Vec<String> =
                member_parties.iter().map(|p| p.label.clone()).collect();
            for notify in private_bridge::notify_labels(member_labels.iter().map(|s| s.as_str())) {
                if member_parties.iter().any(|p| p.label == notify) {
                    continue;
                }
                if supervisor_parties.iter().any(|p| p.label == notify) {
                    continue;
                }
                let pk = match private_bridge::encryption_public_for_label(
                    conn,
                    Some(key_id),
                    &notify,
                ) {
                    Ok(pk) => pk,
                    Err(_) => return Err(usage(&format!(
                        "need an encryption public key for supervisor {notify} (parent of a --member). Pass --supervisor {notify}=FILE.pub"
                    ))),
                };
                supervisor_parties.push(private_bridge::BridgePartyInput {
                    label: notify,
                    encryption_public_key: pk,
                    signing_public_key: None,
                });
            }
            let planned = private_bridge::plan_create(
                Some(key_id),
                label.as_deref(),
                &member_parties,
                &supervisor_parties,
                self_node.as_deref(),
            )?;
            let delivered =
                deliver_commit_push(conn, &delivery, &planned.created.packages, || {
                    private_bridge::commit_planned_creation(conn, &planned)
                })?;
            let created = &planned.created;
            outln!(
                "Created private bridge {} (generation {}). Notify {} store(s):",
                created.uid,
                created.generation,
                created.packages.len()
            );
            for (index, pkg) in created.packages.iter().enumerate() {
                outln!(
                    "  {} ({:?}) -> {}",
                    pkg.label,
                    pkg.role,
                    delivered.location(index)
                );
            }
            delivered.report_upload();
        }
        PrivateBridgeCommand::List { key_id } => {
            let listing = private_bridge::list(conn, key_id)?;
            if listing.is_empty() {
                outln!("(no private bridges)");
            } else {
                for bridge in listing {
                    let status = if bridge.destroyed {
                        "destroyed"
                    } else {
                        "live"
                    };
                    outln!(
                        "{}\tgen {}\t{}\t{}",
                        bridge.uid,
                        bridge.generation,
                        status,
                        bridge.label.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        PrivateBridgeCommand::Show { uid } => {
            print_bridge_summary(&private_bridge::get(conn, &uid)?);
        }
        PrivateBridgeCommand::Events { uid, since } => {
            let events = private_bridge::events(conn, uid.as_deref(), since)?;
            if events.is_empty() {
                outln!("(no events)");
            } else {
                for event in events {
                    outln!(
                        "{}\t{}\t{}\t{}",
                        event.id,
                        event.uid,
                        event.event_type,
                        event.detail
                    );
                }
            }
        }
        PrivateBridgeCommand::Import {
            file,
            share_file,
            slot,
        } => {
            // One inbox carries bridge envelopes and authenticated
            // organization updates alike, so dispatch on the kind byte
            // rather than making the operator sort them by hand.
            let bytes = env::read(&file)?;
            let sk = encryption_secret_from(share_file.as_deref(), slot.as_deref())?;
            match org_update::import_any(conn, &bytes, &sk)? {
                org_update::ImportedEnvelope::Bridge(summary) => {
                    outln!("Imported private bridge {}", summary.uid);
                    print_bridge_summary(&summary);
                }
                org_update::ImportedEnvelope::Update(applied) => {
                    outln!("{}", describe_applied_update(&applied));
                }
            }
        }
        PrivateBridgeCommand::RemoveMember {
            uid,
            member,
            node,
            share_file,
            slot,
            delivery,
        } => {
            let sk = encryption_secret_from(share_file.as_deref(), slot.as_deref())?;
            let planned = private_bridge::plan_remove_member(conn, &uid, &member, &node, &sk)?;
            let delivered =
                deliver_commit_push(conn, &delivery, &planned.outcome.packages, || {
                    private_bridge::commit_planned_removal(conn, &planned)
                })?;
            let outcome = &planned.outcome;
            if outcome.destroyed {
                outln!("Destroyed private bridge {uid}");
            } else {
                outln!(
                    "Removed {member} from {uid}; remaining {}",
                    outcome.remaining_members.join(", ")
                );
            }
            outln!("Deliver these packages to each store:");
            for (index, pkg) in outcome.packages.iter().enumerate() {
                outln!(
                    "  {} ({:?}) -> {}",
                    pkg.label,
                    pkg.role,
                    delivered.location(index)
                );
            }
            delivered.report_upload();
        }
    }
    Ok(())
}

fn resolve_parties(
    conn: &Connection,
    key_id: Option<i64>,
    specs: &[String],
    require_signing: bool,
) -> Result<Vec<private_bridge::BridgePartyInput>> {
    let mut out = Vec::new();
    for spec in specs {
        let (label, pk) = if let Some((label, path)) = spec.split_once('=') {
            (label.to_string(), read_key_array_32(Path::new(path))?)
        } else {
            (
                spec.clone(),
                private_bridge::encryption_public_for_label(conn, key_id, spec)?,
            )
        };
        let signing_public_key = if require_signing {
            Some(private_bridge::signing_public_for_label(conn, &label)?)
        } else {
            None
        };
        out.push(private_bridge::BridgePartyInput {
            label,
            encryption_public_key: pk,
            signing_public_key,
        });
    }
    Ok(out)
}

/// Delivery envelopes written to disk ahead of the database commit they
/// belong to.
///
/// `write_owner_only` refuses to overwrite an existing file, so envelopes
/// left behind by a commit that failed after the write would block the very
/// retry that failure calls for — and they describe a bridge this store
/// never recorded, so they must not be delivered either. Dropping this
/// guard without [`PendingDelivery::keep`] deletes every file it created,
/// and only those.
#[must_use = "the delivery files are removed unless the commit calls keep()"]
#[derive(Debug)]
pub struct PendingDelivery {
    paths: Vec<PathBuf>,
}

impl PendingDelivery {
    /// The commit succeeded: hand back the paths and leave them on disk.
    fn keep(mut self) -> Vec<PathBuf> {
        std::mem::take(&mut self.paths)
    }
}

impl Drop for PendingDelivery {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = env::remove_file(path);
        }
    }
}

/// Writes one owner-only `.kqpb` per package into `output_dir`. The caller
/// commits and then calls `keep()` on the returned guard; anything else —
/// an error here, a failed commit, an early return — removes the files
/// again so the command can simply be run once more.
fn write_delivery_packages(
    output_dir: &Path,
    packages: &[impl Envelope],
) -> Result<PendingDelivery> {
    let mut planned = Vec::with_capacity(packages.len());
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    for package in packages {
        let name = sanitize_label(package.label())?;
        let file = format!("{name}.kqpb");
        if !claimed.insert(name) {
            return Err(Error::AmbiguousDeliveryName(file));
        }
        planned.push((output_dir.join(file), package.bytes()));
    }

    let mut pending = PendingDelivery { paths: Vec::new() };
    for (path, bytes) in planned {
        env::write_new(&path, bytes)?;
        pending.paths.push(path);
    }
    Ok(pending)
}

/// A sealed envelope on its way to one store. The private-bridge and
/// organization-update producers describe their packages with different
/// types — a bridge package also carries the recipient's role — but
/// delivery only ever needs the recipient label and the bytes.
trait Envelope {
    fn label(&self) -> &str;
    fn bytes(&self) -> &[u8];
}

impl Envelope for private_bridge::DeliveryPackage {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Envelope for crate::envelope::Addressed {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Write a command's envelopes, then commit the change they describe.
///
/// The order is load-bearing, which is why every command that produces
/// envelopes goes through here rather than spelling it out again: the
/// directory exists before anything is written, the files land before the
/// database moves, and `commit` runs last. If `commit` fails, the
/// `PendingDelivery` guard drops and deletes exactly the files this call
/// created — they describe a change this store never recorded, and
/// `write_owner_only` refuses to overwrite, so leaving them behind would
/// make the retry fail with "file exists" instead.
///
/// Returns the paths written, in the same order as `packages`.
fn deliver_then_commit(
    output_dir: &Path,
    packages: &[impl Envelope],
    commit: impl FnOnce() -> Result<()>,
) -> Result<Vec<PathBuf>> {
    env::create_dir_all(output_dir)?;
    let pending = write_delivery_packages(output_dir, packages)?;
    commit()?;
    Ok(pending.keep())
}

fn sanitize_label(label: &str) -> Result<String> {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().all(|c| c == '.') {
        return Err(Error::InvalidPath);
    }
    Ok(out)
}

fn print_bridge_summary(summary: &private_bridge::BridgeSummary) {
    outln!(
        "{}  gen {}  {}",
        summary.uid,
        summary.generation,
        if summary.destroyed {
            "destroyed"
        } else {
            "live"
        }
    );
    if let Some(label) = &summary.label {
        outln!("  label: {label}");
    }
    outln!("  public: {}", hex::encode(summary.public_key));
    outln!("  salt:   {}", hex::encode(summary.salt));
    outln!("  parties:");
    for party in &summary.parties {
        outln!(
            "    {}  {:?}  local={}  sealed={}",
            party.label,
            party.role,
            party.is_local,
            party.has_sealed_key
        );
    }
}

fn run_access(conn: &mut Connection, command: AccessCommand) -> Result<()> {
    match command {
        AccessCommand::Password(args) => run_access_password(conn, args),
        AccessCommand::Quorum(args) => run_access_quorum(conn, args),
    }
}

fn run_access_password(conn: &Connection, args: AccessPasswordArgs) -> Result<()> {
    match args.state {
        0 => {
            let source = require(args.source, "source")?;
            let encrypted_path = require(args.encrypted_path, "encrypted-path")?;
            let password = prompt_secret("Lock password: ")?;
            let expires_at = match args.expires {
                Some(expires_at) => {
                    locked_files::require_future_expires_utc(conn, &expires_at)?;
                    Some(expires_at)
                }
                None => None,
            };
            let id = locked_files::lock_file_until_in(
                &mut env::EnvStorage,
                conn,
                &source,
                &encrypted_path,
                &password,
                expires_at.as_deref(),
            )?;
            if args.pin {
                let pin_value = prompt_secret("Set a 4-digit PIN: ")?;
                set_default_pin(conn, ResourceType::LockedFile, id, &pin_value)?;
            }
            outln!("Locked file {id}");
            if let Some(expires_at) = expires_at {
                outln!("Expires at: {expires_at} UTC");
            }
        }
        1 => {
            let id = require(args.id, "id")?;
            gate_link::note_if_gone(Gate::Password, conn, id);
            let mut pin_step = gate_link::PinStep::NotRequired;
            let attempt = (|| -> Result<Vec<u8>> {
                locked_files::purge_if_expired_in(&mut env::EnvStorage, conn, id)?;
                check_pin(conn, ResourceType::LockedFile, id, &mut pin_step)?;
                let password = prompt_secret("Unlock password: ")?;
                locked_files::unlock_file_in(&mut env::EnvStorage, conn, id, &password)
            })();
            gate_link::record_unlock_with(
                Gate::Password,
                conn,
                id,
                attempt.as_ref().err(),
                &[],
                &pin_step.detail(),
            );
            let plaintext = attempt?;
            match args.output {
                Some(path) => env::write_new(&path, &plaintext)?,
                None => env::stdout_bytes(&plaintext)?,
            }
        }
        _ => return Err(usage("--state must be 0 (lock) or 1 (unlock)")),
    }
    Ok(())
}

/// The unlock half of `access quorum --state 1`, shared with `send
/// --quorum-file`: purge an expired file, collect the presented shares,
/// check custody and parent approval, reconstruct, decrypt, and record the
/// attempt at the file's gate. Returns the plaintext; the caller decides
/// where it goes, and a failure leaves exactly what the command always left.
fn unlock_quorum_file(
    conn: &Connection,
    id: i64,
    share_files: &[String],
    slots: &[String],
    approves: &[String],
    verbose: bool,
) -> Result<Vec<u8>> {
    // Before anything else: an expired file is destroyed on the
    // first unlock attempt, whether or not the presented shares
    // would have reconstructed it (see quorum::unlock_file_with_approval).
    gate_link::note_if_gone(Gate::Quorum, conn, id);
    if let Err(err) = quorum::purge_if_expired_in(&mut env::EnvStorage, conn, id) {
        gate_link::record_unlock(Gate::Quorum, conn, id, Some(&err), &[]);
        return Err(err);
    }
    let file_status = quorum::status(conn, id)?;
    let shares = collect_shares(conn, &file_status.tree.root, share_files, slots)?;
    // What the gate's history may say about this attempt: counts and
    // the policy it ran under, never a share, key or device secret.
    let policy = device::custody_policy(conn, file_status.tree.key_id)?;
    let mut safe = vec![
        ("shares", shares.len().to_string()),
        (
            "threshold",
            file_status
                .tree
                .root
                .threshold
                .map_or_else(|| "-".to_string(), |t| t.to_string()),
        ),
        ("custody", policy.mode.as_str().to_string()),
        (
            "minimum_devices",
            policy.minimum_physical_devices.to_string(),
        ),
        ("approval", policy.unlock_approval.as_str().to_string()),
    ];
    if verbose {
        let mut leaves = Vec::new();
        collect_leaves(&file_status.tree.root, &mut leaves);
        let unwrapped: Vec<&str> = leaves
            .iter()
            .filter(|(node_id, _, _)| shares.contains_key(node_id))
            .map(|(_, _, label)| label.as_str())
            .collect();
        errln!(
            "Shares unwrapped: {}",
            if unwrapped.is_empty() {
                "none".to_string()
            } else {
                unwrapped.join(", ")
            }
        );
    }
    let presented = match key_tree::reconstruct_presented(conn, file_status.tree.key_id, &shares) {
        Ok(presented) => presented,
        Err(err) => {
            quorum::record_unlock_failure(conn, id, &err)?;
            gate_link::record_unlock_with(Gate::Quorum, conn, id, Some(&err), &[], &safe);
            return Err(err);
        }
    };
    safe.push(("devices", presented.devices.len().to_string()));
    if verbose {
        let used: Vec<&str> = presented
            .leaves
            .iter()
            .map(|leaf| leaf.leaf_label.as_str())
            .collect();
        errln!("Threshold met using: {}", used.join(", "));
        errln!(
            "Physical devices: {} (minimum {}) — {}",
            presented.devices.len(),
            policy.minimum_physical_devices,
            device::format_presentation(&presented.devices)
        );
    }
    let grants = match approval_grants(id, file_status.tree.key_id, &presented.devices, approves) {
        Ok(grants) => grants,
        Err(err) => {
            let mut secret = presented.secret;
            secret.zeroize();
            quorum::record_unlock_failure(conn, id, &err)?;
            safe.push(("approvals", "missing".to_string()));
            gate_link::record_unlock_with(Gate::Quorum, conn, id, Some(&err), &[], &safe);
            return Err(err);
        }
    };
    safe.push(("approvals", grants.len().to_string()));
    if verbose {
        for grant in &grants {
            errln!(
                "Parent approval: {} signed for {}",
                grant.countersigner_label,
                grant.leaf_label
            );
        }
    }
    let presented_labels: Vec<String> = presented
        .leaves
        .iter()
        .map(|leaf| leaf.leaf_label.clone())
        .collect();
    let unlocked = quorum::complete_unlock_in(&mut env::EnvStorage, conn, id, presented, &grants);
    gate_link::record_unlock_with(
        Gate::Quorum,
        conn,
        id,
        unlocked.as_ref().err(),
        &presented_labels,
        &safe,
    );
    unlocked
}

fn run_access_quorum(conn: &mut Connection, args: AccessQuorumArgs) -> Result<()> {
    if args.status {
        let id = require(args.id, "id")?;
        let file_status = quorum::status(conn, id)?;
        outln!("{} (file {})", file_status.name, file_status.id);
        outln!("Encrypted path: {}", file_status.encrypted_path);
        outln!("Created at:     {}", file_status.created_at);
        print_tree_node(&file_status.tree.root, 0);
        return Ok(());
    }

    match args.state {
        Some(0) => {
            let source = require(args.source, "source")?;
            let encrypted_path = require(args.encrypted_path, "encrypted-path")?;
            let from_leaves = args.tree_spec.is_none();
            let spec = match args.tree_spec {
                Some(path) => parse_tree_spec(conn, &path)?,
                None => {
                    if args.leaves.is_empty() {
                        return Err(usage(
                            "access quorum --state 0 requires --leaf label=pub or --tree-spec FILE",
                        ));
                    }
                    let name = args
                        .name
                        .clone()
                        .or_else(|| source.file_name().map(|n| n.to_string_lossy().into_owned()))
                        .unwrap_or_else(|| "file".into());
                    build_spec_from_leaves(
                        conn,
                        &name,
                        args.root.as_deref(),
                        args.threshold.unwrap_or(2),
                        &args.leaves,
                        args.generate_keys,
                        args.register,
                    )?
                }
            };
            if let Some(expires_at) = args.expires.as_deref() {
                locked_files::require_future_expires_utc(conn, expires_at)?;
            }
            let id = quorum::lock_file_until_in(
                &mut env::EnvStorage,
                conn,
                &source,
                &encrypted_path,
                args.name.as_deref(),
                &spec,
                args.expires.as_deref(),
            )?;
            if from_leaves {
                let file_status = quorum::status(conn, id)?;
                key_tree::bind_all_sibling_leaf_pairs(conn, file_status.tree.key_id)?;
                for (a, b) in parse_bind_pairs(&args.binds)? {
                    key_tree::bind_pair(conn, file_status.tree.key_id, &a, &b)?;
                }
            }
            outln!("Locked file {id}");
            if let Some(expires_at) = &args.expires {
                outln!("Expires at: {expires_at} UTC");
            }
            let file_status = quorum::status(conn, id)?;
            device_cmd::apply_policy(
                conn,
                file_status.tree.key_id,
                args.custody.as_deref(),
                args.minimum_physical_devices,
                args.unlock_approval.as_deref(),
            )?;
        }
        Some(1) => {
            let id = require(args.id, "id")?;
            let plaintext = unlock_quorum_file(
                conn,
                id,
                &args.share_files,
                &args.slots,
                &args.approves,
                args.verbose,
            )?;
            match args.output {
                Some(path) => env::write_new(&path, &plaintext)?,
                None => env::stdout_bytes(&plaintext)?,
            }
        }
        _ => {
            return Err(usage(
                "--state must be 0 (lock) or 1 (unlock), or pass --status",
            ))
        }
    }
    Ok(())
}

fn run_export(conn: &Connection, command: ExportCommand) -> Result<()> {
    match command {
        ExportCommand::Credential {
            id,
            recipient_key_file,
            output,
        } => {
            let recipient_public_key = read_key_array_32(&recipient_key_file)?;
            let master_password = prompt_secret("Master password: ")?;
            let bundle =
                export::export_credential(conn, id, &master_password, &recipient_public_key)?;
            env::write_new(&output, &bundle)?;
            outln!("Exported credential {id} to {}", output.display());
        }
        ExportCommand::File {
            id,
            recipient_key_file,
            output,
        } => {
            let recipient_public_key = read_key_array_32(&recipient_key_file)?;
            let password = prompt_secret("Unlock password: ")?;
            let bundle = export::export_file_in(
                &mut env::EnvStorage,
                conn,
                id,
                &password,
                &recipient_public_key,
            )?;
            env::write_new(&output, &bundle)?;
            outln!("Exported file {id} to {}", output.display());
        }
        ExportCommand::TrackedFile {
            file,
            recipient_key_file,
            output,
            record,
            as_label,
        } => {
            let recipient_public_key = read_key_array_32(&recipient_key_file)?;
            // KQTF is a binary container. Keep it as bytes; the exporter
            // decodes it to refuse a malformed or tampered artifact.
            let container = env::read(&file)?;
            let bundle = export::export_tracked_file(&container, &recipient_public_key)?;
            env::write_new(&output, &bundle)?;
            outln!(
                "Exported tracked file {} to {}",
                file.display(),
                output.display()
            );
            if record {
                // The bundle above holds the container as it was sent; the
                // event lands in the sender's copy only.
                file_cmd::record_access(
                    conn,
                    &file,
                    HistoryEventType::HistoryExported,
                    HistoryOutcome::Success,
                    None,
                    as_label.as_deref(),
                    EventDetails::new().with("bundle_type", "3"),
                )?;
            }
        }
    }
    Ok(())
}

fn persist_checked_key(
    conn: &Connection,
    url: &str,
    token: &str,
    check: &relay::KeyCheckResponse,
) -> Result<()> {
    if !check.valid {
        return Err(Error::InvalidApiKey);
    }
    let scope = check.scope.as_deref().ok_or(Error::InvalidApiKey)?;
    let key_hash = relay::hash_bearer(token)?;
    db::relay_credential::save(
        conn,
        &db::relay_credential::StoredRelayKey {
            relay_url: url.to_string(),
            scope: scope.to_string(),
            key_hash,
            token: token.to_string(),
            remote_id: check.id,
            label: check.label.clone(),
        },
    )
}

/// The revocation list the environment points at, and the digest of the file
/// it came from (of nothing when there is none).
fn revocation_list(root: &[u8; 32]) -> Result<(std::collections::HashSet<String>, String)> {
    use sha2::{Digest, Sha256};
    match env::var("KEYQUORUM_PROVIDER_KRL")
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(path) => {
            let bytes = env::read(Path::new(&path))?;
            let digest = hex::encode(Sha256::digest(&bytes));
            Ok((provider::verify_revocation_list(root, &bytes)?, digest))
        }
        None => Ok((Default::default(), hex::encode(Sha256::digest([])))),
    }
}

/// Official clients verify a KeyQuorum-signed provider certificate before
/// sending a bearer. A modified relay cannot skip this check.
fn authenticate_official_relay(url: &str) -> Result<provider::Certificate> {
    let now = env::now_utc()?;
    let root = env::provider_root();
    let (revoked, _) = revocation_list(&root)?;
    let cert = relay::authenticate_provider(&env::EnvRelay, url, &root, &now, &revoked)?;
    profile::mark_relay_proven(url);
    Ok(cert)
}

/// The identity check for a command that presents only a stored key. A check
/// that passed for this relay in the last 15 minutes, against the same
/// revocation list and stored key hash, stands in for a new challenge; so does
/// one this command already ran. Anything else, and every new bearer, runs the
/// full challenge. Only a passed check is ever remembered.
fn authenticate_relay_for_stored_key(conn: &Connection, url: &str, key_hash: &str) -> Result<()> {
    if profile::relay_proven(url) {
        return Ok(());
    }
    let root = env::provider_root();
    let (_, krl_digest) = revocation_list(&root)?;
    let now = env::now_utc()?;
    let cached = profile::caching(conn);
    if cached && db::cache::relay_trust_hit(conn, url, &krl_digest, key_hash, &now)? {
        profile::mark_relay_proven(url);
        return Ok(());
    }
    let cert = authenticate_official_relay(url)?;
    if cached {
        let fingerprint = format!("{}:{}", cert.provider_id, cert.serial);
        let _ = db::cache::store_relay_trust(
            conn,
            &db::cache::RelayTrust {
                relay_url: url,
                cert_fingerprint: &fingerprint,
                krl_digest: &krl_digest,
                key_hash,
                cert_not_after: &cert.expires_at,
            },
            &now,
        );
    }
    Ok(())
}

fn configured_relay_url(
    conn: &Connection,
    explicit: Option<String>,
    scope: relay::ApiKeyScope,
) -> Result<Option<String>> {
    if let Some(url) = explicit.filter(|s| !s.is_empty()) {
        let url = db::relay_credential::normalize_url(&url);
        relay::validate_relay_url(&url)?;
        return Ok(Some(url));
    }
    match env::var("KEYQUORUM_RELAY_URL") {
        Ok(url) if !url.is_empty() => {
            let url = db::relay_credential::normalize_url(&url);
            relay::validate_relay_url(&url)?;
            Ok(Some(url))
        }
        _ => {
            let preferred = db::profile::get(conn, db::profile::DEFAULT_RELAY_URL)?;
            if let Some(url) = preferred {
                relay::validate_relay_url(&url)?;
                return Ok(Some(url));
            }
            let stored = db::relay_credential::get_for_scope(conn, scope.as_str())?;
            match stored.as_slice() {
                [one] => {
                    relay::validate_relay_url(&one.relay_url)?;
                    Ok(Some(one.relay_url.clone()))
                }
                [] => Ok(None),
                _ => Err(Error::RelayRequest(
                    "multiple stored relay URLs; pass --url".into(),
                )),
            }
        }
    }
}

fn resolve_relay_url(
    conn: &Connection,
    explicit: Option<String>,
    scope: relay::ApiKeyScope,
) -> Result<String> {
    configured_relay_url(conn, explicit, scope)?.ok_or_else(|| {
        Error::RelayRequest("relay URL required (--url or KEYQUORUM_RELAY_URL)".into())
    })
}

/// Every device letter for this pull key, following `next_after` until the
/// relay reports no further page. A cursor that does not advance is refused
/// so a misbehaving relay cannot loop the CLI forever.
pub(crate) fn pull_all_device_packages(
    url: &str,
    api_key: &str,
) -> Result<Vec<relay::InboxEnvelope>> {
    let mut after = None;
    let mut packages = Vec::new();
    loop {
        let page = relay::pull_device_packages(
            &env::EnvRelay,
            url,
            api_key,
            after,
            Some(relay::MAX_INBOX_PAGE),
        )?;
        packages.extend(page.packages);
        match page.next_after {
            Some(next) if after.is_none_or(|prev| next > prev) => after = Some(next),
            Some(_) => {
                return Err(Error::RelayRequest(
                    "relay returned a device page cursor that does not advance".into(),
                ))
            }
            None => return Ok(packages),
        }
    }
}

/// `--api-key` / env win, then a stored key whose hash still passes `/keycheck`.
/// A newly presented bearer is stored (by scope) after a successful check.
pub(crate) fn resolve_relay_auth(
    conn: &Connection,
    explicit_url: Option<String>,
    explicit_key: Option<String>,
    required: relay::ApiKeyScope,
) -> Result<(String, String)> {
    let url = resolve_relay_url(conn, explicit_url, required)?;
    let provided = explicit_key.filter(|s| !s.is_empty()).or_else(|| {
        match env::var("KEYQUORUM_RELAY_API_KEY") {
            Ok(key) if !key.is_empty() => Some(key),
            _ => None,
        }
    });

    if let Some(token) = provided {
        // A bearer not yet stored always meets the full challenge first.
        if !profile::relay_proven(&url) {
            authenticate_official_relay(&url)?;
        }
        let check = relay::check_key(&env::EnvRelay, &url, &token)?;
        if !check.valid {
            return Err(Error::InvalidApiKey);
        }
        if check.scope.as_deref() != Some(required.as_str()) {
            return Err(Error::ApiKeyScopeDenied);
        }
        persist_checked_key(conn, &url, &token, &check)?;
        return Ok((url, token));
    }

    match db::relay_credential::get(conn, &url, required.as_str())? {
        Some(stored) => {
            authenticate_relay_for_stored_key(conn, &url, &stored.key_hash)?;
            let check = relay::check_key_hash(&env::EnvRelay, &url, &stored.key_hash)?;
            if !check.valid {
                db::cache::forget_relay_trust(conn, &url)?;
                db::relay_credential::delete(conn, &url, required.as_str())?;
                return Err(Error::RelayRequest(format!(
                    "stored API key for {} is no longer valid; run `keyquorum loadkey`",
                    required.as_str()
                )));
            }
            db::relay_credential::touch_checked(conn, &url, required.as_str())?;
            Ok((url, stored.token))
        }
        None => {
            if !profile::relay_proven(&url) {
                authenticate_official_relay(&url)?;
            }
            Err(Error::RelayRequest(format!(
                "no stored API key for {}; run `keyquorum loadkey` or pass --api-key",
                required.as_str()
            )))
        }
    }
}

fn run_loadkey(db_path: &Path, api_key: Option<String>, url: Option<String>) -> Result<()> {
    env::with_db(db_path, |conn| loadkey_in_store(conn, api_key, url))
}

fn loadkey_in_store(conn: &Connection, api_key: Option<String>, url: Option<String>) -> Result<()> {
    let url = if let Some(url) = url.filter(|s| !s.is_empty()) {
        db::relay_credential::normalize_url(&url)
    } else {
        match env::var("KEYQUORUM_RELAY_URL") {
            Ok(url) if !url.is_empty() => db::relay_credential::normalize_url(&url),
            _ => {
                return Err(Error::RelayRequest(
                    "relay URL required (--url or KEYQUORUM_RELAY_URL)".into(),
                ))
            }
        }
    };
    relay::validate_relay_url(&url)?;
    // `loadkey` always meets the full challenge, and drops any cached pass.
    db::cache::forget_relay_trust(conn, &url)?;
    authenticate_official_relay(&url)?;
    let token = match api_key.filter(|s| !s.is_empty()) {
        Some(token) => token,
        None => prompt_secret("Relay API key: ")?,
    };
    let check = relay::check_key(&env::EnvRelay, &url, &token)?;
    persist_checked_key(conn, &url, &token, &check)?;
    let scope = check.scope.as_deref().unwrap_or("unknown");
    out!("Stored {scope} API key for {url}");
    if let Some(label) = check.label.as_deref().filter(|s| !s.is_empty()) {
        out!(" ({label})");
    }
    outln!();
    Ok(())
}

fn run_relay(db_path: &Path, command: RelayCommand) -> Result<()> {
    // `relay push` stays the carrier for the producer commands until they
    // push for themselves, so only a pull is called legacy for now.
    let pulled = matches!(command, RelayCommand::Pull { .. });
    env::with_db(db_path, |conn| relay_in_store(conn, command))?;
    if pulled {
        legacy::notice("relay pull", legacy::PULL);
    }
    Ok(())
}

fn relay_in_store(conn: &Connection, command: RelayCommand) -> Result<()> {
    match command {
        RelayCommand::Push {
            dir,
            url,
            api_key,
            expires,
        } => {
            if let Some(expires) = expires.as_deref() {
                locked_files::require_future_expires_utc(conn, expires)?;
            }
            let (url, api_key) =
                resolve_relay_auth(conn, url, api_key, relay::ApiKeyScope::InboxPush)?;
            let mut items = Vec::new();
            for path in env::read_dir(&dir)? {
                if path.extension().and_then(|s| s.to_str()) != Some("kqpb") {
                    continue;
                }
                items.push((path.display().to_string(), env::read(&path)?));
            }
            if items.is_empty() {
                return Err(Error::RelayRequest(format!(
                    "no .kqpb files in {}",
                    dir.display()
                )));
            }
            push_packages(conn, &url, &api_key, &items, expires.as_deref(), |_| {})?;
        }
        RelayCommand::Pull {
            import,
            share_file,
            slot,
            output_dir,
            url,
            api_key,
            after,
            limit,
        } => {
            let (url, api_key) =
                resolve_relay_auth(conn, url, api_key, relay::ApiKeyScope::InboxPull)?;
            if !(1..=relay::MAX_INBOX_PAGE).contains(&limit) {
                return Err(Error::InvalidInboxPage);
            }
            let listed = relay::pull_inbox(&env::EnvRelay, &url, &api_key, after, Some(limit))?;
            for slice in &listed.trees {
                let applied = key_tree::apply_public_tree(conn, None, slice)?;
                outln!(
                    "Merged {} (generation {}, {} nodes) into key {applied}",
                    slice.label,
                    slice.generation,
                    slice.nodes.len()
                );
            }
            if listed.envelopes.is_empty() {
                if listed.trees.is_empty() {
                    outln!("(no envelopes)");
                }
                return Ok(());
            }

            let share_sk = if import {
                Some(encryption_secret_from(
                    share_file.as_deref(),
                    slot.as_deref(),
                )?)
            } else {
                None
            };

            if let Some(output_dir) = &output_dir {
                env::create_dir_all(output_dir)?;
            }

            for item in &listed.envelopes {
                let bytes =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &item.bytes)
                        .map_err(|_| Error::InvalidBridgePackage)?;
                if let Some(output_dir) = &output_dir {
                    let path = output_dir.join(format!("{}.kqpb", item.id));
                    env::write_new(&path, &bytes)?;
                    outln!("Wrote {}", path.display());
                }
                let kind = crate::envelope::kind(&bytes)?;
                if kind == crate::envelope::KIND_FILE_HISTORY_SNAPSHOT {
                    // Opened by `file open-history`; nothing to import.
                    outln!(
                        "Envelope {} is a tracked-file history snapshot; open it with `keyquorum file open-history`",
                        item.id
                    );
                    continue;
                }
                if kind == crate::envelope::KIND_FILE_REQUEST
                    || kind == crate::envelope::KIND_FILE_REQUEST_ANSWER
                {
                    // Opened by `file open-request` / `file open-answer`;
                    // a request asks and an answer says yes or no, so there
                    // is nothing to import.
                    outln!(
                        "Envelope {} is a file {}; open it with `keyquorum file {}`",
                        item.id,
                        if kind == crate::envelope::KIND_FILE_REQUEST {
                            "request"
                        } else {
                            "request answer"
                        },
                        if kind == crate::envelope::KIND_FILE_REQUEST {
                            "open-request"
                        } else {
                            "open-answer"
                        }
                    );
                    continue;
                }
                if kind == crate::envelope::KIND_FILE_HISTORY
                    || kind == crate::envelope::KIND_FILE_HISTORY_ACK
                {
                    // Tracked-file letters are opened by `file receive` and
                    // `file ack`, not imported into the store.
                    if share_sk.is_some() {
                        outln!(
                            "Envelope {} is a tracked-file {}; open it with `keyquorum file {}`{}",
                            item.id,
                            if kind == crate::envelope::KIND_FILE_HISTORY {
                                "letter"
                            } else {
                                "acknowledgement"
                            },
                            if kind == crate::envelope::KIND_FILE_HISTORY {
                                "receive"
                            } else {
                                "ack"
                            },
                            if output_dir.is_some() {
                                ""
                            } else {
                                " (pass --output-dir to keep it)"
                            }
                        );
                    }
                    continue;
                }
                if kind == crate::envelope::KIND_FILE_DELIVERY
                    || kind == crate::envelope::KIND_FILE_DELIVERY_ACK
                {
                    // Letters and acknowledgements are opened by `deliver`,
                    // not imported into the store.
                    if share_sk.is_some() {
                        outln!(
                            "Envelope {} is a file delivery {}; open it with `keyquorum deliver {}`{}",
                            item.id,
                            if kind == crate::envelope::KIND_FILE_DELIVERY {
                                "letter"
                            } else {
                                "acknowledgement"
                            },
                            if kind == crate::envelope::KIND_FILE_DELIVERY {
                                "open"
                            } else {
                                "ack"
                            },
                            if output_dir.is_some() {
                                ""
                            } else {
                                " (pass --output-dir to keep it)"
                            }
                        );
                    }
                    continue;
                }
                if let Some(sk) = share_sk.as_ref() {
                    import_envelope(conn, item.id, &bytes, sk)?;
                }
            }
            if let Some(cursor) = listed.next_after {
                outln!("More envelopes remain; pass --after {cursor} to continue");
            }
        }
    }
    Ok(())
}

/// Import one bridge or org-update envelope and say what it did.
fn import_envelope(conn: &Connection, id: i64, bytes: &[u8], sk: &[u8; 32]) -> Result<()> {
    match org_update::import_any(conn, bytes, sk)? {
        org_update::ImportedEnvelope::Bridge(summary) => outln!(
            "Imported envelope {id} as private bridge {} gen {}",
            summary.uid,
            summary.generation
        ),
        org_update::ImportedEnvelope::Update(applied) => {
            outln!(
                "Imported envelope {id}: {}",
                describe_applied_update(&applied)
            )
        }
    }
    Ok(())
}

fn describe_applied_update(applied: &org_update::AppliedUpdate) -> String {
    match applied {
        org_update::AppliedUpdate::KeyReissue {
            subject_label,
            sequence,
            encryption_rotated,
            signing_rotated,
            ..
        } => {
            let mut rotated = Vec::new();
            if *encryption_rotated {
                rotated.push("encryption");
            }
            if *signing_rotated {
                rotated.push("signing");
            }
            format!(
                "applied reissue {sequence} for {subject_label} ({} key)",
                rotated.join(" and ")
            )
        }
        org_update::AppliedUpdate::TreeProposal {
            tree_label,
            authorizer_label,
            countersigner_label,
            generation,
            recipients,
        } => format!(
            "recorded {tree_label} restructure proposal generation {generation} from {authorizer_label}, waiting for {countersigner_label} ({recipients} recipient(s))"
        ),
        org_update::AppliedUpdate::TreeRestructure {
            tree_label,
            key_id,
            generation,
            nodes,
            ..
        } => format!(
            "applied {tree_label} restructure (generation {generation}, {nodes} nodes) into key {key_id}"
        ),
    }
}

fn export_local_public_trees(conn: &Connection) -> Result<Vec<key_tree::PublicTree>> {
    let mut trees = Vec::new();
    for listing in key_tree::list_trees(conn)? {
        match key_tree::export_public_tree(conn, listing.key_id) {
            Ok(tree) => trees.push(tree),
            Err(Error::NodeNotFound | Error::TreeNotFound) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(trees)
}

fn run_share(conn: &Connection, command: ShareCommand) -> Result<()> {
    match command {
        ShareCommand::CreateCredential {
            credential_id,
            ttl_seconds,
            max_uses,
            pin: set_pin_flag,
            pin_required_every_use,
        } => {
            let share =
                sharing::create_credential_share(conn, credential_id, ttl_seconds, max_uses)?;
            if set_pin_flag {
                let pin_value = prompt_secret("Set a 4-digit PIN for this share: ")?;
                pin::set_pin(
                    conn,
                    ResourceType::CredentialShare,
                    share.id,
                    &pin_value,
                    pin_required_every_use,
                    PIN_TTL_SECONDS,
                )?;
            }
            print_share(&share);
        }
        ShareCommand::CreateFile {
            file_id,
            ttl_seconds,
            expires,
            max_uses,
            pin: set_pin_flag,
            pin_required_every_use,
        } => {
            if ttl_seconds.is_some() && expires.is_some() {
                return Err(usage("use --expires or --ttl-seconds, not both"));
            }
            let share = match expires {
                Some(raw) => {
                    locked_files::require_future_expires_utc(conn, &raw)?;
                    sharing::create_file_share_until(conn, file_id, &raw, max_uses)?
                }
                None => sharing::create_file_share(
                    conn,
                    file_id,
                    ttl_seconds.unwrap_or(3600),
                    max_uses,
                )?,
            };
            gate_link::record_share(
                conn,
                file_id,
                HistoryEventType::ShareLinkCreated,
                None,
                share.id,
                &[("expires_at", share.expires_at.clone())],
            );
            if set_pin_flag {
                let pin_value = prompt_secret("Set a 4-digit PIN for this share: ")?;
                pin::set_pin(
                    conn,
                    ResourceType::FileShare,
                    share.id,
                    &pin_value,
                    pin_required_every_use,
                    PIN_TTL_SECONDS,
                )?;
            }
            print_share(&share);
        }
        ShareCommand::RedeemCredential => {
            let token = prompt_secret("Credential share token: ")?;
            let share_id = sharing::credential_share_id_for_token(conn, &token)?;
            if pin::verification_required(conn, ResourceType::CredentialShare, share_id)? {
                let pin_value = prompt_secret("PIN: ")?;
                pin::verify_pin(conn, ResourceType::CredentialShare, share_id, &pin_value)?;
            }
            let credential_id = sharing::redeem_credential_share(conn, &token)?;
            outln!("Redeemed credential {credential_id}");
        }
        ShareCommand::RedeemFile => {
            let token = prompt_secret("File share token: ")?;
            // Read before anything can purge the file and its share rows.
            let known = gate_link::share_of_token(conn, &token);
            let mut pin_step = gate_link::PinStep::NotRequired;
            let attempt = (|| -> Result<i64> {
                sharing::purge_expired_file_share_in(&mut env::EnvStorage, conn, &token)?;
                let share_id = sharing::file_share_id_for_token(conn, &token)?;
                check_pin(conn, ResourceType::FileShare, share_id, &mut pin_step)?;
                sharing::redeem_file_share_in(&mut env::EnvStorage, conn, &token)
            })();
            // A share link is a bearer credential: whoever holds the token
            // redeems it, and nothing here proves who that is.
            let mut redeem_details = vec![("redeemer", "UNKNOWN_BEARER".to_string())];
            redeem_details.extend(pin_step.detail());
            if let Some((share_id, file_id)) = known {
                match attempt.as_ref().err() {
                    Some(Error::FileExpired) => {
                        gate_link::record_expiry(gate_link::Gate::Password, conn, file_id)
                    }
                    failure => gate_link::record_share(
                        conn,
                        file_id,
                        HistoryEventType::ShareLinkRedeemed,
                        failure,
                        share_id,
                        &redeem_details,
                    ),
                }
            }
            let file_id = attempt?;
            outln!("Redeemed file {file_id}");
        }
        ShareCommand::RevokeCredential { share_id } => {
            sharing::revoke_credential_share(conn, share_id)?;
            outln!("Revoked credential share {share_id}");
        }
        ShareCommand::RevokeFile { share_id } => {
            let file_id = gate_link::file_of_share(conn, share_id);
            let revoked = sharing::revoke_file_share(conn, share_id);
            if let Some(file_id) = file_id {
                gate_link::record_share(
                    conn,
                    file_id,
                    HistoryEventType::ShareLinkRevoked,
                    revoked.as_ref().err(),
                    share_id,
                    &[],
                );
            }
            revoked?;
            outln!("Revoked file share {share_id}");
        }
    }
    Ok(())
}

/// Ask for the PIN when the resource needs one, tracking how far the check
/// got so the gate's history can say so (the outcome only, never the PIN).
fn check_pin(
    conn: &Connection,
    resource: ResourceType,
    id: i64,
    step: &mut gate_link::PinStep,
) -> Result<()> {
    if !pin::verification_required(conn, resource, id)? {
        return Ok(());
    }
    *step = gate_link::PinStep::Asked;
    let pin_value = prompt_secret("PIN: ")?;
    let result = pin::verify_pin(conn, resource, id, &pin_value);
    *step = gate_link::PinStep::from_result(&result);
    result
}

fn run_pin(conn: &Connection, command: PinCommand) -> Result<()> {
    match command {
        PinCommand::Relock { resource, id } => {
            pin::relock(conn, resource.into(), id)?;
            outln!("Relocked PIN for resource {id}");
        }
    }
    Ok(())
}

fn print_share(share: &sharing::Share) {
    outln!("Share id:   {}", share.id);
    outln!("Token:      {}", share.token);
    outln!("Expires at: {}", share.expires_at);
}

fn print_tree_node(node: &TreeNodeSummary, depth: usize) {
    let indent = "  ".repeat(depth);
    let inactive = if node.is_active { "" } else { " [inactive]" };
    match &node.hardware_key_label {
        Some(label) => outln!(
            "{indent}{} (node {}){inactive} -> hardware key {} ({label})",
            node.label,
            node.id,
            node.hardware_key_id.unwrap_or(-1)
        ),
        None => outln!(
            "{indent}{} (node {}){inactive} [{} of {}]",
            node.label,
            node.id,
            node.threshold.unwrap_or(0),
            node.children.len()
        ),
    }
    if !node.allowed_bridges.is_empty() {
        outln!(
            "{indent}  allowed bridges: {}",
            node.allowed_bridges.join(", ")
        );
    }
    for child in &node.children {
        print_tree_node(child, depth + 1);
    }
}

pub struct HardwareRevokeArgs<'a> {
    hardware_id: i64,
    key_id: Option<i64>,
    node_label: Option<&'a str>,
    evict: bool,
    share_files: &'a [String],
    slots: &'a [String],
    deny_peers: &'a [String],
    remove_peers: &'a [String],
}

/// Ban `hardware_id` from new trees and drop its pairings on every live
/// spec. Optional `--evict` PSS-refreshes survivors of the matching leaf
/// (`--key-id` / `--node`, or the unique leaf this token backs).
fn apply_hardware_revoke(conn: &mut Connection, args: HardwareRevokeArgs<'_>) -> Result<()> {
    let HardwareRevokeArgs {
        hardware_id,
        key_id,
        node_label,
        evict,
        share_files,
        slots,
        deny_peers,
        remove_peers,
    } = args;
    if let (Some(key_id), Some(node_label)) = (key_id, node_label) {
        let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
        let _node = leaf_backed_by(&tree, node_label, hardware_id)?;
        for peer in remove_peers {
            key_tree::remove_bridge(conn, key_id, node_label, peer)?;
            outln!("Removed bridge {node_label} <-> {peer}");
        }
        for peer in deny_peers {
            key_tree::deny_bridge(conn, key_id, node_label, peer)?;
            outln!("Denied {node_label} bridging to {peer}");
        }
    }

    let leaves = key_tree::drop_bindings_for_hardware(conn, hardware_id)?;
    for leaf in &leaves {
        outln!(
            "Dropped binds for {} (node {}) on tree {}",
            leaf.label,
            leaf.node_id,
            leaf.key_id
        );
    }

    let mut evict_changes = Vec::new();
    if evict {
        let target = match (key_id, node_label) {
            (Some(key_id), Some(node_label)) => {
                let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
                let node = leaf_backed_by(&tree, node_label, hardware_id)?;
                (key_id, node.db_id)
            }
            _ => match leaves.as_slice() {
                [leaf] => (leaf.key_id, leaf.node_id),
                [] => {
                    return Err(usage(
                        "revoke --evict needs a live leaf; this hardware key backs none",
                    ))
                }
                _ => {
                    return Err(usage(
                        "this hardware key backs more than one leaf; pass --key-id and --node",
                    ))
                }
            },
        };
        let summary = key_tree::describe(conn, target.0)?;
        let shares = collect_shares(conn, &summary.root, share_files, slots)?;
        let changes = key_tree::evict_and_refresh(conn, target.0, target.1, &shares)?;
        outln!("Evicted node {}; survivor shares refreshed", target.1);
        evict_changes = changes;
    }

    let hardware = keys::get_key(conn, hardware_id)?;
    let mut labels = BTreeSet::new();
    labels.insert(hardware.label.clone());
    for leaf in &leaves {
        labels.insert(leaf.label.clone());
    }
    let mut revoke_changes = Vec::new();
    for label in labels {
        revoke_changes.extend(private_bridge::on_member_revoked(conn, &label)?);
    }

    keys::revoke_key(conn, hardware_id)?;
    outln!("Revoked key {hardware_id}");

    write_bridge_change_notices(&evict_changes)?;
    write_bridge_change_notices(&revoke_changes)?;
    Ok(())
}

fn write_bridge_change_notices(changes: &[private_bridge::BridgeChange]) -> Result<()> {
    for change in changes {
        let kind = match change.kind {
            private_bridge::BridgeChangeKind::NeedsMemberRotate => "remaining members must rotate",
            private_bridge::BridgeChangeKind::Destroyed => "bridge destroyed",
        };
        outln!(
            "Private bridge {}: removed {}; {}.",
            change.uid,
            change.removed_member,
            kind
        );
        outln!(
            "  Notify these stores (members + department managers): {}",
            change.notify.join(", ")
        );
        let notice_path = format!(
            "bridge-{}-removed-{}.kqbn",
            change.uid,
            sanitize_label(&change.removed_member)?
        );
        env::write_new(Path::new(&notice_path), &change.notice)?;
        outln!("  Wrote notice {notice_path}");
    }
    Ok(())
}

fn print_lca(conn: &Connection, key_id: i64, nodes: &[String]) -> Result<()> {
    let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
    let mut indices = Vec::with_capacity(nodes.len());
    for token in nodes {
        indices.push(resolve_node_index(conn, &tree, token)?);
    }
    let lca_idx = tree.find_lowest_common_ancestor_of(&indices)?;
    let lca = &tree.nodes[lca_idx];
    outln!("{} (node {})", lca.id, lca.db_id);
    Ok(())
}

/// A node label (`M.A`) or a key file whose public key uniquely backs one
/// active leaf (`AccountingDepartment.pub`).
fn resolve_node_index(
    conn: &Connection,
    tree: &key_tree::KeyQuorumTree,
    token: &str,
) -> Result<usize> {
    if let Ok(idx) = tree.index_by_label(token) {
        return Ok(idx);
    }
    let path = Path::new(token);
    if !env::is_file(path) {
        return Err(Error::NodeNotFound);
    }
    let raw = read_key_bytes(path)?;
    if raw.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked");
    let hardware = match keys::get_key_by_public_key(conn, &arr) {
        Ok(key) => key,
        Err(_) => {
            let public = keys::encryption_public_from_secret(&arr);
            keys::get_key_by_public_key(conn, &public)?
        }
    };
    let matches: Vec<usize> = tree
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.is_active && node.hardware_key_id == Some(hardware.id))
        .map(|(idx, _)| idx)
        .collect();
    match matches.as_slice() {
        [idx] => Ok(*idx),
        [] => Err(Error::NodeNotFound),
        _ => Err(usage(&format!(
            "{token} backs more than one leaf; pass the node label from `tree`"
        ))),
    }
}

fn leaf_backed_by<'a>(
    tree: &'a key_tree::KeyQuorumTree,
    label: &str,
    hardware_id: i64,
) -> Result<&'a key_tree::KeyNode> {
    let idx = tree.index_by_label(label)?;
    let node = &tree.nodes[idx];
    if node.hardware_key_id != Some(hardware_id) {
        return Err(usage(&format!(
            "--node '{label}' is not a leaf backed by hardware key {hardware_id}"
        )));
    }
    Ok(node)
}

fn signing_secret_from(
    key_file: Option<&Path>,
    device_path: Option<&Path>,
    slot: Option<&str>,
) -> Result<[u8; 32]> {
    if let Some(path) = key_file {
        return read_key_array_32(path);
    }
    let (Some(path), Some(slot)) = (device_path, slot) else {
        return Err(usage(
            "countersign requires --signing-key-file or --device and --slot",
        ));
    };
    let container = env::fs(|fs| device::open_in(fs, path))?;
    let passphrase = env::prompt_passphrase(&format!("Passphrase for {slot}: "))?;
    let secrets = env::fs(|fs| device::open_slot_in(fs, &container, slot, &passphrase))?;
    Ok(*secrets.signing_secret)
}

fn encryption_secret_from(
    share_file: Option<&str>,
    slot: Option<&str>,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    match (share_file, slot) {
        (Some(path), None) => Ok(zeroize::Zeroizing::new(read_key_array_32(Path::new(path))?)),
        (None, Some(spec)) => open_slot_encryption_secret(spec),
        _ => Err(usage("pass --share-file or --slot container=label")),
    }
}

fn open_slot_encryption_secret(entry: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    Ok(open_slot_secrets(entry)?.encryption_secret)
}

/// Open the identity slot named by `--slot container=label`, prompting for
/// its passphrase.
fn open_slot_secrets(entry: &str) -> Result<device::SlotSecrets> {
    let (path, label) = entry
        .rsplit_once('=')
        .ok_or_else(|| usage("--slot must be container=label"))?;
    if path.is_empty() || label.is_empty() {
        return Err(usage("--slot must be container=label"));
    }
    profile::slot_secrets(entry, || {
        let container = env::fs(|fs| device::open_in(fs, Path::new(path)))?;
        let passphrase = env::prompt_passphrase(&format!("Passphrase for {label}: "))?;
        env::fs(|fs| device::open_slot_in(fs, &container, label, &passphrase))
    })
}

fn add_slot_shares(
    conn: &Connection,
    root: &TreeNodeSummary,
    shares: &mut HashMap<i64, Vec<u8>>,
    slots: &[String],
) -> Result<()> {
    if slots.is_empty() {
        return Ok(());
    }
    let mut leaves = Vec::new();
    collect_leaves(root, &mut leaves);
    for entry in slots {
        let (path, label) = entry
            .rsplit_once('=')
            .ok_or_else(|| usage("--slot must be container=label"))?;
        if path.is_empty() || label.is_empty() {
            return Err(usage("--slot must be container=label"));
        }
        let container = env::fs(|fs| device::open_in(fs, Path::new(path)))?;
        let passphrase = env::prompt_passphrase(&format!("Passphrase for {label}: "))?;
        let secrets = env::fs(|fs| device::open_slot_in(fs, &container, label, &passphrase))?;
        unwrap_leaves_for_secret(conn, &leaves, shares, secrets.encryption_secret.as_slice())?;
    }
    Ok(())
}

fn approval_grants(
    file_id: i64,
    key_id: i64,
    devices: &[device::PresentedDevice],
    approves: &[String],
) -> Result<Vec<crate::authority::UnlockGrant>> {
    if approves.is_empty() {
        return Ok(Vec::new());
    }
    let mut device_ids: Vec<[u8; 16]> = devices.iter().map(|device| device.device_id).collect();
    device_ids.sort();
    let mut grants = Vec::with_capacity(approves.len());
    for entry in approves {
        let (leaf, spec) = entry
            .split_once('=')
            .ok_or_else(|| usage("--approve must be leaf=key-file or leaf=container>slot"))?;
        let parent = private_bridge::parent_node_label(leaf)
            .ok_or(Error::UnlockApprovalRequired)?
            .to_string();
        let preimage = crate::authority::unlock_approval_preimage(
            file_id,
            key_id,
            leaf,
            &parent,
            &device_ids,
        )?;
        let signature = if let Some((container, slot)) = spec.split_once('>') {
            let opened = env::fs(|fs| device::open_in(fs, Path::new(container)))?;
            let passphrase = env::prompt_passphrase(&format!("Passphrase for {slot}: "))?;
            let secrets = env::fs(|fs| device::open_slot_in(fs, &opened, slot, &passphrase))?;
            device::sign_message(&secrets, &preimage)
        } else {
            let secret = zeroize::Zeroizing::new(read_key_array_32(Path::new(spec))?);
            signing::sign(&secret, &preimage)
        };
        grants.push(crate::authority::UnlockGrant {
            leaf_label: leaf.to_string(),
            countersigner_label: parent,
            signature,
        });
    }
    Ok(grants)
}

/// Gathers raw shares for every active leaf in `root`. `--share-file` is a
/// path to the hardware key that backs the leaf (`.pub`, `.key`, PEM, or
/// hex). `--slot` is `container=label` and unwraps with that slot's key.
/// A matching private key unwraps the sealed share in the database.
/// `node_id=path` is still accepted as a raw already-unwrapped share.
/// Leaves not covered by a flag are prompted for (key-file path or hex
/// private key). Never takes share or key material as a bare argv value.
fn collect_shares(
    conn: &Connection,
    root: &TreeNodeSummary,
    share_files: &[String],
    slots: &[String],
) -> Result<HashMap<i64, Vec<u8>>> {
    let mut leaves = Vec::new();
    collect_leaves(root, &mut leaves);

    let mut shares = HashMap::new();
    for entry in share_files {
        if let Some((node_id_str, path)) = entry.split_once('=') {
            if let Ok(node_id) = node_id_str.parse::<i64>() {
                apply_raw_share_file(&leaves, &mut shares, node_id, Path::new(path))?;
                continue;
            }
        }
        apply_key_file(conn, &leaves, &mut shares, Path::new(entry))?;
    }
    add_slot_shares(conn, root, &mut shares, slots)?;

    for (node_id, hardware_key_id, label) in &leaves {
        if shares.contains_key(node_id) {
            continue;
        }
        let prompt = format!(
            "Key for '{label}' (node {node_id}, hardware key {hardware_key_id}; path to .key/.pub or hex private key, blank to skip): "
        );
        let entered = prompt_secret(&prompt)?;
        let trimmed = entered.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = Path::new(trimmed);
        if env::exists(path) {
            apply_key_file(conn, &leaves, &mut shares, path)?;
        } else {
            let secret = hex::decode(trimmed)
                .map_err(|_| usage("key must be a file path or hex-encoded"))?;
            unwrap_leaves_for_secret(conn, &leaves, &mut shares, &secret)?;
        }
    }

    Ok(shares)
}

fn apply_raw_share_file(
    leaves: &[(i64, i64, String)],
    shares: &mut HashMap<i64, Vec<u8>>,
    node_id: i64,
    path: &Path,
) -> Result<()> {
    if !leaves.iter().any(|(id, _, _)| *id == node_id) {
        return Err(usage(&format!(
            "--share-file references node {node_id}, which isn't a leaf in this tree \
             (see `tree`/`--status` for valid leaf node ids)"
        )));
    }
    if shares.contains_key(&node_id) {
        return Err(usage(&format!(
            "--share-file for node {node_id} was given more than once"
        )));
    }
    let bytes = read_hex_bytes(path).map_err(|err| usage(&err.to_string()))?;
    shares.insert(node_id, bytes);
    Ok(())
}

fn apply_key_file(
    conn: &Connection,
    leaves: &[(i64, i64, String)],
    shares: &mut HashMap<i64, Vec<u8>>,
    path: &Path,
) -> Result<()> {
    let raw = read_key_bytes(path)?;
    if raw.len() != 32 {
        return Err(usage(&format!(
            "{} is not a 32-byte key file",
            path.display()
        )));
    }
    let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked above");
    let secret = match keys::get_key_by_public_key(conn, &arr) {
        Ok(_) => resolve_private_for_public(path, &arr)?,
        Err(_) => zeroize::Zeroizing::new(arr),
    };
    unwrap_leaves_for_secret(conn, leaves, shares, secret.as_ref())
}

fn resolve_private_for_public(
    public_path: &Path,
    public_key: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let sibling = public_path.with_extension("key");
    if sibling != public_path && env::is_file(&sibling) {
        let raw = read_key_bytes(&sibling)?;
        let secret: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)?;
        if keys::encryption_public_from_secret(&secret) != *public_key {
            return Err(usage(&format!(
                "{} does not match public key {}",
                sibling.display(),
                public_path.display()
            )));
        }
        return Ok(zeroize::Zeroizing::new(secret));
    }

    let entered = prompt_secret(&format!(
        "Private key for {} (hex, blank to skip): ",
        public_path.display()
    ))?;
    let trimmed = entered.trim();
    if trimmed.is_empty() {
        return Err(usage(&format!(
            "{} is a public key; pass the matching .key file or enter the private key",
            public_path.display()
        )));
    }
    let raw = keys::parse_key_text(trimmed)?;
    let secret: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    if keys::encryption_public_from_secret(&secret) != *public_key {
        return Err(usage(&format!(
            "private key does not match {}",
            public_path.display()
        )));
    }
    Ok(zeroize::Zeroizing::new(secret))
}

fn unwrap_leaves_for_secret(
    conn: &Connection,
    leaves: &[(i64, i64, String)],
    shares: &mut HashMap<i64, Vec<u8>>,
    secret: &[u8],
) -> Result<()> {
    let secret_arr: [u8; 32] = secret.try_into().map_err(|_| Error::InvalidPublicKey)?;
    let public = keys::encryption_public_from_secret(&secret_arr);
    let hardware = keys::get_key_by_public_key(conn, &public)?;
    let mut matched = false;
    for (node_id, hardware_key_id, _) in leaves {
        if *hardware_key_id != hardware.id {
            continue;
        }
        matched = true;
        if shares.contains_key(node_id) {
            continue;
        }
        shares.insert(
            *node_id,
            key_tree::unwrap_leaf_share(conn, *node_id, &secret_arr)?,
        );
    }
    if !matched {
        return Err(usage(&format!(
            "key file is registered as hardware key {} but does not back any leaf in this tree",
            hardware.id
        )));
    }
    Ok(())
}

fn collect_leaves(node: &TreeNodeSummary, out: &mut Vec<(i64, i64, String)>) {
    if node.is_active {
        if let Some(hardware_key_id) = node.hardware_key_id {
            out.push((node.id, hardware_key_id, node.label.clone()));
        }
    }
    for child in &node.children {
        collect_leaves(child, out);
    }
}

fn build_spec_from_leaves(
    conn: &Connection,
    key_label: &str,
    root: Option<&str>,
    threshold: u8,
    leaf_args: &[String],
    generate_keys: bool,
    register: bool,
) -> Result<NodeSpec> {
    let leaves = parse_spec_leaves(leaf_args)?;
    if threshold == 0 || (threshold as usize) > leaves.len() {
        return Err(Error::InvalidQuorumThreshold);
    }
    let root_label = infer_root_label(
        &leaves.iter().map(|l| l.label.clone()).collect::<Vec<_>>(),
        root,
        key_label,
    )?;
    let mut resolved = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        let hw_id =
            resolve_or_register_pub(conn, &leaf.label, &leaf.pub_path, generate_keys, register)?;
        resolved.push((leaf.label.clone(), hw_id));
    }
    Ok(NodeSpec::flat_split(root_label, threshold, resolved))
}

fn infer_root_label(
    leaf_labels: &[String],
    explicit: Option<&str>,
    fallback: &str,
) -> Result<String> {
    if let Some(root) = explicit {
        if root.is_empty() {
            return Err(usage("--root must not be empty"));
        }
        return Ok(root.to_string());
    }
    let prefixes: Vec<Option<&str>> = leaf_labels
        .iter()
        .map(|label| label.rsplit_once('.').map(|(prefix, _)| prefix))
        .collect();
    if prefixes.iter().all(|prefix| prefix.is_some()) {
        let first = prefixes[0].expect("all prefixes are Some");
        if first.is_empty() || prefixes.iter().any(|prefix| prefix != &Some(first)) {
            return Err(usage(
                "dotted --leaf labels do not share a common parent; pass --root",
            ));
        }
        return Ok(first.to_string());
    }
    if prefixes.iter().all(|prefix| prefix.is_none()) {
        return Ok(fallback.to_string());
    }
    Err(usage(
        "mix of dotted and undotted --leaf labels; pass --root",
    ))
}

fn parse_bind_pairs(args: &[String]) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::with_capacity(args.len());
    for entry in args {
        let (a, b) = entry
            .split_once('=')
            .ok_or_else(|| usage("--bind must be in the form label=peer (e.g. M.S=M.A)"))?;
        if a.is_empty() || b.is_empty() || a == b {
            return Err(usage("--bind must name two different labels"));
        }
        pairs.push((a.to_string(), b.to_string()));
    }
    Ok(pairs)
}

fn resolve_or_register_pub(
    conn: &Connection,
    label: &str,
    pub_path: &Path,
    generate_keys: bool,
    register: bool,
) -> Result<i64> {
    if generate_keys {
        generate_leaf_keypair(pub_path)?;
    }
    let public_key = read_key_bytes(pub_path)?;
    if public_key.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    match keys::get_key_by_public_key(conn, &public_key) {
        Ok(hardware) => {
            if register {
                errln!("Using existing hardware key {} for {label}", hardware.id);
            }
            Ok(hardware.id)
        }
        Err(_) if register => {
            let id = keys::register_key(conn, label, keys::KeyType::Encryption, &public_key)?;
            errln!("Registered {label} as hardware key {id}");
            Ok(id)
        }
        Err(err) => Err(err),
    }
}

fn secret_for_named_leaf(
    conn: &Connection,
    key_id: i64,
    label: &str,
    share_file: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
    let idx = tree.index_by_label(label)?;
    if !tree.nodes[idx].is_active || tree.nodes[idx].hardware_key_id.is_none() {
        return Err(Error::NodeNotFound);
    }
    let path = Path::new(share_file);
    let raw = read_key_bytes(path)?;
    if raw.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked");
    let secret = match keys::get_key_by_public_key(conn, &arr) {
        Ok(_) => resolve_private_for_public(path, &arr)?,
        Err(_) => zeroize::Zeroizing::new(arr),
    };
    Ok(secret)
}

fn find_tree_node<'a>(node: &'a TreeNodeSummary, label: &str) -> Option<&'a TreeNodeSummary> {
    if node.label == label {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_tree_node(child, label))
}

fn write_live_spec(conn: &Connection, key_id: i64, path: &Path) -> Result<()> {
    let spec = key_tree::export_spec(conn, key_id)?;
    let rendered = serde_json::to_string_pretty(&spec).map_err(|_| Error::InvalidTreeSpec)?;
    env::write(path, format!("{rendered}\n").as_bytes())?;
    errln!("Wrote live spec to {}", path.display());
    Ok(())
}

pub struct SpecLeaf {
    label: String,
    pub_path: PathBuf,
}

fn parse_spec_leaves(args: &[String]) -> Result<Vec<SpecLeaf>> {
    let mut leaves = Vec::with_capacity(args.len());
    let mut seen = std::collections::HashSet::new();
    for entry in args {
        let (label, path) = entry.split_once('=').ok_or_else(|| {
            usage("--leaf must be in the form label=path (e.g. M.S=SoftwareDepartment.pub)")
        })?;
        if label.is_empty() || path.is_empty() {
            return Err(usage("--leaf must be in the form label=path"));
        }
        if !seen.insert(label.to_string()) {
            return Err(Error::DuplicateNodeLabel);
        }
        leaves.push(SpecLeaf {
            label: label.to_string(),
            pub_path: PathBuf::from(path),
        });
    }
    Ok(leaves)
}

fn generate_leaf_keypair(pub_path: &Path) -> Result<()> {
    if env::exists(pub_path) {
        return Err(usage(&format!(
            "refusing to overwrite existing key file {}",
            pub_path.display()
        )));
    }
    let key_path = pub_path.with_extension("key");
    if env::exists(&key_path) {
        return Err(usage(&format!(
            "refusing to overwrite existing key file {}",
            key_path.display()
        )));
    }
    if let Some(parent) = pub_path.parent() {
        if !parent.as_os_str().is_empty() && !env::exists(parent) {
            env::create_dir_all(parent)?;
        }
    }
    let (secret, public) = keys::generate_encryption_keypair();
    write_hex_file(pub_path, &public)?;
    write_hex_file(&key_path, secret.as_ref())?;
    errln!(
        "Generated {} and {}",
        pub_path.display(),
        key_path.display()
    );
    Ok(())
}

fn parse_tree_spec(conn: &Connection, path: &Path) -> Result<NodeSpec> {
    let contents = env::read_to_string(path)?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|_| Error::InvalidTreeSpec)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    resolve_public_key_files(conn, &mut value, base)?;
    serde_json::from_value(value).map_err(|_| Error::InvalidTreeSpec)
}

/// Leaves may name a registered key by `public_key_file` instead of
/// `hardware_key_id`. Paths are relative to the tree-spec file.
fn resolve_public_key_files(
    conn: &Connection,
    value: &mut serde_json::Value,
    base: &Path,
) -> Result<()> {
    let serde_json::Value::Object(map) = value else {
        return Ok(());
    };
    if let Some(file) = map.remove("public_key_file") {
        if map.contains_key("hardware_key_id") {
            return Err(Error::InvalidTreeSpec);
        }
        let rel = file.as_str().ok_or(Error::InvalidTreeSpec)?;
        let raw = read_key_bytes(&base.join(rel))?;
        if raw.len() != 32 {
            return Err(Error::InvalidPublicKey);
        }
        let hardware = keys::get_key_by_public_key(conn, &raw)?;
        map.insert("hardware_key_id".to_string(), hardware.id.into());
    }
    if let Some(serde_json::Value::Array(arr)) = map.get_mut("children") {
        for child in arr {
            resolve_public_key_files(conn, child, base)?;
        }
    }
    Ok(())
}

/// Exact file bytes for `--source`, after checking the text parses as a key.
fn read_key_file_payload(path: &Path) -> Result<Vec<u8>> {
    let contents = env::read(path)?;
    let text = std::str::from_utf8(&contents).map_err(|_| Error::InvalidPublicKey)?;
    keys::parse_key_text(text)?;
    if contents.is_empty() {
        return Err(Error::InvalidPublicKey);
    }
    Ok(contents)
}

fn write_reassembled_secret(secret: &[u8], output: Option<&Path>) -> Result<()> {
    match output {
        Some(path) => {
            env::write_new(path, secret)?;
            errln!("Wrote reassembled key to {}", path.display());
        }
        None => outln!("{}", hex::encode(secret)),
    }
    Ok(())
}

fn read_key_bytes(path: &Path) -> Result<Vec<u8>> {
    let contents = env::read_to_string(path)?;
    keys::parse_key_text(&contents)
}

pub(crate) fn read_key_array_32(path: &Path) -> Result<[u8; 32]> {
    read_key_bytes(path)?
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

fn read_hex_bytes(path: &Path) -> Result<Vec<u8>> {
    let contents = env::read_to_string(path)?;
    hex::decode(contents.trim()).map_err(|_| Error::InvalidPublicKey)
}

fn read_hex_array_64(path: &Path) -> Result<[u8; 64]> {
    read_hex_bytes(path)?
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

fn write_hex_file(path: &Path, bytes: &[u8]) -> Result<()> {
    env::write_new(path, hex::encode(bytes).as_bytes())
}

/// A CLI-argument-shape problem — a missing conditionally-required flag, a
/// malformed `--share-file` value — as opposed to a library, crypto, or DB
/// failure. The binary reports it and exits with code 2, clap's own
/// convention for usage errors.
fn usage(message: &str) -> Error {
    Error::Usage(message.to_string())
}

fn require<T>(value: Option<T>, flag: &str) -> Result<T> {
    value.ok_or_else(|| usage(&format!("--{flag} is required for this --state value")))
}

fn prompt_secret(prompt: &str) -> Result<String> {
    env::prompt_secret(prompt)
}

fn set_default_pin(
    conn: &Connection,
    resource_type: ResourceType,
    resource_id: i64,
    pin_value: &str,
) -> Result<()> {
    pin::set_pin(
        conn,
        resource_type,
        resource_id,
        pin_value,
        false,
        PIN_TTL_SECONDS,
    )
}

fn parse_positive_i64(value: &str) -> std::result::Result<i64, String> {
    let value = value
        .parse::<i64>()
        .map_err(|_| "must be a positive integer".to_owned())?;
    if value > 0 {
        Ok(value)
    } else {
        Err("must be greater than zero".to_owned())
    }
}

fn parse_expires_arg(value: &str) -> std::result::Result<String, String> {
    locked_files::parse_expires_utc(value).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests;
