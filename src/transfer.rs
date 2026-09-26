//! Key identity transfer between two devices that are open at once.
//!
//! A key identity is a stable 16-byte id plus its public keys. The dotted
//! label is only the current place in the hierarchy. Possession on this
//! device is separate: `active` means the slot secret is here, `ghost`
//! means the hierarchy row remains and the secret does not, and no row
//! means the identity is absent.
//!
//! COPY leaves the source active. MOVE records a ghost only after the
//! destination has committed and the source slot token is gone. The row
//! stays active until that deletion succeeds. The signed `KQTX` package
//! is not a sealed envelope and is not written into SQLite. A relay copy
//! is a sealed `KQPB` letter built in `device_relay`; this module still
//! only sees the package and the acknowledgement hash.
//! Authorization is a [`TransferAuth`] policy so a later countersignature
//! rule can refuse a transfer without a different package format.

use crate::db;
use crate::device::{self, Container};
use crate::envelope::{push_len_prefixed, take_array, take_len_prefixed, take_u32, take_u8};
use crate::error::{Error, Result};
use crate::keys::{self, KeyType};
use crate::private_bridge::parent_node_label;
use crate::signing;
use crate::storage::{NativeStorage, Storage};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"KQTX";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"KQ-TRANSFER-v1";
const KIND_SECRET: u8 = 1;
const KIND_HINT: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferOp {
    Copy,
    Move,
}

impl TransferOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Move => "move",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Copy => 1,
            Self::Move => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Copy),
            2 => Ok(Self::Move),
            _ => Err(Error::IntegrityCheckFailed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescendantMode {
    KeyOnly,
    DirectChildren,
    AllDescendants,
}

impl DescendantMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyOnly => "key-only",
            Self::DirectChildren => "direct-children",
            Self::AllDescendants => "all-descendants",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "key-only" | "key_only" => Ok(Self::KeyOnly),
            "direct-children" | "direct_children" => Ok(Self::DirectChildren),
            "all-descendants" | "all_descendants" => Ok(Self::AllDescendants),
            _ => Err(Error::TransferDenied),
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::KeyOnly => 1,
            Self::DirectChildren => 2,
            Self::AllDescendants => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::KeyOnly),
            2 => Ok(Self::DirectChildren),
            3 => Ok(Self::AllDescendants),
            _ => Err(Error::IntegrityCheckFailed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Possession {
    Active,
    Ghost,
}

impl Possession {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ghost => "ghost",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "ghost" => Ok(Self::Ghost),
            _ => Err(Error::IntegrityCheckFailed),
        }
    }
}

/// What an active identity is allowed to transfer. Possession is not itself
/// permission. `countersign_required` refuses the operation so a later
/// approval step can be added without a new package format.
#[derive(Clone, Debug)]
pub struct TransferAuth {
    pub self_copy: bool,
    pub self_move: bool,
    pub descendant_copy: bool,
    pub descendant_move: bool,
    pub countersign_required: bool,
    pub allow_ancestor_import: bool,
}

impl Default for TransferAuth {
    fn default() -> Self {
        Self {
            self_copy: true,
            self_move: true,
            descendant_copy: true,
            descendant_move: true,
            countersign_required: false,
            allow_ancestor_import: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct IdentityInfo {
    pub id: [u8; 16],
    pub label: String,
    pub parent_label: Option<String>,
    pub state: Possession,
    pub generation: i64,
    pub enc_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    Finalized,
    Aborted,
    AlreadyComplete,
    NeedsAdmin,
}

pub struct PreparedTransfer {
    pub id: [u8; 16],
    pub operation: TransferOp,
    pub descendants: DescendantMode,
    pub root_label: String,
    pub actor: String,
    secret_labels: Vec<String>,
    hint_labels: Vec<String>,
    package: Zeroizing<Vec<u8>>,
}

impl PreparedTransfer {
    pub fn package(&self) -> &[u8] {
        &self.package
    }

    pub fn secret_labels(&self) -> &[String] {
        &self.secret_labels
    }

    pub fn hint_labels(&self) -> &[String] {
        &self.hint_labels
    }
}

struct BundleEntry {
    identity_id: [u8; 16],
    generation: i64,
    label: String,
    parent_label: Option<String>,
    enc_public: [u8; 32],
    sign_public: [u8; 32],
    enc_fingerprint: String,
    sign_fingerprint: String,
    enc_secret: Option<Zeroizing<[u8; 32]>>,
    sign_secret: Option<Zeroizing<[u8; 32]>>,
}

struct Bundle {
    id: [u8; 16],
    operation: TransferOp,
    descendants: DescendantMode,
    source_device_id: [u8; 16],
    destination_device_id: [u8; 16],
    actor: String,
    root_label: String,
    entries: Vec<BundleEntry>,
}

/// Record a provisioned slot as an active identity. The id is random and
/// stays with the key when it is copied.
pub fn enroll(
    conn: &Connection,
    container: &mut Container,
    label: &str,
    passphrase: &str,
) -> Result<[u8; 16]> {
    enroll_in(&mut NativeStorage, conn, container, label, passphrase)
}

/// [`enroll`] against any [`Storage`].
pub fn enroll_in(
    storage: &mut dyn Storage,
    conn: &Connection,
    container: &mut Container,
    label: &str,
    passphrase: &str,
) -> Result<[u8; 16]> {
    device::validate_slot_label(label)?;
    if container.slot(label).is_none() {
        device::provision_in(storage, container, label, passphrase)?;
    }
    let secrets = device::open_slot_in(storage, container, label, passphrase)?;
    if let Some(existing) = identity_by_label(conn, label)? {
        if existing.enc_public != secrets.encryption_public
            || existing.sign_public != secrets.signing_public
        {
            return Err(Error::IdentityConflict);
        }
        return Ok(existing.id);
    }
    let id = random_id();
    ensure_hardware(conn, label, KeyType::Encryption, &secrets.encryption_public)?;
    ensure_hardware(conn, label, KeyType::Signing, &secrets.signing_public)?;
    let parent = parent_node_label(label).map(str::to_string);
    db::with_immediate_transaction(conn, || {
        insert_identity(
            conn,
            &id,
            label,
            parent.as_deref(),
            &secrets.encryption_public,
            &secrets.signing_public,
            Possession::Active,
            1,
        )
    })?;
    Ok(id)
}

pub fn possession(conn: &Connection, label: &str) -> Result<Option<Possession>> {
    let state: Option<String> = conn
        .query_row(
            "SELECT p.state FROM key_possession p
             JOIN key_identities i ON i.id = p.identity_id
             WHERE i.label = ?1",
            params![label],
            |row| row.get(0),
        )
        .optional()?;
    state.map(|value| Possession::parse(&value)).transpose()
}

pub fn identity(conn: &Connection, label: &str) -> Result<Option<IdentityInfo>> {
    let row = identity_by_label(conn, label)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let state = possession(conn, label)?.ok_or(Error::IntegrityCheckFailed)?;
    let generation: i64 = conn.query_row(
        "SELECT generation FROM key_possession WHERE identity_id = ?1",
        params![row.id.to_vec()],
        |r| r.get(0),
    )?;
    Ok(Some(IdentityInfo {
        id: row.id,
        label: row.label,
        parent_label: row.parent_label,
        state,
        generation,
        enc_fingerprint: row.enc_fingerprint,
    }))
}

/// Operational list hides ghosts. `include_ghosts` is the administrative view.
pub fn list_identities(conn: &Connection, include_ghosts: bool) -> Result<Vec<IdentityInfo>> {
    let sql = "SELECT i.id, i.label, i.parent_label, p.state, p.generation, i.enc_fingerprint
               FROM key_identities i
               JOIN key_possession p ON p.identity_id = i.id
               ORDER BY i.label";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let id_bytes: Vec<u8> = row.get(0)?;
        let state: String = row.get(3)?;
        Ok((
            id_bytes,
            row.get(1)?,
            row.get(2)?,
            state,
            row.get(4)?,
            row.get(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id_bytes, label, parent_label, state, generation, enc_fingerprint) = row?;
        let state = Possession::parse(&state)?;
        if state == Possession::Ghost && !include_ghosts {
            continue;
        }
        let id = id_array(&id_bytes)?;
        out.push(IdentityInfo {
            id,
            label,
            parent_label,
            state,
            generation,
            enc_fingerprint,
        });
    }
    Ok(out)
}

/// Sign with an active slot. A ghost has no secret and cannot sign.
pub fn sign_active(
    conn: &Connection,
    container: &Container,
    label: &str,
    passphrase: &str,
    message: &[u8],
) -> Result<[u8; 64]> {
    sign_active_in(&NativeStorage, conn, container, label, passphrase, message)
}

/// [`sign_active`] against any [`Storage`].
pub fn sign_active_in(
    storage: &dyn Storage,
    conn: &Connection,
    container: &Container,
    label: &str,
    passphrase: &str,
    message: &[u8],
) -> Result<[u8; 64]> {
    match possession(conn, label)? {
        Some(Possession::Active) => {}
        Some(Possession::Ghost) => return Err(Error::GhostDenied),
        None => return Err(Error::TransferDenied),
    }
    let secrets = device::open_slot_in(storage, container, label, passphrase)?;
    Ok(device::sign_message(&secrets, message))
}

pub fn export_secret_labels(
    conn: &Connection,
    label: &str,
    descendants: DescendantMode,
) -> Result<Vec<String>> {
    let (secrets, _) = select_export(conn, label, descendants)?;
    Ok(secrets)
}

pub struct TransferRequest<'a> {
    pub source_conn: &'a Connection,
    pub source: &'a mut Container,
    /// Where the source container's slot tokens live. Native callers pass
    /// `&mut NativeStorage`; the browser lab passes its in-memory store.
    pub source_storage: &'a mut dyn Storage,
    pub dest_conn: &'a Connection,
    pub dest: &'a mut Container,
    /// [`Storage`] for the destination container, same reasoning as
    /// `source_storage`. A second handle, even against the same in-memory
    /// backing, mirrors the physical requirement that a transfer moves a
    /// token between two distinct containers.
    pub dest_storage: &'a mut dyn Storage,
    pub actor: &'a str,
    pub label: &'a str,
    pub operation: TransferOp,
    pub descendants: DescendantMode,
    pub passphrases: &'a HashMap<String, String>,
    pub auth: &'a TransferAuth,
}

pub fn transfer(request: TransferRequest<'_>) -> Result<[u8; 16]> {
    let prepared = prepare_in(
        request.source_storage,
        request.source_conn,
        request.source,
        request.dest.device_id(),
        request.actor,
        request.label,
        request.operation,
        request.descendants,
        request.passphrases,
        request.auth,
    )?;
    let committed = (|| -> Result<()> {
        stage_destination(
            request.dest_conn,
            request.dest,
            request.source,
            prepared.package(),
            request.auth.allow_ancestor_import,
        )?;
        write_destination_slots_in(
            request.dest_storage,
            request.dest_conn,
            request.dest,
            request.source,
            prepared.package(),
            request.passphrases,
            None,
        )?;
        commit_destination_rows(
            request.dest_conn,
            request.dest,
            request.source,
            prepared.package(),
            request.auth.allow_ancestor_import,
        )?;
        acknowledge(request.dest_conn, &prepared.id)?;
        finalize_source_in(
            request.source_storage,
            request.source_conn,
            request.source,
            request.dest_conn,
            &prepared.id,
        )?;
        Ok(())
    })();
    if let Err(err) = committed {
        if !destination_committed(request.dest_conn, &prepared.id)? {
            let _ = abort_transfer_in(
                request.dest_storage,
                request.source_conn,
                request.dest_conn,
                request.dest,
                &prepared.id,
            );
        }
        return Err(err);
    }
    Ok(prepared.id)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare(
    conn: &Connection,
    source: &Container,
    destination_device_id: &[u8; 16],
    actor: &str,
    label: &str,
    operation: TransferOp,
    descendants: DescendantMode,
    passphrases: &HashMap<String, String>,
    auth: &TransferAuth,
) -> Result<PreparedTransfer> {
    prepare_in(
        &NativeStorage,
        conn,
        source,
        destination_device_id,
        actor,
        label,
        operation,
        descendants,
        passphrases,
        auth,
    )
}

/// [`prepare`] against any [`Storage`].
#[allow(clippy::too_many_arguments)]
pub fn prepare_in(
    storage: &dyn Storage,
    conn: &Connection,
    source: &Container,
    destination_device_id: &[u8; 16],
    actor: &str,
    label: &str,
    operation: TransferOp,
    descendants: DescendantMode,
    passphrases: &HashMap<String, String>,
    auth: &TransferAuth,
) -> Result<PreparedTransfer> {
    let tx_id = random_id();
    let denied = |reason: &str| -> Result<PreparedTransfer> {
        let key_id = identity_by_label(conn, label)
            .ok()
            .flatten()
            .map(|row| row.id)
            .unwrap_or([0u8; 16]);
        let _ = write_audit(
            conn,
            &tx_id,
            operation,
            source.device_id(),
            destination_device_id,
            &key_id,
            label,
            descendants,
            "denied",
            &format!("reason={reason}"),
        );
        Err(if reason == "ghost" {
            Error::GhostDenied
        } else {
            Error::TransferDenied
        })
    };
    if device::validate_slot_label(actor).is_err() || device::validate_slot_label(label).is_err() {
        return denied("label");
    }
    if let Err(err) = authorize(conn, actor, label, operation, descendants, auth) {
        return denied(if matches!(err, Error::GhostDenied) {
            "ghost"
        } else {
            "unauthorized"
        });
    }
    let (secret_labels, hint_labels) = match select_export(conn, label, descendants) {
        Ok(pair) => pair,
        Err(err) => {
            return denied(if matches!(err, Error::GhostDenied) {
                "ghost"
            } else {
                "export"
            });
        }
    };
    let mut entries = Vec::new();
    for secret_label in &secret_labels {
        let row = identity_by_label(conn, secret_label)?.ok_or(Error::TransferDenied)?;
        let generation = generation_of(conn, &row.id)?;
        let passphrase = passphrases
            .get(secret_label)
            .ok_or(Error::InvalidPassword)?;
        let secrets = device::open_slot_in(storage, source, secret_label, passphrase)?;
        if secrets.encryption_public != row.enc_public || secrets.signing_public != row.sign_public
        {
            return Err(Error::IdentityConflict);
        }
        entries.push(BundleEntry {
            identity_id: row.id,
            generation,
            label: secret_label.clone(),
            parent_label: row.parent_label,
            enc_public: row.enc_public,
            sign_public: row.sign_public,
            enc_fingerprint: row.enc_fingerprint,
            sign_fingerprint: row.sign_fingerprint,
            enc_secret: Some(secrets.encryption_secret),
            sign_secret: Some(secrets.signing_secret),
        });
    }
    for hint_label in &hint_labels {
        let Some(row) = identity_by_label(conn, hint_label)? else {
            continue;
        };
        let generation = generation_of(conn, &row.id)?;
        entries.push(BundleEntry {
            identity_id: row.id,
            generation,
            label: hint_label.clone(),
            parent_label: row.parent_label,
            enc_public: row.enc_public,
            sign_public: row.sign_public,
            enc_fingerprint: row.enc_fingerprint,
            sign_fingerprint: row.sign_fingerprint,
            enc_secret: None,
            sign_secret: None,
        });
    }
    let bundle = Bundle {
        id: tx_id,
        operation,
        descendants,
        source_device_id: *source.device_id(),
        destination_device_id: *destination_device_id,
        actor: actor.to_string(),
        root_label: label.to_string(),
        entries,
    };
    let package = Zeroizing::new(encode_bundle(storage, source, &bundle)?);
    let hash = sha256(&package);
    let detail = format_detail("prepared", &secret_labels, &hint_labels, &[]);
    let root = identity_by_label(conn, label)?.ok_or(Error::TransferDenied)?;
    db::with_immediate_transaction(conn, || {
        insert_tx(
            conn,
            &tx_id,
            operation,
            "source",
            "prepared",
            destination_device_id,
            label,
            descendants,
            &hash,
            &detail,
        )?;
        write_audit(
            conn,
            &tx_id,
            operation,
            source.device_id(),
            destination_device_id,
            &root.id,
            label,
            descendants,
            "prepared",
            &detail,
        )
    })?;
    Ok(PreparedTransfer {
        id: tx_id,
        operation,
        descendants,
        root_label: label.to_string(),
        actor: actor.to_string(),
        secret_labels,
        hint_labels,
        package,
    })
}

pub fn stage_destination(
    dest_conn: &Connection,
    dest: &Container,
    source: &Container,
    package: &[u8],
    allow_ancestor_import: bool,
) -> Result<()> {
    let bundle = open_bundle(package, source, dest)?;
    if tx_exists(dest_conn, &bundle.id)? {
        audit_bundle(dest_conn, &bundle, "denied", "reason=replay")?;
        return Err(Error::TransferReplay);
    }
    if let Err(err) = receiver_accepts(dest_conn, &bundle, allow_ancestor_import) {
        let reason = match err {
            Error::IdentityConflict => "reason=identity_conflict",
            Error::TransferReplay => "reason=replay",
            _ => "reason=ancestry",
        };
        audit_bundle(dest_conn, &bundle, "denied", reason)?;
        return Err(err);
    }
    let hash = sha256(package);
    let (included, excluded) = bundle_labels(&bundle);
    let detail = format_detail("transferred", &included, &excluded, &[]);
    db::with_immediate_transaction(dest_conn, || {
        insert_tx(
            dest_conn,
            &bundle.id,
            bundle.operation,
            "destination",
            "transferred",
            &bundle.source_device_id,
            &bundle.root_label,
            bundle.descendants,
            &hash,
            &detail,
        )?;
        audit_bundle(dest_conn, &bundle, "transferred", &detail)
    })?;
    Ok(())
}

/// Install slot tokens. `limit` stops after that many new slots so a test
/// can simulate a disconnect during the write. State stays `writing`.
pub fn write_destination_slots(
    dest_conn: &Connection,
    dest: &mut Container,
    source: &Container,
    package: &[u8],
    passphrases: &HashMap<String, String>,
    limit: Option<usize>,
) -> Result<()> {
    write_destination_slots_in(
        &mut NativeStorage,
        dest_conn,
        dest,
        source,
        package,
        passphrases,
        limit,
    )
}

/// [`write_destination_slots`] against any [`Storage`].
pub fn write_destination_slots_in(
    storage: &mut dyn Storage,
    dest_conn: &Connection,
    dest: &mut Container,
    source: &Container,
    package: &[u8],
    passphrases: &HashMap<String, String>,
    limit: Option<usize>,
) -> Result<()> {
    let bundle = open_bundle(package, source, dest)?;
    let state = tx_state(dest_conn, &bundle.id)?.ok_or(Error::TransferIncomplete)?;
    if !matches!(state.as_str(), "transferred" | "writing") {
        return Err(Error::TransferReplay);
    }
    set_state(dest_conn, &bundle.id, "writing")?;
    let mut installed = detail_list(&tx_detail(dest_conn, &bundle.id)?, "installed");
    let mut written = 0usize;
    for entry in bundle
        .entries
        .iter()
        .filter(|entry| entry.enc_secret.is_some())
    {
        if limit.is_some_and(|limit| written >= limit) {
            break;
        }
        if dest.slot(&entry.label).is_some() {
            let passphrase = passphrases
                .get(&entry.label)
                .ok_or(Error::InvalidPassword)?;
            let opened = device::open_slot_in(storage, dest, &entry.label, passphrase)?;
            if opened.encryption_public != entry.enc_public {
                return Err(Error::IdentityConflict);
            }
            continue;
        }
        let passphrase = passphrases
            .get(&entry.label)
            .ok_or(Error::InvalidPassword)?;
        if !installed.iter().any(|label| label == &entry.label) {
            installed.push(entry.label.clone());
            let detail =
                replace_detail_list(&tx_detail(dest_conn, &bundle.id)?, "installed", &installed);
            set_detail(dest_conn, &bundle.id, &detail)?;
        }
        let enc = entry
            .enc_secret
            .as_ref()
            .ok_or(Error::IntegrityCheckFailed)?;
        let sign = entry
            .sign_secret
            .as_ref()
            .ok_or(Error::IntegrityCheckFailed)?;
        device::install_slot_in(storage, dest, &entry.label, passphrase, enc, sign)?;
        written += 1;
    }
    Ok(())
}

pub fn commit_destination_rows(
    dest_conn: &Connection,
    dest: &Container,
    source: &Container,
    package: &[u8],
    allow_ancestor_import: bool,
) -> Result<()> {
    let bundle = open_bundle(package, source, dest)?;
    let state = tx_state(dest_conn, &bundle.id)?.ok_or(Error::TransferIncomplete)?;
    if state != "writing" && state != "destination_committed" {
        return Err(Error::TransferIncomplete);
    }
    if state == "destination_committed" {
        return Ok(());
    }
    for entry in bundle
        .entries
        .iter()
        .filter(|entry| entry.enc_secret.is_some())
    {
        if dest.slot(&entry.label).is_none() {
            return Err(Error::TransferIncomplete);
        }
    }
    let active_before = active_labels(dest_conn)?;
    db::with_immediate_transaction(dest_conn, || {
        receiver_accepts_with(dest_conn, &bundle, allow_ancestor_import, &active_before)?;
        for entry in &bundle.entries {
            apply_entry(dest_conn, dest, &bundle, entry)?;
        }
        set_state(dest_conn, &bundle.id, "destination_committed")?;
        audit_bundle(
            dest_conn,
            &bundle,
            "destination_committed",
            "reason=committed",
        )
    })?;
    Ok(())
}

pub fn acknowledge(dest_conn: &Connection, tx_id: &[u8; 16]) -> Result<()> {
    let state = tx_state(dest_conn, tx_id)?.ok_or(Error::TransferIncomplete)?;
    if state == "acknowledged" || state == "completed" {
        return Ok(());
    }
    if state != "destination_committed" {
        return Err(Error::TransferIncomplete);
    }
    set_state(dest_conn, tx_id, "acknowledged")
}

/// Install a package whose source device is known by id and verify key.
/// The source container's secrets are not required. A destination that
/// already committed this transaction is acknowledged again so the caller
/// can resend the sealed acknowledgement.
pub fn accept_package(
    dest_conn: &Connection,
    dest: &mut Container,
    source_device_id: &[u8; 16],
    source_verify_key: &[u8; 32],
    package: &[u8],
    passphrases: &HashMap<String, String>,
    allow_ancestor_import: bool,
) -> Result<[u8; 16]> {
    let header = authenticated_package(package)?;
    if header.source_device_id != *source_device_id || header.verify_key != *source_verify_key {
        return Err(Error::SignatureVerificationFailed);
    }
    if header.destination_device_id != *dest.device_id() {
        return Err(Error::SignatureVerificationFailed);
    }
    if let Some(state) = tx_state(dest_conn, &header.id)? {
        return resume_accept(
            dest_conn,
            dest,
            source_device_id,
            source_verify_key,
            package,
            passphrases,
            allow_ancestor_import,
            &header.id,
            &state,
        );
    }
    let source = device::verification_container(*source_device_id, *source_verify_key);
    stage_destination(dest_conn, dest, &source, package, allow_ancestor_import)?;
    write_destination_slots(dest_conn, dest, &source, package, passphrases, None)?;
    commit_destination_rows(dest_conn, dest, &source, package, allow_ancestor_import)?;
    acknowledge(dest_conn, &header.id)?;
    Ok(header.id)
}

#[allow(clippy::too_many_arguments)]
fn resume_accept(
    dest_conn: &Connection,
    dest: &mut Container,
    source_device_id: &[u8; 16],
    source_verify_key: &[u8; 32],
    package: &[u8],
    passphrases: &HashMap<String, String>,
    allow_ancestor_import: bool,
    tx_id: &[u8; 16],
    state: &str,
) -> Result<[u8; 16]> {
    if matches!(
        state,
        "acknowledged" | "completed" | "source_finalized" | "destination_committed"
    ) {
        if state == "destination_committed" {
            acknowledge(dest_conn, tx_id)?;
        }
        return Ok(*tx_id);
    }
    if !matches!(state, "transferred" | "writing") {
        return Err(Error::TransferReplay);
    }
    let source = device::verification_container(*source_device_id, *source_verify_key);
    write_destination_slots(dest_conn, dest, &source, package, passphrases, None)?;
    commit_destination_rows(dest_conn, dest, &source, package, allow_ancestor_import)?;
    acknowledge(dest_conn, tx_id)?;
    Ok(*tx_id)
}

/// Slot labels whose secrets the destination must wrap. Used to prompt
/// before [`accept_package`].
pub fn package_secret_labels(
    package: &[u8],
    source_device_id: &[u8; 16],
    source_verify_key: &[u8; 32],
    destination: &Container,
) -> Result<Vec<String>> {
    let header = authenticated_package(package)?;
    if header.source_device_id != *source_device_id || header.verify_key != *source_verify_key {
        return Err(Error::SignatureVerificationFailed);
    }
    let source = device::verification_container(*source_device_id, *source_verify_key);
    let bundle = open_bundle(package, &source, destination)?;
    Ok(bundle
        .entries
        .iter()
        .filter(|entry| entry.enc_secret.is_some())
        .map(|entry| entry.label.clone())
        .collect())
}

pub fn finalize_source(
    source_conn: &Connection,
    source: &mut Container,
    dest_conn: &Connection,
    tx_id: &[u8; 16],
) -> Result<()> {
    finalize_source_in(&mut NativeStorage, source_conn, source, dest_conn, tx_id)
}

/// [`finalize_source`] against any [`Storage`].
pub fn finalize_source_in(
    storage: &mut dyn Storage,
    source_conn: &Connection,
    source: &mut Container,
    dest_conn: &Connection,
    tx_id: &[u8; 16],
) -> Result<()> {
    let source_state = tx_state(source_conn, tx_id)?.ok_or(Error::TransferIncomplete)?;
    if source_state == "completed" {
        return Ok(());
    }
    if source_state != "source_finalized" {
        retire_source_material(storage, source_conn, source, dest_conn, tx_id)?;
    } else {
        // An older finalize committed GHOST and then deleted the token.
        // Recovery still removes a leftover slot before calling the move done.
        scrub_moved_slots(storage, source_conn, source, tx_id)?;
    }
    let _ = set_state(dest_conn, tx_id, "completed");
    set_state(source_conn, tx_id, "completed")
}

/// Finish a source that is still `prepared` after a destination
/// acknowledgement. The acknowledgement hash has to match the hash stored
/// at prepare. MOVE deletes the slot token before the ghost row is written.
/// The destination database is not required.
pub fn has_transfer(conn: &Connection, tx_id: &[u8; 16]) -> Result<bool> {
    tx_exists(conn, tx_id)
}

pub fn finalize_after_ack(
    source_conn: &Connection,
    source: &mut Container,
    tx_id: &[u8; 16],
    ack_hash: &[u8; 32],
) -> Result<()> {
    let source_state = tx_state(source_conn, tx_id)?.ok_or(Error::TransferIncomplete)?;
    if source_state == "completed" {
        return Ok(());
    }
    if source_state == "source_finalized" {
        scrub_moved_slots(&mut NativeStorage, source_conn, source, tx_id)?;
        return set_state(source_conn, tx_id, "completed");
    }
    if source_state != "prepared" {
        return Err(Error::TransferIncomplete);
    }
    let source_hash = tx_hash(source_conn, tx_id)?;
    if source_hash != *ack_hash {
        set_state(source_conn, tx_id, "needs_admin")?;
        return Err(Error::TransferIncomplete);
    }
    let operation = tx_operation(source_conn, tx_id)?;
    let detail = tx_detail(source_conn, tx_id)?;
    let secret_labels = detail_list(&detail, "included");
    let root = tx_root(source_conn, tx_id)?;
    let descendants = tx_mode(source_conn, tx_id)?;
    let peer = tx_peer(source_conn, tx_id)?;
    scrub_moved_slots(&mut NativeStorage, source_conn, source, tx_id)?;
    db::with_immediate_transaction(source_conn, || {
        for label in &secret_labels {
            let row = identity_by_label(source_conn, label)?.ok_or(Error::TransferDenied)?;
            let generation = generation_of(source_conn, &row.id)?;
            let target = if operation == TransferOp::Move {
                generation.saturating_add(1)
            } else {
                generation
            };
            if operation == TransferOp::Move {
                set_possession(source_conn, &row.id, Possession::Ghost, target)?;
                upsert_provenance(source_conn, &row.id, source.device_id(), Possession::Ghost)?;
            } else {
                upsert_provenance(source_conn, &row.id, source.device_id(), Possession::Active)?;
            }
            upsert_provenance(source_conn, &row.id, &peer, Possession::Active)?;
        }
        set_state(source_conn, tx_id, "source_finalized")?;
        write_audit(
            source_conn,
            tx_id,
            operation,
            source.device_id(),
            &peer,
            &identity_by_label(source_conn, &root)?
                .map(|row| row.id)
                .unwrap_or([0u8; 16]),
            &root,
            descendants,
            "source_finalized",
            &format_detail(
                if operation == TransferOp::Move {
                    "ghost"
                } else {
                    "copied"
                },
                &secret_labels,
                &detail_list(&detail, "excluded"),
                &[],
            ),
        )?;
        set_state(source_conn, tx_id, "completed")
    })
}

/// Delete moved slot tokens, then commit `GHOST`. The row stays `ACTIVE`
/// until every included token is gone, so a crash cannot report a ghost
/// that `keyquorum-device` can still open.
fn retire_source_material(
    storage: &mut dyn Storage,
    source_conn: &Connection,
    source: &mut Container,
    dest_conn: &Connection,
    tx_id: &[u8; 16],
) -> Result<()> {
    let dest_state = tx_state(dest_conn, tx_id)?.ok_or(Error::TransferIncomplete)?;
    if !matches!(
        dest_state.as_str(),
        "destination_committed" | "acknowledged" | "completed" | "source_finalized"
    ) {
        return Err(Error::TransferIncomplete);
    }
    let source_hash = tx_hash(source_conn, tx_id)?;
    let dest_hash = tx_hash(dest_conn, tx_id)?;
    if source_hash != dest_hash {
        set_state(source_conn, tx_id, "needs_admin")?;
        set_state(dest_conn, tx_id, "needs_admin")?;
        return Err(Error::TransferIncomplete);
    }
    let operation = tx_operation(source_conn, tx_id)?;
    let detail = tx_detail(source_conn, tx_id)?;
    let secret_labels = detail_list(&detail, "included");
    let root = tx_root(source_conn, tx_id)?;
    let descendants = tx_mode(source_conn, tx_id)?;
    let peer = tx_peer(source_conn, tx_id)?;
    scrub_moved_slots(storage, source_conn, source, tx_id)?;
    db::with_immediate_transaction(source_conn, || {
        for label in &secret_labels {
            let row = identity_by_label(source_conn, label)?.ok_or(Error::TransferDenied)?;
            let generation = generation_of(source_conn, &row.id)?;
            let target = if operation == TransferOp::Move {
                generation.saturating_add(1)
            } else {
                generation
            };
            if operation == TransferOp::Move {
                set_possession(source_conn, &row.id, Possession::Ghost, target)?;
                upsert_provenance(source_conn, &row.id, source.device_id(), Possession::Ghost)?;
            } else {
                upsert_provenance(source_conn, &row.id, source.device_id(), Possession::Active)?;
            }
            upsert_provenance(source_conn, &row.id, &peer, Possession::Active)?;
            let _ = set_generation_at_least(dest_conn, &row.id, target);
            let _ = upsert_provenance(
                dest_conn,
                &row.id,
                source.device_id(),
                match operation {
                    TransferOp::Move => Possession::Ghost,
                    TransferOp::Copy => Possession::Active,
                },
            );
            let _ = upsert_provenance(dest_conn, &row.id, &peer, Possession::Active);
        }
        set_state(source_conn, tx_id, "source_finalized")?;
        write_audit(
            source_conn,
            tx_id,
            operation,
            source.device_id(),
            &peer,
            &identity_by_label(source_conn, &root)?
                .map(|row| row.id)
                .unwrap_or([0u8; 16]),
            &root,
            descendants,
            "source_finalized",
            &format_detail(
                if operation == TransferOp::Move {
                    "ghost"
                } else {
                    "copied"
                },
                &secret_labels,
                &detail_list(&detail, "excluded"),
                &[],
            ),
        )
    })
}

/// Drop moved slot tokens while the source row is still active. The ghost
/// commit runs only after this returns. A crash in between leaves an active
/// row whose token is already gone; the next finalize records the ghost.
fn scrub_moved_slots(
    storage: &mut dyn Storage,
    source_conn: &Connection,
    source: &mut Container,
    tx_id: &[u8; 16],
) -> Result<()> {
    if tx_operation(source_conn, tx_id)? != TransferOp::Move {
        return Ok(());
    }
    for label in detail_list(&tx_detail(source_conn, tx_id)?, "included") {
        if source.slot(&label).is_some() {
            device::remove_slot_in(storage, source, &label)?;
        }
    }
    Ok(())
}

pub fn abort_transfer(
    source_conn: &Connection,
    dest_conn: &Connection,
    dest: &mut Container,
    tx_id: &[u8; 16],
) -> Result<()> {
    abort_transfer_in(&mut NativeStorage, source_conn, dest_conn, dest, tx_id)
}

/// [`abort_transfer`] against any [`Storage`].
pub fn abort_transfer_in(
    storage: &mut dyn Storage,
    source_conn: &Connection,
    dest_conn: &Connection,
    dest: &mut Container,
    tx_id: &[u8; 16],
) -> Result<()> {
    if destination_committed(dest_conn, tx_id)? {
        return Err(Error::TransferIncomplete);
    }
    if let Ok(detail) = tx_detail(dest_conn, tx_id) {
        for label in detail_list(&detail, "installed") {
            if dest.slot(&label).is_some() {
                device::remove_slot_in(storage, dest, &label)?;
            }
        }
        set_state(dest_conn, tx_id, "aborted")?;
    }
    if tx_exists(source_conn, tx_id)? {
        let state = tx_state(source_conn, tx_id)?;
        if matches!(state.as_deref(), Some("prepared") | Some("aborted")) {
            set_state(source_conn, tx_id, "aborted")?;
        }
    }
    Ok(())
}

pub fn recover_pair(
    source_conn: &Connection,
    source: &mut Container,
    dest_conn: &Connection,
    dest: &mut Container,
    tx_id: &[u8; 16],
) -> Result<Recovery> {
    let source_state = tx_state(source_conn, tx_id)?.ok_or(Error::TransferIncomplete)?;
    let dest_state = tx_state(dest_conn, tx_id)?;
    if let Some(dest_state) = dest_state.as_deref() {
        if tx_exists(dest_conn, tx_id)?
            && tx_hash(source_conn, tx_id)? != tx_hash(dest_conn, tx_id)?
        {
            set_state(source_conn, tx_id, "needs_admin")?;
            set_state(dest_conn, tx_id, "needs_admin")?;
            return Ok(Recovery::NeedsAdmin);
        }
        let _ = dest_state;
    }
    if source_state == "needs_admin" {
        return Ok(Recovery::NeedsAdmin);
    }
    if source_state == "completed" {
        if dest_state.is_some() {
            let _ = set_state(dest_conn, tx_id, "completed");
        }
        return Ok(Recovery::AlreadyComplete);
    }
    if source_state == "source_finalized" {
        finalize_source(source_conn, source, dest_conn, tx_id)?;
        return Ok(Recovery::AlreadyComplete);
    }
    let dest_ready = matches!(
        dest_state.as_deref(),
        Some("destination_committed")
            | Some("acknowledged")
            | Some("completed")
            | Some("source_finalized")
    );
    if dest_ready {
        finalize_source(source_conn, source, dest_conn, tx_id)?;
        return Ok(Recovery::Finalized);
    }
    abort_transfer(source_conn, dest_conn, dest, tx_id)?;
    Ok(Recovery::Aborted)
}

fn destination_committed(conn: &Connection, tx_id: &[u8; 16]) -> Result<bool> {
    let state = tx_state(conn, tx_id)?;
    Ok(matches!(
        state.as_deref(),
        Some("destination_committed")
            | Some("acknowledged")
            | Some("source_finalized")
            | Some("completed")
    ))
}

fn authorize(
    conn: &Connection,
    actor: &str,
    label: &str,
    operation: TransferOp,
    descendants: DescendantMode,
    auth: &TransferAuth,
) -> Result<()> {
    if auth.countersign_required {
        return Err(Error::TransferDenied);
    }
    match possession(conn, actor)? {
        Some(Possession::Active) => {}
        Some(Possession::Ghost) => return Err(Error::GhostDenied),
        None => return Err(Error::TransferDenied),
    }
    let self_ok = match operation {
        TransferOp::Copy => auth.self_copy,
        TransferOp::Move => auth.self_move,
    };
    let descendant_ok = match operation {
        TransferOp::Copy => auth.descendant_copy,
        TransferOp::Move => auth.descendant_move,
    };
    let allowed = if actor == label {
        self_ok && (descendants == DescendantMode::KeyOnly || descendant_ok)
    } else if is_strict_descendant(label, actor) {
        descendant_ok
    } else {
        false
    };
    if !allowed {
        return Err(Error::TransferDenied);
    }
    Ok(())
}

fn select_export(
    conn: &Connection,
    label: &str,
    descendants: DescendantMode,
) -> Result<(Vec<String>, Vec<String>)> {
    match possession(conn, label)? {
        Some(Possession::Active) => {}
        Some(Possession::Ghost) => return Err(Error::GhostDenied),
        None => return Err(Error::TransferDenied),
    }
    let mut secrets = vec![label.to_string()];
    match descendants {
        DescendantMode::KeyOnly => {}
        DescendantMode::DirectChildren => {
            for child in children_of(conn, label)? {
                if possession(conn, &child)? == Some(Possession::Active) {
                    secrets.push(child);
                }
            }
        }
        DescendantMode::AllDescendants => {
            for child in descendants_of(conn, label)? {
                if possession(conn, &child)? == Some(Possession::Active) {
                    secrets.push(child);
                }
            }
        }
    }
    let mut hints = Vec::new();
    for ancestor in ancestor_labels(label) {
        if identity_by_label(conn, &ancestor)?.is_some()
            && !secrets.iter().any(|item| item == &ancestor)
        {
            hints.push(ancestor);
        }
    }
    let subtree = {
        let mut labels = descendants_of(conn, label)?;
        labels.push(label.to_string());
        labels
    };
    for node in subtree {
        if !secrets.iter().any(|item| item == &node) && !hints.iter().any(|item| item == &node) {
            hints.push(node);
        }
    }
    Ok((secrets, hints))
}

fn receiver_accepts(conn: &Connection, bundle: &Bundle, allow_ancestor_import: bool) -> Result<()> {
    let active = active_labels(conn)?;
    receiver_accepts_with(conn, bundle, allow_ancestor_import, &active)
}

fn receiver_accepts_with(
    conn: &Connection,
    bundle: &Bundle,
    allow_ancestor_import: bool,
    active_before: &[String],
) -> Result<()> {
    for entry in &bundle.entries {
        match classify_incoming(conn, entry)? {
            Incoming::Conflict => return Err(Error::IdentityConflict),
            Incoming::Replay => return Err(Error::TransferReplay),
            Incoming::Reconcile | Incoming::Hint => {}
            Incoming::NewSecret => {
                if active_before.is_empty() {
                    continue;
                }
                let under_active = active_before
                    .iter()
                    .any(|ancestor| is_strict_descendant(&entry.label, ancestor));
                let ancestor_ok = allow_ancestor_import
                    && active_before
                        .iter()
                        .any(|descendant| is_strict_descendant(descendant, &entry.label));
                if !under_active && !ancestor_ok {
                    return Err(Error::TransferDenied);
                }
            }
        }
    }
    Ok(())
}

enum Incoming {
    NewSecret,
    Hint,
    Reconcile,
    Conflict,
    Replay,
}

fn classify_incoming(conn: &Connection, entry: &BundleEntry) -> Result<Incoming> {
    if let Some(by_label) = identity_by_label(conn, &entry.label)? {
        if by_label.id != entry.identity_id
            || by_label.enc_public != entry.enc_public
            || by_label.sign_public != entry.sign_public
        {
            return Ok(Incoming::Conflict);
        }
    }
    if let Some(by_id) = identity_by_id(conn, &entry.identity_id)? {
        if by_id.label != entry.label
            || by_id.enc_public != entry.enc_public
            || by_id.sign_public != entry.sign_public
        {
            return Ok(Incoming::Conflict);
        }
        let generation = generation_of(conn, &entry.identity_id)?;
        if entry.generation < generation {
            return Ok(Incoming::Replay);
        }
        return Ok(Incoming::Reconcile);
    }
    if entry.enc_secret.is_none() {
        Ok(Incoming::Hint)
    } else {
        Ok(Incoming::NewSecret)
    }
}

fn apply_entry(
    conn: &Connection,
    dest: &Container,
    bundle: &Bundle,
    entry: &BundleEntry,
) -> Result<()> {
    match classify_incoming(conn, entry)? {
        Incoming::Conflict => return Err(Error::IdentityConflict),
        Incoming::Replay => return Err(Error::TransferReplay),
        Incoming::Reconcile => {
            if entry.enc_secret.is_some() {
                set_possession(
                    conn,
                    &entry.identity_id,
                    Possession::Active,
                    entry.generation,
                )?;
            }
        }
        Incoming::Hint => {
            if identity_by_id(conn, &entry.identity_id)?.is_none() {
                ensure_hardware(conn, &entry.label, KeyType::Encryption, &entry.enc_public)?;
                ensure_hardware(conn, &entry.label, KeyType::Signing, &entry.sign_public)?;
                insert_identity(
                    conn,
                    &entry.identity_id,
                    &entry.label,
                    entry.parent_label.as_deref(),
                    &entry.enc_public,
                    &entry.sign_public,
                    Possession::Ghost,
                    entry.generation,
                )?;
            }
        }
        Incoming::NewSecret => {
            ensure_hardware(conn, &entry.label, KeyType::Encryption, &entry.enc_public)?;
            ensure_hardware(conn, &entry.label, KeyType::Signing, &entry.sign_public)?;
            insert_identity(
                conn,
                &entry.identity_id,
                &entry.label,
                entry.parent_label.as_deref(),
                &entry.enc_public,
                &entry.sign_public,
                Possession::Active,
                entry.generation,
            )?;
        }
    }
    let state = if entry.enc_secret.is_some()
        || possession(conn, &entry.label)? == Some(Possession::Active)
    {
        Possession::Active
    } else {
        Possession::Ghost
    };
    upsert_provenance(conn, &entry.identity_id, dest.device_id(), state)?;
    let source_state = if entry.enc_secret.is_some() {
        Possession::Active
    } else {
        Possession::Ghost
    };
    upsert_provenance(
        conn,
        &entry.identity_id,
        &bundle.source_device_id,
        source_state,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_identity(
    conn: &Connection,
    id: &[u8; 16],
    label: &str,
    parent: Option<&str>,
    enc_public: &[u8; 32],
    sign_public: &[u8; 32],
    state: Possession,
    generation: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO key_identities
         (id, label, parent_label, enc_public, sign_public, enc_fingerprint, sign_fingerprint)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id.to_vec(),
            label,
            parent,
            enc_public.to_vec(),
            sign_public.to_vec(),
            keys::fingerprint(enc_public),
            keys::fingerprint(sign_public),
        ],
    )?;
    conn.execute(
        "INSERT INTO key_possession (identity_id, state, generation) VALUES (?1, ?2, ?3)",
        params![id.to_vec(), state.as_str(), generation],
    )?;
    Ok(())
}

fn set_possession(
    conn: &Connection,
    id: &[u8; 16],
    state: Possession,
    generation: i64,
) -> Result<()> {
    let updated = conn.execute(
        "UPDATE key_possession SET state = ?1, generation = ?2 WHERE identity_id = ?3",
        params![state.as_str(), generation, id.to_vec()],
    )?;
    if updated != 1 {
        return Err(Error::TransferDenied);
    }
    Ok(())
}

fn set_generation_at_least(conn: &Connection, id: &[u8; 16], generation: i64) -> Result<()> {
    conn.execute(
        "UPDATE key_possession SET generation = ?1
         WHERE identity_id = ?2 AND generation < ?1",
        params![generation, id.to_vec()],
    )?;
    Ok(())
}

fn upsert_provenance(
    conn: &Connection,
    id: &[u8; 16],
    device_id: &[u8; 16],
    state: Possession,
) -> Result<()> {
    conn.execute(
        "INSERT INTO key_provenance (identity_id, device_id, state) VALUES (?1, ?2, ?3)
         ON CONFLICT(identity_id, device_id) DO UPDATE SET state = excluded.state",
        params![id.to_vec(), device_id.to_vec(), state.as_str()],
    )?;
    Ok(())
}

struct IdentityRow {
    id: [u8; 16],
    label: String,
    parent_label: Option<String>,
    enc_public: [u8; 32],
    sign_public: [u8; 32],
    enc_fingerprint: String,
    sign_fingerprint: String,
}

fn identity_by_label(conn: &Connection, label: &str) -> Result<Option<IdentityRow>> {
    load_identity(
        conn,
        "SELECT id, label, parent_label, enc_public, sign_public, enc_fingerprint, sign_fingerprint
         FROM key_identities WHERE label = ?1",
        params![label],
    )
}

fn identity_by_id(conn: &Connection, id: &[u8; 16]) -> Result<Option<IdentityRow>> {
    load_identity(
        conn,
        "SELECT id, label, parent_label, enc_public, sign_public, enc_fingerprint, sign_fingerprint
         FROM key_identities WHERE id = ?1",
        params![id.to_vec()],
    )
}

fn load_identity(
    conn: &Connection,
    sql: &str,
    query_params: impl rusqlite::Params,
) -> Result<Option<IdentityRow>> {
    let row = conn
        .query_row(sql, query_params, |row| {
            Ok(RawIdentity {
                id: row.get(0)?,
                label: row.get(1)?,
                parent_label: row.get(2)?,
                enc_public: row.get(3)?,
                sign_public: row.get(4)?,
                enc_fingerprint: row.get(5)?,
                sign_fingerprint: row.get(6)?,
            })
        })
        .optional()?;
    row.map(IdentityRow::from_raw).transpose()
}

struct RawIdentity {
    id: Vec<u8>,
    label: String,
    parent_label: Option<String>,
    enc_public: Vec<u8>,
    sign_public: Vec<u8>,
    enc_fingerprint: String,
    sign_fingerprint: String,
}

impl IdentityRow {
    fn from_raw(parts: RawIdentity) -> Result<Self> {
        Ok(Self {
            id: id_array(&parts.id)?,
            label: parts.label,
            parent_label: parts.parent_label,
            enc_public: array32(&parts.enc_public)?,
            sign_public: array32(&parts.sign_public)?,
            enc_fingerprint: parts.enc_fingerprint,
            sign_fingerprint: parts.sign_fingerprint,
        })
    }
}

fn generation_of(conn: &Connection, id: &[u8; 16]) -> Result<i64> {
    conn.query_row(
        "SELECT generation FROM key_possession WHERE identity_id = ?1",
        params![id.to_vec()],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(Error::TransferDenied)
}

fn children_of(conn: &Connection, label: &str) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT label FROM key_identities WHERE parent_label = ?1 ORDER BY label")?;
    let rows = stmt.query_map(params![label], |row| row.get(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)
}

fn descendants_of(conn: &Connection, label: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut queue = children_of(conn, label)?;
    while let Some(current) = queue.pop() {
        let mut nested = children_of(conn, &current)?;
        queue.append(&mut nested);
        out.push(current);
    }
    Ok(out)
}

fn ancestor_labels(label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = label.to_string();
    while let Some(parent) = parent_node_label(&current) {
        out.push(parent.to_string());
        current = parent.to_string();
    }
    out
}

fn active_labels(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT i.label FROM key_identities i
         JOIN key_possession p ON p.identity_id = i.id
         WHERE p.state = 'active'",
    )?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)
}

fn is_strict_descendant(label: &str, ancestor: &str) -> bool {
    let Some(rest) = label.strip_prefix(ancestor) else {
        return false;
    };
    rest.starts_with('.') && !rest[1..].is_empty()
}

fn ensure_hardware(
    conn: &Connection,
    label: &str,
    key_type: KeyType,
    public_key: &[u8; 32],
) -> Result<i64> {
    if let Ok(existing) = keys::get_key_by_public_key(conn, public_key) {
        return Ok(existing.id);
    }
    keys::register_key(conn, label, key_type, public_key)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedPackage {
    pub id: [u8; 16],
    pub source_device_id: [u8; 16],
    pub destination_device_id: [u8; 16],
    pub verify_key: [u8; 32],
}

/// Verify the package signature against the verify key carried in the body.
/// Returns that source device id and verify key.
pub fn authenticated_source(package: &[u8]) -> Result<([u8; 16], [u8; 32])> {
    let header = authenticated_package(package)?;
    Ok((header.source_device_id, header.verify_key))
}

/// SHA-256 of the exact `KQTX` bytes. Prepare stores this, and an
/// acknowledgement has to repeat it.
pub fn package_hash(package: &[u8]) -> [u8; 32] {
    sha256(package)
}

pub fn authenticated_package(package: &[u8]) -> Result<AuthenticatedPackage> {
    let (body, signature) = split_package(package)?;
    let mut data = body;
    let id = take_array::<16>(&mut data)?;
    let _operation = take_u8(&mut data)?;
    let _descendants = take_u8(&mut data)?;
    let source_device_id = take_array::<16>(&mut data)?;
    let destination_device_id = take_array::<16>(&mut data)?;
    let verify_key = take_array::<32>(&mut data)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + body.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(body);
    signing::verify_signature(&verify_key, &message, &signature)?;
    Ok(AuthenticatedPackage {
        id,
        source_device_id,
        destination_device_id,
        verify_key,
    })
}

fn split_package(package: &[u8]) -> Result<(&[u8], [u8; 64])> {
    if package.len() < 4 + 1 + 4 + 64 || &package[..4] != MAGIC {
        return Err(Error::IntegrityCheckFailed);
    }
    let mut cursor = &package[4..];
    let version = take_u8(&mut cursor)?;
    if version != VERSION {
        return Err(Error::IntegrityCheckFailed);
    }
    let body_len = take_u32(&mut cursor)? as usize;
    if cursor.len() != body_len + 64 {
        return Err(Error::IntegrityCheckFailed);
    }
    let body = &cursor[..body_len];
    let signature = cursor[body_len..]
        .try_into()
        .map_err(|_| Error::IntegrityCheckFailed)?;
    Ok((body, signature))
}

fn encode_bundle(storage: &dyn Storage, source: &Container, bundle: &Bundle) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&bundle.id);
    body.push(bundle.operation.tag());
    body.push(bundle.descendants.tag());
    body.extend_from_slice(&bundle.source_device_id);
    body.extend_from_slice(&bundle.destination_device_id);
    body.extend_from_slice(source.verify_key());
    push_len_prefixed(&mut body, bundle.actor.as_bytes())?;
    push_len_prefixed(&mut body, bundle.root_label.as_bytes())?;
    let count = u16::try_from(bundle.entries.len()).map_err(|_| Error::IntegrityCheckFailed)?;
    body.extend_from_slice(&count.to_be_bytes());
    for entry in &bundle.entries {
        let kind = if entry.enc_secret.is_some() {
            KIND_SECRET
        } else {
            KIND_HINT
        };
        body.push(kind);
        body.extend_from_slice(&entry.identity_id);
        body.extend_from_slice(&(entry.generation as u64).to_be_bytes());
        push_len_prefixed(&mut body, entry.label.as_bytes())?;
        match &entry.parent_label {
            Some(parent) => {
                body.push(1);
                push_len_prefixed(&mut body, parent.as_bytes())?;
            }
            None => body.push(0),
        }
        body.extend_from_slice(&entry.enc_public);
        body.extend_from_slice(&entry.sign_public);
        push_len_prefixed(&mut body, entry.enc_fingerprint.as_bytes())?;
        push_len_prefixed(&mut body, entry.sign_fingerprint.as_bytes())?;
        if kind == KIND_SECRET {
            let enc = entry
                .enc_secret
                .as_ref()
                .ok_or(Error::IntegrityCheckFailed)?;
            let sign = entry
                .sign_secret
                .as_ref()
                .ok_or(Error::IntegrityCheckFailed)?;
            body.extend_from_slice(enc.as_slice());
            body.extend_from_slice(sign.as_slice());
        }
    }
    let mut message = Vec::with_capacity(DOMAIN.len() + body.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&body);
    let secret = device::device_signing_secret_in(storage, source)?;
    let signature = signing::sign(&secret, &message);
    let mut package = Vec::new();
    package.extend_from_slice(MAGIC);
    package.push(VERSION);
    let len = u32::try_from(body.len()).map_err(|_| Error::IntegrityCheckFailed)?;
    package.extend_from_slice(&len.to_be_bytes());
    package.extend_from_slice(&body);
    package.extend_from_slice(&signature);
    Ok(package)
}

fn open_bundle(package: &[u8], source: &Container, dest: &Container) -> Result<Bundle> {
    if package.len() < 4 + 1 + 4 + 64 || &package[..4] != MAGIC {
        return Err(Error::IntegrityCheckFailed);
    }
    let mut cursor = &package[4..];
    let version = take_u8(&mut cursor)?;
    if version != VERSION {
        return Err(Error::IntegrityCheckFailed);
    }
    let body_len = take_u32(&mut cursor)? as usize;
    if cursor.len() < body_len + 64 {
        return Err(Error::IntegrityCheckFailed);
    }
    let body = &cursor[..body_len];
    let signature: [u8; 64] = cursor[body_len..body_len + 64]
        .try_into()
        .map_err(|_| Error::IntegrityCheckFailed)?;
    if cursor.len() != body_len + 64 {
        return Err(Error::IntegrityCheckFailed);
    }
    let mut message = Vec::with_capacity(DOMAIN.len() + body.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(body);
    signing::verify_signature(source.verify_key(), &message, &signature)?;
    let mut data = body;
    let id = take_array::<16>(&mut data)?;
    let operation = TransferOp::from_tag(take_u8(&mut data)?)?;
    let descendants = DescendantMode::from_tag(take_u8(&mut data)?)?;
    let source_device_id = take_array::<16>(&mut data)?;
    let destination_device_id = take_array::<16>(&mut data)?;
    let verify_key = take_array::<32>(&mut data)?;
    if source_device_id != *source.device_id()
        || destination_device_id != *dest.device_id()
        || verify_key != *source.verify_key()
    {
        return Err(Error::SignatureVerificationFailed);
    }
    let actor = utf8_text(take_len_prefixed(&mut data)?)?;
    let root_label = utf8_text(take_len_prefixed(&mut data)?)?;
    device::validate_slot_label(&actor)?;
    device::validate_slot_label(&root_label)?;
    let count = u16::from_be_bytes(take_array::<2>(&mut data)?);
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let kind = take_u8(&mut data)?;
        let identity_id = take_array::<16>(&mut data)?;
        let generation = i64::try_from(u64::from_be_bytes(take_array::<8>(&mut data)?))
            .map_err(|_| Error::IntegrityCheckFailed)?;
        if generation < 1 {
            return Err(Error::IntegrityCheckFailed);
        }
        let label = utf8_text(take_len_prefixed(&mut data)?)?;
        device::validate_slot_label(&label)?;
        let parent_flag = take_u8(&mut data)?;
        let parent_label = if parent_flag == 1 {
            let parent = utf8_text(take_len_prefixed(&mut data)?)?;
            device::validate_slot_label(&parent)?;
            Some(parent)
        } else if parent_flag == 0 {
            None
        } else {
            return Err(Error::IntegrityCheckFailed);
        };
        let enc_public = take_array::<32>(&mut data)?;
        let sign_public = take_array::<32>(&mut data)?;
        let enc_fingerprint = utf8_text(take_len_prefixed(&mut data)?)?;
        let sign_fingerprint = utf8_text(take_len_prefixed(&mut data)?)?;
        if enc_fingerprint != keys::fingerprint(&enc_public)
            || sign_fingerprint != keys::fingerprint(&sign_public)
        {
            return Err(Error::IntegrityCheckFailed);
        }
        let (enc_secret, sign_secret) = if kind == KIND_SECRET {
            let enc = Zeroizing::new(take_array::<32>(&mut data)?);
            let sign = Zeroizing::new(take_array::<32>(&mut data)?);
            if keys::encryption_public_from_secret(&enc) != enc_public
                || SigningKey::from_bytes(&sign).verifying_key().to_bytes() != sign_public
            {
                return Err(Error::IntegrityCheckFailed);
            }
            (Some(enc), Some(sign))
        } else if kind == KIND_HINT {
            (None, None)
        } else {
            return Err(Error::IntegrityCheckFailed);
        };
        entries.push(BundleEntry {
            identity_id,
            generation,
            label,
            parent_label,
            enc_public,
            sign_public,
            enc_fingerprint,
            sign_fingerprint,
            enc_secret,
            sign_secret,
        });
    }
    if !data.is_empty() {
        return Err(Error::IntegrityCheckFailed);
    }
    if !entries
        .iter()
        .any(|entry| entry.label == root_label && entry.enc_secret.is_some())
    {
        return Err(Error::GhostDenied);
    }
    Ok(Bundle {
        id,
        operation,
        descendants,
        source_device_id,
        destination_device_id,
        actor,
        root_label,
        entries,
    })
}

fn utf8_text(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| Error::IntegrityCheckFailed)
}

fn bundle_labels(bundle: &Bundle) -> (Vec<String>, Vec<String>) {
    let mut included = Vec::new();
    let mut excluded = Vec::new();
    for entry in &bundle.entries {
        if entry.enc_secret.is_some() {
            included.push(entry.label.clone());
        } else {
            excluded.push(entry.label.clone());
        }
    }
    (included, excluded)
}

fn audit_bundle(conn: &Connection, bundle: &Bundle, result: &str, detail: &str) -> Result<()> {
    let root_id = bundle
        .entries
        .iter()
        .find(|entry| entry.label == bundle.root_label)
        .map(|entry| entry.identity_id)
        .unwrap_or([0u8; 16]);
    write_audit(
        conn,
        &bundle.id,
        bundle.operation,
        &bundle.source_device_id,
        &bundle.destination_device_id,
        &root_id,
        &bundle.root_label,
        bundle.descendants,
        result,
        detail,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_audit(
    conn: &Connection,
    tx_id: &[u8; 16],
    operation: TransferOp,
    source_device_id: &[u8; 16],
    destination_device_id: &[u8; 16],
    key_id: &[u8; 16],
    tree_path: &str,
    descendants: DescendantMode,
    result: &str,
    detail: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO transfer_audit
         (transaction_id, operation_type, source_device_id, destination_device_id,
          key_id, tree_path, descendant_mode, result, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            tx_id.to_vec(),
            operation.as_str(),
            source_device_id.to_vec(),
            destination_device_id.to_vec(),
            key_id.to_vec(),
            tree_path,
            descendants.as_str(),
            result,
            detail,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_tx(
    conn: &Connection,
    id: &[u8; 16],
    operation: TransferOp,
    role: &str,
    state: &str,
    peer: &[u8; 16],
    root: &str,
    descendants: DescendantMode,
    hash: &[u8; 32],
    detail: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO transfer_transactions
         (id, operation, role, state, peer_device_id, root_label, descendant_mode, package_hash, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id.to_vec(),
            operation.as_str(),
            role,
            state,
            peer.to_vec(),
            root,
            descendants.as_str(),
            hash.to_vec(),
            detail,
        ],
    )?;
    Ok(())
}

fn tx_exists(conn: &Connection, id: &[u8; 16]) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM transfer_transactions WHERE id = ?1",
            params![id.to_vec()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn tx_state(conn: &Connection, id: &[u8; 16]) -> Result<Option<String>> {
    conn.query_row(
        "SELECT state FROM transfer_transactions WHERE id = ?1",
        params![id.to_vec()],
        |row| row.get(0),
    )
    .optional()
    .map_err(Error::from)
}

fn tx_detail(conn: &Connection, id: &[u8; 16]) -> Result<String> {
    conn.query_row(
        "SELECT detail FROM transfer_transactions WHERE id = ?1",
        params![id.to_vec()],
        |row| row.get(0),
    )
    .map_err(|_| Error::TransferIncomplete)
}

fn tx_hash(conn: &Connection, id: &[u8; 16]) -> Result<[u8; 32]> {
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT package_hash FROM transfer_transactions WHERE id = ?1",
            params![id.to_vec()],
            |row| row.get(0),
        )
        .map_err(|_| Error::TransferIncomplete)?;
    array32(&bytes)
}

fn tx_operation(conn: &Connection, id: &[u8; 16]) -> Result<TransferOp> {
    let value: String = conn
        .query_row(
            "SELECT operation FROM transfer_transactions WHERE id = ?1",
            params![id.to_vec()],
            |row| row.get(0),
        )
        .map_err(|_| Error::TransferIncomplete)?;
    match value.as_str() {
        "copy" => Ok(TransferOp::Copy),
        "move" => Ok(TransferOp::Move),
        _ => Err(Error::IntegrityCheckFailed),
    }
}

fn tx_root(conn: &Connection, id: &[u8; 16]) -> Result<String> {
    conn.query_row(
        "SELECT root_label FROM transfer_transactions WHERE id = ?1",
        params![id.to_vec()],
        |row| row.get(0),
    )
    .map_err(|_| Error::TransferIncomplete)
}

fn tx_mode(conn: &Connection, id: &[u8; 16]) -> Result<DescendantMode> {
    let value: String = conn
        .query_row(
            "SELECT descendant_mode FROM transfer_transactions WHERE id = ?1",
            params![id.to_vec()],
            |row| row.get(0),
        )
        .map_err(|_| Error::TransferIncomplete)?;
    DescendantMode::parse(&value)
}

fn tx_peer(conn: &Connection, id: &[u8; 16]) -> Result<[u8; 16]> {
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT peer_device_id FROM transfer_transactions WHERE id = ?1",
            params![id.to_vec()],
            |row| row.get(0),
        )
        .map_err(|_| Error::TransferIncomplete)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::IntegrityCheckFailed)
}

fn set_state(conn: &Connection, id: &[u8; 16], state: &str) -> Result<()> {
    let updated = conn.execute(
        "UPDATE transfer_transactions SET state = ?1 WHERE id = ?2",
        params![state, id.to_vec()],
    )?;
    if updated != 1 {
        return Err(Error::TransferIncomplete);
    }
    Ok(())
}

fn set_detail(conn: &Connection, id: &[u8; 16], detail: &str) -> Result<()> {
    conn.execute(
        "UPDATE transfer_transactions SET detail = ?1 WHERE id = ?2",
        params![detail, id.to_vec()],
    )?;
    Ok(())
}

fn format_detail(
    reason: &str,
    included: &[String],
    excluded: &[String],
    installed: &[String],
) -> String {
    format!(
        "reason={reason};included={};excluded={};installed={}",
        included.join(","),
        excluded.join(","),
        installed.join(",")
    )
}

fn replace_detail_list(detail: &str, key: &str, values: &[String]) -> String {
    let mut parts: Vec<String> = detail
        .split(';')
        .filter(|part| !part.starts_with(&format!("{key}=")))
        .map(str::to_string)
        .collect();
    parts.push(format!("{key}={}", values.join(",")));
    parts.join(";")
}

fn detail_list(detail: &str, key: &str) -> Vec<String> {
    detail
        .split(';')
        .find_map(|part| {
            let (found, value) = part.split_once('=')?;
            if found == key {
                if value.is_empty() {
                    Some(Vec::new())
                } else {
                    Some(value.split(',').map(str::to_string).collect())
                }
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

fn id_array(bytes: &[u8]) -> Result<[u8; 16]> {
    bytes.try_into().map_err(|_| Error::IntegrityCheckFailed)
}

fn array32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| Error::IntegrityCheckFailed)
}

#[cfg(test)]
#[path = "transfer/tests.rs"]
mod tests;
