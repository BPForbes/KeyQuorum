//! C ABI for tracked files and co-signed delivery (`include/keyquorum_files.h`).
//!
//! A container is the encoded `KQTF` bytes ([`TrackedFile::encode`]); every
//! function decodes, works in memory and, when it changes the file, encodes
//! the result into a caller buffer. Nothing is stored and no clock is read:
//! times come in as UTC text (`2026-10-20T13:00:00.000Z`).
//!
//! Trust is never taken from a container. The caller passes the signing keys
//! its own registry holds, as a table of (label, public key); a label's
//! identity is [`keyquorum::file_history::label_identity`].
//!
//! A co-signed delivery: the author checks in and signs a revision; the
//! public part of that revision ([`KqFileOffer`]) goes to the host, which
//! verifies the author's signature and the recipient's co-signature over the
//! same public fields without ever holding the content; the content travels
//! sealed to the recipient's box key, and the recipient attaches its
//! co-signature after opening it and checks the delivery is complete.

use super::{bytes_in, bytes_out, input};
use keyquorum::file_delivery::{self, Freshness, OutgoingHistory};
use keyquorum::file_history::{
    self, current_revision, delivery_readiness, latest_trusted_revision_where, proof_descriptor,
    select_shareable_revision, supervisor_permits, BridgeEvidence, DeliveryReadiness, EventDetails,
    FilePolicy, GenerationEvidence, HistoryEvent, HistoryEventType, HistoryOutcome, ImportContext,
    NewEvent, NewRevision, ProofKind, TrackedFile, TrustContext,
};
use keyquorum::signing;
use sha2::{Digest, Sha256};
use std::ffi::{c_char, c_int};
use zeroize::Zeroizing;

/// The call succeeded (and, for a readiness check, the delivery may fire).
pub const KQ_FILE_OK: c_int = 0;
/// A pointer is null, text is not UTF-8, or a container or letter is malformed.
pub const KQ_FILE_INVALID: c_int = -1;
/// The output buffer is too small; `*out_len` holds the size needed.
pub const KQ_FILE_NO_ROOM: c_int = -3;
/// A signature does not verify, or the revision is not trusted.
pub const KQ_FILE_UNTRUSTED: c_int = -5;
/// The file has two heads: nothing is "the" file until someone merges.
pub const KQ_FILE_FORKED: c_int = -6;
/// Freshness: an older copy, another branch, or the same revision again.
pub const KQ_FILE_NOT_NEWER: c_int = -7;
/// Freshness: exactly this revision and history were accepted before.
pub const KQ_FILE_REPLAYED: c_int = -8;
/// No such revision, or no trusted one to serve.
pub const KQ_FILE_NO_REVISION: c_int = -10;
/// A delivery holds fewer valid signatures than it needs.
pub const KQ_FILE_BELOW_THRESHOLD: c_int = -11;
/// Freshness: nothing from this file was accepted before.
pub const KQ_FILE_FIRST: c_int = 1;
/// Freshness: extends everything accepted before and adds a revision.
pub const KQ_FILE_NEWER: c_int = 2;
/// Bumped when a signature or struct in the header changes.
pub const KQ_FILE_ABI_VERSION: c_int = 2;

/// A signing key the caller's registry holds for a label.
#[repr(C)]
pub struct KqFileKey {
    pub label: *const c_char,
    pub signing_public: [u8; 32],
}

/// The keys trust is judged with.
#[repr(C)]
pub struct KqFileTrust {
    pub keys: *const KqFileKey,
    pub nkeys: usize,
}

/// The public part of an author-signed revision: everything the author's
/// signature covers and nothing of the content.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KqFileOffer {
    pub file_id: [u8; 16],
    pub revision_id: [u8; 32],
    pub content_commitment: [u8; 32],
    pub author_identity: [u8; 16],
    pub author_signature: [u8; 64],
    pub topology_generation: u64,
    pub policy_hash: [u8; 32],
}

/// [`TrustContext`] over the caller's key table. A key counts only for the
/// identity its label derives to; there is no bridge evidence, so a policy
/// rule that needs a bridge falls back to the owner's countersignature.
struct TableTrust {
    keys: Vec<(String, [u8; 32])>,
}

impl TrustContext for TableTrust {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        if file_history::label_identity(label) != *identity {
            return None;
        }
        self.keys
            .iter()
            .find(|(known, _)| known == label)
            .map(|(_, key)| *key)
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }

    /// A key table records no topology, so only generation 0 (no published
    /// topology) is judged; any other generation stays pending, never
    /// judged against today's keys.
    fn generation_evidence(&self, _scope_root: &str, generation: u64) -> GenerationEvidence {
        if generation == 0 {
            GenerationEvidence::Current
        } else {
            GenerationEvidence::Unavailable
        }
    }
}

/// # Safety
/// `trust` must be null or point to a table whose `keys` holds `nkeys`
/// entries with valid NUL-terminated labels.
unsafe fn trust_in(trust: *const KqFileTrust) -> Option<TableTrust> {
    let trust = trust.as_ref()?;
    if trust.nkeys > 0 && trust.keys.is_null() {
        return None;
    }
    let mut keys = Vec::with_capacity(trust.nkeys);
    for i in 0..trust.nkeys {
        let entry = &*trust.keys.add(i);
        keys.push((input(entry.label)?.to_string(), entry.signing_public));
    }
    Some(TableTrust { keys })
}

/// # Safety
/// `p` must be null or readable for `len` bytes.
unsafe fn slice_in<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if p.is_null() {
        return (len == 0).then_some(&[][..]);
    }
    Some(std::slice::from_raw_parts(p, len))
}

/// # Safety
/// `p` must be null or readable for `len` bytes.
unsafe fn container_in(p: *const u8, len: usize) -> Option<TrackedFile> {
    TrackedFile::decode(slice_in(p, len)?).ok()
}

/// Writes `value` into `out` when it fits; `*out_len` always gets its size.
///
/// # Safety
/// `out` must be null or writable for `cap` bytes; `out_len` must be null or
/// writable.
unsafe fn buf_out(value: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> c_int {
    if out_len.is_null() {
        return KQ_FILE_INVALID;
    }
    *out_len = value.len();
    if out.is_null() || cap < value.len() {
        return KQ_FILE_NO_ROOM;
    }
    std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
    KQ_FILE_OK
}

/// # Safety
/// As [`buf_out`].
unsafe fn file_out(file: &TrackedFile, out: *mut u8, cap: usize, out_len: *mut usize) -> c_int {
    match file.encode() {
        Ok(bytes) => buf_out(&bytes, out, cap, out_len),
        Err(_) => KQ_FILE_INVALID,
    }
}

fn policy_of(file: &TrackedFile) -> Option<&FilePolicy> {
    file.policy()
}

/// The author's content proof for `revision`, the first one held.
fn author_proof<'a>(
    file: &'a TrackedFile,
    revision: &'a [u8; 32],
) -> Option<&'a keyquorum::file_history::RevisionProof> {
    let stored = file.graph().get(revision)?;
    let author = &stored.revision;
    file.proofs_for(revision, ProofKind::Content).find(|proof| {
        proof.signer_label == author.author_hcp_label
            && Some(proof.signer_identity) == author.author_identity
    })
}

fn offer_preimage(offer: &KqFileOffer) -> [u8; 32] {
    signing::file_revision_preimage(
        &offer.file_id,
        &offer.revision_id,
        &offer.content_commitment,
        &offer.author_identity,
        offer.topology_generation,
        &offer.policy_hash,
    )
}

fn coauthor_preimage(offer: &KqFileOffer, coauthor: &str) -> Option<[u8; 32]> {
    let author_hash: [u8; 32] = Sha256::digest(offer.author_signature).into();
    signing::file_coauthor_preimage(
        &offer.file_id,
        &offer.revision_id,
        &offer.author_identity,
        &author_hash,
        &file_history::label_identity(coauthor),
        coauthor,
        offer.topology_generation,
        &offer.policy_hash,
    )
    .ok()
}

/// The ABI version this library implements (`KQ_FILE_ABI_VERSION`).
#[no_mangle]
pub extern "C" fn kq_file_abi_version() -> c_int {
    KQ_FILE_ABI_VERSION
}

/// The name of history event type `code` ("TrackingStarted", ...), a static
/// NUL-terminated string the caller never frees, or null for a code this
/// build does not know. Added in ABI version 2.
#[no_mangle]
pub extern "C" fn kq_file_event_name(code: u8) -> *const c_char {
    file_history::HistoryEventType::name_of(code).map_or(std::ptr::null(), |n| n.as_ptr())
}

/// The name of history outcome `code` ("Success", ...), a static NUL-terminated
/// string the caller never frees, or null for a code this build does not know.
/// Added in ABI version 2.
#[no_mangle]
pub extern "C" fn kq_file_outcome_name(code: u8) -> *const c_char {
    file_history::HistoryOutcome::name_of(code).map_or(std::ptr::null(), |n| n.as_ptr())
}

/// Writes the 16-byte identity of `label` into `id_out`.
///
/// # Safety
/// `label` must be null or a valid NUL-terminated string; `id_out` must be
/// null or writable for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_file_label_identity(label: *const c_char, id_out: *mut u8) -> c_int {
    match input(label) {
        Some(label) if bytes_out(&file_history::label_identity(label), id_out) => KQ_FILE_OK,
        _ => KQ_FILE_INVALID,
    }
}

/// A new tracked file with no revisions, owned by `scope_root` under the
/// standard policy.
///
/// # Safety
/// `file_id` must be null or readable for 16 bytes; the strings null or
/// NUL-terminated; `out` null or writable for `cap`; `out_len` null or writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_new(
    file_id: *const u8,
    name: *const c_char,
    scope_root: *const c_char,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(file_id), Some(name), Some(scope_root)) =
        (bytes_in::<16>(file_id), input(name), input(scope_root))
    else {
        return KQ_FILE_INVALID;
    };
    let file = TrackedFile::with_policy(file_id, name, FilePolicy::standard(scope_root));
    file_out(&file, out, cap, out_len)
}

/// Checks in `payload` as a new revision by `author` on the current head and
/// signs it with the author's 32-byte signing secret. The new container goes
/// to `out` and the revision id to `rev_out`. `KQ_FILE_FORKED` when the file
/// has two heads.
///
/// # Safety
/// Pointers as in the header: `c` readable for `clen`, `payload` for `plen`,
/// `secret` for 32; `rev_out` writable for 32.
#[no_mangle]
pub unsafe extern "C" fn kq_file_check_in(
    c: *const u8,
    clen: usize,
    author: *const c_char,
    created_at_utc: *const c_char,
    payload: *const u8,
    plen: usize,
    secret: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    rev_out: *mut u8,
) -> c_int {
    let (Some(mut file), Some(author), Some(created_at), Some(payload), Some(secret)) = (
        container_in(c, clen),
        input(author),
        input(created_at_utc),
        slice_in(payload, plen),
        bytes_in::<32>(secret).map(Zeroizing::new),
    ) else {
        return KQ_FILE_INVALID;
    };
    let Some(policy_hash) = policy_of(&file).and_then(|p| p.policy_hash().ok()) else {
        return KQ_FILE_INVALID;
    };
    let parents = if file.revisions().is_empty() {
        Vec::new()
    } else {
        match current_revision(&file) {
            Some(head) => vec![head],
            None => return KQ_FILE_FORKED,
        }
    };
    let identity = file_history::label_identity(author);
    let new = NewRevision {
        parent_revision_ids: parents,
        user_label: None,
        author_identity: Some(identity),
        author_hcp_label: author.to_string(),
        created_at_utc: created_at.to_string(),
        topology_generation: 0,
        policy_hash,
    };
    let base = new.parent_revision_ids.first().copied();
    let Ok(revision) = file.check_in(new, payload.to_vec()) else {
        return KQ_FILE_INVALID;
    };
    // The same two events the CLI's `file checkin` records, so a check-in made through the FFI
    // is as visible in the history as one made from the command line.
    let mut details = EventDetails::new();
    if let Some(base) = base {
        details = details.with("base_revision", &hex(&base));
    }
    let checked_in = event_for(
        HistoryEventType::EditCheckedIn,
        Some(revision),
        created_at,
        identity,
        author,
        details,
    );
    if file.append(checked_in).is_err() {
        return KQ_FILE_INVALID;
    }
    if file
        .sign_revision(&revision, identity, author, &secret)
        .is_err()
    {
        return KQ_FILE_INVALID;
    }
    let signed = event_for(
        HistoryEventType::RevisionSigned,
        Some(revision),
        created_at,
        identity,
        author,
        EventDetails::new(),
    );
    if file.append(signed).is_err() {
        return KQ_FILE_INVALID;
    }
    let rc = file_out(&file, out, cap, out_len);
    if rc == KQ_FILE_OK && !bytes_out(&revision, rev_out) {
        return KQ_FILE_INVALID;
    }
    rc
}

/// Checks the container's structure and history chain; writes its history
/// root to `root_out` (may be null).
///
/// # Safety
/// `c` readable for `clen`; `root_out` null or writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_file_verify(c: *const u8, clen: usize, root_out: *mut u8) -> c_int {
    let Some(file) = container_in(c, clen) else {
        return KQ_FILE_INVALID;
    };
    match file_history::verify_tracked_file(&file) {
        Ok(root) => {
            if !root_out.is_null() {
                bytes_out(&root, root_out);
            }
            KQ_FILE_OK
        }
        Err(_) => KQ_FILE_INVALID,
    }
}

/// Lowercase hex of `bytes`, as the CLI prints ids.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A successful event by `actor` on `revision`, at the caller's time.
fn event_for(
    kind: HistoryEventType,
    revision: Option<[u8; 32]>,
    at: &str,
    identity: [u8; 16],
    actor: &str,
    details: EventDetails,
) -> NewEvent {
    NewEvent {
        revision_id: revision,
        occurred_at: at.to_string(),
        actor_identity: Some(identity),
        actor_label: Some(actor.to_string()),
        topology_generation: Some(0),
        event_type: kind,
        outcome: HistoryOutcome::Success,
        details,
    }
}

/// One line for `event`: sequence, time, type code, outcome code, actor, revision (hex, empty when
/// none) and the details as `key=value` pairs joined by `;`, tab-separated. `None` when a field
/// holds a tab, a newline, a carriage return or a `;` that would blur the line.
fn event_line(event: &HistoryEvent) -> Option<String> {
    let blurs = |text: &str| text.contains(['\t', '\n', '\r', ';']);
    let mut details = Vec::new();
    for (key, value) in event.details.entries() {
        if blurs(key) || blurs(value) {
            return None;
        }
        details.push(format!("{key}={value}"));
    }
    let actor = event.actor_label.clone().unwrap_or_default();
    let revision = event.revision_id.map(|id| hex(&id)).unwrap_or_default();
    let fields = [
        event.sequence.to_string(),
        event.occurred_at.clone(),
        (event.event_type as u8).to_string(),
        (event.outcome as u8).to_string(),
        actor,
        revision,
        details.join(";"),
    ];
    if fields.iter().take(6).any(|field| blurs(field)) {
        return None;
    }
    Some(fields.join("\t"))
}

/// The events of the container, oldest first, one line each into `out` (see [`event_line`]).
/// This is the offline view of a file's history: it needs only the container.
///
/// # Safety
/// `c` readable for `clen`; `out` null or writable for `cap`; `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_events(
    c: *const u8,
    clen: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let Some(file) = container_in(c, clen) else {
        return KQ_FILE_INVALID;
    };
    let mut text = String::new();
    for event in file.events() {
        let Some(line) = event_line(event) else {
            return KQ_FILE_INVALID;
        };
        text.push_str(&line);
        text.push('\n');
    }
    buf_out(text.as_bytes(), out, cap, out_len)
}

/// The single head into `rev_out`; `KQ_FILE_FORKED` with two heads,
/// `KQ_FILE_NO_REVISION` with none.
///
/// # Safety
/// `c` readable for `clen`; `rev_out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_file_head(c: *const u8, clen: usize, rev_out: *mut u8) -> c_int {
    let Some(file) = container_in(c, clen) else {
        return KQ_FILE_INVALID;
    };
    if file.revisions().is_empty() {
        return KQ_FILE_NO_REVISION;
    }
    match current_revision(&file) {
        Some(head) if bytes_out(&head, rev_out) => KQ_FILE_OK,
        Some(_) => KQ_FILE_INVALID,
        None => KQ_FILE_FORKED,
    }
}

/// The payload of `rev` into `out`.
///
/// # Safety
/// `c` readable for `clen`, `rev` for 32; `out` null or writable for `cap`;
/// `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_payload(
    c: *const u8,
    clen: usize,
    rev: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(file), Some(rev)) = (container_in(c, clen), bytes_in::<32>(rev)) else {
        return KQ_FILE_INVALID;
    };
    match file
        .graph()
        .get(&rev)
        .map(|stored| stored.payload.as_deref())
    {
        Some(Some(payload)) => buf_out(payload, out, cap, out_len),
        Some(None) => KQ_FILE_INVALID,
        None => KQ_FILE_NO_REVISION,
    }
}

/// A copy holding only `rev`, its ancestors and their proofs: what may leave
/// when a newer revision is not trusted.
///
/// # Safety
/// As [`kq_file_payload`].
#[no_mangle]
pub unsafe extern "C" fn kq_file_extract(
    c: *const u8,
    clen: usize,
    rev: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(file), Some(rev)) = (container_in(c, clen), bytes_in::<32>(rev)) else {
        return KQ_FILE_INVALID;
    };
    if file.graph().get(&rev).is_none() {
        return KQ_FILE_NO_REVISION;
    }
    match file.extract_revision(&rev) {
        Ok(copy) => file_out(&copy, out, cap, out_len),
        Err(_) => KQ_FILE_INVALID,
    }
}

/// Imports `incoming`'s revisions and proofs into `local` (same file id and
/// policy, both must verify), recording the import as `actor` at
/// `occurred_at_utc`. With `llen == 0` the result is `incoming` itself.
///
/// # Safety
/// `local` readable for `llen`, `incoming` for `ilen`; strings NUL-terminated;
/// `out` null or writable for `cap`; `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_merge(
    local: *const u8,
    llen: usize,
    incoming: *const u8,
    ilen: usize,
    actor: *const c_char,
    occurred_at_utc: *const c_char,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(incoming), Some(actor), Some(occurred_at)) = (
        container_in(incoming, ilen),
        input(actor),
        input(occurred_at_utc),
    ) else {
        return KQ_FILE_INVALID;
    };
    if llen == 0 {
        return file_out(&incoming, out, cap, out_len);
    }
    let Some(mut file) = container_in(local, llen) else {
        return KQ_FILE_INVALID;
    };
    let context = ImportContext {
        actor_identity: Some(file_history::label_identity(actor)),
        actor_label: actor.to_string(),
        occurred_at: occurred_at.to_string(),
        topology_generation: 0,
    };
    match file.merge_history(&incoming, &context) {
        Ok(_) => file_out(&file, out, cap, out_len),
        Err(_) => KQ_FILE_INVALID,
    }
}

/// Every label that authored a revision or signed a proof, NUL-separated, so
/// the caller knows which keys to put in the trust table.
///
/// # Safety
/// `c` readable for `clen`; `out` null or writable for `cap`; `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_signers(
    c: *const u8,
    clen: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let Some(file) = container_in(c, clen) else {
        return KQ_FILE_INVALID;
    };
    let mut labels: Vec<&str> = file
        .revisions()
        .iter()
        .map(|stored| stored.revision.author_hcp_label.as_str())
        .chain(
            file.proofs()
                .iter()
                .map(|proof| proof.signer_label.as_str()),
        )
        .collect();
    if let Some(policy) = file.policy() {
        labels.push(policy.scope_root.as_str());
    }
    labels.sort_unstable();
    labels.dedup();
    let mut bytes = Vec::new();
    for label in labels {
        bytes.extend_from_slice(label.as_bytes());
        bytes.push(0);
    }
    buf_out(&bytes, out, cap, out_len)
}

/// The public part of `rev` and its author's signature, for the host.
/// `KQ_FILE_UNTRUSTED` when the author has not signed it.
///
/// # Safety
/// `c` readable for `clen`, `rev` for 32; `offer_out` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_offer(
    c: *const u8,
    clen: usize,
    rev: *const u8,
    offer_out: *mut KqFileOffer,
) -> c_int {
    let (Some(file), Some(rev)) = (container_in(c, clen), bytes_in::<32>(rev)) else {
        return KQ_FILE_INVALID;
    };
    if offer_out.is_null() {
        return KQ_FILE_INVALID;
    }
    let Some(stored) = file.graph().get(&rev) else {
        return KQ_FILE_NO_REVISION;
    };
    let revision = &stored.revision;
    let (Some(proof), Some(author)) = (author_proof(&file, &rev), revision.author_identity) else {
        return KQ_FILE_UNTRUSTED;
    };
    *offer_out = KqFileOffer {
        file_id: revision.file_id,
        revision_id: revision.revision_id,
        content_commitment: revision.content_commitment,
        author_identity: author,
        author_signature: proof.signature,
        topology_generation: revision.topology_generation,
        policy_hash: revision.policy_hash,
    };
    KQ_FILE_OK
}

/// Whether `offer` carries `author_label`'s signature under `author_public`.
///
/// # Safety
/// `offer` readable; `author_label` NUL-terminated; `author_public` readable
/// for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_file_offer_verify(
    offer: *const KqFileOffer,
    author_label: *const c_char,
    author_public: *const u8,
) -> c_int {
    let (Some(offer), Some(label), Some(public)) = (
        offer.as_ref(),
        input(author_label),
        bytes_in::<32>(author_public),
    ) else {
        return KQ_FILE_INVALID;
    };
    if file_history::label_identity(label) != offer.author_identity {
        return KQ_FILE_UNTRUSTED;
    }
    match signing::verify_signature(&public, &offer_preimage(offer), &offer.author_signature) {
        Ok(()) => KQ_FILE_OK,
        Err(_) => KQ_FILE_UNTRUSTED,
    }
}

/// `coauthor`'s co-signature on the offered revision, without the content:
/// 64 bytes into `sig_out`. Refused for the offer's own author.
///
/// # Safety
/// `offer` readable; `coauthor` NUL-terminated; `secret` readable for 32;
/// `sig_out` writable for 64.
#[no_mangle]
pub unsafe extern "C" fn kq_file_coauthor_sign(
    offer: *const KqFileOffer,
    coauthor: *const c_char,
    secret: *const u8,
    sig_out: *mut u8,
) -> c_int {
    let (Some(offer), Some(coauthor), Some(secret)) = (
        offer.as_ref(),
        input(coauthor),
        bytes_in::<32>(secret).map(Zeroizing::new),
    ) else {
        return KQ_FILE_INVALID;
    };
    if file_history::label_identity(coauthor) == offer.author_identity {
        return KQ_FILE_INVALID;
    }
    match coauthor_preimage(offer, coauthor) {
        Some(digest) if bytes_out(&signing::sign(&secret, &digest), sig_out) => KQ_FILE_OK,
        _ => KQ_FILE_INVALID,
    }
}

/// Whether `sig` is `coauthor`'s co-signature on the offer under `public`.
///
/// # Safety
/// `offer` readable; `coauthor` NUL-terminated; `public` readable for 32 and
/// `sig` for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn kq_file_coauthor_verify(
    offer: *const KqFileOffer,
    coauthor: *const c_char,
    public: *const u8,
    sig: *const u8,
) -> c_int {
    let (Some(offer), Some(coauthor), Some(public), Some(sig)) = (
        offer.as_ref(),
        input(coauthor),
        bytes_in::<32>(public),
        bytes_in::<64>(sig),
    ) else {
        return KQ_FILE_INVALID;
    };
    if file_history::label_identity(coauthor) == offer.author_identity {
        return KQ_FILE_UNTRUSTED;
    }
    match coauthor_preimage(offer, coauthor)
        .map(|digest| signing::verify_signature(&public, &digest, &sig))
    {
        Some(Ok(())) => KQ_FILE_OK,
        Some(Err(_)) => KQ_FILE_UNTRUSTED,
        None => KQ_FILE_INVALID,
    }
}

/// Adds a co-signature made with [`kq_file_coauthor_sign`] to the container,
/// backing the author signature named in `offer`. Unverified here:
/// [`kq_file_readiness`] checks it.
///
/// # Safety
/// `c` readable for `clen`; `offer` readable; `coauthor` NUL-terminated;
/// `sig` readable for 64; `out` null or writable for `cap`; `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_attach_coauthor(
    c: *const u8,
    clen: usize,
    offer: *const KqFileOffer,
    coauthor: *const c_char,
    sig: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(mut file), Some(offer), Some(coauthor), Some(sig)) = (
        container_in(c, clen),
        offer.as_ref(),
        input(coauthor),
        bytes_in::<64>(sig),
    ) else {
        return KQ_FILE_INVALID;
    };
    let author_hash: [u8; 32] = Sha256::digest(offer.author_signature).into();
    if file
        .attach_coauthor_signature(
            &offer.revision_id,
            &author_hash,
            file_history::label_identity(coauthor),
            coauthor,
            sig,
        )
        .is_err()
    {
        return KQ_FILE_INVALID;
    }
    file_out(&file, out, cap, out_len)
}

/// Judges a co-signed delivery of `rev` to `recipient`: writes how many of
/// the required conditions hold (author signature, trust under the file's
/// policy, the recipient's co-signature) and how many are needed.
/// `KQ_FILE_OK` when it may fire, `KQ_FILE_FORKED` on two heads,
/// `KQ_FILE_BELOW_THRESHOLD` otherwise.
///
/// # Safety
/// `c` readable for `clen`, `rev` for 32; `recipient` NUL-terminated; `trust`
/// as [`KqFileTrust`]; `potential` and `threshold` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_readiness(
    c: *const u8,
    clen: usize,
    rev: *const u8,
    recipient: *const c_char,
    trust: *const KqFileTrust,
    potential: *mut u32,
    threshold: *mut u32,
) -> c_int {
    let (Some(file), Some(rev), Some(recipient), Some(trust)) = (
        container_in(c, clen),
        bytes_in::<32>(rev),
        input(recipient),
        trust_in(trust),
    ) else {
        return KQ_FILE_INVALID;
    };
    if potential.is_null() || threshold.is_null() {
        return KQ_FILE_INVALID;
    }
    let Some(policy) = policy_of(&file) else {
        return KQ_FILE_INVALID;
    };
    let Ok(ready) = delivery_readiness(
        &file,
        &rev,
        &file_history::label_identity(recipient),
        recipient,
        policy,
        &trust,
    ) else {
        return KQ_FILE_NO_REVISION;
    };
    *potential = ready.potential();
    *threshold = DeliveryReadiness::THRESHOLD;
    if ready.forked {
        KQ_FILE_FORKED
    } else if ready.ready() {
        KQ_FILE_OK
    } else {
        KQ_FILE_BELOW_THRESHOLD
    }
}

/// `KQ_FILE_OK` when a supervisor of the file's scope has countersigned `rev` over the author's
/// verified signature, `KQ_FILE_UNTRUSTED` when none has, `KQ_FILE_INVALID` on bad input. A
/// checkpoint requires this before it accepts a newer copy of a file it already holds.
///
/// # Safety
/// `c` readable for `clen`, `rev` for 32; `trust` as [`KqFileTrust`].
#[no_mangle]
pub unsafe extern "C" fn kq_file_permits_newer(
    c: *const u8,
    clen: usize,
    rev: *const u8,
    trust: *const KqFileTrust,
) -> c_int {
    let (Some(file), Some(rev), Some(trust)) =
        (container_in(c, clen), bytes_in::<32>(rev), trust_in(trust))
    else {
        return KQ_FILE_INVALID;
    };
    if supervisor_permits(&file, &rev, &trust) {
        KQ_FILE_OK
    } else {
        KQ_FILE_UNTRUSTED
    }
}

/// Adds `supervisor`'s countersignature over `rev` into `out` (the container with it). The
/// signer is judged later, by [`kq_file_permits_newer`]; this only records the signature.
/// `KQ_FILE_INVALID` when `rev` is unknown, has no verifiable author signature under `trust`, or
/// the input is malformed.
///
/// # Safety
/// `c` readable for `clen`, `rev` for 32, `supervisor` NUL-terminated, `secret` for 32,
/// `trust` as [`KqFileTrust`]; `out` null or writable for `cap`; `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn kq_file_countersign(
    c: *const u8,
    clen: usize,
    rev: *const u8,
    supervisor: *const c_char,
    secret: *const u8,
    trust: *const KqFileTrust,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (Some(mut file), Some(rev), Some(supervisor), Some(secret), Some(trust)) = (
        container_in(c, clen),
        bytes_in::<32>(rev),
        input(supervisor),
        bytes_in::<32>(secret).map(Zeroizing::new),
        trust_in(trust),
    ) else {
        return KQ_FILE_INVALID;
    };
    let identity = file_history::label_identity(supervisor);
    if file
        .countersign_revision_checked(&rev, identity, supervisor, &secret, &trust)
        .is_err()
    {
        return KQ_FILE_INVALID;
    }
    file_out(&file, out, cap, out_len)
}

/// The revision a read at some moment may return: the newest trusted one
/// among the `naccepted` ids the host accepted by then (by its own clock).
/// `KQ_FILE_FORKED` on two heads; `KQ_FILE_NO_REVISION` when none qualifies.
///
/// # Safety
/// `c` readable for `clen`; `trust` as [`KqFileTrust`]; `accepted` readable
/// for `naccepted` 32-byte ids (null when zero); `rev_out` writable for 32.
#[no_mangle]
pub unsafe extern "C" fn kq_file_select_read(
    c: *const u8,
    clen: usize,
    trust: *const KqFileTrust,
    accepted: *const [u8; 32],
    naccepted: usize,
    rev_out: *mut u8,
) -> c_int {
    let (Some(file), Some(trust)) = (container_in(c, clen), trust_in(trust)) else {
        return KQ_FILE_INVALID;
    };
    if naccepted > 0 && accepted.is_null() {
        return KQ_FILE_INVALID;
    }
    let accepted: &[[u8; 32]] = if naccepted == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(accepted, naccepted)
    };
    let Some(policy) = policy_of(&file) else {
        return KQ_FILE_INVALID;
    };
    if file.revisions().is_empty() {
        return KQ_FILE_NO_REVISION;
    }
    if current_revision(&file).is_none() {
        return KQ_FILE_FORKED;
    }
    match latest_trusted_revision_where(&file, policy, &trust, |id| accepted.contains(id)) {
        Some(rev) if bytes_out(&rev, rev_out) => KQ_FILE_OK,
        Some(_) => KQ_FILE_INVALID,
        None => KQ_FILE_NO_REVISION,
    }
}

/// Seals `rev` (with only its ancestors) to `recipient`'s box key, signed by
/// `sender`: the encoded delivery. Refused with `KQ_FILE_UNTRUSTED` unless
/// `rev` is trusted under the file's policy and `trust`. The letter goes to
/// `out`, its delivery id to `delivery_id_out` (16 bytes).
///
/// # Safety
/// `c` readable for `clen`, `rev` for 32, `sender_secret`,
/// `sender_box_public` and `recipient_box_public` for 32; strings
/// NUL-terminated; `out` null or writable for `cap`; `out_len` writable;
/// `delivery_id_out` writable for 16.
#[no_mangle]
pub unsafe extern "C" fn kq_file_seal_letter(
    c: *const u8,
    clen: usize,
    rev: *const u8,
    trust: *const KqFileTrust,
    sender: *const c_char,
    sender_secret: *const u8,
    sender_box_public: *const u8,
    recipient: *const c_char,
    recipient_box_public: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    delivery_id_out: *mut u8,
) -> c_int {
    let (
        Some(file),
        Some(rev),
        Some(trust),
        Some(sender),
        Some(sender_secret),
        Some(sender_box_public),
        Some(recipient),
        Some(recipient_box_public),
    ) = (
        container_in(c, clen),
        bytes_in::<32>(rev),
        trust_in(trust),
        input(sender),
        bytes_in::<32>(sender_secret).map(Zeroizing::new),
        bytes_in::<32>(sender_box_public),
        input(recipient),
        bytes_in::<32>(recipient_box_public),
    )
    else {
        return KQ_FILE_INVALID;
    };
    if delivery_id_out.is_null() {
        return KQ_FILE_INVALID;
    }
    let Some(policy) = policy_of(&file) else {
        return KQ_FILE_INVALID;
    };
    let Ok(decision) = select_shareable_revision(&file, &rev, None, policy, &trust) else {
        return KQ_FILE_NO_REVISION;
    };
    if decision.delivered_revision != Some(rev) {
        return KQ_FILE_UNTRUSTED;
    }
    let (Ok(copy), Ok(content_proof)) =
        (file.extract_revision(&rev), proof_descriptor(&file, &rev))
    else {
        return KQ_FILE_INVALID;
    };
    let Ok(container) = copy.encode() else {
        return KQ_FILE_INVALID;
    };
    let sealed = file_delivery::seal_history_letter(&OutgoingHistory {
        sender_label: sender,
        sender_signing_secret: &sender_secret,
        sender_encryption_public: &sender_box_public,
        recipient_label: recipient,
        recipient_encryption_public: &recipient_box_public,
        file_name: &file.logical_name,
        file_id: file.file_id,
        revision_id: rev,
        history_root: copy.history_root(),
        decision: decision.decision.code(),
        content_proof,
        container: &container,
    });
    let Ok(sealed) = sealed else {
        return KQ_FILE_INVALID;
    };
    let rc = buf_out(&sealed.bytes, out, cap, out_len);
    if rc == KQ_FILE_OK {
        bytes_out(&sealed.delivery_id, delivery_id_out);
    }
    rc
}

/// Opens a letter with the recipient's box secret and checks it: signed by
/// `expected_sender` under `sender_public`, addressed to `expected_recipient`,
/// its container verifying and holding the revision and proofs the signed
/// header names. Writes the container to `out`, the revision to `rev_out` and
/// the history root to `root_out`.
///
/// # Safety
/// `letter` readable for `llen`; `box_secret` and `sender_public` for 32;
/// strings NUL-terminated; `out` null or writable for `cap`; `out_len`
/// writable; `rev_out` and `root_out` writable for 32.
#[no_mangle]
pub unsafe extern "C" fn kq_file_open_letter(
    letter: *const u8,
    llen: usize,
    box_secret: *const u8,
    expected_sender: *const c_char,
    expected_recipient: *const c_char,
    sender_public: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    rev_out: *mut u8,
    root_out: *mut u8,
) -> c_int {
    let (Some(letter), Some(box_secret), Some(sender), Some(recipient), Some(sender_public)) = (
        slice_in(letter, llen),
        bytes_in::<32>(box_secret).map(Zeroizing::new),
        input(expected_sender),
        input(expected_recipient),
        bytes_in::<32>(sender_public),
    ) else {
        return KQ_FILE_INVALID;
    };
    if rev_out.is_null() || root_out.is_null() {
        return KQ_FILE_INVALID;
    }
    let Ok(opened) =
        file_delivery::open_history_letter_with_key(&box_secret, &sender_public, letter)
    else {
        return KQ_FILE_UNTRUSTED;
    };
    if opened.sender_label != sender || opened.recipient_label != recipient {
        return KQ_FILE_UNTRUSTED;
    }
    let Ok(file) = TrackedFile::decode(&opened.container) else {
        return KQ_FILE_INVALID;
    };
    if file.file_id != opened.file_id
        || file.history_root() != opened.history_root
        || file.graph().get(&opened.revision_id).is_none()
        || proof_descriptor(&file, &opened.revision_id).ok() != Some(opened.content_proof)
    {
        return KQ_FILE_UNTRUSTED;
    }
    let rc = buf_out(&opened.container, out, cap, out_len);
    if rc == KQ_FILE_OK {
        bytes_out(&opened.revision_id, rev_out);
        bytes_out(&opened.history_root, root_out);
    }
    rc
}

/// Judges `rev` with history `root` against the `nseen` (revision, root)
/// pairs, 64 bytes each, the caller accepted before for this file. `rev`
/// must be a revision of `c` and `root` its history root, else
/// `KQ_FILE_INVALID`. `KQ_FILE_FIRST`, `KQ_FILE_NEWER`, `KQ_FILE_REPLAYED` or `KQ_FILE_NOT_NEWER`.
///
/// # Safety
/// `seen` readable for `nseen` 64-byte pairs (null when zero); `c` readable
/// for `clen`; `rev` and `root` for 32.
#[no_mangle]
pub unsafe extern "C" fn kq_file_freshness(
    seen: *const [u8; 64],
    nseen: usize,
    c: *const u8,
    clen: usize,
    rev: *const u8,
    root: *const u8,
) -> c_int {
    let (Some(file), Some(rev), Some(root)) = (
        container_in(c, clen),
        bytes_in::<32>(rev),
        bytes_in::<32>(root),
    ) else {
        return KQ_FILE_INVALID;
    };
    if nseen > 0 && seen.is_null() {
        return KQ_FILE_INVALID;
    }
    // The judged pair must be this container's: a revision it holds and its
    // own history root, never metadata the caller supplies apart from it.
    let graph = file.graph();
    if graph.get(&rev).is_none() || root != file.history_root() {
        return KQ_FILE_INVALID;
    }
    let pairs: Vec<([u8; 32], [u8; 32])> = (0..nseen)
        .map(|i| {
            let pair = &*seen.add(i);
            (
                std::array::from_fn(|j| pair[j]),
                std::array::from_fn(|j| pair[32 + j]),
            )
        })
        .collect();
    match file_delivery::freshness_against(
        &pairs,
        &rev,
        &root,
        |id| graph.get(id).is_some(),
        |r| file.passes_through(r),
    ) {
        Freshness::First => KQ_FILE_FIRST,
        Freshness::Newer => KQ_FILE_NEWER,
        Freshness::Replayed => KQ_FILE_REPLAYED,
        Freshness::NotNewer => KQ_FILE_NOT_NEWER,
    }
}

#[cfg(test)]
#[path = "files/tests.rs"]
mod tests;
