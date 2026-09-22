//! Authenticated update envelopes for the two organization changes that
//! private-bridge invites and rotations do not cover: **hardware-key
//! reissue** and **key-tree restructure**.
//!
//! Both ride the same `.kqpb` envelope the mailbox relay already carries
//! (see [`crate::envelope`]), so the relay routes them by recipient
//! fingerprint without learning anything new. The letter inside is sealed
//! to one recipient and signed by an *authorizing* label, so every store
//! can decide on its own whether to apply it.
//!
//! A store accepts an update only when all of these hold:
//!
//! - **Addressed here.** The envelope's recipient public key is an
//!   unrevoked encryption key this store has registered under the
//!   `recipient_label` named inside the letter. A letter re-addressed to
//!   someone else's mailbox therefore fails before it can change anything.
//! - **Authorized.** `authorizer_label` is the subject itself or one of
//!   its ancestors in the dotted label hierarchy (`M` over `M.S` over
//!   `M.S.2`), and this store already holds a registered signing key for
//!   that label. Peers and unrelated branches cannot restructure a tree or
//!   swap someone's token.
//! - **Signed.** An Ed25519 signature over a domain-separated hash that
//!   binds every field *including* the recipient label and the recipient
//!   public key, so no field can be edited and no letter re-targeted.
//! - **In order.** A key reissue must be exactly one past the reissue this
//!   store last applied for that subject; a tree restructure must carry a
//!   public generation strictly greater than the one stored. Replays and
//!   stale envelopes are rejected before any write.
//!
//! Every accepted update is recorded in `org_updates`, which is also the
//! replay guard of last resort: its `UNIQUE (kind, tree_label,
//! subject_label, sequence)` makes a second application of the same update
//! fail at the SQL layer inside the same transaction that would apply it.
//!
//! Convergence follows from the shape of the two letters. A reissue is a
//! delta applied in sequence, so stores that see the same run of reissues
//! end with the same keys. A restructure carries the recipient's whole
//! visible slice at one generation, so a store that missed intermediate
//! restructures still lands on the newest topology in one step.

use crate::envelope::{
    hash_len_prefixed, is_weak_x25519_public_key, push_len_prefixed, push_len_prefixed_u32,
    take_array, take_len_prefixed, take_len_prefixed_u32, take_u32, take_u8, utf8, Addressed,
    KIND_COUNTERSIGNED_TREE, KIND_KEY_REISSUE, KIND_TREE_PROPOSAL, KIND_TREE_UPDATE,
};
use crate::error::{Error, Result};
use crate::key_tree::{self, PublicTree};
use crate::keys::{self, KeyType};
pub use crate::private_bridge::is_ancestor_or_self;
use crate::private_bridge::{self, BridgeSummary};
use crate::signing;
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use serde_json::json;
use sha2::{Digest, Sha256};

const REISSUE_DOMAIN: &[u8] = b"KQORG-KEYREISSUE-v1";
const TREE_DOMAIN: &[u8] = b"KQORG-TREEUPDATE-v1";
const COUNTERSIGN_DOMAIN: &[u8] = b"KQORG-COUNTERSIGN-v1";

const KIND_REISSUE_STR: &str = "key_reissue";
const KIND_TREE_STR: &str = "tree_restructure";

const FLAG_NEW_ENCRYPTION: u8 = 0b001;
const FLAG_NEW_SIGNING: u8 = 0b010;
const FLAG_REVOKE_PREVIOUS: u8 = 0b100;

/// What an accepted update did to this store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppliedUpdate {
    KeyReissue {
        tree_label: String,
        subject_label: String,
        recipient_label: String,
        sequence: u32,
        encryption_rotated: bool,
        signing_rotated: bool,
    },
    TreeRestructure {
        tree_label: String,
        recipient_label: String,
        key_id: i64,
        generation: u32,
        nodes: usize,
    },
    /// Recorded locally, not applied. Effective only after the named parent
    /// countersigns.
    TreeProposal {
        tree_label: String,
        authorizer_label: String,
        countersigner_label: String,
        generation: u32,
        recipients: usize,
    },
}

/// Result of importing one `.kqpb`, whichever kind it turned out to be.
#[derive(Debug)]
pub enum ImportedEnvelope {
    Bridge(BridgeSummary),
    Update(AppliedUpdate),
}

/// One row of the local `org_updates` audit log.
#[derive(Clone, Debug)]
pub struct UpdateRecord {
    pub id: i64,
    pub kind: String,
    pub tree_label: String,
    pub subject_label: String,
    pub sequence: u32,
    pub authorizer_label: String,
    pub detail: String,
    pub applied_at: String,
}

/// A hardware-key reissue ready to deliver: one envelope per affected
/// store, plus the change this store applies when it commits.
#[derive(Debug)]
pub struct PlannedKeyReissue {
    pub packages: Vec<Addressed>,
    letter: ReissueLetter,
}

impl PlannedKeyReissue {
    pub fn subject_label(&self) -> &str {
        &self.letter.subject_label
    }

    pub fn tree_label(&self) -> &str {
        &self.letter.tree_label
    }

    pub fn sequence(&self) -> u32 {
        self.letter.sequence
    }
}

/// A key-tree restructure ready to deliver: one slice envelope per leaf
/// the authorizer has standing over, at the tree's next public generation.
#[derive(Debug)]
pub struct PlannedTreeRestructure {
    pub packages: Vec<Addressed>,
    /// Leaves left without an envelope because `authorizer_label` is not
    /// one of their ancestors — they would reject the letter anyway.
    pub skipped: Vec<String>,
    pub tree_label: String,
    pub generation: u32,
    key_id: i64,
    previous_generation: u32,
    authorizer_label: String,
    /// `true` when the authorizer is not the root. Commit stores a pending
    /// proposal and does not advance `public_generation`.
    pub needs_countersign: bool,
    pub countersigner_label: Option<String>,
    proposals: Vec<Vec<u8>>,
}

/// Countersigned restructure envelopes, ready to deliver. Commit is what
/// advances `public_generation`.
#[derive(Debug)]
pub struct PlannedCountersign {
    pub packages: Vec<Addressed>,
    key_id: i64,
    pub generation: u32,
    previous_generation: u32,
    tree_label: String,
    authorizer_label: String,
    countersigner_label: String,
}

// ---------------------------------------------------------------------
// Hardware-key reissue
// ---------------------------------------------------------------------

/// Build the envelopes that replace `subject_label`'s hardware key across
/// every store that holds it, without touching this database.
///
/// Recipients are the active leaves of `key_id` whose own slice names the
/// subject (when the reissue is scoped to a split tree) plus every party
/// of every live private bridge the subject belongs to — the same stores a
/// bridge rotation notifies. Everyone else never held the key, so telling
/// them would leak a rotation they have no part in.
/// The subject's own envelope is sealed to the **new** encryption key when
/// one is being issued: that is the key their replacement token holds, and
/// the old one may already be gone.
///
/// `revoke_previous` governs the **encryption** key only: whether the
/// retired token is formally revoked everywhere this reissue reaches, or
/// left active alongside the new one. A **signing** key reissue always
/// retires every other active signing key for `subject_label`, regardless
/// of this flag — that key doubles as an authorization identity
/// (`private_bridge::signing_public_for_label`, which every authorizer
/// check in this module and bridge sign/verify go through), and that
/// lookup errors the moment a label has more than one active signing key.
///
/// The caller writes the envelopes, then calls
/// [`commit_planned_key_reissue`], matching how `private_bridge::create`
/// keeps files and database state in step.
#[allow(clippy::too_many_arguments)]
pub fn plan_key_reissue(
    conn: &Connection,
    key_id: Option<i64>,
    subject_label: &str,
    new_encryption_public_key: Option<[u8; 32]>,
    new_signing_public_key: Option<[u8; 32]>,
    revoke_previous: bool,
    authorizer_label: &str,
    authorizer_signing_secret: &[u8; 32],
) -> Result<PlannedKeyReissue> {
    if subject_label.is_empty() || authorizer_label.is_empty() {
        return Err(Error::NodeNotFound);
    }
    if new_encryption_public_key.is_none() && new_signing_public_key.is_none() {
        return Err(Error::InvalidUpdatePackage);
    }
    if !is_ancestor_or_self(authorizer_label, subject_label) {
        return Err(Error::UpdateNotAuthorized);
    }
    if let Some(pk) = new_encryption_public_key.as_ref() {
        if is_weak_x25519_public_key(pk) {
            return Err(Error::InvalidPublicKey);
        }
    }
    if let Some(pk) = new_signing_public_key.as_ref() {
        ed25519_dalek::VerifyingKey::from_bytes(pk).map_err(|_| Error::InvalidPublicKey)?;
    }
    let signing_key = SigningKey::from_bytes(authorizer_signing_secret);
    let authorizer_public = signing_key.verifying_key().to_bytes();
    if private_bridge::signing_public_for_label(conn, authorizer_label)? != authorizer_public {
        return Err(Error::UpdateNotAuthorized);
    }

    let tree_label = match key_id {
        Some(id) => key_tree::tree_label(conn, id)?,
        None => String::new(),
    };
    let sequence = last_sequence(conn, KIND_REISSUE_STR, &tree_label, subject_label)? + 1;

    let letter = ReissueLetter {
        tree_label,
        subject_label: subject_label.to_string(),
        sequence,
        recipient_label: String::new(),
        authorizer_label: authorizer_label.to_string(),
        new_encryption_public_key,
        new_signing_public_key,
        revoke_previous,
        previous_encryption_fingerprint: current_fingerprint(
            conn,
            subject_label,
            KeyType::Encryption,
        )?,
        previous_signing_fingerprint: current_fingerprint(conn, subject_label, KeyType::Signing)?,
    };

    let mut packages = Vec::new();
    for (label, mut recipient_public_key) in reissue_recipients(conn, key_id, subject_label)? {
        // The subject reads this letter on the token that replaced the one
        // being retired, so address theirs to the incoming key.
        if label == subject_label {
            if let Some(new_pk) = new_encryption_public_key {
                recipient_public_key = new_pk;
            }
        }
        let addressed = ReissueLetter {
            recipient_label: label.clone(),
            ..letter.clone()
        };
        packages.push(Addressed {
            bytes: addressed.seal(&recipient_public_key, &signing_key)?,
            label,
            recipient_public_key,
        });
    }

    Ok(PlannedKeyReissue { packages, letter })
}

/// Apply a planned reissue to this store, so the operator who issued the
/// envelopes converges with everyone they were sent to.
pub fn commit_planned_key_reissue(
    conn: &Connection,
    planned: &PlannedKeyReissue,
) -> Result<AppliedUpdate> {
    crate::db::with_immediate_transaction(conn, || apply_reissue(conn, &planned.letter))
}

#[derive(Clone, Debug)]
struct ReissueLetter {
    tree_label: String,
    subject_label: String,
    sequence: u32,
    recipient_label: String,
    authorizer_label: String,
    new_encryption_public_key: Option<[u8; 32]>,
    new_signing_public_key: Option<[u8; 32]>,
    revoke_previous: bool,
    previous_encryption_fingerprint: String,
    previous_signing_fingerprint: String,
}

impl ReissueLetter {
    fn flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.new_encryption_public_key.is_some() {
            flags |= FLAG_NEW_ENCRYPTION;
        }
        if self.new_signing_public_key.is_some() {
            flags |= FLAG_NEW_SIGNING;
        }
        if self.revoke_previous {
            flags |= FLAG_REVOKE_PREVIOUS;
        }
        flags
    }

    fn preimage(&self, recipient_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(REISSUE_DOMAIN);
        hash_len_prefixed(&mut hasher, self.tree_label.as_bytes())?;
        hash_len_prefixed(&mut hasher, self.subject_label.as_bytes())?;
        hasher.update(self.sequence.to_be_bytes());
        hash_len_prefixed(&mut hasher, self.recipient_label.as_bytes())?;
        hasher.update(recipient_public_key);
        hash_len_prefixed(&mut hasher, self.authorizer_label.as_bytes())?;
        hasher.update([self.flags()]);
        if let Some(pk) = self.new_encryption_public_key.as_ref() {
            hasher.update(pk);
        }
        if let Some(pk) = self.new_signing_public_key.as_ref() {
            hasher.update(pk);
        }
        hash_len_prefixed(&mut hasher, self.previous_encryption_fingerprint.as_bytes())?;
        hash_len_prefixed(&mut hasher, self.previous_signing_fingerprint.as_bytes())?;
        Ok(hasher.finalize().into())
    }

    fn seal(&self, recipient_public_key: &[u8; 32], signing_key: &SigningKey) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        push_len_prefixed(&mut payload, self.tree_label.as_bytes())?;
        push_len_prefixed(&mut payload, self.subject_label.as_bytes())?;
        payload.extend_from_slice(&self.sequence.to_be_bytes());
        push_len_prefixed(&mut payload, self.recipient_label.as_bytes())?;
        push_len_prefixed(&mut payload, self.authorizer_label.as_bytes())?;
        payload.push(self.flags());
        if let Some(pk) = self.new_encryption_public_key.as_ref() {
            payload.extend_from_slice(pk);
        }
        if let Some(pk) = self.new_signing_public_key.as_ref() {
            payload.extend_from_slice(pk);
        }
        push_len_prefixed(
            &mut payload,
            self.previous_encryption_fingerprint.as_bytes(),
        )?;
        push_len_prefixed(&mut payload, self.previous_signing_fingerprint.as_bytes())?;
        let preimage = self.preimage(recipient_public_key)?;
        payload.extend_from_slice(&signing::sign(&signing_key.to_bytes(), &preimage));
        crate::envelope::seal(
            crate::envelope::PACKAGE,
            KIND_KEY_REISSUE,
            recipient_public_key,
            &payload,
        )
    }

    fn decode(payload: &[u8]) -> Result<(Self, [u8; 64])> {
        let mut data = payload;
        let tree_label = utf8(take_len_prefixed(&mut data)?)?;
        let subject_label = utf8(take_len_prefixed(&mut data)?)?;
        let sequence = take_u32(&mut data)?;
        let recipient_label = utf8(take_len_prefixed(&mut data)?)?;
        let authorizer_label = utf8(take_len_prefixed(&mut data)?)?;
        let flags = take_u8(&mut data)?;
        if flags & !(FLAG_NEW_ENCRYPTION | FLAG_NEW_SIGNING | FLAG_REVOKE_PREVIOUS) != 0 {
            return Err(Error::InvalidUpdatePackage);
        }
        let new_encryption_public_key = if flags & FLAG_NEW_ENCRYPTION != 0 {
            Some(take_array::<32>(&mut data)?)
        } else {
            None
        };
        let new_signing_public_key = if flags & FLAG_NEW_SIGNING != 0 {
            Some(take_array::<32>(&mut data)?)
        } else {
            None
        };
        let previous_encryption_fingerprint = utf8(take_len_prefixed(&mut data)?)?;
        let previous_signing_fingerprint = utf8(take_len_prefixed(&mut data)?)?;
        let auth_sig = take_array::<64>(&mut data)?;
        if !data.is_empty() {
            return Err(Error::InvalidUpdatePackage);
        }
        if subject_label.is_empty() || recipient_label.is_empty() || authorizer_label.is_empty() {
            return Err(Error::InvalidUpdatePackage);
        }
        if new_encryption_public_key.is_none() && new_signing_public_key.is_none() {
            return Err(Error::InvalidUpdatePackage);
        }
        Ok((
            Self {
                tree_label,
                subject_label,
                sequence,
                recipient_label,
                authorizer_label,
                new_encryption_public_key,
                new_signing_public_key,
                revoke_previous: flags & FLAG_REVOKE_PREVIOUS != 0,
                previous_encryption_fingerprint,
                previous_signing_fingerprint,
            },
            auth_sig,
        ))
    }
}

fn import_reissue(
    conn: &Connection,
    payload: &[u8],
    recipient_public_key: &[u8; 32],
) -> Result<AppliedUpdate> {
    let (letter, auth_sig) = ReissueLetter::decode(payload)?;
    require_addressed_here(conn, &letter.recipient_label, recipient_public_key)?;
    if !is_ancestor_or_self(&letter.authorizer_label, &letter.subject_label) {
        return Err(Error::UpdateNotAuthorized);
    }
    let authorizer_public = authorizer_signing_key(conn, &letter.authorizer_label)?;
    signing::verify_signature(
        &authorizer_public,
        &letter.preimage(recipient_public_key)?,
        &auth_sig,
    )?;

    if letter.sequence
        != last_sequence(
            conn,
            KIND_REISSUE_STR,
            &letter.tree_label,
            &letter.subject_label,
        )? + 1
    {
        return Err(Error::StaleUpdate);
    }
    // A stated previous key must be the key this store actually holds:
    // an envelope minted against a token we already replaced is stale, and
    // silently overwriting a key we never saw retired would hide that.
    require_previous_matches(
        conn,
        &letter.subject_label,
        KeyType::Encryption,
        &letter.previous_encryption_fingerprint,
        letter.new_encryption_public_key.as_ref(),
    )?;
    require_previous_matches(
        conn,
        &letter.subject_label,
        KeyType::Signing,
        &letter.previous_signing_fingerprint,
        letter.new_signing_public_key.as_ref(),
    )?;

    crate::db::with_immediate_transaction(conn, || apply_reissue(conn, &letter))
}

fn apply_reissue(conn: &Connection, letter: &ReissueLetter) -> Result<AppliedUpdate> {
    let scope = leaf_scope(conn, &letter.tree_label)?;

    if let Some(new_pk) = letter.new_encryption_public_key.as_ref() {
        if letter.revoke_previous {
            keys::revoke_superseded(conn, &letter.subject_label, KeyType::Encryption, new_pk)?;
        }
        let new_id =
            register_reissued_key(conn, &letter.subject_label, KeyType::Encryption, new_pk)?;
        match scope {
            LeafScope::Tree(key_id) => key_tree::adopt_reissued_hardware_key(
                conn,
                &letter.subject_label,
                Some(key_id),
                new_id,
            )?,
            LeafScope::NoTree | LeafScope::NoSuchTree => {}
        }
        conn.execute(
            "UPDATE private_bridge_members SET encryption_public_key = ?1
             WHERE node_label = ?2
               AND bridge_id IN (SELECT id FROM private_bridges WHERE destroyed_at IS NULL)",
            params![new_pk.as_slice(), letter.subject_label],
        )?;
    }

    if let Some(new_pk) = letter.new_signing_public_key.as_ref() {
        // Unlike the encryption case, a subject's signing key is also an
        // identity used to authorize *other* updates
        // (`private_bridge::signing_public_for_label`, used by
        // `plan_key_reissue`/`plan_tree_restructure`'s authorizer check and
        // by bridge sign/verify) — and that lookup errors the moment a
        // label has more than one active signing key. `--revoke-previous`
        // stays optional for encryption, where leaving an old token active
        // has no such effect, but a signing reissue always retires every
        // other active signing key for this subject so that identity never
        // becomes ambiguous, whatever the flag says.
        keys::revoke_superseded(conn, &letter.subject_label, KeyType::Signing, new_pk)?;
        register_reissued_key(conn, &letter.subject_label, KeyType::Signing, new_pk)?;
        conn.execute(
            "UPDATE private_bridge_members SET signing_public_key = ?1
             WHERE node_label = ?2 AND role = 'member'
               AND bridge_id IN (SELECT id FROM private_bridges WHERE destroyed_at IS NULL)",
            params![new_pk.as_slice(), letter.subject_label],
        )?;
    }

    record_update(
        conn,
        KIND_REISSUE_STR,
        &letter.tree_label,
        &letter.subject_label,
        letter.sequence,
        &letter.authorizer_label,
        &json!({
            "recipient": letter.recipient_label,
            "encryption_rotated": letter.new_encryption_public_key.is_some(),
            "signing_rotated": letter.new_signing_public_key.is_some(),
            "revoked_previous": letter.revoke_previous,
        })
        .to_string(),
    )?;

    Ok(AppliedUpdate::KeyReissue {
        tree_label: letter.tree_label.clone(),
        subject_label: letter.subject_label.clone(),
        recipient_label: letter.recipient_label.clone(),
        sequence: letter.sequence,
        encryption_rotated: letter.new_encryption_public_key.is_some(),
        signing_rotated: letter.new_signing_public_key.is_some(),
    })
}

/// A leaf's sealed share was wrapped to the retired key, so it is dropped
/// rather than carried onto a token that cannot open it. The holder
/// recovers it from the quorum (or a `bind --public-key-file` reseal).
/// Register the announced key, un-retiring it if this store had revoked
/// those same bytes before — the authority is stating it is current now.
///
/// Unlike `keys::get_or_register`'s general contract, `label` here *is*
/// this subject's identity: every other lookup this module makes for them
/// (`active_keys_for`, `current_fingerprint`, and — if they go on to
/// authorize something — `signing_public_for_label`) is keyed on it.
/// Silently adopting a key already registered under a *different* label
/// would merge that other identity's row onto this subject without
/// renaming it, so those label-keyed lookups would then find nothing for
/// either person.
fn register_reissued_key(
    conn: &Connection,
    label: &str,
    key_type: KeyType,
    public_key: &[u8; 32],
) -> Result<i64> {
    if let Ok(existing) = keys::get_key_by_public_key(conn, public_key) {
        if existing.key_type == key_type {
            if existing.label != label {
                return Err(Error::PublicKeyLabelMismatch);
            }
            if existing.revoked_at.is_some() {
                keys::unrevoke_key(conn, existing.id)?;
            }
        }
    }
    keys::get_or_register(conn, label, key_type, public_key)
}

fn require_previous_matches(
    conn: &Connection,
    label: &str,
    key_type: KeyType,
    stated: &str,
    incoming: Option<&[u8; 32]>,
) -> Result<()> {
    let held = current_fingerprint(conn, label, key_type)?;
    // A store that has never held this person's key of that purpose has
    // nothing to contradict, and the sequence check above already fixes
    // the order updates arrive in.
    if held.is_empty() || stated.is_empty() || held == stated {
        return Ok(());
    }
    // The subject's replacement device registered the incoming key when it
    // generated it — that registration is what lets it open this envelope
    // at all — so the key it holds is the one being announced, not the one
    // being retired.
    if incoming.is_some_and(|pk| keys::fingerprint(pk) == held) {
        return Ok(());
    }
    Err(Error::StaleUpdate)
}

/// Fingerprint of the single unrevoked key of that purpose for `label`, or
/// an empty string when this store holds none. Several unrevoked keys mean
/// the store cannot say which one is being retired, so nothing is stated.
fn current_fingerprint(conn: &Connection, label: &str, key_type: KeyType) -> Result<String> {
    match keys::active_keys_for(conn, label, key_type)?.as_slice() {
        [one] => Ok(one.fingerprint.clone()),
        _ => Ok(String::new()),
    }
}

/// Every store that holds `subject_label`'s public key: the leaves of the
/// split tree whose own slice contains the subject, plus every party of
/// every live private bridge the subject is on.
///
/// Leaves that cannot see the subject are left out on purpose. Their slice
/// never named that person, so an update about them would hand an
/// unrelated branch a public key and a token rotation it has no business
/// learning — and their store would have nothing to apply it to.
fn reissue_recipients(
    conn: &Connection,
    key_id: Option<i64>,
    subject_label: &str,
) -> Result<Vec<(String, [u8; 32])>> {
    let mut found: std::collections::BTreeMap<String, [u8; 32]> = std::collections::BTreeMap::new();

    if let Some(key_id) = key_id {
        for (label, pk) in tree_recipients(conn, key_id)? {
            if !key_tree::visible_labels(conn, key_id, &label)?.contains(subject_label) {
                continue;
            }
            found.entry(label).or_insert(pk);
        }
    }

    for (label, pk) in private_bridge::bridge_notify_targets(conn, subject_label)? {
        insert_recipient(&mut found, label, &pk)?;
    }

    Ok(found.into_iter().collect())
}

fn insert_recipient(
    found: &mut std::collections::BTreeMap<String, [u8; 32]>,
    label: String,
    public_key: &[u8; 32],
) -> Result<()> {
    if is_weak_x25519_public_key(public_key) {
        return Err(Error::InvalidPublicKey);
    }
    found.entry(label).or_insert(*public_key);
    Ok(())
}

// ---------------------------------------------------------------------
// Key-tree restructure
// ---------------------------------------------------------------------

/// Build one envelope per active leaf carrying that leaf's visible slice
/// of the restructured tree, at the tree's next public generation.
///
/// The slice is exactly what `relay pull` would hand that person — own
/// lineage, siblings, descendants, and established-bridge peers — so a
/// store applying it converges on the same subgraph either way. Leaves the
/// authorizer has no standing over are reported in `skipped` rather than
/// handed a letter they would refuse.
///
/// Nothing is written until [`commit_planned_tree_restructure`], which is
/// what advances `keys.public_generation`.
pub fn plan_tree_restructure(
    conn: &Connection,
    key_id: i64,
    authorizer_label: &str,
    authorizer_signing_secret: &[u8; 32],
) -> Result<PlannedTreeRestructure> {
    let signing_key = SigningKey::from_bytes(authorizer_signing_secret);
    let authorizer_public = signing_key.verifying_key().to_bytes();
    if private_bridge::signing_public_for_label(conn, authorizer_label)? != authorizer_public {
        return Err(Error::UpdateNotAuthorized);
    }

    let mut full = key_tree::export_public_tree(conn, key_id)?;
    let previous_generation = full.generation;
    let generation = previous_generation
        .checked_add(1)
        .ok_or(Error::StalePublicTree)?;
    full.generation = generation;
    let tree_label = full.label.clone();
    let countersigner_label =
        crate::authority::restructure_countersigner(authorizer_label).map(str::to_string);
    let kind = if countersigner_label.is_some() {
        KIND_TREE_PROPOSAL
    } else {
        KIND_TREE_UPDATE
    };

    // The export and the arena load are the expensive parts and do not
    // vary by recipient, so they happen once here rather than inside the
    // loop — `visible_labels` would redo both for every leaf.
    let (tree, links) = key_tree::load_for_visibility(conn, key_id)?;

    let mut packages = Vec::new();
    let mut proposals = Vec::new();
    let mut skipped = Vec::new();
    for (label, recipient_public_key) in tree_recipients(conn, key_id)? {
        if !is_ancestor_or_self(authorizer_label, &label) {
            skipped.push(label);
            continue;
        }
        let visible = key_tree::visible_labels_for_links(&tree, &links, &label)?;
        let slice = key_tree::filter_public_tree(&full, &visible);
        let letter = TreeLetter {
            tree_label: tree_label.clone(),
            generation,
            recipient_label: label.clone(),
            authorizer_label: authorizer_label.to_string(),
            slice_json: serde_json::to_vec(&slice).map_err(|_| Error::InvalidTreeSpec)?,
        };
        let payload = letter.encode(&recipient_public_key, &signing_key)?;
        let bytes = crate::envelope::seal(
            crate::envelope::PACKAGE,
            kind,
            &recipient_public_key,
            &payload,
        )?;
        proposals.push(payload);
        packages.push(Addressed {
            bytes,
            label,
            recipient_public_key,
        });
    }

    Ok(PlannedTreeRestructure {
        packages,
        skipped,
        tree_label,
        generation,
        key_id,
        previous_generation,
        authorizer_label: authorizer_label.to_string(),
        needs_countersign: countersigner_label.is_some(),
        countersigner_label,
        proposals,
    })
}

/// Advance this store to the generation the envelopes announce. Refuses if
/// the tree moved on since the plan was built, so the letters already
/// written always describe the generation this store publishes.
pub fn commit_planned_tree_restructure(
    conn: &Connection,
    planned: &PlannedTreeRestructure,
) -> Result<AppliedUpdate> {
    if planned.needs_countersign {
        let countersigner = planned
            .countersigner_label
            .as_deref()
            .ok_or(Error::UpdateNotAuthorized)?;
        return crate::db::with_immediate_transaction(conn, || {
            for proposal in &planned.proposals {
                insert_pending(
                    conn,
                    Some(planned.key_id),
                    &planned.tree_label,
                    &planned.authorizer_label,
                    countersigner,
                    planned.generation,
                    proposal,
                )?;
            }
            Ok(AppliedUpdate::TreeProposal {
                tree_label: planned.tree_label.clone(),
                authorizer_label: planned.authorizer_label.clone(),
                countersigner_label: countersigner.to_string(),
                generation: planned.generation,
                recipients: planned.packages.len(),
            })
        });
    }
    crate::db::with_immediate_transaction(conn, || {
        let updated = conn.execute(
            "UPDATE keys SET public_generation = ?1 WHERE id = ?2 AND public_generation = ?3",
            params![
                i64::from(planned.generation),
                planned.key_id,
                i64::from(planned.previous_generation)
            ],
        )?;
        if updated != 1 {
            return Err(Error::StalePublicTree);
        }
        let nodes: i64 = conn.query_row(
            "SELECT COUNT(*) FROM key_nodes WHERE key_id = ?1",
            params![planned.key_id],
            |row| row.get(0),
        )?;
        record_update(
            conn,
            KIND_TREE_STR,
            &planned.tree_label,
            &planned.tree_label,
            planned.generation,
            &planned.authorizer_label,
            &json!({
                "recipient": planned.tree_label,
                "recipients": planned.packages.len(),
                "skipped": planned.skipped,
            })
            .to_string(),
        )?;
        Ok(AppliedUpdate::TreeRestructure {
            tree_label: planned.tree_label.clone(),
            recipient_label: planned.tree_label.clone(),
            key_id: planned.key_id,
            generation: planned.generation,
            nodes: usize::try_from(nodes).unwrap_or(0),
        })
    })
}

#[derive(Clone, Debug)]
struct TreeLetter {
    tree_label: String,
    generation: u32,
    recipient_label: String,
    authorizer_label: String,
    slice_json: Vec<u8>,
}

impl TreeLetter {
    fn preimage(&self, recipient_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(TREE_DOMAIN);
        hash_len_prefixed(&mut hasher, self.tree_label.as_bytes())?;
        hasher.update(self.generation.to_be_bytes());
        hash_len_prefixed(&mut hasher, self.recipient_label.as_bytes())?;
        hasher.update(recipient_public_key);
        hash_len_prefixed(&mut hasher, self.authorizer_label.as_bytes())?;
        let len = u32::try_from(self.slice_json.len()).map_err(|_| Error::BundleFieldTooLarge)?;
        hasher.update(len.to_be_bytes());
        hasher.update(&self.slice_json);
        Ok(hasher.finalize().into())
    }

    fn encode(&self, recipient_public_key: &[u8; 32], signing_key: &SigningKey) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        push_len_prefixed(&mut payload, self.tree_label.as_bytes())?;
        payload.extend_from_slice(&self.generation.to_be_bytes());
        push_len_prefixed(&mut payload, self.recipient_label.as_bytes())?;
        push_len_prefixed(&mut payload, self.authorizer_label.as_bytes())?;
        push_len_prefixed_u32(&mut payload, &self.slice_json)?;
        let preimage = self.preimage(recipient_public_key)?;
        payload.extend_from_slice(&signing::sign(&signing_key.to_bytes(), &preimage));
        Ok(payload)
    }

    #[cfg(test)]
    fn seal(&self, recipient_public_key: &[u8; 32], signing_key: &SigningKey) -> Result<Vec<u8>> {
        let payload = self.encode(recipient_public_key, signing_key)?;
        crate::envelope::seal(
            crate::envelope::PACKAGE,
            KIND_TREE_UPDATE,
            recipient_public_key,
            &payload,
        )
    }

    fn decode(payload: &[u8]) -> Result<(Self, [u8; 64])> {
        let mut data = payload;
        let tree_label = utf8(take_len_prefixed(&mut data)?)?;
        let generation = take_u32(&mut data)?;
        let recipient_label = utf8(take_len_prefixed(&mut data)?)?;
        let authorizer_label = utf8(take_len_prefixed(&mut data)?)?;
        let slice_json = take_len_prefixed_u32(&mut data)?.to_vec();
        let auth_sig = take_array::<64>(&mut data)?;
        if !data.is_empty() {
            return Err(Error::InvalidUpdatePackage);
        }
        if tree_label.is_empty()
            || recipient_label.is_empty()
            || authorizer_label.is_empty()
            || generation == 0
        {
            return Err(Error::InvalidUpdatePackage);
        }
        Ok((
            Self {
                tree_label,
                generation,
                recipient_label,
                authorizer_label,
                slice_json,
            },
            auth_sig,
        ))
    }
}

fn import_tree_update(
    conn: &Connection,
    payload: &[u8],
    recipient_public_key: &[u8; 32],
) -> Result<AppliedUpdate> {
    let (letter, auth_sig) = TreeLetter::decode(payload)?;
    require_addressed_here(conn, &letter.recipient_label, recipient_public_key)?;
    if !is_ancestor_or_self(&letter.authorizer_label, &letter.recipient_label) {
        return Err(Error::UpdateNotAuthorized);
    }
    let authorizer_public = authorizer_signing_key(conn, &letter.authorizer_label)?;
    signing::verify_signature(
        &authorizer_public,
        &letter.preimage(recipient_public_key)?,
        &auth_sig,
    )?;
    // A non-root authorizer can only propose. A direct KIND_TREE_UPDATE
    // signed by that authorizer alone would skip the parent countersignature.
    if crate::authority::restructure_countersigner(&letter.authorizer_label).is_some() {
        return Err(Error::UpdateNotAuthorized);
    }

    let slice: PublicTree =
        serde_json::from_slice(&letter.slice_json).map_err(|_| Error::InvalidTreeSpec)?;
    if slice.label != letter.tree_label || slice.generation != letter.generation {
        return Err(Error::InvalidUpdatePackage);
    }
    // The recipient must be in their own slice, under the very key this
    // envelope was sealed to — otherwise it describes somebody else's view.
    let node = slice
        .nodes
        .iter()
        .find(|n| n.label == letter.recipient_label)
        .ok_or(Error::UpdateRecipientMismatch)?;
    match node.encryption_public_key.as_deref() {
        Some(hex_pk) if hex::decode(hex_pk).ok().as_deref() == Some(recipient_public_key) => {}
        _ => return Err(Error::UpdateRecipientMismatch),
    }

    let existing = key_tree::tree_by_label(conn, &letter.tree_label)?;
    if let Some((_, stored_generation)) = existing {
        if letter.generation <= stored_generation {
            return Err(Error::StaleUpdate);
        }
    }

    // One transaction over the merge and the audit row: nested
    // `with_immediate_transaction` calls join the outer one, so a
    // duplicate caught by `org_updates` rolls the topology back too.
    let key_id = crate::db::with_immediate_transaction(conn, || {
        let key_id = key_tree::apply_public_tree(conn, existing.map(|(id, _)| id), &slice)?;
        record_update(
            conn,
            KIND_TREE_STR,
            &letter.tree_label,
            &letter.tree_label,
            letter.generation,
            &letter.authorizer_label,
            &json!({
                "recipient": letter.recipient_label,
                "nodes": slice.nodes.len(),
            })
            .to_string(),
        )?;
        Ok(key_id)
    })?;

    Ok(AppliedUpdate::TreeRestructure {
        tree_label: letter.tree_label,
        recipient_label: letter.recipient_label,
        key_id,
        generation: letter.generation,
        nodes: slice.nodes.len(),
    })
}

fn import_tree_proposal(
    conn: &Connection,
    payload: &[u8],
    recipient_public_key: &[u8; 32],
) -> Result<AppliedUpdate> {
    let (letter, auth_sig) = TreeLetter::decode(payload)?;
    verify_tree_letter(conn, &letter, &auth_sig, recipient_public_key)?;
    let countersigner = crate::authority::restructure_countersigner(&letter.authorizer_label)
        .ok_or(Error::UpdateNotAuthorized)?;
    let existing = key_tree::tree_by_label(conn, &letter.tree_label)?;
    if let Some((_, stored_generation)) = existing {
        if letter.generation <= stored_generation {
            return Err(Error::StaleUpdate);
        }
    }
    let countersigner_label = countersigner.to_string();
    insert_pending(
        conn,
        existing.map(|(id, _)| id),
        &letter.tree_label,
        &letter.authorizer_label,
        &countersigner_label,
        letter.generation,
        payload,
    )?;
    Ok(AppliedUpdate::TreeProposal {
        tree_label: letter.tree_label,
        authorizer_label: letter.authorizer_label,
        countersigner_label,
        generation: letter.generation,
        recipients: 1,
    })
}

fn import_countersigned_tree(
    conn: &Connection,
    payload: &[u8],
    recipient_public_key: &[u8; 32],
) -> Result<AppliedUpdate> {
    let (countersigner_label, countersign_sig, inner) = decode_countersigned(payload)?;
    let preimage = countersign_preimage(&inner, &countersigner_label, recipient_public_key)?;
    let countersigner_public = authorizer_signing_key(conn, &countersigner_label)?;
    signing::verify_signature(&countersigner_public, &preimage, &countersign_sig)?;
    let (letter, auth_sig) = TreeLetter::decode(&inner)?;
    if crate::authority::restructure_countersigner(&letter.authorizer_label)
        != Some(countersigner_label.as_str())
    {
        return Err(Error::UpdateNotAuthorized);
    }
    verify_tree_letter(conn, &letter, &auth_sig, recipient_public_key)?;
    apply_tree_letter(conn, &letter, recipient_public_key, &inner)
}

/// Sign every pending proposal for `key_id`. Does not advance the generation;
/// [`commit_planned_countersign`] does that after the envelopes are written.
pub fn plan_restructure_countersign(
    conn: &Connection,
    key_id: i64,
    countersigner_label: &str,
    countersigner_secret: &[u8; 32],
) -> Result<PlannedCountersign> {
    let signing_key = SigningKey::from_bytes(countersigner_secret);
    let countersigner_public = signing_key.verifying_key().to_bytes();
    if private_bridge::signing_public_for_label(conn, countersigner_label)? != countersigner_public
    {
        return Err(Error::UpdateNotAuthorized);
    }
    let pending = load_pending(conn, key_id)?;
    if pending.is_empty() {
        return Err(Error::ProposalNotFound);
    }
    let first = &pending[0];
    if pending.iter().any(|row| {
        row.countersigner_label != countersigner_label
            || row.generation != first.generation
            || row.tree_label != first.tree_label
            || row.authorizer_label != first.authorizer_label
    }) {
        return Err(Error::UpdateNotAuthorized);
    }
    if crate::authority::restructure_countersigner(&first.authorizer_label)
        != Some(countersigner_label)
    {
        return Err(Error::UpdateNotAuthorized);
    }
    let mut packages = Vec::with_capacity(pending.len());
    for row in &pending {
        let (letter, auth_sig) = TreeLetter::decode(&row.proposal)?;
        let recipient_public_key = private_bridge::encryption_public_for_label(
            conn,
            Some(key_id),
            &letter.recipient_label,
        )?;
        verify_tree_letter(conn, &letter, &auth_sig, &recipient_public_key)?;
        let preimage =
            countersign_preimage(&row.proposal, countersigner_label, &recipient_public_key)?;
        let signature = signing::sign(countersigner_secret, &preimage);
        packages.push(Addressed {
            bytes: seal_countersigned(
                &row.proposal,
                countersigner_label,
                &signature,
                &recipient_public_key,
            )?,
            label: letter.recipient_label,
            recipient_public_key,
        });
    }
    let generation = u32::try_from(first.generation).map_err(|_| Error::StalePublicTree)?;
    let previous_generation = generation.checked_sub(1).ok_or(Error::StalePublicTree)?;
    Ok(PlannedCountersign {
        packages,
        key_id,
        generation,
        previous_generation,
        tree_label: first.tree_label.clone(),
        authorizer_label: first.authorizer_label.clone(),
        countersigner_label: countersigner_label.to_string(),
    })
}

pub fn commit_planned_countersign(
    conn: &Connection,
    planned: &PlannedCountersign,
) -> Result<AppliedUpdate> {
    crate::db::with_immediate_transaction(conn, || {
        let updated = conn.execute(
            "UPDATE keys SET public_generation = ?1 WHERE id = ?2 AND public_generation = ?3",
            params![
                i64::from(planned.generation),
                planned.key_id,
                i64::from(planned.previous_generation)
            ],
        )?;
        if updated != 1 {
            return Err(Error::StalePublicTree);
        }
        conn.execute(
            "DELETE FROM pending_org_actions WHERE key_id = ?1",
            params![planned.key_id],
        )?;
        let nodes: i64 = conn.query_row(
            "SELECT COUNT(*) FROM key_nodes WHERE key_id = ?1",
            params![planned.key_id],
            |row| row.get(0),
        )?;
        record_update(
            conn,
            KIND_TREE_STR,
            &planned.tree_label,
            &planned.tree_label,
            planned.generation,
            &planned.countersigner_label,
            &json!({
                "authorizer": planned.authorizer_label,
                "countersigner": planned.countersigner_label,
                "recipients": planned.packages.len(),
            })
            .to_string(),
        )?;
        Ok(AppliedUpdate::TreeRestructure {
            tree_label: planned.tree_label.clone(),
            recipient_label: planned.tree_label.clone(),
            key_id: planned.key_id,
            generation: planned.generation,
            nodes: usize::try_from(nodes).unwrap_or(0),
        })
    })
}

fn verify_tree_letter(
    conn: &Connection,
    letter: &TreeLetter,
    auth_sig: &[u8; 64],
    recipient_public_key: &[u8; 32],
) -> Result<()> {
    require_addressed_here(conn, &letter.recipient_label, recipient_public_key)?;
    if !is_ancestor_or_self(&letter.authorizer_label, &letter.recipient_label) {
        return Err(Error::UpdateNotAuthorized);
    }
    let authorizer_public = authorizer_signing_key(conn, &letter.authorizer_label)?;
    signing::verify_signature(
        &authorizer_public,
        &letter.preimage(recipient_public_key)?,
        auth_sig,
    )?;
    Ok(())
}

fn apply_tree_letter(
    conn: &Connection,
    letter: &TreeLetter,
    recipient_public_key: &[u8; 32],
    proposal: &[u8],
) -> Result<AppliedUpdate> {
    let slice: PublicTree =
        serde_json::from_slice(&letter.slice_json).map_err(|_| Error::InvalidTreeSpec)?;
    if slice.label != letter.tree_label || slice.generation != letter.generation {
        return Err(Error::InvalidUpdatePackage);
    }
    let node = slice
        .nodes
        .iter()
        .find(|n| n.label == letter.recipient_label)
        .ok_or(Error::UpdateRecipientMismatch)?;
    match node.encryption_public_key.as_deref() {
        Some(hex_pk) if hex::decode(hex_pk).ok().as_deref() == Some(recipient_public_key) => {}
        _ => return Err(Error::UpdateRecipientMismatch),
    }
    let existing = key_tree::tree_by_label(conn, &letter.tree_label)?;
    if let Some((_, stored_generation)) = existing {
        if letter.generation <= stored_generation {
            return Err(Error::StaleUpdate);
        }
    }
    let key_id = crate::db::with_immediate_transaction(conn, || {
        let key_id = key_tree::apply_public_tree(conn, existing.map(|(id, _)| id), &slice)?;
        conn.execute(
            "DELETE FROM pending_org_actions WHERE proposal_hash = ?1",
            params![Sha256::digest(proposal).as_slice()],
        )?;
        record_update(
            conn,
            KIND_TREE_STR,
            &letter.tree_label,
            &letter.tree_label,
            letter.generation,
            &letter.authorizer_label,
            &json!({
                "recipient": letter.recipient_label,
                "nodes": slice.nodes.len(),
            })
            .to_string(),
        )?;
        Ok(key_id)
    })?;
    Ok(AppliedUpdate::TreeRestructure {
        tree_label: letter.tree_label.clone(),
        recipient_label: letter.recipient_label.clone(),
        key_id,
        generation: letter.generation,
        nodes: slice.nodes.len(),
    })
}

struct PendingProposal {
    tree_label: String,
    authorizer_label: String,
    countersigner_label: String,
    generation: i64,
    proposal: Vec<u8>,
}

fn load_pending(conn: &Connection, key_id: i64) -> Result<Vec<PendingProposal>> {
    let mut stmt = conn.prepare(
        "SELECT tree_label, authorizer_label, countersigner_label, generation, proposal
         FROM pending_org_actions WHERE key_id = ?1 ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![key_id], |row| {
            Ok(PendingProposal {
                tree_label: row.get(0)?,
                authorizer_label: row.get(1)?,
                countersigner_label: row.get(2)?,
                generation: row.get(3)?,
                proposal: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn insert_pending(
    conn: &Connection,
    key_id: Option<i64>,
    tree_label: &str,
    authorizer_label: &str,
    countersigner_label: &str,
    generation: u32,
    proposal: &[u8],
) -> Result<()> {
    let hash = Sha256::digest(proposal);
    match conn.execute(
        "INSERT INTO pending_org_actions
         (key_id, tree_label, authorizer_label, countersigner_label, generation, proposal_hash, proposal)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            key_id,
            tree_label,
            authorizer_label,
            countersigner_label,
            i64::from(generation),
            hash.as_slice(),
            proposal,
        ],
    ) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(Error::StaleUpdate)
        }
        Err(err) => Err(err.into()),
    }
}

fn countersign_preimage(
    proposal: &[u8],
    countersigner_label: &str,
    recipient_public_key: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(COUNTERSIGN_DOMAIN);
    hasher.update(Sha256::digest(proposal));
    hash_len_prefixed(&mut hasher, countersigner_label.as_bytes())?;
    hasher.update(recipient_public_key);
    Ok(hasher.finalize().into())
}

fn seal_countersigned(
    proposal: &[u8],
    countersigner_label: &str,
    signature: &[u8; 64],
    recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    push_len_prefixed(&mut payload, countersigner_label.as_bytes())?;
    payload.extend_from_slice(signature);
    payload.extend_from_slice(proposal);
    crate::envelope::seal(
        crate::envelope::PACKAGE,
        KIND_COUNTERSIGNED_TREE,
        recipient_public_key,
        &payload,
    )
}

fn decode_countersigned(payload: &[u8]) -> Result<(String, [u8; 64], Vec<u8>)> {
    let mut data = payload;
    let countersigner_label = utf8(take_len_prefixed(&mut data)?)?;
    let signature = take_array(&mut data)?;
    if countersigner_label.is_empty() || data.is_empty() {
        return Err(Error::InvalidUpdatePackage);
    }
    Ok((countersigner_label, signature, data.to_vec()))
}

/// Every active leaf of the tree that has an unrevoked encryption key: the
/// stores that need a slice of the new topology. Goes through
/// [`insert_recipient`] rather than trusting `key_tree::active_encryption_leaves`'s
/// rows to already be one-per-label — that uniqueness is an application
/// invariant, not a database constraint.
fn tree_recipients(conn: &Connection, key_id: i64) -> Result<Vec<(String, [u8; 32])>> {
    let mut found = std::collections::BTreeMap::new();
    for (label, pk) in key_tree::active_encryption_leaves(conn, key_id)? {
        insert_recipient(&mut found, label, &pk)?;
    }
    Ok(found.into_iter().collect())
}

// ---------------------------------------------------------------------
// Import and history
// ---------------------------------------------------------------------

/// Apply one hardware-key-reissue or key-tree-restructure envelope.
pub fn import_update(
    conn: &Connection,
    bytes: &[u8],
    recipient_secret: &[u8; 32],
) -> Result<AppliedUpdate> {
    let (kind, recipient_public_key, payload) = crate::envelope::open(bytes, recipient_secret)?;
    if recipient_public_key != keys::encryption_public_from_secret(recipient_secret) {
        return Err(Error::UpdateRecipientMismatch);
    }
    match kind {
        KIND_KEY_REISSUE => import_reissue(conn, &payload, &recipient_public_key),
        KIND_TREE_UPDATE => import_tree_update(conn, &payload, &recipient_public_key),
        KIND_TREE_PROPOSAL => import_tree_proposal(conn, &payload, &recipient_public_key),
        KIND_COUNTERSIGNED_TREE => import_countersigned_tree(conn, &payload, &recipient_public_key),
        _ => Err(Error::InvalidUpdatePackage),
    }
}

/// Apply any `.kqpb`, dispatching on the kind byte in the outer header:
/// private-bridge invites and rotations go to `private_bridge`, the two
/// update kinds here to [`import_update`]. `relay pull --import` hands
/// every envelope it downloaded to this, since one mailbox carries both.
pub fn import_any(
    conn: &Connection,
    bytes: &[u8],
    recipient_secret: &[u8; 32],
) -> Result<ImportedEnvelope> {
    match crate::envelope::kind(bytes)? {
        KIND_KEY_REISSUE | KIND_TREE_UPDATE | KIND_TREE_PROPOSAL | KIND_COUNTERSIGNED_TREE => Ok(
            ImportedEnvelope::Update(import_update(conn, bytes, recipient_secret)?),
        ),
        _ => Ok(ImportedEnvelope::Bridge(private_bridge::import_package(
            conn,
            bytes,
            recipient_secret,
        )?)),
    }
}

/// Updates this store has applied, oldest first.
pub fn history(conn: &Connection, since_id: Option<i64>) -> Result<Vec<UpdateRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, tree_label, subject_label, sequence, authorizer_label, detail, applied_at
         FROM org_updates WHERE id > ?1 ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![since_id.unwrap_or(0)], |row| {
            Ok(UpdateRecord {
                id: row.get(0)?,
                kind: row.get(1)?,
                tree_label: row.get(2)?,
                subject_label: row.get(3)?,
                sequence: u32::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                authorizer_label: row.get(5)?,
                detail: row.get(6)?,
                applied_at: row.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------

/// The letter names a label; this store must hold that label's unrevoked
/// encryption key, and it must be the key the envelope was sealed to.
fn require_addressed_here(
    conn: &Connection,
    recipient_label: &str,
    recipient_public_key: &[u8; 32],
) -> Result<()> {
    let held = keys::active_keys_for(conn, recipient_label, KeyType::Encryption)?;
    if held
        .iter()
        .any(|key| key.public_key == recipient_public_key)
    {
        Ok(())
    } else {
        Err(Error::UpdateRecipientMismatch)
    }
}

fn authorizer_signing_key(conn: &Connection, authorizer_label: &str) -> Result<[u8; 32]> {
    private_bridge::signing_public_for_label(conn, authorizer_label).map_err(|err| match err {
        // No registered key for that label, or several: either way this
        // store has no basis to accept the authority.
        Error::NodeNotFound | Error::InvalidBridge => Error::UpdateNotAuthorized,
        other => other,
    })
}

/// Which of this store's leaves a reissue may repoint.
enum LeafScope {
    /// The letter names no tree — a bridge-only reissue. `reissue_recipients`
    /// never adds tree leaves to the notify set for this scope (only the
    /// subject's private-bridge peers get an envelope), so no leaf may be
    /// touched here either: repointing one would drop its sealed share and
    /// diverge this store's tree topology from every other store holding
    /// the same tree, none of which received anything to apply.
    NoTree,
    /// The letter names a tree this store has.
    Tree(i64),
    /// The letter names a tree this store does not have. Registering the
    /// new key and updating bridge rosters still applies, but no leaf is
    /// touched: a leaf under some *other* tree was not in the letter's
    /// scope and its token has not been announced as replaced.
    NoSuchTree,
}

fn leaf_scope(conn: &Connection, tree_label: &str) -> Result<LeafScope> {
    if tree_label.is_empty() {
        return Ok(LeafScope::NoTree);
    }
    Ok(match key_tree::tree_by_label(conn, tree_label)? {
        Some((key_id, _)) => LeafScope::Tree(key_id),
        None => LeafScope::NoSuchTree,
    })
}

fn last_sequence(
    conn: &Connection,
    kind: &str,
    tree_label: &str,
    subject_label: &str,
) -> Result<u32> {
    let max: i64 = conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM org_updates
         WHERE kind = ?1 AND tree_label = ?2 AND subject_label = ?3",
        params![kind, tree_label, subject_label],
        |row| row.get(0),
    )?;
    u32::try_from(max).map_err(|_| Error::StaleUpdate)
}

fn record_update(
    conn: &Connection,
    kind: &str,
    tree_label: &str,
    subject_label: &str,
    sequence: u32,
    authorizer_label: &str,
    detail: &str,
) -> Result<()> {
    // The UNIQUE index turns a replay that slipped past the sequence check
    // into a failed transaction rather than a second application.
    conn.execute(
        "INSERT INTO org_updates
            (kind, tree_label, subject_label, sequence, authorizer_label, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            kind,
            tree_label,
            subject_label,
            i64::from(sequence),
            authorizer_label,
            detail
        ],
    )
    .map_err(|err| match err {
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Error::StaleUpdate
        }
        other => Error::Db(other),
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "org_update/tests.rs"]
mod tests;
