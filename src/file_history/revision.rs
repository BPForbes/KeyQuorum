//! Immutable revisions and the DAG they form.
//!
//! `revision_id = SHA-256("KQ-FILE-REVISION-ID-v1" || canonical_body)`. The
//! body commits to the parent revision ids, so a revision cannot be
//! re-parented without changing its identity. This domain is deliberately
//! distinct from the `KQ-FILE-REVISION-v1` content-signature preimage in
//! `signing`, so a revision id can never double as a signed message.

use super::codec::{
    bad, push_opt_array, push_opt_str, push_str, push_u64, take_fixed, take_opt_array,
    take_opt_str, take_str, take_u64,
};
use crate::envelope::{push_len_prefixed_u32, take_len_prefixed_u32};
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const REVISION_ID_DOMAIN: &[u8] = b"KQ-FILE-REVISION-ID-v1";
const CONTENT_DOMAIN: &[u8] = b"KQ-FILE-CONTENT-v1";

/// Author-supplied part of a revision. The content commitment, generated
/// label and id are derived when the revision is checked in.
#[derive(Clone, Debug)]
pub struct NewRevision {
    /// Empty only for the first revision; one for an edit; several for a
    /// merge, in the order the caller wants them recorded.
    pub parent_revision_ids: Vec<[u8; 32]>,
    pub user_label: Option<String>,
    pub author_identity: Option<[u8; 16]>,
    pub author_hcp_label: String,
    pub created_at_utc: String,
    pub topology_generation: u64,
    pub policy_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRevision {
    pub revision_id: [u8; 32],
    pub file_id: [u8; 16],
    pub parent_revision_ids: Vec<[u8; 32]>,
    pub content_commitment: [u8; 32],
    /// `R<normalized-file-name>-<UTC timestamp>-<HCP label>`, always present.
    pub generated_label: String,
    pub user_label: Option<String>,
    pub author_identity: Option<[u8; 16]>,
    pub author_hcp_label: String,
    pub created_at_utc: String,
    pub topology_generation: u64,
    pub policy_hash: [u8; 32],
}

/// A revision with the native bytes it commits to. `payload` is `None` once
/// the file has expired and its content was destroyed; the revision itself
/// (and so the graph and every signature over it) is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRevision {
    pub revision: FileRevision,
    pub payload: Option<Vec<u8>>,
}

/// Commitment to a payload, bound to the file so it is not a globally
/// comparable plaintext fingerprint.
pub fn content_commitment(file_id: &[u8; 16], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_DOMAIN);
    hasher.update(file_id);
    hasher.update(payload);
    hasher.finalize().into()
}

/// `R<normalized-file-name>-<UTC timestamp>-<HCP label>`. The extension is
/// dropped, whitespace, `-` and `_` become single hyphens, other
/// punctuation is removed, and the HCP label keeps its dotted form.
pub fn generated_label(
    logical_name: &str,
    created_at_utc: &str,
    hcp_label: &str,
) -> Result<String> {
    if hcp_label.is_empty() {
        return Err(Error::InvalidTrackedFile);
    }
    Ok(format!(
        "R{}-{}-{}",
        normalize_name(logical_name),
        compact_utc(created_at_utc)?,
        hcp_label
    ))
}

fn normalize_name(name: &str) -> String {
    let stem = match name.rfind('.') {
        Some(index) if index > 0 => &name[..index],
        _ => name,
    };
    let mut out = String::new();
    for c in stem.chars() {
        if c.is_alphanumeric() {
            out.push(c);
        } else if (c.is_whitespace() || c == '-' || c == '_') && !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `2026-10-02T14:32:05.482Z` → `20261002T143205.482Z`. Only UTC (`Z`)
/// timestamps with optional fractional seconds and a real calendar date and
/// clock time are accepted.
fn compact_utc(value: &str) -> Result<String> {
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    let (date, time) = value.split_once('T').ok_or(Error::InvalidTrackedFile)?;
    let time = time.strip_suffix('Z').ok_or(Error::InvalidTrackedFile)?;
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = clock.split(':').collect();
    let shaped = d.len() == 3
        && digits(d[0], 4)
        && digits(d[1], 2)
        && digits(d[2], 2)
        && t.len() == 3
        && t.iter().all(|part| digits(part, 2))
        && fraction
            .is_none_or(|f| !f.is_empty() && f.len() <= 9 && f.bytes().all(|b| b.is_ascii_digit()));
    if !shaped {
        return Err(Error::InvalidTrackedFile);
    }
    // Real calendar and clock ranges; leap seconds are not accepted.
    let number = |s: &str| s.parse::<u32>().unwrap_or(u32::MAX);
    let (year, month, day) = (number(d[0]), number(d[1]), number(d[2]));
    let (hour, minute, second) = (number(t[0]), number(t[1]), number(t[2]));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err(Error::InvalidTrackedFile);
    }
    let mut out = format!("{}{}{}T{}{}{}", d[0], d[1], d[2], t[0], t[1], t[2]);
    if let Some(fraction) = fraction {
        out.push('.');
        out.push_str(fraction);
    }
    out.push('Z');
    Ok(out)
}

impl FileRevision {
    pub(super) fn create(
        file_id: [u8; 16],
        logical_name: &str,
        payload: &[u8],
        new: NewRevision,
    ) -> Result<Self> {
        let generated = generated_label(logical_name, &new.created_at_utc, &new.author_hcp_label)?;
        let mut revision = Self {
            revision_id: [0; 32],
            file_id,
            parent_revision_ids: new.parent_revision_ids,
            content_commitment: content_commitment(&file_id, payload),
            generated_label: generated,
            user_label: new.user_label,
            author_identity: new.author_identity,
            author_hcp_label: new.author_hcp_label,
            created_at_utc: new.created_at_utc,
            topology_generation: new.topology_generation,
            policy_hash: new.policy_hash,
        };
        revision.revision_id = revision.compute_id()?;
        Ok(revision)
    }

    /// True when the generated label is `R<name>-<UTC>-<HCP>` for this
    /// revision's own timestamp and HCP label, with a normalized, non-empty
    /// name in front. The name is not compared with the file's current
    /// logical name: renaming a file must not invalidate older revisions.
    pub(super) fn generated_label_is_consistent(&self) -> bool {
        let Ok(stamp) = compact_utc(&self.created_at_utc) else {
            return false;
        };
        let suffix = format!("-{}-{}", stamp, self.author_hcp_label);
        !self.author_hcp_label.is_empty()
            && self
                .generated_label
                .strip_prefix('R')
                .and_then(|rest| rest.strip_suffix(suffix.as_str()))
                .is_some_and(|name| !name.is_empty() && normalize_name(name) == name)
    }

    /// Canonical encoding of every field except `revision_id`. Parent ids
    /// are written in the recorded order.
    fn body(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.file_id);
        let parents = u16::try_from(self.parent_revision_ids.len())
            .map_err(|_| Error::BundleFieldTooLarge)?;
        out.extend_from_slice(&parents.to_be_bytes());
        for parent in &self.parent_revision_ids {
            out.extend_from_slice(parent);
        }
        out.extend_from_slice(&self.content_commitment);
        push_str(&mut out, &self.generated_label)?;
        push_opt_str(&mut out, self.user_label.as_deref())?;
        push_opt_array(&mut out, self.author_identity.as_ref());
        push_str(&mut out, &self.author_hcp_label)?;
        push_str(&mut out, &self.created_at_utc)?;
        push_u64(&mut out, self.topology_generation);
        out.extend_from_slice(&self.policy_hash);
        Ok(out)
    }

    pub fn compute_id(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(REVISION_ID_DOMAIN);
        hasher.update(self.body()?);
        Ok(hasher.finalize().into())
    }

    fn decode(data: &mut &[u8]) -> Result<Self> {
        let file_id = take_fixed::<16>(data)?;
        let parents = u16::from_be_bytes(take_fixed::<2>(data)?);
        let mut parent_revision_ids = Vec::new();
        for _ in 0..parents {
            parent_revision_ids.push(take_fixed::<32>(data)?);
        }
        let content_commitment = take_fixed::<32>(data)?;
        let generated_label = take_str(data)?;
        let user_label = take_opt_str(data)?;
        let author_identity = take_opt_array::<16>(data)?;
        let author_hcp_label = take_str(data)?;
        let created_at_utc = take_str(data)?;
        let topology_generation = take_u64(data)?;
        let policy_hash = take_fixed::<32>(data)?;
        let revision_id = take_fixed::<32>(data)?;
        Ok(Self {
            revision_id,
            file_id,
            parent_revision_ids,
            content_commitment,
            generated_label,
            user_label,
            author_identity,
            author_hcp_label,
            created_at_utc,
            topology_generation,
            policy_hash,
        })
    }
}

impl StoredRevision {
    /// `present(1) payload` or `absent(0)`; version 4 had no flag and
    /// always carried the payload.
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.revision.body()?);
        out.extend_from_slice(&self.revision.revision_id);
        match &self.payload {
            Some(payload) => {
                out.push(1);
                push_len_prefixed_u32(out, payload)
            }
            None => {
                out.push(0);
                Ok(())
            }
        }
    }

    pub(super) fn decode(data: &mut &[u8], version: u8) -> Result<Self> {
        let revision = FileRevision::decode(data)?;
        let present = if version < 5 {
            true
        } else {
            match take_fixed::<1>(data)?[0] {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidTrackedFile),
            }
        };
        let payload = if present {
            Some(bad(take_len_prefixed_u32(data))?.to_vec())
        } else {
            None
        };
        Ok(Self { revision, payload })
    }

    /// The native bytes, unless they were destroyed at expiry.
    pub fn content(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }
}

/// How an incoming head relates to a local one within one graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadRelation {
    Equal,
    /// The incoming head descends from the local one: a fast-forward
    /// candidate (still subject to trust checks elsewhere).
    IncomingAhead,
    /// The local head already contains the incoming one.
    IncomingBehind,
    /// Neither contains the other: a fork, kept rather than overwritten.
    Diverged,
}

/// Nearest common ancestor of two revisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeBase {
    Unique([u8; 32]),
    /// Several equally near common ancestors (a criss-cross history); no
    /// single base exists, so callers must not guess one.
    Ambiguous,
    None,
}

/// Read-only view of the revision DAG of one tracked file. Revisions are
/// stored parents-first, which `TrackedFile` enforces.
pub struct RevisionGraph<'a> {
    revisions: &'a [StoredRevision],
}

impl<'a> RevisionGraph<'a> {
    pub fn new(revisions: &'a [StoredRevision]) -> Self {
        Self { revisions }
    }

    pub fn get(&self, revision_id: &[u8; 32]) -> Option<&'a StoredRevision> {
        self.revisions
            .iter()
            .find(|stored| &stored.revision.revision_id == revision_id)
    }

    /// Revisions no other revision names as a parent, in storage order.
    /// More than one head means the history has forked.
    pub fn heads(&self) -> Vec<[u8; 32]> {
        let parents: HashSet<&[u8; 32]> = self
            .revisions
            .iter()
            .flat_map(|stored| stored.revision.parent_revision_ids.iter())
            .collect();
        self.revisions
            .iter()
            .map(|stored| stored.revision.revision_id)
            .filter(|id| !parents.contains(id))
            .collect()
    }

    pub fn has_fork(&self) -> bool {
        self.heads().len() > 1
    }

    fn index_of(&self) -> HashMap<[u8; 32], usize> {
        self.revisions
            .iter()
            .enumerate()
            .map(|(i, stored)| (stored.revision.revision_id, i))
            .collect()
    }

    /// True when `ancestor` is `descendant` or reachable from it through
    /// parent links. Unknown ids are never ancestors.
    pub fn is_ancestor_or_self(&self, ancestor: &[u8; 32], descendant: &[u8; 32]) -> bool {
        let index = self.index_of();
        if !index.contains_key(ancestor) {
            return false;
        }
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut stack = vec![*descendant];
        while let Some(id) = stack.pop() {
            if &id == ancestor {
                return true;
            }
            if !seen.insert(id) {
                continue;
            }
            if let Some(&i) = index.get(&id) {
                stack.extend(
                    self.revisions[i]
                        .revision
                        .parent_revision_ids
                        .iter()
                        .copied(),
                );
            }
        }
        false
    }

    /// `id` and every revision reachable from it through parent links, built
    /// in one pass. Use it when many revisions are tested against the same
    /// descendant, instead of calling [`RevisionGraph::is_ancestor_or_self`]
    /// once per revision. Unknown ids give an empty set.
    pub fn ancestor_set(&self, id: &[u8; 32]) -> HashSet<[u8; 32]> {
        let index = self.index_of();
        let marked = self.mark_ancestors(&index, id);
        self.revisions
            .iter()
            .zip(marked)
            .filter(|(_, marked)| *marked)
            .map(|(stored, _)| stored.revision.revision_id)
            .collect()
    }

    /// Marks, by storage index, `id` and everything reachable from it.
    fn mark_ancestors(&self, index: &HashMap<[u8; 32], usize>, id: &[u8; 32]) -> Vec<bool> {
        let mut marked = vec![false; self.revisions.len()];
        let mut stack = vec![*id];
        while let Some(next) = stack.pop() {
            if let Some(&i) = index.get(&next) {
                if !marked[i] {
                    marked[i] = true;
                    stack.extend(
                        self.revisions[i]
                            .revision
                            .parent_revision_ids
                            .iter()
                            .copied(),
                    );
                }
            }
        }
        marked
    }

    /// The nearest common ancestor of `a` and `b`: a common ancestor that is
    /// not itself an ancestor of another common ancestor. Two or more of
    /// those make the base [`MergeBase::Ambiguous`].
    pub fn merge_base(&self, a: &[u8; 32], b: &[u8; 32]) -> MergeBase {
        let index = self.index_of();
        let from_a = self.mark_ancestors(&index, a);
        let from_b = self.mark_ancestors(&index, b);
        // Revisions are stored parents-first, so one reverse pass sees every
        // descendant before its parents: `covered` marks the strict
        // ancestors of any common ancestor.
        let mut covered = vec![false; self.revisions.len()];
        let mut nearest: Vec<[u8; 32]> = Vec::new();
        for i in (0..self.revisions.len()).rev() {
            let common = from_a[i] && from_b[i];
            if common && !covered[i] {
                nearest.push(self.revisions[i].revision.revision_id);
            }
            if common || covered[i] {
                for parent in &self.revisions[i].revision.parent_revision_ids {
                    if let Some(&p) = index.get(parent) {
                        covered[p] = true;
                    }
                }
            }
        }
        match nearest.as_slice() {
            [] => MergeBase::None,
            [only] => MergeBase::Unique(*only),
            _ => MergeBase::Ambiguous,
        }
    }

    /// Structural comparison only; never timestamp-based. Both ids must be
    /// in the graph.
    pub fn compare(&self, local: &[u8; 32], incoming: &[u8; 32]) -> Result<HeadRelation> {
        if self.get(local).is_none() || self.get(incoming).is_none() {
            return Err(Error::InvalidTrackedFile);
        }
        Ok(if local == incoming {
            HeadRelation::Equal
        } else if self.is_ancestor_or_self(local, incoming) {
            HeadRelation::IncomingAhead
        } else if self.is_ancestor_or_self(incoming, local) {
            HeadRelation::IncomingBehind
        } else {
            HeadRelation::Diverged
        })
    }
}
