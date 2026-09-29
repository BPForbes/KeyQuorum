//! Automatic three-way merge of two divergent heads.
//!
//! Only the content merge is new logic here. Ancestry comes from
//! [`RevisionGraph`], the structural checks from `verify`, and trust is left
//! to `policy`: a machine-made merge is a new multi-parent revision with no
//! signatures and starts out untrusted, whatever its parents' proofs were.
//!
//! The strategy is deliberately conservative. Only UTF-8 text is merged,
//! by line, against the nearest common ancestor. Anything else, any
//! overlapping edit, a criss-cross history, a damaged file or a policy that
//! disables auto-merge stops here and is left for a human. HCP seniority
//! never picks a winning line.

use super::container::TrackedFile;
use super::event::{EventDetails, HistoryEventType, HistoryOutcome, NewEvent};
use super::revision::{HeadRelation, MergeBase, NewRevision};
use super::verify::verify_structure;
use crate::error::{Error, Result};

/// Largest diff table (in cells) the line matcher will build.
const MAX_DIFF_CELLS: usize = 4_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoMergeOutcome {
    /// One head already contains the other; nothing to merge.
    FastForward,
    /// Both heads hold identical content.
    AlreadyEquivalent,
    /// The edits combine without touching the same lines.
    CleanMerge,
    RequiresHuman,
    PolicyBlocked,
    UnsupportedContent,
}

/// What a merge attempt decided. `content` is set for `FastForward`
/// (the descendant's bytes), `AlreadyEquivalent` and `CleanMerge`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoMerge {
    pub outcome: AutoMergeOutcome,
    /// Short machine-readable reason, recorded in the history.
    pub reason: &'static str,
    pub merge_base: Option<[u8; 32]>,
    pub content: Option<Vec<u8>>,
    /// The revision made for `AlreadyEquivalent` / `CleanMerge`, once
    /// `TrackedFile::auto_merge` has checked it in.
    pub merge_revision: Option<[u8; 32]>,
}

impl AutoMerge {
    fn stop(outcome: AutoMergeOutcome, reason: &'static str, base: Option<[u8; 32]>) -> Self {
        Self {
            outcome,
            reason,
            merge_base: base,
            content: None,
            merge_revision: None,
        }
    }

    fn with_content(
        outcome: AutoMergeOutcome,
        reason: &'static str,
        base: Option<[u8; 32]>,
        content: Vec<u8>,
    ) -> Self {
        Self {
            outcome,
            reason,
            merge_base: base,
            content: Some(content),
            merge_revision: None,
        }
    }
}

/// One side's change to the base: base lines `start..end` become `lines`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Hunk<'a> {
    start: usize,
    end: usize,
    lines: Vec<&'a str>,
}

impl Hunk<'_> {
    fn is_insertion(&self) -> bool {
        self.start == self.end
    }
}

/// Longest-common-subsequence matches between `a` and `b` as increasing
/// `(index in a, index in b)` pairs. `None` when the table would be too big.
fn matches(a: &[&str], b: &[&str]) -> Option<Vec<(usize, usize)>> {
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ma, mb) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    let (na, nb) = (ma.len(), mb.len());
    if (na + 1).checked_mul(nb + 1)? > MAX_DIFF_CELLS {
        return None;
    }
    let width = nb + 1;
    let mut table = vec![0u32; (na + 1) * width];
    for i in (0..na).rev() {
        for j in (0..nb).rev() {
            table[i * width + j] = if ma[i] == mb[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    let mut pairs: Vec<(usize, usize)> = (0..prefix).map(|i| (i, i)).collect();
    let (mut i, mut j) = (0, 0);
    while i < na && j < nb {
        if ma[i] == mb[j] {
            pairs.push((prefix + i, prefix + j));
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    pairs.extend((0..suffix).map(|k| (a.len() - suffix + k, b.len() - suffix + k)));
    Some(pairs)
}

fn hunks<'a>(base: &[&str], other: &[&'a str]) -> Option<Vec<Hunk<'a>>> {
    let found = matches(base, other)?;
    let (mut bi, mut oi) = (0, 0);
    let mut out = Vec::new();
    for (mb, mo) in found.into_iter().chain([(base.len(), other.len())]) {
        if mb > bi || mo > oi {
            out.push(Hunk {
                start: bi,
                end: mb,
                lines: other[oi..mo].to_vec(),
            });
        }
        bi = mb + 1;
        oi = mo + 1;
    }
    Some(out)
}

/// Whether two hunks touch the same base lines. Changes to adjacent lines
/// do not overlap; two insertions at one point do.
fn overlaps(a: &Hunk, b: &Hunk) -> bool {
    (a.start < b.end && b.start < a.end)
        || (a.is_insertion() && b.is_insertion() && a.start == b.start)
}

/// Whether a line was taken out of the old text or put into the new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Removed,
    Added,
}

/// One changed line. `line` is 1-based: a position in the old text for a
/// removed line and in the new text for an added one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineChange {
    pub kind: ChangeKind,
    pub line: usize,
    pub text: String,
}

/// The lines that differ between `old` and `new`, in order, removals before
/// the additions that replace them. Text keeps its line endings. `None`
/// when the inputs are too large to compare.
pub fn diff_text(old: &str, new: &str) -> Option<Vec<LineChange>> {
    let old_lines: Vec<&str> = old.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let mut out = Vec::new();
    let mut shift: isize = 0;
    for hunk in hunks(&old_lines, &new_lines)? {
        for (offset, text) in old_lines[hunk.start..hunk.end].iter().enumerate() {
            out.push(LineChange {
                kind: ChangeKind::Removed,
                line: hunk.start + offset + 1,
                text: text.to_string(),
            });
        }
        let new_start = (hunk.start as isize + shift) as usize;
        for (offset, text) in hunk.lines.iter().enumerate() {
            out.push(LineChange {
                kind: ChangeKind::Added,
                line: new_start + offset + 1,
                text: text.to_string(),
            });
        }
        shift += hunk.lines.len() as isize - (hunk.end - hunk.start) as isize;
    }
    Some(out)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum TextMerge {
    Clean(String),
    Conflict,
    /// The inputs are too large for the matcher.
    TooLarge,
}

/// Three-way merge by line. Lines keep their terminators, so unrelated
/// bytes (CRLF, trailing spaces, a missing final newline) survive as-is.
pub(super) fn merge_text(base: &str, left: &str, right: &str) -> TextMerge {
    let (b, l, r): (Vec<&str>, Vec<&str>, Vec<&str>) = (
        base.split_inclusive('\n').collect(),
        left.split_inclusive('\n').collect(),
        right.split_inclusive('\n').collect(),
    );
    let (Some(left_hunks), Some(right_hunks)) = (hunks(&b, &l), hunks(&b, &r)) else {
        return TextMerge::TooLarge;
    };
    let mut all: Vec<(Hunk, bool)> = left_hunks
        .into_iter()
        .map(|h| (h, true))
        .chain(right_hunks.into_iter().map(|h| (h, false)))
        .collect();
    all.sort_by(|x, y| (x.0.start, x.0.end, !x.1).cmp(&(y.0.start, y.0.end, !y.1)));

    let mut out = String::new();
    let mut position = 0;
    let mut last: Option<&Hunk> = None;
    for (hunk, _) in &all {
        if let Some(previous) = last {
            if previous == hunk {
                continue; // both sides made exactly this change
            }
            if overlaps(previous, hunk) {
                return TextMerge::Conflict;
            }
        }
        out.extend(b[position..hunk.start].iter().copied());
        out.extend(hunk.lines.iter().copied());
        position = hunk.end;
        last = Some(hunk);
    }
    out.extend(b[position..].iter().copied());
    TextMerge::Clean(out)
}

impl TrackedFile {
    /// Decide what can be done automatically about heads `left` and `right`
    /// without changing anything. `allowed` is the file policy's switch for
    /// automatic merging of a divergence; it does not stop a fast-forward.
    pub fn plan_auto_merge(
        &self,
        left: &[u8; 32],
        right: &[u8; 32],
        allowed: bool,
    ) -> Result<AutoMerge> {
        use AutoMergeOutcome as O;
        let graph = self.graph();
        let payload = |id: &[u8; 32]| graph.get(id).map(|stored| stored.payload.as_slice());
        let (Some(left_bytes), Some(right_bytes)) = (payload(left), payload(right)) else {
            return Err(Error::InvalidTrackedFile);
        };
        if verify_structure(self).is_err() {
            return Ok(AutoMerge::stop(
                O::RequiresHuman,
                "VERIFICATION_FAILED",
                None,
            ));
        }
        match graph.compare(left, right)? {
            HeadRelation::Equal | HeadRelation::IncomingBehind => {
                return Ok(AutoMerge::with_content(
                    O::FastForward,
                    "ANCESTOR_HEAD",
                    Some(*right).filter(|_| left != right),
                    left_bytes.to_vec(),
                ));
            }
            HeadRelation::IncomingAhead => {
                return Ok(AutoMerge::with_content(
                    O::FastForward,
                    "ANCESTOR_HEAD",
                    Some(*left),
                    right_bytes.to_vec(),
                ));
            }
            HeadRelation::Diverged => {
                // A merge only settles a divergence between current heads;
                // merging older revisions would leave the real heads apart.
                let heads = graph.heads();
                if !heads.contains(left) || !heads.contains(right) {
                    return Err(Error::InvalidTrackedFile);
                }
            }
        }
        // The policy switch governs merging a real divergence. A fast-forward
        // (above) merges nothing, so it is never blocked by it.
        if !allowed {
            return Ok(AutoMerge::stop(
                O::PolicyBlocked,
                "AUTO_MERGE_DISABLED",
                None,
            ));
        }
        if left_bytes == right_bytes {
            return Ok(AutoMerge::with_content(
                O::AlreadyEquivalent,
                "IDENTICAL_CONTENT",
                None,
                left_bytes.to_vec(),
            ));
        }
        let base = match graph.merge_base(left, right) {
            MergeBase::Unique(id) => id,
            MergeBase::Ambiguous => {
                return Ok(AutoMerge::stop(
                    O::RequiresHuman,
                    "AMBIGUOUS_MERGE_BASE",
                    None,
                ))
            }
            MergeBase::None => {
                return Ok(AutoMerge::stop(
                    O::RequiresHuman,
                    "NO_COMMON_ANCESTOR",
                    None,
                ))
            }
        };
        let base_bytes = payload(&base).ok_or(Error::InvalidTrackedFile)?;
        let (Ok(b), Ok(l), Ok(r)) = (
            std::str::from_utf8(base_bytes),
            std::str::from_utf8(left_bytes),
            std::str::from_utf8(right_bytes),
        ) else {
            return Ok(AutoMerge::stop(
                O::UnsupportedContent,
                "NOT_UTF8_TEXT",
                Some(base),
            ));
        };
        Ok(match merge_text(b, l, r) {
            TextMerge::Clean(text) => AutoMerge::with_content(
                O::CleanMerge,
                "THREE_WAY_TEXT",
                Some(base),
                text.into_bytes(),
            ),
            TextMerge::Conflict => {
                AutoMerge::stop(O::RequiresHuman, "OVERLAPPING_EDIT", Some(base))
            }
            TextMerge::TooLarge => AutoMerge::stop(O::UnsupportedContent, "TOO_LARGE", Some(base)),
        })
    }

    /// Run [`TrackedFile::plan_auto_merge`] and record it. A clean or
    /// equivalent result is checked in as a new revision with `left` and
    /// `right` as its parents (in that order) and no proofs, so it is
    /// pending until the normal trust policy approves it. `new` supplies
    /// the author, time, generation and policy; its parents are replaced.
    /// A fast-forward adds no revision. Either everything is recorded or,
    /// on error, nothing is. A divergent pair must be current heads.
    pub fn auto_merge(
        &mut self,
        left: &[u8; 32],
        right: &[u8; 32],
        allowed: bool,
        new: NewRevision,
    ) -> Result<AutoMerge> {
        self.atomically(|file| file.auto_merge_steps(left, right, allowed, new))
    }

    /// Run a multi-step change and put back the revisions, proofs and events
    /// as they were if any step fails, so a half-recorded change is never
    /// left behind.
    pub(super) fn atomically<T>(
        &mut self,
        steps: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let (revisions, proofs, events) =
            (self.revisions.len(), self.proofs.len(), self.events.len());
        let result = steps(self);
        if result.is_err() {
            self.revisions.truncate(revisions);
            self.proofs.truncate(proofs);
            self.events.truncate(events);
        }
        result
    }

    fn auto_merge_steps(
        &mut self,
        left: &[u8; 32],
        right: &[u8; 32],
        allowed: bool,
        mut new: NewRevision,
    ) -> Result<AutoMerge> {
        use AutoMergeOutcome as O;
        let mut result = self.plan_auto_merge(left, right, allowed)?;
        let (actor, label, at, generation) = (
            new.author_identity,
            new.author_hcp_label.clone(),
            new.created_at_utc.clone(),
            new.topology_generation,
        );
        if let (O::CleanMerge | O::AlreadyEquivalent, Some(content)) =
            (result.outcome, result.content.clone())
        {
            new.parent_revision_ids = vec![*left, *right];
            result.merge_revision = Some(self.check_in(new, content)?);
        }
        let event = |kind, revision_id, details: EventDetails| NewEvent {
            revision_id,
            occurred_at: at.clone(),
            actor_identity: actor,
            actor_label: Some(label.clone()),
            topology_generation: Some(generation),
            event_type: kind,
            outcome: HistoryOutcome::Info,
            details,
        };
        let hex_of = |id: &[u8; 32]| hex::encode(id);
        let mut attempt = EventDetails::new()
            .with("left", &hex_of(left))
            .with("right", &hex_of(right));
        if let Some(base) = &result.merge_base {
            attempt = attempt.with("base", &hex_of(base));
        }
        self.append(event(HistoryEventType::AutoMergeAttempted, None, attempt))?;
        let (kind, revision, outcome) = match result.outcome {
            O::FastForward => (
                HistoryEventType::AutoMergeFastForward,
                None,
                HistoryOutcome::Success,
            ),
            O::AlreadyEquivalent => (
                HistoryEventType::AutoMergeEquivalent,
                result.merge_revision,
                HistoryOutcome::Success,
            ),
            O::CleanMerge => (
                HistoryEventType::AutoMergeClean,
                result.merge_revision,
                HistoryOutcome::Success,
            ),
            O::PolicyBlocked | O::UnsupportedContent => (
                HistoryEventType::AutoMergeBlocked,
                None,
                HistoryOutcome::Denied,
            ),
            O::RequiresHuman => (
                HistoryEventType::AutoMergeRequiresHuman,
                None,
                HistoryOutcome::Denied,
            ),
        };
        let mut done = event(
            kind,
            revision,
            EventDetails::new().with("reason", result.reason),
        );
        if revision.is_some() {
            done.details = done.details.with("trust_state", "PENDING");
        }
        done.outcome = outcome;
        self.append(done)?;
        Ok(result)
    }
}
