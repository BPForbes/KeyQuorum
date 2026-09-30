//! What the interactive review shows, and how keys move around it. No
//! terminal and no dependencies live here: [`ReviewView`] is built from the
//! same `file_history` calls `keyquorum file review` prints, and
//! [`ReviewState`] is a pure key handler over it. The terminal shell
//! (`review_tui`, feature `tui`) only draws it. Nothing here decides trust
//! or edits a history: commands that would (`:sign`, `:accept`, `:finalize`)
//! answer with the CLI command to run instead.

// The key handler and state are driven by the terminal shell (feature `tui`)
// and by the tests; `ReviewView` is what `keyquorum file review` prints too.
#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use crate::file_history::{
    apply_hunks, diff_hunks, diff_text, ChangeKind, DiffHunk, MergeBase, TrackedFile,
};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewLine {
    pub kind: ChangeKind,
    /// 1-based, in the old text for a removal and the new text for an add.
    pub number: usize,
    pub text: String,
    /// Which change on this side the line belongs to (counting from 0): a
    /// removal and the additions that replace it are one hunk.
    pub hunk: usize,
    /// An unchanged line shown for orientation around a change. It is not
    /// part of any diff: the printed review leaves it out, and the
    /// interactive one can hide it.
    pub context: bool,
    /// Who authored the revision this side's change belongs to.
    pub provenance: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pane {
    pub heading: String,
    pub revision: String,
    pub lines: Vec<ViewLine>,
    /// This side's changes to the common ancestor, by `ViewLine::hunk`; the
    /// ones a person can pick from when composing a result.
    pub hunks: Vec<DiffHunk>,
    /// Why there are no lines, when there are none to show.
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReviewView {
    pub title: String,
    pub panes: Vec<Pane>,
    /// The common ancestor's text, when there is a single one and it is
    /// UTF-8: what the picked hunks are applied to.
    pub base_text: Option<String>,
    /// Merge outcome and who reviews it: filled by the caller from
    /// `file_history` (it needs the store's keys), empty until then.
    pub status: Vec<String>,
}

fn short(id: &[u8; 32]) -> String {
    hex::encode(&id[..6])
}

fn describe(file: &TrackedFile, id: &[u8; 32]) -> String {
    file.graph()
        .get(id)
        .map(|stored| {
            let r = &stored.revision;
            // The user label first when there is one, then the generated
            // label and the short hash.
            let user = r
                .user_label
                .as_deref()
                .map(|label| format!("{label} · "))
                .unwrap_or_default();
            format!(
                "{} · {user}{} {} · {}",
                r.author_hcp_label,
                r.generated_label,
                short(id),
                r.created_at_utc
            )
        })
        .unwrap_or_default()
}

fn text(file: &TrackedFile, id: &[u8; 32]) -> Option<String> {
    let stored = file.graph().get(id)?;
    String::from_utf8(stored.content()?.to_vec()).ok()
}

/// Which revision on one side wrote each line of its diff from the merge
/// base. The side's first-parent chain is replayed one revision at a time:
/// a line a step adds belongs to that step's revision, and a line the step
/// removes from the base is removed by it. `None` (so the caller falls back
/// to the head) when the chain does not reach the base, is not text, or is
/// too large to compare.
struct Blame {
    /// New-text line number (1-based) -> the revision that wrote it.
    added_by: HashMap<usize, [u8; 32]>,
    /// Base-text line number (1-based) -> the revision that removed it.
    removed_by: HashMap<usize, [u8; 32]>,
}

fn blame(file: &TrackedFile, base: &[u8; 32], head: &[u8; 32]) -> Option<Blame> {
    let graph = file.graph();
    let mut chain = Vec::new();
    let mut at = *head;
    while at != *base {
        chain.push(at);
        at = *graph.get(&at)?.revision.parent_revision_ids.first()?;
    }
    chain.reverse();

    #[derive(Clone)]
    struct Origin {
        rev: Option<[u8; 32]>,
        base_line: Option<usize>,
    }
    let mut previous = text(file, base)?;
    let mut current: Vec<Origin> = (1..=previous.split_inclusive('\n').count())
        .map(|n| Origin {
            rev: None,
            base_line: Some(n),
        })
        .collect();
    let mut removed_by = HashMap::new();
    for id in chain {
        let next = text(file, &id)?;
        let changes = diff_text(&previous, &next)?;
        let removed: HashSet<usize> = changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Removed)
            .map(|c| c.line)
            .collect();
        let added: HashSet<usize> = changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Added)
            .map(|c| c.line)
            .collect();
        for line in &removed {
            if let Some(base_line) = current.get(line - 1).and_then(|o| o.base_line) {
                removed_by.insert(base_line, id);
            }
        }
        let mut carried = Vec::new();
        let mut old = 0usize;
        for n in 1..=next.split_inclusive('\n').count() {
            if added.contains(&n) {
                carried.push(Origin {
                    rev: Some(id),
                    base_line: None,
                });
                continue;
            }
            while removed.contains(&(old + 1)) {
                old += 1;
            }
            carried.push(current.get(old)?.clone());
            old += 1;
        }
        current = carried;
        previous = next;
    }
    let added_by = current
        .iter()
        .enumerate()
        .filter_map(|(i, o)| o.rev.map(|rev| (i + 1, rev)))
        .collect();
    Some(Blame {
        added_by,
        removed_by,
    })
}

/// Unchanged lines kept on each side of a change, for orientation.
const CONTEXT_LINES: usize = 2;

/// `changed` (grouped by hunk, in order) with up to [`CONTEXT_LINES`]
/// unchanged lines of the new text before and after each change. Lines two
/// changes are close enough to share are shown once, after the earlier one.
fn with_context(new: &str, hunks: &[DiffHunk], changed: Vec<ViewLine>) -> Vec<ViewLine> {
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let context = |index: usize, hunk: usize| ViewLine {
        kind: ChangeKind::Added,
        number: index + 1,
        text: new_lines[index].trim_end_matches('\n').to_string(),
        hunk,
        context: true,
        provenance: "unchanged since the common ancestor".to_string(),
    };
    // Where each change starts and ends in the new text.
    let mut spans = Vec::with_capacity(hunks.len());
    let mut shift: isize = 0;
    for hunk in hunks {
        let start = (hunk.start as isize + shift).max(0) as usize;
        spans.push((start, start + hunk.lines.len()));
        shift += hunk.lines.len() as isize - (hunk.end - hunk.start) as isize;
    }
    let mut out = Vec::with_capacity(changed.len());
    let mut lines = changed.into_iter().peekable();
    let mut emitted = 0usize;
    for (index, (start, end)) in spans.iter().copied().enumerate() {
        for line in emitted.max(start.saturating_sub(CONTEXT_LINES))..start.min(new_lines.len()) {
            out.push(context(line, index));
        }
        while lines.peek().is_some_and(|line| line.hunk == index) {
            out.extend(lines.next());
        }
        emitted = end;
        let limit = spans
            .get(index + 1)
            .map_or(new_lines.len(), |next| next.0)
            .min(end + CONTEXT_LINES);
        for line in end..limit.min(new_lines.len()) {
            out.push(context(line, index));
        }
        emitted = emitted.max(limit.min(new_lines.len()));
    }
    out.extend(lines);
    out
}

/// One side of a review: the lines `id` changed since `base`, each with the
/// revision on that side that wrote it (the head describes any line the
/// replay cannot place).
fn side_pane(file: &TrackedFile, base: Option<[u8; 32]>, side: &str, id: &[u8; 32]) -> Pane {
    let provenance = describe(file, id);
    let hunks = match base.map(|base| (text(file, &base), text(file, id))) {
        Some((Some(old), Some(new))) => diff_hunks(&old, &new).unwrap_or_default(),
        _ => Vec::new(),
    };
    let (lines, note) = match base {
        None => (
            Vec::new(),
            Some("no single common ancestor: no line view".to_string()),
        ),
        Some(base) => match (text(file, &base), text(file, id)) {
            (Some(old), Some(new)) => match diff_text(&old, &new) {
                Some(changes) if changes.is_empty() => {
                    (Vec::new(), Some("no changed lines".to_string()))
                }
                Some(changes) => {
                    let blame = blame(file, &base, id);
                    let who = |line: &crate::file_history::LineChange| {
                        blame
                            .as_ref()
                            .and_then(|b| match line.kind {
                                ChangeKind::Added => b.added_by.get(&line.line),
                                ChangeKind::Removed => b.removed_by.get(&line.line),
                            })
                            .map(|rev| describe(file, rev))
                            .unwrap_or_else(|| provenance.clone())
                    };
                    let changed: Vec<ViewLine> = changes
                        .iter()
                        .map(|c| ViewLine {
                            kind: c.kind,
                            number: c.line,
                            text: c.text.trim_end_matches('\n').to_string(),
                            hunk: c.hunk,
                            context: false,
                            provenance: who(c),
                        })
                        .collect();
                    (with_context(&new, &hunks, changed), None)
                }
                None => (
                    Vec::new(),
                    Some("too large to compare: no line view".to_string()),
                ),
            },
            _ => (Vec::new(), Some("not UTF-8 text: no line view".to_string())),
        },
    };
    Pane {
        heading: side.to_string(),
        revision: provenance,
        lines,
        hunks,
        note,
    }
}

impl ReviewView {
    /// The two sides of a forked history, each as the lines it changed
    /// since the unique common ancestor; or, when the only head is a
    /// two-parent merge, its two parents and the merged result (see
    /// [`ReviewView::pending_merge`]). `None` for any other shape.
    pub fn of(file: &TrackedFile) -> Option<Self> {
        let heads = file.graph().heads();
        let [left, right] = match heads.as_slice() {
            [left, right] => [left, right],
            [head] => return Self::pending_merge(file, head),
            _ => return None,
        };
        let base = match file.graph().merge_base(left, right) {
            MergeBase::Unique(id) => Some(id),
            _ => None,
        };
        Some(Self {
            title: format!("{} — merge review", file.logical_name),
            base_text: base.and_then(|base| text(file, &base)),
            panes: vec![
                side_pane(file, base, "LEFT", left),
                side_pane(file, base, "RIGHT", right),
            ],
            status: Vec::new(),
        })
    }

    /// The merge revision waiting at a sole head: what each parent changed
    /// since the common ancestor, and what the merge itself changed, so a
    /// person can review a clean merge before it is signed. `None` unless
    /// `head` has exactly two parents.
    pub fn pending_merge(file: &TrackedFile, head: &[u8; 32]) -> Option<Self> {
        let parents = &file.graph().get(head)?.revision.parent_revision_ids;
        let [left, right] = parents.as_slice() else {
            return None;
        };
        let base = match file.graph().merge_base(left, right) {
            MergeBase::Unique(id) => Some(id),
            _ => None,
        };
        Some(Self {
            title: format!("{} — merge review", file.logical_name),
            base_text: base.and_then(|base| text(file, &base)),
            panes: vec![
                side_pane(file, base, "LEFT PARENT", left),
                side_pane(file, base, "RIGHT PARENT", right),
                side_pane(file, base, "MERGED", head),
            ],
            status: Vec::new(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Ctrl(char),
    Enter,
    Esc,
    Tab,
    BackTab,
    Backspace,
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
}

/// A command the review hands to the shell to run for the person, as the
/// label and slot they gave. The shell runs the real `keyquorum file`
/// command, which is where authority is judged: nothing here decides it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// `file resolve --keep left`
    KeepLeft,
    /// `file resolve --keep right`
    KeepRight,
    /// `file resolve --from`, with this text as the merge result
    Result(String),
    /// `file resolve --reject`
    Reject,
    /// `file sign`
    Sign,
    /// `file finalize`
    Finalize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    Quit,
    Message(String),
    /// Let the person edit this text in their editor; the shell hands the
    /// result back through [`ReviewState::set_edited`].
    Edit(String),
    /// Run this command as the person; see [`Action`].
    Run(Action),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Command,
    Search,
}

pub struct ReviewState {
    pub view: ReviewView,
    pub pane: usize,
    cursors: Vec<usize>,
    hover: Option<usize>,
    pub mode: Mode,
    pub command: String,
    search: Option<String>,
    pending_g: bool,
    pending_z: bool,
    /// Hunks folded to a single line, per side.
    folded: Vec<HashSet<usize>>,
    /// Whether unchanged context lines are shown (`c` toggles).
    show_context: bool,
    /// Changes picked to build a result from, per side.
    picked: Vec<HashSet<usize>>,
    /// The text the person edited; it replaces the picked changes.
    edited: Option<String>,
    /// Who the person says they are: the label, and the `container=label`
    /// slot that proves it when a command signs.
    as_label: Option<String>,
    slot: Option<String>,
}

const HELP: &str = "j/k move · gg/G ends · Ctrl-d/u page · Tab or h/l switch side · \
/ search · n/N repeat · za/zc/zo fold a change · zM/zR fold or open all · Space pick a change · c context · \
:compose :edit :as :slot :accept :reject :sign :finalize :q · hover a line for who wrote it";

/// What to run when the review cannot act for the person (no `:as` and
/// `:slot` yet, or a command it never performs).
fn guidance(command: &str) -> Option<&'static str> {
    Some(match command {
        "sign" => "needs :as LABEL and :slot CONTAINER=LABEL first; or run `keyquorum file sign` as the author",
        "countersign" => "not available here: run `keyquorum file countersign` as the supervisor",
        "accept" => {
            "needs :as LABEL and :slot CONTAINER=LABEL first; or, as the reviewer, run `keyquorum file resolve --keep left|right` or `--from FILE`"
        }
        "reject" => {
            "needs :as LABEL and :slot CONTAINER=LABEL first; or, as the reviewer, run `keyquorum file resolve --reject` on a proposed merge"
        }
        "finalize" => {
            "needs :as LABEL and :slot CONTAINER=LABEL first; or, once the revision is trusted, run `keyquorum file finalize` as the scope owner"
        }
        _ => return None,
    })
}

impl ReviewState {
    pub fn new(view: ReviewView) -> Self {
        let panes = view.panes.len();
        Self {
            view,
            pane: 0,
            cursors: vec![0; panes],
            hover: None,
            mode: Mode::Normal,
            command: String::new(),
            search: None,
            pending_g: false,
            pending_z: false,
            folded: vec![HashSet::new(); panes],
            show_context: true,
            picked: vec![HashSet::new(); panes],
            edited: None,
            as_label: None,
            slot: None,
        }
    }

    fn lines(&self) -> usize {
        self.view.panes[self.pane].lines.len()
    }

    /// The lines of `pane` that are shown: all of them (context only while
    /// it is switched on), except that a folded change shows only its first
    /// changed line.
    pub fn visible(&self, pane: usize) -> Vec<usize> {
        let lines = &self.view.panes[pane].lines;
        let mut shown = Vec::with_capacity(lines.len());
        let mut headed: HashSet<usize> = HashSet::new();
        for (index, line) in lines.iter().enumerate() {
            if line.context && !self.show_context {
                continue;
            }
            let folded = self.folded[pane].contains(&line.hunk);
            // A fold keeps one line: the first changed line of the change.
            if !folded || (!line.context && headed.insert(line.hunk)) {
                shown.push(index);
            }
        }
        shown
    }

    /// How many lines the fold at `index` hides, when that line is the one
    /// a folded change keeps.
    pub fn fold_hidden(&self, pane: usize, index: usize) -> Option<usize> {
        let lines = &self.view.panes[pane].lines;
        let hunk = lines.get(index)?.hunk;
        if !self.folded[pane].contains(&hunk) || lines[index].context {
            return None;
        }
        let first_changed = lines.iter().position(|l| l.hunk == hunk && !l.context)?;
        if first_changed != index {
            return None;
        }
        let total = lines
            .iter()
            .filter(|l| l.hunk == hunk && (self.show_context || !l.context))
            .count();
        Some(total - 1)
    }

    /// The change the cursor is in.
    fn hunk_at_cursor(&self) -> Option<usize> {
        self.view.panes[self.pane]
            .lines
            .get(self.cursor())
            .map(|line| line.hunk)
    }

    fn set_fold(&mut self, hunk: usize, fold: bool) {
        if fold {
            self.folded[self.pane].insert(hunk);
        } else {
            self.folded[self.pane].remove(&hunk);
        }
        // A cursor inside a fold moves to the fold's line.
        let index = self.cursor();
        self.move_to(index);
    }

    /// Whether the change at line `index` of `pane` is picked.
    pub fn is_picked(&self, pane: usize, index: usize) -> bool {
        self.view.panes[pane]
            .lines
            .get(index)
            .is_some_and(|line| self.picked[pane].contains(&line.hunk))
    }

    /// How many changes are picked across both sides.
    pub fn picked_count(&self) -> usize {
        self.picked.iter().map(HashSet::len).sum()
    }

    fn toggle_pick(&mut self) -> Effect {
        let pane = &self.view.panes[self.pane];
        if pane.hunks.is_empty() || self.view.base_text.is_none() {
            return Effect::Message("nothing to pick: this side has no line changes".to_string());
        }
        let Some(hunk) = self.hunk_at_cursor() else {
            return Effect::None;
        };
        if !self.picked[self.pane].remove(&hunk) {
            self.picked[self.pane].insert(hunk);
        }
        Effect::Message(format!(
            "{} change(s) picked; :compose shows the result",
            self.picked_count()
        ))
    }

    /// The text the person has settled on: what they edited, else the
    /// common ancestor with the picked changes applied. Never a decision:
    /// the result is only ever handed to `file resolve`.
    pub fn compose(&self) -> Result<String, String> {
        if let Some(text) = &self.edited {
            return Ok(text.clone());
        }
        let Some(base) = &self.view.base_text else {
            return Err("no single UTF-8 common ancestor to build a result from".to_string());
        };
        if self.picked_count() == 0 {
            return Err("nothing picked: Space picks the change under the cursor".to_string());
        }
        let chosen: Vec<&DiffHunk> = self
            .view
            .panes
            .iter()
            .zip(&self.picked)
            .flat_map(|(pane, picked)| picked.iter().filter_map(|hunk| pane.hunks.get(*hunk)))
            .collect();
        apply_hunks(base, &chosen)
            .ok_or_else(|| "the picked changes overlap: unpick one of them".to_string())
    }

    /// What `:edit` opens: the current result if there is one, else the
    /// common ancestor.
    fn edit_text(&self) -> Result<String, String> {
        match self.compose() {
            Ok(text) => Ok(text),
            Err(_) => self
                .view
                .base_text
                .clone()
                .ok_or_else(|| "no UTF-8 common ancestor to edit".to_string()),
        }
    }

    /// Say who is acting, before any command that signs. Both are only what
    /// the person typed; the command they lead to checks them.
    pub fn with_identity(mut self, as_label: Option<String>, slot: Option<String>) -> Self {
        self.as_label = as_label;
        self.slot = slot;
        self
    }

    /// The label and slot given, when both are.
    pub fn identity(&self) -> Option<(&str, &str)> {
        Some((self.as_label.as_deref()?, self.slot.as_deref()?))
    }

    /// Replace the view after a command changed the history: what was
    /// picked, edited or folded no longer applies.
    pub fn reload(&mut self, view: ReviewView) {
        let (as_label, slot) = (self.as_label.take(), self.slot.take());
        *self = Self::new(view).with_identity(as_label, slot);
    }

    fn act(&mut self, action: Action) -> Effect {
        if self.identity().is_none() {
            return Effect::Message(
                match action {
                    Action::KeepLeft | Action::KeepRight | Action::Result(_) => guidance("accept"),
                    Action::Reject => guidance("reject"),
                    Action::Sign => guidance("sign"),
                    Action::Finalize => guidance("finalize"),
                }
                .unwrap_or_default()
                .to_string(),
            );
        }
        Effect::Run(action)
    }

    /// `:accept left|right|result`: settle the conflict with a side, or
    /// with the text built by picking changes or by editing.
    fn accept(&mut self, choice: &str) -> Effect {
        match choice {
            "left" => self.act(Action::KeepLeft),
            "right" => self.act(Action::KeepRight),
            "result" | "picked" | "edited" => match self.compose() {
                Ok(text) => self.act(Action::Result(text)),
                Err(reason) => Effect::Message(reason),
            },
            _ => Effect::Message("usage: :accept left | right | result".to_string()),
        }
    }

    /// Take the text an editor returned as the result.
    pub fn set_edited(&mut self, text: String) {
        self.edited = Some(text);
    }

    fn fold_key(&mut self, key: Key) -> Effect {
        let all: HashSet<usize> = self.view.panes[self.pane]
            .lines
            .iter()
            .map(|line| line.hunk)
            .collect();
        match key {
            Key::Char('M') => {
                self.folded[self.pane] = all;
                let index = self.cursor();
                self.move_to(index);
            }
            Key::Char('R') => self.folded[self.pane].clear(),
            Key::Char(c @ ('c' | 'o' | 'a')) => {
                let Some(hunk) = self.hunk_at_cursor() else {
                    return Effect::None;
                };
                let fold = match c {
                    'c' => true,
                    'o' => false,
                    _ => !self.folded[self.pane].contains(&hunk),
                };
                self.set_fold(hunk, fold);
            }
            _ => {}
        }
        Effect::None
    }

    pub fn cursor(&self) -> usize {
        self.cursors[self.pane]
    }

    /// Put the cursor on line `index`, or on the fold that hides it.
    fn move_to(&mut self, index: usize) {
        let visible = self.visible(self.pane);
        let last = self.lines().saturating_sub(1);
        let index = index.min(last);
        self.cursors[self.pane] = visible
            .iter()
            .rev()
            .find(|shown| **shown <= index)
            .or(visible.first())
            .copied()
            .unwrap_or(0);
    }

    /// Move `by` shown lines, so a fold counts as one.
    fn step(&mut self, by: isize) {
        let visible = self.visible(self.pane);
        let at = visible
            .iter()
            .position(|shown| *shown >= self.cursor())
            .unwrap_or(visible.len().saturating_sub(1));
        let target = (at as isize + by).clamp(0, visible.len().saturating_sub(1) as isize);
        if let Some(index) = visible.get(target as usize) {
            self.cursors[self.pane] = *index;
        }
    }

    fn switch(&mut self, forward: bool) {
        let n = self.view.panes.len();
        self.pane = if forward {
            (self.pane + 1) % n
        } else {
            (self.pane + n - 1) % n
        };
        self.hover = None;
    }

    /// The pointer is over line `index` of the current side (or off it).
    pub fn hover(&mut self, index: Option<usize>) {
        self.hover = index.filter(|i| *i < self.lines());
    }

    /// Who wrote the line under the pointer, else under the cursor.
    pub fn provenance(&self) -> Option<&str> {
        let pane = &self.view.panes[self.pane];
        let index = self.hover.unwrap_or(self.cursor());
        pane.lines.get(index).map(|l| l.provenance.as_str())
    }

    pub fn handle(&mut self, key: Key) -> Effect {
        match self.mode {
            Mode::Command => self.command_key(key),
            Mode::Search => self.search_key(key),
            Mode::Normal => self.normal_key(key),
        }
    }

    fn normal_key(&mut self, key: Key) -> Effect {
        let was_g = std::mem::take(&mut self.pending_g);
        if std::mem::take(&mut self.pending_z) {
            return self.fold_key(key);
        }
        match key {
            Key::Char('z') => self.pending_z = true,
            Key::Char(' ') => return self.toggle_pick(),
            Key::Char('c') => {
                self.show_context = !self.show_context;
                let index = self.cursor();
                self.move_to(index);
                return Effect::Message(format!(
                    "unchanged context {}",
                    if self.show_context { "shown" } else { "hidden" }
                ));
            }
            Key::Char('j') | Key::Down => self.step(1),
            Key::Char('k') | Key::Up => self.step(-1),
            Key::Char('g') if was_g => self.move_to(0),
            Key::Char('g') => self.pending_g = true,
            Key::Char('G') => self.move_to(usize::MAX),
            Key::Ctrl('d') | Key::PageDown => self.step(10),
            Key::Ctrl('u') | Key::PageUp => self.step(-10),
            Key::Tab | Key::Char('l') | Key::Right => self.switch(true),
            Key::BackTab | Key::Char('h') | Key::Left => self.switch(false),
            Key::Char(':') => {
                self.mode = Mode::Command;
                self.command.clear();
            }
            Key::Char('/') => {
                self.mode = Mode::Search;
                self.command.clear();
            }
            Key::Char('n') => return self.repeat_search(true),
            Key::Char('N') => return self.repeat_search(false),
            Key::Char('?') => return Effect::Message(HELP.to_string()),
            Key::Char('q') => return Effect::Quit,
            _ => {}
        }
        Effect::None
    }

    fn command_key(&mut self, key: Key) -> Effect {
        match key {
            Key::Esc => {
                self.mode = Mode::Normal;
                self.command.clear();
            }
            Key::Backspace => match self.command.pop() {
                Some(_) => {}
                None => self.mode = Mode::Normal,
            },
            Key::Char(c) => self.command.push(c),
            Key::Enter => {
                let command = std::mem::take(&mut self.command);
                self.mode = Mode::Normal;
                let command = command.trim();
                let (word, argument) = command
                    .split_once(char::is_whitespace)
                    .map_or((command, ""), |(word, rest)| (word, rest.trim()));
                return match word {
                    "" => Effect::None,
                    "q" | "quit" => Effect::Quit,
                    "help" | "h" => Effect::Message(HELP.to_string()),
                    "as" if !argument.is_empty() => {
                        self.as_label = Some(argument.to_string());
                        Effect::Message(format!("acting as {argument}; :slot CONTAINER=LABEL next"))
                    }
                    "slot" if argument.contains('=') => {
                        self.slot = Some(argument.to_string());
                        Effect::Message(format!("signing slot {argument}"))
                    }
                    "as" | "slot" => Effect::Message(format!(
                        "usage: :as LABEL · :slot CONTAINER=LABEL (got \"{command}\")"
                    )),
                    "accept" => self.accept(argument),
                    "reject" => self.act(Action::Reject),
                    "sign" => self.act(Action::Sign),
                    "finalize" => self.act(Action::Finalize),
                    "compose" => Effect::Message(match self.compose() {
                        Ok(text) => format!(
                            "result: {} line(s) from {}",
                            text.split_inclusive('\n').count(),
                            if self.edited.is_some() {
                                "your edit".to_string()
                            } else {
                                format!("{} picked change(s)", self.picked_count())
                            }
                        ),
                        Err(reason) => reason,
                    }),
                    "edit" => match self.edit_text() {
                        Ok(text) => Effect::Edit(text),
                        Err(reason) => Effect::Message(reason),
                    },
                    "unpick" => {
                        self.picked.iter_mut().for_each(HashSet::clear);
                        self.edited = None;
                        Effect::Message("picks and edit cleared".to_string())
                    }
                    _ => Effect::Message(match guidance(command) {
                        Some(text) => text.to_string(),
                        None => format!("unknown command: {command}"),
                    }),
                };
            }
            _ => {}
        }
        Effect::None
    }

    fn search_key(&mut self, key: Key) -> Effect {
        match key {
            Key::Esc => {
                self.mode = Mode::Normal;
                self.command.clear();
            }
            Key::Backspace => match self.command.pop() {
                Some(_) => {}
                None => self.mode = Mode::Normal,
            },
            Key::Char(c) => self.command.push(c),
            Key::Enter => {
                let query = std::mem::take(&mut self.command);
                self.mode = Mode::Normal;
                if query.trim().is_empty() {
                    return Effect::None;
                }
                self.search = Some(query);
                return self.repeat_search(true);
            }
            _ => {}
        }
        Effect::None
    }

    fn repeat_search(&mut self, forward: bool) -> Effect {
        let Some(query) = self.search.clone() else {
            return Effect::Message("no previous search".to_string());
        };
        let needle = query.to_lowercase();
        let lines = &self.view.panes[self.pane].lines;
        if lines.is_empty() {
            return Effect::Message(format!("pattern not found: {query}"));
        }
        let start = self.cursor();
        let found = (1..=lines.len()).find_map(|offset| {
            let index = if forward {
                (start + offset) % lines.len()
            } else {
                (start + lines.len() - (offset % lines.len())) % lines.len()
            };
            lines[index]
                .text
                .to_lowercase()
                .contains(&needle)
                .then_some(index)
        });
        if let Some(index) = found {
            // A match inside a fold opens it.
            let hunk = self.view.panes[self.pane].lines[index].hunk;
            self.folded[self.pane].remove(&hunk);
            self.move_to(index);
            self.hover = None;
            return Effect::None;
        }
        Effect::Message(format!("pattern not found: {query}"))
    }
}

#[cfg(test)]
#[path = "review_view/tests.rs"]
mod tests;
