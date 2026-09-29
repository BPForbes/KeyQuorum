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

use crate::file_history::{diff_text, ChangeKind, MergeBase, TrackedFile};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewLine {
    pub kind: ChangeKind,
    /// 1-based, in the old text for a removal and the new text for an add.
    pub number: usize,
    pub text: String,
    /// Who authored the revision this side's change belongs to.
    pub provenance: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pane {
    pub heading: String,
    pub revision: String,
    pub lines: Vec<ViewLine>,
    /// Why there are no lines, when there are none to show.
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewView {
    pub title: String,
    pub panes: Vec<Pane>,
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
            // label and the short hash (design §35).
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

impl ReviewView {
    /// The two sides of a forked history, each as the lines it changed
    /// since the unique common ancestor. `None` unless there are exactly
    /// two heads.
    pub fn of(file: &TrackedFile) -> Option<Self> {
        let heads = file.graph().heads();
        let [left, right] = heads.as_slice() else {
            return None;
        };
        let base = match file.graph().merge_base(left, right) {
            MergeBase::Unique(id) => Some(id),
            _ => None,
        };
        let pane = |side: &str, id: &[u8; 32]| {
            let provenance = describe(file, id);
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
                            // Each line is attributed to the revision on this
                            // side that wrote it; the head describes any
                            // line the replay cannot place.
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
                            (
                                changes
                                    .iter()
                                    .map(|c| ViewLine {
                                        kind: c.kind,
                                        number: c.line,
                                        text: c.text.trim_end_matches('\n').to_string(),
                                        provenance: who(c),
                                    })
                                    .collect(),
                                None,
                            )
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
                note,
            }
        };
        Some(Self {
            title: format!("{} — merge review", file.logical_name),
            panes: vec![pane("LEFT", left), pane("RIGHT", right)],
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    Quit,
    Message(String),
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
}

const HELP: &str = "j/k move · gg/G ends · Ctrl-d/u page · Tab or h/l switch side · \
/ search · n/N repeat · :q quit · hover a line for who wrote it";

/// The commands the interface does not perform, and what to run.
fn guidance(command: &str) -> Option<&'static str> {
    Some(match command {
        "sign" => "not available here: run `keyquorum file sign` as the author",
        "countersign" => "not available here: run `keyquorum file countersign` as the supervisor",
        "accept" => {
            "not available here: as the reviewer, run `keyquorum file resolve --keep left|right` or `--from FILE`"
        }
        "reject" => {
            "not available here: as the reviewer, run `keyquorum file resolve --reject` on a proposed merge"
        }
        "finalize" => {
            "not available here: once the revision is trusted, run `keyquorum file finalize` as the scope owner"
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
        }
    }

    fn lines(&self) -> usize {
        self.view.panes[self.pane].lines.len()
    }

    pub fn cursor(&self) -> usize {
        self.cursors[self.pane]
    }

    fn move_to(&mut self, index: usize) {
        let last = self.lines().saturating_sub(1);
        self.cursors[self.pane] = index.min(last);
    }

    fn step(&mut self, by: isize) {
        let target = self.cursor() as isize + by;
        self.move_to(target.max(0) as usize);
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
        match key {
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
                return match command.trim() {
                    "" => Effect::None,
                    "q" | "quit" => Effect::Quit,
                    "help" | "h" => Effect::Message(HELP.to_string()),
                    other => Effect::Message(match guidance(other) {
                        Some(text) => text.to_string(),
                        None => format!("unknown command: {other}"),
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
