//! Tracked files in the lab: a registry of `.kqtf` containers whose
//! history the activity log follows, and the GUI actions that work on them.
//! Every action is one real `keyquorum file` command run as the active
//! person against their own store, with their own slot; the lab decides
//! nothing about trust, merging, reviewers or delivery. After any command
//! (a button or a terminal line), the containers are re-read and events the
//! log has not seen yet are appended, so the timeline stays live.

use super::*;
use crate::cli::file_cmd::StoreTrust;
use crate::file_history::{
    current_revision, evaluate_revision_trust, is_finalized, latest_finalized_ancestor,
    latest_trusted_revision, select_shareable_revision, HistoryOutcome, TrackedFile, TrustState,
};

/// Where tracked-file letters and acknowledgements are handed over: a
/// shared folder standing in for the relay or a USB stick.
const LETTERS_DIR: &str = "/srv/keyquorum/tracked/letters";
const ACKS_DIR: &str = "/srv/keyquorum/tracked/acks";
/// How much of a revision's text the snapshot carries for the edit box.
const TEXT_LIMIT: usize = 4096;

pub(in crate::lab) struct Tracked {
    path: PathBuf,
    /// Hash of the newest event already in the activity log.
    last: Option<[u8; 32]>,
    /// History snapshots (`KQHS`) exported from this file.
    snapshots: Vec<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LetterStatus {
    Waiting,
    Accepted,
    Rejected,
}

pub(in crate::lab) struct TrackedLetter {
    id: i64,
    file_name: String,
    from_user: String,
    to_user: String,
    /// The sender's container, where their acknowledgement is recorded.
    sender_kqtf: PathBuf,
    letter: PathBuf,
    ack: Option<PathBuf>,
    status: LetterStatus,
    ack_recorded: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestStatus {
    Waiting,
    Accepted,
    Declined,
}

/// A request letter (`file request`) and the answer to it.
pub(in crate::lab) struct TrackedRequest {
    id: i64,
    file_name: String,
    /// `file` or `change`.
    kind: &'static str,
    message: String,
    from_user: String,
    to_user: String,
    /// The requester's container, where the answer is recorded.
    requester_kqtf: PathBuf,
    letter: PathBuf,
    answer: Option<PathBuf>,
    opened: bool,
    status: RequestStatus,
    answer_recorded: bool,
}

/// `AutoMergeRequiresHuman` as "Auto merge requires human".
fn humanize(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn trust_word(state: &TrustState) -> &'static str {
    match state {
        TrustState::Trusted => "trusted",
        TrustState::Pending(_) => "pending",
        TrustState::Denied(_) => "denied",
    }
}

/// The paths a `keyquorum file` line names as containers: every `.kqtf`
/// argument, plus the `<file>.kqtf` that `file track <file>` writes when no
/// `--out` is given.
fn named_containers(line: &str) -> Vec<String> {
    let words: Vec<&str> = line
        .split_whitespace()
        .map(|w| w.trim_matches('"').trim_matches('\''))
        .collect();
    let mut paths: Vec<String> = words
        .iter()
        .filter(|w| w.ends_with(".kqtf"))
        .map(|w| w.to_string())
        .collect();
    if let Some(at) = words.windows(2).position(|w| w == ["file", "track"]) {
        let has_out = words.contains(&"--out");
        if let Some(source) = words.get(at + 2).filter(|w| !w.starts_with('-')) {
            if !has_out {
                paths.push(format!("{source}.kqtf"));
            }
        }
    }
    paths
}

impl LabState {
    /// The active person's own store, where every slot's public keys are
    /// registered: the one their `keyquorum file` commands run against.
    fn own_store(&self) -> String {
        self.actor().store()
    }

    fn trust_store(&self) -> &Connection {
        self.vm()
            .store(&self.own_store())
            .unwrap_or_else(|| self.org())
    }

    /// Start following a container. Unknown or unreadable paths are ignored.
    pub(super) fn register_tracked(&mut self, path: &Path) -> bool {
        let path = self.vm().resolve(path);
        if self.tracked.iter().any(|t| t.path == path) {
            return true;
        }
        let readable = self
            .vm()
            .read(&path)
            .ok()
            .and_then(|bytes| TrackedFile::decode(&bytes).ok())
            .is_some();
        if readable {
            self.tracked.push(Tracked {
                path,
                last: None,
                snapshots: Vec::new(),
            });
        }
        readable
    }

    /// Follow any container a command line names.
    pub(super) fn register_from_command(&mut self, line: &str) {
        if !line.contains(" file ") {
            return;
        }
        // Resolved exactly as the command itself resolved them.
        for path in named_containers(line) {
            self.register_tracked(Path::new(&path));
        }
    }

    /// Append every event the log has not seen yet, from every followed
    /// container. A container rewritten from scratch (its last seen event is
    /// gone) is read again from the start.
    pub(super) fn sync_history(&mut self) {
        let mut entries = Vec::new();
        for index in 0..self.tracked.len() {
            let path = self.tracked[index].path.clone();
            let Some(file) = self
                .vm()
                .read(&path)
                .ok()
                .and_then(|bytes| TrackedFile::decode(&bytes).ok())
            else {
                continue;
            };
            let start = match self.tracked[index].last {
                None => 0,
                Some(last) => file
                    .events()
                    .iter()
                    .position(|e| e.event_hash == last)
                    .map_or(0, |i| i + 1),
            };
            if start >= file.events().len() {
                continue;
            }
            entries.extend(self.history_entries(&path, &file, start));
            self.tracked[index].last = file.events().last().map(|e| e.event_hash);
        }
        for mut entry in entries {
            entry.seq = self.next_seq;
            self.next_seq += 1;
            self.activity.push(entry);
        }
    }

    /// One activity entry per event from `start` on. `finalization_state` is
    /// the revision's trust as judged when the event was read in.
    fn history_entries(&self, path: &Path, file: &TrackedFile, start: usize) -> Vec<ActivityView> {
        let ctx = StoreTrust {
            conn: self.trust_store(),
        };
        let policy = file.policy().cloned();
        file.events()[start..]
            .iter()
            .map(|event| {
                let revision = event
                    .revision_id
                    .and_then(|id| file.graph().get(&id).map(|stored| &stored.revision));
                let finalization = event
                    .revision_id
                    .zip(policy.as_ref())
                    .and_then(|(id, policy)| evaluate_revision_trust(file, &id, policy, &ctx).ok());
                ActivityView {
                    seq: 0,
                    actor: event
                        .actor_label
                        .clone()
                        .unwrap_or_else(|| "system".to_string()),
                    kind: "history".to_string(),
                    outcome: match event.outcome {
                        HistoryOutcome::Success => "granted",
                        HistoryOutcome::Failure | HistoryOutcome::Denied => "denied",
                        HistoryOutcome::Info => "info",
                    }
                    .to_string(),
                    title: format!(
                        "{} · {}",
                        humanize(&format!("{:?}", event.event_type)),
                        file.logical_name
                    ),
                    trace: event
                        .details
                        .entries()
                        .iter()
                        .map(|(key, value)| TraceStep::info(format!("{key}: {value}")))
                        .collect(),
                    command: Some(format!("keyquorum file history {}", path.display())),
                    history: Some(HistoryFields {
                        file_id: hex::encode(file.file_id),
                        file_name: file.logical_name.clone(),
                        history_event_type: format!("{:?}", event.event_type),
                        history_category: event.event_type.category().to_string(),
                        history_root: hex::encode(event.event_hash),
                        revision_id: event.revision_id.map(hex::encode),
                        generated_label: revision.map(|r| r.generated_label.clone()),
                        user_label: revision.and_then(|r| r.user_label.clone()),
                        parent_revision_ids: revision
                            .map(|r| r.parent_revision_ids.iter().map(hex::encode).collect())
                            .unwrap_or_default(),
                        finalization_state: finalization
                            .as_ref()
                            .map(|state| trust_word(state).to_string()),
                    }),
                }
            })
            .collect()
    }

    /// Every followed container as the active person's store judges it now.
    pub(super) fn tracked_views(&self) -> Vec<TrackedFileView> {
        let ctx = StoreTrust {
            conn: self.trust_store(),
        };
        let homes: Vec<(PathBuf, String)> = self
            .users
            .iter()
            .map(|user| (user.home(), user.id.clone()))
            .collect();
        self.tracked
            .iter()
            .filter_map(|tracked| {
                let bytes = self.vm().read(&tracked.path).ok()?;
                let file = TrackedFile::decode(&bytes).ok()?;
                let policy = file.policy()?.clone();
                let graph = file.graph();
                let heads = graph.heads();
                let revisions = file
                    .revisions()
                    .iter()
                    .map(|stored| {
                        let revision = &stored.revision;
                        let id = revision.revision_id;
                        let state = evaluate_revision_trust(&file, &id, &policy, &ctx).ok();
                        let reason = match &state {
                            Some(TrustState::Pending(r)) | Some(TrustState::Denied(r)) => {
                                Some(format!("{r:?}"))
                            }
                            _ => None,
                        };
                        TrackedRevisionView {
                            id: hex::encode(id),
                            generated_label: revision.generated_label.clone(),
                            user_label: revision.user_label.clone(),
                            author: revision.author_hcp_label.clone(),
                            created_at: revision.created_at_utc.clone(),
                            parents: revision
                                .parent_revision_ids
                                .iter()
                                .map(hex::encode)
                                .collect(),
                            head: heads.contains(&id),
                            trust: state.as_ref().map_or("unknown", trust_word).to_string(),
                            reason,
                            finalized: is_finalized(&file, &id, &policy, &ctx),
                            text: stored
                                .content()
                                .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
                                .filter(|text| text.len() <= TEXT_LIMIT),
                        }
                    })
                    .collect();
                let shareable = match heads.as_slice() {
                    [head] => select_shareable_revision(&file, head, None, &policy, &ctx)
                        .ok()
                        .and_then(|decision| decision.delivered_revision.map(hex::encode)),
                    _ => None,
                };
                let owner = homes
                    .iter()
                    .find(|(home, _)| tracked.path.starts_with(home))
                    .map(|(_, id)| id.clone());
                Some(TrackedFileView {
                    path: tracked.path.display().to_string(),
                    name: file.logical_name.clone(),
                    file_id: hex::encode(file.file_id),
                    scope: policy.scope_root.clone(),
                    owner,
                    auto_merge: policy.auto_merge,
                    forked: heads.len() > 1,
                    history_len: file.events().len(),
                    history_root: hex::encode(file.history_root()),
                    revisions,
                    shareable,
                    current_revision: current_revision(&file).map(hex::encode),
                    trusted_revision: latest_trusted_revision(&file, &policy, &ctx)
                        .map(hex::encode),
                    finalized_revision: match heads.as_slice() {
                        [head] => {
                            latest_finalized_ancestor(&file, head, &policy, &ctx).map(hex::encode)
                        }
                        _ => None,
                    },
                    expires_at: file.expires_at(),
                    destroyed: file.is_destroyed(),
                    snapshots: tracked
                        .snapshots
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect(),
                    links: self.gate_links(&file.file_id),
                })
            })
            .collect()
    }

    pub(super) fn letter_views(&self) -> Vec<TrackedLetterView> {
        let name = |id: &str| {
            self.users
                .iter()
                .find(|user| user.id == id)
                .map(|user| (user.name.clone(), user.label.clone()))
                .unwrap_or_default()
        };
        self.letters
            .iter()
            .map(|letter| {
                let (from_name, from_label) = name(&letter.from_user);
                let (to_name, to_label) = name(&letter.to_user);
                TrackedLetterView {
                    id: letter.id,
                    file_name: letter.file_name.clone(),
                    from: letter.from_user.clone(),
                    from_name,
                    from_label,
                    to: letter.to_user.clone(),
                    to_name,
                    to_label,
                    status: match letter.status {
                        LetterStatus::Waiting => "waiting",
                        LetterStatus::Accepted => "accepted",
                        LetterStatus::Rejected => "rejected",
                    }
                    .to_string(),
                    ack_recorded: letter.ack_recorded,
                }
            })
            .collect()
    }

    pub(super) fn request_views(&self) -> Vec<TrackedRequestView> {
        let name = |id: &str| {
            self.users
                .iter()
                .find(|user| user.id == id)
                .map(|user| (user.name.clone(), user.label.clone()))
                .unwrap_or_default()
        };
        self.requests
            .iter()
            .map(|request| {
                let (from_name, from_label) = name(&request.from_user);
                let (to_name, to_label) = name(&request.to_user);
                TrackedRequestView {
                    id: request.id,
                    file_name: request.file_name.clone(),
                    kind: request.kind.to_string(),
                    message: request.message.clone(),
                    from: request.from_user.clone(),
                    from_name,
                    from_label,
                    to: request.to_user.clone(),
                    to_name,
                    to_label,
                    status: match request.status {
                        RequestStatus::Waiting => "waiting",
                        RequestStatus::Accepted => "accepted",
                        RequestStatus::Declined => "declined",
                    }
                    .to_string(),
                    answer_recorded: request.answer_recorded,
                }
            })
            .collect()
    }

    fn tracked_path(&self, path: &str) -> Option<PathBuf> {
        let path = self.vm().resolve(Path::new(path));
        self.tracked.iter().any(|t| t.path == path).then_some(path)
    }

    fn file_line(&self) -> String {
        format!("keyquorum --db {} file", self.own_store())
    }

    /// Run one `keyquorum file` line as an activity of `kind`.
    fn history_command(&mut self, kind: &str, title: &str, line: String) -> (Outcome, CommandRun) {
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let message = match run.error() {
            Some(error) => format!("{title}: {error}"),
            None => run
                .stdout_text()
                .lines()
                .next()
                .map_or_else(|| title.to_string(), str::to_string),
        };
        self.log(
            kind,
            if run.ok { "granted" } else { "denied" },
            title,
            trace.clone(),
            Some(line),
        );
        (Outcome::done(run.ok, message, trace), run)
    }

    fn no_slot(&self) -> Outcome {
        Outcome::done(
            false,
            format!("{} has no slot on any drive", self.actor().label),
            vec![],
        )
    }

    fn unknown_tracked(path: &str) -> Outcome {
        Outcome::done(false, format!("{path} is not a tracked file here"), vec![])
    }

    /// `keyquorum file track`: a new tracked file scoped to the active
    /// person, signed with their slot, in their home.
    pub fn history_track(&mut self, name: &str, text: &str) -> Result<Outcome> {
        let name = name.trim();
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Ok(Outcome::done(false, "Give the file a plain name", vec![]));
        }
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let label = self.actor().label.clone();
        let dir = self.actor().home().join("tracked");
        let source = dir.join(name);
        let out = dir.join(format!("{name}.kqtf"));
        self.write_file(&source, text.as_bytes())?;
        let line = format!(
            "{} track {} --scope {label} --as {label} --slot {slot} --out {}",
            self.file_line(),
            quote(&source.display().to_string()),
            quote(&out.display().to_string()),
        );
        let (outcome, _) = self.history_command("history-track", &format!("Track {name}"), line);
        Ok(outcome)
    }

    /// `keyquorum file checkin`: a new revision of the file's sole head,
    /// signed by the active person or left unsigned.
    pub fn history_checkin(
        &mut self,
        path: &str,
        text: &str,
        signed: bool,
        label: Option<&str>,
    ) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let who = self.actor().label.clone();
        let edit = self.actor().home().join("tracked").join(".edit");
        self.write_file(&edit, text.as_bytes())?;
        let mut line = format!(
            "{} checkin {} --from {} --as {who}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
            quote(&edit.display().to_string()),
        );
        if signed {
            let Some(slot) = self.own_slot_arg() else {
                return Ok(self.no_slot());
            };
            line.push_str(&format!(" --slot {slot}"));
        } else {
            line.push_str(" --unsigned");
        }
        if let Some(label) = label.map(str::trim).filter(|l| !l.is_empty()) {
            line.push_str(&format!(" --label {}", quote(label)));
        }
        let name = self.tracked_name(&kqtf);
        let title = if signed {
            format!("Check in a signed edit to {name}")
        } else {
            format!("Check in an unsigned edit to {name}")
        };
        let (outcome, _) = self.history_command("history-checkin", &title, line);
        Ok(outcome)
    }

    fn tracked_name(&self, kqtf: &Path) -> String {
        self.vm()
            .read(kqtf)
            .ok()
            .and_then(|bytes| TrackedFile::decode(&bytes).ok())
            .map(|file| file.logical_name)
            .unwrap_or_else(|| kqtf.display().to_string())
    }

    fn revision_arg(revision: Option<&str>) -> String {
        revision
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(|r| format!(" --revision {r}"))
            .unwrap_or_default()
    }

    /// `keyquorum file sign`: sign a revision the active person authored.
    pub fn history_sign(&mut self, path: &str, revision: Option<&str>) -> Result<Outcome> {
        self.signing_command(path, revision, "sign", "history-sign", "Sign")
    }

    /// `keyquorum file finalize`: mark a trusted revision final, as the
    /// active person with their own slot. The CLI decides who may.
    pub fn history_finalize(&mut self, path: &str, revision: Option<&str>) -> Result<Outcome> {
        self.signing_command(path, revision, "finalize", "history-finalize", "Finalize")
    }

    /// `keyquorum file countersign`: approve a descendant's revision as its
    /// author's direct parent.
    pub fn history_countersign(&mut self, path: &str, revision: Option<&str>) -> Result<Outcome> {
        self.signing_command(
            path,
            revision,
            "countersign",
            "history-countersign",
            "Countersign",
        )
    }

    fn signing_command(
        &mut self,
        path: &str,
        revision: Option<&str>,
        verb: &str,
        kind: &str,
        title: &str,
    ) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let who = self.actor().label.clone();
        let line = format!(
            "{} {verb} {}{} --as {who} --slot {slot}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
            Self::revision_arg(revision),
        );
        let name = self.tracked_name(&kqtf);
        let (outcome, _) = self.history_command(kind, &format!("{title} {name}"), line);
        Ok(outcome)
    }

    /// `keyquorum file merge`: join two heads, automatically when the merge
    /// is clean, else record the conflict and who reviews it.
    pub fn history_merge(&mut self, path: &str, label: Option<&str>) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let who = self.actor().label.clone();
        let mut line = format!(
            "{} merge {} --as {who}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
        );
        if let Some(label) = label.map(str::trim).filter(|l| !l.is_empty()) {
            line.push_str(&format!(" --label {}", quote(label)));
        }
        let name = self.tracked_name(&kqtf);
        let (outcome, _) = self.history_command("history-merge", &format!("Merge {name}"), line);
        Ok(outcome)
    }

    /// `keyquorum file resolve`: settle a conflict as the active person, with
    /// their own slot. `choice` is `left`, `right`, `edited` (with `text` as
    /// the result) or `reject` (a proposed merge at the head). The CLI decides
    /// who may: the lab adds no reviewer check of its own.
    pub fn history_resolve(
        &mut self,
        path: &str,
        choice: &str,
        text: Option<&str>,
        label: Option<&str>,
    ) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let who = self.actor().label.clone();
        let mut line = format!(
            "{} resolve {}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
        );
        match choice {
            "left" | "right" => line.push_str(&format!(" --keep {choice}")),
            "reject" => line.push_str(" --reject"),
            "edited" => {
                let edit = self.actor().home().join("tracked").join(".resolve");
                self.write_file(&edit, text.unwrap_or_default().as_bytes())?;
                line.push_str(&format!(" --from {}", quote(&edit.display().to_string())));
            }
            other => {
                return Ok(Outcome::done(
                    false,
                    format!("unknown resolution {other}: use left, right, edited or reject"),
                    vec![],
                ))
            }
        }
        line.push_str(&format!(" --as {who} --slot {slot}"));
        if let Some(label) = label.map(str::trim).filter(|l| !l.is_empty()) {
            line.push_str(&format!(" --label {}", quote(label)));
        }
        let name = self.tracked_name(&kqtf);
        let title = match choice {
            "reject" => format!("Reject the proposed merge of {name}"),
            "edited" => format!("Resolve {name} with an edited result"),
            side => format!("Resolve {name}, keeping {side}"),
        };
        let (outcome, _) = self.history_command("history-resolve", &title, line);
        Ok(outcome)
    }

    /// A read-only command whose output opens like a file.
    fn history_report(
        &mut self,
        path: &str,
        verb: &str,
        kind: &str,
        title: &str,
    ) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let line = format!(
            "{} {verb} {}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
        );
        let name = self.tracked_name(&kqtf);
        let title = format!("{title} {name}");
        let (mut outcome, run) = self.history_command(kind, &title, line);
        if run.ok {
            outcome.opened = Some(OpenedFile {
                name: title,
                text: run.stdout_text(),
            });
        }
        Ok(outcome)
    }

    /// `keyquorum file verify`: check the chain and graph, judge every revision.
    pub fn history_verify(&mut self, path: &str) -> Result<Outcome> {
        self.history_report(path, "verify", "history-verify", "Verify")
    }

    /// `keyquorum file review`: the two sides of a fork and who reviews it.
    pub fn history_review(&mut self, path: &str) -> Result<Outcome> {
        self.history_report(path, "review", "history-review", "Review")
    }

    /// `keyquorum file expire`: schedule when the file's content is
    /// destroyed (`at` as `yyyy-mm-ddThh:mm`, UTC), or destroy it now.
    pub fn history_expire(&mut self, path: &str, at: Option<&str>) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let who = self.actor().label.clone();
        let when = match at.map(str::trim).filter(|a| !a.is_empty()) {
            Some(at) if at.chars().all(|c| c.is_ascii_digit() || "-:T".contains(c)) => {
                format!("--at {at}")
            }
            Some(_) => {
                return Ok(Outcome::done(
                    false,
                    "Give the time as yyyy-mm-ddThh:mm (UTC)",
                    vec![],
                ))
            }
            None => "--now".to_string(),
        };
        let line = format!(
            "{} expire {} --as {who} {when} --slot {slot}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
        );
        let name = self.tracked_name(&kqtf);
        let title = if at.is_some() {
            format!("Schedule expiry of {name}")
        } else {
            format!("Destroy the content of {name}")
        };
        let (outcome, _) = self.history_command("history-expire", &title, line);
        Ok(outcome)
    }

    /// `keyquorum file rename`: change the name a tracked file is shown
    /// under; its id and revision ids stay the same.
    pub fn history_rename(&mut self, path: &str, new_name: &str) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let who = self.actor().label.clone();
        let line = format!(
            "{} rename {} {} --as {who} --slot {slot}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
            quote(new_name.trim()),
        );
        let name = self.tracked_name(&kqtf);
        let (outcome, _) = self.history_command(
            "history-rename",
            &format!("Rename {name} to {}", new_name.trim()),
            line,
        );
        Ok(outcome)
    }

    /// The gates (quorum files in the org store, password files in their
    /// owner's store) linked to this tracked file. Read-only.
    fn gate_links(&self, file_id: &[u8; 16]) -> Vec<TrackedLinkView> {
        let mut stores = vec![ORG_DB.to_string()];
        stores.extend(self.users.iter().map(|user| user.store()));
        let mut links = Vec::new();
        for store in stores {
            let Some(conn) = self.vm().store(&store) else {
                continue;
            };
            let rows = conn
                .prepare(
                    "SELECT gate, gate_file_id FROM tracked_gate_links WHERE tracked_file_id = ?1",
                )
                .and_then(|mut stmt| {
                    stmt.query_map([file_id.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?
                        .collect::<rusqlite::Result<Vec<(String, i64)>>>()
                });
            for (gate, id) in rows.unwrap_or_default() {
                links.push(TrackedLinkView { gate, id });
            }
        }
        links
    }

    /// `keyquorum file diff`: the changed lines between two revisions (by
    /// default the head and its first parent), shown like an opened file.
    pub fn history_diff(
        &mut self,
        path: &str,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let mut line = format!(
            "{} diff {}",
            self.file_line(),
            quote(&kqtf.display().to_string())
        );
        for (flag, value) in [("--from", from), ("--to", to)] {
            if let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) {
                line.push_str(&format!(" {flag} {value}"));
            }
        }
        let name = self.tracked_name(&kqtf);
        self.report_line(line, "history-diff", &format!("Diff {name}"))
    }

    /// `keyquorum file checkout` of one revision into a scratch file, read
    /// back and removed: an older revision viewed without replacing anything.
    pub fn history_view_revision(&mut self, path: &str, revision: &str) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let scratch = self.actor().home().join("tracked").join(".checkout");
        if self.vm().exists(&scratch) {
            self.remove_file(&scratch)?;
        }
        let line = format!(
            "{} checkout {} --revision {} --out {}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
            revision.trim(),
            quote(&scratch.display().to_string()),
        );
        let name = self.tracked_name(&kqtf);
        let short: String = revision.trim().chars().take(8).collect();
        let title = format!("View {name} at {short}");
        let (mut outcome, run) = self.history_command("history-checkout", &title, line);
        if run.ok {
            let text = String::from_utf8_lossy(&self.vm().read(&scratch)?).into_owned();
            self.remove_file(&scratch)?;
            outcome.opened = Some(OpenedFile { name: title, text });
        }
        Ok(outcome)
    }

    fn report_line(&mut self, line: String, kind: &str, title: &str) -> Result<Outcome> {
        let (mut outcome, run) = self.history_command(kind, title, line);
        if run.ok {
            outcome.opened = Some(OpenedFile {
                name: title.to_string(),
                text: run.stdout_text(),
            });
        }
        Ok(outcome)
    }

    /// `keyquorum file history --export`: a portable, verifiable snapshot
    /// (`KQHS`) of the event history, kept next to the active person's files.
    pub fn history_export(&mut self, path: &str) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let name = self.tracked_name(&kqtf);
        let index = self
            .tracked
            .iter()
            .position(|t| t.path == kqtf)
            .unwrap_or(0);
        let number = self.tracked[index].snapshots.len() + 1;
        let out = self
            .actor()
            .home()
            .join("tracked")
            .join(format!("{name}-{number}.kqhs"));
        let line = format!(
            "{} history {} --export {}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
            quote(&out.display().to_string()),
        );
        let (outcome, run) = self.history_command(
            "history-export",
            &format!("Export the history of {name}"),
            line,
        );
        if run.ok {
            self.tracked[index].snapshots.push(out);
        }
        Ok(outcome)
    }

    /// `keyquorum file verify-snapshot --against`: the snapshot verifies and
    /// is a point in this file's history.
    pub fn history_verify_snapshot(&mut self, path: &str, snapshot: &str) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let line = format!(
            "{} verify-snapshot {} --against {}",
            self.file_line(),
            quote(snapshot),
            quote(&kqtf.display().to_string()),
        );
        let name = self.tracked_name(&kqtf);
        self.report_line(
            line,
            "history-verify-snapshot",
            &format!("Check a snapshot of {name}"),
        )
    }

    /// `keyquorum file import`: bring another followed copy of the same file
    /// into this one. A fork is kept as two heads.
    pub fn history_import(&mut self, path: &str, from: &str) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let Some(other) = self.tracked_path(from) else {
            return Ok(Self::unknown_tracked(from));
        };
        let who = self.actor().label.clone();
        let line = format!(
            "{} import {} --from {} --as {who}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
            quote(&other.display().to_string()),
        );
        let name = self.tracked_name(&kqtf);
        let (outcome, _) = self.history_command(
            "history-import",
            &format!("Import another copy of {name}"),
            line,
        );
        Ok(outcome)
    }

    /// `keyquorum file link|unlink`: record (or stop recording) what happens
    /// at a quorum file's gate (org store) or a password file's gate (the
    /// active person's store, where their password files live).
    pub fn history_link(&mut self, path: &str, gate: &str, id: i64, link: bool) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let (store, flag) = match gate {
            "quorum" => (ORG_DB.to_string(), "--quorum-file"),
            "password" => (self.own_store(), "--locked-file"),
            other => {
                return Ok(Outcome::done(
                    false,
                    format!("No gate kind {other}"),
                    vec![],
                ))
            }
        };
        let verb = if link { "link" } else { "unlink" };
        let line = format!(
            "keyquorum --db {store} file {verb} {} {flag} {id}",
            quote(&kqtf.display().to_string()),
        );
        let name = self.tracked_name(&kqtf);
        let title = if link {
            format!("Link {gate} file {id} to {name}")
        } else {
            format!("Unlink {gate} file {id} from {name}")
        };
        let (outcome, _) = self.history_command("history-link", &title, line);
        Ok(outcome)
    }

    /// `keyquorum send` of a tracked file: seal the newest trusted revision to another
    /// person. The letter is left in the shared letters folder for them.
    pub fn history_share(&mut self, path: &str, to_user: &str) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let Some(to) = self.user_index(to_user) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user {to_user}"),
                vec![],
            ));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let (to_id, to_label, to_name) = {
            let user = &self.users[to];
            (user.id.clone(), user.label.clone(), user.name.clone())
        };
        let who = self.actor().label.clone();
        let line = format!(
            "keyquorum --db {} send {} --to {to_label} --as {who} --slot {slot} --output-dir {LETTERS_DIR}",
            self.actor().store(),
            quote(&kqtf.display().to_string()),
        );
        let name = self.tracked_name(&kqtf);
        let (outcome, run) = self.history_command(
            "history-share",
            &format!("Share {name} with {to_name}"),
            line,
        );
        if let Some(letter) = written_path(&run) {
            let id = self.next_letter_id;
            self.next_letter_id += 1;
            self.letters.push(TrackedLetter {
                id,
                file_name: name,
                from_user: self.actor().id.clone(),
                to_user: to_id,
                sender_kqtf: kqtf,
                letter,
                ack: None,
                status: LetterStatus::Waiting,
                ack_recorded: false,
            });
        }
        Ok(outcome)
    }

    /// `keyquorum file receive`: open a letter as the active person, merge it
    /// into their copy of that file if they follow one, else keep it as a
    /// new copy in their home; `accept = false` refuses it. Either way a
    /// signed answer goes back to the sender.
    pub fn history_receive(&mut self, letter_id: i64, accept: bool) -> Result<Outcome> {
        let Some(index) = self.letters.iter().position(|l| l.id == letter_id) else {
            return Ok(Outcome::done(
                false,
                format!("No letter {letter_id}"),
                vec![],
            ));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let (letter, file_name) = {
            let letter = &self.letters[index];
            (letter.letter.clone(), letter.file_name.clone())
        };
        let home = self.actor().home();
        let mut line = format!(
            "{} receive --letter {} --slot {slot} --ack-dir {ACKS_DIR}",
            self.file_line(),
            quote(&letter.display().to_string()),
        );
        if accept {
            let file_id = self
                .tracked_views()
                .into_iter()
                .find(|view| view.name == file_name && Path::new(&view.path).starts_with(&home))
                .map(|view| view.path);
            match file_id {
                Some(existing) => line.push_str(&format!(" --into {}", quote(&existing))),
                None => {
                    let out = home.join("tracked").join(format!("{file_name}.kqtf"));
                    line.push_str(&format!(" --out {}", quote(&out.display().to_string())));
                }
            }
        } else {
            line.push_str(" --reject");
        }
        let title = if accept {
            format!("Receive {file_name}")
        } else {
            format!("Refuse {file_name}")
        };
        let (outcome, run) = self.history_command("history-receive", &title, line);
        if run.ok {
            // The receiver may still refuse a revision it cannot trust; the
            // answer it wrote says which.
            let accepted = accept && !run.stderr.contains("Refused");
            let letter = &mut self.letters[index];
            letter.ack = written_path(&run);
            letter.status = if accepted {
                LetterStatus::Accepted
            } else {
                LetterStatus::Rejected
            };
        }
        Ok(outcome)
    }

    /// `keyquorum file ack`: record the recipient's answer in the sender's
    /// own copy.
    pub fn history_ack(&mut self, letter_id: i64) -> Result<Outcome> {
        let Some(index) = self.letters.iter().position(|l| l.id == letter_id) else {
            return Ok(Outcome::done(
                false,
                format!("No letter {letter_id}"),
                vec![],
            ));
        };
        let Some(ack) = self.letters[index].ack.clone() else {
            return Ok(Outcome::done(
                false,
                "That letter has not been answered yet",
                vec![],
            ));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let (kqtf, name) = {
            let letter = &self.letters[index];
            (letter.sender_kqtf.clone(), letter.file_name.clone())
        };
        let line = format!(
            "{} ack {} --ack {} --slot {slot}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
            quote(&ack.display().to_string()),
        );
        let (outcome, run) = self.history_command(
            "history-ack",
            &format!("Record the answer for {name}"),
            line,
        );
        if run.ok {
            self.letters[index].ack_recorded = true;
        }
        Ok(outcome)
    }

    /// `keyquorum file request`: ask another person for a file, or for a
    /// change to it. The request only asks; the lab delivers nothing here.
    pub fn history_request(
        &mut self,
        path: &str,
        to_user: &str,
        change: bool,
        message: &str,
    ) -> Result<Outcome> {
        let Some(kqtf) = self.tracked_path(path) else {
            return Ok(Self::unknown_tracked(path));
        };
        let Some(to) = self.user_index(to_user) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user {to_user}"),
                vec![],
            ));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let (to_id, to_label, to_name) = {
            let user = &self.users[to];
            (user.id.clone(), user.label.clone(), user.name.clone())
        };
        let who = self.actor().label.clone();
        let mut line = format!(
            "{} request {} --to {to_label} --as {who} --slot {slot} --output-dir {LETTERS_DIR}",
            self.file_line(),
            quote(&kqtf.display().to_string()),
        );
        let message = message.trim();
        if change {
            line.push_str(" --change");
        }
        if !message.is_empty() {
            line.push_str(&format!(" --message {}", quote(message)));
        }
        let name = self.tracked_name(&kqtf);
        let kind = if change { "change" } else { "file" };
        let (outcome, run) = self.history_command(
            "history-request",
            &format!("Ask {to_name} for a {kind} on {name}"),
            line,
        );
        if let Some(letter) = written_path(&run) {
            let id = self.next_request_id;
            self.next_request_id += 1;
            self.requests.push(TrackedRequest {
                id,
                file_name: name,
                kind,
                message: message.to_string(),
                from_user: self.actor().id.clone(),
                to_user: to_id,
                requester_kqtf: kqtf,
                letter,
                answer: None,
                opened: false,
                status: RequestStatus::Waiting,
                answer_recorded: false,
            });
        }
        Ok(outcome)
    }

    /// `keyquorum file open-request` then `answer-request`: the holder reads
    /// the request, it is recorded in their copy of the file when they have
    /// one, and a signed accept or decline goes back.
    pub fn history_answer_request(&mut self, request_id: i64, accept: bool) -> Result<Outcome> {
        let Some(index) = self.requests.iter().position(|r| r.id == request_id) else {
            return Ok(Outcome::done(
                false,
                format!("No request {request_id}"),
                vec![],
            ));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let (letter, file_name) = {
            let request = &self.requests[index];
            (request.letter.clone(), request.file_name.clone())
        };
        let home = self.actor().home();
        let copy = self
            .tracked_views()
            .into_iter()
            .find(|view| view.name == file_name && Path::new(&view.path).starts_with(&home))
            .map(|view| format!(" --file {}", quote(&view.path)))
            .unwrap_or_default();
        let letter_arg = quote(&letter.display().to_string());
        let open = format!(
            "{} open-request --letter {letter_arg} --slot {slot}{copy}",
            self.file_line()
        );
        let (outcome, run) = self.history_command(
            "history-open-request",
            &format!("Read the request for {file_name}"),
            open,
        );
        if !run.ok {
            return Ok(outcome);
        }
        self.requests[index].opened = true;
        let decision = if accept { "accept" } else { "decline" };
        let line = format!(
            "{} answer-request --letter {letter_arg} --decision {decision} --slot {slot}{copy} --ack-dir {ACKS_DIR}",
            self.file_line()
        );
        let title = if accept {
            format!("Accept the request for {file_name}")
        } else {
            format!("Decline the request for {file_name}")
        };
        let (outcome, run) = self.history_command("history-answer-request", &title, line);
        if run.ok {
            let request = &mut self.requests[index];
            request.answer = written_path(&run);
            request.status = if accept {
                RequestStatus::Accepted
            } else {
                RequestStatus::Declined
            };
        }
        Ok(outcome)
    }

    /// `keyquorum file open-answer`: record the holder's answer in the
    /// requester's own copy.
    pub fn history_open_answer(&mut self, request_id: i64) -> Result<Outcome> {
        let Some(index) = self.requests.iter().position(|r| r.id == request_id) else {
            return Ok(Outcome::done(
                false,
                format!("No request {request_id}"),
                vec![],
            ));
        };
        let Some(answer) = self.requests[index].answer.clone() else {
            return Ok(Outcome::done(
                false,
                "That request has not been answered yet",
                vec![],
            ));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(self.no_slot());
        };
        let (kqtf, name) = {
            let request = &self.requests[index];
            (request.requester_kqtf.clone(), request.file_name.clone())
        };
        let line = format!(
            "{} open-answer --answer {} --slot {slot} --file {}",
            self.file_line(),
            quote(&answer.display().to_string()),
            quote(&kqtf.display().to_string()),
        );
        let (outcome, run) = self.history_command(
            "history-open-answer",
            &format!("Record the answer to the request for {name}"),
            line,
        );
        if run.ok {
            self.requests[index].answer_recorded = true;
        }
        Ok(outcome)
    }
}

/// The file a command reported writing (`Wrote <path>`).
fn written_path(run: &CommandRun) -> Option<PathBuf> {
    run.stdout_text()
        .lines()
        .find_map(|line| line.strip_prefix("Wrote "))
        .map(|path| PathBuf::from(path.trim()))
}
