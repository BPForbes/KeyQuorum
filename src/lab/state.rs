//! The one lab state every surface reads: GUI buttons, the terminal, and
//! the WASM facade all call these methods.
//!
//! Every action is a sequence of real `keyquorum` / `keyquorum-device`
//! command lines run in the lab VM ([`super::vm`]); the transcript of
//! those lines is the action's trace. Nothing here decides who may open,
//! send, receive, move, or link anything: the commands do, exactly as they
//! would on a real machine. What this module adds is what a person's
//! desktop adds: who is signed in, which USB drives are plugged in, which
//! letters they have already opened, and read-only views of the stores for
//! rendering.

use super::drives::{DriveBay, MockDrive};
use super::seed::{self, Expiry, Protection};
use super::view::*;
use super::vm::{quote, CommandRun, LabVm, ORG_DB};
use crate::device::{self, CustodyMode, UnlockApproval};
use crate::envelope;
use crate::error::{Error, Result};
use crate::key_tree::{self, KeyQuorumTree, TreeNodeSummary};
use crate::keys;
use crate::private_bridge::{is_ancestor_or_self, parent_node_label};
use crate::quorum;
use crate::relay::{self, ApiKeyScope, NewApiKey};
use crate::storage::Storage;
use crate::transfer;
use rusqlite::Connection;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

const ACTIVITY_LIMIT: usize = 80;
const SRV: &str = "/srv/keyquorum";
const ARCHIVE: &str = "/srv/archive";

struct LabUser {
    id: String,
    name: String,
    label: String,
    role: String,
    drive: String,
}

impl LabUser {
    fn home(&self) -> PathBuf {
        PathBuf::from("/home").join(&self.id)
    }

    fn store(&self) -> String {
        format!("/home/{}/keyquorum.sqlite", self.id)
    }

    fn mail_dir(&self) -> PathBuf {
        self.home().join("mail")
    }

    fn received_dir(&self) -> PathBuf {
        self.home().join("received")
    }
}

enum FileKind {
    /// Plaintext on the file server, readable by anyone.
    Public { path: PathBuf },
    /// A quorum-locked file in the org store.
    Quorum { file_id: i64, key_id: i64 },
}

struct LabFile {
    id: String,
    folder: String,
    name: String,
    lesson: String,
    kind: FileKind,
    size: usize,
    /// Cached at lock time, since an expired file's row is gone once an
    /// unlock purges it.
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SentStatus {
    Delivered,
    Acknowledged,
    Rejected,
}

struct SentItem {
    delivery_id: String,
    relay_id: i64,
    to: String,
    file_name: String,
    status: SentStatus,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InboxStatus {
    Received,
    Rejected,
}

struct Opened {
    status: InboxStatus,
    from: String,
    file_name: String,
}

/// What a person's mail client remembers: which letters they opened,
/// which acknowledgements they checked, and what they sent.
#[derive(Default)]
struct Mailbox {
    opened: BTreeMap<i64, Opened>,
    acks_checked: HashSet<i64>,
    sent: Vec<SentItem>,
}

/// What one action did, before the snapshot is attached.
pub struct Outcome {
    pub ok: bool,
    pub message: String,
    pub trace: Vec<TraceStep>,
    pub opened: Option<OpenedFile>,
}

impl Outcome {
    fn done(ok: bool, message: impl Into<String>, trace: Vec<TraceStep>) -> Self {
        Self {
            ok,
            message: message.into(),
            trace,
            opened: None,
        }
    }
}

pub struct LabState {
    /// Always present between calls; taken only while a command runs.
    vm: Option<LabVm>,
    users: Vec<LabUser>,
    files: Vec<LabFile>,
    active: usize,
    org_key_id: i64,
    mail: HashMap<String, Mailbox>,
    activity: Vec<ActivityView>,
    next_seq: u64,
    last_access: Option<AccessView>,
}

impl LabState {
    /// Build the seeded lab by running the setup an administrator would:
    /// initialize and provision each USB drive, register and bind every
    /// slot in the org store, split the org tree, lock the files, retire a
    /// departed engineer with a MOVE transfer, and load each person's relay
    /// keys and key directory into their own store.
    pub fn seed() -> Result<Self> {
        let mut bay = DriveBay::default();
        for drive in seed::DRIVES {
            bay.drives
                .push(MockDrive::new(drive.id, drive.name, drive.mount));
        }
        let users: Vec<LabUser> = seed::USERS
            .iter()
            .map(|user| LabUser {
                id: user.id.to_string(),
                name: user.name.to_string(),
                label: user.label.to_string(),
                role: user.role.to_string(),
                drive: user.drive.to_string(),
            })
            .collect();
        let active = users
            .iter()
            .position(|user| user.id == seed::INITIAL_USER)
            .ok_or(Error::NodeNotFound)?;
        let mut state = Self {
            vm: Some(LabVm::new(bay)?),
            users,
            files: Vec::new(),
            active,
            org_key_id: 0,
            mail: HashMap::new(),
            activity: Vec::new(),
            next_seq: 1,
            last_access: None,
        };
        let commands = state.provision()?;
        let home = state.actor().home();
        state.vm_mut().set_cwd(home);
        state.log(
            "reset",
            "info",
            "Lab seeded",
            vec![
                TraceStep::info(format!(
                    "{} users, {} mock USB drives, {} files",
                    state.users.len(),
                    seed::DRIVES.len(),
                    state.files.len()
                )),
                TraceStep::info(format!(
                    "Set up by {commands} real keyquorum / keyquorum-device commands: every slot is an Argon2id token in a signed device.kq, and each person has their own store"
                )),
            ],
            None,
        );
        Ok(state)
    }

    fn provision(&mut self) -> Result<usize> {
        let commands = std::cell::Cell::new(0usize);
        let run = |state: &mut Self, line: String| -> Result<CommandRun> {
            commands.set(commands.get() + 1);
            state.checked(&line)
        };

        // Drives: a signed container each, one slot per owner.
        for drive in seed::DRIVES {
            run(self, format!("keyquorum-device init {}", drive.mount))?;
            for slot in drive.slots {
                run(
                    self,
                    format!("keyquorum-device provision {} --label {slot}", drive.mount),
                )?;
                let public = run(
                    self,
                    format!("keyquorum-device public {} --label {slot}", drive.mount),
                )?;
                self.save_public_key(slot, &public)?;
            }
        }
        // The org store knows every slot's keys and which container holds it.
        for drive in seed::DRIVES {
            for slot in drive.slots {
                for kind in ["encryption", "signing"] {
                    run(
                        self,
                        format!(
                            "keyquorum --db {ORG_DB} device register {} --slot {slot} --type {kind}",
                            drive.mount
                        ),
                    )?;
                }
                run(
                    self,
                    format!(
                        "keyquorum --db {ORG_DB} device bind {} --slot {slot}",
                        drive.mount
                    ),
                )?;
            }
        }

        // The org tree whose topology drives visibility, and its one bridge.
        self.write_file(
            &Path::new(SRV).join("org-tree.json"),
            ORG_TREE_SPEC.as_bytes(),
        )?;
        let split = run(
            self,
            format!(
                "keyquorum --db {ORG_DB} split --label {} --tree-spec {SRV}/org-tree.json",
                seed::ORG_TREE
            ),
        )?;
        self.org_key_id = split
            .stderr
            .lines()
            .find_map(|line| line.strip_prefix("Split key "))
            .and_then(|rest| rest.split(';').next())
            .and_then(|id| id.trim().parse().ok())
            .ok_or(Error::TreeNotFound)?;
        let (a, b) = seed::ORG_BRIDGE;
        let key = self.org_key_id;
        run(
            self,
            format!("keyquorum --db {ORG_DB} bridge allow {key} --node {a} --peer {b}"),
        )?;
        run(
            self,
            format!("keyquorum --db {ORG_DB} bridge allow {key} --node {b} --peer {a}"),
        )?;
        run(
            self,
            format!("keyquorum --db {ORG_DB} bridge add {key} --from {a} --to {b}"),
        )?;

        // A departed engineer: enrolled on her old device now, moved to an
        // archive device once the files naming her are locked.
        let ghost = seed::GHOST_LABEL;
        run(
            self,
            format!("keyquorum-device init {ARCHIVE}/retired-device"),
        )?;
        run(
            self,
            format!("keyquorum-device init {ARCHIVE}/archive-device"),
        )?;
        run(
            self,
            format!(
                "keyquorum transfer enroll --device {ARCHIVE}/retired-device --db {ORG_DB} --label {ghost}"
            ),
        )?;
        let public = run(
            self,
            format!("keyquorum-device public {ARCHIVE}/retired-device --label {ghost}"),
        )?;
        self.save_public_key(ghost, &public)?;

        for file in seed::FILES {
            commands.set(commands.get() + self.seed_file(file)?);
        }

        run(
            self,
            format!(
                "keyquorum transfer move --from-device {ARCHIVE}/retired-device --from-db {ORG_DB} \
                 --to-device {ARCHIVE}/archive-device --to-db {ARCHIVE}/archive.sqlite --label {ghost}"
            ),
        )?;

        // The relay operator issues each API key out of band (on a real
        // host that is the provider-only `keyquorum host keys create`);
        // everyone then loads theirs with `keyquorum loadkey`.
        let admin = self.issue_api_key(ApiKeyScope::Admin, None, "org admin")?;
        run(self, format!("keyquorum --db {ORG_DB} loadkey {admin}"))?;
        for index in 0..self.users.len() {
            let (id, label, store) = {
                let user = &self.users[index];
                (user.id.clone(), user.label.clone(), user.store())
            };
            let fingerprint = self.fingerprint_for(&label)?;
            let push = self.issue_api_key(ApiKeyScope::InboxPush, None, &id)?;
            let pull = self.issue_api_key(ApiKeyScope::InboxPull, Some(fingerprint), &id)?;
            for token in [push, pull] {
                run(self, format!("keyquorum --db {store} loadkey {token}"))?;
            }
            // Everyone's public keys, so letters can be sealed to them and
            // their signatures checked.
            for drive in seed::DRIVES {
                for slot in drive.slots {
                    for kind in ["encryption", "signing"] {
                        run(
                            self,
                            format!(
                                "keyquorum --db {store} device register {} --slot {slot} --type {kind}",
                                drive.mount
                            ),
                        )?;
                    }
                }
            }
        }

        for drive in seed::DRIVES {
            if !drive.inserted {
                if let Some(mock) = self.vm_mut().bay.get_mut(drive.id) {
                    mock.connected = false;
                }
            }
        }
        Ok(commands.get())
    }

    /// Lock (or publish) one seeded file the way an administrator would.
    /// Returns how many commands that took.
    fn seed_file(&mut self, file: &seed::FileSeed) -> Result<usize> {
        let bytes = file.contents.as_bytes();
        let kind = match &file.protection {
            Protection::Public => {
                let path = Path::new(SRV).join("public").join(file.name);
                self.write_file(&path, bytes)?;
                self.files.push(LabFile {
                    id: file.id.to_string(),
                    folder: file.folder.to_string(),
                    name: file.name.to_string(),
                    lesson: file.lesson.to_string(),
                    kind: FileKind::Public { path },
                    size: bytes.len(),
                    created_at: String::new(),
                    expires_at: None,
                });
                return Ok(0);
            }
            Protection::Quorum {
                threshold,
                leaves,
                custody,
                minimum_devices,
                approval,
                expires,
            } => (
                threshold,
                leaves,
                custody,
                minimum_devices,
                approval,
                expires,
            ),
        };
        let (threshold, leaves, custody, minimum_devices, approval, expires) = kind;
        let source = Path::new(SRV).join("incoming").join(file.name);
        self.write_file(&source, bytes)?;
        let mut line = format!(
            "keyquorum --db {ORG_DB} access quorum --state 0 --source {} \
             --encrypted-path {SRV}/files/{}/{}.kqenc --name {} --root {} --threshold {threshold}",
            quote(&source.display().to_string()),
            file.folder,
            quote(file.name),
            quote(file.name),
            file.id
        );
        for leaf in leaves.iter() {
            line.push_str(&format!(" --leaf {leaf}={SRV}/keys/{leaf}.pub"));
        }
        line.push_str(&format!(
            " --custody {} --minimum-physical-devices {minimum_devices} --unlock-approval {}",
            match custody {
                CustodyMode::Hardware => "hardware",
                CustodyMode::Logical => "logical",
            },
            match approval {
                UnlockApproval::None => "none",
                UnlockApproval::Parent => "parent",
            }
        ));
        // A TTL still in the future goes on the command line. One already
        // past cannot be locked with (the CLI refuses a past expiry), so
        // the seed backdates that row directly below: it stands in for a
        // file whose time simply ran out before anyone looked.
        let resolved = match expires {
            Expiry::Never => None,
            Expiry::Offset(modifier) => Some(self.resolve_offset(modifier)?),
        };
        let backdate = match &resolved {
            Some((at, true)) => {
                line.push_str(&format!(" --expires {}", quote(at)));
                None
            }
            Some((at, false)) => Some(at.clone()),
            None => None,
        };
        let locked = self.checked(&line)?;
        self.remove_file(&source)?;
        let file_id: i64 = locked
            .stdout_text()
            .lines()
            .find_map(|line| line.strip_prefix("Locked file "))
            .and_then(|id| id.trim().parse().ok())
            .ok_or_else(|| {
                Error::Usage(format!("lab setup: no file id in the output of `{line}`"))
            })?;
        if let Some(at) = &backdate {
            let org = self.org_mut();
            quorum::set_expires_at(org, file_id, Some(at))?;
        }
        let status = quorum::status(self.org(), file_id)?;
        self.files.push(LabFile {
            id: file.id.to_string(),
            folder: file.folder.to_string(),
            name: file.name.to_string(),
            lesson: file.lesson.to_string(),
            kind: FileKind::Quorum {
                file_id,
                key_id: status.tree.key_id,
            },
            size: bytes.len(),
            created_at: status.created_at,
            expires_at: status.expires_at,
        });
        Ok(1)
    }

    /// A seed [`Expiry`] offset as a concrete UTC time, via SQLite's own
    /// clock (the one every `datetime('now')` comparison uses), and whether
    /// it is still in the future.
    fn resolve_offset(&self, modifier: &str) -> Result<(String, bool)> {
        Ok(self.vm().relay_conn().query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', ?1),
                    datetime('now', ?1) > datetime('now')",
            rusqlite::params![modifier],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }

    fn issue_api_key(
        &self,
        scope: ApiKeyScope,
        recipient_fingerprint: Option<String>,
        label: &str,
    ) -> Result<String> {
        Ok(relay::create_api_key(
            self.vm().relay_conn(),
            &NewApiKey {
                scope,
                recipient_fingerprint,
                label: Some(label.to_string()),
                ttl_seconds: None,
            },
        )?
        .token)
    }

    /// Keep the encryption key `keyquorum-device public` printed as
    /// `/srv/keyquorum/keys/<label>.pub`, the file the seed's `--leaf`
    /// flags point at.
    fn save_public_key(&mut self, label: &str, public: &CommandRun) -> Result<()> {
        let key = public
            .stdout_text()
            .lines()
            .find_map(|line| line.trim().strip_prefix("encryption "))
            .map(str::to_string)
            .ok_or(Error::InvalidPublicKey)?;
        self.write_file(
            &Path::new(SRV).join("keys").join(format!("{label}.pub")),
            key.as_bytes(),
        )
    }

    // ----- the VM ---------------------------------------------------------

    fn vm(&self) -> &LabVm {
        self.vm
            .as_ref()
            .expect("the lab VM is present between commands")
    }

    fn vm_mut(&mut self) -> &mut LabVm {
        self.vm
            .as_mut()
            .expect("the lab VM is present between commands")
    }

    /// Run one command line in the VM.
    fn run(&mut self, line: &str) -> CommandRun {
        let vm = self
            .vm
            .take()
            .expect("the lab VM is present between commands");
        let (run, vm) = vm.exec(line);
        self.vm = Some(vm);
        run
    }

    /// Run a setup command that must succeed.
    fn checked(&mut self, line: &str) -> Result<CommandRun> {
        let run = self.run(line);
        if run.ok {
            Ok(run)
        } else {
            Err(Error::Usage(format!(
                "lab setup failed at `{line}`: {}",
                run.stderr.trim()
            )))
        }
    }

    fn write_file(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        let vm = self.vm_mut();
        vm.write(path, contents)
    }

    fn remove_file(&mut self, path: &Path) -> Result<()> {
        self.vm_mut().delete(path)
    }

    fn org(&self) -> &Connection {
        self.vm()
            .store(ORG_DB)
            .expect("the org store exists once seeded")
    }

    fn org_mut(&mut self) -> &mut Connection {
        self.vm_mut()
            .store_mut(ORG_DB)
            .expect("the org store exists once seeded")
    }

    fn fingerprint_for(&self, label: &str) -> Result<String> {
        let key = keys::active_keys_for(self.org(), label, keys::KeyType::Encryption)?
            .into_iter()
            .next()
            .ok_or(Error::NodeNotFound)?;
        Ok(keys::fingerprint(&key.public_key))
    }

    // ----- identity -------------------------------------------------------

    fn actor(&self) -> &LabUser {
        &self.users[self.active]
    }

    fn user_index(&self, key: &str) -> Option<usize> {
        let key = key.trim();
        self.users.iter().position(|user| {
            user.id.eq_ignore_ascii_case(key)
                || user.name.eq_ignore_ascii_case(key)
                || user.label == key
        })
    }

    fn user_by_label(&self, label: &str) -> Option<&LabUser> {
        self.users.iter().find(|user| user.label == label)
    }

    fn describe_label(&self, label: &str) -> String {
        match self.user_by_label(label) {
            Some(user) => format!("{} ({label})", user.name),
            None => label.to_string(),
        }
    }

    fn visible_labels(&self, label: &str) -> Result<HashSet<String>> {
        key_tree::visible_labels(self.org(), self.org_key_id, label)
    }

    /// Sign in as another person: their home directory and store become
    /// the terminal's, and their mail client checks the relay.
    pub fn switch_user(&mut self, key: &str) -> Result<Outcome> {
        let Some(index) = self.user_index(key) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user named {key}"),
                vec![],
            ));
        };
        self.active = index;
        let home = self.actor().home();
        self.vm_mut().set_cwd(home.clone());
        let user = self.actor();
        let mut visible: Vec<String> = self.visible_labels(&user.label)?.into_iter().collect();
        visible.sort();
        let mut trace = vec![
            TraceStep::pass(format!(
                "Active identity: {} / {} — {}",
                user.name, user.label, user.role
            )),
            TraceStep::info(format!("Home directory {}", home.display())),
            TraceStep::info(format!(
                "Visible slice of the org tree: {}",
                visible.join(", ")
            )),
        ];
        let message = format!("Switched to {} ({})", user.name, user.label);
        let (mail_trace, _) = self.check_mail();
        trace.extend(mail_trace);
        self.log("user", "info", &message, trace.clone(), None);
        Ok(Outcome::done(true, message, trace))
    }

    // ----- drives ---------------------------------------------------------

    pub fn set_drive(&mut self, id: &str, connected: bool) -> Result<Outcome> {
        let Some(drive) = self.vm_mut().bay.get_mut(id) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {id}"),
                vec![],
            ));
        };
        let (name, mount) = (drive.name.clone(), drive.mount.display().to_string());
        if drive.connected == connected {
            let state = if connected {
                "already inserted"
            } else {
                "already ejected"
            };
            return Ok(Outcome::done(true, format!("{name} is {state}"), vec![]));
        }
        drive.connected = connected;
        let mut trace = Vec::new();
        let mut commands = Vec::new();
        if connected {
            trace.push(TraceStep::pass(format!("{name} mounted at {mount}")));
            commands.push(format!("mount {mount}"));
            let list = self.run(&format!("keyquorum-device list {mount}"));
            commands.push(list.line.clone());
            trace.extend(transcript(&list, true));
        } else {
            trace.push(TraceStep::info(format!(
                "{name} unmounted from {mount}; its slots can no longer unwrap shares or sign"
            )));
            commands.push(format!("umount {mount}"));
        }
        let message = format!("{name} {}", if connected { "inserted" } else { "ejected" });
        self.log(
            "usb",
            "info",
            &message,
            trace.clone(),
            Some(commands.join("\n")),
        );
        Ok(Outcome::done(true, message, trace))
    }

    fn drive_holding(&self, label: &str) -> Option<&MockDrive> {
        self.vm().bay.holding(label)
    }

    fn slot_connected(&self, label: &str) -> bool {
        self.drive_holding(label)
            .map(|drive| drive.connected)
            .unwrap_or(false)
    }

    /// `--slot <mount>=<label>` for the active user's own slot.
    fn own_slot_arg(&self) -> Option<String> {
        let label = &self.actor().label;
        self.drive_holding(label)
            .map(|drive| format!("{}={label}", drive.mount.display()))
    }

    /// Move a slot's token to another drive with `keyquorum-device
    /// relocate`, then re-bind its placement in the org store with
    /// `keyquorum device bind`, so device counting follows the token.
    pub fn move_slot(&mut self, label: &str, to_drive_id: &str) -> Result<Outcome> {
        let Some(from) = self.drive_holding(label).map(|drive| drive.mount.clone()) else {
            return Ok(Outcome::done(
                false,
                format!("No drive currently carries the slot {label}"),
                vec![],
            ));
        };
        let Some((to, to_name)) = self
            .vm()
            .bay
            .get(to_drive_id)
            .map(|drive| (drive.mount.clone(), drive.name.clone()))
        else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {to_drive_id}"),
                vec![],
            ));
        };
        if from == to {
            return Ok(Outcome::done(
                true,
                format!("{label} is already on that drive"),
                vec![],
            ));
        }
        let lines = [
            format!(
                "keyquorum-device relocate --from {} --to {} --label {label}",
                from.display(),
                to.display()
            ),
            format!(
                "keyquorum --db {ORG_DB} device bind {} --slot {label}",
                to.display()
            ),
        ];
        let (runs, ok) = self.run_all(&lines);
        let mut trace = transcripts(&runs, true);
        let message = if ok {
            let shared = self
                .vm()
                .bay
                .get(to_drive_id)
                .map(|drive| drive.slots().len())
                .unwrap_or(1);
            if shared > 1 {
                trace.push(TraceStep::info(format!(
                    "{to_name} now carries {shared} slots: logical custody lets them meet a threshold together, but they count as one physical device"
                )));
            }
            format!("Moved {label} to {to_name}")
        } else {
            format!("Could not move {label}: {}", last_error(&runs))
        };
        self.log(
            "move",
            if ok { "info" } else { "denied" },
            &message,
            trace.clone(),
            Some(lines_run(&runs)),
        );
        Ok(Outcome::done(ok, message, trace))
    }

    /// Run lines in order, stopping at the first failure.
    fn run_all(&mut self, lines: &[String]) -> (Vec<CommandRun>, bool) {
        let mut runs = Vec::new();
        for line in lines {
            let run = self.run(line);
            let ok = run.ok;
            runs.push(run);
            if !ok {
                return (runs, false);
            }
        }
        (runs, true)
    }

    // ----- terminal commands ----------------------------------------------

    /// Run one `keyquorum` / `keyquorum-device` line typed at the terminal
    /// or sent by a panel button. The trace is the transcript, plus whose
    /// visible slice of the org tree changed if the command changed it.
    pub fn command(&mut self, line: &str) -> Result<(Outcome, CommandRun)> {
        let before = self.slices()?;
        let run = self.run(line);
        let mut trace = transcript(&run, true);
        let after = self.slices()?;
        for (label, now) in &after {
            let was = &before[label];
            let gained: Vec<&String> = now.difference(was).collect();
            let lost: Vec<&String> = was.difference(now).collect();
            let mut parts = Vec::new();
            if !gained.is_empty() {
                parts.push(format!("now sees {}", sorted_join(gained)));
            }
            if !lost.is_empty() {
                parts.push(format!("no longer sees {}", sorted_join(lost)));
            }
            if !parts.is_empty() {
                trace.push(TraceStep::pass(format!(
                    "{} {}",
                    self.describe_label(label),
                    parts.join("; ")
                )));
            }
        }
        let message = match run.error() {
            Some(error) => format!("error: {error}"),
            None => run.stdout_text().lines().next().unwrap_or(line).to_string(),
        };
        self.log(
            "command",
            if run.ok { "granted" } else { "denied" },
            line,
            trace.clone(),
            Some(line.to_string()),
        );
        Ok((Outcome::done(run.ok, message, trace), run))
    }

    /// Every lab user's visible slice, loading the tree and links once.
    fn slices(&self) -> Result<BTreeMap<String, HashSet<String>>> {
        let (tree, links) = key_tree::load_for_visibility(self.org(), self.org_key_id)?;
        self.users
            .iter()
            .map(|user| {
                Ok((
                    user.label.clone(),
                    key_tree::visible_labels_for_links(&tree, &links, &user.label)?,
                ))
            })
            .collect()
    }

    // ----- files ----------------------------------------------------------

    fn file_index(&self, key: &str) -> Option<usize> {
        let key = key.trim();
        self.files
            .iter()
            .position(|file| file.id == key || file.name == key)
    }

    /// A file in the active user's `~/received`.
    fn received_path(&self, key: &str) -> Option<PathBuf> {
        let name = key.trim().strip_prefix("received/").unwrap_or(key.trim());
        let path = self.actor().received_dir().join(name);
        self.vm().is_file(&path).then_some(path)
    }

    fn leaves(&self, key_id: i64) -> Result<Vec<String>> {
        let tree = KeyQuorumTree::load(self.org(), key_id)?;
        Ok(tree
            .nodes
            .iter()
            .filter(|node| node.is_active && node.hardware_key_id.is_some())
            .map(|node| node.id.clone())
            .collect())
    }

    /// How the active user relates to a file's share holders, for display:
    /// `holder`, `oversight` (an ancestor of a holder), `lineage` (a holder
    /// is their manager), or `none`. Nothing is gated on this; unlocking is
    /// the CLI's decision.
    fn relation(&self, file: &LabFile) -> Result<&'static str> {
        let FileKind::Quorum { key_id, .. } = &file.kind else {
            return Ok("public");
        };
        let actor = &self.actor().label;
        let leaves = self.leaves(*key_id)?;
        Ok(if leaves.iter().any(|label| label == actor) {
            "holder"
        } else if leaves.iter().any(|label| is_ancestor_or_self(actor, label)) {
            "oversight"
        } else if leaves.iter().any(|label| is_ancestor_or_self(label, actor)) {
            "lineage"
        } else {
            "none"
        })
    }

    /// The unlock command for a quorum file: every inserted slot that
    /// holds a share of it, and, when the file needs parent approval, each
    /// holder's parent whose slot is inserted too. The command decides.
    fn unlock_line(
        &self,
        file_id: i64,
        key_id: i64,
        output: Option<&Path>,
    ) -> Result<(String, Vec<String>)> {
        let leaves = self.leaves(key_id)?;
        let mut line =
            format!("keyquorum --db {ORG_DB} access quorum --state 1 --id {file_id} --verbose");
        let mut presented = Vec::new();
        for leaf in &leaves {
            if let Some(drive) = self.drive_holding(leaf).filter(|drive| drive.connected) {
                line.push_str(&format!(" --slot {}={leaf}", drive.mount.display()));
                presented.push(leaf.clone());
            }
        }
        if device::custody_policy(self.org(), key_id)?.unlock_approval == UnlockApproval::Parent {
            for leaf in &presented {
                let Some(parent) = parent_node_label(leaf) else {
                    continue;
                };
                if let Some(drive) = self.drive_holding(parent).filter(|drive| drive.connected) {
                    line.push_str(&format!(
                        " --approve {leaf}={}>{parent}",
                        drive.mount.display()
                    ));
                }
            }
        }
        if let Some(output) = output {
            line.push_str(&format!(
                " --output {}",
                quote(&output.display().to_string())
            ));
        }
        Ok((line, presented))
    }

    /// Open a file: `cat` for plaintext (public or received), `keyquorum
    /// access quorum --state 1` for a quorum-locked one.
    pub fn unlock(&mut self, key: &str) -> Result<Outcome> {
        if let Some(path) = self.received_path(key) {
            return self.cat(&path);
        }
        let Some(index) = self.file_index(key) else {
            return Ok(Outcome::done(false, format!("No file named {key}"), vec![]));
        };
        let (file_id, key_id) = match &self.files[index].kind {
            FileKind::Public { path } => {
                let path = path.clone();
                return self.cat(&path);
            }
            FileKind::Quorum { file_id, key_id } => (*file_id, *key_id),
        };
        let name = self.files[index].name.clone();
        let (line, presented) = self.unlock_line(file_id, key_id, None)?;
        let required = self.leaves(key_id)?;
        let run = self.run(&line);
        let mut trace = transcript(&run, false);
        let opened = if run.ok {
            trace.push(TraceStep::pass(format!(
                "Decrypted {} bytes of {name}",
                run.stdout.len()
            )));
            Some(OpenedFile {
                name: name.clone(),
                text: run.stdout_text(),
            })
        } else {
            None
        };
        let message = if run.ok {
            format!("Access granted: {name}")
        } else {
            format!("Access denied: {name}")
        };
        self.last_access = Some(AccessView {
            file_id: self.files[index].id.clone(),
            file_name: name,
            granted: run.ok,
            required,
            satisfied: presented,
        });
        self.log(
            "access",
            if run.ok { "granted" } else { "denied" },
            &message,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome {
            ok: run.ok,
            message,
            trace,
            opened,
        })
    }

    fn cat(&mut self, path: &Path) -> Result<Outcome> {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let contents = self.vm().read(path)?;
        let trace = vec![TraceStep::pass(format!(
            "{} is plaintext: no key tree protects it",
            path.display()
        ))];
        let message = format!("Access granted: {name}");
        self.log(
            "access",
            "granted",
            &message,
            trace.clone(),
            Some(format!("cat {}", quote(&path.display().to_string()))),
        );
        Ok(Outcome {
            ok: true,
            message,
            trace,
            opened: Some(OpenedFile {
                name,
                text: String::from_utf8_lossy(&contents).into_owned(),
            }),
        })
    }

    // ----- delivery -------------------------------------------------------

    /// Send a file with `keyquorum deliver send --push`. A quorum-locked
    /// file is first opened to a temporary file with `access quorum
    /// --state 1 --output` (so only someone who can open it can send it),
    /// which is removed afterward.
    pub fn send(&mut self, file_key: &str, recipient_key: &str) -> Result<Outcome> {
        let Some(recipient) = self.user_index(recipient_key) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user named {recipient_key}"),
                vec![],
            ));
        };
        let (to_id, to_label, to_name) = {
            let user = &self.users[recipient];
            (user.id.clone(), user.label.clone(), user.name.clone())
        };
        let (me_label, store) = (self.actor().label.clone(), self.actor().store());
        let Some(slot) = self.own_slot_arg() else {
            return Ok(Outcome::done(
                false,
                "You have no slot on any drive",
                vec![],
            ));
        };

        let mut lines = Vec::new();
        let mut temporary = None;
        let (source, name) = if let Some(path) = self.received_path(file_key) {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            (path, name.unwrap_or_default())
        } else {
            let Some(index) = self.file_index(file_key) else {
                return Ok(Outcome::done(
                    false,
                    format!("No file named {file_key}"),
                    vec![],
                ));
            };
            let name = self.files[index].name.clone();
            match &self.files[index].kind {
                FileKind::Public { path } => (path.clone(), name),
                FileKind::Quorum { file_id, key_id } => {
                    let (file_id, key_id) = (*file_id, *key_id);
                    let temp = self.actor().home().join(".outgoing").join(&name);
                    let (line, _) = self.unlock_line(file_id, key_id, Some(&temp))?;
                    lines.push(line);
                    temporary = Some(temp.clone());
                    (temp, name)
                }
            }
        };
        lines.push(format!(
            "keyquorum --db {store} deliver send --file {} --name {} --to {to_label} --as {me_label} --slot {slot} --push",
            quote(&source.display().to_string()),
            quote(&name)
        ));
        let (runs, ok) = self.run_all(&lines);
        let mut trace = transcripts(&runs, false);
        let mut commands = lines_run(&runs);
        if let Some(temp) = &temporary {
            if self.vm().exists(temp) {
                self.remove_file(temp)?;
                commands.push_str(&format!("\nrm {}", quote(&temp.display().to_string())));
                trace.push(TraceStep::info(format!(
                    "Removed the temporary plaintext {}",
                    temp.display()
                )));
            }
        }
        let title = format!("Send {name} to {to_name}");
        if !ok {
            let message = format!("{title}: {}", last_error(&runs));
            self.log("send", "denied", &title, trace.clone(), Some(commands));
            return Ok(Outcome::done(false, message, trace));
        }
        let sent_output = runs.last().map(CommandRun::stdout_text).unwrap_or_default();
        let delivery_id = sent_output
            .lines()
            .find_map(|line| line.rsplit_once("(delivery "))
            .map(|(_, rest)| rest.trim_end_matches(')').to_string())
            .unwrap_or_default();
        let relay_id = sent_output
            .lines()
            .find_map(|line| line.strip_prefix("Relay stored letter "))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|id| id.parse().ok())
            .unwrap_or(0);
        let me = self.actor().id.clone();
        self.mail.entry(me).or_default().sent.push(SentItem {
            delivery_id,
            relay_id,
            to: to_id,
            file_name: name.clone(),
            status: SentStatus::Delivered,
        });
        let message = format!("Transfer delivered to the relay for {to_name}");
        self.log("send", "granted", &title, trace.clone(), Some(commands));
        Ok(Outcome::done(true, message, trace))
    }

    /// Check the relay with `keyquorum relay pull`, then check any new
    /// acknowledgements with `keyquorum deliver ack` (which needs the
    /// active user's slot inserted). Returns the trace and how many new
    /// envelopes arrived.
    fn check_mail(&mut self) -> (Vec<TraceStep>, usize) {
        let user = self.actor();
        let (me, store, mail_dir) = (user.id.clone(), user.store(), user.mail_dir());
        let before = self.mail_ids(&mail_dir);
        let mut line = format!(
            "keyquorum --db {store} relay pull --output-dir {}",
            mail_dir.display()
        );
        if let Some(last) = before.iter().max() {
            line.push_str(&format!(" --after {last}"));
        }
        let pull = self.run(&line);
        let mut trace = transcript(&pull, true);
        let arrived = self.mail_ids(&mail_dir).len() - before.len();

        let acks: Vec<i64> = self
            .mail_ids(&mail_dir)
            .into_iter()
            .filter(|id| {
                !self
                    .mail
                    .get(&me)
                    .is_some_and(|mailbox| mailbox.acks_checked.contains(id))
                    && self.letter_kind(&mail_dir, *id) == Some(envelope::KIND_FILE_DELIVERY_ACK)
            })
            .collect();
        if acks.is_empty() {
            return (trace, arrived);
        }
        let Some(slot) = self
            .own_slot_arg()
            .filter(|_| self.slot_connected(&self.actor().label))
        else {
            trace.push(TraceStep::info(format!(
                "{} acknowledgement(s) waiting, sealed to your key — insert your USB to check them",
                acks.len()
            )));
            return (trace, arrived);
        };
        for id in acks {
            let run = self.run(&format!(
                "keyquorum --db {store} deliver ack --file {}/{id}.kqpb --slot {slot}",
                mail_dir.display()
            ));
            trace.extend(transcript(&run, true));
            let mailbox = self.mail.entry(me.clone()).or_default();
            mailbox.acks_checked.insert(id);
            // "Delivery <id> accepted|rejected by <label>"
            let output = run.stdout_text();
            let Some(rest) = output
                .lines()
                .find_map(|line| line.strip_prefix("Delivery "))
            else {
                continue;
            };
            let mut words = rest.split_whitespace();
            let (Some(delivery_id), Some(verdict)) = (words.next(), words.next()) else {
                continue;
            };
            if let Some(item) = mailbox
                .sent
                .iter_mut()
                .find(|item| item.delivery_id == delivery_id)
            {
                item.status = if verdict == "accepted" {
                    SentStatus::Acknowledged
                } else {
                    SentStatus::Rejected
                };
            }
        }
        (trace, arrived)
    }

    fn mail_ids(&self, dir: &Path) -> Vec<i64> {
        self.vm()
            .list(dir)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|path| {
                path.file_name()?
                    .to_str()?
                    .strip_suffix(".kqpb")?
                    .parse()
                    .ok()
            })
            .collect()
    }

    /// The public kind byte in an envelope's header (not its contents).
    fn letter_kind(&self, dir: &Path, id: i64) -> Option<u8> {
        let bytes = self.vm().read(&dir.join(format!("{id}.kqpb"))).ok()?;
        envelope::kind(&bytes).ok()
    }

    /// Check the relay for new letters and acknowledgements.
    pub fn refresh_inbox(&mut self) -> Result<Outcome> {
        let (trace, arrived) = self.check_mail();
        let message = match arrived {
            0 => "Inbox up to date".to_string(),
            1 => "1 new envelope from the relay".to_string(),
            n => format!("{n} new envelopes from the relay"),
        };
        self.log("receive", "info", &message, trace.clone(), None);
        Ok(Outcome::done(true, message, trace))
    }

    /// Open (or reject) a letter with `keyquorum deliver open`, which
    /// verifies the sender and pushes a signed answer back.
    pub fn receive(&mut self, relay_id: i64, accept: bool) -> Result<Outcome> {
        let user = self.actor();
        let (me, label, store, mail_dir, received) = (
            user.id.clone(),
            user.label.clone(),
            user.store(),
            user.mail_dir(),
            user.received_dir(),
        );
        let title = format!(
            "{} letter #{relay_id}",
            if accept { "Receive" } else { "Reject" }
        );
        if self.letter_kind(&mail_dir, relay_id) != Some(envelope::KIND_FILE_DELIVERY) {
            return Ok(Outcome::done(
                false,
                format!("Letter #{relay_id} is not in your mailbox"),
                vec![],
            ));
        }
        if self
            .mail
            .get(&me)
            .is_some_and(|mailbox| mailbox.opened.contains_key(&relay_id))
        {
            return Ok(Outcome::done(
                false,
                "That letter was already answered",
                vec![],
            ));
        }
        let slot = self.own_slot_arg().unwrap_or_default();
        let line = format!(
            "keyquorum --db {store} deliver open --file {}/{relay_id}.kqpb --slot {slot} {} --push-ack",
            mail_dir.display(),
            if accept {
                format!("--save-dir {}", received.display())
            } else {
                "--reject".to_string()
            }
        );
        let run = self.run(&line);
        let trace = transcript(&run, true);
        if !run.ok {
            let message = if self.slot_connected(&label) {
                format!(
                    "Could not open letter #{relay_id}: {}",
                    run.error().unwrap_or("failed")
                )
            } else {
                "Insert your USB to open the letter".to_string()
            };
            self.log("receive", "denied", &title, trace.clone(), Some(line));
            return Ok(Outcome::done(false, message, trace));
        }
        // "From <sender> to <recipient>: <name> (<n> bytes), signature verified"
        let (from, file_name) = run
            .stderr
            .lines()
            .find_map(|line| line.strip_prefix("From "))
            .and_then(|rest| {
                let (from, rest) = rest.split_once(" to ")?;
                let (_, rest) = rest.split_once(": ")?;
                let (name, _) = rest.rsplit_once(" (")?;
                Some((from.to_string(), name.to_string()))
            })
            .unwrap_or_default();
        let opened = if accept {
            let path = received.join(&file_name);
            self.vm().read(&path).ok().map(|contents| OpenedFile {
                name: file_name.clone(),
                text: String::from_utf8_lossy(&contents).into_owned(),
            })
        } else {
            None
        };
        self.mail.entry(me).or_default().opened.insert(
            relay_id,
            Opened {
                status: if accept {
                    InboxStatus::Received
                } else {
                    InboxStatus::Rejected
                },
                from,
                file_name: file_name.clone(),
            },
        );
        let message = if accept {
            format!("Transfer received: {file_name}")
        } else {
            format!("Transfer rejected: {file_name}")
        };
        self.log(
            "receive",
            if accept { "granted" } else { "info" },
            &message,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome {
            ok: true,
            message,
            trace,
            opened,
        })
    }

    // ----- snapshot -------------------------------------------------------

    fn log(
        &mut self,
        kind: &str,
        outcome: &str,
        title: &str,
        trace: Vec<TraceStep>,
        command: Option<String>,
    ) {
        let actor = self.actor();
        self.activity.push(ActivityView {
            seq: self.next_seq,
            actor: format!("{} ({})", actor.name, actor.label),
            kind: kind.to_string(),
            outcome: outcome.to_string(),
            title: title.to_string(),
            trace,
            command,
        });
        self.next_seq += 1;
        if self.activity.len() > ACTIVITY_LIMIT {
            let excess = self.activity.len() - ACTIVITY_LIMIT;
            self.activity.drain(..excess);
        }
    }

    pub fn inspect(&self, key: &str) -> Result<Option<FileView>> {
        if let Some(path) = self.received_path(key) {
            return Ok(Some(self.received_view(&path)?));
        }
        match self.file_index(key) {
            Some(index) => Ok(Some(self.file_view(&self.files[index])?)),
            None => Ok(None),
        }
    }

    fn file_view(&self, file: &LabFile) -> Result<FileView> {
        let (requirement, policy, quorum_file_id) = match &file.kind {
            FileKind::Quorum { file_id, key_id } => {
                let summary = key_tree::describe(self.org(), *key_id)?;
                let policy = device::custody_policy(self.org(), *key_id)?;
                (
                    Some(self.requirement(&summary.root)?),
                    Some(PolicyView {
                        custody: match policy.mode {
                            CustodyMode::Hardware => "hardware".into(),
                            CustodyMode::Logical => "logical".into(),
                        },
                        minimum_devices: policy.minimum_physical_devices,
                        approval: match policy.unlock_approval {
                            UnlockApproval::None => "none".into(),
                            UnlockApproval::Parent => "parent".into(),
                        },
                    }),
                    Some(*file_id),
                )
            }
            FileKind::Public { .. } => (None, None, None),
        };
        let expired = match &file.expires_at {
            Some(expires_at) => expiry_passed(self.vm().relay_conn(), expires_at)?,
            None => false,
        };
        Ok(FileView {
            id: file.id.clone(),
            folder: file.folder.clone(),
            name: file.name.clone(),
            lesson: file.lesson.clone(),
            protection: match file.kind {
                FileKind::Public { .. } => "public",
                FileKind::Quorum { .. } => "quorum",
            }
            .into(),
            access: self.relation(file)?.into(),
            size: file.size,
            created_at: file.created_at.clone(),
            expires_at: file.expires_at.clone(),
            expired,
            requirement,
            policy,
            quorum_file_id,
            received_from: None,
        })
    }

    fn received_view(&self, path: &Path) -> Result<FileView> {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let from = self.mail.get(&self.actor().id).and_then(|mailbox| {
            mailbox
                .opened
                .values()
                .rev()
                .find(|opened| opened.status == InboxStatus::Received && opened.file_name == name)
                .map(|opened| self.describe_label(&opened.from))
        });
        Ok(FileView {
            id: format!("received/{name}"),
            folder: "received".into(),
            lesson: format!(
                "Delivered with keyquorum deliver and saved to {} after the sender's signature verified.",
                path.display()
            ),
            name,
            protection: "received".into(),
            access: "holder".into(),
            size: self.vm().read(path)?.len(),
            created_at: String::new(),
            expires_at: None,
            expired: false,
            requirement: None,
            policy: None,
            quorum_file_id: None,
            received_from: from,
        })
    }

    fn requirement(&self, node: &TreeNodeSummary) -> Result<RequirementNode> {
        // The same question `device::leaf_is_ghost` asks at reconstruction:
        // is this leaf's identity a real `transfer.rs` ghost.
        let ghost = node.hardware_key_id.is_some()
            && transfer::possession(self.org(), &node.label)? == Some(transfer::Possession::Ghost);
        let children = node
            .children
            .iter()
            .map(|child| self.requirement(child))
            .collect::<Result<Vec<_>>>()?;
        Ok(RequirementNode {
            label: node.label.clone(),
            threshold: node.threshold,
            holder: node.hardware_key_id.and_then(|_| {
                self.user_by_label(&node.label)
                    .map(|user| user.name.clone())
                    .or_else(|| {
                        node.hardware_key_label
                            .clone()
                            .filter(|label| label != &node.label)
                    })
            }),
            ghost,
            children,
        })
    }

    fn user_view(&self, index: usize, visible: &HashSet<String>) -> UserView {
        let user = &self.users[index];
        UserView {
            id: user.id.clone(),
            name: user.name.clone(),
            label: user.label.clone(),
            role: user.role.clone(),
            drive_id: self
                .drive_holding(&user.label)
                .map(|drive| drive.id.clone())
                .unwrap_or_else(|| user.drive.clone()),
            active: index == self.active,
            visible: visible.contains(&user.label),
        }
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let actor = self.actor();
        let visible = self.visible_labels(&actor.label)?;
        let users: Vec<UserView> = (0..self.users.len())
            .map(|index| self.user_view(index, &visible))
            .collect();

        let drives = self
            .vm()
            .bay
            .drives
            .iter()
            .map(|drive| DriveView {
                id: drive.id.clone(),
                name: drive.name.clone(),
                mount: drive.mount.display().to_string(),
                connected: drive.connected,
                device_id: drive.device_id().map(hex::encode).unwrap_or_default(),
                slots: drive
                    .slots()
                    .into_iter()
                    .map(|label| SlotView {
                        holder: self
                            .user_by_label(&label)
                            .map(|user| user.name.clone())
                            .unwrap_or_default(),
                        label,
                    })
                    .collect(),
                files: if drive.connected {
                    drive.listing()
                } else {
                    Vec::new()
                },
            })
            .collect();

        let tree = self.tree_view(&visible)?;

        let mut files = self
            .files
            .iter()
            .map(|file| self.file_view(file))
            .collect::<Result<Vec<_>>>()?;
        for path in self.vm().list(&actor.received_dir()).unwrap_or_default() {
            files.push(self.received_view(&path)?);
        }

        let mailbox = self.mail.get(&actor.id);
        let mail_dir = actor.mail_dir();
        let mut inbox = Vec::new();
        let mut pending_acks = 0;
        for id in self.mail_ids(&mail_dir) {
            match self.letter_kind(&mail_dir, id) {
                Some(envelope::KIND_FILE_DELIVERY) => {
                    let opened = mailbox.and_then(|mailbox| mailbox.opened.get(&id));
                    inbox.push(InboxItemView {
                        relay_id: id,
                        status: match opened.map(|opened| opened.status) {
                            None => "new",
                            Some(InboxStatus::Received) => "received",
                            Some(InboxStatus::Rejected) => "rejected",
                        }
                        .into(),
                        bytes: self
                            .vm()
                            .read(&mail_dir.join(format!("{id}.kqpb")))
                            .map(|bytes| bytes.len())
                            .unwrap_or(0),
                        from: opened.map(|opened| self.describe_label(&opened.from)),
                        file_name: opened.map(|opened| opened.file_name.clone()),
                        file_id: opened
                            .filter(|opened| opened.status == InboxStatus::Received)
                            .map(|opened| format!("received/{}", opened.file_name)),
                    });
                }
                Some(envelope::KIND_FILE_DELIVERY_ACK)
                    if !mailbox.is_some_and(|mailbox| mailbox.acks_checked.contains(&id)) =>
                {
                    pending_acks += 1;
                }
                _ => {}
            }
        }
        inbox.sort_by_key(|item| item.relay_id);

        let sent = mailbox
            .map(|mailbox| {
                mailbox
                    .sent
                    .iter()
                    .map(|item| {
                        let to = self.users.iter().find(|user| user.id == item.to);
                        SentItemView {
                            delivery_id: item.delivery_id.clone(),
                            relay_id: item.relay_id,
                            to: to.map(|user| user.name.clone()).unwrap_or_default(),
                            to_label: to.map(|user| user.label.clone()).unwrap_or_default(),
                            file_name: item.file_name.clone(),
                            status: match item.status {
                                SentStatus::Delivered => "delivered",
                                SentStatus::Acknowledged => "acknowledged",
                                SentStatus::Rejected => "rejected",
                            }
                            .into(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Snapshot {
            active_user: self.user_view(self.active, &visible),
            users,
            drives,
            tree,
            files,
            inbox,
            pending_acks,
            sent,
            activity: self.activity.iter().rev().cloned().collect(),
            last_access: self.last_access.clone(),
            cwd: self.vm().cwd().display().to_string(),
            org_db: ORG_DB.to_string(),
        })
    }

    fn tree_view(&self, visible: &HashSet<String>) -> Result<TreeView> {
        let tree = KeyQuorumTree::load(self.org(), self.org_key_id)?;
        let actor = self.actor();
        let (required, satisfied): (HashSet<&str>, HashSet<&str>) = match &self.last_access {
            Some(access) => (
                access.required.iter().map(String::as_str).collect(),
                access.satisfied.iter().map(String::as_str).collect(),
            ),
            None => (HashSet::new(), HashSet::new()),
        };
        let nodes = tree
            .nodes
            .iter()
            .map(|node| {
                let person = self.user_by_label(&node.id);
                TreeNodeView {
                    label: node.id.clone(),
                    parent: node.parent_idx.map(|idx| tree.nodes[idx].id.clone()),
                    kind: if node.hardware_key_id.is_some() {
                        "leaf".into()
                    } else {
                        "split".into()
                    },
                    threshold: node.threshold,
                    person: person.map(|user| user.name.clone()),
                    role: person.map(|user| user.role.clone()),
                    active_user: node.id == actor.label,
                    visible: visible.contains(&node.id),
                    slot_drive: self.drive_holding(&node.id).map(|drive| drive.name.clone()),
                    slot_connected: self.slot_connected(&node.id),
                    required: required.contains(node.id.as_str()),
                    satisfied: satisfied.contains(node.id.as_str()),
                }
            })
            .collect();
        let listing = key_tree::list_bridges(self.org(), self.org_key_id)?;
        let bridges = listing
            .established
            .into_iter()
            .map(|edge| (edge.from, edge.to))
            .collect();
        Ok(TreeView {
            key_id: self.org_key_id,
            nodes,
            bridges,
            allowed: listing.allowed,
        })
    }

    // ----- terminal support -----------------------------------------------

    pub(crate) fn user_names(&self) -> Vec<(String, String, String, bool)> {
        self.users
            .iter()
            .enumerate()
            .map(|(index, user)| {
                (
                    user.name.clone(),
                    user.label.clone(),
                    user.role.clone(),
                    index == self.active,
                )
            })
            .collect()
    }

    pub(crate) fn active_summary(&self) -> String {
        let actor = self.actor();
        format!("{} ({}) — {}", actor.name, actor.label, actor.role)
    }

    /// A shell path: `~` is the active user's home.
    fn shell_path(&self, path: &str) -> PathBuf {
        let path = match path.strip_prefix('~') {
            Some(rest) => self.actor().home().join(rest.trim_start_matches('/')),
            None => PathBuf::from(path),
        };
        self.vm().resolve(&path)
    }

    /// A shell's `ls`: entries of a directory in the VM.
    pub(crate) fn ls(&self, path: &str) -> Result<Vec<String>> {
        let dir = self.shell_path(path);
        Ok(self
            .vm()
            .list(&dir)?
            .into_iter()
            .map(|entry| entry.display().to_string())
            .collect())
    }

    /// A shell's `cat`.
    pub(crate) fn read_text(&self, path: &str) -> Result<String> {
        let path = self.shell_path(path);
        Ok(String::from_utf8_lossy(&self.vm().read(&path)?).into_owned())
    }

    /// A shell's `cd`.
    pub(crate) fn cd(&mut self, path: &str) -> String {
        let dir = self.shell_path(path);
        self.vm_mut().set_cwd(dir.clone());
        dir.display().to_string()
    }

    pub(crate) fn cwd(&self) -> String {
        self.vm().cwd().display().to_string()
    }
}

/// The trace of one command: the line, what it printed on stderr (prompts
/// with masked answers, diagnostics), and, when `with_stdout`, its output.
fn transcript(run: &CommandRun, with_stdout: bool) -> Vec<TraceStep> {
    let mut steps = vec![TraceStep::info(format!("$ {}", run.line))];
    for line in run.stderr.lines() {
        if line.starts_with("error: ") {
            steps.push(TraceStep::fail(line));
        } else {
            steps.push(TraceStep::info(line));
        }
    }
    if with_stdout {
        steps.extend(run.stdout_text().lines().map(TraceStep::pass));
    }
    steps
}

fn transcripts(runs: &[CommandRun], with_stdout: bool) -> Vec<TraceStep> {
    runs.iter()
        .flat_map(|run| transcript(run, with_stdout))
        .collect()
}

fn lines_run(runs: &[CommandRun]) -> String {
    runs.iter()
        .map(|run| run.line.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn last_error(runs: &[CommandRun]) -> String {
    runs.iter()
        .rev()
        .find_map(|run| run.error())
        .unwrap_or("failed")
        .to_string()
}

fn sorted_join(labels: Vec<&String>) -> String {
    let mut labels: Vec<&str> = labels.into_iter().map(String::as_str).collect();
    labels.sort_unstable();
    labels.join(", ")
}

/// Whether a resolved expiry has passed, on SQLite's clock. Never
/// destructive on its own: the purge happens when an unlock touches it.
fn expiry_passed(conn: &Connection, expires_at: &str) -> Result<bool> {
    conn.query_row(
        "SELECT datetime(?1) <= datetime('now')",
        rusqlite::params![expires_at],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// The org tree `keyquorum split --tree-spec` builds at seed time. Leaves
/// name their key by `public_key_file`, relative to this file.
const ORG_TREE_SPEC: &str = r#"{
  "label": "M",
  "threshold": 2,
  "children": [
    {
      "label": "M.S",
      "threshold": 2,
      "children": [
        { "label": "M.S.1", "public_key_file": "keys/M.S.1.pub" },
        { "label": "M.S.2", "public_key_file": "keys/M.S.2.pub" }
      ]
    },
    {
      "label": "M.A",
      "threshold": 2,
      "children": [
        { "label": "M.A.1", "public_key_file": "keys/M.A.1.pub" },
        { "label": "M.A.2", "public_key_file": "keys/M.A.2.pub" }
      ]
    }
  ]
}
"#;
