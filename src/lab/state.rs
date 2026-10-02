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

mod history;

const ACTIVITY_LIMIT: usize = 80;
const SRV: &str = "/srv/keyquorum";
const ARCHIVE: &str = "/srv/archive";
const TRACKED_DIR: &str = "/srv/keyquorum/tracked";
/// The store the seeded tracked files are made with: their author's own.
const SEED_TRACKER_STORE: &str = "/home/sarah/keyquorum.sqlite";

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

/// A password-locked file a lab user created from the GUI (`access
/// password --state 0`), tracked so the Security panel can list and unlock
/// it later. Lives in that user's own personal store, never the org DB.
struct PasswordFile {
    id: i64,
    name: String,
    owner: String,
    created_at: String,
    expires_at: Option<String>,
    pin: bool,
}

/// A portable `KQXB` bundle a lab user exported from one of their own
/// password-locked files (`keyquorum export file`), tracked so the
/// Security panel can list it and let its exporter view the sealed bytes
/// later. The bundle itself lives in the exporter's home directory.
struct ExportedBundle {
    id: i64,
    file_name: String,
    owner: String,
    recipient: String,
    path: PathBuf,
    size: usize,
    created_at: String,
}

/// A share link a lab user created for one of their own password-locked
/// files (`keyquorum share create-file`). The bearer token itself is
/// never kept here — only its metadata — matching the crate's own
/// show-once, hash-only storage.
struct FileShare {
    id: i64,
    file_name: String,
    owner: String,
    pin_protected: bool,
    expires_at: String,
    revoked: bool,
}

/// A signature a lab user produced over a public or received file with
/// `keyquorum sign`, tracked so the panel can list it and let a bridge
/// member verify it later against the same plaintext.
struct SignedFile {
    id: i64,
    /// The lookup key (`file_index`/`received_path`) that resolves back
    /// to the exact plaintext this signature covers.
    source_key: String,
    file_name: String,
    /// Tree label of the signer (`M.S` or `M.A`), not their bridge label.
    signer: String,
    bridge_uid: String,
    path: PathBuf,
    size: usize,
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
    /// Uid of the org's one private sign bridge (`LabState::sign_file`).
    bridge_uid: String,
    mail: HashMap<String, Mailbox>,
    activity: Vec<ActivityView>,
    next_seq: u64,
    last_access: Option<AccessView>,
    password_files: Vec<PasswordFile>,
    exports: Vec<ExportedBundle>,
    next_export_id: i64,
    file_shares: Vec<FileShare>,
    signatures: Vec<SignedFile>,
    next_signature_id: i64,
    /// Tracked-file containers whose history the activity log follows.
    tracked: Vec<history::Tracked>,
    /// Tracked-file letters handed between people in the lab.
    letters: Vec<history::TrackedLetter>,
    next_letter_id: i64,
    /// Request letters (`file request`) and their answers.
    requests: Vec<history::TrackedRequest>,
    next_request_id: i64,
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
            bridge_uid: String::new(),
            mail: HashMap::new(),
            activity: Vec::new(),
            next_seq: 1,
            last_access: None,
            password_files: Vec::new(),
            exports: Vec::new(),
            next_export_id: 1,
            file_shares: Vec::new(),
            signatures: Vec::new(),
            next_signature_id: 1,
            tracked: Vec::new(),
            letters: Vec::new(),
            next_letter_id: 1,
            requests: Vec::new(),
            next_request_id: 1,
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

        // `seed::RESTRUCTURE_AUTHORITY`'s own authority signing key,
        // replacing the one just registered from her device slot above:
        // `reissue`/`tree restructure` need a plaintext private key file
        // to authorize `--as`, which a device slot can never produce.
        {
            let authority_label = seed::RESTRUCTURE_AUTHORITY;
            let old_signing =
                keys::active_keys_for(self.org(), authority_label, keys::KeyType::Signing)?
                    .into_iter()
                    .next()
                    .ok_or(Error::NodeNotFound)?;
            run(
                self,
                format!("keyquorum --db {ORG_DB} revoke {}", old_signing.id),
            )?;
            let generated = run(
                self,
                format!(
                    "keyquorum --db {ORG_DB} generate --type signing --public-key-out {SRV}/keys/{authority_label}-authority.pub --label {authority_label} --register"
                ),
            )?;
            let private_hex = generated
                .stdout_text()
                .lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .ok_or_else(|| {
                    Error::Usage("lab setup: no private key on stdout of `generate`".into())
                })?
                .to_string();
            let owner = self
                .user_by_label(authority_label)
                .ok_or(Error::NodeNotFound)?;
            let key_path = owner
                .home()
                .join("keys")
                .join(format!("{authority_label}-authority.key"));
            self.write_file(&key_path, private_hex.as_bytes())?;
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

        // The org's one private sign bridge, between the same two
        // managers, each with a personal signing key generated and
        // registered under its own (undotted) label — see
        // `seed::BRIDGE_SIGNERS` for why this is not their device slot's
        // signing key.
        for (tree_label, signer_label) in seed::BRIDGE_SIGNERS {
            let generated = run(
                self,
                format!(
                    "keyquorum --db {ORG_DB} generate --type signing --public-key-out {SRV}/keys/{signer_label}.pub --label {signer_label} --register"
                ),
            )?;
            let private_hex = generated
                .stdout_text()
                .lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .ok_or_else(|| {
                    Error::Usage("lab setup: no private key on stdout of `generate`".into())
                })?
                .to_string();
            let owner = self.user_by_label(tree_label).ok_or(Error::NodeNotFound)?;
            let key_path = owner
                .home()
                .join("keys")
                .join(format!("{signer_label}.key"));
            self.write_file(&key_path, private_hex.as_bytes())?;
        }
        let (a_signer, b_signer) = (seed::BRIDGE_SIGNERS[0].1, seed::BRIDGE_SIGNERS[1].1);
        let bridge_packages = Path::new(SRV).join("bridge-packages");
        let created = run(
            self,
            format!(
                "keyquorum --db {ORG_DB} bridge private create {key} --member {a_signer}={SRV}/keys/{a}.pub --member {b_signer}={SRV}/keys/{b}.pub --self {a_signer} --output-dir {} --label {}",
                bridge_packages.display(),
                seed::PRIVATE_BRIDGE_LABEL,
            ),
        )?;
        self.bridge_uid = created
            .stdout_text()
            .lines()
            .find_map(|line| line.strip_prefix("Created private bridge "))
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_string)
            .ok_or_else(|| {
                Error::Usage("lab setup: no bridge uid in `bridge private create` output".into())
            })?;
        // David's own package sits in `bridge_packages` for delivery to
        // his own store on a real deployment. The lab has only one org
        // database, and `bridge private import` refuses a bridge this
        // store already has a row for (`create` just wrote one), so David
        // stays a full roster member — his signing and encryption public
        // keys are recorded, and either of them can verify his signature
        // — without a usable sealed copy of the shared secret to sign
        // with here. That is the crate's real "at most one store keeps
        // the local member's sealed copy" rule, not a shortcut.

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
        // The org store also sends: a quorum file is unlocked there (its
        // wrapped shares live nowhere else), so `send --quorum-file` runs
        // against it with its own push key.
        let org_push = self.issue_api_key(ApiKeyScope::InboxPush, None, "org push")?;
        run(self, format!("keyquorum --db {ORG_DB} loadkey {org_push}"))?;
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
            // Where this person's own slot lives is their default, so
            // `doctor` can say whether their setup is whole.
            if let Some(mount) = self
                .drive_holding(&label)
                .map(|d| d.mount.display().to_string())
            {
                run(
                    self,
                    format!("keyquorum --db {store} use --device {mount} --slot {label}"),
                )?;
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
            // Binding follows the keys being registered: this person's own
            // slot now belongs to the device it sits on.
            if let Some(mount) = self
                .drive_holding(&label)
                .map(|d| d.mount.display().to_string())
            {
                run(
                    self,
                    format!("keyquorum --db {store} device bind {mount} --slot {label}"),
                )?;
            }
        }

        // Tracked files with a history, made by real `keyquorum file`
        // commands while every drive is still connected.
        commands.set(commands.get() + self.seed_tracked()?);

        for drive in seed::DRIVES {
            if !drive.inserted {
                if let Some(mock) = self.vm_mut().bay.get_mut(drive.id) {
                    mock.connected = false;
                }
            }
        }
        Ok(commands.get())
    }

    /// Three tracked files, each ending somewhere different: a newer
    /// unsigned edit that shares the last trusted revision, two edits by
    /// Alice and Bob that auto-merge, and two edits to one line that go to
    /// a person (Sarah, who wrote the trusted base). Every
    /// step is a real `keyquorum file` command; the history is then read
    /// back from the containers into the activity log.
    fn seed_tracked(&mut self) -> Result<usize> {
        let count = std::cell::Cell::new(0usize);
        let run = |state: &mut Self, line: String| -> Result<CommandRun> {
            count.set(count.get() + 1);
            state.checked(&line)
        };
        let mount = |label: &str| -> Result<String> {
            seed::DRIVES
                .iter()
                .find(|drive| drive.slots.contains(&label))
                .map(|drive| format!("{}={label}", drive.mount))
                .ok_or(Error::NodeNotFound)
        };
        let sarah = mount("M.S")?;
        let dir = TRACKED_DIR;
        let file = |name: &str| format!("{dir}/{name}.kqtf");
        let edit = |state: &mut Self, name: &str, text: &str| -> Result<String> {
            let path = format!("{dir}/{name}");
            state.write_file(Path::new(&path), text.as_bytes())?;
            Ok(path)
        };
        let db = format!("keyquorum --db {} file", SEED_TRACKER_STORE);

        // 1. A newer edit nobody has signed: sharing falls back.
        let source = edit(self, "budget.txt", "Q4 budget: 120000\n")?;
        run(
            self,
            format!(
                "{db} track {source} --scope M.S --as M.S --slot {sarah} --label \"Q4 baseline\""
            ),
        )?;
        let later = edit(self, "budget-edit.txt", "Q4 budget: 125000\n")?;
        run(
            self,
            format!(
                "{db} checkin {} --from {later} --as M.S --unsigned --label \"Late edit, unsigned\"",
                file("budget.txt")
            ),
        )?;
        run(
            self,
            format!(
                "{db} share {} --to M --as M.S --slot {sarah} --output-dir {dir}/outbox",
                file("budget.txt")
            ),
        )?;

        // 2 and 3. Two people edit their own copy, then bring them together.
        for (name, base, alice_text, bob_text, label) in [
            (
                "forecast.txt",
                "north 10\nsouth 20\neast 30\n",
                "north 10\nsouth 20\neast 35\n",
                "north 12\nsouth 20\neast 30\n",
                "Merged forecast",
            ),
            (
                "memo.txt",
                "Owner: TBD\nBudget: 100\n",
                "Owner: TBD\nBudget: 110\n",
                "Owner: TBD\nBudget: 90\n",
                "Merged memo",
            ),
        ] {
            let source = edit(self, name, base)?;
            run(
                self,
                format!("{db} track {source} --scope M.S --as M.S --slot {sarah}"),
            )?;
            let original = file(name);
            let copy = format!("{dir}/{name}.bob.kqtf");
            let bytes = self.vm().read(Path::new(&original))?;
            self.write_file(Path::new(&copy), &bytes)?;
            let a = edit(self, &format!("{name}.alice"), alice_text)?;
            let b = edit(self, &format!("{name}.bob"), bob_text)?;
            run(
                self,
                format!("{db} checkin {original} --from {a} --as M.S.1 --unsigned"),
            )?;
            run(
                self,
                format!("{db} checkin {copy} --from {b} --as M.S.2 --unsigned"),
            )?;
            run(
                self,
                format!("{db} import {original} --from {copy} --as M.S"),
            )?;
            run(
                self,
                format!("{db} merge {original} --as M.S --label \"{label}\""),
            )?;
        }

        for name in ["budget.txt", "forecast.txt", "memo.txt"] {
            self.register_tracked(Path::new(&file(name)));
        }
        self.sync_history();
        Ok(count.get())
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
        trace.extend(self.settle_mail_and_answers());
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
            // Answers sealed to this person's slot can be opened now.
            trace.extend(self.settle_mail_and_answers());
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
        let mut lines = vec![
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
        // The slot's owner keeps their own defaults and binding pointing at
        // the drive it now sits on.
        if let Some(owner) = self.user_by_label(label) {
            let store = owner.store();
            lines.push(format!(
                "keyquorum --db {store} use --device {} --slot {label}",
                to.display()
            ));
            lines.push(format!(
                "keyquorum --db {store} device bind {} --slot {label}",
                to.display()
            ));
        }
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
    /// The shares this person can present for a file's key tree: one slot
    /// flag per leaf whose drive is inserted (`--slot` for `access quorum`,
    /// `--unlock-slot` for `send --quorum-file`) and, when the policy asks
    /// for a parent's approval, the `--approve` pairs. Also returns the
    /// leaves presented.
    fn unlock_flags(&self, key_id: i64, slot_flag: &str) -> Result<(String, Vec<String>)> {
        let mut flags = String::new();
        let mut presented = Vec::new();
        for leaf in &self.leaves(key_id)? {
            if let Some(drive) = self.drive_holding(leaf).filter(|drive| drive.connected) {
                flags.push_str(&format!(" {slot_flag} {}={leaf}", drive.mount.display()));
                presented.push(leaf.clone());
            }
        }
        if device::custody_policy(self.org(), key_id)?.unlock_approval == UnlockApproval::Parent {
            for leaf in &presented {
                let Some(parent) = parent_node_label(leaf) else {
                    continue;
                };
                if let Some(drive) = self.drive_holding(parent).filter(|drive| drive.connected) {
                    flags.push_str(&format!(
                        " --approve {leaf}={}>{parent}",
                        drive.mount.display()
                    ));
                }
            }
        }
        Ok((flags, presented))
    }

    fn unlock_line(
        &self,
        file_id: i64,
        key_id: i64,
        output: Option<&Path>,
    ) -> Result<(String, Vec<String>)> {
        let mut line =
            format!("keyquorum --db {ORG_DB} access quorum --state 1 --id {file_id} --verbose");
        let (flags, presented) = self.unlock_flags(key_id, "--slot")?;
        line.push_str(&flags);
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

    // ----- password-locked files -------------------------------------------

    /// Lock a note as a password-protected file in the active user's own
    /// store (`access password --state 0`), using the password (and,
    /// optionally, PIN) the person typed rather than a seeded demo value.
    /// The plaintext is written to a temporary path only long enough for
    /// the command to read it, then removed either way.
    pub fn lock_password_file(
        &mut self,
        name: &str,
        contents: &str,
        password: &str,
        pin: Option<&str>,
    ) -> Result<Outcome> {
        if password.is_empty() {
            return Ok(Outcome::done(false, "A lock password is required", vec![]));
        }
        let (owner, store) = (self.actor().label.clone(), self.actor().store());
        let home = self.actor().home();
        let source = home.join(format!(".tmp-lock-{name}"));
        let encrypted = home.join("locked").join(format!("{name}.kqenc"));
        self.write_file(&source, contents.as_bytes())?;
        let mut line = format!(
            "keyquorum --db {store} access password --state 0 --source {} --encrypted-path {}",
            quote(&source.display().to_string()),
            quote(&encrypted.display().to_string())
        );
        let mut secrets = vec![password.to_string()];
        if let Some(pin_value) = pin {
            line.push_str(" --pin");
            secrets.push(pin_value.to_string());
        }
        self.vm_mut().stage_secrets(secrets);
        let run = self.run(&line);
        self.vm_mut().clear_pending_secrets();
        let _ = self.remove_file(&source);
        let mut trace = transcript(&run, true);
        let title = format!("Lock {name} with a password");
        if !run.ok {
            let message = format!("{title}: {}", run.error().unwrap_or("failed"));
            self.log("password-lock", "denied", &title, trace.clone(), Some(line));
            return Ok(Outcome::done(false, message, trace));
        }
        let id: i64 = run
            .stdout_text()
            .lines()
            .find_map(|line| line.strip_prefix("Locked file "))
            .and_then(|rest| rest.trim().parse().ok())
            .ok_or(Error::NodeNotFound)?;
        let created_at: String = self.vm().relay_conn().query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:00', 'now')",
            [],
            |row| row.get(0),
        )?;
        self.password_files.push(PasswordFile {
            id,
            name: name.to_string(),
            owner: owner.clone(),
            created_at,
            expires_at: None,
            pin: pin.is_some(),
        });
        trace.push(TraceStep::pass(format!(
            "Locked as password-protected file {id} in {owner}'s store"
        )));
        let message = format!("{name} is now password-protected");
        self.log(
            "password-lock",
            "granted",
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(true, message, trace))
    }

    /// Looks up a password-locked file by its owner's label *and* row id,
    /// never by id alone: each lab user has their own SQLite store, so two
    /// users can each have a row 1, and an id-only lookup would resolve to
    /// whichever entry was tracked first — silently treating a later
    /// user's own file as someone else's.
    fn password_file_index(&self, owner: &str, id: i64) -> Option<usize> {
        self.password_files
            .iter()
            .position(|file| file.owner == owner && file.id == id)
    }

    /// Denial message for a password-locked file id the active user does
    /// not own: names the real owner and name when some user's row happens
    /// to share that id, otherwise reports the id as unknown.
    fn password_file_denial(&self, id: i64) -> String {
        match self.password_files.iter().find(|file| file.id == id) {
            Some(file) => format!(
                "{name} is protected in {owner}'s own store, not yours",
                name = file.name,
                owner = file.owner
            ),
            None => format!("No password-locked file {id}"),
        }
    }

    /// Open a password-locked file with the password (and PIN, when it was
    /// set with one) the person typed. Only the owner's own store has the
    /// row, so this only ever runs against that store.
    pub fn unlock_password_file(
        &mut self,
        id: i64,
        password: &str,
        pin: Option<&str>,
    ) -> Result<Outcome> {
        let owner_label = self.actor().label.clone();
        let Some(index) = self.password_file_index(&owner_label, id) else {
            return Ok(Outcome::done(false, self.password_file_denial(id), vec![]));
        };
        let (name, wants_pin) = {
            let file = &self.password_files[index];
            (file.name.clone(), file.pin)
        };
        let store = self.actor().store();
        let line = format!("keyquorum --db {store} access password --state 1 --id {id}");
        let mut secrets = Vec::new();
        if wants_pin {
            secrets.push(pin.unwrap_or_default().to_string());
        }
        secrets.push(password.to_string());
        self.vm_mut().stage_secrets(secrets);
        let run = self.run(&line);
        self.vm_mut().clear_pending_secrets();
        let trace = transcript(&run, false);
        let opened = if run.ok {
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
            format!("Access denied: {name}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            "password-access",
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

    fn password_file_views(&self) -> Vec<PasswordFileView> {
        self.password_files
            .iter()
            .map(|file| PasswordFileView {
                id: file.id,
                name: file.name.clone(),
                owner: file.owner.clone(),
                created_at: file.created_at.clone(),
                expires_at: file.expires_at.clone(),
                pin_protected: file.pin,
            })
            .collect()
    }

    // ----- export ------------------------------------------------------------

    /// Export a password-locked file as a portable `KQXB` bundle sealed to
    /// another lab user's public encryption key (`keyquorum export file`).
    /// Only the owning store holds the file's row, so this only ever reads
    /// from the active user's own store, same as `unlock_password_file`.
    /// Opening a bundle back up (`import`) has no implementation yet — see
    /// `export.rs` — so this only ever produces the sealed bytes; nothing
    /// in the lab can decrypt them.
    pub fn export_file(
        &mut self,
        id: i64,
        recipient_label: &str,
        password: &str,
    ) -> Result<Outcome> {
        if password.is_empty() {
            return Ok(Outcome::done(
                false,
                "The file's own lock password is required",
                vec![],
            ));
        }
        let owner = self.actor().label.clone();
        let Some(index) = self.password_file_index(&owner, id) else {
            return Ok(Outcome::done(false, self.password_file_denial(id), vec![]));
        };
        let name = self.password_files[index].name.clone();
        let Some(recipient) = self.user_by_label(recipient_label) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user labeled {recipient_label}"),
                vec![],
            ));
        };
        let recipient_name = recipient.name.clone();
        let key_file = Path::new(SRV)
            .join("keys")
            .join(format!("{recipient_label}.pub"));
        let store = self.actor().store();
        let bundle_id = self.next_export_id;
        let output = self
            .actor()
            .home()
            .join("exports")
            .join(format!("{bundle_id}-{name}.kqxb"));
        let line = format!(
            "keyquorum --db {store} export file {id} --recipient-key-file {} --output {}",
            quote(&key_file.display().to_string()),
            quote(&output.display().to_string())
        );
        self.vm_mut().stage_secret(password.to_string());
        let run = self.run(&line);
        self.vm_mut().clear_pending_secrets();
        let mut trace = transcript(&run, true);
        let title = format!("Export {name} for {recipient_name}");
        if !run.ok {
            let message = format!("{title}: {}", run.error().unwrap_or("failed"));
            self.log("export", "denied", &title, trace.clone(), Some(line));
            return Ok(Outcome::done(false, message, trace));
        }
        let size = self
            .vm()
            .read(&output)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let created_at: String = self.vm().relay_conn().query_row(
            "SELECT strftime('%Y-%m-%d %H:%M:00', 'now')",
            [],
            |row| row.get(0),
        )?;
        self.exports.push(ExportedBundle {
            id: bundle_id,
            file_name: name.clone(),
            owner,
            recipient: recipient_label.to_string(),
            path: output.clone(),
            size,
            created_at,
        });
        self.next_export_id += 1;
        trace.push(TraceStep::pass(format!(
            "Sealed bundle written to {}",
            output.display()
        )));
        let message = format!(
            "Exported {name} for {recipient_name}; only their private key could open it, which this build has no import step for yet"
        );
        self.log("export", "granted", &title, trace.clone(), Some(line));
        Ok(Outcome::done(true, message, trace))
    }

    fn export_index(&self, id: i64) -> Option<usize> {
        self.exports.iter().position(|bundle| bundle.id == id)
    }

    /// Show a bundle's sealed bytes as hex — the closest thing to "opening"
    /// it, since the crate has no import/unseal path yet. Only the
    /// exporter, whose own home directory holds the bundle, can view it.
    pub fn view_export(&mut self, id: i64) -> Result<Outcome> {
        let Some(index) = self.export_index(id) else {
            return Ok(Outcome::done(
                false,
                format!("No exported bundle {id}"),
                vec![],
            ));
        };
        let (owner, name, path) = {
            let bundle = &self.exports[index];
            (
                bundle.owner.clone(),
                bundle.file_name.clone(),
                bundle.path.clone(),
            )
        };
        if owner != self.actor().label {
            return Ok(Outcome::done(
                false,
                format!("That bundle is in {owner}'s own home directory, not yours"),
                vec![],
            ));
        }
        let bytes = self.vm().read(&path)?;
        let text = hex::encode(&bytes);
        let message = format!("Sealed bundle for {name} ({} bytes)", bytes.len());
        let trace = vec![TraceStep::info(format!(
            "{} bytes, sealed under a KQXB envelope at {}; no import step exists yet to unseal it",
            bytes.len(),
            path.display()
        ))];
        self.log("export-view", "info", &message, trace.clone(), None);
        Ok(Outcome {
            ok: true,
            message,
            trace,
            opened: Some(OpenedFile {
                name: format!("{name}.kqxb"),
                text,
            }),
        })
    }

    fn export_views(&self) -> Vec<ExportedBundleView> {
        self.exports
            .iter()
            .map(|bundle| ExportedBundleView {
                id: bundle.id,
                file_name: bundle.file_name.clone(),
                owner: bundle.owner.clone(),
                recipient: bundle.recipient.clone(),
                recipient_name: self
                    .user_by_label(&bundle.recipient)
                    .map(|user| user.name.clone())
                    .unwrap_or_default(),
                size: bundle.size,
                created_at: bundle.created_at.clone(),
            })
            .collect()
    }

    // ----- share links ---------------------------------------------------

    fn file_share_index(&self, id: i64) -> Option<usize> {
        self.file_shares.iter().position(|share| share.id == id)
    }

    /// Create a time-limited, revocable share link for one of the active
    /// user's own password-locked files (`keyquorum share create-file`).
    /// The bearer token is returned once, as the opened text, matching a
    /// real deployment: nothing durable keeps the raw token, only its
    /// hash, so redemption always needs someone to actually have been
    /// given it.
    pub fn create_file_share(
        &mut self,
        file_id: i64,
        ttl_seconds: i64,
        pin: Option<&str>,
    ) -> Result<Outcome> {
        let owner = self.actor().label.clone();
        let Some(index) = self.password_file_index(&owner, file_id) else {
            return Ok(Outcome::done(
                false,
                self.password_file_denial(file_id),
                vec![],
            ));
        };
        let name = self.password_files[index].name.clone();
        let store = self.actor().store();
        let mut line = format!(
            "keyquorum --db {store} share create-file {file_id} --ttl-seconds {ttl_seconds}"
        );
        if let Some(pin_value) = pin {
            line.push_str(" --pin");
            self.vm_mut().stage_secret(pin_value.to_string());
        }
        let run = self.run(&line);
        self.vm_mut().clear_pending_secrets();
        let mut trace = transcript(&run, true);
        let title = format!("Create a share link for {name}");
        if !run.ok {
            let message = format!("{title}: {}", run.error().unwrap_or("failed"));
            self.log("share-create", "denied", &title, trace.clone(), Some(line));
            return Ok(Outcome::done(false, message, trace));
        }
        let stdout = run.stdout_text();
        let share_id: i64 = stdout
            .lines()
            .find_map(|line| line.strip_prefix("Share id:"))
            .and_then(|rest| rest.trim().parse().ok())
            .ok_or(Error::NodeNotFound)?;
        let token = stdout
            .lines()
            .find_map(|line| line.strip_prefix("Token:"))
            .map(|rest| rest.trim().to_string())
            .ok_or(Error::NodeNotFound)?;
        let expires_at = stdout
            .lines()
            .find_map(|line| line.strip_prefix("Expires at:"))
            .map(|rest| rest.trim().to_string())
            .ok_or(Error::NodeNotFound)?;
        self.file_shares.push(FileShare {
            id: share_id,
            file_name: name.clone(),
            owner: owner.clone(),
            pin_protected: pin.is_some(),
            expires_at: expires_at.clone(),
            revoked: false,
        });
        trace.push(TraceStep::pass(format!(
            "Share {share_id} expires at {expires_at}"
        )));
        let message = format!(
            "Share link created for {name}; copy the token now, it will not be shown again"
        );
        self.log("share-create", "granted", &title, trace.clone(), Some(line));
        Ok(Outcome {
            ok: true,
            message,
            trace,
            opened: Some(OpenedFile {
                name: format!("Share link for {name}"),
                text: format!(
                    "Token: {token}\nExpires at (UTC): {expires_at}\nShare id: {share_id}"
                ),
            }),
        })
    }

    /// Redeem a file share's bearer token (`keyquorum share redeem-file`),
    /// consuming one of its uses. The token, not who is asking, is what
    /// authorizes this — any lab user, including one signed in as someone
    /// else, can redeem it once they have been given the token, exactly
    /// like a real share link. This only grants the share's own use
    /// accounting; the file itself is still password-protected and needs
    /// its own lock password to open.
    pub fn redeem_file_share(
        &mut self,
        share_id: i64,
        token: &str,
        pin: Option<&str>,
    ) -> Result<Outcome> {
        if token.is_empty() {
            return Ok(Outcome::done(false, "A share token is required", vec![]));
        }
        let Some(index) = self.file_share_index(share_id) else {
            return Ok(Outcome::done(false, format!("No share {share_id}"), vec![]));
        };
        let (owner, name, revoked) = {
            let share = &self.file_shares[index];
            (share.owner.clone(), share.file_name.clone(), share.revoked)
        };
        if revoked {
            return Ok(Outcome::done(
                false,
                format!("Share {share_id} for {name} was revoked"),
                vec![],
            ));
        }
        let Some(owner_user) = self.user_by_label(&owner) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user labeled {owner}"),
                vec![],
            ));
        };
        let store = owner_user.store();
        let line = format!("keyquorum --db {store} share redeem-file");
        let mut secrets = vec![token.to_string()];
        if let Some(pin_value) = pin {
            secrets.push(pin_value.to_string());
        }
        self.vm_mut().stage_secrets(secrets);
        let run = self.run(&line);
        self.vm_mut().clear_pending_secrets();
        let trace = transcript(&run, true);
        let title = format!("Redeem the share link for {name}");
        let message = if run.ok {
            format!("Redeemed access to {name} (owned by {owner}); its own lock password still opens it")
        } else {
            format!("{title}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            "share-redeem",
            if run.ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    /// Revoke a share link the active user created (`keyquorum share
    /// revoke-file`); its remaining uses can never be redeemed again.
    pub fn revoke_file_share(&mut self, share_id: i64) -> Result<Outcome> {
        let Some(index) = self.file_share_index(share_id) else {
            return Ok(Outcome::done(false, format!("No share {share_id}"), vec![]));
        };
        let (owner, name) = {
            let share = &self.file_shares[index];
            (share.owner.clone(), share.file_name.clone())
        };
        if owner != self.actor().label {
            return Ok(Outcome::done(
                false,
                format!("Share {share_id} belongs to {owner}, not you"),
                vec![],
            ));
        }
        let store = self.actor().store();
        let line = format!("keyquorum --db {store} share revoke-file {share_id}");
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let title = format!("Revoke the share link for {name}");
        let message = if run.ok {
            self.file_shares[index].revoked = true;
            format!("Revoked the share link for {name}")
        } else {
            format!("{title}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            "share-revoke",
            if run.ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    fn file_share_views(&self) -> Vec<FileShareView> {
        self.file_shares
            .iter()
            .map(|share| FileShareView {
                id: share.id,
                file_name: share.file_name.clone(),
                owner: share.owner.clone(),
                pin_protected: share.pin_protected,
                expires_at: share.expires_at.clone(),
                revoked: share.revoked,
            })
            .collect()
    }

    // ----- sign / verify -----------------------------------------------------

    /// A bridge member's own tree label (`M.S`, `M.A`) maps to their
    /// personal bridge signing identity (`seed::BRIDGE_SIGNERS`).
    fn bridge_signer_label(&self, tree_label: &str) -> Option<&'static str> {
        seed::BRIDGE_SIGNERS
            .iter()
            .find(|(node, _)| *node == tree_label)
            .map(|(_, signer)| *signer)
    }

    fn signature_index(&self, id: i64) -> Option<usize> {
        self.signatures.iter().position(|entry| entry.id == id)
    }

    /// Sign a public or received file's plaintext with the active user's
    /// personal bridge signing key (`keyquorum sign`). Sarah and David
    /// are both members of the org's one private sign bridge, but only
    /// Sarah (the bridge's `--self` at seed time) has a sealed copy of
    /// its shared secret in this shared org store; David's attempt fails
    /// with the CLI's own `SealedKeyNotHeld` error, same as it would on a
    /// second person's real, separate store that never imported the
    /// package addressed to them. Quorum-locked files are not offered
    /// here: they would first need decrypting to a temporary plaintext
    /// the same way `send` does, which this build keeps out of scope.
    pub fn sign_file(&mut self, file_key: &str) -> Result<Outcome> {
        let actor_label = self.actor().label.clone();
        let Some(signer_label) = self.bridge_signer_label(&actor_label) else {
            return Ok(Outcome::done(
                false,
                format!(
                    "{actor_label} holds no personal signing key for the cross-department bridge"
                ),
                vec![],
            ));
        };
        let Some(slot) = self.own_slot_arg() else {
            return Ok(Outcome::done(
                false,
                "You have no slot on any drive",
                vec![],
            ));
        };
        let (source, name, source_key) = if let Some(path) = self.received_path(file_key) {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let key = format!("received/{name}");
            (path, name, key)
        } else {
            let Some(index) = self.file_index(file_key) else {
                return Ok(Outcome::done(
                    false,
                    format!("No file named {file_key}"),
                    vec![],
                ));
            };
            match &self.files[index].kind {
                FileKind::Public { path } => (
                    path.clone(),
                    self.files[index].name.clone(),
                    self.files[index].id.clone(),
                ),
                FileKind::Quorum { .. } => {
                    return Ok(Outcome::done(
                        false,
                        "Only public or received files can be signed here",
                        vec![],
                    ));
                }
            }
        };
        let signature_out = self
            .actor()
            .home()
            .join("signatures")
            .join(format!("{name}.sig"));
        let key_file = self
            .actor()
            .home()
            .join("keys")
            .join(format!("{signer_label}.key"));
        let bridge_uid = self.bridge_uid.clone();
        let line = format!(
            "keyquorum --db {ORG_DB} sign --bridge-uid {bridge_uid} --node {signer_label} \
             --signing-key-file {} --slot {slot} --message-file {} --signature-out {}",
            quote(&key_file.display().to_string()),
            quote(&source.display().to_string()),
            quote(&signature_out.display().to_string()),
        );
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let title = format!("Sign {name}");
        if !run.ok {
            let message = format!("{title}: {}", run.error().unwrap_or("failed"));
            self.log("sign", "denied", &title, trace.clone(), Some(line));
            return Ok(Outcome::done(false, message, trace));
        }
        let size = self
            .vm()
            .read(&signature_out)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let id = self.next_signature_id;
        self.signatures.push(SignedFile {
            id,
            source_key,
            file_name: name.clone(),
            signer: actor_label,
            bridge_uid: bridge_uid.clone(),
            path: signature_out,
            size,
        });
        self.next_signature_id += 1;
        let message = format!("Signed {name} as {signer_label} on bridge {bridge_uid}");
        self.log("sign", "granted", &title, trace.clone(), Some(line));
        Ok(Outcome::done(true, message, trace))
    }

    /// Verify a signature against its bridge's roster (`keyquorum
    /// verify --bridge-uid`), re-reading the same plaintext it was signed
    /// over. Either bridge member can verify the other's signature.
    pub fn verify_signature(&mut self, signature_id: i64) -> Result<Outcome> {
        let Some(index) = self.signature_index(signature_id) else {
            return Ok(Outcome::done(
                false,
                format!("No signature {signature_id}"),
                vec![],
            ));
        };
        let (source_key, bridge_uid, sig_path, file_name, signer) = {
            let entry = &self.signatures[index];
            (
                entry.source_key.clone(),
                entry.bridge_uid.clone(),
                entry.path.clone(),
                entry.file_name.clone(),
                entry.signer.clone(),
            )
        };
        let actor_label = self.actor().label.clone();
        let Some(verifier_label) = self.bridge_signer_label(&actor_label) else {
            return Ok(Outcome::done(
                false,
                format!(
                    "{actor_label} is not a member of the private bridge that made this signature"
                ),
                vec![],
            ));
        };
        let source = if let Some(path) = self.received_path(&source_key) {
            path
        } else if let Some(file_index) = self.file_index(&source_key) {
            match &self.files[file_index].kind {
                FileKind::Public { path } => path.clone(),
                FileKind::Quorum { .. } => {
                    return Ok(Outcome::done(
                        false,
                        "The original file this signature covers is no longer plaintext",
                        vec![],
                    ));
                }
            }
        } else {
            return Ok(Outcome::done(
                false,
                "The original file this signature covers no longer exists",
                vec![],
            ));
        };
        let line = format!(
            "keyquorum --db {ORG_DB} verify --bridge-uid {bridge_uid} --as-node {verifier_label} \
             --message-file {} --signature-file {}",
            quote(&source.display().to_string()),
            quote(&sig_path.display().to_string()),
        );
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let title = format!("Verify {file_name}'s signature");
        let message = if run.ok {
            format!(
                "Signature by {} over {file_name} is valid",
                self.describe_label(&signer)
            )
        } else {
            format!("{title}: {}", run.error().unwrap_or("invalid"))
        };
        self.log(
            "verify",
            if run.ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    fn signature_views(&self) -> Vec<SignatureView> {
        self.signatures
            .iter()
            .map(|entry| SignatureView {
                id: entry.id,
                file_name: entry.file_name.clone(),
                signer: entry.signer.clone(),
                signer_name: self.describe_label(&entry.signer),
                bridge_uid: entry.bridge_uid.clone(),
                size: entry.size,
            })
            .collect()
    }

    // ----- device slots and the relay ---------------------------------------

    /// Provision a new slot on an inserted drive with `keyquorum-device
    /// provision`, using the passphrase the person chose instead of the
    /// seeded demo passphrase. This is the lab's "create a new key" action:
    /// it mints a fresh encryption/signing keypair pair sealed under that
    /// passphrase, but does not register or bind it into the org tree —
    /// that stays a deliberate follow-up step (`keyquorum register` /
    /// `device bind`), same as on a real machine.
    pub fn provision_slot(
        &mut self,
        drive_id: &str,
        label: &str,
        passphrase: &str,
    ) -> Result<Outcome> {
        if passphrase.is_empty() {
            return Ok(Outcome::done(false, "A passphrase is required", vec![]));
        }
        let Some(drive) = self.vm().bay.get(drive_id) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {drive_id}"),
                vec![],
            ));
        };
        if !drive.connected {
            return Ok(Outcome::done(
                false,
                format!("{} is not inserted", drive.name),
                vec![],
            ));
        }
        let (mount, drive_name) = (drive.mount.clone(), drive.name.clone());
        let line = format!(
            "keyquorum-device provision {} --label {label}",
            mount.display()
        );
        self.vm_mut()
            .stage_secrets([passphrase.to_string(), passphrase.to_string()]);
        let run = self.run(&line);
        self.vm_mut().clear_pending_secrets();
        let trace = transcript(&run, true);
        let title = format!("Provision slot {label} on {drive_name}");
        let message = if run.ok {
            format!("Provisioned {label} on {drive_name}")
        } else {
            format!("{title}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            "provision",
            if run.ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    /// Register a provisioned-but-unregistered slot's keys and insert it
    /// as a new leaf under an existing org-tree node: `keyquorum device
    /// register` for both key types, `device bind`, then `keyquorum add`.
    /// `add` reshares the parent from its existing children's shares at
    /// their configured threshold — a real consequence of growing a live
    /// tree, not something this glosses over. Every currently inserted,
    /// active sibling under `parent_label` is offered as recovery
    /// material; the command itself decides whether that meets the
    /// parent's threshold.
    pub fn register_leaf(
        &mut self,
        drive_id: &str,
        slot_label: &str,
        parent_label: &str,
    ) -> Result<Outcome> {
        self.register_leaf_with(drive_id, slot_label, parent_label, None)
    }

    /// Provision a slot and register it as a leaf in one action: the same
    /// `keyquorum-device provision` then the register, bind and `add` steps
    /// of [`LabState::register_leaf`], with the passphrase just typed.
    pub fn create_and_register_leaf(
        &mut self,
        drive_id: &str,
        slot_label: &str,
        parent_label: &str,
        passphrase: &str,
    ) -> Result<Outcome> {
        let provisioned = self.provision_slot(drive_id, slot_label, passphrase)?;
        if !provisioned.ok {
            return Ok(provisioned);
        }
        let mut registered =
            self.register_leaf_with(drive_id, slot_label, parent_label, Some(passphrase))?;
        let mut trace = provisioned.trace;
        trace.append(&mut registered.trace);
        registered.trace = trace;
        Ok(registered)
    }

    fn register_leaf_with(
        &mut self,
        drive_id: &str,
        slot_label: &str,
        parent_label: &str,
        passphrase: Option<&str>,
    ) -> Result<Outcome> {
        if slot_label.trim().is_empty() {
            return Ok(Outcome::done(false, "A leaf label is required", vec![]));
        }
        let Some(drive) = self.vm().bay.get(drive_id) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {drive_id}"),
                vec![],
            ));
        };
        if !drive.connected {
            return Ok(Outcome::done(
                false,
                format!("{} is not inserted", drive.name),
                vec![],
            ));
        }
        if !drive.slots().iter().any(|slot| slot == slot_label) {
            return Ok(Outcome::done(
                false,
                format!("{} has no provisioned slot named {slot_label}", drive.name),
                vec![],
            ));
        }
        let (mount, drive_name) = (drive.mount.clone(), drive.name.clone());

        let key_id = self.org_key_id;
        let tree = KeyQuorumTree::load(self.org(), key_id)?;
        let Some(parent) = tree.nodes.iter().find(|node| node.id == parent_label) else {
            return Ok(Outcome::done(
                false,
                format!("No node {parent_label} in the org tree"),
                vec![],
            ));
        };
        if tree.nodes.iter().any(|node| node.id == slot_label) {
            return Ok(Outcome::done(
                false,
                format!("{slot_label} is already a node in the org tree"),
                vec![],
            ));
        }
        let siblings: Vec<String> = parent
            .children_indices
            .iter()
            .map(|&index| &tree.nodes[index])
            .filter(|node| node.is_active && node.hardware_key_id.is_some())
            .map(|node| node.id.clone())
            .collect();

        let title = format!("Register {slot_label} under {parent_label}");
        let public = self.run(&format!(
            "keyquorum-device public {} --label {slot_label}",
            mount.display()
        ));
        let mut trace = transcript(&public, true);
        if !public.ok {
            let message = format!("{title}: {}", public.error().unwrap_or("failed"));
            self.log(
                "register-leaf",
                "denied",
                &title,
                trace.clone(),
                Some(public.line.clone()),
            );
            return Ok(Outcome::done(false, message, trace));
        }
        let public_line = public.line.clone();
        self.save_public_key(slot_label, &public)?;

        let mut add_line = format!(
            "keyquorum --db {ORG_DB} add {key_id} --parent {parent_label} --node {slot_label} \
             --public-key-file {SRV}/keys/{slot_label}.pub"
        );
        for sibling in &siblings {
            if let Some(sib_drive) = self.drive_holding(sibling).filter(|drive| drive.connected) {
                add_line.push_str(&format!(" --slot {}={sibling}", sib_drive.mount.display()));
            }
        }
        let lines = [
            format!(
                "keyquorum --db {ORG_DB} device register {} --slot {slot_label} --type encryption",
                mount.display()
            ),
            format!(
                "keyquorum --db {ORG_DB} device register {} --slot {slot_label} --type signing",
                mount.display()
            ),
            format!(
                "keyquorum --db {ORG_DB} device bind {} --slot {slot_label}",
                mount.display()
            ),
            add_line,
        ];
        // `device bind` asks for the slot's passphrase (twice); a slot just
        // created with a typed passphrase answers with that one.
        if let Some(passphrase) = passphrase {
            self.vm_mut()
                .stage_secrets([passphrase.to_string(), passphrase.to_string()]);
        }
        let (runs, ok) = self.run_all(&lines);
        self.vm_mut().clear_pending_secrets();
        trace.extend(transcripts(&runs, true));
        let message = if ok {
            format!("Registered {slot_label} on {drive_name} as a new leaf under {parent_label}")
        } else {
            format!("{title}: {}", last_error(&runs))
        };
        self.log(
            "register-leaf",
            if ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(format!("{public_line}\n{}", lines_run(&runs))),
        );
        Ok(Outcome::done(ok, message, trace))
    }

    /// `keyquorum doctor`: what is missing for the active person, and the
    /// command that fixes each thing. Reads only.
    pub fn doctor(&mut self) -> Result<Outcome> {
        let line = format!("keyquorum --db {} doctor", self.actor().store());
        let run = self.run(&line);
        // Doctor prints one verdict per line (`ok`, `FIX`, a `->` hint, `info`);
        // show each as what it says rather than as a passed step.
        let mut trace = vec![TraceStep::info(format!("$ {line}"))];
        for text in run.stdout_text().lines() {
            let trimmed = text.trim_start();
            trace.push(if trimmed.starts_with("ok ") {
                TraceStep::pass(text.to_string())
            } else if trimmed.starts_with("FIX ") {
                TraceStep::fail(text.to_string())
            } else {
                TraceStep::info(text.to_string())
            });
        }
        let message = if run.ok {
            "Everything checks out".to_string()
        } else {
            run.error().unwrap_or("Problems found").to_string()
        };
        self.log(
            "doctor",
            "info",
            "Check my setup",
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(true, message, trace))
    }

    /// `keyquorum use`: make the drive the active person's slot sits on
    /// their default.
    pub fn use_current_drive(&mut self) -> Result<Outcome> {
        let Some(slot) = self.own_slot_arg() else {
            return Ok(Outcome::done(
                false,
                "You have no slot on any drive",
                vec![],
            ));
        };
        let (mount, label) = slot.rsplit_once('=').unwrap_or((&slot, ""));
        let line = format!(
            "keyquorum --db {} use --device {mount} --slot {label}",
            self.actor().store()
        );
        self.setup_command("use", "Use my current drive as my default", line)
    }

    /// `keyquorum device bind`: tie the active person's slot to the device it
    /// sits on, in their own store.
    pub fn bind_slot(&mut self) -> Result<Outcome> {
        let Some(slot) = self.own_slot_arg() else {
            return Ok(Outcome::done(
                false,
                "You have no slot on any drive",
                vec![],
            ));
        };
        let (mount, label) = slot.rsplit_once('=').unwrap_or((&slot, ""));
        let line = format!(
            "keyquorum --db {} device bind {mount} --slot {label}",
            self.actor().store()
        );
        self.setup_command("bind", "Bind my slot to its device", line)
    }

    fn setup_command(&mut self, kind: &str, title: &str, line: String) -> Result<Outcome> {
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let message = if run.ok {
            title.to_string()
        } else {
            format!("{title}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            kind,
            if run.ok { "granted" } else { "denied" },
            title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    /// Read-only: `keyquorum-device list` for an inserted drive's
    /// container, shown as an opened "file" so the existing viewer can
    /// display it. Nothing is decided here; this is what a real desktop's
    /// device manager would show.
    pub fn device_log(&mut self, drive_id: &str) -> Result<Outcome> {
        let Some(drive) = self.vm().bay.get(drive_id) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {drive_id}"),
                vec![],
            ));
        };
        if !drive.connected {
            return Ok(Outcome::done(
                false,
                format!("{} is not inserted", drive.name),
                vec![],
            ));
        }
        let (mount, drive_name) = (drive.mount.clone(), drive.name.clone());
        let line = format!("keyquorum-device list {}", mount.display());
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let message = format!("Device log for {drive_name}");
        self.log("device-log", "info", &message, trace.clone(), Some(line));
        Ok(Outcome {
            ok: run.ok,
            message,
            trace,
            opened: run.ok.then(|| OpenedFile {
                name: format!("{drive_name} device log"),
                text: run.stdout_text(),
            }),
        })
    }

    /// Read-only counts of what this session's in-process relay holds,
    /// queried directly from its store rather than shelling a command,
    /// since the CLI has no "relay status" subcommand.
    fn relay_status(&self) -> Result<RelayStatusView> {
        let conn = self.vm().relay_conn();
        let count = |sql: &str| -> Result<i64> { Ok(conn.query_row(sql, [], |row| row.get(0))?) };
        Ok(RelayStatusView {
            url: super::vm::RELAY_URL.to_string(),
            package_letters: count("SELECT COUNT(*) FROM mailbox")?,
            device_letters: count("SELECT COUNT(*) FROM device_mailbox")?,
            published_trees: count("SELECT COUNT(*) FROM org_tree_docs")?,
            registered_devices: count("SELECT COUNT(*) FROM device_directory")?,
            api_keys: count("SELECT COUNT(*) FROM api_keys")?,
        })
    }

    // ----- revocation -------------------------------------------------------

    /// Ban a node's hardware key from any future tree and drop its existing
    /// bindings and bridge pairings (`keyquorum revoke`). `revoke` is not
    /// itself access-controlled in the CLI — it does not check who is
    /// asking, only that the key and, when given, the leaf it backs, exist
    /// — so this lets any lab visitor revoke any node's key, same as the
    /// bridge allow/add/deny/remove buttons already do against the shared
    /// org tree. This does not pass `--evict`: refreshing survivor shares
    /// needs their key files or slots collected up front, which the GUI
    /// does not do; a maintainer can still run that from the Terminal tab.
    pub fn revoke_key(&mut self, node_label: &str) -> Result<Outcome> {
        let tree = KeyQuorumTree::load(self.org(), self.org_key_id)?;
        let Some(node) = tree.nodes.iter().find(|node| node.id == node_label) else {
            return Ok(Outcome::done(
                false,
                format!("No node {node_label} in the org tree"),
                vec![],
            ));
        };
        let Some(hardware_id) = node.hardware_key_id else {
            return Ok(Outcome::done(
                false,
                format!("{node_label} is a split node, not a hardware-backed leaf"),
                vec![],
            ));
        };
        let key_id = self.org_key_id;
        let line = format!(
            "keyquorum --db {ORG_DB} revoke {hardware_id} --key-id {key_id} --node {node_label}"
        );
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let title = format!("Revoke {node_label}'s hardware key");
        let message = if run.ok {
            format!("Revoked {node_label}'s hardware key; its bindings and pairings are dropped")
        } else {
            format!("{title}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            "revoke",
            if run.ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    // ----- reissue ------------------------------------------------------------

    /// Reissue a node's hardware key onto an already-provisioned
    /// replacement token (`Self::provision_slot`, the same precondition
    /// `register_leaf` has), authorized "as" `seed::RESTRUCTURE_AUTHORITY`
    /// — the only label in this lab holding a plaintext signing key (see
    /// its own doc comment). `keyquorum reissue` only rewrites the key
    /// registry (and, for the subject's own encryption key, the tree's
    /// `hardware_key_id` via `key_tree::adopt_reissued_hardware_key`); it
    /// never touches a device container itself, so this binds the
    /// replacement slot afterward the same way `register_leaf` binds a
    /// brand-new leaf. The real CLI, not this method, decides whether the
    /// authorizer actually has standing: asking to reissue a node outside
    /// her subtree (anyone but `M.A`, `M.A.1`, `M.A.2`) reaches
    /// `org_update::plan_key_reissue` and comes back `UpdateNotAuthorized`.
    pub fn reissue_key(
        &mut self,
        node_label: &str,
        to_drive_id: &str,
        passphrase: &str,
    ) -> Result<Outcome> {
        if passphrase.is_empty() {
            return Ok(Outcome::done(false, "A passphrase is required", vec![]));
        }
        let key_id = self.org_key_id;
        let tree = KeyQuorumTree::load(self.org(), key_id)?;
        let Some(node) = tree.nodes.iter().find(|node| node.id == node_label) else {
            return Ok(Outcome::done(
                false,
                format!("No node {node_label} in the org tree"),
                vec![],
            ));
        };
        if node.hardware_key_id.is_none() {
            return Ok(Outcome::done(
                false,
                format!("{node_label} is a split node, not a hardware-backed leaf"),
                vec![],
            ));
        }
        let Some(drive) = self.vm().bay.get(to_drive_id) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {to_drive_id}"),
                vec![],
            ));
        };
        if !drive.connected {
            return Ok(Outcome::done(
                false,
                format!("{} is not inserted", drive.name),
                vec![],
            ));
        }
        if !drive.slots().iter().any(|slot| slot == node_label) {
            return Ok(Outcome::done(
                false,
                format!(
                    "{} has no provisioned slot named {node_label}; provision the replacement token first",
                    drive.name
                ),
                vec![],
            ));
        }
        let (mount, drive_name) = (drive.mount.clone(), drive.name.clone());
        let authority_label = seed::RESTRUCTURE_AUTHORITY;
        let Some(authority_owner) = self.user_by_label(authority_label) else {
            return Ok(Outcome::done(
                false,
                format!("No authority signing key registered for {authority_label}"),
                vec![],
            ));
        };
        let authority_key_file = authority_owner
            .home()
            .join("keys")
            .join(format!("{authority_label}-authority.key"));

        let title = format!("Reissue {node_label}'s hardware key");
        let public = self.run(&format!(
            "keyquorum-device public {} --label {node_label}",
            mount.display()
        ));
        let mut trace = transcript(&public, true);
        if !public.ok {
            let message = format!("{title}: {}", public.error().unwrap_or("failed"));
            self.log(
                "reissue",
                "denied",
                &title,
                trace.clone(),
                Some(public.line.clone()),
            );
            return Ok(Outcome::done(false, message, trace));
        }
        let (new_encryption, new_signing) = slot_public_keys(&public)?;
        let enc_path = Path::new(SRV)
            .join("keys")
            .join(format!("{node_label}-reissue-encryption.pub"));
        let sign_path = Path::new(SRV)
            .join("keys")
            .join(format!("{node_label}-reissue-signing.pub"));
        self.write_file(&enc_path, new_encryption.as_bytes())?;
        self.write_file(&sign_path, new_signing.as_bytes())?;

        let output_dir = Path::new(SRV).join("reissue-packages");
        let reissue_line = format!(
            "keyquorum --db {ORG_DB} reissue --node {node_label} --key-id {key_id} \
             --encryption-public-key-file {} --signing-public-key-file {} --as {authority_label} \
             --signing-key-file {} --revoke-previous --output-dir {}",
            enc_path.display(),
            sign_path.display(),
            authority_key_file.display(),
            output_dir.display(),
        );
        let reissue_run = self.run(&reissue_line);
        trace.extend(transcript(&reissue_run, true));
        if !reissue_run.ok {
            let message = format!("{title}: {}", reissue_run.error().unwrap_or("failed"));
            self.log(
                "reissue",
                "denied",
                &title,
                trace.clone(),
                Some(reissue_line),
            );
            return Ok(Outcome::done(false, message, trace));
        }

        self.vm_mut()
            .stage_secrets([passphrase.to_string(), passphrase.to_string()]);
        let bind = self.run(&format!(
            "keyquorum --db {ORG_DB} device bind {} --slot {node_label}",
            mount.display()
        ));
        self.vm_mut().clear_pending_secrets();
        trace.extend(transcript(&bind, true));
        let ok = bind.ok;
        let message = if ok {
            format!(
                "Reissued {node_label}'s hardware key onto {drive_name}, authorized by {authority_label}; the old token is revoked"
            )
        } else {
            format!(
                "Reissue applied, but binding the new device failed: {}",
                bind.error().unwrap_or("failed")
            )
        };
        self.log(
            "reissue",
            if ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(reissue_line),
        );
        Ok(Outcome::done(ok, message, trace))
    }

    // ----- tree restructure -----------------------------------------------

    /// `seed::RESTRUCTURE_AUTHORITY` proposes republishing the org tree at
    /// its next public generation (`keyquorum tree restructure`). She is
    /// not the root, so `org_update::plan_tree_restructure` marks this a
    /// proposal rather than applying it: it lands in `pending_org_actions`
    /// (surfaced to the countersigner as `Snapshot::pending_restructures`)
    /// and only takes effect once her parent, `M`, countersigns it with
    /// [`Self::countersign_restructure`].
    pub fn propose_restructure(&mut self) -> Result<Outcome> {
        let authorizer_label = seed::RESTRUCTURE_AUTHORITY;
        let Some(owner) = self.user_by_label(authorizer_label) else {
            return Ok(Outcome::done(
                false,
                format!("No authority signing key registered for {authorizer_label}"),
                vec![],
            ));
        };
        let authority_key_file = owner
            .home()
            .join("keys")
            .join(format!("{authorizer_label}-authority.key"));
        let key_id = self.org_key_id;
        let output_dir = Path::new(SRV)
            .join("restructure-packages")
            .join("proposals");
        let line = format!(
            "keyquorum --db {ORG_DB} tree restructure {key_id} --as {authorizer_label} \
             --signing-key-file {} --output-dir {}",
            authority_key_file.display(),
            output_dir.display(),
        );
        let run = self.run(&line);
        let trace = transcript(&run, true);
        let title = format!("Propose a tree restructure as {authorizer_label}");
        let message = if run.ok {
            run.stdout_text()
                .lines()
                .find(|line| line.contains("waiting for"))
                .map(str::to_string)
                .unwrap_or_else(|| format!("{authorizer_label} proposed a restructure"))
        } else {
            format!("{title}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            "restructure-propose",
            if run.ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    /// The active user countersigns every pending restructure proposal
    /// addressed to them (`keyquorum tree countersign`), using their own
    /// device slot rather than a plaintext key file — unlike `restructure`
    /// and `reissue`, `tree countersign` accepts `--device`/`--slot`, so
    /// the root never needs a personal signing keypair of her own.
    pub fn countersign_restructure(&mut self, passphrase: &str) -> Result<Outcome> {
        if passphrase.is_empty() {
            return Ok(Outcome::done(false, "A passphrase is required", vec![]));
        }
        let actor_label = self.actor().label.clone();
        let pending = self.pending_restructure_views()?;
        if !pending
            .iter()
            .any(|proposal| proposal.countersigner_label == actor_label)
        {
            return Ok(Outcome::done(
                false,
                format!("{actor_label} has no pending restructure to countersign"),
                vec![],
            ));
        }
        let Some(mount) = self
            .drive_holding(&actor_label)
            .filter(|drive| drive.connected)
            .map(|drive| drive.mount.clone())
        else {
            return Ok(Outcome::done(
                false,
                format!("{actor_label}'s drive is not inserted"),
                vec![],
            ));
        };
        let key_id = self.org_key_id;
        let output_dir = Path::new(SRV)
            .join("restructure-packages")
            .join("countersigned");
        let line = format!(
            "keyquorum --db {ORG_DB} tree countersign {key_id} --as {actor_label} --device {} \
             --slot {actor_label} --output-dir {}",
            mount.display(),
            output_dir.display(),
        );
        self.vm_mut().stage_secret(passphrase.to_string());
        let run = self.run(&line);
        self.vm_mut().clear_pending_secrets();
        let trace = transcript(&run, true);
        let title = format!("Countersign the pending restructure as {actor_label}");
        let message = if run.ok {
            format!("{actor_label} countersigned the restructure; it is now in effect")
        } else {
            format!("{title}: {}", run.error().unwrap_or("failed"))
        };
        self.log(
            "restructure-countersign",
            if run.ok { "granted" } else { "denied" },
            &title,
            trace.clone(),
            Some(line),
        );
        Ok(Outcome::done(run.ok, message, trace))
    }

    /// Read-only: every proposal still waiting on a countersignature, for
    /// `Snapshot::pending_restructures`. Nothing here decides anything —
    /// `tree countersign` is what applies or refuses one.
    fn pending_restructure_views(&self) -> Result<Vec<RestructureProposalView>> {
        let mut stmt = self.org().prepare(
            "SELECT tree_label, authorizer_label, countersigner_label, generation
             FROM pending_org_actions WHERE key_id = ?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![self.org_key_id], |row| {
                Ok(RestructureProposalView {
                    tree_label: row.get(0)?,
                    authorizer_label: row.get(1)?,
                    countersigner_label: row.get(2)?,
                    generation: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ----- transfer ---------------------------------------------------------

    /// Copy an active identity to a second drive with `keyquorum transfer
    /// copy` (`COPY leaves the source active`, unlike `move_slot`, which
    /// relocates the one token a drive already carries). The first copy of
    /// a node's identity also enrolls it as a transfer identity
    /// (`keyquorum transfer enroll`), same as the seeded ghost was; later
    /// copies skip that step since it is idempotent but would otherwise
    /// prompt again. Both steps unwrap (and reseal) the slot with the same
    /// passphrase the person typed, since the CLI does not ask for a new
    /// one at the destination.
    pub fn transfer_copy(
        &mut self,
        label: &str,
        to_drive_id: &str,
        passphrase: &str,
    ) -> Result<Outcome> {
        if passphrase.is_empty() {
            return Ok(Outcome::done(false, "A passphrase is required", vec![]));
        }
        let Some(from_drive) = self.drive_holding(label) else {
            return Ok(Outcome::done(
                false,
                format!("No drive currently carries the slot {label}"),
                vec![],
            ));
        };
        if !from_drive.connected {
            return Ok(Outcome::done(
                false,
                format!("{}'s drive is not inserted", from_drive.name),
                vec![],
            ));
        }
        let from = from_drive.mount.clone();
        let Some(to_drive) = self.vm().bay.get(to_drive_id) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {to_drive_id}"),
                vec![],
            ));
        };
        if !to_drive.connected {
            return Ok(Outcome::done(
                false,
                format!("{} is not inserted", to_drive.name),
                vec![],
            ));
        }
        let (to, to_name) = (to_drive.mount.clone(), to_drive.name.clone());
        if from == to {
            return Ok(Outcome::done(
                false,
                format!("{label} is already on that drive"),
                vec![],
            ));
        }

        let mut steps: Vec<(String, Vec<String>)> = Vec::new();
        if transfer::identity(self.org(), label)?.is_none() {
            steps.push((
                format!(
                    "keyquorum transfer enroll --device {} --db {ORG_DB} --label {label}",
                    from.display()
                ),
                vec![passphrase.to_string(), passphrase.to_string()],
            ));
        }
        steps.push((
            format!(
                "keyquorum transfer copy --from-device {} --from-db {ORG_DB} --to-device {} --to-db {ORG_DB} --label {label} --as {label}",
                from.display(),
                to.display()
            ),
            vec![passphrase.to_string(), passphrase.to_string()],
        ));

        let mut runs = Vec::new();
        let mut ok = true;
        for (line, secrets) in steps {
            self.vm_mut().stage_secrets(secrets);
            let run = self.run(&line);
            self.vm_mut().clear_pending_secrets();
            ok = run.ok;
            runs.push(run);
            if !ok {
                break;
            }
        }
        let trace = transcripts(&runs, true);
        let message = if ok {
            format!("Copied {label} to {to_name}; {label} stays active on its original drive")
        } else {
            format!("Could not copy {label}: {}", last_error(&runs))
        };
        self.log(
            "transfer-copy",
            if ok { "granted" } else { "denied" },
            &message,
            trace.clone(),
            Some(lines_run(&runs)),
        );
        Ok(Outcome::done(ok, message, trace))
    }

    // ----- delivery -------------------------------------------------------

    /// Send a file with `keyquorum send` (which pushes to the relay). A quorum-locked
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

        let (line, name) = if let Some(path) = self.received_path(file_key) {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            let name = name.unwrap_or_default();
            (
                format!(
                    "keyquorum --db {store} send {} --name {} --to {to_label} --as {me_label} --slot {slot}",
                    quote(&path.display().to_string()),
                    quote(&name)
                ),
                name,
            )
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
                FileKind::Public { path } => (
                    format!(
                        "keyquorum --db {store} send {} --name {} --to {to_label} --as {me_label} --slot {slot}",
                        quote(&path.display().to_string()),
                        quote(&name)
                    ),
                    name,
                ),
                // A quorum file is unlocked where its shares are (the org
                // store), by the shares of whichever drives are inserted, and
                // sealed in memory: nothing is written to disk.
                FileKind::Quorum { file_id, key_id } => {
                    let (file_id, key_id) = (*file_id, *key_id);
                    let (flags, _) = self.unlock_flags(key_id, "--unlock-slot")?;
                    (
                        format!(
                            "keyquorum --db {ORG_DB} send --quorum-file {file_id} --name {} --to {to_label} --as {me_label} --slot {slot}{flags}",
                            quote(&name)
                        ),
                        name,
                    )
                }
            }
        };
        let lines = [line];
        let (runs, ok) = self.run_all(&lines);
        let trace = transcripts(&runs, false);
        let commands = lines_run(&runs);
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

    /// Check the relay with `keyquorum inbox list`, then check any new
    /// acknowledgements with `keyquorum inbox open` (which needs the
    /// active user's slot inserted). Returns the trace and how many new
    /// envelopes arrived.
    fn check_mail(&mut self) -> (Vec<TraceStep>, usize) {
        let user = self.actor();
        let (me, store, mail_dir) = (user.id.clone(), user.store(), user.mail_dir());
        let before = self.mail_ids(&mail_dir);
        // The store remembers where the last pull stopped, so no cursor is
        // passed.
        let line = format!(
            "keyquorum --db {store} inbox list --dir {}",
            mail_dir.display()
        );
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
                "keyquorum --db {store} inbox open {id} --dir {} --slot {slot}",
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

    /// What happens by itself when a person is present with their slot in:
    /// the relay is checked (`inbox list`), acknowledgements to their
    /// deliveries are opened (`inbox open`), and answers to the tracked
    /// files and requests they sent are recorded (`file ack`, `file
    /// open-answer`). Each is the real command, shown in the transcript;
    /// deciding to accept or refuse something stays a click.
    fn settle_mail_and_answers(&mut self) -> Vec<TraceStep> {
        let (mut trace, _) = self.check_mail();
        trace.extend(self.record_waiting_answers());
        trace
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

    /// Open (or reject) a letter with `keyquorum inbox open`, which
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
        // Pull first, as `inbox open` itself does, so a letter that arrived
        // since the last refresh can still be received.
        let pull = self.run(&format!(
            "keyquorum --db {store} inbox list --dir {}",
            mail_dir.display()
        ));
        let mut pulled = transcript(&pull, true);
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
            "keyquorum --db {store} inbox open {relay_id} --dir {} --slot {slot} --save-dir {}{}",
            mail_dir.display(),
            received.display(),
            if accept { "" } else { " --reject" }
        );
        let run = self.run(&line);
        pulled.extend(transcript(&run, true));
        let trace = pulled;
        let line = format!("{}\n{line}", pull.line);
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
        let mut trace = trace;
        trace.extend(self.settle_mail_and_answers());
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
        // History the action just wrote goes in first, so the action's own
        // entry stays the newest one (tutorial gates read `activity[0]`).
        if let Some(line) = &command {
            self.register_from_command(line);
        }
        self.sync_history();
        let actor = self.actor();
        self.activity.push(ActivityView {
            seq: self.next_seq,
            actor: format!("{} ({})", actor.name, actor.label),
            kind: kind.to_string(),
            outcome: outcome.to_string(),
            title: title.to_string(),
            trace,
            command,
            history: None,
        });
        self.next_seq += 1;
        if self.activity.len() > ACTIVITY_LIMIT {
            let excess = self.activity.len() - ACTIVITY_LIMIT;
            self.activity.drain(..excess);
        }
    }

    /// Record a browser-only interaction that has no CLI equivalent but is
    /// still useful tutorial/audit evidence (for example opening Properties
    /// or sorting the Explorer). The UI supplies only fixed, non-secret
    /// labels from its own event handlers.
    pub fn note_ui(&mut self, kind: &str, title: &str) -> Outcome {
        self.log(kind, "info", title, vec![], None);
        Outcome::done(true, title, vec![])
    }

    /// `command` carries the real line that produced this activity (e.g. the
    /// terminal input), so the UI's "equivalent operation" display -- and a
    /// gated tutorial step -- can tell one command apart from another; kinds
    /// with no real command line (`note_ui`) pass `None`.
    pub fn note_action(&mut self, kind: &str, title: &str, ok: bool, command: Option<String>) {
        self.log(
            kind,
            if ok { "granted" } else { "denied" },
            title,
            vec![],
            command,
        );
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
            password_files: self.password_file_views(),
            relay_status: self.relay_status()?,
            exports: self.export_views(),
            file_shares: self.file_share_views(),
            signatures: self.signature_views(),
            pending_restructures: self.pending_restructure_views()?,
            tracked_files: self.tracked_views(),
            tracked_letters: self.letter_views(),
            tracked_requests: self.request_views(),
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

/// Both public keys from `keyquorum-device public`'s "encryption "/"signing "
/// stdout lines (see `device_tool::print_slot`).
fn slot_public_keys(run: &CommandRun) -> Result<(String, String)> {
    let text = run.stdout_text();
    let encryption = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("encryption "))
        .map(str::to_string);
    let signing = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("signing "))
        .map(str::to_string);
    match (encryption, signing) {
        (Some(encryption), Some(signing)) => Ok((encryption, signing)),
        _ => Err(Error::InvalidPublicKey),
    }
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
