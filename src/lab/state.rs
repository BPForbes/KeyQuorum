//! The one lab state every surface reads: GUI buttons, the terminal, and
//! the WASM facade all call these methods, and every snapshot is built
//! from the same organization store, drive bay, and relay.
//!
//! Nothing here decides who may open a file. Unlocking gathers the shares
//! the inserted drives can unwrap and hands them to
//! `key_tree::reconstruct_presented`, `authority::require_unlock_approval`
//! (through `quorum::complete_unlock_in`), and `device::enforce_devices`
//! exactly as `keyquorum access quorum --state 1` does; the trace only
//! reports what those calls decided.

use super::drives::{DriveBay, MockDrive};
use super::relay::{LabRelay, MemoryLabRelay};
use super::seed::{self, Expiry, Protection};
use super::view::*;
use crate::authority::{self, UnlockGrant};
use crate::db;
use crate::device::{self, CustodyMode, CustodyPolicy, SlotSecrets, UnlockApproval, UsedLeaf};
use crate::envelope;
use crate::error::{Error, Result};
use crate::file_delivery;
use crate::key_tree::{self, KeyQuorumTree, NodeSpec, TreeNodeSummary};
use crate::keys::{self, KeyType};
use crate::private_bridge::{is_ancestor_or_self, parent_node_label};
use crate::quorum;
use crate::storage::MemoryStorage;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const ACTIVITY_LIMIT: usize = 80;
const FILE_ROOT: &str = "/lab/files";
const RECEIVED_ROOT: &str = "/lab/received";

struct LabUser {
    id: String,
    name: String,
    label: String,
    role: String,
    drive: String,
}

enum FileKind {
    Public {
        contents: Vec<u8>,
    },
    Quorum {
        file_id: i64,
        key_id: i64,
    },
    Received {
        owner: String,
        from: String,
        file_id: i64,
        key_id: i64,
    },
}

struct LabFile {
    id: String,
    folder: String,
    name: String,
    lesson: String,
    kind: FileKind,
    size: usize,
    /// Cached at lock time, since `created_at` is unreachable once a
    /// purge removes the `files` row (see [`FileKind::Quorum`]).
    created_at: String,
    /// Resolved UTC cutoff (`YYYY-MM-DD HH:MM:SS`), cached the same way
    /// and for the same reason. `None` if the file never expires.
    expires_at: Option<String>,
}

impl LabFile {
    fn quorum_ids(&self) -> Option<(i64, i64)> {
        match self.kind {
            FileKind::Public { .. } => None,
            FileKind::Quorum { file_id, key_id }
            | FileKind::Received {
                file_id, key_id, ..
            } => Some((file_id, key_id)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SentStatus {
    Delivered,
    Acknowledged,
    Rejected,
}

struct SentItem {
    delivery_id: [u8; 16],
    relay_id: i64,
    from: String,
    to: String,
    file_name: String,
    status: SentStatus,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InboxStatus {
    Received,
    Rejected,
    Invalid,
}

struct ReceivedItem {
    status: InboxStatus,
    from: Option<String>,
    file_name: Option<String>,
    file_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ApprovalStatus {
    Pending,
    Approved,
    Declined,
}

struct Approval {
    id: u64,
    file_name: String,
    file_id: i64,
    key_id: i64,
    leaf: String,
    approver: String,
    requested_by: String,
    device_ids: Vec<[u8; 16]>,
    status: ApprovalStatus,
    signature: Option<[u8; 64]>,
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

/// Result of one unlock evaluation.
struct Access {
    granted: bool,
    plaintext: Option<Zeroizing<Vec<u8>>>,
    trace: Vec<TraceStep>,
    required: Vec<String>,
    satisfied: Vec<String>,
    command: Option<String>,
}

pub struct LabState {
    conn: Connection,
    relay: MemoryLabRelay,
    bay: DriveBay,
    disk: MemoryStorage,
    users: Vec<LabUser>,
    files: Vec<LabFile>,
    active: usize,
    org_key_id: i64,
    sent: Vec<SentItem>,
    received: BTreeMap<i64, ReceivedItem>,
    acks_opened: HashSet<i64>,
    approvals: Vec<Approval>,
    next_approval: u64,
    activity: Vec<ActivityView>,
    next_seq: u64,
    last_access: Option<AccessView>,
    received_count: u32,
}

impl LabState {
    /// Build the seeded lab: containers and slots on each mock drive,
    /// registered keys and placements, the org tree, and the locked files.
    pub fn seed() -> Result<Self> {
        let mut conn = db::open_in_memory()?;
        let mut bay = DriveBay::default();
        for drive in seed::DRIVES {
            bay.drives.push(MockDrive::new(
                drive.id,
                drive.name,
                drive.mount,
                drive.slots,
            ));
        }
        // Every slot's encryption secret, kept only long enough to seed the
        // one file that demonstrates a ghost eviction (survivor shares must
        // be unwrapped to call `key_tree::evict_and_refresh`).
        let mut slot_secrets: HashMap<String, Zeroizing<[u8; 32]>> = HashMap::new();
        for drive in seed::DRIVES {
            let mount = PathBuf::from(drive.mount);
            let mut container = device::init_in(&mut bay, &mount)?;
            for slot in drive.slots {
                let passphrase = seed::demo_passphrase(slot);
                let provisioned =
                    device::provision_in(&mut bay, &mut container, slot, &passphrase)?;
                keys::register_key(
                    &conn,
                    slot,
                    KeyType::Encryption,
                    &provisioned.encryption_public,
                )?;
                keys::register_key(&conn, slot, KeyType::Signing, &provisioned.signing_public)?;
                device::bind_slot_in(&bay, &conn, &container, slot, &passphrase)?;
                slot_secrets.insert(slot.to_string(), provisioned.encryption_secret);
            }
            let seeded = bay.get_mut(drive.id).ok_or(Error::InvalidDevice)?;
            seeded.device_id = *container.device_id();
            seeded.connected = drive.inserted;
        }

        let org_key_id = seed_org_tree(&mut conn)?;

        let mut disk = MemoryStorage::new();
        let mut files = Vec::new();
        for file in seed::FILES {
            let kind = match &file.protection {
                Protection::Public => FileKind::Public {
                    contents: file.contents.as_bytes().to_vec(),
                },
                Protection::Quorum {
                    threshold,
                    leaves,
                    custody,
                    minimum_devices,
                    approval,
                    expires,
                } => {
                    let expires_at = resolve_expiry(&conn, expires)?;
                    let leaves = leaves
                        .iter()
                        .map(|label| Ok((label.to_string(), encryption_key_id(&conn, label)?)))
                        .collect::<Result<Vec<_>>>()?;
                    let spec = NodeSpec::flat_split(file.id, *threshold, leaves);
                    let path = Path::new(FILE_ROOT).join(format!("{}.kqenc", file.name));
                    let file_id = quorum::lock_bytes_until_in(
                        &mut disk,
                        &mut conn,
                        file.contents.as_bytes(),
                        &path,
                        file.name,
                        &spec,
                        expires_at.as_deref(),
                    )?;
                    let key_id = quorum::status(&conn, file_id)?.tree.key_id;
                    device::set_custody_policy(
                        &conn,
                        key_id,
                        &CustodyPolicy {
                            mode: *custody,
                            minimum_physical_devices: *minimum_devices,
                            unlock_approval: *approval,
                        },
                    )?;
                    FileKind::Quorum { file_id, key_id }
                }
                Protection::QuorumWithGhost {
                    threshold,
                    leaves,
                    ghost_label,
                    custody,
                    minimum_devices,
                } => {
                    // A key for the departed person, registered but never
                    // provisioned onto any container: nobody holds its
                    // secret, so it can never unwrap a share. It exists
                    // only long enough to be evicted below.
                    let (_ghost_secret, ghost_public) = keys::generate_encryption_keypair();
                    keys::register_key(&conn, ghost_label, KeyType::Encryption, &ghost_public)?;
                    let mut node_leaves: Vec<(String, i64)> = leaves
                        .iter()
                        .map(|label| Ok((label.to_string(), encryption_key_id(&conn, label)?)))
                        .collect::<Result<Vec<_>>>()?;
                    node_leaves.push((
                        ghost_label.to_string(),
                        encryption_key_id(&conn, ghost_label)?,
                    ));
                    let spec = NodeSpec::flat_split(file.id, *threshold, node_leaves);
                    let path = Path::new(FILE_ROOT).join(format!("{}.kqenc", file.name));
                    let file_id = quorum::lock_bytes_in(
                        &mut disk,
                        &mut conn,
                        file.contents.as_bytes(),
                        &path,
                        file.name,
                        &spec,
                    )?;
                    let key_id = quorum::status(&conn, file_id)?.tree.key_id;
                    device::set_custody_policy(
                        &conn,
                        key_id,
                        &CustodyPolicy {
                            mode: *custody,
                            minimum_physical_devices: *minimum_devices,
                            unlock_approval: UnlockApproval::None,
                        },
                    )?;
                    evict_ghost(&mut conn, key_id, ghost_label, leaves, &slot_secrets)?;
                    FileKind::Quorum { file_id, key_id }
                }
            };
            let created_at = match kind {
                FileKind::Quorum { file_id, .. } => quorum::status(&conn, file_id)?.created_at,
                _ => String::new(),
            };
            let expires_at = match kind {
                FileKind::Quorum { file_id, .. } => quorum::status(&conn, file_id)?.expires_at,
                _ => None,
            };
            files.push(LabFile {
                id: file.id.to_string(),
                folder: file.folder.to_string(),
                name: file.name.to_string(),
                lesson: file.lesson.to_string(),
                kind,
                size: file.contents.len(),
                created_at,
                expires_at,
            });
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
            conn,
            relay: MemoryLabRelay::new()?,
            bay,
            disk,
            users,
            files,
            active,
            org_key_id,
            sent: Vec::new(),
            received: BTreeMap::new(),
            acks_opened: HashSet::new(),
            approvals: Vec::new(),
            next_approval: 1,
            activity: Vec::new(),
            next_seq: 1,
            last_access: None,
            received_count: 0,
        };
        state.log(
            "reset",
            "info",
            "Lab seeded",
            vec![
                TraceStep::info(format!(
                    "{} users, {} mock USB drives, {} files",
                    state.users.len(),
                    state.bay.drives.len(),
                    state.files.len()
                )),
                TraceStep::info(
                    "Every slot is a real Argon2id token in a signed device.kq container",
                ),
            ],
            None,
        );
        Ok(state)
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

    fn user_by_id(&self, id: &str) -> Option<&LabUser> {
        self.users.iter().find(|user| user.id == id)
    }

    fn describe_label(&self, label: &str) -> String {
        match self.user_by_label(label) {
            Some(user) => format!("{} ({label})", user.name),
            None => label.to_string(),
        }
    }

    pub fn switch_user(&mut self, key: &str) -> Result<Outcome> {
        let Some(index) = self.user_index(key) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user named {key}"),
                vec![],
            ));
        };
        self.active = index;
        let user = self.actor();
        let visible = self.visible_labels(&user.label)?;
        let mut visible: Vec<String> = visible.into_iter().collect();
        visible.sort();
        let trace = vec![
            TraceStep::pass(format!(
                "Active identity: {} / {} — {}",
                user.name, user.label, user.role
            )),
            TraceStep::info(format!(
                "Visible slice of the org tree: {}",
                visible.join(", ")
            )),
        ];
        let message = format!("Switched to {} ({})", user.name, user.label);
        self.log("user", "info", &message, trace.clone(), None);
        Ok(Outcome::done(true, message, trace))
    }

    fn visible_labels(&self, label: &str) -> Result<HashSet<String>> {
        key_tree::visible_labels(&self.conn, self.org_key_id, label)
    }

    // ----- drives ---------------------------------------------------------

    pub fn set_drive(&mut self, id: &str, connected: bool) -> Result<Outcome> {
        let Some(drive) = self.bay.get_mut(id) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {id}"),
                vec![],
            ));
        };
        if drive.connected == connected {
            let state = if connected {
                "already inserted"
            } else {
                "already ejected"
            };
            return Ok(Outcome::done(
                true,
                format!("{} is {state}", drive.name),
                vec![],
            ));
        }
        drive.connected = connected;
        let name = drive.name.clone();
        let mount = drive.mount.display().to_string();
        let mut trace = Vec::new();
        let command = if connected {
            let container = device::open_in(&self.bay, Path::new(&mount))?;
            trace.push(TraceStep::pass(format!(
                "{name} mounted at {mount}; device.kq signature verified"
            )));
            trace.push(TraceStep::info(format!(
                "Device id {} with slots {}",
                hex::encode(container.device_id()),
                container
                    .slots()
                    .iter()
                    .map(|slot| slot.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
            format!("keyquorum device list {mount}")
        } else {
            trace.push(TraceStep::info(format!(
                "{name} ejected; its slots can no longer unwrap shares or sign"
            )));
            format!("umount {mount}")
        };
        let message = format!("{name} {}", if connected { "inserted" } else { "ejected" });
        self.log("usb", "info", &message, trace.clone(), Some(command));
        Ok(Outcome::done(true, message, trace))
    }

    /// Open a slot on whichever drive carries it. Fails when that drive is
    /// ejected, because the container read itself fails.
    fn open_slot(&self, label: &str) -> Result<(String, SlotSecrets)> {
        let drive = self.bay.holding(label).ok_or(Error::InvalidSlot)?;
        let container = device::open_in(&self.bay, &drive.mount)?;
        let secrets =
            device::open_slot_in(&self.bay, &container, label, &seed::demo_passphrase(label))?;
        Ok((drive.name.clone(), secrets))
    }

    fn drive_name_for(&self, label: &str) -> String {
        self.bay
            .holding(label)
            .map(|drive| drive.name.clone())
            .unwrap_or_else(|| "no drive".into())
    }

    fn slot_connected(&self, label: &str) -> bool {
        self.bay
            .holding(label)
            .map(|drive| drive.connected)
            .unwrap_or(false)
    }

    /// Move a slot's token and signed placement to another drive, using
    /// `device::relocate_slot_in` (delete-then-write, same as the native
    /// `keyquorum-device` container-to-container move) followed by
    /// `device::bind_slot_in` so `device_placements` — and so every
    /// physical-device count — reflects the new container immediately.
    /// Both drives must be inserted, matching the physical requirement of
    /// moving a token between two USB drives that are actually plugged in.
    pub fn move_slot(&mut self, label: &str, to_drive_id: &str) -> Result<Outcome> {
        let actor_label = self.actor().label.clone();
        let mut trace = vec![TraceStep::pass(format!(
            "Active identity: {}",
            self.describe_label(&actor_label)
        ))];
        let Some(from_drive) = self.bay.holding(label).map(|drive| drive.id.clone()) else {
            return Ok(Outcome::done(
                false,
                format!("No drive currently carries the slot {label}"),
                trace,
            ));
        };
        let Some(to_drive) = self.bay.get(to_drive_id).map(|drive| drive.id.clone()) else {
            return Ok(Outcome::done(
                false,
                format!("No mock drive named {to_drive_id}"),
                trace,
            ));
        };
        if from_drive == to_drive {
            return Ok(Outcome::done(
                true,
                format!("{label} is already on that drive"),
                trace,
            ));
        }
        let from_name = self.bay.get(&from_drive).unwrap().name.clone();
        let to_name = self.bay.get(&to_drive).unwrap().name.clone();
        if !self.bay.get(&from_drive).unwrap().connected {
            trace.push(TraceStep::fail(format!(
                "{from_name} (currently holding {label}) is not inserted"
            )));
            return Ok(Outcome::done(
                false,
                format!("Insert {from_name} to move {label} off of it"),
                trace,
            ));
        }
        if !self.bay.get(&to_drive).unwrap().connected {
            trace.push(TraceStep::fail(format!("{to_name} is not inserted")));
            return Ok(Outcome::done(
                false,
                format!("Insert {to_name} to move {label} onto it"),
                trace,
            ));
        }

        let passphrase = seed::demo_passphrase(label);
        let from_mount = self.bay.get(&from_drive).unwrap().mount.clone();
        let to_mount = self.bay.get(&to_drive).unwrap().mount.clone();
        let mut from_container = device::open_in(&self.bay, &from_mount)?;
        let mut to_container = device::open_in(&self.bay, &to_mount)?;
        device::relocate_slot_in(
            &mut self.bay,
            &mut from_container,
            &mut to_container,
            label,
            &passphrase,
        )?;
        device::bind_slot_in(&self.bay, &self.conn, &to_container, label, &passphrase)?;

        if let Some(drive) = self.bay.get_mut(&from_drive) {
            drive.slots.retain(|slot| slot != label);
        }
        if let Some(drive) = self.bay.get_mut(&to_drive) {
            drive.slots.push(label.to_string());
        }

        trace.push(TraceStep::pass(format!(
            "Slot {label} relocated: {from_name} → {to_name} (device.kq re-signed on both ends)"
        )));
        let now_sharing = self
            .bay
            .get(&to_drive)
            .map(|drive| drive.slots.len())
            .unwrap_or(1);
        if now_sharing > 1 {
            trace.push(TraceStep::info(format!(
                "{to_name} now carries {now_sharing} slots; logical custody lets them meet a threshold together, but they still count as one physical device"
            )));
        }
        trace.push(TraceStep::info(
            "device_placements re-bound to the new container's device id — quorum evaluation reflects this on the next unlock",
        ));
        let message = format!("Moved {label} from {from_name} to {to_name}");
        self.log(
            "move",
            "info",
            &message,
            trace.clone(),
            Some(format!(
                "keyquorum device relocate --from {from_mount} --to {to_mount} --slot {label}",
                from_mount = from_mount.display(),
                to_mount = to_mount.display()
            )),
        );
        Ok(Outcome::done(true, message, trace))
    }

    // ----- files ----------------------------------------------------------

    fn file_index(&self, key: &str) -> Option<usize> {
        let key = key.trim();
        let owner = &self.actor().id;
        self.files.iter().position(|file| {
            let visible = match &file.kind {
                FileKind::Received { owner: o, .. } => o == owner,
                _ => true,
            };
            visible && (file.id == key || file.name == key)
        })
    }

    fn leaves(&self, key_id: i64) -> Result<Vec<(i64, String)>> {
        let tree = KeyQuorumTree::load(&self.conn, key_id)?;
        Ok(tree
            .nodes
            .iter()
            .filter(|node| node.is_active && node.hardware_key_id.is_some())
            .map(|node| (node.db_id, node.id.clone()))
            .collect())
    }

    /// How the active user relates to a file's share holders: `holder`,
    /// `oversight` (a dotted-label ancestor of a holder), `lineage` (a
    /// holder is the user's own ancestor, e.g. their manager), or `none`.
    /// This only decides who may *start* an unlock; whether it succeeds is
    /// the key tree's decision.
    fn access_class(&self, file: &LabFile) -> Result<&'static str> {
        let actor = self.actor();
        match &file.kind {
            FileKind::Public { .. } => Ok("public"),
            FileKind::Received { owner, .. } if owner != &actor.id => Ok("none"),
            FileKind::Quorum { key_id, .. } | FileKind::Received { key_id, .. } => {
                let leaves = self.leaves(*key_id)?;
                if leaves.iter().any(|(_, label)| label == &actor.label) {
                    Ok("holder")
                } else if leaves
                    .iter()
                    .any(|(_, label)| is_ancestor_or_self(&actor.label, label))
                {
                    Ok("oversight")
                } else if leaves
                    .iter()
                    .any(|(_, label)| is_ancestor_or_self(label, &actor.label))
                {
                    Ok("lineage")
                } else {
                    Ok("none")
                }
            }
        }
    }

    pub fn unlock(&mut self, key: &str) -> Result<Outcome> {
        let Some(index) = self.file_index(key) else {
            return Ok(Outcome::done(false, format!("No file named {key}"), vec![]));
        };
        let access = self.evaluate(index)?;
        let file = &self.files[index];
        let name = file.name.clone();
        let id = file.id.clone();
        let message = if access.granted {
            format!("Access granted: {name}")
        } else {
            format!("Access denied: {name}")
        };
        let opened = access.plaintext.as_ref().map(|plain| OpenedFile {
            name: name.clone(),
            text: String::from_utf8_lossy(plain).into_owned(),
        });
        self.last_access = Some(AccessView {
            file_id: id,
            file_name: name,
            granted: access.granted,
            required: access.required.clone(),
            satisfied: access.satisfied.clone(),
        });
        let outcome = if access.granted { "granted" } else { "denied" };
        self.log(
            "access",
            outcome,
            &message,
            access.trace.clone(),
            access.command.clone(),
        );
        Ok(Outcome {
            ok: access.granted,
            message,
            trace: access.trace,
            opened,
        })
    }

    /// Run one unlock attempt for the active user against file `index`.
    fn evaluate(&mut self, index: usize) -> Result<Access> {
        let actor_label = self.actor().label.clone();
        let actor_name = self.actor().name.clone();
        let mut trace = vec![TraceStep::pass(format!(
            "Active identity: {actor_name} / {actor_label}"
        ))];
        let file = &self.files[index];
        let file_name = file.name.clone();
        let expires_at = file.expires_at.clone();

        let (file_id, key_id) = match &file.kind {
            FileKind::Public { contents } => {
                trace.push(TraceStep::pass("Public file: no key tree protects it"));
                return Ok(Access {
                    granted: true,
                    plaintext: Some(Zeroizing::new(contents.clone())),
                    trace,
                    required: vec![],
                    satisfied: vec![],
                    command: Some(format!("cat /lab/{}/{}", file.folder, file.name)),
                });
            }
            FileKind::Quorum { file_id, key_id }
            | FileKind::Received {
                file_id, key_id, ..
            } => (*file_id, *key_id),
        };
        let leaves = self.leaves(key_id)?;
        let required: Vec<String> = leaves.iter().map(|(_, label)| label.clone()).collect();
        let denied = |trace: Vec<TraceStep>, satisfied: Vec<String>| Access {
            granted: false,
            plaintext: None,
            trace,
            required: required.clone(),
            satisfied,
            command: None,
        };

        // An expired file is gone before anyone's identity or shares even
        // matter. The real destroy (ciphertext + `files` row) runs through
        // `quorum::purge_if_expired_in`, same as an unlock attempt against
        // the native CLI; this only decides whether to call it.
        if let Some(expires_at) = &expires_at {
            if expiry_passed(&self.conn, expires_at)? {
                trace.push(TraceStep::fail(format!(
                    "This file expired on {expires_at} UTC and was removed on first access."
                )));
                let _ = quorum::purge_if_expired_in(&mut self.disk, &self.conn, file_id);
                let mut access = denied(trace, vec![]);
                access.command = Some(format!("keyquorum access quorum --state 1 --id {file_id}"));
                return Ok(access);
            }
        }

        match self.access_class(&self.files[index])? {
            "holder" => trace.push(TraceStep::pass(format!(
                "{actor_label} holds a share in {file_name}"
            ))),
            "oversight" => trace.push(TraceStep::pass(format!(
                "{actor_label} is a dotted-label ancestor of share holders ({})",
                required.join(", ")
            ))),
            "lineage" => trace.push(TraceStep::pass(format!(
                "A share holder is in {actor_label}'s own lineage ({})",
                required
                    .iter()
                    .filter(|label| is_ancestor_or_self(label, &actor_label))
                    .map(|label| self.describe_label(label))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
            _ => {
                trace.push(TraceStep::fail(format!(
                    "{actor_label} holds no share in {file_name}, and no holder is in its lineage ({})",
                    required.join(", ")
                )));
                return Ok(denied(trace, vec![]));
            }
        }

        let own_drive = self.drive_name_for(&actor_label);
        if self.slot_connected(&actor_label) {
            trace.push(TraceStep::pass(format!(
                "Your slot {actor_label} is on {own_drive} (inserted)"
            )));
        } else {
            trace.push(TraceStep::fail(format!(
                "Your slot {actor_label} is on {own_drive}, which is not inserted"
            )));
            return Ok(denied(trace, vec![]));
        }

        let policy = device::custody_policy(&self.conn, key_id)?;
        trace.push(TraceStep::info(policy_line(&policy)));

        for drive in &self.bay.drives {
            let held: Vec<&str> = leaves
                .iter()
                .filter(|(_, label)| drive.slots.contains(label))
                .map(|(_, label)| label.as_str())
                .collect();
            if held.is_empty() {
                continue;
            }
            if drive.connected {
                trace.push(TraceStep::pass(format!(
                    "{} inserted · device {}",
                    drive.name,
                    short_hex(&drive.device_id)
                )));
            } else {
                trace.push(TraceStep::fail(format!(
                    "{} not inserted (carries {})",
                    drive.name,
                    held.join(", ")
                )));
            }
        }

        let mut shares = HashMap::new();
        let mut unwrapped = Vec::new();
        let mut slot_args = Vec::new();
        for (node_id, label) in &leaves {
            match self.open_slot(label) {
                Ok((drive_name, secrets)) => {
                    let share = key_tree::unwrap_leaf_share(
                        &self.conn,
                        *node_id,
                        secrets.encryption_secret.as_slice(),
                    )?;
                    shares.insert(*node_id, share);
                    unwrapped.push(label.clone());
                    if let Some(drive) = self.bay.holding(label) {
                        slot_args.push(format!("--slot {}={label}", drive.mount.display()));
                    }
                    trace.push(TraceStep::pass(format!(
                        "Share {label} unwrapped by its slot on {drive_name}"
                    )));
                }
                Err(_) => trace.push(TraceStep::fail(format!(
                    "Share {label} unavailable: {} is not inserted",
                    self.drive_name_for(label)
                ))),
            }
        }
        let mut command = format!(
            "keyquorum access quorum --state 1 --id {file_id} {}",
            slot_args.join(" ")
        );

        let presented = match key_tree::reconstruct_presented(&self.conn, key_id, &shares) {
            Ok(presented) => presented,
            Err(err) => {
                let _ = quorum::record_unlock_failure(&self.conn, file_id, &err);
                trace.push(TraceStep::fail(
                    self.reconstruct_failure(&err, key_id, &leaves, &unwrapped, &policy)?,
                ));
                let mut access = denied(trace, unwrapped);
                access.command = Some(command);
                return Ok(access);
            }
        };
        let used: Vec<String> = presented
            .leaves
            .iter()
            .map(|leaf| leaf.leaf_label.clone())
            .collect();
        trace.push(TraceStep::pass(format!(
            "Shamir threshold met; shares used: {}",
            used.join(", ")
        )));
        trace.push(TraceStep::pass(format!(
            "Physical devices: {} (minimum {}) — {}",
            presented.devices.len(),
            policy.minimum_physical_devices,
            device::format_presentation(&presented.devices)
        )));

        let mut grants = Vec::new();
        if policy.unlock_approval == UnlockApproval::Parent {
            let mut device_ids: Vec<[u8; 16]> = presented
                .devices
                .iter()
                .map(|device| device.device_id)
                .collect();
            device_ids.sort();
            let mut missing = false;
            for leaf in &presented.leaves {
                let Some(parent) = parent_node_label(&leaf.leaf_label) else {
                    missing = true;
                    continue;
                };
                let approved = self.approvals.iter().find(|approval| {
                    approval.status == ApprovalStatus::Approved
                        && approval.file_id == file_id
                        && approval.leaf == leaf.leaf_label
                        && approval.approver == parent
                        && approval.device_ids == device_ids
                });
                match approved.and_then(|approval| approval.signature) {
                    Some(signature) => {
                        trace.push(TraceStep::pass(format!(
                            "Parent approval: {} signed for {}",
                            self.describe_label(parent),
                            leaf.leaf_label
                        )));
                        if let Some(drive) = self.bay.holding(parent) {
                            command.push_str(&format!(
                                " --approve {}='{}>{parent}'",
                                leaf.leaf_label,
                                drive.mount.display()
                            ));
                        }
                        grants.push(UnlockGrant {
                            leaf_label: leaf.leaf_label.clone(),
                            countersigner_label: parent.to_string(),
                            signature,
                        });
                    }
                    None => {
                        missing = true;
                        trace.push(TraceStep::fail(format!(
                            "Parent approval from {} missing for {}",
                            self.describe_label(parent),
                            leaf.leaf_label
                        )));
                        let requested_by = self.actor().id.clone();
                        self.request_approval(
                            &file_name,
                            file_id,
                            key_id,
                            &leaf.leaf_label,
                            parent,
                            &requested_by,
                            &device_ids,
                        );
                        trace.push(TraceStep::info(format!(
                            "Approval request sent to {} (switch to them to approve)",
                            self.describe_label(parent)
                        )));
                    }
                }
            }
            if missing {
                let err = Error::UnlockApprovalRequired;
                let _ = quorum::record_unlock_failure(&self.conn, file_id, &err);
                let mut secret = presented.secret;
                secret.zeroize();
                let mut access = denied(trace, used);
                access.command = Some(command);
                return Ok(access);
            }
        }

        match quorum::complete_unlock_in(&mut self.disk, &self.conn, file_id, presented, &grants) {
            Ok(plaintext) => {
                trace.push(TraceStep::pass(format!(
                    "Data key reconstructed; {} bytes decrypted with AES-256-GCM",
                    plaintext.len()
                )));
                Ok(Access {
                    granted: true,
                    plaintext: Some(Zeroizing::new(plaintext)),
                    trace,
                    required,
                    satisfied: used,
                    command: Some(command),
                })
            }
            Err(err) => {
                trace.push(TraceStep::fail(format!(
                    "KeyQuorum refused the unlock: {err}"
                )));
                let mut access = denied(trace, used);
                access.command = Some(command);
                Ok(access)
            }
        }
    }

    fn reconstruct_failure(
        &self,
        err: &Error,
        key_id: i64,
        leaves: &[(i64, String)],
        unwrapped: &[String],
        policy: &CustodyPolicy,
    ) -> Result<String> {
        Ok(match err {
            Error::QuorumNotMet => format!(
                "Quorum not satisfied: {} of {} shares presented ({})",
                unwrapped.len(),
                leaves.len(),
                threshold_line(&self.conn, key_id)?
            ),
            Error::PhysicalDevicesNotMet => {
                let used: Vec<UsedLeaf> = leaves
                    .iter()
                    .filter(|(_, label)| unwrapped.contains(label))
                    .filter_map(|(_, label)| {
                        let key = encryption_key_id(&self.conn, label).ok()?;
                        Some(UsedLeaf {
                            hardware_key_id: key,
                            leaf_label: label.clone(),
                        })
                    })
                    .collect();
                let devices = device::classify_devices(&self.conn, key_id, &used)
                    .map(|groups| groups.len())
                    .unwrap_or(0);
                format!(
                    "Minimum physical devices: {} required, shares came from {devices}",
                    policy.minimum_physical_devices
                )
            }
            Error::CustodyViolation => {
                "Custody: hardware mode allows one key per device, and two shares came from one container".into()
            }
            other => format!("KeyQuorum refused the reconstruction: {other}"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn request_approval(
        &mut self,
        file_name: &str,
        file_id: i64,
        key_id: i64,
        leaf: &str,
        approver: &str,
        requested_by: &str,
        device_ids: &[[u8; 16]],
    ) {
        let exists = self.approvals.iter().any(|approval| {
            approval.status == ApprovalStatus::Pending
                && approval.file_id == file_id
                && approval.leaf == leaf
                && approval.device_ids == device_ids
        });
        if exists {
            return;
        }
        self.approvals.push(Approval {
            id: self.next_approval,
            file_name: file_name.to_string(),
            file_id,
            key_id,
            leaf: leaf.to_string(),
            approver: approver.to_string(),
            requested_by: requested_by.to_string(),
            device_ids: device_ids.to_vec(),
            status: ApprovalStatus::Pending,
            signature: None,
        });
        self.next_approval += 1;
    }

    /// Sign (or decline) a pending unlock approval as the active user. The
    /// signature is Ed25519 over `authority::unlock_approval_preimage`,
    /// bound to the file, leaf, and the exact device set of the request.
    pub fn answer_approval(&mut self, id: u64, approve: bool) -> Result<Outcome> {
        let actor_label = self.actor().label.clone();
        let Some(index) = self.approvals.iter().position(|approval| approval.id == id) else {
            return Ok(Outcome::done(
                false,
                format!("No approval request #{id}"),
                vec![],
            ));
        };
        let approval = &self.approvals[index];
        let mut trace = vec![TraceStep::pass(format!(
            "Active identity: {}",
            self.describe_label(&actor_label)
        ))];
        if approval.status != ApprovalStatus::Pending {
            return Ok(Outcome::done(
                false,
                format!("Approval #{id} was already answered"),
                trace,
            ));
        }
        if approval.approver != actor_label {
            trace.push(TraceStep::fail(format!(
                "Only {} (the parent of {}) can answer this request",
                self.describe_label(&approval.approver),
                approval.leaf
            )));
            return Ok(Outcome::done(false, "Not your approval to give", trace));
        }
        let title = format!(
            "{} unlock of {} for {}",
            if approve { "Approved" } else { "Declined" },
            approval.file_name,
            approval.leaf
        );
        if !approve {
            self.approvals[index].status = ApprovalStatus::Declined;
            trace.push(TraceStep::info("Request declined; nothing was signed"));
            self.log("approval", "info", &title, trace.clone(), None);
            return Ok(Outcome::done(true, title, trace));
        }
        let (drive_name, secrets) = match self.open_slot(&actor_label) {
            Ok(opened) => opened,
            Err(_) => {
                trace.push(TraceStep::fail(format!(
                    "Your signing key is on {}, which is not inserted",
                    self.drive_name_for(&actor_label)
                )));
                return Ok(Outcome::done(false, "Insert your USB to sign", trace));
            }
        };
        let preimage = authority::unlock_approval_preimage(
            approval.file_id,
            approval.key_id,
            &approval.leaf,
            &approval.approver,
            &approval.device_ids,
        )?;
        let signature = device::sign_message(&secrets, &preimage);
        trace.push(TraceStep::pass(format!(
            "Signed KQ-UNLOCK-APPROVAL-v1 preimage with {actor_label}'s slot on {drive_name}"
        )));
        trace.push(TraceStep::info(format!(
            "Bound to file {}, leaf {}, devices {}",
            approval.file_name,
            approval.leaf,
            approval
                .device_ids
                .iter()
                .map(short_hex)
                .collect::<Vec<_>>()
                .join(", ")
        )));
        self.approvals[index].status = ApprovalStatus::Approved;
        self.approvals[index].signature = Some(signature);
        self.log("approval", "granted", &title, trace.clone(), None);
        Ok(Outcome::done(true, title, trace))
    }

    // ----- delivery -------------------------------------------------------

    fn fingerprint_for(&self, label: &str) -> Result<String> {
        let key = keys::active_keys_for(&self.conn, label, KeyType::Encryption)?
            .into_iter()
            .next()
            .ok_or(Error::NodeNotFound)?;
        Ok(keys::fingerprint(&key.public_key))
    }

    pub fn send(&mut self, file_key: &str, recipient_key: &str) -> Result<Outcome> {
        let Some(index) = self.file_index(file_key) else {
            return Ok(Outcome::done(
                false,
                format!("No file named {file_key}"),
                vec![],
            ));
        };
        let Some(recipient) = self.user_index(recipient_key) else {
            return Ok(Outcome::done(
                false,
                format!("No lab user named {recipient_key}"),
                vec![],
            ));
        };
        let actor = self.actor();
        let (actor_id, actor_label, actor_name) =
            (actor.id.clone(), actor.label.clone(), actor.name.clone());
        let recipient = &self.users[recipient];
        let (to_id, to_label, to_name) = (
            recipient.id.clone(),
            recipient.label.clone(),
            recipient.name.clone(),
        );
        let file_name = self.files[index].name.clone();
        let title = format!("Send {file_name} to {to_name}");
        let mut trace = vec![TraceStep::pass(format!(
            "Sender: {actor_name} / {actor_label}"
        ))];

        if to_id == actor_id {
            trace.push(TraceStep::fail(
                "Sender and recipient are the same identity",
            ));
            return Ok(self.denied_send(&title, trace));
        }
        let visible = self.visible_labels(&actor_label)?;
        if !visible.contains(&to_label) {
            trace.push(TraceStep::fail(format!(
                "{to_name} ({to_label}) is outside your visible slice: no lineage, sibling, or established bridge reaches that label"
            )));
            return Ok(self.denied_send(&title, trace));
        }
        trace.push(TraceStep::pass(format!(
            "{to_name} ({to_label}) is in your slice ({})",
            self.reach_reason(&actor_label, &to_label)
        )));

        let (drive_name, sender_secrets) = match self.open_slot(&actor_label) {
            Ok(opened) => opened,
            Err(_) => {
                trace.push(TraceStep::fail(format!(
                    "Your signing key is on {}, which is not inserted",
                    self.drive_name_for(&actor_label)
                )));
                return Ok(self.denied_send(&title, trace));
            }
        };
        trace.push(TraceStep::pass(format!(
            "Signing with {actor_label}'s slot on {drive_name}"
        )));

        let access = self.evaluate(index)?;
        let Some(plaintext) = access.plaintext else {
            trace.push(TraceStep::fail(
                "You can only send a file you can open right now:",
            ));
            trace.extend(access.trace);
            return Ok(self.denied_send(&title, trace));
        };
        trace.push(TraceStep::pass(format!("{file_name} opened for sending")));

        let recipient_key = keys::active_keys_for(&self.conn, &to_label, KeyType::Encryption)?
            .into_iter()
            .next()
            .ok_or(Error::NodeNotFound)?;
        let recipient_public: [u8; 32] = recipient_key
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)?;
        let sealed = file_delivery::seal_letter(&file_delivery::Outgoing {
            sender_label: &actor_label,
            sender_signing_secret: &sender_secrets.signing_secret,
            sender_encryption_public: &sender_secrets.encryption_public,
            recipient_label: &to_label,
            recipient_encryption_public: &recipient_public,
            file_name: &file_name,
            contents: &plaintext,
        })?;
        trace.push(TraceStep::pass(format!(
            "Sealed a KQPB file-delivery letter ({} bytes) to {to_label}'s encryption key and signed it",
            sealed.bytes.len()
        )));
        let relay_id = self.relay.push(&sealed.bytes)?;
        trace.push(TraceStep::pass(format!(
            "Relay stored letter #{relay_id} for fingerprint {}… (it cannot read the name or contents)",
            &self.fingerprint_for(&to_label)?[..12]
        )));
        self.sent.push(SentItem {
            delivery_id: sealed.delivery_id,
            relay_id,
            from: actor_id,
            to: to_id,
            file_name: file_name.clone(),
            status: SentStatus::Delivered,
        });
        let message = format!("Transfer delivered to the relay for {to_name}");
        self.log(
            "send",
            "granted",
            &title,
            trace.clone(),
            Some(format!(
                "# library: file_delivery::seal_letter, then relay push (POST /inbox) for {to_label}"
            )),
        );
        Ok(Outcome::done(true, message, trace))
    }

    fn denied_send(&mut self, title: &str, trace: Vec<TraceStep>) -> Outcome {
        self.log("send", "denied", title, trace.clone(), None);
        Outcome::done(false, format!("{title}: refused"), trace)
    }

    fn reach_reason(&self, from: &str, to: &str) -> &'static str {
        if is_ancestor_or_self(from, to) || is_ancestor_or_self(to, from) {
            "same lineage"
        } else if parent_node_label(from) == parent_node_label(to) {
            "sibling"
        } else {
            "reached through the established M.S ↔ M.A bridge"
        }
    }

    fn letter_for(&self, label: &str, relay_id: i64) -> Result<Option<Vec<u8>>> {
        let fingerprint = self.fingerprint_for(label)?;
        Ok(self
            .relay
            .pull(&fingerprint)?
            .into_iter()
            .find(|stored| stored.id == relay_id)
            .map(|stored| stored.bytes))
    }

    /// Open a delivery letter addressed to the active user. `accept` stores
    /// the file locked to the recipient's own slot and acknowledges it;
    /// otherwise the letter is refused with a signed rejection.
    pub fn receive(&mut self, relay_id: i64, accept: bool) -> Result<Outcome> {
        let actor = self.actor();
        let (actor_id, actor_label, actor_name) =
            (actor.id.clone(), actor.label.clone(), actor.name.clone());
        let verb = if accept { "Receive" } else { "Reject" };
        let title = format!("{verb} letter #{relay_id}");
        let mut trace = vec![TraceStep::pass(format!(
            "Recipient: {actor_name} / {actor_label}"
        ))];
        let Some(bytes) = self.letter_for(&actor_label, relay_id)? else {
            return Ok(Outcome::done(
                false,
                format!("Letter #{relay_id} is not in your relay inbox"),
                trace,
            ));
        };
        if envelope::kind(&bytes)? != envelope::KIND_FILE_DELIVERY {
            return Ok(Outcome::done(
                false,
                "That letter is not a file delivery",
                trace,
            ));
        }
        if self.received.contains_key(&relay_id) {
            return Ok(Outcome::done(
                false,
                "That letter was already answered",
                trace,
            ));
        }
        let (drive_name, secrets) = match self.open_slot(&actor_label) {
            Ok(opened) => opened,
            Err(_) => {
                trace.push(TraceStep::fail(format!(
                    "The letter is sealed to {actor_label}'s key on {}, which is not inserted",
                    self.drive_name_for(&actor_label)
                )));
                self.log("receive", "denied", &title, trace.clone(), None);
                return Ok(Outcome::done(
                    false,
                    "Insert your USB to open the letter",
                    trace,
                ));
            }
        };
        let letter =
            match file_delivery::open_letter(&self.conn, &secrets.encryption_secret, &bytes) {
                Ok(letter) if letter.recipient_label == actor_label => letter,
                Ok(_) | Err(_) => {
                    trace.push(TraceStep::fail(
                        "Letter failed to open or its signature did not verify",
                    ));
                    self.received.insert(
                        relay_id,
                        ReceivedItem {
                            status: InboxStatus::Invalid,
                            from: None,
                            file_name: None,
                            file_id: None,
                        },
                    );
                    self.log("receive", "denied", &title, trace.clone(), None);
                    return Ok(Outcome::done(false, "Letter rejected as invalid", trace));
                }
            };
        let sender = self
            .user_by_label(&letter.sender_label)
            .map(|user| user.id.clone())
            .unwrap_or_else(|| letter.sender_label.clone());
        trace.push(TraceStep::pass(format!(
            "Unsealed with {actor_label}'s slot on {drive_name}"
        )));
        trace.push(TraceStep::pass(format!(
            "Signature by {} verified against the registered key",
            self.describe_label(&letter.sender_label)
        )));

        let mut file_id = None;
        let mut opened = None;
        if accept {
            self.received_count += 1;
            let count = self.received_count;
            let path = Path::new(RECEIVED_ROOT)
                .join(&actor_id)
                .join(format!("{count}-{}.kqenc", letter.file_name));
            let leaf = encryption_key_id(&self.conn, &actor_label)?;
            let spec = NodeSpec::flat_split(
                format!("received-{count}"),
                1,
                vec![(actor_label.clone(), leaf)],
            );
            let quorum_id = quorum::lock_bytes_in(
                &mut self.disk,
                &mut self.conn,
                &letter.contents,
                &path,
                &letter.file_name,
                &spec,
            )?;
            let status = quorum::status(&self.conn, quorum_id)?;
            let key_id = status.tree.key_id;
            let lab_id = format!("received-{count}");
            self.files.push(LabFile {
                id: lab_id.clone(),
                folder: "received".into(),
                name: letter.file_name.clone(),
                lesson: format!(
                    "Delivered by {}; re-locked to your own slot on arrival.",
                    self.describe_label(&letter.sender_label)
                ),
                kind: FileKind::Received {
                    owner: actor_id.clone(),
                    from: sender.clone(),
                    file_id: quorum_id,
                    key_id,
                },
                size: letter.contents.len(),
                created_at: status.created_at,
                expires_at: None,
            });
            trace.push(TraceStep::pass(format!(
                "{} saved to /received, locked to {actor_label}'s key",
                letter.file_name
            )));
            opened = Some(OpenedFile {
                name: letter.file_name.clone(),
                text: String::from_utf8_lossy(&letter.contents).into_owned(),
            });
            file_id = Some(lab_id);
        }
        let ack = file_delivery::seal_ack(&letter, &secrets.signing_secret, accept)?;
        let ack_id = self.relay.push(&ack)?;
        trace.push(TraceStep::pass(format!(
            "Signed {} sealed back to {} and stored at the relay as #{ack_id}",
            if accept {
                "acknowledgement"
            } else {
                "rejection"
            },
            self.describe_label(&letter.sender_label)
        )));
        self.received.insert(
            relay_id,
            ReceivedItem {
                status: if accept {
                    InboxStatus::Received
                } else {
                    InboxStatus::Rejected
                },
                from: Some(sender),
                file_name: Some(letter.file_name.clone()),
                file_id,
            },
        );
        let message = if accept {
            format!("Transfer received: {}", letter.file_name)
        } else {
            format!("Transfer rejected: {}", letter.file_name)
        };
        self.log(
            "receive",
            if accept { "granted" } else { "info" },
            &message,
            trace.clone(),
            Some("# library: file_delivery::open_letter + seal_ack (cf. keyquorum relay pull --import)".into()),
        );
        Ok(Outcome {
            ok: true,
            message,
            trace,
            opened,
        })
    }

    /// Open acknowledgements sealed to the active user and settle the
    /// matching sent items. Needs the user's slot, like any letter.
    pub fn refresh_inbox(&mut self) -> Result<Outcome> {
        let actor_label = self.actor().label.clone();
        let actor_id = self.actor().id.clone();
        let fingerprint = self.fingerprint_for(&actor_label)?;
        let envelopes = self.relay.pull(&fingerprint)?;
        let mut trace = vec![TraceStep::info(format!(
            "Relay holds {} letter(s) for {actor_label}",
            envelopes.len()
        ))];
        let acks: Vec<_> = envelopes
            .into_iter()
            .filter(|stored| {
                !self.acks_opened.contains(&stored.id)
                    && envelope::kind(&stored.bytes).ok() == Some(envelope::KIND_FILE_DELIVERY_ACK)
            })
            .collect();
        if acks.is_empty() {
            return Ok(Outcome::done(true, "Inbox up to date", trace));
        }
        let secrets = match self.open_slot(&actor_label) {
            Ok((_, secrets)) => secrets,
            Err(_) => {
                trace.push(TraceStep::fail(format!(
                    "{} acknowledgement(s) waiting, sealed to your key on {} — insert it to verify them",
                    acks.len(),
                    self.drive_name_for(&actor_label)
                )));
                return Ok(Outcome::done(
                    false,
                    "Insert your USB to read acknowledgements",
                    trace,
                ));
            }
        };
        for stored in acks {
            self.acks_opened.insert(stored.id);
            match file_delivery::open_ack(&self.conn, &secrets.encryption_secret, &stored.bytes) {
                Ok(ack) => {
                    if let Some(item) = self
                        .sent
                        .iter_mut()
                        .find(|item| item.delivery_id == ack.delivery_id && item.from == actor_id)
                    {
                        item.status = if ack.accepted {
                            SentStatus::Acknowledged
                        } else {
                            SentStatus::Rejected
                        };
                        trace.push(TraceStep::pass(format!(
                            "{} {} {} (signature verified)",
                            ack.recipient_label,
                            if ack.accepted {
                                "acknowledged"
                            } else {
                                "rejected"
                            },
                            item.file_name
                        )));
                    }
                }
                Err(err) => trace.push(TraceStep::fail(format!(
                    "Acknowledgement #{} did not verify: {err}",
                    stored.id
                ))),
            }
        }
        let message = "Transfer acknowledgements verified".to_string();
        self.log("receive", "info", &message, trace.clone(), None);
        Ok(Outcome::done(true, message, trace))
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
        match self.file_index(key) {
            Some(index) => Ok(Some(self.file_view(&self.files[index])?)),
            None => Ok(None),
        }
    }

    fn file_view(&self, file: &LabFile) -> Result<FileView> {
        let (requirement, policy, quorum_file_id) = match file.quorum_ids() {
            Some((file_id, key_id)) => {
                let summary = key_tree::describe(&self.conn, key_id)?;
                let policy = device::custody_policy(&self.conn, key_id)?;
                (
                    Some(self.requirement(&summary.root)),
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
                    Some(file_id),
                )
            }
            None => (None, None, None),
        };
        let (protection, received_from) = match &file.kind {
            FileKind::Public { .. } => ("public", None),
            FileKind::Quorum { .. } => ("quorum", None),
            FileKind::Received { from, .. } => (
                "received",
                Some(
                    self.user_by_id(from)
                        .map(|user| format!("{} ({})", user.name, user.label))
                        .unwrap_or_else(|| from.clone()),
                ),
            ),
        };
        let expired = match &file.expires_at {
            Some(expires_at) => expiry_passed(&self.conn, expires_at)?,
            None => false,
        };
        Ok(FileView {
            id: file.id.clone(),
            folder: file.folder.clone(),
            name: file.name.clone(),
            lesson: file.lesson.clone(),
            protection: protection.into(),
            access: self.access_class(file)?.into(),
            size: file.size,
            created_at: file.created_at.clone(),
            expires_at: file.expires_at.clone(),
            expired,
            requirement,
            policy,
            quorum_file_id,
            received_from,
        })
    }

    fn requirement(&self, node: &TreeNodeSummary) -> RequirementNode {
        RequirementNode {
            label: node.label.clone(),
            threshold: node.threshold,
            // `None` when the registry label is the same string as the
            // tree-node label (e.g. the ghost, registered under her own
            // leaf label): the UI already shows `label`, so repeating it
            // as `holder` would just read "Priya Priya".
            holder: node.hardware_key_id.and_then(|_| {
                self.user_by_label(&node.label)
                    .map(|user| user.name.clone())
                    .or_else(|| {
                        node.hardware_key_label
                            .clone()
                            .filter(|label| label != &node.label)
                    })
            }),
            // A leaf a real person once held, kept in the tree by label but
            // excluded from every future reconstruction — see
            // `key_tree::evict_and_refresh`.
            ghost: !node.is_active && node.hardware_key_id.is_some(),
            children: node
                .children
                .iter()
                .map(|child| self.requirement(child))
                .collect(),
        }
    }

    fn user_view(&self, index: usize, visible: &HashSet<String>) -> UserView {
        let user = &self.users[index];
        UserView {
            id: user.id.clone(),
            name: user.name.clone(),
            label: user.label.clone(),
            role: user.role.clone(),
            drive_id: user.drive.clone(),
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
            .bay
            .drives
            .iter()
            .map(|drive| DriveView {
                id: drive.id.clone(),
                name: drive.name.clone(),
                mount: drive.mount.display().to_string(),
                connected: drive.connected,
                device_id: hex::encode(drive.device_id),
                slots: drive
                    .slots
                    .iter()
                    .map(|label| SlotView {
                        label: label.clone(),
                        holder: self
                            .user_by_label(label)
                            .map(|user| user.name.clone())
                            .unwrap_or_default(),
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

        let files = self
            .files
            .iter()
            .filter(|file| match &file.kind {
                FileKind::Received { owner, .. } => owner == &actor.id,
                _ => true,
            })
            .map(|file| self.file_view(file))
            .collect::<Result<Vec<_>>>()?;

        let fingerprint = self.fingerprint_for(&actor.label)?;
        let mut inbox = Vec::new();
        let mut pending_acks = 0;
        for stored in self.relay.pull(&fingerprint)? {
            match envelope::kind(&stored.bytes)? {
                envelope::KIND_FILE_DELIVERY => {
                    let item = self.received.get(&stored.id);
                    inbox.push(InboxItemView {
                        relay_id: stored.id,
                        status: match item.map(|item| item.status) {
                            None => "new",
                            Some(InboxStatus::Received) => "received",
                            Some(InboxStatus::Rejected) => "rejected",
                            Some(InboxStatus::Invalid) => "invalid",
                        }
                        .into(),
                        bytes: stored.bytes.len(),
                        from: item
                            .and_then(|item| item.from.as_deref())
                            .and_then(|id| self.user_by_id(id))
                            .map(|user| format!("{} ({})", user.name, user.label)),
                        file_name: item.and_then(|item| item.file_name.clone()),
                        file_id: item.and_then(|item| item.file_id.clone()),
                    });
                }
                envelope::KIND_FILE_DELIVERY_ACK if !self.acks_opened.contains(&stored.id) => {
                    pending_acks += 1;
                }
                _ => {}
            }
        }

        let sent = self
            .sent
            .iter()
            .filter(|item| item.from == actor.id)
            .map(|item| {
                let to = self.user_by_id(&item.to);
                SentItemView {
                    delivery_id: hex::encode(item.delivery_id),
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
            .collect();

        let approvals = self
            .approvals
            .iter()
            .filter(|approval| {
                approval.approver == actor.label || approval.requested_by == actor.id
            })
            .map(|approval| ApprovalView {
                id: approval.id,
                file_name: approval.file_name.clone(),
                leaf: approval.leaf.clone(),
                approver: self.describe_label(&approval.approver),
                requested_by: self
                    .user_by_id(&approval.requested_by)
                    .map(|user| format!("{} ({})", user.name, user.label))
                    .unwrap_or_default(),
                devices: approval.device_ids.iter().map(short_hex).collect(),
                status: match approval.status {
                    ApprovalStatus::Pending => "pending",
                    ApprovalStatus::Approved => "approved",
                    ApprovalStatus::Declined => "declined",
                }
                .into(),
                actionable: approval.status == ApprovalStatus::Pending
                    && approval.approver == actor.label,
            })
            .collect();

        Ok(Snapshot {
            active_user: self.user_view(self.active, &visible),
            users,
            drives,
            tree,
            files,
            inbox,
            pending_acks,
            sent,
            approvals,
            activity: self.activity.iter().rev().cloned().collect(),
            last_access: self.last_access.clone(),
        })
    }

    fn tree_view(&self, visible: &HashSet<String>) -> Result<TreeView> {
        let tree = KeyQuorumTree::load(&self.conn, self.org_key_id)?;
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
                    slot_drive: self.bay.holding(&node.id).map(|drive| drive.name.clone()),
                    slot_connected: self.slot_connected(&node.id),
                    required: required.contains(node.id.as_str()),
                    satisfied: satisfied.contains(node.id.as_str()),
                }
            })
            .collect();
        let bridges = key_tree::list_bridges(&self.conn, self.org_key_id)?
            .established
            .into_iter()
            .map(|edge| (edge.from, edge.to))
            .collect();
        Ok(TreeView { nodes, bridges })
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
}

fn seed_org_tree(conn: &mut Connection) -> Result<i64> {
    let leaf = |label: &str| -> Result<NodeSpec> {
        Ok(NodeSpec::Leaf {
            label: label.into(),
            hardware_key_id: encryption_key_id(conn, label)?,
            allowed_bridges: vec![],
        })
    };
    let spec = NodeSpec::Split {
        label: "M".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Split {
                label: "M.S".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![leaf("M.S.1")?, leaf("M.S.2")?],
            },
            NodeSpec::Split {
                label: "M.A".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![leaf("M.A.1")?, leaf("M.A.2")?],
            },
        ],
    };
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut secret[..]);
    let key_id = key_tree::split(conn, seed::ORG_TREE, &secret[..], &spec)?;
    key_tree::bind_pair(conn, key_id, seed::ORG_BRIDGE.0, seed::ORG_BRIDGE.1)?;
    Ok(key_id)
}

fn encryption_key_id(conn: &Connection, label: &str) -> Result<i64> {
    keys::active_keys_for(conn, label, KeyType::Encryption)?
        .into_iter()
        .next()
        .map(|key| key.id)
        .ok_or(Error::NodeNotFound)
}

/// Resolve a seed [`Expiry`] to a concrete `YYYY-MM-DD HH:MM:SS` UTC
/// string via SQLite's own clock, so "expires shortly after load" really
/// does — the same clock every `datetime('now')` comparison in `quorum.rs`
/// and this module uses.
fn resolve_expiry(conn: &Connection, expiry: &Expiry) -> Result<Option<String>> {
    match expiry {
        Expiry::Never => Ok(None),
        Expiry::Offset(modifier) => {
            let resolved: String = conn.query_row(
                "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', ?1)",
                rusqlite::params![modifier],
                |row| row.get(0),
            )?;
            Ok(Some(resolved))
        }
    }
}

/// Whether a resolved expiry has passed, using the same clock. Never
/// destructive on its own — see `quorum::purge_if_expired_in` for that.
fn expiry_passed(conn: &Connection, expires_at: &str) -> Result<bool> {
    conn.query_row(
        "SELECT datetime(?1) <= datetime('now')",
        rusqlite::params![expires_at],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// Seed a ghost: `ghost_label`'s leaf was included in the split (see the
/// `QuorumWithGhost` seeding above) and is evicted here, before the lab
/// hands control to a visitor, via the crate's own
/// `key_tree::evict_and_refresh` — the exact function a real "this person
/// left" workflow calls. `survivors` must already hold raw shares
/// obtainable from `slot_secrets`.
fn evict_ghost(
    conn: &mut Connection,
    key_id: i64,
    ghost_label: &str,
    survivors: &[&str],
    slot_secrets: &HashMap<String, Zeroizing<[u8; 32]>>,
) -> Result<()> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    let evicted_node_id = tree.nodes[tree.index_by_label(ghost_label)?].db_id;
    let mut survivor_shares = HashMap::new();
    for label in survivors {
        let node_id = tree.nodes[tree.index_by_label(label)?].db_id;
        let secret = slot_secrets.get(*label).ok_or(Error::NodeNotFound)?;
        let raw = key_tree::unwrap_leaf_share(conn, node_id, secret.as_slice())?;
        survivor_shares.insert(node_id, raw);
    }
    key_tree::evict_and_refresh(conn, key_id, evicted_node_id, &survivor_shares)?;
    Ok(())
}

fn threshold_line(conn: &Connection, key_id: i64) -> Result<String> {
    let summary = key_tree::describe(conn, key_id)?;
    Ok(match summary.root.threshold {
        Some(threshold) => format!(
            "needs {threshold} of {}",
            summary
                .root
                .children
                .iter()
                .map(|child| child.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        None => "needs the single leaf".into(),
    })
}

fn policy_line(policy: &CustodyPolicy) -> String {
    format!(
        "Policy: {} custody · minimum {} physical device(s) · parent approval {}",
        match policy.mode {
            CustodyMode::Hardware => "hardware",
            CustodyMode::Logical => "logical",
        },
        policy.minimum_physical_devices,
        match policy.unlock_approval {
            UnlockApproval::None => "not required",
            UnlockApproval::Parent => "required",
        }
    )
}

fn short_hex(bytes: &[u8; 16]) -> String {
    hex::encode(&bytes[..4])
}
