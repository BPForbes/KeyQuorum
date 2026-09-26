//! Serialized views handed across the WASM boundary. One action returns
//! one [`ActionResult`] carrying a full [`Snapshot`], so the UI renders
//! from a single structured read instead of many small calls.

use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Pass,
    Fail,
    Info,
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceStep {
    pub status: StepStatus,
    pub text: String,
}

impl TraceStep {
    pub fn pass(text: impl Into<String>) -> Self {
        Self {
            status: StepStatus::Pass,
            text: text.into(),
        }
    }

    pub fn fail(text: impl Into<String>) -> Self {
        Self {
            status: StepStatus::Fail,
            text: text.into(),
        }
    }

    pub fn info(text: impl Into<String>) -> Self {
        Self {
            status: StepStatus::Info,
            text: text.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    pub id: String,
    pub name: String,
    pub label: String,
    pub role: String,
    pub drive_id: String,
    pub active: bool,
    /// In the active user's visible slice of the org tree.
    pub visible: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotView {
    pub label: String,
    pub holder: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveView {
    pub id: String,
    pub name: String,
    pub mount: String,
    pub connected: bool,
    pub device_id: String,
    pub slots: Vec<SlotView>,
    /// Files on the container while inserted; empty when ejected.
    pub files: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeNodeView {
    pub label: String,
    pub parent: Option<String>,
    /// `split` nodes are topology: they hold no share of the org key.
    pub kind: String,
    pub threshold: Option<usize>,
    pub person: Option<String>,
    pub role: Option<String>,
    pub active_user: bool,
    pub visible: bool,
    pub slot_drive: Option<String>,
    pub slot_connected: bool,
    pub required: bool,
    pub satisfied: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeView {
    pub nodes: Vec<TreeNodeView>,
    pub bridges: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequirementNode {
    pub label: String,
    pub threshold: Option<i64>,
    pub holder: Option<String>,
    /// A leaf a real person once held, now excluded from every future
    /// reconstruction (`transfer::Possession::Ghost`, recorded after a MOVE
    /// transfer takes her secret away) but kept in the tree by label — the
    /// crate's real "this person left" state.
    pub ghost: bool,
    pub children: Vec<RequirementNode>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyView {
    pub custody: String,
    pub minimum_devices: u8,
    pub approval: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileView {
    pub id: String,
    pub folder: String,
    pub name: String,
    pub lesson: String,
    /// `public`, `quorum`, or `received`.
    pub protection: String,
    /// `public`, `holder`, `oversight`, `lineage`, or `none` for the active user.
    pub access: String,
    pub size: usize,
    /// Empty for a public file (no `files` row backs it).
    pub created_at: String,
    /// UTC cutoff. `None` means the file never expires.
    pub expires_at: Option<String>,
    /// Whether `expires_at` has passed. Computed live, not cached, so it
    /// stays correct for a file whose row has already been purged.
    pub expired: bool,
    pub requirement: Option<RequirementNode>,
    pub policy: Option<PolicyView>,
    pub quorum_file_id: Option<i64>,
    pub received_from: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxItemView {
    pub relay_id: i64,
    /// `new`, `received`, `rejected`, or `invalid`.
    pub status: String,
    pub bytes: usize,
    pub from: Option<String>,
    pub file_name: Option<String>,
    pub file_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentItemView {
    pub delivery_id: String,
    pub relay_id: i64,
    pub to: String,
    pub to_label: String,
    pub file_name: String,
    /// `delivered`, `acknowledged`, or `rejected`.
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalView {
    pub id: u64,
    pub file_name: String,
    pub leaf: String,
    pub approver: String,
    pub requested_by: String,
    pub devices: Vec<String>,
    /// `pending`, `approved`, or `declined`.
    pub status: String,
    /// The active user is the one who can answer it.
    pub actionable: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityView {
    pub seq: u64,
    pub actor: String,
    pub kind: String,
    /// `granted`, `denied`, or `info`.
    pub outcome: String,
    pub title: String,
    pub trace: Vec<TraceStep>,
    pub command: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessView {
    pub file_id: String,
    pub file_name: String,
    pub granted: bool,
    pub required: Vec<String>,
    pub satisfied: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub active_user: UserView,
    pub users: Vec<UserView>,
    pub drives: Vec<DriveView>,
    pub tree: TreeView,
    pub files: Vec<FileView>,
    pub inbox: Vec<InboxItemView>,
    /// Acknowledgements sealed to the active user that are still unopened.
    pub pending_acks: usize,
    pub sent: Vec<SentItemView>,
    pub approvals: Vec<ApprovalView>,
    pub activity: Vec<ActivityView>,
    pub last_access: Option<AccessView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedFile {
    pub name: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    pub ok: bool,
    pub message: String,
    pub trace: Vec<TraceStep>,
    pub opened: Option<OpenedFile>,
    /// Terminal output lines, when the action came from the terminal.
    pub output: Vec<String>,
    pub snapshot: Snapshot,
}
