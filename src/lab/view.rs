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
    /// The org tree's key id: the `<KEY_ID>` argument of `keyquorum bridge`.
    pub key_id: i64,
    pub nodes: Vec<TreeNodeView>,
    /// Established undirected links (`key_node_links`), which drive visibility.
    pub bridges: Vec<(String, String)>,
    /// Directed whitelist entries (`key_node_bridges`): node may link to peer.
    pub allowed: Vec<(String, String)>,
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
pub struct ActivityView {
    pub seq: u64,
    pub actor: String,
    pub kind: String,
    /// `granted`, `denied`, or `info`.
    pub outcome: String,
    pub title: String,
    pub trace: Vec<TraceStep>,
    pub command: Option<String>,
    /// Set only on entries drawn from a tracked file's history
    /// (`kind == "history"`); every other entry serializes exactly as before.
    #[serde(flatten)]
    pub history: Option<HistoryFields>,
}

/// What a tracked-file history event adds to an activity entry. Read from
/// the `.kqtf` container, never computed by the lab.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryFields {
    pub file_id: String,
    pub file_name: String,
    pub history_event_type: String,
    /// From `HistoryEventType::category`: `file`, `revision`, `security`,
    /// `sharing` or `conflict`.
    pub history_category: String,
    /// The event's own hash: the history root as of this event.
    pub history_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_label: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parent_revision_ids: Vec<String>,
    /// The revision's trust under the file's policy when the entry was
    /// recorded: `trusted`, `pending` or `denied`. The tracked-file
    /// snapshot carries the current value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalization_state: Option<String>,
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
pub struct PasswordFileView {
    pub id: i64,
    pub name: String,
    /// The lab-user label whose own store holds this file's row; only that
    /// person can unlock it.
    pub owner: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub pin_protected: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedBundleView {
    pub id: i64,
    pub file_name: String,
    /// The lab-user label whose own store the source file's row lives in.
    pub owner: String,
    pub recipient: String,
    pub recipient_name: String,
    pub size: usize,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileShareView {
    pub id: i64,
    pub file_name: String,
    /// The lab-user label whose own store created this share; only they
    /// may revoke it. Redemption itself is not identity-scoped — the
    /// bearer token is what authorizes it, same as a real share link.
    pub owner: String,
    pub pin_protected: bool,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureView {
    pub id: i64,
    pub file_name: String,
    /// Tree label of the signer (`M.S` or `M.A`).
    pub signer: String,
    pub signer_name: String,
    pub bridge_uid: String,
    pub size: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatusView {
    pub url: String,
    pub package_letters: i64,
    pub device_letters: i64,
    pub published_trees: i64,
    pub registered_devices: i64,
    pub api_keys: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestructureProposalView {
    pub tree_label: String,
    /// Label that proposed the restructure (`seed::RESTRUCTURE_AUTHORITY`
    /// in this lab).
    pub authorizer_label: String,
    /// Parent label that must countersign before this takes effect.
    pub countersigner_label: String,
    pub generation: i64,
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
    pub activity: Vec<ActivityView>,
    pub last_access: Option<AccessView>,
    /// The terminal's working directory in the lab VM.
    pub cwd: String,
    /// The shared org store's path, for `keyquorum --db` lines the panels build.
    pub org_db: String,
    /// Password-locked files created from the Security panel, across every
    /// lab user (each is only unlockable by its own owner).
    pub password_files: Vec<PasswordFileView>,
    pub relay_status: RelayStatusView,
    /// Portable `KQXB` bundles created from the Security panel, across
    /// every lab user (each only viewable by its own exporter).
    pub exports: Vec<ExportedBundleView>,
    /// Share links created from the Security panel, across every lab
    /// user. Listed for everyone since redemption is bearer-token
    /// authorized, not identity-scoped.
    pub file_shares: Vec<FileShareView>,
    /// Signatures produced from the FileExplorer's Sign action, across
    /// every lab user; either private-bridge member can verify one.
    pub signatures: Vec<SignatureView>,
    /// Tree restructure proposals still waiting on their countersigner.
    pub pending_restructures: Vec<RestructureProposalView>,
    /// Tracked files the activity log follows, judged by the active
    /// person's store.
    pub tracked_files: Vec<TrackedFileView>,
    /// Tracked-file letters handed between people.
    pub tracked_letters: Vec<TrackedLetterView>,
    /// Requests for a file or a change, and their answers.
    pub tracked_requests: Vec<TrackedRequestView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedFileView {
    pub path: String,
    pub name: String,
    pub file_id: String,
    pub scope: String,
    /// The lab user whose home holds the container; `None` for shared ones.
    pub owner: Option<String>,
    pub auto_merge: bool,
    pub forked: bool,
    pub history_len: usize,
    pub history_root: String,
    /// Oldest first.
    pub revisions: Vec<TrackedRevisionView>,
    /// The revision `file share` would send from the sole head, if any.
    pub shareable: Option<String>,
    /// The sole head, or `None` when the history has forked.
    pub current_revision: Option<String>,
    /// The latest revision this store trusts, which need not be the current one.
    pub trusted_revision: Option<String>,
    /// The latest finalized revision behind the sole head, if any; none on
    /// a fork, where no branch is picked.
    pub finalized_revision: Option<String>,
    /// The scheduled expiry (`YYYY-MM-DDTHH:MM:SSZ`), if one was set.
    pub expires_at: Option<String>,
    /// Whether every revision's content was destroyed at expiry.
    pub destroyed: bool,
    /// History snapshots (`KQHS`) exported from this file in the lab.
    pub snapshots: Vec<String>,
    /// Quorum or password files whose gate records into this history.
    pub links: Vec<TrackedLinkView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedLinkView {
    /// `quorum` or `password`.
    pub gate: String,
    pub id: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedRevisionView {
    pub id: String,
    pub generated_label: String,
    pub user_label: Option<String>,
    pub author: String,
    pub created_at: String,
    pub parents: Vec<String>,
    pub head: bool,
    /// `trusted`, `pending` or `denied`, from `file_history`.
    pub trust: String,
    pub reason: Option<String>,
    /// Whether the scope owner or an ancestor finalized it, judged by this
    /// store's keys.
    pub finalized: bool,
    /// The revision's text, when it is UTF-8 and small enough to edit here.
    pub text: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedLetterView {
    pub id: i64,
    pub file_name: String,
    pub from: String,
    pub from_name: String,
    pub from_label: String,
    pub to: String,
    pub to_name: String,
    pub to_label: String,
    /// `waiting`, `accepted` or `rejected`.
    pub status: String,
    pub ack_recorded: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedRequestView {
    pub id: i64,
    pub file_name: String,
    /// `file` or `change`.
    pub kind: String,
    pub message: String,
    pub from: String,
    pub from_name: String,
    pub from_label: String,
    pub to: String,
    pub to_name: String,
    pub to_label: String,
    /// `waiting`, `accepted` or `declined`.
    pub status: String,
    pub answer_recorded: bool,
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
