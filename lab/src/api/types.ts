// Mirrors src/lab/view.rs in the KeyQuorum crate. The Rust side is the
// source of truth; these types only describe the JSON it returns.

export type StepStatus = "pass" | "fail" | "info";

export interface TraceStep {
  status: StepStatus;
  text: string;
}

export interface UserView {
  id: string;
  name: string;
  label: string;
  role: string;
  driveId: string;
  active: boolean;
  visible: boolean;
}

export interface SlotView {
  label: string;
  holder: string;
}

export interface DriveView {
  id: string;
  name: string;
  mount: string;
  connected: boolean;
  deviceId: string;
  slots: SlotView[];
  files: string[];
}

export interface TreeNodeView {
  label: string;
  parent: string | null;
  kind: "split" | "leaf";
  threshold: number | null;
  person: string | null;
  role: string | null;
  activeUser: boolean;
  visible: boolean;
  slotDrive: string | null;
  slotConnected: boolean;
  required: boolean;
  satisfied: boolean;
}

export interface RequirementNode {
  label: string;
  threshold: number | null;
  holder: string | null;
  /** A leaf a real person once held, evicted (key_tree::evict_and_refresh) and kept only by label. */
  ghost: boolean;
  children: RequirementNode[];
}

export interface PolicyView {
  custody: "hardware" | "logical";
  minimumDevices: number;
  approval: "none" | "parent";
}

export type FileAccess = "public" | "holder" | "oversight" | "lineage" | "none";

export interface FileView {
  id: string;
  folder: string;
  name: string;
  lesson: string;
  protection: "public" | "quorum" | "received";
  access: FileAccess;
  size: number;
  /** Empty for a public file — no `files` row backs it. */
  createdAt: string;
  /** UTC cutoff (`YYYY-MM-DD HH:MM:SS`). `null` means the file never expires. */
  expiresAt: string | null;
  /** Whether `expiresAt` has passed. Computed live on every snapshot. */
  expired: boolean;
  requirement: RequirementNode | null;
  policy: PolicyView | null;
  quorumFileId: number | null;
  receivedFrom: string | null;
}

export interface InboxItemView {
  relayId: number;
  status: "new" | "received" | "rejected" | "invalid";
  bytes: number;
  from: string | null;
  fileName: string | null;
  fileId: string | null;
}

export interface SentItemView {
  deliveryId: string;
  relayId: number;
  to: string;
  toLabel: string;
  fileName: string;
  status: "delivered" | "acknowledged" | "rejected";
}

export interface ActivityView {
  seq: number;
  actor: string;
  kind: string;
  outcome: "granted" | "denied" | "info";
  title: string;
  trace: TraceStep[];
  command: string | null;
  /**
   * The fields below are present only on entries read back from a tracked
   * file's history (`kind === "history"`); every other entry omits them.
   */
  fileId?: string;
  fileName?: string;
  historyEventType?: string;
  historyCategory?: HistoryCategory;
  /** The event's own hash: the file's history root as of this event. */
  historyRoot?: string;
  revisionId?: string;
  generatedLabel?: string;
  userLabel?: string;
  parentRevisionIds?: string[];
  /** The revision's trust under the file's policy: trusted, pending or denied. */
  finalizationState?: "trusted" | "pending" | "denied";
}

export type HistoryCategory = "file" | "revision" | "security" | "sharing" | "conflict";

export interface AccessView {
  fileId: string;
  fileName: string;
  granted: boolean;
  required: string[];
  satisfied: string[];
}

export interface PasswordFileView {
  id: number;
  name: string;
  /** The lab-user label whose own store holds this file; only they can unlock it. */
  owner: string;
  createdAt: string;
  expiresAt: string | null;
  pinProtected: boolean;
}

export interface ExportedBundleView {
  id: number;
  fileName: string;
  /** The lab-user label whose own store the source file's row lives in. */
  owner: string;
  recipient: string;
  recipientName: string;
  size: number;
  createdAt: string;
}

export interface FileShareView {
  id: number;
  fileName: string;
  /** The lab-user label who created this share; only they may revoke it. */
  owner: string;
  pinProtected: boolean;
  expiresAt: string;
  revoked: boolean;
}

export interface SignatureView {
  id: number;
  fileName: string;
  /** Tree label of the signer (`M.S` or `M.A`). */
  signer: string;
  signerName: string;
  bridgeUid: string;
  size: number;
}

export interface RelayStatusView {
  url: string;
  packageLetters: number;
  deviceLetters: number;
  publishedTrees: number;
  registeredDevices: number;
  apiKeys: number;
}

export interface RestructureProposalView {
  treeLabel: string;
  /** Label that proposed the restructure. */
  authorizerLabel: string;
  /** Parent label that must countersign before this takes effect. */
  countersignerLabel: string;
  generation: number;
}

export interface Snapshot {
  activeUser: UserView;
  users: UserView[];
  drives: DriveView[];
  // keyId: the org tree's `<KEY_ID>` for `keyquorum bridge`.
  // bridges: established undirected links (drive visibility).
  // allowed: directed whitelist entries, node → peer.
  tree: { keyId: number; nodes: TreeNodeView[]; bridges: [string, string][]; allowed: [string, string][] };
  files: FileView[];
  inbox: InboxItemView[];
  pendingAcks: number;
  sent: SentItemView[];
  activity: ActivityView[];
  lastAccess: AccessView | null;
  // The terminal's working directory in the lab machine.
  cwd: string;
  // The org store's path, for `keyquorum --db` lines panels build.
  orgDb: string;
  passwordFiles: PasswordFileView[];
  relayStatus: RelayStatusView;
  exports: ExportedBundleView[];
  fileShares: FileShareView[];
  signatures: SignatureView[];
  pendingRestructures: RestructureProposalView[];
  /** Tracked files the activity log follows, judged by the active person's store. */
  trackedFiles: TrackedFileView[];
  /** Tracked-file letters handed between people. */
  trackedLetters: TrackedLetterView[];
}

export interface TrackedRevisionView {
  id: string;
  generatedLabel: string;
  userLabel: string | null;
  author: string;
  createdAt: string;
  parents: string[];
  head: boolean;
  trust: "trusted" | "pending" | "denied" | "unknown";
  reason: string | null;
  /** The revision's text, when it is UTF-8 and small enough to edit here. */
  text: string | null;
}

export interface TrackedFileView {
  path: string;
  name: string;
  fileId: string;
  scope: string;
  /** The lab user whose home holds the container; null for shared ones. */
  owner: string | null;
  autoMerge: boolean;
  forked: boolean;
  historyLen: number;
  historyRoot: string;
  /** Oldest first. */
  revisions: TrackedRevisionView[];
  /** The revision `file share` would send from the sole head, if any. */
  shareable: string | null;
  /** The scheduled expiry (`YYYY-MM-DDTHH:MM:SSZ`), if one was set. */
  expiresAt: string | null;
  /** Whether every revision's content was destroyed at expiry. */
  destroyed: boolean;
  /** History snapshots (`KQHS`) exported from this file in the lab. */
  snapshots: string[];
  /** Quorum or password files whose gate records into this history. */
  links: { gate: "quorum" | "password"; id: number }[];
}

export interface TrackedLetterView {
  id: number;
  fileName: string;
  from: string;
  fromName: string;
  fromLabel: string;
  to: string;
  toName: string;
  toLabel: string;
  status: "waiting" | "accepted" | "rejected";
  ackRecorded: boolean;
}

export interface OpenedFile {
  name: string;
  text: string;
}

export interface ActionResult {
  ok: boolean;
  message: string;
  trace: TraceStep[];
  opened: OpenedFile | null;
  output: string[];
  snapshot: Snapshot;
}
