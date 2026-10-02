// Content for the guided tutorials (the "Tutorials" button in the lab
// header). Each module is a short, self-contained walkthrough of one part
// of the lab; a visitor picks whichever module covers what they want to
// learn and is never required to work through the others. A step with
// `isDone` is "gated": the tooltip stays put, describing a real action to
// take, until that action actually happens (checked against the live
// snapshot / activity log) — it does not just advance on a timer or a
// "Next" click standing in for the real thing.
import type { ReactNode } from "react";
import type { Act, Tab } from "../App";
import type { ActivityView, RequirementNode, Snapshot } from "../api/types";

/** Free-form data one step's `remember` captures for a later step's `isDone` to read. */
export type TutorialMemory = Record<string, unknown>;

export interface TutorialStep {
  title: string;
  body: ReactNode;
  /** Switch to this tab first (matters on phone width; desktop shows every panel at once). */
  tab?: Tab;
  /**
   * CSS selectors to spotlight, tried in order; the first one present in the
   * DOM wins. Letting a step offer more than one candidate is what makes a
   * single step track a target across a page navigation the visitor drives
   * themselves — e.g. a folder tile until they open it, then the file row
   * that appears in its place.
   */
  target: (snapshot: Snapshot) => (string | null)[];
  /**
   * Called once, when the step starts (including re-entering it via Back),
   * to put the lab into a state where the step's own action is actually
   * possible and meaningful -- e.g. if a "switch to David" step began while
   * David was already active, undo that first. Runs a real action through
   * `act` (never fakes state) and returns whatever snapshot that leaves;
   * return the input unchanged if nothing needed fixing. The gate's
   * activity cursor is taken *after* this runs, so the corrective action
   * itself can never be mistaken for the visitor's own.
   */
  ensure?: (snapshot: Snapshot, act: Act) => Snapshot;
  /**
   * Undefined means "read this, then click Next." Defined means "do this to
   * advance." Tutorial only ever calls this once a *new* activity-log entry
   * has appeared since the step started, so a condition already true when
   * the step began (a leftover action from before this run, or from
   * `ensure` above) cannot satisfy it by itself. If `requiredKind` is also
   * set, that new entry must be of that activity kind too -- otherwise an
   * unrelated action (e.g. switching identity while a drive-connected
   * check happens to already be true) could satisfy a state check it had
   * nothing to do with.
   */
  isDone?: (snapshot: Snapshot, latest: ActivityView | undefined, memory: TutorialMemory) => boolean;
  requiredKind?: ActivityView["kind"];
  /** Called once, right when isDone flips true, to capture data a later step in the same module can read via `memory`. */
  remember?: (snapshot: Snapshot, latest: ActivityView | undefined) => TutorialMemory;
}

export interface TutorialModule {
  id: string;
  category: "identities" | "files" | "mailbox" | "history";
  title: string;
  summary: string;
  steps: TutorialStep[];
}

const fileRow = (snapshot: Snapshot, name: string): string | null => {
  const file = snapshot.files.find((candidate) => candidate.name === name);
  return file ? `[data-testid="file-row-${file.id}"]` : null;
};

const wasOpened = (latest: ActivityView | undefined, name: string) =>
  latest?.kind === "access" && latest.title.includes(name);

// LabState::send logs its activity title as "Send <file> to <name>" only
// when the delivery actually succeeds (a denied send logs the same kind
// with outcome "denied"); LabState::receive logs "receive"/"granted" only
// for an actually-opened letter — a disconnected drive logs "denied" and
// the inbox-refresh button logs "receive"/"info". Checking kind alone
// would let a failed attempt, or an unrelated refresh, complete the step.
const wasSentTo = (latest: ActivityView | undefined, recipientName: string) =>
  latest?.kind === "send" && latest.outcome === "granted" && latest.title.includes(`to ${recipientName}`);

const wasReceived = (latest: ActivityView | undefined) => latest?.kind === "receive" && latest.outcome === "granted";

// LabState::move_slot logs "Moved <label> to <drive>" only on success (a
// denied move logs "Could not move <label>: ..."), so checking the title's
// prefix ties the gate to the one slot the step names rather than any move.
const wasMoved = (latest: ActivityView | undefined, label: string) =>
  latest?.kind === "move" && latest.outcome !== "denied" && latest.title.startsWith(`Moved ${label} `);

// The Bridges panel's buttons and the Terminal tab both end up calling
// `client.runCommand`, which always logs the same generic "terminal" kind
// (see KeyQuorumLab::run_command) -- the only thing that tells one command
// apart from another is the real line carried in `command`. Matching a
// substring of it (rather than the whole line) is what lets a step accept
// either of two equivalent phrasings (the canned button's exact args, or
// something a visitor typed by hand) while still refusing an unrelated
// command, e.g. `ls` or `su david`, that happens to also log "terminal".
const ranCommand = (latest: ActivityView | undefined, ...substrings: string[]) => {
  const command = latest?.kind === "terminal" && latest.outcome === "granted" ? latest.command : undefined;
  return typeof command === "string" && substrings.some((substring) => command.includes(substring));
};

// FileExplorer's Properties button logs "Viewed properties for <name>", the
// only place a file's name is attached to that activity -- reading it back
// is how a later gated step (e.g. "bring the right drives online") learns
// which file the visitor is working through, rather than guessing at one.
const propertiesFileName = (latest: ActivityView | undefined): string | undefined =>
  latest?.kind === "properties" ? latest.title.match(/^Viewed properties for (.+)$/)?.[1] : undefined;

// LabState::lock_password_file logs "Lock <name> with a password", the only
// place that name is attached to the activity -- reading it back is how a
// later step in the same module ties its own gate to this same file
// instead of accepting a password unlock, export, or share of any file.
const passwordLockFileName = (latest: ActivityView | undefined): string | undefined =>
  latest?.kind === "password-lock" ? latest.title.match(/^Lock (.+) with a password$/)?.[1] : undefined;

const requirementLeaves = (node: RequirementNode | undefined | null): RequirementNode[] =>
  !node ? [] : node.children.length === 0 ? [node] : node.children.flatMap(requirementLeaves);

// How many distinct physical devices, among the ones this file's own
// requirement tree actually names, are connected right now. Two leaves
// sharing one relocated container still count once -- matching the same
// "logical shares, one physical device" rule the lab's own copy explains.
const connectedRequiredDevices = (snapshot: Snapshot, fileName: string): number => {
  const file = snapshot.files.find((candidate) => candidate.name === fileName);
  const leafLabels = new Set(requirementLeaves(file?.requirement).map((leaf) => leaf.label));
  const drives = new Set(
    snapshot.tree.nodes
      .filter((node) => leafLabels.has(node.label) && node.slotConnected && node.slotDrive)
      .map((node) => node.slotDrive),
  );
  return drives.size;
};

// Precondition helpers for `TutorialStep.ensure`. Each takes a real action
// through `act` -- never fakes the resulting snapshot -- so a step that
// asks the visitor to switch to, or connect, something specific can't
// start already satisfied (nothing to demonstrate) or blocked (e.g.
// SendDialog excludes the active user from its own recipient list, so a
// "send to David" step is impossible while David is already active).
const ensureActiveUserIsNot =
  (blockedId: string, fallbackId: string) =>
  (snapshot: Snapshot, act: Act): Snapshot => {
    if (snapshot.activeUser.id !== blockedId) return snapshot;
    const result = act((client) => client.switchUser(fallbackId));
    return result?.snapshot ?? snapshot;
  };

const ensureActiveUser =
  (userId: string) =>
  (snapshot: Snapshot, act: Act): Snapshot => {
    if (snapshot.activeUser.id === userId) return snapshot;
    const result = act((client) => client.switchUser(userId));
    return result?.snapshot ?? snapshot;
  };

const ensureDriveDisconnected =
  (driveId: string) =>
  (snapshot: Snapshot, act: Act): Snapshot => {
    const drive = snapshot.drives.find((candidate) => candidate.id === driveId);
    if (!drive?.connected) return snapshot;
    const result = act((client) => client.ejectDrive(driveId));
    return result?.snapshot ?? snapshot;
  };

const ensureDrivesConnected =
  (...driveIds: string[]) =>
  (snapshot: Snapshot, act: Act): Snapshot => {
    let current = snapshot;
    for (const driveId of driveIds) {
      if (current.drives.find((drive) => drive.id === driveId)?.connected) continue;
      current = act((client) => client.insertDrive(driveId))?.snapshot ?? current;
    }
    return current;
  };

const composeEnsures =
  (...ensures: NonNullable<TutorialStep["ensure"]>[]) =>
  (snapshot: Snapshot, act: Act): Snapshot =>
    ensures.reduce((current, ensure) => ensure(current, act), snapshot);

export const TUTORIALS: TutorialModule[] = [
  {
    id: "identities-and-drives",
    category: "identities",
    title: "Identities & drives",
    summary: "Who you're acting as, and how a mock USB drive stands in for a physical device.",
    steps: [
      {
        title: "This is you",
        body: (
          <p>
            The bar at the top shows who you are acting as, and which USB drive their personal key slot lives on.
            Click another name's chip any time to switch — like sitting down at a different desk.
          </p>
        ),
        target: () => [".active-user"],
      },
      {
        title: "Try it: insert David's USB",
        body: (
          <p>
            A drive's slots only work while it's connected. Switch to the <strong>USB devices</strong> tab and press{" "}
            <strong>Insert David&rsquo;s USB</strong>.
          </p>
        ),
        tab: "usb",
        target: () => ['[data-testid="drive-david"]'],
        ensure: ensureDriveDisconnected("david"),
        requiredKind: "usb",
        isDone: (snapshot) => snapshot.drives.find((drive) => drive.id === "david")?.connected === true,
      },
      {
        title: "The organization key tree",
        body: (
          <p>
            This is the split-key hierarchy: dotted labels like <code>M</code>, <code>M.S</code>, <code>M.S.1</code>{" "}
            show who descends from whom. You only ever see your own slice of it — your lineage, descendants,
            siblings, and established bridge peers.
          </p>
        ),
        tab: "organization",
        target: () => ['[data-panel="organization"]'],
      },
      {
        title: "Try it: switch to David",
        body: (
          <p>
            Click <strong>David</strong>&rsquo;s chip in the Active user bar at the top of the page to act as him
            instead of Alice.
          </p>
        ),
        target: () => ['[aria-label="Switch user"]'],
        ensure: ensureActiveUserIsNot("david", "alice"),
        requiredKind: "user",
        isDone: (snapshot) => snapshot.activeUser.id === "david",
      },
      {
        title: "Try it: eject David's USB",
        body: (
          <p>
            Return to <strong>USB devices</strong> and eject David&rsquo;s USB. Its slots immediately stop participating
            in unlocks and signatures.
          </p>
        ),
        tab: "usb",
        target: () => ['[data-testid="drive-david"]'],
        ensure: ensureDrivesConnected("david"),
        requiredKind: "usb",
        isDone: (snapshot) => snapshot.drives.find((drive) => drive.id === "david")?.connected === false,
      },
    ],
  },
  {
    id: "files-and-unlocking",
    category: "files",
    title: "Files & unlocking",
    summary: "Open a public file, then see what a quorum-protected one asks for.",
    steps: [
      {
        title: "Try it: navigate or sort files",
        body: (
          <p>
            A Windows-Explorer-style view onto your files, grouped into folders. Double-clicking a file unlocks and
            views it; a protected file prompts for whatever it needs first.
          </p>
        ),
        tab: "files",
        target: () => ['[data-panel="files"]'],
        isDone: (_snapshot, latest) => latest?.kind === "file-navigate" || latest?.kind === "file-sort",
      },
      {
        title: "Try it: open a public file",
        body: (
          <p>
            Open the <strong>public</strong> folder, then double-click <code>company-handbook.txt</code>. Nothing
            protects it, so it opens immediately.
          </p>
        ),
        tab: "files",
        target: (snapshot) => ['[data-testid="folder-public"]', fileRow(snapshot, "company-handbook.txt")],
        isDone: (_snapshot, latest) => wasOpened(latest, "company-handbook.txt"),
      },
      {
        title: "Try it: open a protected file",
        body: (
          <p>
            Now open the <strong>engineering</strong> folder and double-click <code>architecture.md</code>. Alice
            alone may not meet its quorum — that's fine, the point is to see what happens when you try.
          </p>
        ),
        tab: "files",
        target: (snapshot) => ['[data-testid="folder-engineering"]', fileRow(snapshot, "architecture.md")],
        isDone: (_snapshot, latest) => wasOpened(latest, "architecture.md"),
      },
      {
        title: "Try it: read the trace",
        body: (
          <p>
            Switch to the <strong>Activity</strong> tab. Every attempt leaves a trace of exactly which checks ran and
            whether each passed — including the one you just made.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-panel="activity"]'],
        requiredKind: "activity-expand",
        isDone: (_snapshot, latest) => latest?.kind === "activity-expand",
      },
    ],
  },
  {
    id: "mailbox",
    category: "mailbox",
    title: "Mailbox: sending & receiving",
    summary: "Seal a file to someone else, receive it as them, and watch the acknowledgement arrive on its own.",
    steps: [
      {
        title: "Try it: send a file",
        body: (
          <p>
            In the <strong>Files</strong> tab, select any file, press <strong>Send&hellip;</strong>, and choose David
            as the recipient. It's sealed to his key — the relay itself can never read it.
          </p>
        ),
        tab: "files",
        target: () => ['[data-panel="files"]'],
        // SendDialog excludes the active user from their own recipient
        // list, so this step is unrunnable, not just already-satisfied,
        // if David happens to be active when it starts (e.g. right after
        // the "Identities & drives" module, which ends on David).
        ensure: ensureActiveUserIsNot("david", "alice"),
        isDone: (_snapshot, latest) => wasSentTo(latest, "David"),
        // Remember which delivery this was, so the receive step below can
        // require that specific letter rather than "any granted receive"
        // (David's inbox may already hold others from outside this run).
        remember: (snapshot) => ({ relayId: snapshot.sent[snapshot.sent.length - 1]?.relayId }),
      },
      {
        title: "Try it: receive the letter",
        body: (
          <p>
            You are now <strong>David</strong> with his USB in &mdash; only his key can open a letter sealed to him. In
            the <strong>Inbox</strong> tab press <strong>Receive</strong> on the sealed letter. It checks the relay
            first, so there is nothing to refresh.
          </p>
        ),
        tab: "mailbox",
        target: () => ['[data-testid^="inbox-"]', '[data-panel="mailbox"]'],
        ensure: composeEnsures(ensureActiveUser("david"), ensureDrivesConnected("david")),
        isDone: (snapshot, latest, memory) => {
          if (!wasReceived(latest)) return false;
          const relayId = memory.relayId;
          if (typeof relayId !== "number") return false;
          return snapshot.inbox.find((item) => item.relayId === relayId)?.status === "received";
        },
      },
      {
        title: "Try it: back to the sender",
        body: (
          <p>
            Click <strong>Alice</strong>&rsquo;s chip. Her USB is in, so signing in opens David&rsquo;s signed answer by
            itself (<code>keyquorum inbox open</code>); the <strong>Sent</strong> view then reads{" "}
            <em>Acknowledged by recipient</em>.
          </p>
        ),
        tab: "mailbox",
        target: () => ['[aria-label="Switch user"]'],
        ensure: composeEnsures(ensureActiveUserIsNot("alice", "david"), ensureDrivesConnected("alice")),
        requiredKind: "user",
        isDone: (snapshot, _latest, memory) => {
          const relayId = memory.relayId;
          return (
            snapshot.activeUser.id === "alice" &&
            typeof relayId === "number" &&
            snapshot.sent.find((item) => item.relayId === relayId)?.status === "acknowledged"
          );
        },
      },
    ],
  },
  {
    id: "slot-custody",
    category: "identities",
    title: "Move & copy slots",
    summary: "Move and copy slots, then inspect how containers affect physical-device policy.",
    steps: [
      {
        title: "Two similar-looking operations",
        body: <p><strong>Move</strong> relocates a slot to another container; <strong>Copy</strong> creates another active copy. Neither creates a ghost. Insert both source and destination drives before trying either operation.</p>,
        tab: "usb",
        target: () => ['[data-testid="drive-alice"]'],
      },
      {
        title: "Try it: move a slot",
        body: <p>Choose a destination beside Alice&rsquo;s slot and press <strong>Move</strong>. Both drives must be inserted. The lab runs <code>keyquorum-device relocate</code> and immediately rebinds the placement.</p>,
        tab: "usb",
        target: () => ['[data-testid="move-slot-M.S.1"]'],
        ensure: ensureDrivesConnected("alice", "morgan"),
        requiredKind: "move",
        isDone: (_snapshot, latest) => wasMoved(latest, "M.S.1"),
      },
      {
        title: "Try it: copy a slot",
        body: (
          <p>
            The adjacent <strong>Copy</strong> form runs <code>transfer copy</code> and asks for the
            slot&rsquo;s own passphrase before it will seal a second copy. Every seeded USB slot uses{" "}
            <code>lab-demo-&lt;label&gt;</code> — for <code>M.S.1</code>, Alice&rsquo;s own slot, that&rsquo;s{" "}
            <code>lab-demo-M.S.1</code>. Copy leaves the source usable, unlike a transfer move.
          </p>
        ),
        tab: "usb",
        target: () => ['[data-testid="copy-slot-M.S.1"]'],
        requiredKind: "transfer-copy",
        isDone: (_snapshot, latest) => latest?.kind === "transfer-copy" && latest.outcome === "granted",
      },
      {
        title: "Try it: inspect custody in Properties",
        body: <p>Open a protected file&rsquo;s <strong>Properties</strong> to see hardware/logical custody, minimum physical devices, and parent approval. Multiple logical slots on one drive still count as one physical device.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
        requiredKind: "properties",
        isDone: (_snapshot, latest) => latest?.kind === "properties",
      },
      {
        title: "Ghosts are deliberately read-only here",
        body: <p>A ghost is created by <code>transfer move</code>, not the Move or Copy controls. The lab exposes no interactive ghost-creation action. Its real pre-seeded ghost is visible only in the Properties requirements for <code>legacy-migration-notes.txt</code>.</p>,
        tab: "files",
        target: (snapshot) => [fileRow(snapshot, "legacy-migration-notes.txt"), '[data-panel="files"]'],
      },
    ],
  },
  {
    id: "check-setup",
    category: "identities",
    title: "Check your setup",
    summary: "Ask doctor what is missing for you, fix it with one action, and check again.",
    steps: [
      {
        title: "Try it: see what is missing",
        body: (
          <p>
            You are Alice, and her USB has just been unplugged. In <strong>Security</strong> press{" "}
            <strong>Check my setup</strong>. <code>keyquorum doctor</code> only reads: it lists what works and, for
            each thing that does not, the command that fixes it.
          </p>
        ),
        tab: "security",
        target: () => ['[data-testid="doctor-run"]', '[data-testid="doctor"]'],
        ensure: composeEnsures(ensureActiveUser("alice"), ensureDriveDisconnected("alice")),
        requiredKind: "doctor",
        isDone: (_snapshot, latest) =>
          latest?.kind === "doctor" && latest.trace.some((step) => step.text.includes("cannot be opened")),
      },
      {
        title: "Try it: plug the drive back in",
        body: (
          <p>
            Doctor said to plug the device in. On the <strong>USB devices</strong> tab press{" "}
            <strong>Insert Alice&rsquo;s USB</strong>.
          </p>
        ),
        tab: "usb",
        target: () => ['[data-testid="drive-alice"]'],
        requiredKind: "usb",
        isDone: (snapshot) => snapshot.drives.find((drive) => drive.id === "alice")?.connected === true,
      },
      {
        title: "Try it: check again",
        body: (
          <p>
            Press <strong>Check my setup</strong> again. It is the same command, so the only thing that changed is
            your setup. If it ever names a default or a binding, the buttons beside it (<strong>Use my current drive</strong>,{" "}
            <strong>Bind my slot</strong>) run those fixes.
          </p>
        ),
        tab: "security",
        target: () => ['[data-testid="doctor-run"]', '[data-testid="doctor"]'],
        requiredKind: "doctor",
        isDone: (_snapshot, latest) =>
          latest?.kind === "doctor" && latest.trace.some((step) => step.text.includes("Everything checks out")),
      },
    ],
  },
  {
    id: "identity-enrollment",
    category: "identities",
    title: "Provision & register a leaf",
    summary: "Mint a fresh device slot and register it in the organization tree in one step.",
    steps: [
      {
        title: "Create and register in one step",
        body: <p>In <strong>Create and register a new leaf</strong>, choose an inserted drive, a new dotted label, a passphrase and a parent node. One action mints the keys on the device (<code>keyquorum-device provision</code>), registers both, binds the container and adds that exact slot below the parent, resharing with the active siblings the CLI can collect.</p>,
        tab: "security",
        target: () => ['[data-testid="create-register-leaf"]'],
        requiredKind: "register-leaf",
        isDone: (_snapshot, latest) => latest?.kind === "register-leaf" && latest.outcome === "granted",
      },
      {
        title: "Confirm it in the tree",
        body: <p>The organization view is the result, not a second implementation: it renders the personal store&rsquo;s visible slice after the real CLI mutates the tree.</p>,
        tab: "organization",
        target: () => ['[data-panel="organization"]'],
      },
    ],
  },
  {
    id: "key-administration",
    category: "identities",
    title: "Key administration",
    summary: "Revoke, reissue, restructure, countersign, and understand parent approval.",
    steps: [
      {
        title: "Revoke versus reissue",
        body: (
          <p>
            Try either one on this leaf: <strong>Revoke key</strong> bans its current hardware key, while{" "}
            <strong>Reissue&hellip;</strong> adopts an already-provisioned replacement token and authenticates an
            update to affected stores. They&rsquo;re related, but distinct — either action here completes this step.
          </p>
        ),
        tab: "organization",
        target: () => ['[data-testid="tree-node-M.A.1"]', '[data-panel="organization"]'],
        isDone: (_snapshot, latest) =>
          (latest?.kind === "revoke" || latest?.kind === "reissue") && latest.outcome === "granted",
      },
      {
        title: "Try it: propose a restructure",
        body: (
          <p>
            Only the organization&rsquo;s authority (<code>M.A</code>, played by David here) may propose the next
            public generation. Press <strong>Propose restructure</strong>.
          </p>
        ),
        tab: "organization",
        target: () => ['[data-testid="restructure-admin"]'],
        ensure: ensureActiveUser("david"),
        requiredKind: "restructure-propose",
        isDone: (_snapshot, latest) => latest?.kind === "restructure-propose" && latest.outcome === "granted",
      },
      {
        title: "Try it: countersign as the parent",
        body: (
          <p>
            A non-root proposal stays pending until its parent countersigns with that parent&rsquo;s own device
            passphrase. Switch to <strong>Morgan</strong>, the proposal&rsquo;s parent, then press{" "}
            <strong>Countersign</strong>.
          </p>
        ),
        tab: "organization",
        target: () => ['[data-testid="restructure-admin"]'],
        ensure: composeEnsures(ensureActiveUser("morgan"), ensureDrivesConnected("morgan")),
        requiredKind: "restructure-countersign",
        isDone: (_snapshot, latest) => latest?.kind === "restructure-countersign" && latest.outcome === "granted",
      },
      {
        title: "Parent approval is enforced at unlock",
        body: <p>A file&rsquo;s Properties dialog reports whether <code>unlock_approval = parent</code>. It is policy, not a toggle in this lab; when required, the approving parent&rsquo;s participation is part of the real unlock path.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
        requiredKind: "properties",
        isDone: (_snapshot, latest) => latest?.kind === "properties",
      },
    ],
  },
  {
    id: "bridges-and-device-relay",
    category: "identities",
    title: "Bridges & remote devices",
    summary: "Manage cross-branch visibility and distinguish local device actions from relay transfer.",
    steps: [
      {
        title: "Whitelist before linking",
        body: <p>Select a node and peer, then <strong>Allow node → peer</strong>. Establishing a bridge is refused until one endpoint has whitelisted the other.</p>,
        tab: "organization",
        target: () => ['[data-testid="bridges"]'],
        requiredKind: "terminal",
        isDone: (_snapshot, latest) => ranCommand(latest, "bridge allow"),
      },
      {
        title: "Establish, remove, or deny",
        body: <p><strong>Establish bridge</strong> changes each endpoint&rsquo;s visible slice. The Established and Whitelist lists then expose <strong>Remove</strong> and <strong>Deny</strong>. This same private bridge supports file signing and verification.</p>,
        tab: "organization",
        target: () => ['[data-testid="bridges"]'],
        requiredKind: "terminal",
        isDone: (_snapshot, latest) => ranCommand(latest, "bridge add", "bridge remove", "bridge deny"),
      },
      {
        title: "Remote device transfer is not a GUI action",
        body: <p>Device publish, relay-send, collect, and finalize are intentionally not buttons in this lab. They use opaque device letters in the same in-process relay; use the Terminal to explore the CLI. The read-only relay counters show those letters without opening them.</p>,
        tab: "terminal",
        target: () => ['[data-panel="terminal"]'],
        requiredKind: "terminal",
        isDone: (_snapshot, latest) =>
          ranCommand(latest, "device publish", "relay-send", "relay-collect", "relay-finalize"),
      },
    ],
  },
  {
    id: "successful-quorum",
    category: "files",
    title: "Complete a quorum unlock",
    summary: "Read a file's requirements, connect cooperating devices, and complete an unlock.",
    steps: [
      {
        title: "Start with Properties",
        body: <p>Select a protected file and open <strong>Properties</strong>. The requirement tree tells you which leaves can satisfy each threshold; policy below it tells you how many distinct physical devices are required.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
        requiredKind: "properties",
        isDone: (_snapshot, latest) => latest?.kind === "properties",
        // Remember which file this run is about, so the next two steps can
        // check the drives and the unlock against this same file rather
        // than any drive or any granted access.
        remember: (_snapshot, latest) => ({ fileName: propertiesFileName(latest) }),
      },
      {
        title: "Bring the required devices online",
        body: <p>Insert enough separate drives in <strong>USB devices</strong>. Slots moved onto the same container may satisfy logical shares, but still contribute only one physical device.</p>,
        tab: "usb",
        target: () => ['[data-panel="usb"]'],
        requiredKind: "usb",
        isDone: (snapshot, _latest, memory) => {
          const fileName = memory.fileName;
          if (typeof fileName !== "string") return false;
          const file = snapshot.files.find((candidate) => candidate.name === fileName);
          const needed = file?.policy?.minimumDevices ?? 1;
          return connectedRequiredDevices(snapshot, fileName) >= needed;
        },
      },
      {
        title: "Try it: unlock successfully",
        body: <p>Return to Files and open the protected file. A successful attempt decrypts it; a denied attempt leaves a precise trace so you can adjust the connected drives and retry.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
        requiredKind: "access",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.fileName;
          return typeof fileName === "string" && latest?.outcome === "granted" && wasOpened(latest, fileName);
        },
      },
      {
        title: "Audit the decision",
        body: <p>The Activity panel records the command and every custody, quorum, ghost, expiry, and approval check that led to the result.</p>,
        tab: "activity",
        target: () => ['[data-panel="activity"]'],
        requiredKind: "activity-expand",
        isDone: (_snapshot, latest) => latest?.kind === "activity-expand",
      },
    ],
  },
  {
    id: "password-files",
    category: "files",
    title: "Passwords & PINs",
    summary: "Create and unlock the lab's second, independent protection scheme.",
    steps: [
      {
        title: "Create a password-locked note",
        body: <p>Fill in a name, contents, and your own password. Optionally enable the four-digit PIN. This protection is separate from organization quorum shares.</p>,
        tab: "security",
        target: () => ['[data-testid="password-lock"]'],
        requiredKind: "password-lock",
        isDone: (_snapshot, latest) => latest?.kind === "password-lock" && latest.outcome === "granted",
        remember: (_snapshot, latest) => ({ fileName: passwordLockFileName(latest) }),
      },
      {
        title: "Try the unlock path",
        body: <p>Your new file appears directly below the form. Enter the same password and PIN, if selected, then press <strong>Unlock</strong>.</p>,
        tab: "security",
        target: () => ['[data-testid="password-files"]'],
        requiredKind: "password-access",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.fileName;
          return (
            typeof fileName === "string" &&
            latest?.kind === "password-access" &&
            latest.outcome === "granted" &&
            latest.title === `Access granted: ${fileName}`
          );
        },
      },
      {
        title: "Try it: lock one from the Terminal",
        body: (
          <p>
            Switch to the <strong>Terminal</strong> tab and run{" "}
            <code>
              keyquorum --db /home/alice/keyquorum.sqlite access password --state 0 --source
              /srv/keyquorum/public/company-handbook.txt --encrypted-path /home/alice/&lt;name&gt;.kqenc --pin
            </code>
            , replacing <code>&lt;name&gt;</code> with anything you like (locking over an existing name is
            refused). Typing a command yourself, instead of filling in the GUI form, still has to answer its
            password and PIN prompts — the terminal answers both with the lab&rsquo;s own published defaults,{" "}
            <code>lab-demo-password</code> and <code>0000</code>, the same way a slot passphrase prompt falls
            back to <code>lab-demo-&lt;label&gt;</code> when you don&rsquo;t type your own.
          </p>
        ),
        tab: "terminal",
        target: () => ['[data-panel="terminal"]'],
        ensure: ensureActiveUser("alice"),
        requiredKind: "terminal",
        isDone: (_snapshot, latest) =>
          latest?.kind === "terminal" &&
          latest.outcome === "granted" &&
          typeof latest.command === "string" &&
          latest.command.includes("access password") &&
          latest.command.includes("--state 0") &&
          latest.command.includes("--pin"),
      },
    ],
  },
  {
    id: "portable-sharing",
    category: "files",
    title: "Export bundles & share links",
    summary: "Contrast recipient-sealed export bundles with bearer share links.",
    steps: [
      {
        title: "Try it: create the file you will share",
        body: <p>Create a password-locked note first. Remember the password: you will use this same file for the export and share-link steps that follow.</p>,
        tab: "security",
        target: () => ['[data-testid="password-lock"]'],
        requiredKind: "password-lock",
        isDone: (_snapshot, latest) => latest?.kind === "password-lock" && latest.outcome === "granted",
        remember: (_snapshot, latest) => ({ fileName: passwordLockFileName(latest) }),
      },
      {
        title: "Try it: create a recipient-bound export",
        body: <p>On the password file you just created, open <strong>Export…</strong>, choose another user, and enter the file password. The resulting <code>KQXB</code> is sealed to that recipient.</p>,
        tab: "security",
        target: () => ['[data-testid="password-files"]'],
        requiredKind: "export",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.fileName;
          return (
            typeof fileName === "string" &&
            latest?.kind === "export" &&
            latest.outcome === "granted" &&
            latest.title.startsWith(`Export ${fileName} for `)
          );
        },
      },
      {
        title: "Try it: view the export bundle",
        body: <p>Under <strong>Exported bundles</strong>, press <strong>View sealed bytes</strong>. The viewer shows the portable <code>KQXB</code> ciphertext, not its protected plaintext.</p>,
        tab: "security",
        target: () => ['[data-testid="exported-bundles"]', '[data-panel="security"]'],
        requiredKind: "export-view",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.fileName;
          return (
            typeof fileName === "string" &&
            latest?.kind === "export-view" &&
            latest.title.startsWith(`Sealed bundle for ${fileName} `)
          );
        },
      },
      {
        title: "Try it: create a bearer share link",
        body: <p>Open <strong>Share…</strong> on that file, choose its lifetime and optional PIN, and create it. The displayed token is the capability: possession of it, not lab identity, authorizes access.</p>,
        tab: "security",
        target: () => ['[data-testid="password-files"]'],
        requiredKind: "share-create",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.fileName;
          return (
            typeof fileName === "string" &&
            latest?.kind === "share-create" &&
            latest.outcome === "granted" &&
            latest.title === `Create a share link for ${fileName}`
          );
        },
      },
      {
        title: "Try it: redeem the share link",
        body: <p>Copy the newly displayed bearer token, close its viewer, paste it into the share&rsquo;s redemption form, and press <strong>Redeem</strong>. Add the PIN too if you chose one.</p>,
        tab: "security",
        target: () => ['[data-testid="share-links"]'],
        requiredKind: "share-redeem",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.fileName;
          return (
            typeof fileName === "string" &&
            latest?.kind === "share-redeem" &&
            latest.outcome === "granted" &&
            latest.title === `Redeem the share link for ${fileName}`
          );
        },
      },
      {
        title: "Try it: revoke the share",
        body: <p>Close the token viewer, then press <strong>Revoke</strong> beside the live share. Future redemption ends, while the independently sealed export bundle is unaffected.</p>,
        tab: "security",
        target: () => ['[data-testid="share-links"]'],
        requiredKind: "share-revoke",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.fileName;
          return (
            typeof fileName === "string" &&
            latest?.kind === "share-revoke" &&
            latest.outcome === "granted" &&
            latest.title === `Revoke the share link for ${fileName}`
          );
        },
      },
    ],
  },
  {
    id: "signatures-properties-expiry",
    category: "files",
    title: "Signatures, properties & expiry",
    summary: "Sign and verify through a bridge, inspect properties, and observe destructive expiry.",
    steps: [
      {
        title: "Try it: become the signer",
        body: <p>Switch to <strong>Sarah</strong>. Sarah is the seeded bridge member whose sealed shared secret is present, so she can complete the signing workflow.</p>,
        target: () => ['[aria-label="Switch user"]'],
        ensure: ensureActiveUserIsNot("sarah", "alice"),
        requiredKind: "user",
        isDone: (snapshot) => snapshot.activeUser.id === "sarah",
      },
      {
        title: "Try it: sign a file",
        body: <p>Open the <strong>public</strong> folder, select a file, and press <strong>Sign</strong>. This exercises the private-bridge signing path.</p>,
        tab: "files",
        target: (snapshot) => ['[data-testid="folder-public"]', fileRow(snapshot, "company-handbook.txt"), '[data-testid="file-actions"]'],
        requiredKind: "sign",
        isDone: (_snapshot, latest) => latest?.kind === "sign" && latest.outcome === "granted",
        // LabState::sign_file logs "Sign <name>" -- remember it so the
        // verify step below checks the signature it just made, not any
        // signature that happens to already be granted.
        remember: (_snapshot, latest) => ({ signedFileName: latest?.title.match(/^Sign (.+)$/)?.[1] }),
      },
      {
        title: "Try it: verify the signature",
        body: <p>The signature now appears under <strong>Signatures</strong>. Press <strong>Verify</strong> to check the artifact and registered signer key.</p>,
        tab: "security",
        target: () => ['[data-testid="signatures"]'],
        requiredKind: "verify",
        isDone: (_snapshot, latest, memory) => {
          const fileName = memory.signedFileName;
          return (
            typeof fileName === "string" &&
            latest?.kind === "verify" &&
            latest.outcome === "granted" &&
            latest.title === `Verify ${fileName}'s signature`
          );
        },
      },
      {
        title: "Try it: inspect Properties",
        body: <p>Properties shows type, size, source, expiry, requirement tree, ghosts, custody mode, minimum devices, and parent approval without attempting an unlock.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
        requiredKind: "properties",
        isDone: (_snapshot, latest) => latest?.kind === "properties",
      },
      {
        title: "Try it: observe expiry and purge",
        body: <p>Some seeded files expire while the tab is open. Their timestamp updates passively; the first unlock attempt after expiry runs the real destructive purge, deleting ciphertext and its database row.</p>,
        tab: "files",
        target: () => ['[data-panel="files"]'],
        requiredKind: "access",
        isDone: (_snapshot, latest) =>
          latest?.kind === "access" && latest.trace.some((step) => /expir|purge|delet/i.test(step.text)),
      },
    ],
  },
  {
    id: "mailbox-decisions",
    category: "mailbox",
    title: "Reject & acknowledge",
    summary: "Exercise the rejection path and see the sender learn of it without refreshing anything.",
    steps: [
      {
        title: "Try it: send a letter to reject",
        body: <p>Open the <strong>public</strong> folder, select a file, press <strong>Send…</strong>, and choose David. This creates this module&rsquo;s own letter, so it works independently of every other tutorial.</p>,
        tab: "files",
        target: () => ['[data-panel="files"]'],
        // Later steps hard-code Alice as the sender (the final step reads
        // her own snapshot.sent for this relayId; each lab user's sent
        // list is their own mailbox, not a global one), so this must force
        // Alice specifically -- not just "away from David" -- or a module
        // entered right after one that left Morgan, Sarah, Bob, Emma, or
        // Chris active would record the send under the wrong mailbox and
        // the acknowledgement step could never find it.
        ensure: ensureActiveUser("alice"),
        isDone: (_snapshot, latest) => wasSentTo(latest, "David"),
        remember: (snapshot) => ({ relayId: snapshot.sent[snapshot.sent.length - 1]?.relayId }),
      },
      {
        title: "Try it: reject the letter",
        body: <p>You are now <strong>David</strong>, with his USB in. Press <strong>Reject</strong> on the new letter. Rejection opens and authenticates the envelope, records no received file, and sends a signed acknowledgement.</p>,
        tab: "mailbox",
        target: () => ['[data-testid^="inbox-"]', '[data-panel="mailbox"]'],
        ensure: composeEnsures(ensureActiveUser("david"), ensureDrivesConnected("david")),
        requiredKind: "receive",
        isDone: (snapshot, latest, memory) => {
          const relayId = memory.relayId;
          return latest?.kind === "receive" && latest.outcome === "info" && typeof relayId === "number" &&
            snapshot.inbox.find((item) => item.relayId === relayId)?.status === "rejected";
        },
      },
      {
        title: "Try it: return to the sender",
        body: <p>Switch back to <strong>Alice</strong>. Her USB is in, so David&rsquo;s signed rejection is opened for her as she signs in; <strong>Sent</strong> reads <em>Rejected by recipient</em>.</p>,
        tab: "mailbox",
        target: () => ['[aria-label="Switch user"]'],
        ensure: composeEnsures(ensureActiveUserIsNot("alice", "david"), ensureDrivesConnected("alice")),
        requiredKind: "user",
        isDone: (snapshot, _latest, memory) => {
          const relayId = memory.relayId;
          return (
            snapshot.activeUser.id === "alice" &&
            typeof relayId === "number" &&
            snapshot.sent.find((item) => item.relayId === relayId)?.status === "rejected"
          );
        },
      },
    ],
  },
  {
    id: "mailbox-protocols",
    category: "mailbox",
    title: "Updates & device letters",
    summary: "See which higher-level workflows use sealed letters and where their controls actually live.",
    steps: [
      {
        title: "Organization updates live in Organization",
        body: <p>Reissue and restructure/countersign produce authenticated sealed update letters underneath, but they are organization actions—not mailbox buttons. Their only GUI controls are here.</p>,
        tab: "organization",
        target: () => ['[data-testid="restructure-admin"]', '[data-panel="organization"]'],
      },
      {
        title: "Bridge membership lives here too",
        body: <p>Allow, establish, remove, and deny are all managed in the Bridges panel. The inbox transports resulting private bridge packages, but does not duplicate those controls.</p>,
        tab: "organization",
        target: () => ['[data-testid="bridges"]'],
      },
      {
        title: "Device letters remain opaque",
        body: <p>Remote copy/move/relocate handshakes use the relay&rsquo;s device mailbox. This lab has no GUI buttons for publish, relay-send, collect, or finalize; the Relay status panel exposes only counts, while Device logs report inserted containers.</p>,
        tab: "security",
        target: () => ['[data-testid="device-logs"]', '[data-testid="relay-status"]'],
        requiredKind: "device-log",
        isDone: (_snapshot, latest) => latest?.kind === "device-log",
      },
    ],
  },
  {
    id: "tracked-file-history",
    category: "history",
    title: "1 · Track, sign & fall back",
    summary: "Track a file, check in an unsigned edit, watch sharing fall back to the last trusted revision, then sign it.",
    steps: [
      {
        title: "Tracked files live on the Activity page",
        body: (
          <p>
            A tracked file carries its own signed, hash-chained history. You're acting as <strong>Sarah</strong> (M.S)
            with her drive inserted. Every button here runs a real <code>keyquorum file</code> command with her slot.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-files"]', '[data-panel="activity"]'],
        ensure: composeEnsures(ensureActiveUser("sarah"), ensureDrivesConnected("sarah")),
      },
      {
        title: "Try it: track a new file",
        body: (
          <p>
            Type a name (for example <code>notes.txt</code>) and some text under <strong>New tracked file</strong>,
            then press <strong>Track and sign</strong>. The first revision is signed by Sarah, so it is trusted.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="history-track"]'],
        ensure: composeEnsures(ensureActiveUser("sarah"), ensureDrivesConnected("sarah")),
        requiredKind: "history-track",
        isDone: (_snapshot, latest) => latest?.outcome === "granted",
      },
      {
        title: "Try it: check in an unsigned edit",
        body: (
          <p>
            Change the text under <strong>Edit the current revision</strong>, <em>untick</em>{" "}
            <strong>Sign this edit with my slot</strong>, and press <strong>Check in</strong>. The new revision is
            recorded, but nobody has vouched for it yet.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="history-checkin"]'],
        requiredKind: "history-checkin",
        isDone: (_snapshot, latest) => latest?.outcome === "granted" && latest.title.includes("unsigned"),
      },
      {
        title: "Sharing falls back",
        body: (
          <p>
            The newest revision is <strong>pending</strong>, so sharing would send the last trusted one instead. An
            unsigned edit never leaves Sarah's copy — the line below says which revision would go.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-shareable"]'],
      },
      {
        title: "Try it: sign the edit",
        body: (
          <p>
            Press <strong>Sign revision</strong> next to the pending revision. It becomes trusted, and sharing now sends it.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-revisions"] li[data-trust="pending"]', '[data-testid="tracked-revisions"]'],
        requiredKind: "history-sign",
        isDone: (_snapshot, latest) => latest?.outcome === "granted",
      },
      {
        title: "Try it: read the timeline",
        body: (
          <p>
            Open <strong>Full activity log</strong> below and pick the <strong>Revision</strong> filter. Every check-in,
            signature and policy decision you just made is there, read back from the file's own history.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-panel="activity"] details.log'],
        requiredKind: "history-filter",
        isDone: (_snapshot, latest) => latest?.title === "Showed Revision activity",
      },
    ],
  },
  {
    id: "history-hand-off",
    category: "history",
    title: "2 · Hand a file over",
    summary: "Share a tracked file with Alice, accept it as her, and see her signed answer recorded in Sarah's history when Sarah returns.",
    steps: [
      {
        title: "Try it: share it with Alice",
        body: (
          <p>
            You're Sarah. In <strong>Tracked files</strong>, pick <code>budget.txt</code>; its newest edit was never
            signed, so the line under the revisions says which revision would actually be sent. Under{" "}
            <strong>Share with</strong>, choose <strong>Alice</strong> and press <strong>Share file</strong>. The letter
            is sealed to Alice's key and signed by Sarah; only the trusted revision goes in it.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-select"]', '[data-testid="history-share"]', '[data-testid="tracked-files"]'],
        ensure: composeEnsures(ensureActiveUser("sarah"), ensureDrivesConnected("sarah", "alice")),
        requiredKind: "history-share",
        isDone: (_snapshot, latest) => latest?.outcome === "granted" && latest.title.endsWith("with Alice"),
        remember: (snapshot) => ({ letterId: snapshot.trackedLetters[snapshot.trackedLetters.length - 1]?.id }),
      },
      {
        title: "Try it: accept the letter",
        body: (
          <p>
            You are now <strong>Alice</strong>. Under <strong>Tracked-file letters</strong>, press{" "}
            <strong>Accept budget.txt</strong>. Alice's store checks Sarah's signature, then judges the revision by the
            file's own policy before keeping a copy.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-letters"]', '[data-testid="tracked-files"]'],
        ensure: composeEnsures(ensureActiveUser("alice"), ensureDrivesConnected("sarah", "alice")),
        requiredKind: "history-receive",
        isDone: (snapshot, latest, memory) =>
          latest?.outcome === "granted" &&
          snapshot.trackedLetters.find((letter) => letter.id === memory.letterId)?.status === "accepted",
      },
      {
        title: "Try it: back to Sarah",
        body: (
          <p>
            Switch back to <strong>Sarah</strong>. Her USB is in, so Alice's signed answer is recorded in her copy as she
            signs in (<code>keyquorum inbox open</code>): the letter reads <em>answer recorded</em>.
          </p>
        ),
        tab: "activity",
        target: () => ['[aria-label="Switch user"]'],
        ensure: composeEnsures(ensureActiveUserIsNot("sarah", "alice"), ensureDrivesConnected("sarah", "alice")),
        requiredKind: "user",
        isDone: (snapshot, _latest, memory) =>
          snapshot.activeUser.id === "sarah" &&
          snapshot.trackedLetters.find((letter) => letter.id === memory.letterId)?.ackRecorded === true,
      },
      {
        title: "The hand-off is in the history",
        body: (
          <p>
            Open <strong>Full activity log</strong> and pick <strong>Sharing</strong>: the attempt, and Alice's
            acceptance, are events in <code>budget.txt</code>'s own chain, not just in the lab's log.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-panel="activity"] details.log'],
      },
    ],
  },
  {
    id: "history-merges",
    category: "history",
    title: "3 · Merges & conflicts",
    summary: "Sign a merge that happened on its own, then see who has to review a conflict it could not settle.",
    steps: [
      {
        title: "Try it: see what the merge changed",
        body: (
          <p>
            You're Sarah. Pick <code>forecast.txt</code>: two people edited different lines, so the edits merged into a
            new revision with <strong>two parents</strong>, and it is <strong>pending</strong> &mdash; a merge never
            inherits its parents' signatures. Press <strong>Diff</strong> on the newest revision to see the lines it
            changed against its first parent.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-revisions"]'],
        ensure: composeEnsures(ensureActiveUser("sarah"), ensureDrivesConnected("sarah")),
        requiredKind: "history-diff",
        isDone: (_snapshot, latest) => latest?.outcome === "granted" && latest.title.includes("forecast.txt"),
      },
      {
        title: "Try it: sign the merge",
        body: (
          <p>
            Sarah made the merge, so press <strong>Sign revision</strong> on it. Only now is the merged text trusted.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-revisions"] li[data-trust="pending"]', '[data-testid="tracked-revisions"]'],
        requiredKind: "history-sign",
        isDone: (_snapshot, latest) => latest?.outcome === "granted" && latest.title.includes("forecast.txt"),
      },
      {
        title: "Try it: review a conflict",
        body: (
          <p>
            Now pick <code>memo.txt</code>. Two edits changed the same line differently, so it still has two heads.
            Press <strong>Review the fork</strong>.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-select"]', '[data-testid="tracked-files"]'],
        requiredKind: "history-review",
        isDone: (_snapshot, latest) => latest?.outcome === "granted" && latest.title.includes("memo.txt"),
      },
      {
        title: "A person decides",
        body: (
          <p>
            The review shows each side's changed lines, who wrote each one, and the reviewer the history names
            &mdash; here Sarah, the file's prior neutral owner. Seniority never picks a winning line; the reviewer
            settles it by editing, and until then both heads stay exactly as they were.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-files"]'],
      },
    ],
  },
  {
    id: "history-expiry-gates",
    category: "history",
    title: "4 · Gate links & expiry",
    summary: "Record a quorum file's unlocks in a tracked file's history, then expire the tracked file and verify the tombstone.",
    steps: [
      {
        title: "Try it: track a file",
        body: (
          <p>
            You're Alice. Under <strong>New tracked file</strong>, give a name and some text and press{" "}
            <strong>Track and sign</strong>.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="history-track"]'],
        ensure: composeEnsures(ensureActiveUser("alice"), ensureDrivesConnected("alice", "sarah")),
        requiredKind: "history-track",
        isDone: (_snapshot, latest) => latest?.outcome === "granted",
      },
      {
        title: "Try it: link a gate",
        body: (
          <p>
            Under <strong>Record unlocks of</strong>, choose <strong>architecture.md (quorum)</strong> and press{" "}
            <strong>Link gate</strong>. The quorum gate itself does not change.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="history-link"]', '[data-testid="history-tools"]'],
        requiredKind: "history-link",
        isDone: (_snapshot, latest) => latest?.outcome === "granted",
      },
      {
        title: "Try it: open the linked file",
        body: (
          <p>
            In the <strong>Files</strong> tab, open the <strong>engineering</strong> folder and double-click{" "}
            <code>architecture.md</code>.
          </p>
        ),
        tab: "files",
        target: (snapshot) => ['[data-testid="folder-engineering"]', fileRow(snapshot, "architecture.md")],
        isDone: (_snapshot, latest) => wasOpened(latest, "architecture.md"),
      },
      {
        title: "Try it: find the unlock in the history",
        body: (
          <p>
            Back on the Activity tab, open <strong>Full activity log</strong> and pick <strong>Security</strong>. The
            unlock you just made is now an event in your tracked file's history.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-panel="activity"] details.log'],
        requiredKind: "history-filter",
        isDone: (_snapshot, latest) => latest?.title === "Showed Security activity",
      },
      {
        title: "Try it: end the file",
        body: (
          <p>
            Pick your tracked file again and press <strong>Destroy content now</strong>. Every revision's content goes
            at once.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="history-expire"]', '[data-testid="tracked-files"]'],
        requiredKind: "history-expire",
        isDone: (_snapshot, latest) => latest?.outcome === "granted" && latest.title.startsWith("Destroy"),
      },
      {
        title: "Try it: verify the tombstone",
        body: (
          <p>
            Press <strong>Verify history</strong>. The content is gone, but the history, revisions and signatures still
            verify &mdash; and any later attempt to use the content is recorded.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-files"]'],
        requiredKind: "history-verify",
        isDone: (_snapshot, latest) => latest?.outcome === "granted",
      },
    ],
  },
  {
    id: "history-requests",
    category: "history",
    title: "5 · Ask for a file or a change",
    summary: "Ask Alice for a change to a tracked file, watch her accept, and see her signed answer recorded in Sarah's history when Sarah returns.",
    steps: [
      {
        title: "Try it: ask Alice for a change",
        body: (
          <p>
            You're Sarah. In <strong>Tracked files</strong>, pick <code>budget.txt</code>. A <strong>request</strong> is
            a signed letter that only <em>asks</em>: it delivers nothing and changes nothing. Under <strong>Ask</strong>,
            choose <strong>Alice</strong> for <strong>a change to this file</strong>, type a message and press{" "}
            <strong>Send request</strong>. The message is shown to Alice and never recorded in the history; the
            request's id and kind are.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-select"]', '[data-testid="history-request"]', '[data-testid="tracked-files"]'],
        ensure: composeEnsures(ensureActiveUser("sarah"), ensureDrivesConnected("sarah", "alice")),
        requiredKind: "history-request",
        isDone: (_snapshot, latest) => latest?.outcome === "granted" && latest.title.startsWith("Ask Alice for a change"),
        remember: (snapshot) => ({ requestId: snapshot.trackedRequests[snapshot.trackedRequests.length - 1]?.id }),
      },
      {
        title: "Try it: accept the request",
        body: (
          <p>
            You are now <strong>Alice</strong>. Under <strong>Requests for a file or a change</strong>, read Sarah's
            message and press <strong>Accept request for budget.txt</strong>. Accepting only says yes: a change arrives
            later as an ordinary revision, and a file is sent with <strong>Share file</strong>.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-testid="tracked-requests"]'],
        ensure: composeEnsures(ensureActiveUser("alice"), ensureDrivesConnected("sarah", "alice")),
        requiredKind: "history-answer-request",
        isDone: (snapshot, latest, memory) =>
          latest?.outcome === "granted" &&
          snapshot.trackedRequests.find((request) => request.id === memory.requestId)?.status === "accepted",
      },
      {
        title: "Try it: back to Sarah",
        body: (
          <p>
            Switch back to <strong>Sarah</strong>. Her USB is in, so Alice's signed answer is checked against the request
            she made and recorded as she signs in (<code>keyquorum inbox open</code>).
          </p>
        ),
        tab: "activity",
        target: () => ['[aria-label="Switch user"]'],
        ensure: composeEnsures(ensureActiveUserIsNot("sarah", "alice"), ensureDrivesConnected("sarah", "alice")),
        requiredKind: "user",
        isDone: (snapshot, _latest, memory) =>
          snapshot.activeUser.id === "sarah" &&
          snapshot.trackedRequests.find((request) => request.id === memory.requestId)?.answerRecorded === true,
      },
      {
        title: "The request is in the history",
        body: (
          <p>
            Open <strong>Full activity log</strong>: <em>Change requested</em> and <em>Request answered</em> are events
            in <code>budget.txt</code>'s own chain, with the id, kind and decision only.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-panel="activity"] details.log'],
      },
    ],
  },
];
