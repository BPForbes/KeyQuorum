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
import type { ActivityView, Snapshot } from "../api/types";

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
  category: "identities" | "files" | "mailbox";
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
        title: "That's the basics",
        body: (
          <p>
            You now know how to bring a drive online and how to tell who you're acting as. The other modules build on
            this one.
          </p>
        ),
        target: () => [".active-user"],
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
        title: "The File Explorer",
        body: (
          <p>
            A Windows-Explorer-style view onto your files, grouped into folders. Double-clicking a file unlocks and
            views it; a protected file prompts for whatever it needs first.
          </p>
        ),
        tab: "files",
        target: () => ['[data-panel="files"]'],
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
        title: "Read the trace",
        body: (
          <p>
            Switch to the <strong>Activity</strong> tab. Every attempt leaves a trace of exactly which checks ran and
            whether each passed — including the one you just made.
          </p>
        ),
        tab: "activity",
        target: () => ['[data-panel="activity"]'],
      },
    ],
  },
  {
    id: "mailbox",
    category: "mailbox",
    title: "Mailbox: sending & receiving",
    summary: "Seal a file to someone else, then switch identity and receive it.",
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
        title: "Try it: become the recipient",
        body: (
          <p>
            Click <strong>David</strong>&rsquo;s chip in the Active user bar to act as him — only his own key can open
            a letter sealed to him.
          </p>
        ),
        target: () => ['[aria-label="Switch user"]'],
        ensure: ensureActiveUserIsNot("david", "alice"),
        requiredKind: "user",
        isDone: (snapshot) => snapshot.activeUser.id === "david",
      },
      {
        title: "Try it: receive the letter",
        body: (
          <p>
            Switch to the <strong>Inbox</strong> tab and press <strong>Receive</strong> on the sealed letter waiting
            there.
          </p>
        ),
        tab: "mailbox",
        target: () => ['[data-testid^="inbox-"]', '[data-panel="mailbox"]'],
        isDone: (snapshot, latest, memory) => {
          if (!wasReceived(latest)) return false;
          const relayId = memory.relayId;
          if (typeof relayId !== "number") return false;
          return snapshot.inbox.find((item) => item.relayId === relayId)?.status === "received";
        },
      },
      {
        title: "Sent and acknowledged",
        body: (
          <p>
            Back on the sender's side, the <strong>Sent</strong> view (inside the Inbox tab) tracks whether a
            delivery is still awaiting the recipient's signed acknowledgement.
          </p>
        ),
        tab: "mailbox",
        target: () => ['[data-panel="mailbox"]'],
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
        isDone: (_snapshot, latest) => latest?.kind === "move" && latest.outcome !== "denied",
      },
      {
        title: "Copy keeps the source active",
        body: <p>The adjacent <strong>Copy</strong> form runs <code>transfer copy</code>. It needs the slot&rsquo;s published demo passphrase and leaves the source usable, unlike a transfer move.</p>,
        tab: "usb",
        target: () => ['[data-testid^="copy-slot-"]'],
      },
      {
        title: "Custody is about containers",
        body: <p>Open a protected file&rsquo;s <strong>Properties</strong> to see hardware/logical custody, minimum physical devices, and parent approval. Multiple logical slots on one drive still count as one physical device.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
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
    id: "identity-enrollment",
    category: "identities",
    title: "Provision & register a leaf",
    summary: "Provision a fresh device slot, then register it in the organization tree.",
    steps: [
      {
        title: "Provision first",
        body: <p>In <strong>Create a new key</strong>, choose an inserted drive, a new dotted label, and a passphrase. Provisioning mints keys on the device but does not yet grant an organization role.</p>,
        tab: "security",
        target: () => ['[data-testid="provision-slot"]'],
      },
      {
        title: "Register the leaf separately",
        body: <p>Use <strong>Register a new leaf</strong> after provisioning. Registration binds the container and adds that exact slot below a selected split node, resharing with the active siblings the CLI can collect.</p>,
        tab: "security",
        target: () => ['[data-testid="register-leaf"]'],
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
        body: <p><strong>Revoke key</strong> bans a leaf&rsquo;s current hardware key. <strong>Reissue</strong> adopts an already-provisioned replacement token and authenticates an update to affected stores. These are related, but distinct, operations.</p>,
        tab: "organization",
        target: () => ['[data-testid="tree-node-M.A.1"]', '[data-panel="organization"]'],
      },
      {
        title: "Restructure is a two-person workflow",
        body: <p>The authority proposes the next public generation here. A non-root proposal remains pending until its parent switches in and countersigns with that parent&rsquo;s device passphrase.</p>,
        tab: "organization",
        target: () => ['[data-testid="restructure-admin"]'],
      },
      {
        title: "Parent approval is enforced at unlock",
        body: <p>A file&rsquo;s Properties dialog reports whether <code>unlock_approval = parent</code>. It is policy, not a toggle in this lab; when required, the approving parent&rsquo;s participation is part of the real unlock path.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
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
      },
      {
        title: "Establish, remove, or deny",
        body: <p><strong>Establish bridge</strong> changes each endpoint&rsquo;s visible slice. The Established and Whitelist lists then expose <strong>Remove</strong> and <strong>Deny</strong>. This same private bridge supports file signing and verification.</p>,
        tab: "organization",
        target: () => ['[data-testid="bridges"]'],
      },
      {
        title: "Remote device transfer is not a GUI action",
        body: <p>Device publish, relay-send, collect, and finalize are intentionally not buttons in this lab. They use opaque device letters in the same in-process relay; use the Terminal to explore the CLI. The read-only relay counters show those letters without opening them.</p>,
        tab: "security",
        target: () => ['[data-testid="relay-status"]'],
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
      },
      {
        title: "Bring the required devices online",
        body: <p>Insert enough separate drives in <strong>USB devices</strong>. Slots moved onto the same container may satisfy logical shares, but still contribute only one physical device.</p>,
        tab: "usb",
        target: () => ['[data-panel="usb"]'],
      },
      {
        title: "Try it: unlock successfully",
        body: <p>Return to Files and open the protected file. A successful attempt decrypts it; a denied attempt leaves a precise trace so you can adjust the connected drives and retry.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
        requiredKind: "access",
        isDone: (_snapshot, latest) => latest?.kind === "access" && latest.outcome === "granted",
      },
      {
        title: "Audit the decision",
        body: <p>The Activity panel records the command and every custody, quorum, ghost, expiry, and approval check that led to the result.</p>,
        tab: "activity",
        target: () => ['[data-panel="activity"]'],
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
      },
      {
        title: "Try the unlock path",
        body: <p>Your new file appears directly below the form. Enter the same password and PIN, if selected, then press <strong>Unlock</strong>.</p>,
        tab: "security",
        target: () => ['[data-testid="password-files"]'],
        requiredKind: "password-access",
        isDone: (_snapshot, latest) => latest?.kind === "password-access" && latest.outcome === "granted",
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
      },
      {
        title: "Try it: create a recipient-bound export",
        body: <p>On the password file you just created, open <strong>Export…</strong>, choose another user, and enter the file password. The resulting <code>KQXB</code> is sealed to that recipient.</p>,
        tab: "security",
        target: () => ['[data-testid="password-files"]'],
        requiredKind: "export",
        isDone: (_snapshot, latest) => latest?.kind === "export" && latest.outcome === "granted",
      },
      {
        title: "Try it: create a bearer share link",
        body: <p>Open <strong>Share…</strong> on that file, choose its lifetime and optional PIN, and create it. The displayed token is the capability: possession of it, not lab identity, authorizes access.</p>,
        tab: "security",
        target: () => ['[data-testid="password-files"]'],
        requiredKind: "share-create",
        isDone: (_snapshot, latest) => latest?.kind === "share-create" && latest.outcome === "granted",
      },
      {
        title: "Try it: revoke the share",
        body: <p>Close the token viewer, then press <strong>Revoke</strong> beside the live share. Future redemption ends, while the independently sealed export bundle is unaffected.</p>,
        tab: "security",
        target: () => ['[data-testid="share-links"]'],
        requiredKind: "share-revoke",
        isDone: (_snapshot, latest) => latest?.kind === "share-revoke" && latest.outcome === "granted",
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
      },
      {
        title: "Try it: verify the signature",
        body: <p>The signature now appears under <strong>Signatures</strong>. Press <strong>Verify</strong> to check the artifact and registered signer key.</p>,
        tab: "security",
        target: () => ['[data-testid="signatures"]'],
        requiredKind: "verify",
        isDone: (_snapshot, latest) => latest?.kind === "verify" && latest.outcome === "granted",
      },
      {
        title: "Properties explains before you act",
        body: <p>Properties shows type, size, source, expiry, requirement tree, ghosts, custody mode, minimum devices, and parent approval without attempting an unlock.</p>,
        tab: "files",
        target: () => ['[data-testid="file-actions"]', '[data-panel="files"]'],
      },
      {
        title: "Expiry purges on first touch",
        body: <p>Some seeded files expire while the tab is open. Their timestamp updates passively; the first unlock attempt after expiry runs the real destructive purge, deleting ciphertext and its database row.</p>,
        tab: "files",
        target: () => ['[data-panel="files"]'],
      },
    ],
  },
  {
    id: "mailbox-decisions",
    category: "mailbox",
    title: "Reject & acknowledge",
    summary: "Exercise the rejection path and explicitly refresh a sender's acknowledgement state.",
    steps: [
      {
        title: "Try it: send a letter to reject",
        body: <p>Open the <strong>public</strong> folder, select a file, press <strong>Send…</strong>, and choose David. This creates this module&rsquo;s own letter, so it works independently of every other tutorial.</p>,
        tab: "files",
        target: () => ['[data-panel="files"]'],
        ensure: ensureActiveUserIsNot("david", "alice"),
        isDone: (_snapshot, latest) => wasSentTo(latest, "David"),
        remember: (snapshot) => ({ relayId: snapshot.sent[snapshot.sent.length - 1]?.relayId }),
      },
      {
        title: "Try it: become the recipient",
        body: <p>Switch to <strong>David</strong>, then insert David&rsquo;s USB if it is not already connected. His key is required to authenticate and answer the letter.</p>,
        target: () => ['[aria-label="Switch user"]'],
        ensure: ensureDrivesConnected("david"),
        requiredKind: "user",
        isDone: (snapshot) => snapshot.activeUser.id === "david",
      },
      {
        title: "Try it: reject the letter",
        body: <p>Press <strong>Reject</strong> on the new letter. Rejection opens and authenticates the envelope, records no received file, and sends a signed acknowledgement.</p>,
        tab: "mailbox",
        target: () => ['[data-testid^="inbox-"]', '[data-panel="mailbox"]'],
        requiredKind: "receive",
        isDone: (snapshot, latest, memory) => {
          const relayId = memory.relayId;
          return latest?.kind === "receive" && latest.outcome === "info" && typeof relayId === "number" &&
            snapshot.inbox.find((item) => item.relayId === relayId)?.status === "rejected";
        },
      },
      {
        title: "Try it: return to the sender",
        body: <p>Switch back to <strong>Alice</strong>, the sender of this module&rsquo;s letter.</p>,
        target: () => ['[aria-label="Switch user"]'],
        requiredKind: "user",
        isDone: (snapshot) => snapshot.activeUser.id === "alice",
      },
      {
        title: "Try it: collect the acknowledgement",
        body: <p>Select <strong>Sent</strong>, then click <strong>Check relay for acknowledgements</strong>. Refresh is a real relay action, not an automatic tutorial shortcut.</p>,
        tab: "mailbox",
        target: () => ['[data-testid="mailbox-refresh"]', '[data-panel="mailbox"]'],
        requiredKind: "receive",
        isDone: (_snapshot, latest) =>
          latest?.kind === "receive" &&
          latest.outcome === "info" &&
          (latest.title === "Inbox up to date" || latest.title.includes("new envelope")),
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
      },
    ],
  },
];
