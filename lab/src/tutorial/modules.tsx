// Content for the guided tutorials (the "Tutorials" button in the lab
// header). Each module is a short, self-contained walkthrough of one part
// of the lab; a visitor picks whichever module covers what they want to
// learn and is never required to work through the others. A step with
// `isDone` is "gated": the tooltip stays put, describing a real action to
// take, until that action actually happens (checked against the live
// snapshot / activity log) — it does not just advance on a timer or a
// "Next" click standing in for the real thing.
import type { ReactNode } from "react";
import type { Tab } from "../App";
import type { ActivityView, Snapshot } from "../api/types";

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
  /** Undefined means "read this, then click Next." Defined means "do this to advance." */
  isDone?: (snapshot: Snapshot, latest: ActivityView | undefined) => boolean;
}

export interface TutorialModule {
  id: string;
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

export const TUTORIALS: TutorialModule[] = [
  {
    id: "identities-and-drives",
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
        isDone: (_snapshot, latest) => wasSentTo(latest, "David"),
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
        isDone: (_snapshot, latest) => wasReceived(latest),
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
];
