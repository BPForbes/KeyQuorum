import { useCallback, useEffect, useRef, useState } from "react";
import { LabClient } from "./api/lab";
import { announceReady } from "./api/embed";
import type { ActionResult, Snapshot } from "./api/types";
import { ActiveUser } from "./components/ActiveUser";
import { ActivityPanel } from "./components/ActivityPanel";
import { Drives } from "./components/Drives";
import { FileExplorer } from "./components/FileExplorer";
import { Mailbox } from "./components/Mailbox";
import { OrgTree } from "./components/OrgTree";
import { Terminal } from "./components/Terminal";

type Boot = { state: "loading" } | { state: "ready" } | { state: "error"; message: string };

export type Act = (run: (client: LabClient) => ActionResult) => ActionResult | null;

const TABS = [
  ["organization", "Organization"],
  ["usb", "USB devices"],
  ["files", "Files"],
  ["mailbox", "Inbox"],
  ["activity", "Activity"],
  ["terminal", "Terminal"],
] as const;
type Tab = (typeof TABS)[number][0];

export function App() {
  const clientRef = useRef<LabClient | null>(null);
  const [boot, setBoot] = useState<Boot>({ state: "loading" });
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [last, setLast] = useState<ActionResult | null>(null);
  const [tab, setTab] = useState<Tab>("files");
  const [terminal, setTerminal] = useState<string[]>([
    "KeyQuorum Lab terminal — same state as the buttons above. Type `help`.",
  ]);

  useEffect(() => {
    let cancelled = false;
    LabClient.create()
      .then((client) => {
        if (cancelled) return;
        clientRef.current = client;
        setSnapshot(client.snapshot().snapshot);
        setBoot({ state: "ready" });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setBoot({ state: "error", message: error instanceof Error ? error.message : String(error) });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Announce only after the seeded lab has rendered.
  useEffect(() => {
    if (boot.state === "ready") announceReady(__BUILD_COMMIT__);
  }, [boot.state]);

  const act: Act = useCallback((run) => {
    const client = clientRef.current;
    if (!client) return null;
    try {
      const result = run(client);
      setSnapshot(result.snapshot);
      setLast(result);
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLast((previous) =>
        previous
          ? { ...previous, ok: false, message: `Lab error: ${message}`, trace: [], opened: null, output: [] }
          : null,
      );
      return null;
    }
  }, []);

  const reset = () => {
    const result = act((client) => client.reset());
    if (result) {
      setTerminal(["Lab reset to its seeded state."]);
    }
  };

  const switchUser = (id: string) => {
    act((client) => client.switchUser(id));
  };

  if (boot.state !== "ready" || !snapshot) {
    return (
      <div className="lab-boot" role="status" aria-live="polite">
        <p className="eyebrow">KeyQuorum Lab · Mock hardware environment</p>
        {boot.state === "error" ? (
          <>
            <h1>The lab could not start</h1>
            <p>{boot.message}</p>
            <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
              Reload
            </button>
          </>
        ) : (
          <>
            <h1>Seeding the lab…</h1>
            <p>Provisioning mock USB containers and Argon2id slot tokens in WebAssembly.</p>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="lab" data-lab-state="ready">
      <header className="lab-header">
        <div>
          <p className="eyebrow">KeyQuorum Lab · Mock hardware environment</p>
          <h1>KeyQuorum Security Lab</h1>
        </div>
        <div className="lab-header-actions">
          <span className="lab-build" title="Source commit of this build">
            build <code>{__BUILD_COMMIT__}</code>
          </span>
          <button type="button" className="btn btn-danger" onClick={reset}>
            Reset Lab
          </button>
        </div>
      </header>

      <p className="lab-disclaimer">
        The USB drives here are simulated in your browser, and every slot passphrase is a published demo value, so they
        give none of the physical protection real hardware keys do. What is real is the logic: quorum reconstruction,
        custody and device counting, parent approval, visibility, and sealed delivery all run KeyQuorum&rsquo;s own Rust
        code, compiled to WebAssembly. Nothing leaves this page.
      </p>

      <ActiveUser snapshot={snapshot} onSwitch={switchUser} />

      <p className={`lab-status ${last ? (last.ok ? "is-ok" : "is-error") : ""}`} role="status" aria-live="polite">
        {last?.message || "Pick a file and press Unlock, or insert another USB drive."}
      </p>

      <nav className="lab-tabs" aria-label="Lab sections">
        {TABS.map(([id, label]) => (
          <button
            key={id}
            type="button"
            className="lab-tab"
            aria-pressed={tab === id}
            onClick={() => setTab(id)}
          >
            {label}
            {id === "mailbox" && snapshot.inbox.some((item) => item.status === "new") ? " •" : ""}
          </button>
        ))}
      </nav>

      <main className="lab-grid" data-tab={tab}>
        <OrgTree snapshot={snapshot} />
        <Drives snapshot={snapshot} act={act} />
        <FileExplorer snapshot={snapshot} act={act} />
        <Mailbox snapshot={snapshot} act={act} />
        <ActivityPanel snapshot={snapshot} last={last} />
        <Terminal
          lines={terminal}
          onRun={(line) => {
            const result = act((client) => client.runCommand(line));
            setTerminal((previous) =>
              [...previous, `$ ${line}`, ...(result ? result.output : ["(lab error)"])].slice(-400),
            );
          }}
        />
      </main>

      <footer className="lab-footer">
        <p>
          Everything shown is synthetic demonstration data. Source:{" "}
          <a href="https://github.com/BPForbes/KeyQuorum" target="_blank" rel="noopener noreferrer">
            github.com/BPForbes/KeyQuorum
          </a>
        </p>
      </footer>
    </div>
  );
}
