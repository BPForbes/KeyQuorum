import { useCallback, useEffect, useRef, useState } from "react";
import { RelayClient, RelayError } from "./api/relay";
import type { RequestRecord, Session } from "./api/types";
import { ActivityPanel } from "./components/ActivityPanel";
import { ApiKeysPanel } from "./components/ApiKeysPanel";
import { AuditPanel } from "./components/AuditPanel";
import { DevicesPanel } from "./components/DevicesPanel";
import { KeyCheckPanel } from "./components/KeyCheckPanel";
import { SessionPanel } from "./components/SessionPanel";
import { StatusPanel } from "./components/StatusPanel";
import { TreesPanel } from "./components/TreesPanel";

type Boot = { state: "loading" } | { state: "ready" } | { state: "error"; message: string };

export interface Outcome {
  ok: boolean;
  message: string;
}

/**
 * Run one console action against the relay and report its outcome in the
 * status line, the way the lab's `act` runs one command per click. A 401
 * signs the tab out, because the relay no longer accepts its key.
 */
export type Act = <T>(what: string, run: (client: RelayClient) => Promise<T>) => Promise<T | null>;

const TABS = [
  ["relay", "Relay"],
  ["keys", "API keys"],
  ["audit", "Audit trail"],
  ["check", "Key check"],
  ["trees", "Trees"],
  ["devices", "Devices"],
  ["activity", "Activity"],
] as const;
export type Tab = (typeof TABS)[number][0];

/** Newest first; the Activity panel is a window, not a log. */
const MAX_RECORDS = 200;

export function App() {
  const [records, setRecords] = useState<RequestRecord[]>([]);
  const clientRef = useRef<RelayClient | null>(null);
  if (clientRef.current === null) {
    clientRef.current = new RelayClient(null, (entry) =>
      setRecords((previous) => [entry, ...previous].slice(0, MAX_RECORDS)),
    );
  }
  const [boot, setBoot] = useState<Boot>({ state: "loading" });
  const [session, setSession] = useState<Session | null>(null);
  const [last, setLast] = useState<Outcome | null>(null);
  const [tab, setTab] = useState<Tab>("relay");

  useEffect(() => {
    let cancelled = false;
    const client = clientRef.current;
    if (!client) return;
    client
      .health()
      .then(() => {
        if (!cancelled) setBoot({ state: "ready" });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setBoot({ state: "error", message: error instanceof Error ? error.message : String(error) });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const signOut = useCallback((message: string) => {
    clientRef.current?.setToken(null);
    setSession(null);
    setLast({ ok: false, message });
  }, []);

  const act: Act = useCallback(
    async (what, run) => {
      const client = clientRef.current;
      if (!client) return null;
      try {
        const result = await run(client);
        setLast({ ok: true, message: what });
        return result;
      } catch (error) {
        if (error instanceof RelayError && error.unauthorized && client.signedIn) {
          signOut(`${what}: the relay no longer accepts this key (401). Signed out.`);
          return null;
        }
        const detail = error instanceof Error ? error.message : String(error);
        const retry = error instanceof RelayError && error.retryAfterSeconds ? ` Retry after ${error.retryAfterSeconds} s.` : "";
        setLast({ ok: false, message: `${what}: ${detail}${retry}` });
        return null;
      }
    },
    [signOut],
  );

  const signIn = async (token: string) => {
    const client = clientRef.current;
    if (!client) return;
    const check = await act("Signed in", (relay) => relay.checkToken(token));
    if (!check) return;
    if (!check.valid) {
      setLast({ ok: false, message: "The relay does not accept that key (unknown, expired or revoked)." });
      return;
    }
    client.setToken(token);
    setSession({
      id: check.id ?? null,
      scope: check.scope ?? "unknown",
      label: check.label ?? null,
      recipientFingerprint: check.recipient_fingerprint ?? null,
    });
  };

  if (boot.state !== "ready") {
    return (
      <div className="console-boot" role="status" aria-live="polite">
        <p className="eyebrow">KeyQuorum Relay · Operator console</p>
        {boot.state === "error" ? (
          <>
            <h1>The relay did not answer</h1>
            <p>{boot.message}</p>
            <p className="muted small">
              This page is served by the relay and talks only to it, at <code>{window.location.origin}</code>.
            </p>
            <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
              Reload
            </button>
          </>
        ) : (
          <>
            <h1>Reaching the relay…</h1>
            <p>
              Asking <code>GET /health</code> at <code>{window.location.origin}</code>.
            </p>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="console" data-console-state="ready">
      <header className="console-header">
        <div>
          <p className="eyebrow">KeyQuorum Relay · Operator console</p>
          <h1>KeyQuorum Relay Console</h1>
        </div>
        <div className="console-header-actions">
          <span className="console-build" title="Source commit of this build">
            build <code>{__BUILD_COMMIT__}</code>
          </span>
          <a className="btn" href="/swagger-ui/" target="_blank" rel="noreferrer">
            OpenAPI (Swagger UI)
          </a>
          {session ? (
            <button type="button" className="btn btn-danger" onClick={() => signOut("Signed out. The key was only ever in this tab's memory.")}>
              Sign out
            </button>
          ) : null}
        </div>
      </header>

      <p className="console-disclaimer">
        This console is served by the relay at <code>{window.location.origin}</code> and talks only to that relay. The
        API key you sign in with stays in this tab's memory until you sign out or close the tab; it is never stored in
        the browser. What you can see and do is exactly what the relay's HTTP API allows that key: list and revoke keys
        and read the whole audit trail with an <code>admin</code> key, or only your own key's events with any other.
        Minting and rotating keys stay host-local commands (<code>keyquorum host keys</code>); no page can do them.
      </p>

      <SessionPanel session={session} onSignIn={signIn} />

      <p className={`console-status ${last ? (last.ok ? "is-ok" : "is-error") : ""}`} role="status" aria-live="polite">
        {last?.message || (session ? "Pick a panel." : "Sign in with an API key, or watch the relay's status without one.")}
      </p>

      <nav className="console-tabs" aria-label="Console sections">
        {TABS.map(([id, label]) => (
          <button key={id} type="button" className="console-tab" aria-pressed={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </nav>

      <main className="console-grid" data-tab={tab}>
        <StatusPanel act={act} />
        <ApiKeysPanel session={session} act={act} />
        <AuditPanel session={session} act={act} />
        <KeyCheckPanel act={act} />
        <TreesPanel session={session} act={act} />
        <DevicesPanel session={session} act={act} />
        <ActivityPanel records={records} />
      </main>

      <footer className="console-footer">
        <p>
          The relay never unseals a letter, and this page never asks it to: a mailbox's contents are visible to
          nobody but the key they were sealed to. For deployment and secret handling see the operator runbook,{" "}
          <code>docs/operator/relay-deployment.md</code>.
        </p>
      </footer>
    </div>
  );
}
