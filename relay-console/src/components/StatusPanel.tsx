import { useCallback, useEffect, useState } from "react";
import type { Act } from "../App";
import { base64Length, sha256OfBase64 } from "../api/relay";

interface Identity {
  certificateSha256: string;
  certificateBytes: number;
  signatureBytes: number;
}

const POLL_MS = 15_000;

/** `GET /health`, `GET /ready` and `POST /provider-identity`, no key needed. */
export function StatusPanel({ act }: { act: Act }) {
  const [health, setHealth] = useState<string | null>(null);
  const [ready, setReady] = useState<{ status: string; store: string } | null>(null);
  const [identity, setIdentity] = useState<Identity | null | "missing">(null);
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [polling, setPolling] = useState(true);

  const refresh = useCallback(async () => {
    const h = await act("Status refreshed", (relay) => relay.health());
    setHealth(h ? h.status : null);
    setReady(await act("Status refreshed", (relay) => relay.ready()));
    setCheckedAt(new Date().toISOString());
  }, [act]);

  const challenge = useCallback(async () => {
    const answer = await act("Provider identity challenged", (relay) => relay.providerIdentity());
    if (!answer) {
      setIdentity("missing");
      return;
    }
    setIdentity({
      certificateSha256: await sha256OfBase64(answer.certificate),
      certificateBytes: base64Length(answer.certificate),
      signatureBytes: base64Length(answer.signature),
    });
  }, [act]);

  useEffect(() => {
    void refresh();
    void challenge();
  }, [refresh, challenge]);

  // /health and /ready are cheap and unauthenticated; a quiet poll keeps the
  // panel current while the tab is open, well inside the relay's per-client
  // allowance (600 requests a minute by default).
  useEffect(() => {
    if (!polling) return;
    const id = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(id);
  }, [polling, refresh]);

  return (
    <section className="panel" data-panel="relay" aria-labelledby="relay-heading">
      <h2 id="relay-heading" className="panel-title">
        Relay status
      </h2>
      <dl className="facts">
        <div>
          <dt>Origin</dt>
          <dd>
            <code>{window.location.origin}</code>
          </dd>
        </div>
        <div>
          <dt>
            Process (<code>GET /health</code>)
          </dt>
          <dd data-testid="status-health">
            <span className={`status-pill ${health === "ok" ? "status-ok" : "status-error"}`}>{health ?? "no answer"}</span>
          </dd>
        </div>
        <div>
          <dt>
            Store (<code>GET /ready</code>)
          </dt>
          <dd data-testid="status-ready">
            {ready ? (
              <>
                <span className="status-pill status-ok">{ready.status}</span> <code>{ready.store}</code>
              </>
            ) : (
              <span className="status-pill status-error">store unavailable</span>
            )}
          </dd>
        </div>
        <div>
          <dt>
            Provider identity (<code>POST /provider-identity</code>)
          </dt>
          <dd data-testid="status-identity">
            {identity === null ? (
              "not challenged yet"
            ) : identity === "missing" ? (
              <span className="status-pill status-error">no identity presented</span>
            ) : (
              <>
                <span className="status-pill status-ok">certificate presented</span>{" "}
                <span className="muted small">
                  {identity.certificateBytes} bytes, signature {identity.signatureBytes} bytes
                </span>
                <br />
                <span className="small">
                  SHA-256 <code className="hash">{identity.certificateSha256}</code>
                </span>
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Last checked</dt>
          <dd>{checkedAt ?? "—"}</dd>
        </div>
      </dl>
      <p className="small muted">
        The certificate digest is for comparing with the <code>provider.kqcert</code> you installed. This page does not
        verify the certificate or the signature against the KeyQuorum root; <code>keyquorum loadkey</code> does, and
        that is the check that matters to customers.
      </p>
      <div className="button-row">
        <button type="button" className="btn" data-testid="status-refresh" onClick={() => void refresh()}>
          Refresh
        </button>
        <button type="button" className="btn" onClick={() => void challenge()}>
          Challenge identity again
        </button>
        <label className="checkbox-row">
          <input type="checkbox" checked={polling} onChange={(event) => setPolling(event.target.checked)} />
          Refresh every {POLL_MS / 1000} s
        </label>
      </div>
    </section>
  );
}
