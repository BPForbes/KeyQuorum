import { useState } from "react";
import type { Act } from "../App";
import type { KeyCheckResponse } from "../api/types";

const HEX_64 = /^[0-9a-f]{64}$/i;

/** `POST /keycheck` by stored hash: what a customer's `loadkey` left in
 * their store, never a bearer. No key is needed to ask. */
export function KeyCheckPanel({ act }: { act: Act }) {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<KeyCheckResponse | null>(null);
  const valid = HEX_64.test(hash.trim());
  return (
    <section className="panel" data-panel="check" aria-labelledby="check-heading">
      <h2 id="check-heading" className="panel-title">
        Key check
      </h2>
      <p className="small muted">
        A customer's store keeps <code>hex(SHA-256(raw))</code> of their key, and <code>keyquorum doctor</code> prints
        it. Paste that hash to ask the relay whether the key is live, as their own commands do before each request.
        Only a hash is accepted here: a bearer never belongs in a form that is not the sign-in.
      </p>
      <form
        className="check-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (!valid) return;
          void act("Key hash checked", (relay) => relay.checkHash(hash.trim().toLowerCase())).then((answer) => setResult(answer));
        }}
      >
        <label htmlFor="check-hash">Key hash (64 hex characters)</label>
        <input
          id="check-hash"
          data-testid="check-hash"
          value={hash}
          onChange={(event) => setHash(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="sha-256 of the bearer"
        />
        <button type="submit" className="btn" disabled={!valid}>
          Check
        </button>
      </form>
      {result ? (
        <dl className="facts" data-testid="check-result">
          <div>
            <dt>Live</dt>
            <dd>
              <span className={`status-pill ${result.valid ? "status-ok" : "status-error"}`}>{result.valid ? "yes" : "no"}</span>
            </dd>
          </div>
          {result.valid ? (
            <>
              <div>
                <dt>Key</dt>
                <dd>{result.id === undefined ? "—" : `#${result.id}`}</dd>
              </div>
              <div>
                <dt>Scope</dt>
                <dd>
                  <code>{result.scope ?? "—"}</code>
                </dd>
              </div>
              <div>
                <dt>Label</dt>
                <dd>{result.label ?? "—"}</dd>
              </div>
              <div>
                <dt>Recipient</dt>
                <dd>{result.recipient_fingerprint ? <code className="hash">{result.recipient_fingerprint}</code> : "—"}</dd>
              </div>
            </>
          ) : (
            <div>
              <dt>Why</dt>
              <dd className="muted">unknown, expired or revoked: the relay does not say which</dd>
            </div>
          )}
        </dl>
      ) : null}
    </section>
  );
}
