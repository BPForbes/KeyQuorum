import { useState } from "react";
import type { Session } from "../api/types";

/** Who this tab is to the relay, like the lab's active user. */
export function SessionPanel({ session, onSignIn }: { session: Session | null; onSignIn: (token: string) => Promise<void> }) {
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <section className="panel session" aria-labelledby="session-heading">
      <div>
        <h2 id="session-heading" className="panel-title">
          Signed-in key
        </h2>
        {session ? (
          <>
            <p className="session-name">
              <strong data-testid="session-id">{session.id === null ? "key" : `key #${session.id}`}</strong>{" "}
              <code data-testid="session-scope">{session.scope}</code>
            </p>
            <p className="muted">{session.label ? `label ${session.label}` : "no label"}</p>
            <p className="muted small">
              {session.recipientFingerprint ? (
                <>
                  bound to recipient <code>{session.recipientFingerprint}</code>
                </>
              ) : (
                "not bound to a recipient"
              )}
            </p>
          </>
        ) : (
          <p className="muted">Not signed in. The status panel works without a key.</p>
        )}
      </div>
      {session ? null : (
        <form
          className="signin-form"
          onSubmit={(event) => {
            event.preventDefault();
            const token = key.trim();
            if (!token || busy) return;
            setBusy(true);
            onSignIn(token).finally(() => {
              setBusy(false);
              setKey("");
            });
          }}
        >
          <label htmlFor="signin-key">API key (an admin key for the full console)</label>
          <input
            id="signin-key"
            data-testid="signin-key"
            type="password"
            value={key}
            onChange={(event) => setKey(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="kq_…"
            required
          />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            Sign in
          </button>
          <p className="small muted">
            The key is checked with <code>POST /keycheck</code> and then sent as a bearer on each request, over this
            page's own origin. Paste it here rather than into a shell, where it would stay in your history.
          </p>
        </form>
      )}
    </section>
  );
}
