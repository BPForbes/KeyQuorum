import { useCallback, useEffect, useState } from "react";
import type { Act } from "../App";
import type { ApiKeyView, Session } from "../api/types";
import { Modal } from "./Modal";

function keyState(key: ApiKeyView): [string, string] {
  if (key.revoked_at) return ["revoked", "status-error"];
  if (key.expires_at && key.expires_at <= new Date().toISOString().slice(0, 19).replace("T", " ")) return ["expired", "status-muted"];
  return ["live", "status-ok"];
}

/** `GET /api-keys` and `POST /api-keys/{id}/revoke`: an admin key only. */
export function ApiKeysPanel({ session, act }: { session: Session | null; act: Act }) {
  const [keys, setKeys] = useState<ApiKeyView[] | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);
  const [confirm, setConfirm] = useState<ApiKeyView | null>(null);
  const admin = session?.scope === "admin";

  const refresh = useCallback(async () => {
    if (!admin) {
      setKeys(null);
      return;
    }
    setKeys(await act("API keys listed", (relay) => relay.listKeys()));
  }, [act, admin]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const revoke = async (key: ApiKeyView) => {
    setConfirm(null);
    // One action: revoke, then re-list, so the status line names the revocation.
    const listed = await act(`Key #${key.id} revoked`, async (relay) => {
      await relay.revokeKey(key.id);
      return relay.listKeys();
    });
    if (listed) setKeys(listed);
  };

  const visible = (keys ?? []).filter((key) => showRevoked || !key.revoked_at);

  return (
    <section className="panel panel-wide" data-panel="keys" aria-labelledby="keys-heading">
      <h2 id="keys-heading" className="panel-title">
        API keys
      </h2>
      <p className="small muted">
        What the relay holds about each key: id, scope, label, recipient binding and dates. Never a bearer, and
        never its hash. Minting and rotating happen on the host (<code>keyquorum host keys create|rotate</code>);
        here a key can only be listed and revoked.
      </p>
      {!session ? (
        <p className="empty">Sign in with an admin key to list keys.</p>
      ) : !admin ? (
        <p className="empty">
          This key's scope is <code>{session.scope}</code>; listing keys needs <code>admin</code>.
        </p>
      ) : (
        <>
          <div className="button-row">
            <button type="button" className="btn" data-testid="keys-refresh" onClick={() => void refresh()}>
              Refresh
            </button>
            <label className="checkbox-row">
              <input type="checkbox" checked={showRevoked} onChange={(event) => setShowRevoked(event.target.checked)} />
              Show revoked keys
            </label>
          </div>
          {keys === null ? (
            <p className="empty">Not loaded.</p>
          ) : visible.length === 0 ? (
            <p className="empty">No keys to show.</p>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Id</th>
                    <th>State</th>
                    <th>Scope</th>
                    <th>Label</th>
                    <th>Recipient</th>
                    <th>Created (UTC)</th>
                    <th>Expires</th>
                    <th>Last used</th>
                    <th>
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((key) => {
                    const [state, pill] = keyState(key);
                    const self = session.id === key.id;
                    return (
                      <tr key={key.id} data-testid={`api-key-${key.id}`} data-state={state}>
                        <td>#{key.id}</td>
                        <td>
                          <span className={`status-pill ${pill}`}>{state}</span>
                          {self ? <span className="tag">this tab</span> : null}
                        </td>
                        <td>
                          <code>{key.scope}</code>
                        </td>
                        <td>{key.label ?? <span className="muted">—</span>}</td>
                        <td>{key.recipient_fingerprint ? <code className="hash">{key.recipient_fingerprint}</code> : <span className="muted">—</span>}</td>
                        <td>{key.created_at}</td>
                        <td>{key.expires_at ?? <span className="muted">never</span>}</td>
                        <td>{key.last_used_at ?? <span className="muted">never</span>}</td>
                        <td>
                          {key.revoked_at ? (
                            <span className="muted small">revoked {key.revoked_at}</span>
                          ) : (
                            <button type="button" className="btn small-btn btn-danger" data-testid={`revoke-${key.id}`} onClick={() => setConfirm(key)}>
                              Revoke…
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      {confirm ? (
        <Modal title={`Revoke key #${confirm.id}?`} labelledBy="revoke-dialog-title" onClose={() => setConfirm(null)}>
          <p>
            Scope <code>{confirm.scope}</code>
            {confirm.label ? (
              <>
                , label <strong>{confirm.label}</strong>
              </>
            ) : null}
            . The relay refuses it from the next request on, records the revocation in the audit trail with this key as
            the actor, and signs the chain head at once. There is no undo: a replacement is minted on the host.
          </p>
          {session?.id === confirm.id ? (
            <p className="notice">This is the key this tab is signed in with. Revoking it signs you out.</p>
          ) : null}
          <div className="button-row">
            <button type="button" className="btn btn-danger" data-testid="revoke-confirm" onClick={() => void revoke(confirm)}>
              Revoke key #{confirm.id}
            </button>
            <button type="button" className="btn" onClick={() => setConfirm(null)}>
              Keep it
            </button>
          </div>
        </Modal>
      ) : null}
    </section>
  );
}
