import { useCallback, useEffect, useState } from "react";
import type { Act } from "../App";
import type { ApiKeyEvent, Session } from "../api/types";

const short = (hash: string) => hash.slice(0, 12);

/** `GET /audit/api-keys`: every event for an admin key, own events otherwise. */
export function AuditPanel({ session, act }: { session: Session | null; act: Act }) {
  const [events, setEvents] = useState<ApiKeyEvent[] | null>(null);
  const [filter, setFilter] = useState("");

  const refresh = useCallback(async () => {
    if (!session) {
      setEvents(null);
      return;
    }
    setEvents(await act("Audit trail read", (relay) => relay.auditEvents()));
  }, [act, session]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const text = filter.trim().toLowerCase();
  const visible = (events ?? [])
    .filter(
      (event) =>
        !text ||
        [String(event.key_id), event.event, event.actor, event.related_key_id === null ? "" : String(event.related_key_id)].some((field) =>
          field.toLowerCase().includes(text),
        ),
    )
    .sort((a, b) => b.id - a.id);

  return (
    <section className="panel panel-wide" data-panel="audit" aria-labelledby="audit-heading">
      <h2 id="audit-heading" className="panel-title">
        Audit trail
      </h2>
      <p className="small muted">
        The relay's <code>api_key_events</code>: who created, rotated or revoked which key, and when. Each row's{" "}
        <code>entry_hash</code> is its link in the hash chain the relay key signs. An admin key sees every event, any
        other key only the events about itself. Verification against the relay key and your checkpoints runs on the
        host (<code>keyquorum host keys events --verify</code>), not here.
      </p>
      {!session ? (
        <p className="empty">Sign in to read the audit trail.</p>
      ) : (
        <>
          <div className="button-row">
            <button type="button" className="btn" data-testid="audit-refresh" onClick={() => void refresh()}>
              Refresh
            </button>
            <label htmlFor="audit-filter" className="visually-hidden">
              Filter events
            </label>
            <input
              id="audit-filter"
              className="filter"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="Filter by key id, event or actor"
            />
            <span className="muted small">
              {visible.length} of {events?.length ?? 0}
            </span>
          </div>
          {events === null ? (
            <p className="empty">Not loaded.</p>
          ) : visible.length === 0 ? (
            <p className="empty">No events.</p>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Row</th>
                    <th>When (UTC)</th>
                    <th>Event</th>
                    <th>Key</th>
                    <th>Actor</th>
                    <th>Related key</th>
                    <th>Entry hash</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((event) => (
                    <tr key={event.id} data-testid="audit-event" data-event={event.event}>
                      <td>{event.id}</td>
                      <td>{event.occurred_at}</td>
                      <td>
                        <code>{event.event}</code>
                      </td>
                      <td>#{event.key_id}</td>
                      <td>
                        <code>{event.actor}</code>
                      </td>
                      <td>{event.related_key_id === null ? <span className="muted">—</span> : `#${event.related_key_id}`}</td>
                      <td>
                        <code className="hash" title={event.entry_hash}>
                          {short(event.entry_hash)}…
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}
