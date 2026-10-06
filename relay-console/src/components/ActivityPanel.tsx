import type { RequestRecord } from "../api/types";

/** Every request this tab made, newest first: the console's trace. */
export function ActivityPanel({ records }: { records: RequestRecord[] }) {
  return (
    <section className="panel panel-wide log" data-panel="activity" aria-labelledby="activity-heading">
      <h2 id="activity-heading" className="panel-title">
        Activity
      </h2>
      <p className="small muted">
        Each request this page sent, by method, path, status and time. Headers and bodies are not kept, so no bearer
        ever appears here. The relay's own record of what happened is its log and its audit trail.
      </p>
      {records.length === 0 ? (
        <p className="empty">Nothing yet.</p>
      ) : (
        <ol>
          {records.map((record) => (
            <li key={record.seq} data-testid="activity-entry" data-ok={record.ok}>
              <span className={`outcome ${record.ok ? "outcome-ok" : "outcome-failed"}`}>{record.ok ? "ok" : "failed"}</span>{" "}
              <code>
                {record.method} {record.path}
              </code>{" "}
              <span className="muted small">
                {record.status === null ? "no answer" : `HTTP ${record.status}`} · {record.ms} ms · {record.at}
              </span>
              {record.ok ? null : <p className="small">{record.note}</p>}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
