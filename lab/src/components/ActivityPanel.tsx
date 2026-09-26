import type { ActionResult, Snapshot, TraceStep } from "../api/types";

const MARK: Record<TraceStep["status"], [string, string]> = {
  pass: ["✓", "Passed"],
  fail: ["✕", "Failed"],
  info: ["·", "Note"],
};

export function Trace({ steps }: { steps: TraceStep[] }) {
  return (
    <ol className="trace">
      {steps.map((step, index) => (
        <li key={index} data-status={step.status}>
          <span className="trace-mark" aria-hidden="true">
            {MARK[step.status][0]}
          </span>
          <span className="visually-hidden">{MARK[step.status][1]}: </span>
          {step.text}
        </li>
      ))}
    </ol>
  );
}

export function ActivityPanel({ snapshot, last }: { snapshot: Snapshot; last: ActionResult | null }) {
  const latest = snapshot.activity[0];
  const showing = last && last.trace.length > 0 ? last : null;
  return (
    <section className="panel panel-wide" data-panel="activity" aria-labelledby="activity-heading">
      <h2 id="activity-heading" className="panel-title">
        Activity and access trace
      </h2>
      {showing ? (
        <div className="trace-card" data-testid="access-trace" data-ok={showing.ok}>
          <p className="trace-title">{showing.message}</p>
          <Trace steps={showing.trace} />
          {latest?.command ? (
            <p className="small">
              Equivalent operation: <code>{latest.command}</code>
            </p>
          ) : null}
        </div>
      ) : (
        <p className="empty">Actions and the checks behind them appear here.</p>
      )}
      <details className="log">
        <summary>Full activity log ({snapshot.activity.length})</summary>
        <ol>
          {snapshot.activity.map((entry) => (
            <li key={entry.seq}>
              <p>
                <span className={`outcome outcome-${entry.outcome}`}>{entry.outcome}</span> {entry.title}{" "}
                <span className="muted small">· {entry.actor}</span>
              </p>
              {entry.trace.length > 0 ? <Trace steps={entry.trace} /> : null}
              {entry.command ? <code className="small">{entry.command}</code> : null}
            </li>
          ))}
        </ol>
      </details>
    </section>
  );
}
