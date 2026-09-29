import { useState } from "react";
import type { Act } from "../App";
import type { ActionResult, ActivityView, HistoryCategory, Snapshot, TraceStep } from "../api/types";

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

type Filter = "all" | HistoryCategory;

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "file", label: "Tracked File" },
  { id: "revision", label: "Revision" },
  { id: "security", label: "Security" },
  { id: "sharing", label: "Sharing" },
  { id: "conflict", label: "Conflict" },
];

const short = (id: string) => id.slice(0, 8);

/** Only history entries belong to a category; the rest show under All. */
function matches(entry: ActivityView, filter: Filter) {
  return filter === "all" || entry.historyCategory === filter;
}

function HistoryEntry({ entry }: { entry: ActivityView }) {
  const facts: [string, string | undefined][] = [
    ["File", entry.fileName],
    ["Revision", entry.revisionId ? short(entry.revisionId) : undefined],
    ["Generated label", entry.generatedLabel],
    ["Label", entry.userLabel],
    ["Parents", entry.parentRevisionIds?.length ? entry.parentRevisionIds.map(short).join(" + ") : undefined],
    ["Trust now", entry.finalizationState],
    ["Review", entry.reviewState],
    ["History root", entry.historyRoot ? short(entry.historyRoot) : undefined],
  ];
  return (
    <details className="history-entry" data-testid="history-entry" data-event={entry.historyEventType}>
      <summary>
        <span className={`outcome outcome-${entry.outcome}`}>{entry.outcome}</span> {entry.title}{" "}
        <span className="muted small">· {entry.actor}</span>
        {entry.reviewState ? <span className="badge"> {entry.reviewState}</span> : null}
      </summary>
      <dl className="history-facts">
        {facts
          .filter(([, value]) => value)
          .map(([name, value]) => (
            <div key={name}>
              <dt>{name}</dt>
              <dd>{value}</dd>
            </div>
          ))}
      </dl>
      {entry.trace.length > 0 ? <Trace steps={entry.trace} /> : null}
      {entry.command ? <code className="small">{entry.command}</code> : null}
    </details>
  );
}

/** The revisions the visible history entries mention, and how they connect. */
function RevisionGraph({ entries }: { entries: ActivityView[] }) {
  const nodes = new Map<string, ActivityView>();
  // The snapshot is newest first; keep the earliest entry naming each
  // revision so the list reads oldest to newest.
  for (const entry of [...entries].reverse()) {
    if (entry.revisionId && entry.generatedLabel && !nodes.has(entry.revisionId)) nodes.set(entry.revisionId, entry);
  }
  if (nodes.size === 0) return null;
  const files = new Map<string, [string, ActivityView][]>();
  for (const node of nodes.entries()) {
    const name = node[1].fileName ?? "";
    files.set(name, [...(files.get(name) ?? []), node]);
  }
  return (
    <div className="revision-graph" data-testid="revision-graph">
      {[...files.entries()].map(([name, revisions]) => (
        <section key={name}>
          <h3 className="small">{name}</h3>
          <ol>
            {revisions.map(([id, entry]) => (
              <li key={id} data-state={entry.finalizationState}>
                <code>{short(id)}</code> {entry.generatedLabel}
                {entry.userLabel ? <> · {entry.userLabel}</> : null}
                {entry.parentRevisionIds?.length ? (
                  <span className="muted small"> ← {entry.parentRevisionIds.map(short).join(" + ")}</span>
                ) : (
                  <span className="muted small"> (root)</span>
                )}
                {entry.finalizationState ? <span className="badge"> {entry.finalizationState}</span> : null}
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}

export function ActivityPanel({ snapshot, last, act }: { snapshot: Snapshot; last: ActionResult | null; act: Act }) {
  const latest = snapshot.activity[0];
  const [filter, setFilter] = useState<Filter>("all");
  const visible = snapshot.activity.filter((entry) => matches(entry, filter));
  const historyEntries = snapshot.activity.filter((entry) => entry.kind === "history");
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
      <details className="log" onToggle={(event) => {
        if (event.currentTarget.open) act((client) => client.noteUi("activity-expand", "Expanded the full activity log"));
      }}>
        <summary>Full activity log ({snapshot.activity.length})</summary>
        <div className="chips" role="group" aria-label="Filter activity">
          {FILTERS.map((option) => (
            <button
              key={option.id}
              type="button"
              className="chip"
              aria-pressed={filter === option.id}
              onClick={() => setFilter(option.id)}
            >
              {option.label}
            </button>
          ))}
        </div>
        {filter !== "all" && visible.length === 0 ? <p className="empty">Nothing under {FILTERS.find((f) => f.id === filter)?.label} yet.</p> : null}
        <ol>
          {visible.map((entry) => (
            <li key={entry.seq} data-kind={entry.kind}>
              {entry.kind === "history" ? (
                <HistoryEntry entry={entry} />
              ) : (
                <>
                  <p>
                    <span className={`outcome outcome-${entry.outcome}`}>{entry.outcome}</span> {entry.title}{" "}
                    <span className="muted small">· {entry.actor}</span>
                  </p>
                  {entry.trace.length > 0 ? <Trace steps={entry.trace} /> : null}
                  {entry.command ? <code className="small">{entry.command}</code> : null}
                </>
              )}
            </li>
          ))}
        </ol>
        {filter !== "all" ? <RevisionGraph entries={historyEntries.filter((entry) => matches(entry, filter))} /> : <RevisionGraph entries={historyEntries} />}
      </details>
    </section>
  );
}
