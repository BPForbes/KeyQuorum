import { useState } from "react";
import type { Act } from "../App";
import { TrackedFiles } from "./TrackedFiles";
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

interface Narrow {
  /** A tracked file's id, or "" for every file. */
  fileId: string;
  /** Text matched against a revision's id, generated label or user label. */
  revision: string;
}

/** Only history entries belong to a category; the rest show under All. */
function matches(entry: ActivityView, filter: Filter, narrow: Narrow = { fileId: "", revision: "" }) {
  if (filter !== "all" && entry.historyCategory !== filter) return false;
  if (narrow.fileId && entry.fileId !== narrow.fileId) return false;
  const text = narrow.revision.trim().toLowerCase();
  if (!text) return true;
  return [entry.revisionId, entry.generatedLabel, entry.userLabel].some((field) => field?.toLowerCase().includes(text));
}

function HistoryEntry({ entry }: { entry: ActivityView }) {
  // The person's own description leads; the generated label and the short
  // hash follow. Commands always take the full id.
  const facts: [string, string | undefined][] = [
    ["File", entry.fileName],
    ["Label", entry.userLabel],
    ["Generated label", entry.generatedLabel],
    ["Revision", entry.revisionId ? short(entry.revisionId) : undefined],
    ["Parents", entry.parentRevisionIds?.length ? entry.parentRevisionIds.map(short).join(" + ") : undefined],
    ["Trust when recorded", entry.finalizationState],
    ["History root", entry.historyRoot ? short(entry.historyRoot) : undefined],
  ];
  return (
    <details className="history-entry" data-testid="history-entry" data-event={entry.historyEventType}>
      <summary>
        <span className={`outcome outcome-${entry.outcome}`}>{entry.outcome}</span> {entry.title}{" "}
        <span className="muted small">· {entry.actor}</span>
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
  // Grouped by the stable file id, so two files with the same name stay apart.
  const files = new Map<string, { name: string; revisions: [string, ActivityView][] }>();
  for (const node of nodes.entries()) {
    const key = node[1].fileId ?? node[1].fileName ?? "";
    const group = files.get(key) ?? { name: node[1].fileName ?? "", revisions: [] };
    group.revisions.push(node);
    files.set(key, group);
  }
  return (
    <div className="revision-graph" data-testid="revision-graph">
      {[...files.entries()].map(([key, { name, revisions }]) => (
        <section key={key} data-file-id={key}>
          <h3 className="small">{name}</h3>
          <ol>
            {revisions.map(([id, entry]) => (
              <li key={id} data-state={entry.finalizationState}>
                {entry.userLabel ? <>{entry.userLabel} · </> : null}
                {entry.generatedLabel} <code>{short(id)}</code>
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
  const [narrow, setNarrow] = useState<Narrow>({ fileId: "", revision: "" });
  const narrowed = narrow.fileId !== "" || narrow.revision.trim() !== "";
  // A file or revision filter only concerns tracked-file entries.
  const visible = snapshot.activity.filter((entry) => (narrowed && entry.kind !== "history" ? false : matches(entry, filter, narrow)));
  const historyEntries = snapshot.activity.filter((entry) => entry.kind === "history");
  const trackedNames = new Map<string, string>();
  for (const entry of historyEntries) if (entry.fileId && entry.fileName) trackedNames.set(entry.fileId, entry.fileName);
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
      <TrackedFiles snapshot={snapshot} act={act} />
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
              onClick={() => {
                setFilter(option.id);
                act((client) => client.noteUi("history-filter", `Showed ${option.label} activity`));
              }}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="tracked-form" data-testid="history-narrow">
          <label htmlFor="history-file-filter">File</label>
          <select
            id="history-file-filter"
            value={narrow.fileId}
            onChange={(event) => setNarrow({ ...narrow, fileId: event.target.value })}
          >
            <option value="">Every file</option>
            {[...trackedNames.entries()].map(([id, name]) => (
              <option key={id} value={id}>
                {name} ({short(id)})
              </option>
            ))}
          </select>
          <label htmlFor="history-revision-filter">Revision</label>
          <input
            id="history-revision-filter"
            type="text"
            placeholder="id, label or description"
            value={narrow.revision}
            onChange={(event) => setNarrow({ ...narrow, revision: event.target.value })}
          />
        </div>
        {(filter !== "all" || narrowed) && visible.length === 0 ? (
          <p className="empty">
            {narrowed ? "Nothing matches these filters yet." : `Nothing under ${FILTERS.find((f) => f.id === filter)?.label} yet.`}
          </p>
        ) : null}
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
        <RevisionGraph entries={historyEntries.filter((entry) => matches(entry, filter, narrow))} />
      </details>
    </section>
  );
}
