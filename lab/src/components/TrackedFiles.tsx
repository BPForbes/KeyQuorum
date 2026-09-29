// Tracked files on the Activity page. Every button here is one real
// `keyquorum file` command run as the active person (track, checkin, sign,
// countersign, merge, review, verify, share, receive, ack); the lab decides
// nothing. What each command wrote to the file's history appears in the
// activity log below as soon as it runs, and the revision list here is
// judged by the active person's own store.
import { useId, useState } from "react";
import type { Act } from "../App";
import type { ActionResult, Snapshot, TrackedFileView, TrackedRevisionView } from "../api/types";
import { FileViewer } from "./FileViewer";

const short = (id: string) => id.slice(0, 8);

/** Run a command whose output opens in the file viewer. */
type Report = (run: Parameters<Act>[0], title: string) => void;

/** `M.S.1` → `M.S`; the root has no parent. */
const parentOf = (label: string) => (label.includes(".") ? label.slice(0, label.lastIndexOf(".")) : null);

function TrackForm({ act, onTracked }: { act: Act; onTracked: (path: string) => void }) {
  const id = useId();
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  return (
    <form
      className="tracked-form"
      data-testid="history-track"
      onSubmit={(event) => {
        event.preventDefault();
        if (!name.trim()) return;
        const result = act((client) => client.historyTrack(name.trim(), text));
        const made = result?.snapshot.trackedFiles.find(
          (file) => file.name === name.trim() && file.owner === result.snapshot.activeUser.id,
        );
        if (result?.ok && made) {
          onTracked(made.path);
          setName("");
          setText("");
        }
      }}
    >
      <label htmlFor={`${id}-name`}>New tracked file</label>
      <input id={`${id}-name`} value={name} onChange={(event) => setName(event.target.value)} placeholder="notes.txt" />
      <label htmlFor={`${id}-text`} className="visually-hidden">
        First revision
      </label>
      <textarea
        id={`${id}-text`}
        value={text}
        onChange={(event) => setText(event.target.value)}
        rows={3}
        placeholder="First revision's text"
      />
      <button type="submit" className="btn btn-primary">
        Track and sign
      </button>
    </form>
  );
}

function RevisionRow({
  file,
  revision,
  me,
  act,
  report,
}: {
  file: TrackedFileView;
  revision: TrackedRevisionView;
  me: string;
  act: Act;
  report: Report;
}) {
  const mine = revision.author === me;
  const countersigner = parentOf(revision.author) === me;
  return (
    <li data-testid={`revision-${short(revision.id)}`} data-trust={revision.trust} data-head={revision.head}>
      <code>{short(revision.id)}</code> {revision.userLabel ?? revision.generatedLabel}{" "}
      <span className="muted small">
        by {revision.author}
        {revision.parents.length ? ` ← ${revision.parents.map(short).join(" + ")}` : " (root)"}
        {revision.head ? " · head" : ""}
      </span>{" "}
      <span className="badge">{revision.trust}</span>
      {revision.reason ? <span className="muted small"> {revision.reason}</span> : null}
      {file.destroyed ? null : (
        <button
          type="button"
          className="btn small-btn"
          aria-label={`View revision ${short(revision.id)}`}
          onClick={() => report((client) => client.historyViewRevision(file.path, revision.id), `${file.name} at ${short(revision.id)}`)}
        >
          View
        </button>
      )}
      {!file.destroyed && revision.parents.length > 0 ? (
        <button
          type="button"
          className="btn small-btn"
          aria-label={`Diff revision ${short(revision.id)}`}
          onClick={() => report((client) => client.historyDiff(file.path, undefined, revision.id), `Changes in ${short(revision.id)}`)}
        >
          Diff
        </button>
      ) : null}
      {revision.trust === "pending" && mine ? (
        <button
          type="button"
          className="btn small-btn"
          onClick={() => act((client) => client.historySign(file.path, revision.id))}
        >
          Sign revision
        </button>
      ) : null}
      {revision.trust === "pending" && countersigner ? (
        <button
          type="button"
          className="btn small-btn"
          title="keyquorum file countersign: approve as the author's direct parent"
          onClick={() => act((client) => client.historyCountersign(file.path, revision.id))}
        >
          Approve as parent
        </button>
      ) : null}
    </li>
  );
}

function EditForm({ file, act }: { file: TrackedFileView; act: Act }) {
  const id = useId();
  const head = file.revisions.filter((revision) => revision.head);
  const [text, setText] = useState(head.length === 1 ? (head[0].text ?? "") : "");
  const [signed, setSigned] = useState(true);
  const [label, setLabel] = useState("");
  if (file.forked) {
    return <p className="small muted">The history has two heads: merge them before checking in another edit.</p>;
  }
  return (
    <form
      className="tracked-form"
      data-testid="history-checkin"
      onSubmit={(event) => {
        event.preventDefault();
        const result = act((client) => client.historyCheckin(file.path, text, signed, label.trim() || undefined));
        if (result?.ok) setLabel("");
      }}
    >
      <label htmlFor={`${id}-text`}>Edit the current revision</label>
      <textarea id={`${id}-text`} value={text} onChange={(event) => setText(event.target.value)} rows={4} />
      <label htmlFor={`${id}-label`} className="visually-hidden">
        Revision label
      </label>
      <input
        id={`${id}-label`}
        value={label}
        onChange={(event) => setLabel(event.target.value)}
        placeholder="Short description (optional)"
      />
      <label className="checkbox-row">
        <input type="checkbox" checked={signed} onChange={(event) => setSigned(event.target.checked)} />
        Sign this edit with my slot
      </label>
      <button type="submit" className="btn">
        Check in
      </button>
    </form>
  );
}

function ExpiryForm({ file, act }: { file: TrackedFileView; act: Act }) {
  const id = useId();
  const [at, setAt] = useState("");
  return (
    <form
      className="tracked-form tracked-share"
      data-testid="history-expire"
      onSubmit={(event) => {
        event.preventDefault();
        if (at) act((client) => client.historyExpire(file.path, at));
      }}
    >
      <label htmlFor={`${id}-at`}>Expires (UTC)</label>
      <input id={`${id}-at`} type="datetime-local" value={at} onChange={(event) => setAt(event.target.value)} />
      <button type="submit" className="btn small-btn">
        Schedule expiry
      </button>
      <button
        type="button"
        className="btn small-btn"
        onClick={() => act((client) => client.historyExpire(file.path))}
      >
        Destroy content now
      </button>
    </form>
  );
}

function HistoryTools({
  file,
  snapshot,
  act,
  report,
}: {
  file: TrackedFileView;
  snapshot: Snapshot;
  act: Act;
  report: Report;
}) {
  const id = useId();
  const copies = snapshot.trackedFiles.filter((other) => other.fileId === file.fileId && other.path !== file.path);
  const [from, setFrom] = useState(copies[0]?.path ?? "");
  const me = snapshot.activeUser.label;
  const gates: { gate: "quorum" | "password"; id: number; label: string }[] = [
    ...snapshot.files
      .filter((candidate) => candidate.quorumFileId != null)
      .map((candidate) => ({ gate: "quorum" as const, id: candidate.quorumFileId as number, label: `${candidate.name} (quorum)` })),
    ...snapshot.passwordFiles
      .filter((candidate) => candidate.owner === me)
      .map((candidate) => ({ gate: "password" as const, id: candidate.id, label: `${candidate.name} (password)` })),
  ];
  const [gate, setGate] = useState(gates[0] ? `${gates[0].gate}:${gates[0].id}` : "");
  const linkName = (link: { gate: string; id: number }) =>
    gates.find((candidate) => candidate.gate === link.gate && candidate.id === link.id)?.label ?? `${link.gate} file ${link.id}`;
  return (
    <div className="tracked-tools" data-testid="history-tools">
      <div className="tracked-actions">
        <button type="button" className="btn small-btn" onClick={() => act((client) => client.historyExport(file.path))}>
          Export history snapshot
        </button>
        {file.snapshots.map((path) => (
          <button
            key={path}
            type="button"
            className="btn small-btn"
            onClick={() => report((client) => client.historyVerifySnapshot(file.path, path), `Check ${path.split("/").pop()}`)}
          >
            Check {path.split("/").pop()}
          </button>
        ))}
      </div>
      {copies.length > 0 && !file.destroyed ? (
        <form
          className="tracked-form tracked-share"
          data-testid="history-import"
          onSubmit={(event) => {
            event.preventDefault();
            if (from) act((client) => client.historyImport(file.path, from));
          }}
        >
          <label htmlFor={`${id}-from`}>Import from</label>
          <select id={`${id}-from`} value={from} onChange={(event) => setFrom(event.target.value)}>
            {copies.map((copy) => (
              <option key={copy.path} value={copy.path}>
                {copy.path}
              </option>
            ))}
          </select>
          <button type="submit" className="btn small-btn">
            Import copy
          </button>
        </form>
      ) : null}
      <form
        className="tracked-form tracked-share"
        data-testid="history-link"
        onSubmit={(event) => {
          event.preventDefault();
          const [kind, number] = gate.split(":");
          if (kind && number) act((client) => client.historyLink(file.path, kind as "quorum" | "password", Number(number), true));
        }}
      >
        <label htmlFor={`${id}-gate`}>Record unlocks of</label>
        <select id={`${id}-gate`} value={gate} onChange={(event) => setGate(event.target.value)}>
          {gates.map((candidate) => (
            <option key={`${candidate.gate}:${candidate.id}`} value={`${candidate.gate}:${candidate.id}`}>
              {candidate.label}
            </option>
          ))}
        </select>
        <button type="submit" className="btn small-btn" disabled={!gate}>
          Link gate
        </button>
      </form>
      {file.links.length > 0 ? (
        <ul className="tracked-links" data-testid="tracked-links">
          {file.links.map((link) => (
            <li key={`${link.gate}:${link.id}`}>
              {linkName(link)}{" "}
              <button
                type="button"
                className="btn small-btn"
                onClick={() => act((client) => client.historyLink(file.path, link.gate, link.id, false))}
              >
                Unlink
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function TrackedFileCard({
  file,
  snapshot,
  act,
  onView,
}: {
  file: TrackedFileView;
  snapshot: Snapshot;
  act: Act;
  onView: (result: ActionResult, title: string) => void;
}) {
  const id = useId();
  const me = snapshot.activeUser.label;
  const others = snapshot.users.filter((user) => user.id !== snapshot.activeUser.id);
  const [to, setTo] = useState(others[0]?.id ?? "");
  const [mergeLabel, setMergeLabel] = useState("");
  const heads = file.revisions.filter((revision) => revision.head).map((revision) => revision.id);
  const report = (run: Parameters<Act>[0], title: string) => {
    const result = act(run);
    if (result) onView(result, title);
  };
  return (
    <div className="tracked-card" data-testid="tracked-file" data-path={file.path} data-forked={file.forked}>
      <p>
        <strong>{file.name}</strong>{" "}
        <span className="muted small">
          scope {file.scope} · {file.historyLen} events · root <code>{short(file.historyRoot)}</code> · {file.path}
        </span>
        {file.forked ? <span className="badge"> forked</span> : null}
        {file.destroyed ? <span className="badge"> expired</span> : null}
      </p>
      {file.destroyed ? (
        <p className="small" data-testid="tracked-tombstone">
          Expired: the content of every revision was destroyed. The history and signatures remain, and any further
          attempt to use the content is recorded.
        </p>
      ) : file.expiresAt ? (
        <p className="small muted">Content is destroyed after {file.expiresAt}.</p>
      ) : null}
      <ol className="tracked-revisions" data-testid="tracked-revisions">
        {file.revisions.map((revision) => (
          <RevisionRow key={revision.id} file={file} revision={revision} me={me} act={act} report={report} />
        ))}
      </ol>
      <p className="small" data-testid="tracked-shareable">
        {file.destroyed
          ? "Nothing can be shared: the content is gone."
          : file.forked
          ? "Two heads: sharing waits for a merge."
          : file.shareable
            ? heads.includes(file.shareable)
              ? `Sharing sends the head, ${short(file.shareable)}.`
              : `The head is not trusted, so sharing sends ${short(file.shareable)}, the last trusted revision.`
            : "Nothing here is trusted yet, so nothing can be shared."}
      </p>
      <div className="tracked-actions">
        <button type="button" className="btn small-btn" onClick={() => report((client) => client.historyVerify(file.path), `Verify ${file.name}`)}>
          Verify history
        </button>
        {file.forked ? (
          <>
            <button type="button" className="btn small-btn" onClick={() => report((client) => client.historyReview(file.path), `Review ${file.name}`)}>
              Review the fork
            </button>
            <label htmlFor={`${id}-merge`} className="visually-hidden">
              Merge label
            </label>
            <input
              id={`${id}-merge`}
              value={mergeLabel}
              onChange={(event) => setMergeLabel(event.target.value)}
              placeholder="Merge label (optional)"
            />
            <button
              type="button"
              className="btn small-btn"
              onClick={() => act((client) => client.historyMerge(file.path, mergeLabel.trim() || undefined))}
            >
              Merge heads
            </button>
          </>
        ) : null}
      </div>
      <HistoryTools file={file} snapshot={snapshot} act={act} report={report} />
      {file.destroyed ? null : (
        <>
          <EditForm key={heads.join()} file={file} act={act} />
          <ExpiryForm file={file} act={act} />
        </>
      )}
      <form
        className="tracked-form tracked-share"
        data-testid="history-share"
        onSubmit={(event) => {
          event.preventDefault();
          if (to) act((client) => client.historyShare(file.path, to));
        }}
      >
        <label htmlFor={`${id}-to`}>Share with</label>
        <select id={`${id}-to`} value={to} onChange={(event) => setTo(event.target.value)}>
          {others.map((user) => (
            <option key={user.id} value={user.id}>
              {user.name} ({user.label})
            </option>
          ))}
        </select>
        <button type="submit" className="btn small-btn">
          Share file
        </button>
      </form>
    </div>
  );
}

function Letters({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const me = snapshot.activeUser.id;
  const mine = snapshot.trackedLetters.filter((letter) => letter.to === me || letter.from === me);
  if (mine.length === 0) return null;
  return (
    <div className="tracked-letters" data-testid="tracked-letters">
      <h4 className="small">Tracked-file letters</h4>
      <ul>
        {mine.map((letter) => (
          <li key={letter.id} data-testid={`tracked-letter-${letter.id}`} data-status={letter.status}>
            {letter.fileName}: {letter.fromName} → {letter.toName} <span className="badge">{letter.status}</span>
            {letter.to === me && letter.status === "waiting" ? (
              <>
                <button type="button" className="btn small-btn" onClick={() => act((client) => client.historyReceive(letter.id, true))}>
                  Accept {letter.fileName}
                </button>
                <button type="button" className="btn small-btn" onClick={() => act((client) => client.historyReceive(letter.id, false))}>
                  Refuse {letter.fileName}
                </button>
              </>
            ) : null}
            {letter.from === me && letter.status !== "waiting" && !letter.ackRecorded ? (
              <button type="button" className="btn small-btn" onClick={() => act((client) => client.historyAck(letter.id))}>
                Record the answer
              </button>
            ) : null}
            {letter.ackRecorded ? <span className="muted small"> · answer recorded</span> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function TrackedFiles({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const id = useId();
  const files = snapshot.trackedFiles;
  const [selected, setSelected] = useState<string>("");
  const [viewing, setViewing] = useState<{ result: ActionResult; title: string } | null>(null);
  const file = files.find((candidate) => candidate.path === selected) ?? files[0];
  return (
    <section className="tracked-files" data-testid="tracked-files" aria-labelledby={`${id}-heading`}>
      <h3 id={`${id}-heading`}>Tracked files</h3>
      <p className="small muted">
        Acting as {snapshot.activeUser.name} ({snapshot.activeUser.label}). Each button runs a real{" "}
        <code>keyquorum file</code> command with your slot; what it records appears in the log below.
      </p>
      <TrackForm act={act} onTracked={setSelected} />
      {files.length > 0 ? (
        <>
          <label htmlFor={`${id}-file`}>Tracked file</label>
          <select
            id={`${id}-file`}
            data-testid="tracked-select"
            value={file?.path ?? ""}
            onChange={(event) => setSelected(event.target.value)}
          >
            {files.map((candidate) => (
              <option key={candidate.path} value={candidate.path}>
                {candidate.name} — {candidate.path}
              </option>
            ))}
          </select>
        </>
      ) : null}
      {file ? (
        <TrackedFileCard
          key={file.path}
          file={file}
          snapshot={snapshot}
          act={act}
          onView={(result, title) => setViewing({ result, title })}
        />
      ) : null}
      <Letters snapshot={snapshot} act={act} />
      {viewing ? <FileViewer result={viewing.result} fileName={viewing.title} onClose={() => setViewing(null)} /> : null}
    </section>
  );
}
