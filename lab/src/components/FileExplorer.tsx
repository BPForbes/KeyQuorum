import { useEffect, useState } from "react";
import type { Act } from "../App";
import type { FileAccess, FileView, OpenedFile, RequirementNode, Snapshot } from "../api/types";
import { SendDialog } from "./SendDialog";

const FOLDERS = ["public", "engineering", "accounting", "executive", "received"];

export const ACCESS_TEXT: Record<FileAccess, string> = {
  public: "Public",
  holder: "You hold a share",
  oversight: "You oversee a holder",
  lineage: "Your manager holds a share",
  none: "Not a participant",
};

function Requirement({ node }: { node: RequirementNode }) {
  if (node.threshold === null) {
    return (
      <li>
        <code>{node.label}</code> {node.holder ?? ""}
      </li>
    );
  }
  return (
    <li>
      <strong>
        {node.threshold} of {node.children.length}
      </strong>{" "}
      ({node.label}):
      <ul>
        {node.children.map((child) => (
          <Requirement key={child.label} node={child} />
        ))}
      </ul>
    </li>
  );
}

function FileDetail({
  file,
  snapshot,
  act,
  opened,
  onClose,
}: {
  file: FileView;
  snapshot: Snapshot;
  act: Act;
  opened: OpenedFile | null;
  onClose: () => void;
}) {
  const [sending, setSending] = useState(false);
  useEffect(() => setSending(false), [file.id, snapshot.activeUser.id]);
  const showing = opened && opened.name === file.name ? opened : null;
  return (
    <div className="file-detail" aria-labelledby="file-detail-heading">
      <h3 id="file-detail-heading">
        {file.name} <span className="tag">{ACCESS_TEXT[file.access]}</span>
      </h3>
      <p>{file.lesson}</p>
      {file.receivedFrom ? <p className="small">Received from {file.receivedFrom}.</p> : null}
      {file.requirement ? (
        <div className="small">
          <p>Access requirement:</p>
          <ul className="requirement">
            <Requirement node={file.requirement} />
          </ul>
          {file.policy ? (
            <p>
              Custody <strong>{file.policy.custody}</strong> · minimum physical devices{" "}
              <strong>{file.policy.minimumDevices}</strong> · parent approval{" "}
              <strong>{file.policy.approval === "parent" ? "required" : "not required"}</strong>
            </p>
          ) : null}
          {file.quorumFileId !== null ? (
            <p className="muted">
              <code>keyquorum access quorum --status --id {file.quorumFileId}</code>
            </p>
          ) : null}
        </div>
      ) : (
        <p className="small">No key tree protects this file.</p>
      )}
      <div className="button-row">
        <button type="button" className="btn btn-primary" onClick={() => act((client) => client.unlockFile(file.id))}>
          {file.protection === "public" ? "Open" : "Unlock"}
        </button>
        <button type="button" className="btn" onClick={() => setSending(true)} aria-expanded={sending}>
          Send…
        </button>
        {showing ? (
          <button type="button" className="btn" onClick={onClose}>
            Close file
          </button>
        ) : null}
      </div>
      {sending ? (
        <SendDialog
          file={file}
          snapshot={snapshot}
          onCancel={() => setSending(false)}
          onSend={(recipient) => {
            const result = act((client) => client.sendFile(file.id, recipient));
            if (result?.ok) setSending(false);
          }}
        />
      ) : null}
      {showing ? (
        <figure className="opened">
          <figcaption>
            {showing.name} — decrypted in this tab
          </figcaption>
          <pre data-testid="opened-file">{showing.text}</pre>
        </figure>
      ) : null}
    </div>
  );
}

export function FileExplorer({
  snapshot,
  act,
  opened,
  onClose,
}: {
  snapshot: Snapshot;
  act: Act;
  opened: OpenedFile | null;
  onClose: () => void;
}) {
  const [selected, setSelected] = useState<string>("architecture");
  const file = snapshot.files.find((candidate) => candidate.id === selected) ?? snapshot.files[0];
  return (
    <section className="panel panel-wide" data-panel="files" aria-labelledby="files-heading">
      <h2 id="files-heading" className="panel-title">
        File explorer
      </h2>
      <div className="explorer">
        <nav className="folders" aria-label="Files">
          {FOLDERS.map((folder) => {
            const files = snapshot.files.filter((candidate) => candidate.folder === folder);
            if (files.length === 0) return null;
            return (
              <div key={folder} className="folder">
                <p className="folder-name">/{folder}/</p>
                <ul>
                  {files.map((candidate) => (
                    <li key={candidate.id}>
                      <button
                        type="button"
                        className="file-button"
                        aria-pressed={candidate.id === file?.id}
                        onClick={() => setSelected(candidate.id)}
                      >
                        <span>{candidate.name}</span>
                        <span className="small muted">{ACCESS_TEXT[candidate.access]}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </nav>
        {file ? <FileDetail file={file} snapshot={snapshot} act={act} opened={opened} onClose={onClose} /> : null}
      </div>
    </section>
  );
}
