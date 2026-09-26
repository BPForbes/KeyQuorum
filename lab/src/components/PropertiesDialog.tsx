import type { FileView, RequirementNode } from "../api/types";
import { fileStatus, fileType, formatSize, formatUtc } from "../explorerTypes";
import { Modal } from "./Modal";

function Requirement({ node }: { node: RequirementNode }) {
  if (node.threshold === null) {
    return (
      <li className={node.ghost ? "requirement-ghost" : undefined}>
        <code>{node.label}</code> {node.holder ?? ""}
        {node.ghost ? <span className="tag tag-ghost">ghost — evicted</span> : null}
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

export function PropertiesDialog({ file, folder, onClose }: { file: FileView; folder: string; onClose: () => void }) {
  const status = fileStatus(file);
  return (
    <Modal title={`${file.name} Properties`} onClose={onClose} labelledBy="properties-title">
      <dl className="properties-grid">
        <dt>Type</dt>
        <dd>{fileType(file.name)}</dd>
        <dt>Location</dt>
        <dd>
          <code>/{folder}/</code>
        </dd>
        <dt>Size</dt>
        <dd>{formatSize(file.size)}</dd>
        <dt>Created</dt>
        <dd>{file.createdAt ? formatUtc(file.createdAt) : "—"}</dd>
        <dt>Expires</dt>
        <dd className={file.expired ? "state-off" : undefined}>
          {file.expiresAt ? `${formatUtc(file.expiresAt)}${file.expired ? " (expired)" : ""}` : "Never"}
        </dd>
        <dt>Status</dt>
        <dd data-tone={status.tone}>{status.label}</dd>
        {file.receivedFrom ? (
          <>
            <dt>Received from</dt>
            <dd>{file.receivedFrom}</dd>
          </>
        ) : null}
      </dl>
      <p className="properties-lesson">{file.lesson}</p>
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
    </Modal>
  );
}
