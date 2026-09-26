import { useEffect, useMemo, useState } from "react";
import type { Act } from "../App";
import type { ActionResult, FileView, Snapshot } from "../api/types";
import { fileStatus, fileType, formatSize, formatUtc } from "../explorerTypes";
import { DriveIcon, FileIcon, FolderIcon } from "./icons";
import { FileViewer } from "./FileViewer";
import { PropertiesDialog } from "./PropertiesDialog";
import { SendDialog } from "./SendDialog";

const FOLDER_ORDER = ["public", "engineering", "accounting", "executive", "received"];

type SortKey = "name" | "modified" | "type" | "size" | "status";

function sortValue(file: FileView, key: SortKey): string | number {
  switch (key) {
    case "name":
      return file.name.toLowerCase();
    case "modified":
      return file.createdAt;
    case "type":
      return fileType(file.name);
    case "size":
      return file.size;
    case "status":
      return fileStatus(file).label;
  }
}

interface ContextMenuState {
  x: number;
  y: number;
  file: FileView;
}

export function FileExplorer({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const [folder, setFolder] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "name", dir: 1 });
  const [viewing, setViewing] = useState<{ result: ActionResult; name: string } | null>(null);
  const [properties, setProperties] = useState<FileView | null>(null);
  const [sending, setSending] = useState<FileView | null>(null);
  const [menu, setMenu] = useState<ContextMenuState | null>(null);

  useEffect(() => {
    const close = () => setMenu(null);
    window.addEventListener("click", close);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("resize", close);
    };
  }, []);

  const folders = useMemo(() => {
    const present = new Set(snapshot.files.map((file) => file.folder));
    return FOLDER_ORDER.filter((name) => present.has(name));
  }, [snapshot.files]);

  const filesInFolder = useMemo(() => {
    if (folder === null) return [];
    const list = snapshot.files.filter((file) => file.folder === folder);
    const sorted = [...list].sort((a, b) => {
      const av = sortValue(a, sort.key);
      const bv = sortValue(b, sort.key);
      if (av < bv) return -1 * sort.dir;
      if (av > bv) return 1 * sort.dir;
      return a.name.localeCompare(b.name) * sort.dir;
    });
    return sorted;
  }, [snapshot.files, folder, sort]);

  // The file a modal refers to can change out from under it after an
  // action (e.g. Send re-fetches the snapshot); keep dialogs in sync
  // rather than showing stale data.
  const selectedFile = filesInFolder.find((file) => file.id === selected) ?? null;

  function openFile(file: FileView) {
    const result = act((client) => client.unlockFile(file.id));
    if (result) setViewing({ result, name: file.name });
  }

  function sortBy(key: SortKey) {
    setSort((current) => (current.key === key ? { key, dir: current.dir === 1 ? -1 : 1 } : { key, dir: 1 }));
  }

  const columns: { key: SortKey; label: string }[] = [
    { key: "name", label: "Name" },
    { key: "modified", label: "Date modified" },
    { key: "type", label: "Type" },
    { key: "size", label: "Size" },
    { key: "status", label: "Status" },
  ];

  return (
    <section className="panel panel-wide explorer-panel" data-panel="files" aria-labelledby="files-heading">
      <h2 id="files-heading" className="panel-title">
        File Explorer
      </h2>

      <nav className="breadcrumb" aria-label="Folder path">
        <button type="button" className="breadcrumb-link" onClick={() => setFolder(null)} aria-current={folder === null ? "page" : undefined}>
          <DriveIcon connected /> This PC
        </button>
        {folder !== null ? (
          <>
            <span aria-hidden="true">›</span>
            <span className="breadcrumb-current" aria-current="page">
              <FolderIcon /> {folder}
            </span>
          </>
        ) : null}
      </nav>

      {folder === null ? (
        <ul className="folder-tiles">
          {folders.map((name) => {
            const count = snapshot.files.filter((file) => file.folder === name).length;
            return (
              <li key={name}>
                <button type="button" className="folder-tile" onDoubleClick={() => setFolder(name)} onClick={() => setFolder(name)}>
                  <FolderIcon />
                  <span>{name}</span>
                  <span className="muted small">
                    {count} item{count === 1 ? "" : "s"}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      ) : (
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead>
              <tr>
                {columns.map((column) => (
                  <th key={column.key} aria-sort={sort.key === column.key ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
                    <button type="button" onClick={() => sortBy(column.key)}>
                      {column.label}
                      {sort.key === column.key ? <span aria-hidden="true">{sort.dir === 1 ? " ▲" : " ▼"}</span> : null}
                    </button>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filesInFolder.map((file) => {
                const status = fileStatus(file);
                return (
                  <tr
                    key={file.id}
                    className={file.id === selected ? "is-selected" : undefined}
                    data-testid={`file-row-${file.id}`}
                    onClick={() => setSelected(file.id)}
                    onDoubleClick={() => {
                      setSelected(file.id);
                      openFile(file);
                    }}
                    onContextMenu={(event) => {
                      event.preventDefault();
                      setSelected(file.id);
                      setMenu({ x: event.clientX, y: event.clientY, file });
                    }}
                  >
                    <td className="explorer-name-cell">
                      <FileIcon expired={file.expired} /> {file.name}
                    </td>
                    <td>{file.createdAt ? formatUtc(file.createdAt) : "—"}</td>
                    <td>{fileType(file.name)}</td>
                    <td>{formatSize(file.size)}</td>
                    <td>
                      <span className={`status-pill status-${status.tone}`}>{status.label}</span>
                    </td>
                  </tr>
                );
              })}
              {filesInFolder.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty">
                    This folder is empty.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      )}

      {selectedFile ? (
        <div className="explorer-toolbar" role="toolbar" aria-label={`Actions for ${selectedFile.name}`}>
          <button type="button" className="btn btn-primary" onClick={() => openFile(selectedFile)}>
            Open
          </button>
          <button type="button" className="btn" onClick={() => setSending(selectedFile)}>
            Send…
          </button>
          <button type="button" className="btn" onClick={() => setProperties(selectedFile)}>
            Properties
          </button>
        </div>
      ) : null}

      {menu ? (
        <ul className="context-menu" style={{ left: menu.x, top: menu.y }} role="menu">
          <li role="none">
            <button type="button" role="menuitem" onClick={() => openFile(menu.file)}>
              Open
            </button>
          </li>
          <li role="none">
            <button type="button" role="menuitem" onClick={() => setSending(menu.file)}>
              Send…
            </button>
          </li>
          <li role="none">
            <button type="button" role="menuitem" onClick={() => setProperties(menu.file)}>
              Properties
            </button>
          </li>
        </ul>
      ) : null}

      {viewing ? <FileViewer result={viewing.result} fileName={viewing.name} onClose={() => setViewing(null)} /> : null}
      {properties ? <PropertiesDialog file={properties} folder={folder ?? properties.folder} onClose={() => setProperties(null)} /> : null}
      {sending ? (
        <SendDialog
          file={sending}
          snapshot={snapshot}
          onCancel={() => setSending(null)}
          onSend={(recipient) => {
            const result = act((client) => client.sendFile(sending.id, recipient));
            if (result?.ok) setSending(null);
          }}
        />
      ) : null}
    </section>
  );
}
