// Shared helpers for the Windows-Explorer-style File Explorer: file "Type"
// by extension, and the one-line status a listing shows per file.
import type { FileView } from "./api/types";

const TYPE_BY_EXTENSION: Record<string, string> = {
  txt: "Text Document",
  md: "Markdown Document",
  csv: "CSV File",
  log: "Log File",
  json: "JSON File",
};

export function fileType(name: string): string {
  const dot = name.lastIndexOf(".");
  if (dot === -1) return "File";
  const extension = name.slice(dot + 1).toLowerCase();
  return TYPE_BY_EXTENSION[extension] ?? `${extension.toUpperCase()} File`;
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

/** `YYYY-MM-DD HH:MM:SS` (as the crate stores it) -> a stable, locale-free display string. */
export function formatUtc(value: string): string {
  if (!value) return "";
  const [date, time] = value.split(/[ T]/);
  return time ? `${date} ${time.slice(0, 5)} UTC` : `${date} UTC`;
}

export type StatusTone = "ok" | "warn" | "error" | "muted";

export function fileStatus(file: FileView): { label: string; tone: StatusTone } {
  if (file.expired) return { label: "Expired", tone: "error" };
  if (file.protection === "public") return { label: "Public", tone: "muted" };
  switch (file.access) {
    case "holder":
      return { label: "You have access", tone: "ok" };
    case "oversight":
      return { label: "Oversight access", tone: "ok" };
    case "lineage":
      return { label: "Access via your manager", tone: "warn" };
    default:
      return { label: "No access", tone: "muted" };
  }
}
