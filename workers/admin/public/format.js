// Pure helpers for the console: no DOM, so they run under Node's test runner
// (admin/src/format.test.mjs) as well as in the page.

export const SCOPE_LABELS = {
  "inbox.push": "Send letters",
  "inbox.pull": "Receive letters",
  "device.push": "Send device letters",
  "device.pull": "Receive device letters",
};

export function scopeLabel(scope) {
  return SCOPE_LABELS[scope] ?? String(scope ?? "");
}

// '2026-10-06T12:00:00.000Z' or '2026-10-06 12:00:00' -> '2026-10-06 12:00 UTC'.
// Anything that is not a date is shown as given, and nothing as a dash.
export function formatTime(value) {
  if (value === null || value === undefined || value === "") return "—";
  const text = String(value);
  const match = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/.exec(text);
  return match ? `${match[1]} ${match[2]} UTC` : text;
}

export function formatDate(value) {
  if (value === null || value === undefined || value === "") return "no end";
  const match = /^(\d{4}-\d{2}-\d{2})/.exec(String(value));
  return match ? match[1] : String(value);
}

// The first characters of an id or fingerprint, for a table cell.
export function shortId(value, length = 10) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

export function isHex(text, length) {
  return typeof text === "string" && new RegExp(`^[0-9a-fA-F]{${length}}$`).test(text.trim());
}

export function plural(count, one, many = `${one}s`) {
  return `${count} ${count === 1 ? one : many}`;
}

export function formatBytes(size) {
  const n = Number(size);
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

// What the operator is told when a request fails. The relay's own wording is
// used where it is a statement about the request; the codes it uses for the
// lock and for operations get plain instructions.
export function describeError(status, body) {
  const code = typeof body?.code === "string" ? body.code : "";
  const message = typeof body?.error === "string" ? body.error : "";
  switch (code) {
    case "lock_required":
      return "This action needs the operator lock. Enter it and try again.";
    case "lock_refused":
      return "The operator lock was refused. The attempt has been recorded.";
    case "no_lock":
      return "The operator lock has not been created yet. Create it on the Overview page first.";
    case "lock_unconfirmed":
      return "The operator lock was created but not confirmed yet. Confirm it on the Overview page first.";
    case "lock_exists":
      return "The operator lock already exists. Replace it with the current lock instead.";
    case "no_identity":
      return "The relay has no identity configured (its certificate and key secrets), so it cannot issue keys or sign.";
    case "operation_id_required":
      return "The page did not send an operation id. Reload the page and try again.";
    case "already_done":
      return `${message || "This operation was already done."}`;
    case "commit_unknown":
      return "The relay could not confirm the change was saved. Submit again: it carries the same operation id, so it will be done once at most.";
    default:
  }
  if (status === 401 || status === 403) return message || "Access was refused.";
  if (status === 429) return "Too many requests. Wait a minute and try again.";
  if (status === 503) return "The relay is not available right now.";
  return message || `The request failed (${status}).`;
}

// Whether a failed change may have been made: the request did not get a clear
// answer from the relay (no response, or an error that does not say it was
// refused). Such a change is retried with the same operation id.
export function outcomeUnknown(status, body) {
  if (status === undefined || status === null) return true;
  if (typeof body?.code === "string" && body.code === "commit_unknown") return true;
  return status >= 500;
}

export function formatMs(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "\u2014";
  return n < 1000 ? `${Math.round(n)} ms` : `${(n / 1000).toFixed(1)} s`;
}

// Whole days from `now` until a date text, rounded down; negative when past.
export function daysUntil(value, now = Date.now()) {
  const match = /^(\d{4}-\d{2}-\d{2})[T ]?(\d{2}:\d{2}:\d{2})?/.exec(String(value ?? ""));
  if (!match) return null;
  const at = Date.parse(`${match[1]}T${match[2] ?? "00:00:00"}Z`);
  return Number.isNaN(at) ? null : Math.floor((at - now) / 86_400_000);
}

// The first characters of an operation id, for a table cell.
export function shortOperation(value) {
  return value ? String(value).slice(0, 8) : "\u2014";
}

// Requests per hour, summed over outcomes, for a bar chart: one entry per hour
// that has any, oldest first, with what was served and what was blocked.
export function hourlyBars(rows) {
  const byHour = new Map();
  for (const row of rows ?? []) {
    const entry = byHour.get(row.hour) ?? { hour: row.hour, served: 0, blocked: 0 };
    if (row.outcome === "ok") entry.served += row.count;
    else entry.blocked += row.count;
    byHour.set(row.hour, entry);
  }
  return [...byHour.values()].sort((a, b) => (a.hour < b.hour ? -1 : a.hour > b.hour ? 1 : 0));
}

export function totals(rows) {
  let served = 0;
  let blocked = 0;
  for (const row of rows ?? []) {
    if (row.outcome === "ok") served += row.count;
    else blocked += row.count;
  }
  return { served, blocked };
}

// The badge kind for a key or licence state.
export function stateKind(state) {
  switch (state) {
    case "live":
    case "active":
      return "good";
    case "revoked":
    case "voided":
      return "bad";
    case "expired":
    case "ended":
      return "warn";
    default:
      return "plain";
  }
}
