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
// lock get plain instructions.
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
    case "lock_exists":
      return "The operator lock already exists and cannot be shown again.";
    case "no_identity":
      return "The relay has no identity configured (its certificate and key secrets), so it cannot issue keys or sign.";
    default:
  }
  if (status === 401 || status === 403) return message || "Access was refused.";
  if (status === 503) return "The relay is not available right now.";
  return message || `The request failed (${status}).`;
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
