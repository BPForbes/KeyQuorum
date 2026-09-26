// Readiness handshake for bailey-forbes.com, which embeds this lab in its
// guest window. The message goes to one named origin, never "*", and only
// after the WASM lab has seeded and rendered, so the host's "Attached ·
// live" state means KeyQuorum is actually running.

export const EMBED_SOURCE = "keyquorum-guest";
export const PORTFOLIO_ORIGIN = "https://bailey-forbes.com";

/** Loopback parents are allowed for local and CI handshake tests only. */
export function allowedParentOrigin(origin: string): boolean {
  if (origin === PORTFOLIO_ORIGIN) return true;
  try {
    const url = new URL(origin);
    return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost");
  } catch {
    return false;
  }
}

export function parentOrigin(search: string): string {
  const requested = new URLSearchParams(search).get("parentOrigin");
  return requested && allowedParentOrigin(requested) ? requested : PORTFOLIO_ORIGIN;
}

export function announceReady(commit: string): void {
  if (window.parent === window) return;
  window.parent.postMessage(
    { source: EMBED_SOURCE, type: "ready", schemaVersion: 1, commit },
    parentOrigin(window.location.search),
  );
}
