// What the public Worker lets through, as pure functions with no I/O: which
// host may be served, which routes the relay exposes, how a bearer is read and
// how a body is bounded. Nothing here decides who may use the relay: the relay
// core does that (key scope, fingerprint binding), in the Durable Object.

// The relay core refuses a larger body too (`MAX_REQUEST_BODY` in
// src/relay/worker.rs); this is the first line, taken before a body is read.
export const MAX_REQUEST_BODY = 2 * 1024 * 1024;

// ALLOWED_HOSTS is a non-secret variable the deploy job fills with the
// relay's custom domain. Empty or missing means the Worker is unconfigured and
// serves nothing. "*" means any host and is only ever set in the `previews`
// block, where a Preview has its own empty Durable Object and no secrets;
// scripts/guard.mjs refuses it anywhere else. Anything else is a comma list of
// hostnames, so a Version URL (a workers.dev host that shares production's
// bindings) is refused, not served.
export function parseAllowedHosts(value) {
  if (typeof value !== "string") return { mode: "closed" };
  const text = value.trim();
  if (text === "") return { mode: "closed" };
  if (text === "*") return { mode: "any" };
  const hosts = new Set(
    text
      .split(",")
      .map((host) => host.trim().toLowerCase().replace(/\.$/, ""))
      .filter(Boolean),
  );
  return hosts.size > 0 ? { mode: "hosts", hosts } : { mode: "closed" };
}

// "unconfigured": serve nothing (503). "refused": not our host (404, as if
// nothing were here). "ok": serve.
export function hostDecision(allowed, hostname) {
  if (allowed.mode === "closed") return "unconfigured";
  if (allowed.mode === "any") return "ok";
  const host = String(hostname).toLowerCase().replace(/\.$/, "");
  return allowed.hosts.has(host) ? "ok" : "refused";
}

// The customer routes of the relay, the same set the native router serves for
// customers (src/relay/server.rs, `router`) and nothing else. `*` is any one
// path segment. There is no operator route here: `/api-keys` (list, revoke),
// the full `/audit/*` and anything that mints are not routed on the public
// Worker, whatever the core's router would do with them.
const RELAY_ROUTES = [
  ["POST", ["provider-identity"]],
  ["POST", ["keycheck"]],
  ["POST", ["inbox"]],
  ["GET", ["inbox"]],
  ["GET", ["audit", "api-keys"]],
  ["PUT", ["trees"]],
  ["GET", ["trees", "*", "context"]],
  ["POST", ["devices", "packages"]],
  ["GET", ["devices", "packages"]],
  ["PUT", ["devices"]],
  ["GET", ["devices", "*"]],
];

// The Worker's own answers.
const OWN_ROUTES = new Map([
  ["/health", "health"],
  ["/ready", "ready"],
  ["/", "status"],
  ["/assets/status.js", "asset"],
  ["/assets/status.css", "asset"],
]);

// Split the way the relay core does (`trim_matches('/')`, then split on '/'),
// so a path means the same thing here and there.
function segmentsOf(pathname) {
  return pathname.replace(/^\/+|\/+$/g, "").split("/");
}

function matches(pattern, segments) {
  return (
    pattern.length === segments.length &&
    pattern.every((part, index) => part === "*" || part === segments[index])
  );
}

// -> { kind: "health" | "ready" | "status" | "asset" | "relay" }
//    | { kind: "not-found" }
//    | { kind: "method-not-allowed", allow: "GET, HEAD" }
export function classify(method, pathname) {
  const own = OWN_ROUTES.get(pathname);
  if (own) {
    return method === "GET" || method === "HEAD"
      ? { kind: own }
      : { kind: "method-not-allowed", allow: "GET, HEAD" };
  }
  const segments = segmentsOf(pathname);
  const methods = new Set();
  for (const [routeMethod, pattern] of RELAY_ROUTES) {
    if (!matches(pattern, segments)) continue;
    if (routeMethod === method) return { kind: "relay" };
    methods.add(routeMethod);
  }
  if (methods.size > 0) return { kind: "method-not-allowed", allow: [...methods].join(", ") };
  return { kind: "not-found" };
}

// The caller's bearer, read as the native router reads it
// (src/relay/server.rs, `token_from_headers`): `Authorization: Bearer <token>`
// with that exact prefix, else a non-empty `x-api-key`. It is handed to the
// core and never logged, stored or put in a response.
export function bearerOf(headers) {
  const authorization = headers.get("authorization");
  if (authorization?.startsWith("Bearer ") && authorization.length > "Bearer ".length) {
    return authorization.slice("Bearer ".length);
  }
  const key = headers.get("x-api-key");
  return key ? key : undefined;
}

// Reads a request body up to `limit` bytes. Returns the bytes, or null when
// the body is larger (the stream is cancelled so the rest is never read).
export async function readLimited(request, limit = MAX_REQUEST_BODY) {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) return null;
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

// The answer headers every response carries: never cached, never sniffed.
export function baseHeaders(extra = {}) {
  return {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...extra,
  };
}

export function jsonResponse(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: baseHeaders({ "content-type": "application/json; charset=utf-8", ...extra }),
  });
}
