#!/usr/bin/env node
// A stand-in relay for the console's browser tests: serves the built console
// from dist/ under /console/ the way src/relay/console.rs does, and answers
// the handful of routes the console uses with fixture data. It is a test
// double, not a second relay: the status codes and scope rules below copy
// what src/relay/service.rs answers (401 without a bearer, 403 for the wrong
// scope, 404 for an unknown key, tree or device) so the console is tested
// against the relay's real behaviour, and nothing here is reachable from
// the product. The bearers it accepts come from the environment
// (playwright.config.ts draws them at random for each run); none is
// written down anywhere.
import { createServer } from "node:http";
import { readFileSync, statSync } from "node:fs";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const port = Number(process.env.MOCK_RELAY_PORT ?? 4175);
const dist = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const adminKey = process.env.CONSOLE_TEST_ADMIN_KEY;
const pullKey = process.env.CONSOLE_TEST_PULL_KEY;
if (!adminKey || !pullKey) {
  throw new Error("CONSOLE_TEST_ADMIN_KEY and CONSOLE_TEST_PULL_KEY must be set (playwright.config.ts sets them)");
}
const storeDown = process.env.MOCK_RELAY_STORE_DOWN === "1";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

const PULL_FINGERPRINT = "7c1e0d2ba5f44d1e9b8a3c6f2e1d0c9b";

/** Fixture state: four keys, their events, one tree, one device. `POST
 * /__test/reset` puts it back, so each browser test starts from the same
 * relay; the real relay has no such route. */
const fixtureKeys = () => [
  { id: 1, scope: "admin", recipient_fingerprint: null, label: "operator", created_at: "2026-09-01 08:00:00", expires_at: null, revoked_at: null, last_used_at: "2026-10-05 17:45:12" },
  { id: 2, scope: "inbox.pull", recipient_fingerprint: PULL_FINGERPRINT, label: "acme-pull", created_at: "2026-09-02 09:30:00", expires_at: null, revoked_at: null, last_used_at: null },
  { id: 3, scope: "inbox.push", recipient_fingerprint: null, label: "acme-push", created_at: "2026-09-02 09:31:00", expires_at: "2027-09-02 09:31:00", revoked_at: null, last_used_at: "2026-10-04 11:02:40" },
  { id: 4, scope: "inbox.pull", recipient_fingerprint: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", label: "old-pull", created_at: "2026-08-01 09:00:00", expires_at: null, revoked_at: "2026-09-01 07:59:00", last_used_at: null },
];
const hash = (n) => n.toString(16).padStart(64, "0");
const fixtureEvents = () => [
  { id: 1, key_id: 1, event: "created", actor: "host", related_key_id: null, occurred_at: "2026-09-01 08:00:00", entry_hash: hash(1) },
  { id: 2, key_id: 2, event: "created", actor: "host", related_key_id: null, occurred_at: "2026-09-02 09:30:00", entry_hash: hash(2) },
  { id: 3, key_id: 3, event: "created", actor: "host", related_key_id: null, occurred_at: "2026-09-02 09:31:00", entry_hash: hash(3) },
  { id: 4, key_id: 4, event: "revoked", actor: "host", related_key_id: null, occurred_at: "2026-09-01 07:59:00", entry_hash: hash(4) },
];
let keys = fixtureKeys();
let events = fixtureEvents();
let nextEvent = 5;
const tree = {
  label: "M.S",
  generation: 3,
  nodes: [
    { label: "M.S", parent_label: null, threshold: 2, is_active: true, encryption_fingerprint: null, encryption_public_key: null },
    { label: "M.S.1", parent_label: "M.S", threshold: null, is_active: true, encryption_fingerprint: PULL_FINGERPRINT, encryption_public_key: "00".repeat(32) },
    { label: "M.S.2", parent_label: "M.S", threshold: null, is_active: true, encryption_fingerprint: "11".repeat(16), encryption_public_key: "11".repeat(32) },
  ],
  whitelist: [],
  links: [{ from: "M.S.1", to: "M.S.2" }],
};
const device = {
  device_id: "a".repeat(32),
  verify_key: "b".repeat(64),
  slots: [{ label: "M.S.1", encryption_public: "c".repeat(64), signing_public: "d".repeat(64) }],
  signature: "e".repeat(128),
};
// A certificate-shaped placeholder: the console only digests and measures it.
const certificate = Buffer.from("KQPC\u0001mock certificate bytes for the console's browser tests").toString("base64");

function json(response, status, body, headers = {}) {
  response.writeHead(status, { "content-type": "application/json", ...headers });
  response.end(body === undefined ? "" : JSON.stringify(body));
}

function authed(request) {
  const header = request.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (token === adminKey) return keys[0];
  if (token === pullKey) return keys[1];
  return null;
}

function keyOf(token) {
  if (token === adminKey) return keys[0];
  if (token === pullKey) return keys[1];
  return null;
}

function requireScope(request, response, scopes) {
  const key = authed(request);
  if (!key || key.revoked_at) {
    json(response, 401, { error: "unauthorized" });
    return null;
  }
  if (!scopes.includes(key.scope)) {
    json(response, 403, { error: "forbidden" });
    return null;
  }
  return key;
}

function readBody(request) {
  return new Promise((resolveBody) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolveBody(Buffer.concat(chunks).toString("utf8")));
  });
}

function serveConsole(pathname, response) {
  if (pathname === "/console") {
    response.writeHead(308, { location: "/console/" });
    response.end();
    return;
  }
  const rel = pathname === "/console/" ? "index.html" : pathname.slice("/console/".length);
  const file = normalize(join(dist, rel));
  if (!file.startsWith(dist)) {
    json(response, 404, { error: "not found" });
    return;
  }
  try {
    if (!statSync(file).isFile()) throw new Error("not a file");
    response.writeHead(200, {
      "content-type": TYPES[extname(file)] ?? "application/octet-stream",
      "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      "cache-control": rel === "index.html" ? "no-store" : "public, max-age=31536000, immutable",
    });
    response.end(readFileSync(file));
  } catch {
    json(response, 404, { error: "not found" });
  }
}

createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  const { pathname } = url;
  const method = request.method ?? "GET";

  if (method === "POST" && pathname === "/__test/reset") {
    keys = fixtureKeys();
    events = fixtureEvents();
    nextEvent = 5;
    return json(response, 204);
  }
  if (pathname === "/console" || pathname.startsWith("/console/")) {
    if (method !== "GET") return json(response, 405, { error: "method not allowed" });
    return serveConsole(pathname, response);
  }
  if (method === "GET" && pathname === "/health") return json(response, 200, { status: "ok" });
  if (method === "GET" && pathname === "/ready") {
    return storeDown ? json(response, 503, { error: "store unavailable" }) : json(response, 200, { status: "ok", store: "sqlite" });
  }
  if (method === "POST" && pathname === "/provider-identity") {
    const body = JSON.parse((await readBody(request)) || "{}");
    const challenge = Buffer.from(String(body.challenge ?? ""), "base64");
    if (challenge.length !== 32) return json(response, 400, { error: "invalid provider challenge" });
    return json(response, 200, { certificate, signature: Buffer.alloc(64, 7).toString("base64") });
  }
  if (method === "POST" && pathname === "/keycheck") {
    const body = JSON.parse((await readBody(request)) || "{}");
    const token = body.token;
    const keyHash = body.key_hash;
    if ((token && keyHash) || (!token && !keyHash)) return json(response, 400, { error: "provide exactly one of token or key_hash" });
    if (keyHash) {
      // Fixture: the hash made of a key's id digit names that key.
      const match = keys.find((key) => keyHash === String(key.id).repeat(64));
      if (!match || match.revoked_at) return json(response, 200, { valid: false });
      return json(response, 200, { valid: true, id: match.id, scope: match.scope, label: match.label, recipient_fingerprint: match.recipient_fingerprint ?? undefined });
    }
    const match = keyOf(token);
    if (!match || match.revoked_at) return json(response, 200, { valid: false });
    return json(response, 200, { valid: true, id: match.id, scope: match.scope, label: match.label, recipient_fingerprint: match.recipient_fingerprint ?? undefined });
  }
  if (method === "GET" && pathname === "/api-keys") {
    if (!requireScope(request, response, ["admin"])) return;
    return json(response, 200, keys);
  }
  const revoke = pathname.match(/^\/api-keys\/(\d+)\/revoke$/);
  if (method === "POST" && revoke) {
    const actor = requireScope(request, response, ["admin"]);
    if (!actor) return;
    const target = keys.find((key) => key.id === Number(revoke[1]));
    if (!target) return json(response, 404, { error: "api key not found" });
    if (!target.revoked_at) {
      target.revoked_at = new Date().toISOString().slice(0, 19).replace("T", " ");
      events.push({ id: nextEvent, key_id: target.id, event: "revoked", actor: `admin:${actor.id}`, related_key_id: null, occurred_at: target.revoked_at, entry_hash: hash(nextEvent) });
      nextEvent += 1;
    }
    response.writeHead(204);
    return response.end();
  }
  if (method === "GET" && pathname === "/audit/api-keys") {
    const key = authed(request);
    if (!key || key.revoked_at) return json(response, 401, { error: "unauthorized" });
    return json(response, 200, key.scope === "admin" ? events : events.filter((event) => event.key_id === key.id));
  }
  const context = pathname.match(/^\/trees\/([^/]+)\/context$/);
  if (method === "GET" && context) {
    const key = requireScope(request, response, ["inbox.pull"]);
    if (!key) return;
    if (decodeURIComponent(context[1]) !== tree.label) return json(response, 404, { error: "tree not found" });
    return json(response, 200, tree);
  }
  const deviceMatch = pathname.match(/^\/devices\/([0-9a-f]+)$/);
  if (method === "GET" && deviceMatch) {
    if (!requireScope(request, response, ["device.pull", "device.push"])) return;
    if (deviceMatch[1] !== device.device_id) return json(response, 404, { error: "device not found" });
    return json(response, 200, device);
  }
  json(response, 404, { error: "not found" });
}).listen(port, "127.0.0.1", () => console.log(`mock relay with console on http://127.0.0.1:${port}/console/`));
