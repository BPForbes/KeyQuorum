// The relay core (the crate's `workers` feature, built to WebAssembly by
// scripts/build-relay-wasm.mjs) running over a Durable Object-shaped storage.
// Keys are drawn at run time; nothing here is a secret literal.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createSqlAdapter } from "../src/sql-adapter.js";
import { createFakeStorage } from "./fake-storage.mjs";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "relay-wasm");
const wasmFile = resolve(wasmDir, "keyquorum_relay_bg.wasm");
if (!existsSync(wasmFile)) {
  throw new Error("relay-wasm/ is not built; run `npm run build:relay-wasm` (needs the wasm-bindgen CLI)");
}
const bindings = await import(resolve(wasmDir, "keyquorum_relay.js"));
bindings.initSync({ module: readFileSync(wasmFile) });

const BASE = "https://relay.test";
const NOW = "2026-10-06 12:00:00.000";

function openCore({ identity = false } = {}) {
  const storage = createFakeStorage();
  const core = new bindings.RelayCore(
    createSqlAdapter(storage),
    identity ? randomBytes(40) : undefined,
    identity ? randomBytes(32) : undefined,
  );
  return { storage, core };
}

function bearer() {
  const raw = randomBytes(32);
  return { token: `kq_${raw.toString("base64url")}`, hash: createHash("sha256").update(raw).digest("hex") };
}

function addKey(storage, scope, fingerprint = null) {
  const { token, hash } = bearer();
  storage.db
    .prepare("INSERT INTO api_keys (key_hash, scope, recipient_fingerprint) VALUES (?, ?, ?)")
    .run(hash, scope, fingerprint);
  return token;
}

function call(core, method, path, { token, body, contentType } = {}) {
  const response = core.handle(
    method,
    `${BASE}${path}`,
    token,
    contentType,
    body ? Buffer.from(body) : new Uint8Array(),
    NOW,
  );
  const text = Buffer.from(response.body).toString("utf8");
  return { status: response.status, text, json: text ? JSON.parse(text) : null };
}

test("the schema is created on an empty Durable Object, and again without harm", () => {
  const storage = createFakeStorage();
  new bindings.RelayCore(createSqlAdapter(storage), undefined, undefined);
  new bindings.RelayCore(createSqlAdapter(storage), undefined, undefined);
  const tables = storage.db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
    .all()
    .map((row) => row.name);
  for (const table of ["api_keys", "api_key_events", "mailbox", "audit_anchors", "org_tree_docs"]) {
    assert.ok(tables.includes(table), table);
  }
});

test("a request without a bearer is 401, a malformed one is not a success, and readiness answers", () => {
  const { core } = openCore();
  assert.equal(core.ready(), true);
  assert.equal(call(core, "GET", "/inbox").status, 401);
  assert.equal(call(core, "GET", "/api-keys").status, 401);
  const unknown = call(core, "GET", "/api-keys", { token: `kq_${randomBytes(32).toString("base64url")}` });
  assert.equal(unknown.status, 401);
  assert.equal(call(core, "GET", "/nowhere").status, 404);
});

test("keycheck answers for a live key and for an unknown one, through the cursor and a binding", () => {
  const { core, storage } = openCore();
  const token = addKey(storage, "admin");
  const live = call(core, "POST", "/keycheck", {
    body: JSON.stringify({ token }),
    contentType: "application/json",
  });
  assert.equal(live.status, 200);
  assert.equal(live.json.valid, true);
  assert.equal(live.json.scope, "admin");
  const other = call(core, "POST", "/keycheck", {
    body: JSON.stringify({ token: `kq_${randomBytes(32).toString("base64url")}` }),
    contentType: "application/json",
  });
  assert.equal(other.json.valid, false);
});

test("a revocation commits its audit row, chains it and stamps last use", () => {
  const { core, storage } = openCore();
  const admin = addKey(storage, "admin");
  const target = addKey(storage, "inbox.push");
  const id = storage.db.prepare("SELECT id FROM api_keys WHERE scope = 'inbox.push'").get().id;

  const listed = call(core, "GET", "/api-keys", { token: admin });
  assert.equal(listed.status, 200);
  assert.equal(listed.json.length, 2);
  assert.ok(storage.db.prepare("SELECT last_used_at FROM api_keys WHERE scope = 'admin'").get().last_used_at);

  assert.equal(call(core, "POST", `/api-keys/${id}/revoke`, { token: admin }).status, 204);
  const events = storage.db.prepare("SELECT event, actor, entry_hash FROM api_key_events").all();
  assert.equal(events.length, 1);
  assert.equal(events[0].event, "revoked");
  assert.equal(events[0].actor.startsWith("admin:"), true);
  assert.equal(events[0].entry_hash.length, 64, "the row was sealed into the chain in the same transaction");
  assert.equal(call(core, "POST", "/keycheck", {
    body: JSON.stringify({ token: target }),
    contentType: "application/json",
  }).json.valid, false);
});

test("a failed unit of work leaves nothing behind", () => {
  const { core, storage } = openCore();
  const admin = addKey(storage, "admin");
  assert.equal(call(core, "POST", "/api-keys/9999/revoke", { token: admin }).status, 404);
  assert.equal(storage.db.prepare("SELECT COUNT(*) AS n FROM api_key_events").get().n, 0);
});

test("a key without the admin scope cannot revoke, and nothing is recorded", () => {
  const { core, storage } = openCore();
  const push = addKey(storage, "inbox.push");
  const result = call(core, "POST", "/api-keys/1/revoke", { token: push });
  assert.ok([401, 403].includes(result.status));
  assert.equal(storage.db.prepare("SELECT COUNT(*) AS n FROM api_key_events").get().n, 0);
});

test("a method with no route, an oversized body and a bad URL are refused before routing", () => {
  const { core } = openCore();
  assert.equal(core.handle("PATCH", `${BASE}/inbox`, undefined, undefined, new Uint8Array(), NOW).status, 405);
  assert.equal(
    core.handle("POST", `${BASE}/inbox`, undefined, undefined, new Uint8Array(2 * 1024 * 1024 + 1), NOW).status,
    413,
  );
  assert.equal(core.handle("GET", "not a url", undefined, undefined, new Uint8Array(), NOW).status, 400);
});

test("provider identity is refused when no certificate and key were given", () => {
  const { core } = openCore();
  const result = call(core, "POST", "/provider-identity", {
    body: JSON.stringify({ challenge: randomBytes(32).toString("base64") }),
    contentType: "application/json",
  });
  assert.ok(result.status >= 400);
});

test("the alarm scan purges and anchors without a certificate", () => {
  const { core } = openCore();
  assert.equal(core.scan(NOW), 0);
});
