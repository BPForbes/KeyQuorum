// The relay inside a Durable Object (src/relay-service.js), over the real
// WebAssembly core and a Durable Object-shaped storage on Node's SQLite. Keys,
// bearers and identity bytes are drawn at run time; nothing here is a secret
// literal.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_IN_FLIGHT, MAX_OPERATE_BODY, SCAN_INTERVAL_MS, createRelayService, relayTime } from "../src/relay-service.js";
import { MAX_REQUEST_BODY } from "../src/policy.js";
import { createFakeStorage } from "./fake-storage.mjs";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "relay-wasm");
const wasmFile = resolve(wasmDir, "keyquorum_relay_bg.wasm");
if (!existsSync(wasmFile)) {
  throw new Error("relay-wasm/ is not built; run `npm run build:relay-wasm` (needs the wasm-bindgen CLI)");
}
const bindings = await import(resolve(wasmDir, "keyquorum_relay.js"));
bindings.initSync({ module: readFileSync(wasmFile) });

const BASE = "https://relay.test";
const NOW = new Date("2026-10-06T12:00:00.000Z");

function spyLog() {
  const lines = [];
  const record = (level) => (...args) => lines.push([level, ...args]);
  return { warn: record("warn"), error: record("error"), lines };
}

// A Durable Object's storage with its alarm: one pending time, or null.
function storageWithAlarm() {
  const storage = createFakeStorage();
  let alarm = null;
  storage.getAlarm = async () => alarm;
  storage.setAlarm = async (time) => {
    alarm = time;
  };
  storage.currentAlarm = () => alarm;
  return storage;
}

function open({ env = {}, withBindings = bindings, storage = storageWithAlarm(), log = spyLog() } = {}) {
  const service = createRelayService({ storage, env, bindings: withBindings, clock: () => NOW, log });
  return { service, storage, log };
}

function addKey(storage, scope, fingerprint = null) {
  const raw = randomBytes(32);
  const token = `kq_${raw.toString("base64url")}`;
  storage.db
    .prepare("INSERT INTO api_keys (key_hash, scope, recipient_fingerprint) VALUES (?, ?, ?)")
    .run(createHash("sha256").update(raw).digest("hex"), scope, fingerprint);
  return token;
}

const get = (service, path, headers = {}) => service.fetch(new Request(`${BASE}${path}`, { headers }));
const post = (service, path, body, headers = {}) =>
  service.fetch(new Request(`${BASE}${path}`, { method: "POST", body, headers }));

test("the time handed to the core is UTC text in the form it parses", () => {
  assert.equal(relayTime(NOW), "2026-10-06 12:00:00.000");
  assert.match(relayTime(new Date()), /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}$/);
});

test("an unauthenticated request is 401, an unknown path 404, and every answer is JSON and never cached", async () => {
  const { service } = open();
  const inbox = await get(service, "/inbox");
  assert.equal(inbox.status, 401);
  assert.match(inbox.headers.get("content-type"), /application\/json/);
  assert.equal(inbox.headers.get("cache-control"), "no-store");
  assert.equal(inbox.headers.get("x-content-type-options"), "nosniff");
  assert.equal((await get(service, "/nowhere")).status, 404);
  assert.equal(service.ready(), true);
});

test("the bearer is read as the native router reads it: exact Bearer prefix, else x-api-key", async () => {
  const { service, storage } = open();
  const admin = addKey(storage, "admin");
  assert.equal((await get(service, "/api-keys", { authorization: `Bearer ${admin}` })).status, 200);
  assert.equal((await get(service, "/api-keys", { "x-api-key": admin })).status, 200);
  assert.equal((await get(service, "/api-keys", { authorization: `bearer ${admin}` })).status, 401);
  assert.equal((await get(service, "/api-keys", { authorization: admin })).status, 401);
  assert.equal((await get(service, "/api-keys", { authorization: "Bearer " })).status, 401);
  // A bad Authorization header does not stop a good x-api-key, as on the native router.
  assert.equal((await get(service, "/api-keys", { authorization: "Basic abc", "x-api-key": admin })).status, 200);
  const unknown = `kq_${randomBytes(32).toString("base64url")}`;
  assert.equal((await get(service, "/api-keys", { authorization: `Bearer ${unknown}` })).status, 401);
});

test("keycheck answers for a live key, and a revocation is 204 with no body and an audit row", async () => {
  const { service, storage } = open();
  const admin = addKey(storage, "admin");
  const target = addKey(storage, "inbox.push");
  const live = await post(service, "/keycheck", JSON.stringify({ token: target }), {
    "content-type": "application/json",
  });
  assert.equal(live.status, 200);
  assert.equal((await live.json()).valid, true);
  const id = storage.db.prepare("SELECT id FROM api_keys WHERE scope = 'inbox.push'").get().id;
  const revoked = await post(service, `/api-keys/${id}/revoke`, undefined, { authorization: `Bearer ${admin}` });
  assert.equal(revoked.status, 204);
  assert.equal(await revoked.text(), "");
  assert.equal(storage.db.prepare("SELECT COUNT(*) AS n FROM api_key_events").get().n, 1);
  const after = await post(service, "/keycheck", JSON.stringify({ token: target }), {
    "content-type": "application/json",
  });
  assert.equal((await after.json()).valid, false);
});

test("a push key cannot pull, and a pull key bound to a recipient can", async () => {
  const { service, storage } = open();
  const response = await get(service, "/inbox", { authorization: `Bearer ${addKey(storage, "inbox.push")}` });
  assert.ok([401, 403].includes(response.status), "a push key cannot pull");
  const pull = await get(service, "/inbox", {
    authorization: `Bearer ${addKey(storage, "inbox.pull", randomBytes(32).toString("hex"))}`,
  });
  assert.equal(pull.status, 200);
});

test("a request the core refuses before routing is JSON, not an empty body", async () => {
  const { service } = open();
  const refused = await service.fetch(new Request(`${BASE}/inbox`, { method: "PATCH", body: "x" }));
  assert.equal(refused.status, 405);
  assert.deepEqual(await refused.json(), { error: "request refused" });
});

test("a body over the cap is 413, declared or streamed, and a streamed one is not read to the end", async () => {
  const { service, log } = open();
  const declared = await post(service, "/inbox", "x", { "content-length": String(MAX_REQUEST_BODY + 1) });
  assert.equal(declared.status, 413);

  let pulled = 0;
  const chunk = new Uint8Array(512 * 1024);
  const stream = new ReadableStream({
    pull(controller) {
      pulled += 1;
      if (pulled > 100) controller.close();
      else controller.enqueue(chunk);
    },
  });
  const streamed = await service.fetch(
    new Request(`${BASE}/inbox`, { method: "POST", body: stream, duplex: "half" }),
  );
  assert.equal(streamed.status, 413);
  assert.ok(pulled <= 8, `read ${pulled} chunks of a body that was over the cap after 4`);
  assert.equal(log.lines.length, 0);
  assert.equal(service.inFlight(), 0);
});

test("past the admission bound a request is refused at once with 503 and Retry-After, and the slots come back", async () => {
  const { service, storage } = open();
  const admin = addKey(storage, "admin");
  const held = [];
  const pending = [];
  for (let index = 0; index < MAX_IN_FLIGHT; index += 1) {
    const stream = new ReadableStream({
      start(controller) {
        held.push(controller);
      },
    });
    pending.push(
      service.fetch(
        new Request(`${BASE}/keycheck`, {
          method: "POST",
          body: stream,
          duplex: "half",
          headers: { "content-type": "application/json" },
        }),
      ),
    );
  }
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(service.inFlight(), MAX_IN_FLIGHT);

  const refused = await get(service, "/api-keys", { authorization: `Bearer ${admin}` });
  assert.equal(refused.status, 503);
  assert.equal(refused.headers.get("retry-after"), "1");
  assert.deepEqual(await refused.json(), { error: "busy" });

  for (const controller of held) {
    controller.enqueue(new TextEncoder().encode(JSON.stringify({ token: "kq_x" })));
    controller.close();
  }
  for (const response of await Promise.all(pending)) assert.equal(response.status, 200);
  assert.equal(service.inFlight(), 0);
  assert.equal((await get(service, "/api-keys", { authorization: `Bearer ${admin}` })).status, 200);
});

test("a core that throws is a generic 500, the slot is released and the response is freed", async () => {
  let freed = 0;
  const throwing = {
    RelayCore: class {
      handle() {
        throw Object.assign(new Error("a private detail"), { name: "JsError" });
      }
      ready() {
        return true;
      }
    },
  };
  const { service, log } = open({ withBindings: throwing });
  const response = await get(service, "/inbox");
  assert.equal(response.status, 500);
  assert.deepEqual(await response.json(), { error: "internal error" });
  assert.equal(service.inFlight(), 0);
  assert.ok(!JSON.stringify(log.lines).includes("private detail"), "the message is not logged");

  const answering = {
    RelayCore: class {
      handle() {
        return { status: 204, body: new Uint8Array(), free: () => (freed += 1) };
      }
      ready() {
        return true;
      }
    },
  };
  const ok = await get(open({ withBindings: answering }).service, "/inbox");
  assert.equal(ok.status, 204);
  assert.equal(freed, 1);
});

test("a core that does not start fails closed, and readiness says so", async () => {
  const broken = {
    RelayCore: class {
      constructor() {
        throw Object.assign(new Error("schema detail"), { name: "JsError" });
      }
    },
  };
  const { service, log } = open({ withBindings: broken });
  const response = await get(service, "/inbox");
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "relay unavailable" });
  assert.equal(service.ready(), false);
  assert.ok(!JSON.stringify(log.lines).includes("schema detail"));
});

test("identity secrets: both valid is a running relay, wrapped base64 is accepted", async () => {
  const certificate = randomBytes(40).toString("base64").replace(/(.{20})/g, "$1\n");
  const key = randomBytes(32).toString("base64");
  const { service } = open({ env: { RELAY_CERTIFICATE: certificate, RELAY_PRIVATE_KEY: `${key}\n` } });
  assert.equal(service.ready(), true);
  assert.equal((await get(service, "/inbox")).status, 401);
});

test("identity secrets: the key is accepted as the hex file `identity generate` writes, or as base64", async () => {
  const certificate = randomBytes(40).toString("base64");
  const raw = randomBytes(32);
  for (const key of [
    raw.toString("hex"),
    `${raw.toString("hex")}\n`,
    raw.toString("hex").toUpperCase(),
    raw.toString("base64"),
  ]) {
    const { service } = open({ env: { RELAY_CERTIFICATE: certificate, RELAY_PRIVATE_KEY: key } });
    assert.equal(service.ready(), true, key.slice(0, 6));
    assert.equal((await get(service, "/inbox")).status, 401);
  }
  // The two spellings are the same key: the core signs the same challenge.
  const challenge = JSON.stringify({ challenge: randomBytes(32).toString("base64") });
  const answers = [];
  for (const key of [raw.toString("hex"), raw.toString("base64")]) {
    const { service } = open({ env: { RELAY_CERTIFICATE: certificate, RELAY_PRIVATE_KEY: key } });
    const response = await post(service, "/provider-identity", challenge, { "content-type": "application/json" });
    answers.push(response.status);
  }
  assert.equal(answers[0], answers[1]);
});

test("identity secrets: a hex key of the wrong length is refused", async () => {
  const certificate = randomBytes(40).toString("base64");
  for (const key of [randomBytes(31).toString("hex"), randomBytes(33).toString("hex"), `${randomBytes(32).toString("hex")}zz`]) {
    const { service } = open({ env: { RELAY_CERTIFICATE: certificate, RELAY_PRIVATE_KEY: key } });
    const response = await get(service, "/inbox");
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "relay identity misconfigured" });
  }
});

test("identity secrets: one without the other, bad base64 or a key of the wrong length fails closed without naming a value", async () => {
  const certificate = randomBytes(40).toString("base64");
  const key = randomBytes(32).toString("base64");
  const cases = [
    { RELAY_CERTIFICATE: certificate },
    { RELAY_PRIVATE_KEY: key },
    { RELAY_CERTIFICATE: "not base64 !!", RELAY_PRIVATE_KEY: key },
    { RELAY_CERTIFICATE: certificate, RELAY_PRIVATE_KEY: "###" },
    { RELAY_CERTIFICATE: certificate, RELAY_PRIVATE_KEY: randomBytes(31).toString("base64") },
    { RELAY_CERTIFICATE: certificate, RELAY_PRIVATE_KEY: randomBytes(33).toString("base64") },
  ];
  for (const env of cases) {
    const { service, log } = open({ env });
    const response = await get(service, "/inbox");
    assert.equal(response.status, 503);
    const text = await response.text();
    assert.deepEqual(JSON.parse(text), { error: "relay identity misconfigured" });
    assert.equal(service.ready(), false);
    const everything = text + JSON.stringify(log.lines);
    for (const value of Object.values(env)) assert.ok(!everything.includes(value));
  }
});

test("without identity secrets the relay answers its routes and refuses the provider challenge", async () => {
  const { service } = open();
  const challenge = await post(service, "/provider-identity", JSON.stringify({ challenge: randomBytes(32).toString("base64") }), {
    "content-type": "application/json",
  });
  assert.ok(challenge.status >= 400, "an official client will not trust it");
  assert.equal((await get(service, "/inbox")).status, 401);
});

test("the alarm is set once at start, kept if one exists, and set again after every run", async () => {
  const { service, storage } = open();
  assert.equal(storage.currentAlarm(), null);
  await service.start();
  assert.equal(storage.currentAlarm(), NOW.getTime() + SCAN_INTERVAL_MS);
  await storage.setAlarm(123);
  await service.start();
  assert.equal(storage.currentAlarm(), 123, "an alarm already set is left alone");
  await service.alarm();
  assert.equal(storage.currentAlarm(), NOW.getTime() + SCAN_INTERVAL_MS);
});

test("a scan that fails is logged by name only, and the next alarm is still set", async () => {
  const scanning = {
    RelayCore: class {
      scan() {
        throw Object.assign(new Error("a private detail"), { name: "JsError" });
      }
      ready() {
        return true;
      }
    },
  };
  const { service, storage, log } = open({ withBindings: scanning });
  await service.alarm();
  assert.equal(storage.currentAlarm(), NOW.getTime() + SCAN_INTERVAL_MS);
  assert.equal(log.lines.length, 1);
  assert.ok(!JSON.stringify(log.lines).includes("private detail"));
});

test("the alarm's scan purges expired letters and works without an identity", async () => {
  const { service } = open();
  await service.alarm();
  assert.equal(service.ready(), true);
});

// --- The provider's console, through the real core ---------------------------

const OPERATOR = "ops@provider.test";
function withIdentity(extra = {}) {
  return open({
    env: {
      RELAY_CERTIFICATE: randomBytes(40).toString("base64"),
      RELAY_PRIVATE_KEY: randomBytes(32).toString("hex"),
      ...extra,
    },
  });
}
let counter = 0;
const operation = () => `op-service-${String((counter += 1)).padStart(6, "0")}`;
const ask = async (service, request, lock) => {
  const answer = service.operate({ body: JSON.stringify(request), operator: OPERATOR, lock });
  return { status: answer.status, body: JSON.parse(answer.body) };
};
const askChange = (service, request, lock) => ask(service, { operation_id: operation(), ...request }, lock);

// The lock, staged and confirmed.
async function lockOf(service) {
  const staged = (await ask(service, { op: "bootstrap" })).body.operator_lock;
  assert.equal((await ask(service, { op: "confirm_lock" }, staged)).status, 200);
  return staged;
}

test("the console answers a read with only the operator's identity", async () => {
  const { service } = withIdentity();
  const { status, body } = await ask(service, { op: "overview" });
  assert.equal(status, 200);
  assert.equal(body.operator_lock, false);
  assert.equal(body.identity_configured, true);
  assert.deepEqual(body.keys, { live: 0, revoked: 0, expired: 0, unassigned: 0 });
  assert.deepEqual(body.letters, { inbox: 0, devices: 0 });
  assert.equal(body.customers, 0);
});

test("the operator lock is staged, confirmed and shown once, and changing anything needs it and an operation id", async () => {
  const { service, log } = withIdentity();
  const issue = (lock, extra = {}) =>
    askChange(
      service,
      {
        op: "issue",
        name: "Acme Ltd",
        terms: "Five seats.",
        scopes: ["inbox.push", "inbox.pull"],
        recipient_public_key: randomBytes(32).toString("hex"),
        relay_url: "https://relay.example.test",
        ...extra,
      },
      lock,
    );
  assert.equal((await issue(undefined)).body.code, "no_lock");
  const staged = (await ask(service, { op: "bootstrap" })).body;
  assert.equal(staged.pending, true);
  const lock = staged.operator_lock;
  assert.match(lock, /^kql_[A-Za-z0-9_-]{20,}$/);
  assert.equal((await issue(lock)).body.code, "lock_unconfirmed", "a staged lock authorises nothing");
  assert.equal((await ask(service, { op: "confirm_lock" }, `kql_${randomBytes(32).toString("base64url")}`)).body.code, "lock_refused");
  assert.equal((await ask(service, { op: "confirm_lock" }, lock)).status, 200);
  assert.equal((await ask(service, { op: "bootstrap" })).status, 409);
  assert.equal((await issue(undefined)).body.code, "lock_required");
  assert.equal((await issue(`kql_${randomBytes(32).toString("base64url")}`)).body.code, "lock_refused");
  assert.equal((await ask(service, { op: "issue", name: "Acme", scopes: ["inbox.push"], recipient_public_key: randomBytes(32).toString("hex"), relay_url: "https://relay.example.test" }, lock)).body.code, "operation_id_required");
  assert.equal((await ask(service, { op: "keys" })).body.keys.length, 0);

  const issued = await issue(lock);
  assert.equal(issued.status, 200);
  assert.equal(issued.body.bundles.length, 2);
  for (const bundle of issued.body.bundles) {
    const bytes = Buffer.from(bundle.bundle_base64, "base64");
    assert.equal(bytes.subarray(0, 4).toString(), "KQXB", "a sealed export bundle");
    assert.ok(bundle.filename.endsWith(".kqkey"));
  }
  const keys = (await ask(service, { op: "keys" })).body.keys;
  assert.equal(keys.length, 2);
  assert.ok(keys.every((key) => key.customer === "Acme Ltd" && key.state === "live" && key.assigned));
  // Neither the lock nor a bearer is in any log or any later answer.
  assert.ok(!JSON.stringify(log.lines).includes(lock));
  for (const feed of ["keys", "actions", "auth"]) {
    assert.ok(!JSON.stringify((await ask(service, { op: "audit", feed })).body).includes(lock));
  }

  const voided = await askChange(service, { op: "void_licence", licence_id: issued.body.licence.id, reason: "end" }, lock);
  assert.equal(voided.status, 200);
  assert.equal(voided.body.revoked_keys.length, 2);
  assert.ok((await ask(service, { op: "keys" })).body.keys.every((key) => key.state === "revoked"));
});

test("a lost response is reconciled by the operation id, never done twice, through the real core", async () => {
  const { service } = withIdentity();
  const lock = await lockOf(service);
  const request = {
    op: "issue",
    operation_id: "op-lost-response-1",
    name: "Acme Ltd",
    scopes: ["inbox.push"],
    recipient_public_key: randomBytes(32).toString("hex"),
    relay_url: "https://relay.example.test",
  };
  const first = await ask(service, request, lock);
  assert.equal(first.status, 200);
  const again = await ask(service, request, lock);
  assert.deepEqual([again.status, again.body.code], [409, "already_done"]);
  assert.equal(again.body.operation.result.licence_id, first.body.licence.id);
  assert.ok(!JSON.stringify(again.body).includes("bundle_base64"));
  assert.equal((await ask(service, { op: "users" })).body.users.length, 1);
  assert.equal((await ask(service, { op: "keys" })).body.keys.length, 1);
});

test("without an identity the console cannot create the lock or issue, and says so", async () => {
  const { service } = open();
  assert.equal((await ask(service, { op: "overview" })).body.identity_configured, false);
  const created = await ask(service, { op: "bootstrap" });
  assert.deepEqual([created.status, created.body.code], [503, "no_identity"]);
  assert.equal((await ask(service, { op: "checkpoint" })).status, 503);
});

test("a console request that is malformed is refused before the core", async () => {
  const { service } = withIdentity();
  for (const request of [
    undefined,
    {},
    { body: 5, operator: OPERATOR },
    { body: "{}", operator: "" },
    { body: "{}", operator: "x".repeat(321) },
    { body: "{}", operator: OPERATOR, lock: 5 },
    { body: "{}", operator: OPERATOR, lock: "k".repeat(257) },
  ]) {
    assert.equal(service.operate(request).status, 400, JSON.stringify(request));
  }
  assert.equal(service.operate({ body: "x".repeat(MAX_OPERATE_BODY + 1), operator: OPERATOR }).status, 413);
  const unknown = await ask(service, { op: "mint" });
  assert.equal(unknown.status, 400);
});

test("a relay that failed to start answers the console with the same refusal as the public route", async () => {
  const { service } = open({ env: { RELAY_CERTIFICATE: randomBytes(40).toString("base64") } });
  const answer = service.operate({ body: JSON.stringify({ op: "overview" }), operator: OPERATOR });
  assert.equal(answer.status, 503);
  const status = await service.status();
  assert.equal(status.ready, false);
  assert.equal(status.failure, "relay identity misconfigured");
  assert.equal(status.relay, null);
});

test("a known key's requests, refusals, time and bytes are counted for the console, and an unknown bearer is not", async () => {
  const { service, storage } = withIdentity();
  const push = addKey(storage, "inbox.push");
  // A push key cannot pull: refused for its scope, and counted as such.
  assert.equal((await get(service, "/inbox", { authorization: `Bearer ${push}` })).status, 403);
  assert.equal((await get(service, "/inbox", { authorization: `Bearer ${push}` })).status, 403);
  const unknown = `kq_${randomBytes(32).toString("base64url")}`;
  assert.equal((await get(service, "/inbox", { authorization: `Bearer ${unknown}` })).status, 401);
  const view = (await ask(service, { op: "activity", hours: 24 })).body;
  assert.equal(view.by_key.length, 1);
  assert.deepEqual([view.by_key[0].route, view.by_key[0].outcome, view.by_key[0].count], ["inbox", "scope", 2]);
  assert.equal(view.totals.blocked, 2);
  assert.equal(view.totals.requests, 2);
  assert.ok(view.totals.bytes_out > 0, "the response bytes are counted");
  assert.equal((await ask(service, { op: "overview" })).body.last_24h.blocked, 2);
  assert.equal(storage.db.prepare("SELECT COUNT(*) AS n FROM access_activity").get().n, 1);
});

test("a failure to count a request never changes its answer", async () => {
  const { service, storage, log } = withIdentity();
  const push = addKey(storage, "inbox.push");
  storage.db.exec("DROP TABLE access_activity");
  assert.equal((await get(service, "/inbox", { authorization: `Bearer ${push}` })).status, 403);
  assert.ok(JSON.stringify(log.lines).includes("could not be counted"));
});

test("the console is not a route of the public fetch: the core knows no such path", async () => {
  const { service } = withIdentity();
  for (const path of ["/operate", "/api/operate", "/console", "/licences", "/users", "/status"]) {
    assert.equal((await post(service, path, JSON.stringify({ op: "overview" }))).status, 404, path);
  }
});

test("the scan drops activity past its retention and keeps the recent", async () => {
  const { service, storage } = withIdentity();
  const push = addKey(storage, "inbox.push");
  await get(service, "/inbox", { authorization: `Bearer ${push}` });
  const id = storage.db.prepare("SELECT id FROM api_keys").get().id;
  storage.db
    .prepare(
      "INSERT INTO access_activity (api_key_id, hour, route, outcome, count) VALUES (?, strftime('%Y-%m-%dT%H:00:00Z', 'now', '-91 days'), 'inbox', 'ok', 4)",
    )
    .run(id);
  await service.alarm();
  assert.equal(storage.db.prepare("SELECT COUNT(*) AS n FROM access_activity").get().n, 1);
});

test("the lock is replaced in two steps through the real core, and the old one stands until the new is confirmed", async () => {
  const { service } = withIdentity();
  const old = await lockOf(service);
  assert.equal((await ask(service, { op: "rotate_lock" })).body.code, "lock_required");
  const staged = await ask(service, { op: "rotate_lock" }, old);
  assert.equal(staged.status, 200);
  const fresh = staged.body.operator_lock;
  assert.notEqual(fresh, old);
  const attempt = (lock) =>
    askChange(service, { op: "void_key", key_id: 1 }, lock).then((answer) => answer.body.code ?? answer.status);
  assert.equal(await attempt(old), "not_found", "the old lock still stands until the new one is confirmed");
  assert.equal(await attempt(fresh), "lock_refused");
  assert.equal((await ask(service, { op: "confirm_lock" }, fresh)).status, 200);
  assert.equal(await attempt(old), "lock_refused");
  assert.equal(await attempt(fresh), "not_found", "the new lock is accepted (there is just no such key)");
});

test("the status joins what the core knows with what only the object can see", async () => {
  const meta = { id: "version-id-1", tag: "v1", timestamp: "2026-10-06T10:00:00.000Z" };
  const { service, storage } = withIdentity({ CF_VERSION_METADATA: meta });
  Object.defineProperty(storage.sql, "databaseSize", { value: 24576 });
  await service.start();
  const before = await service.status();
  assert.equal(before.ready, true);
  assert.equal(before.runtime.started_at, NOW.toISOString());
  assert.deepEqual(before.runtime.deployment, meta);
  assert.equal(before.runtime.storage_bytes, 24576);
  assert.equal(before.runtime.alarm.next_at, new Date(NOW.getTime() + SCAN_INTERVAL_MS).toISOString());
  assert.deepEqual([before.runtime.alarm.last_run_at, before.runtime.alarm.last_failure], [null, null]);
  assert.equal(before.relay.identity.configured, true);
  assert.deepEqual(before.relay.operator_lock, { exists: false, pending: false });
  assert.deepEqual(before.relay.counts, { customers: 0, keys: 0 });
  assert.ok(before.note.includes("not counted here"));

  // Requests admitted and refused for being busy are counted from the object's view.
  const key = addKey(storage, "inbox.pull", "a".repeat(64));
  await get(service, "/inbox", { authorization: `Bearer ${key}` });
  await service.alarm();
  const after = await service.status();
  assert.equal(after.runtime.requests_admitted, 1);
  assert.equal(after.runtime.alarm.last_run_at, NOW.toISOString());
  assert.equal(JSON.stringify(after).includes(key), false);
});

test("the status says plainly when the platform does not tell the size or the version", async () => {
  const { service } = open();
  const status = await service.status();
  assert.equal(status.runtime.storage_bytes, null);
  assert.equal(status.runtime.deployment, null);
  assert.equal(status.relay.identity.configured, false);
});

test("the schema keeps a delivered licence statement immutable in the real object storage", async () => {
  const { service, storage } = withIdentity();
  const lock = await lockOf(service);
  const made = await askChange(service, { op: "create_customer", name: "Acme" }, lock);
  const licence = await askChange(
    service,
    { op: "create_licence", customer_id: made.body.customer.id, terms: "As delivered." },
    lock,
  );
  assert.equal(licence.status, 200);
  assert.throws(() => storage.db.exec("UPDATE licence_versions SET terms = 'rewritten'"), /immutable/);
  assert.throws(() => storage.db.exec("DELETE FROM licence_versions"), /immutable/);
});

test("a second large letter body is refused while one is still being read, and the slot is freed after", async () => {
  const noop = async () => null;
  const { service } = open({ env: { LETTERS: { put: noop, get: noop, delete: noop } } });
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const slow = new ReadableStream({
    async pull(controller) {
      await gate;
      controller.close();
    },
  });
  const first = service.fetch(new Request(`${BASE}/inbox`, { method: "POST", body: slow, duplex: "half" }));
  await new Promise((resolve) => setTimeout(resolve, 5));
  const big = { "content-length": String(MAX_REQUEST_BODY + 1) };
  const refused = await post(service, "/inbox", "x", big);
  assert.equal(refused.status, 503);
  assert.equal(refused.headers.get("retry-after"), "1");
  // A small request is not held up by it.
  assert.notEqual((await get(service, "/health")).status, 503);
  release();
  await first;
  // The slot is free again: the same large declaration now gets past admission.
  const again = await post(service, "/inbox", "x", big);
  assert.notEqual(again.status, 503);
});
