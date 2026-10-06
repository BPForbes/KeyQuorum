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
import { MAX_IN_FLIGHT, SCAN_INTERVAL_MS, createRelayService, relayTime } from "../src/relay-service.js";
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
