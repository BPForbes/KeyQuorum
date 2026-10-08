// The console's API through the admin Worker (POST and GET under /api): what
// it keeps out, and that everything else goes to the relay's object as the
// route table says. The object is a stand-in here; the real core is exercised
// in test/relay-service.test.mjs. Operator locks are drawn at run time.
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { handle } from "./index.js";

const ENV = { ACCESS_TEAM_DOMAIN: "relay-test.cloudflareaccess.com", ACCESS_AUD: "app-aud-tag" };
const EMAIL = "operator@example.com";
const ORIGIN = "https://admin.test";
const allow = (claims = { email: EMAIL, exp: 1_900_000_000 }) => async () => ({ ok: true, claims });
const refuse = () => async () => ({ ok: false, reason: "no token" });
const newLock = () => `kql_${randomBytes(32).toString("base64url")}`;
const OP = "op-0123456789";

// A relay object stand-in that records what it was asked.
function relay({ answer = { status: 200, body: JSON.stringify({ ok: true }) }, throws, statusAnswer = { ready: true } } = {}) {
  const calls = [];
  const statusCalls = [];
  const stub = {
    operate: async (request) => {
      calls.push(request);
      if (throws) throw throws;
      return typeof answer === "function" ? answer(request) : answer;
    },
    status: async () => {
      statusCalls.push(1);
      if (throws) throw throws;
      return statusAnswer;
    },
  };
  return { calls, statusCalls, binding: { idFromName: (name) => name, get: () => stub } };
}

// What the page's own fetch carries.
const SAME = { origin: ORIGIN, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" };

function req(path, { method = "GET", headers = {}, body, contentType = "application/json" } = {}) {
  const init = { method, headers: { ...headers } };
  if (body !== undefined) {
    init.body = typeof body === "string" ? body : JSON.stringify(body);
    if (contentType) init.headers["content-type"] = contentType;
  }
  return new Request(`${ORIGIN}${path}`, init);
}

const change = (path, body = {}, extra = {}) =>
  req(path, { method: "POST", body, headers: { ...SAME, "idempotency-key": OP, "x-operator-lock": newLock(), ...extra } });

async function ask(request, { binding, verify = allow(), env = {} } = {}) {
  return handle(request, { ...ENV, ASSETS: { fetch: async () => new Response("page") }, RELAY_ADMIN: binding, ...env }, { verify });
}

function captureConsole() {
  const lines = [];
  const originals = { warn: console.warn, error: console.error, log: console.log };
  for (const level of Object.keys(originals)) console[level] = (...args) => lines.push(args.join(" "));
  return { lines, restore: () => Object.assign(console, originals) };
}

test("without a valid Access token the relay is never asked, whatever the request", async () => {
  const { calls, statusCalls, binding } = relay();
  for (const request of [req("/api/users"), req("/api/status"), change("/api/users")]) {
    const response = await ask(request, { binding, verify: refuse() });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: "access required" });
  }
  assert.equal(calls.length + statusCalls.length, 0);
});

test("a request from another site is refused before the token is looked at or the relay is asked", async () => {
  const { calls, binding } = relay();
  let verified = 0;
  const verify = async () => (verified++, { ok: true, claims: { email: EMAIL } });
  for (const headers of [
    { "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
    { "sec-fetch-site": "same-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
    { origin: "https://bailey-forbes.com" },
    { origin: "null" },
  ]) {
    for (const request of [req("/api/users", { headers }), req("/api/users", { method: "POST", body: {}, headers: { ...headers, "idempotency-key": OP } })]) {
      const response = await ask(request, { binding, verify });
      assert.equal(response.status, 403, JSON.stringify(headers));
      assert.equal(response.headers.get("access-control-allow-origin"), null);
    }
  }
  const form = req("/api/users", {
    method: "POST",
    body: "name=x",
    contentType: "application/x-www-form-urlencoded",
    headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
  });
  assert.equal((await ask(form, { binding, verify })).status, 403);
  assert.equal(verified, 0);
  assert.equal(calls.length, 0);
});

test("a change must come from this site's own origin, even from a browser Access let in", async () => {
  const { calls, binding } = relay();
  const good = { origin: ORIGIN, "sec-fetch-site": "same-origin", "idempotency-key": OP, "x-operator-lock": newLock() };
  // The cross-site check already refuses a foreign Origin; here the Origin is
  // absent or the fetch metadata says otherwise, which only the second check sees.
  for (const headers of [
    { ...good, origin: undefined },
    { ...good, "sec-fetch-site": "none" },
    { ...good, "sec-fetch-site": "same-site" },
  ]) {
    const clean = Object.fromEntries(Object.entries(headers).filter(([, v]) => v !== undefined));
    const response = await ask(req("/api/users", { method: "POST", body: { name: "Acme" }, headers: clean }), { binding });
    assert.equal(response.status, 403, JSON.stringify(headers));
  }
  assert.equal(calls.length, 0);
  assert.equal((await ask(req("/api/users", { method: "POST", body: { name: "Acme" }, headers: good }), { binding })).status, 200);
  // A read needs no origin: a typed address or a bookmark is fine.
  assert.equal((await ask(req("/api/users"), { binding })).status, 200);
});

test("only a signed-in person may use the console, not a service token", async () => {
  const { calls, binding } = relay();
  for (const claims of [{}, { email: "" }, { email: "   " }, { email: 7 }, { email: "a".repeat(321) }]) {
    for (const request of [req("/api/users"), change("/api/users", { name: "x" })]) {
      const response = await ask(request, { binding, verify: allow(claims) });
      assert.equal(response.status, 403, JSON.stringify(claims));
    }
  }
  assert.equal(calls.length, 0);
});

test("a read goes to the relay as the route says, with the verified person and no lock", async () => {
  const { calls, binding } = relay();
  await ask(req("/api/users?search=acme&status=active&limit=10", { headers: { "x-operator-lock": newLock() } }), { binding });
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].body), { search: "acme", status: "active", limit: 10, op: "users" });
  assert.equal(calls[0].operator, EMAIL);
  assert.equal(calls[0].lock, null, "a lock sent with a read is never forwarded");
  await ask(req("/api/users/7/activity?hours=168&route=inbox"), { binding });
  assert.deepEqual(JSON.parse(calls[1].body), { hours: 168, route: "inbox", customer_id: 7, op: "activity" });
  await ask(req("/api/audit?feed=keys&before=40"), { binding });
  assert.deepEqual(JSON.parse(calls[2].body), { feed: "keys", before: 40, op: "audit" });
});

test("a change carries the person, the lock and the operation id, and the browser cannot choose the operation, id or target", async () => {
  const { calls, binding } = relay({ answer: { status: 200, body: JSON.stringify({ key_id: 9 }) } });
  const lock = newLock();
  const response = await ask(
    change(
      "/api/keys/9/rotate",
      // Everything the browser might try to smuggle in through the body.
      { via: "letter", grace_seconds: 3600, op: "void_licence", operation_id: "op-smuggled-01", key_id: 1, licence_id: 2 },
      { "x-operator-lock": lock, "idempotency-key": "op-from-header-1" },
    ),
    { binding },
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { key_id: 9 });
  assert.equal(calls.length, 1);
  const sent = JSON.parse(calls[0].body);
  assert.equal(sent.op, "rotate");
  assert.equal(sent.operation_id, "op-from-header-1");
  assert.equal(sent.key_id, 9);
  assert.equal(sent.via, "letter");
  assert.equal(calls[0].operator, EMAIL);
  assert.equal(calls[0].lock, lock);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("access-control-allow-origin"), null);
});

test("a change needs an Idempotency-Key, and the lock ceremony and the checkpoint do not", async () => {
  const { calls, binding } = relay();
  for (const key of [undefined, "short", "has space 123", "x".repeat(65), "semi;colon;123"]) {
    const extra = key === undefined ? { "idempotency-key": undefined } : { "idempotency-key": key };
    const headers = { ...SAME, "x-operator-lock": newLock(), ...extra };
    for (const name of Object.keys(headers)) if (headers[name] === undefined) delete headers[name];
    const response = await ask(req("/api/users", { method: "POST", body: { name: "Acme" }, headers }), { binding });
    assert.equal(response.status, 400, String(key));
    assert.equal((await response.json()).code, "operation_id_required");
  }
  assert.equal(calls.length, 0);
  for (const path of ["/api/operator-lock/bootstrap", "/api/operator-lock/replace", "/api/operator-lock/confirm", "/api/checkpoints", "/api/provider-package"]) {
    const response = await ask(req(path, { method: "POST", headers: SAME, body: "{}" }), { binding });
    assert.equal(response.status, 200, path);
  }
  assert.deepEqual(calls.map((c) => JSON.parse(c.body).op), ["bootstrap", "rotate_lock", "confirm_lock", "checkpoint", "provider_package"]);
  assert.ok(calls.every((c) => !("operation_id" in JSON.parse(c.body))));
});

test("a lock that is not shaped like one is refused before the relay, and the checkpoint and provider package never take one", async () => {
  const { calls, binding } = relay();
  for (const lock of ["not-a-lock", `kql_${"a".repeat(300)}`, "kq_wrongprefix_aaaaaaaaaaaaaaaaaaaaaaaa", "kql_short"]) {
    const response = await ask(change("/api/users", { name: "x" }, { "x-operator-lock": lock }), { binding });
    assert.equal(response.status, 400, lock);
  }
  assert.equal(calls.length, 0);
  await ask(req("/api/checkpoints", { method: "POST", headers: { ...SAME, "x-operator-lock": newLock() }, body: "{}" }), { binding });
  assert.equal(calls[0].lock, null);
  await ask(req("/api/provider-package", { method: "POST", headers: { ...SAME, "x-operator-lock": newLock() }, body: "{}" }), { binding });
  assert.equal(calls[1].lock, null);
});

test("a body that is not JSON, not an object, too large, or an unknown route or query never reaches the relay", async () => {
  const { calls, binding } = relay();
  const post = (path, init) => ask(req(path, { method: "POST", headers: { ...SAME, "idempotency-key": OP, "x-operator-lock": newLock() }, ...init }), { binding });
  assert.equal((await post("/api/users", { body: "x=1", contentType: "application/x-www-form-urlencoded" })).status, 415);
  assert.equal((await post("/api/users", { body: "x", contentType: "text/plain" })).status, 415);
  assert.equal((await post("/api/users", { body: "not json" })).status, 400);
  assert.equal((await post("/api/users", { body: "null" })).status, 400);
  assert.equal((await post("/api/users", { body: "[]" })).status, 400);
  assert.equal((await post("/api/users", { body: JSON.stringify({ name: "x".repeat(70 * 1024) }) })).status, 413);
  assert.equal((await post("/api/nothing", { body: "{}" })).status, 404);
  assert.equal((await post("/api/users/abc/keys", { body: "{}" })).status, 404);
  assert.equal((await ask(req("/api/users?limit=abc"), { binding })).status, 400);
  assert.equal((await ask(req("/api/users?op=issue"), { binding })).status, 400);
  // A streamed body with no declared length is bounded as it is read.
  const stream = new ReadableStream({ pull: (controller) => controller.enqueue(new Uint8Array(32 * 1024)) });
  const streamed = new Request(`${ORIGIN}/api/users`, {
    method: "POST",
    headers: { ...SAME, "content-type": "application/json", "idempotency-key": OP, "x-operator-lock": newLock() },
    body: stream,
    duplex: "half",
  });
  assert.equal((await ask(streamed, { binding })).status, 413);
  assert.equal(calls.length, 0);
});

test("the operator is rate limited, reads and changes separately, per verified identity", async () => {
  const { calls, binding } = relay();
  const seen = [];
  const limiter = (name, allowed) => ({ limit: async ({ key }) => (seen.push([name, key]), { success: allowed() }) });
  let writes = 0;
  const env = {
    READ_LIMITER: limiter("read", () => true),
    WRITE_LIMITER: limiter("write", () => ++writes <= 1),
  };
  assert.equal((await ask(req("/api/users"), { binding, env })).status, 200);
  assert.equal((await ask(change("/api/users", { name: "a" }), { binding, env })).status, 200);
  const blocked = await ask(change("/api/users", { name: "b" }), { binding, env });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get("retry-after"), "60");
  assert.deepEqual(seen, [["read", EMAIL], ["write", EMAIL], ["write", EMAIL]]);
  assert.equal(calls.length, 2, "a limited request never reaches the relay");
  // A limiter that cannot answer does not lock the operator out.
  const captured = captureConsole();
  try {
    const broken = { limit: async () => { throw new Error("down"); } };
    assert.equal((await ask(req("/api/users"), { binding, env: { READ_LIMITER: broken } })).status, 200);
  } finally {
    captured.restore();
  }
});

test("the status route asks the object for its status and passes it on", async () => {
  const statusAnswer = { ready: true, runtime: { requests_admitted: 3 } };
  const { calls, statusCalls, binding } = relay({ statusAnswer });
  const response = await ask(req("/api/status"), { binding });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), statusAnswer);
  assert.equal(statusCalls.length, 1);
  assert.equal(calls.length, 0);
  assert.equal((await ask(req("/api/status", { method: "POST", headers: SAME, body: "{}" }), { binding })).status, 405);
});

test("the users licences route returns the customer and its licences only", async () => {
  const whole = { customer: { id: 7 }, licences: [{ id: 1 }], keys: [{ id: 99, secret_looking: "x" }] };
  const { binding } = relay({ answer: { status: 200, body: JSON.stringify(whole) } });
  const response = await ask(req("/api/users/7/licenses"), { binding });
  assert.deepEqual(await response.json(), { customer: { id: 7 }, licences: [{ id: 1 }] });
  const { binding: failing } = relay({ answer: { status: 404, body: JSON.stringify({ error: "no", code: "not_found" }) } });
  const missing = await ask(req("/api/users/7/licenses"), { binding: failing });
  assert.deepEqual([missing.status, (await missing.json()).code], [404, "not_found"]);
});

test("the relay's refusals pass through with their status and body", async () => {
  for (const status of [400, 401, 404, 409, 500]) {
    const { binding } = relay({ answer: { status, body: JSON.stringify({ error: "x", code: "c" }) } });
    const response = await ask(req("/api/overview"), { binding });
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error: "x", code: "c" });
  }
});

test("the lock, the request and the operation never reach a log, and a relay failure is a generic 503", async () => {
  const lock = newLock();
  const captured = captureConsole();
  try {
    const boom = Object.assign(new Error(`failed with ${lock} for Secret Client Name`), { name: "StoreError" });
    const { binding } = relay({ throws: boom });
    const response = await ask(
      change("/api/users", { name: "Secret Client Name" }, { "x-operator-lock": lock }),
      { binding },
    );
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "relay unavailable" });
    const status = await ask(req("/api/status"), { binding });
    assert.equal(status.status, 503);
    const logged = captured.lines.join("\n");
    assert.ok(logged.includes("StoreError"));
    for (const secret of [lock, "Secret Client Name", OP]) assert.ok(!logged.includes(secret), secret);
  } finally {
    captured.restore();
  }
});

test("an answer in an unexpected shape is a 502, and a missing binding a 503", async () => {
  const captured = captureConsole();
  try {
    for (const answer of [null, {}, { status: "200", body: "{}" }, { status: 99, body: "{}" }, { status: 200, body: 5 }]) {
      const { binding } = relay({ answer });
      assert.equal((await ask(req("/api/overview"), { binding })).status, 502, JSON.stringify(answer));
    }
  } finally {
    captured.restore();
  }
  const unbound = await ask(req("/api/overview"), { binding: undefined });
  assert.equal(unbound.status, 503);
  assert.deepEqual(await unbound.json(), { error: "relay not connected" });
});

test("the old single endpoint is gone, and no route of the public Worker leads to the console", async () => {
  const { calls, binding } = relay();
  assert.equal((await ask(change("/api/operate", { op: "overview" }), { binding })).status, 404);
  assert.equal(calls.length, 0);
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const worker = readFileSync(fileURLToPath(new URL("../../src/worker.js", import.meta.url)), "utf8");
  const policy = readFileSync(fileURLToPath(new URL("../../src/policy.js", import.meta.url)), "utf8");
  assert.ok(!/\.operate\(|\.status\(\)/.test(worker + policy), "the public Worker never calls the console methods");
  assert.ok(!/\/api\//.test(worker + policy));
});
