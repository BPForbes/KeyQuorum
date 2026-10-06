// The console's one data route (POST /api/operate): what the admin Worker keeps
// out, and that everything else goes to the relay's object untouched. The
// object is a stand-in here; the real core is exercised in
// test/relay-service.test.mjs. Operator locks are drawn at run time.
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { handle } from "./index.js";

const ENV = { ACCESS_TEAM_DOMAIN: "relay-test.cloudflareaccess.com", ACCESS_AUD: "app-aud-tag" };
const EMAIL = "operator@example.com";
const allow = (claims = { email: EMAIL, exp: 1_900_000_000 }) => async () => ({ ok: true, claims });
const refuse = () => async () => ({ ok: false, reason: "no token" });
const newLock = () => `kql_${randomBytes(32).toString("base64url")}`;

// A relay object stand-in that records what it was asked.
function relay({ answer = { status: 200, body: JSON.stringify({ ok: true }) }, throws } = {}) {
  const calls = [];
  const stub = {
    operate: async (request) => {
      calls.push(request);
      if (throws) throw throws;
      return typeof answer === "function" ? answer(request) : answer;
    },
  };
  return { calls, binding: { idFromName: (name) => name, get: () => stub } };
}

const operate = (body, { headers = {}, method = "POST", contentType = "application/json" } = {}) =>
  new Request("https://admin.test/api/operate", {
    method,
    headers: { ...(contentType ? { "content-type": contentType } : {}), ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

async function ask(request, { binding, verify = allow(), env = {} } = {}) {
  return handle(request, { ...ENV, ASSETS: { fetch: async () => new Response("page") }, RELAY: binding, ...env }, { verify });
}

function captureConsole() {
  const lines = [];
  const originals = { warn: console.warn, error: console.error, log: console.log };
  for (const level of Object.keys(originals)) console[level] = (...args) => lines.push(args.join(" "));
  return {
    lines,
    restore: () => Object.assign(console, originals),
  };
}

test("without a valid Access token the relay is never asked, whatever the request", async () => {
  const { calls, binding } = relay();
  const response = await ask(operate({ op: "overview" }), { binding, verify: refuse() });
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: "access required" });
  assert.equal(calls.length, 0);
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
    const response = await ask(operate({ op: "issue" }, { headers }), { binding, verify });
    assert.equal(response.status, 403, JSON.stringify(headers));
    assert.equal(response.headers.get("access-control-allow-origin"), null);
  }
  // A cross-site form post is a navigation, but not a GET: refused too.
  const form = operate("op=issue", {
    contentType: "application/x-www-form-urlencoded",
    headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
  });
  assert.equal((await ask(form, { binding, verify })).status, 403);
  assert.equal(verified, 0);
  assert.equal(calls.length, 0);
});

test("the page's own request, same-origin with a lock, reaches the relay with the person, the body and the lock", async () => {
  const { calls, binding } = relay({ answer: { status: 201, body: JSON.stringify({ licence: { id: 1 } }) } });
  const lock = newLock();
  const body = { op: "issue", client: "Acme", scopes: ["inbox.push"] };
  const response = await ask(
    operate(body, {
      headers: {
        "x-operator-lock": lock,
        origin: "https://admin.test",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
      },
    }),
    { binding },
  );
  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), { licence: { id: 1 } });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { body: JSON.stringify(body), operator: EMAIL, lock });
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("content-type"), /application\/json/);
});

test("a read carries no lock, and the object is told so", async () => {
  const { calls, binding } = relay();
  await ask(operate({ op: "overview" }), { binding });
  assert.equal(calls[0].lock, null);
});

test("only a signed-in person may use the console, not a service token", async () => {
  const { calls, binding } = relay();
  for (const claims of [{}, { email: "" }, { email: "   " }, { email: 7 }, { email: "a".repeat(321) }]) {
    const response = await ask(operate({ op: "overview" }), { binding, verify: allow(claims) });
    assert.equal(response.status, 403, JSON.stringify(claims));
  }
  assert.equal(calls.length, 0);
});

test("a request that is not JSON, too large, malformed or for an unknown operation never reaches the relay", async () => {
  const { calls, binding } = relay();
  const cases = [
    [operate({ op: "overview" }, { contentType: "text/plain" }), 415],
    [operate({ op: "overview" }, { contentType: null }), 415],
    [operate("not json"), 400],
    [operate("null"), 400],
    [operate("[]"), 400],
    [operate({ op: "mint" }), 400],
    [operate({ op: 7 }), 400],
    [operate({}), 400],
    [operate({ op: "overview" }, { headers: { "x-operator-lock": "not-a-lock" } }), 400],
    [operate({ op: "overview" }, { headers: { "x-operator-lock": `kql_${"a".repeat(300)}` } }), 400],
    [operate({ op: "overview" }, { headers: { "x-operator-lock": "kq_wrongprefix_aaaaaaaaaaaaaaaaaaaaaaaa" } }), 400],
    [operate(JSON.stringify({ op: "issue", terms: "x".repeat(70 * 1024) })), 413],
  ];
  for (const [request, status] of cases) {
    assert.equal((await ask(request, { binding })).status, status, `${request.headers.get("content-type")}`);
  }
  // A streamed body with no declared length is bounded as it is read.
  const stream = new ReadableStream({
    pull(controller) {
      controller.enqueue(new Uint8Array(32 * 1024));
    },
  });
  const streamed = new Request("https://admin.test/api/operate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: stream,
    duplex: "half",
  });
  assert.equal((await ask(streamed, { binding })).status, 413);
  assert.equal(calls.length, 0);
});

test("every operation the Worker allows is one the relay core knows, and the reverse", () => {
  const rust = readFileSync(fileURLToPath(new URL("../../../src/relay/operator.rs", import.meta.url)), "utf8");
  const enumBody = rust.match(/enum Request \{([\s\S]*?)\n\}/)[1];
  const core = [...enumBody.matchAll(/^    ([A-Z][A-Za-z]+)\s*[{,]/gm)].map((m) =>
    m[1].replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase(),
  );
  const worker = readFileSync(fileURLToPath(new URL("./index.js", import.meta.url)), "utf8");
  const listed = [...worker.match(/new Set\(\[([\s\S]*?)\]\)/)[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  assert.deepEqual([...listed].sort(), [...core].sort());
});

test("the lock and the request never reach a log, and a relay failure is a generic 503", async () => {
  const lock = newLock();
  const captured = captureConsole();
  try {
    const { binding } = relay({ throws: Object.assign(new Error(`failed with ${lock}`), { name: "StoreError" }) });
    const response = await ask(
      operate({ op: "issue", client: "Secret Client Name" }, { headers: { "x-operator-lock": lock } }),
      { binding },
    );
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "relay unavailable" });
    const logged = captured.lines.join("\n");
    assert.ok(logged.includes("StoreError"));
    assert.ok(!logged.includes(lock));
    assert.ok(!logged.includes("Secret Client Name"));
  } finally {
    captured.restore();
  }
});

test("an answer in an unexpected shape is a 502, and a missing binding a 503", async () => {
  const captured = captureConsole();
  try {
    for (const answer of [null, {}, { status: "200", body: "{}" }, { status: 99, body: "{}" }, { status: 200, body: 5 }]) {
      const { binding } = relay({ answer });
      assert.equal((await ask(operate({ op: "overview" }), { binding })).status, 502, JSON.stringify(answer));
    }
  } finally {
    captured.restore();
  }
  const unbound = await ask(operate({ op: "overview" }), { binding: undefined });
  assert.equal(unbound.status, 503);
  assert.deepEqual(await unbound.json(), { error: "relay not connected" });
});

test("the relay's refusals pass through with their status and body", async () => {
  for (const status of [400, 401, 404, 409, 500]) {
    const { binding } = relay({ answer: { status, body: JSON.stringify({ error: "x", code: "c" }) } });
    const response = await ask(operate({ op: "overview" }), { binding });
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error: "x", code: "c" });
  }
});

test("no route of the public Worker leads to the console, and the console has no mint route without a body", async () => {
  const worker = readFileSync(fileURLToPath(new URL("../../src/worker.js", import.meta.url)), "utf8");
  const policy = readFileSync(fileURLToPath(new URL("../../src/policy.js", import.meta.url)), "utf8");
  assert.ok(!/operate\(/.test(worker + policy), "the public Worker never calls the console method");
  assert.ok(!/\/api\/operate/.test(worker + policy));
});
