// The public Worker (src/worker.js) with a fake Durable Object in place of the
// relay: what it lets through to the object, what it never does, and what every
// answer carries. Bearers are drawn at run time, never written as literals.
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import worker, { handle } from "../src/worker.js";
import { MAX_LARGE_LETTER_BODY, MAX_REQUEST_BODY, bodyLimit } from "../src/policy.js";
import { STATUS_CSP, STATUS_CSS, STATUS_HTML, STATUS_JS } from "../src/status-page.js";

const HOST = "relay.test";

function bearer() {
  return `kq_${randomBytes(32).toString("base64url")}`;
}

// A relay stand-in: records every request it was handed.
function fakeEnv({ hosts = HOST, ready = true, answer, limiter, withObject = true } = {}) {
  const forwarded = [];
  const stub = {
    ready: async () => {
      if (ready instanceof Error) throw ready;
      return ready;
    },
    fetch: async (request) => {
      forwarded.push(request);
      if (answer instanceof Error) throw answer;
      return answer ? answer(request) : Response.json({ ok: true });
    },
  };
  const env = { ALLOWED_HOSTS: hosts };
  if (withObject) env.RELAY = { idFromName: (name) => name, get: () => stub };
  if (limiter) env.RATE_LIMITER = limiter;
  return { env, forwarded };
}

function spyLog() {
  const lines = [];
  const record = (level) => (...args) => lines.push([level, ...args]);
  return { warn: record("warn"), error: record("error"), lines };
}

// Every route is under /relay (policy.js, RELAY_PREFIX): `call` adds it, so the
// tests read as the routes do; `callRaw` sends a path exactly as given.
const call = (env, path, init = {}, host = HOST, log = spyLog()) =>
  handle(new Request(`https://${host}/relay${path}`, init), env, log);
const callRaw = (env, path, init = {}, host = HOST, log = spyLog()) =>
  handle(new Request(`https://${host}${path}`, init), env, log);

test("an unconfigured Worker serves nothing, whatever the path", async () => {
  for (const hosts of ["", "   ", null, ","]) {
    const { env, forwarded } = fakeEnv({ hosts });
    if (hosts === null) delete env.ALLOWED_HOSTS; // the variable was never set
    for (const path of ["/health", "/ready", "/", "/inbox"]) {
      const response = await call(env, path);
      assert.equal(response.status, 503, `${JSON.stringify(hosts)} ${path}`);
      assert.deepEqual(await response.json(), { error: "relay not configured" });
    }
    assert.equal(forwarded.length, 0);
  }
});

test("only the configured host is served: a Version URL, a lookalike and a suffix are refused", async () => {
  const { env, forwarded } = fakeEnv({ hosts: "relay.test, Relay.Example.COM." });
  for (const host of ["relay.test", "RELAY.test", "relay.test.", "relay.example.com"]) {
    assert.equal((await call(env, "/health", {}, host)).status, 200, host);
  }
  for (const host of [
    "80cd71cc-keyquorum-relay.example.workers.dev",
    "cloudflare-workers-builds-keyquorum-relay.example.workers.dev",
    "evil-relay.test",
    "relay.test.evil.example",
    "sub.relay.test",
    "keyquorum-relay.example.workers.dev",
  ]) {
    for (const path of ["/health", "/inbox", "/"]) {
      const response = await call(env, path, { headers: { authorization: `Bearer ${bearer()}` } }, host);
      assert.equal(response.status, 404, `${host} ${path}`);
      assert.deepEqual(await response.json(), { error: "not found" });
    }
  }
  assert.equal(forwarded.length, 0, "a refused host never reaches the relay");
});

test("a refused host is logged without any header, bearer or body", async () => {
  const { env } = fakeEnv();
  const log = spyLog();
  const token = bearer();
  await call(env, "/inbox", { method: "POST", body: "{}", headers: { authorization: `Bearer ${token}` } }, "other.test", log);
  assert.equal(log.lines.length, 1);
  assert.ok(!JSON.stringify(log.lines).includes(token));
});

test("the wildcard serves any host (it is set only in the previews block)", async () => {
  const { env } = fakeEnv({ hosts: "*" });
  assert.equal((await call(env, "/health", {}, "anything-keyquorum-relay.example.workers.dev")).status, 200);
});

test("each customer route reaches the relay once, and nothing else does", async () => {
  const allowed = [
    ["POST", "/provider-identity"],
    ["POST", "/keycheck"],
    ["POST", "/inbox"],
    ["GET", "/inbox"],
    ["GET", "/inbox?after=3&limit=10"],
    ["GET", "/audit/api-keys"],
    ["PUT", "/trees"],
    ["GET", "/trees/team.one/context"],
    ["POST", "/devices/packages"],
    ["GET", "/devices/packages?after=1"],
    ["PUT", "/devices"],
    ["GET", "/devices/abc123"],
    ["GET", "/inbox/"],
  ];
  for (const [method, path] of allowed) {
    const { env, forwarded } = fakeEnv();
    const init = { method };
    if (method !== "GET") init.body = "{}";
    const response = await call(env, path, init);
    assert.equal(response.status, 200, `${method} ${path}`);
    assert.equal(forwarded.length, 1, `${method} ${path}`);
  }
});

test("no operator, documentation or mint route is routed on the public Worker", async () => {
  const refused = [
    ["GET", "/api-keys"],
    ["POST", "/api-keys"],
    ["POST", "/api-keys/1/revoke"],
    ["GET", "/audit"],
    ["GET", "/audit/keys"],
    ["GET", "/audit/api-keys/extra"],
    ["GET", "/swagger-ui/"],
    ["GET", "/api-docs/openapi.json"],
    ["POST", "/keys"],
    ["POST", "/keys/create"],
    ["POST", "/keys/rotate"],
    ["GET", "//api-keys"],
    ["GET", "/%61pi-keys"],
    ["GET", "/inbox/../api-keys"],
    ["GET", "/./api-keys/"],
    ["GET", "/health/"],
    ["GET", "/ready/x"],
  ];
  for (const [method, path] of refused) {
    const { env, forwarded } = fakeEnv();
    const response = await call(env, path, { method, headers: { authorization: `Bearer ${bearer()}` } });
    assert.equal(response.status, 404, `${method} ${path}`);
    assert.equal(forwarded.length, 0, `${method} ${path}`);
  }
});

test("a route with the wrong method is 405 with the methods it takes, anything unknown is 404", async () => {
  const { env, forwarded } = fakeEnv();
  const inbox = await call(env, "/inbox", { method: "DELETE" });
  assert.equal(inbox.status, 405);
  assert.equal(inbox.headers.get("allow"), "POST, GET");
  const health = await call(env, "/health", { method: "POST", body: "{}" });
  assert.equal(health.status, 405);
  assert.equal(health.headers.get("allow"), "GET, HEAD");
  assert.equal((await call(env, "/keycheck", { method: "GET" })).headers.get("allow"), "POST");
  assert.equal((await call(env, "/nowhere", { method: "PATCH", body: "x" })).status, 404);
  assert.equal((await call(env, "/inbox", { method: "OPTIONS" })).status, 405);
  assert.equal(forwarded.length, 0);
});

test("a declared body over the cap is 413 and never reaches the relay; the cap itself is allowed", async () => {
  const { env, forwarded } = fakeEnv();
  const over = await call(env, "/keycheck", {
    method: "POST",
    body: "x",
    headers: { "content-length": String(MAX_REQUEST_BODY + 1) },
  });
  assert.equal(over.status, 413);
  assert.equal(forwarded.length, 0);
  const at = await call(env, "/keycheck", {
    method: "POST",
    body: "x",
    headers: { "content-length": String(MAX_REQUEST_BODY) },
  });
  assert.equal(at.status, 200);
  assert.equal(forwarded.length, 1);
});

test("only a raw POST /inbox may declare a body as large as a large letter", async () => {
  const { env, forwarded } = fakeEnv();
  const declare = (length, extra = {}) => ({ method: "POST", body: "x", headers: { "content-length": String(length), ...extra } });
  // A raw letter up to the large cap is let through to the relay.
  for (const type of [{}, { "content-type": "application/octet-stream" }]) {
    assert.equal((await call(env, "/inbox", declare(MAX_REQUEST_BODY + 1, type))).status, 200);
    assert.equal((await call(env, "/inbox", declare(MAX_LARGE_LETTER_BODY, type))).status, 200);
    assert.equal((await call(env, "/inbox", declare(MAX_LARGE_LETTER_BODY + 1, type))).status, 413);
  }
  const reached = forwarded.length;
  // JSON, another route and another method keep the small cap.
  for (const [path, init] of [
    ["/inbox", declare(MAX_REQUEST_BODY + 1, { "content-type": "application/json" })],
    ["/devices/packages", declare(MAX_REQUEST_BODY + 1)],
    ["/trees", { ...declare(MAX_REQUEST_BODY + 1), method: "PUT" }],
  ]) {
    assert.equal((await call(env, path, init)).status, 413, path);
  }
  assert.equal(forwarded.length, reached, "none of those reached the relay");
});

test("the body limit is a function of the route and the content type alone", () => {
  assert.equal(bodyLimit("POST", "/inbox", undefined), MAX_REQUEST_BODY, "no bucket, no large body");
  assert.equal(bodyLimit("POST", "/inbox", undefined, true), MAX_LARGE_LETTER_BODY);
  assert.equal(bodyLimit("POST", "/inbox/", "application/octet-stream", true), MAX_LARGE_LETTER_BODY);
  assert.equal(bodyLimit("POST", "/inbox", "Application/JSON; charset=utf-8", true), MAX_REQUEST_BODY);
  assert.equal(bodyLimit("GET", "/inbox", undefined), MAX_REQUEST_BODY);
  assert.equal(bodyLimit("POST", "/inbox/x", undefined), MAX_REQUEST_BODY);
  assert.equal(bodyLimit("POST", "/devices/packages", undefined), MAX_REQUEST_BODY);
});

test("every answer is never cached and never sniffed, whatever the relay said", async () => {
  const cacheable = () =>
    new Response("{}", { status: 200, headers: { "cache-control": "public, max-age=600", etag: "x" } });
  const { env } = fakeEnv({ answer: cacheable });
  const answers = [
    await call(env, "/health"),
    await call(env, "/ready"),
    await call(env, "/"),
    await call(env, "/assets/status.js"),
    await call(env, "/assets/status.css"),
    await call(env, "/inbox"),
    await call(env, "/api-keys"),
    await call(env, "/inbox", { method: "DELETE" }),
    await call(env, "/health", {}, "other.test"),
    await call(fakeEnv({ hosts: "" }).env, "/health"),
    await call(env, "/inbox", { method: "POST", body: "x", headers: { "content-length": String(MAX_REQUEST_BODY + 1) } }),
  ];
  for (const response of answers) {
    assert.equal(response.headers.get("cache-control"), "no-store", String(response.status));
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  }
});

test("health answers from the Worker alone and takes HEAD", async () => {
  const { env, forwarded } = fakeEnv({ withObject: false });
  const get = await call(env, "/health");
  assert.equal(get.status, 200);
  assert.deepEqual(await get.json(), { status: "ok" });
  assert.equal((await call(env, "/health", { method: "HEAD" })).status, 200);
  assert.equal(forwarded.length, 0);
});

test("readiness is the relay's: ready is 200, anything else is 503 with Retry-After", async () => {
  const ok = await call(fakeEnv({ ready: true }).env, "/ready");
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { status: "ready" });
  for (const env of [
    fakeEnv({ ready: false }).env,
    fakeEnv({ ready: new Error("storage said something private") }).env,
    fakeEnv({ withObject: false }).env,
  ]) {
    const log = spyLog();
    const response = await call(env, "/ready", {}, HOST, log);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("retry-after"), "5");
    assert.deepEqual(await response.json(), { status: "unavailable" });
    assert.ok(!JSON.stringify(log.lines).includes("private"), "the error text is not logged");
  }
});

test("the relay's answer passes through with its status, body and content type", async () => {
  const unauthorized = () =>
    Response.json({ error: "invalid API key" }, { status: 401, headers: { "x-extra": "kept" } });
  const { env } = fakeEnv({ answer: unauthorized });
  const response = await call(env, "/inbox");
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "invalid API key" });
  assert.match(response.headers.get("content-type"), /application\/json/);
});

test("the bearer reaches the relay untouched and is never logged", async () => {
  const { env, forwarded } = fakeEnv({ limiter: { limit: async () => ({ success: true }) } });
  const log = spyLog();
  const token = bearer();
  await call(env, "/inbox", { headers: { authorization: `Bearer ${token}`, "x-api-key": token } }, HOST, log);
  assert.equal(forwarded[0].headers.get("authorization"), `Bearer ${token}`);
  assert.equal(forwarded[0].headers.get("x-api-key"), token);
  assert.ok(!JSON.stringify(log.lines).includes(token));
});

test("the rate limiter is keyed on the connecting address and refuses before the relay is called", async () => {
  const keys = [];
  let success = false;
  const limiter = { limit: async ({ key }) => (keys.push(key), { success }) };
  const { env, forwarded } = fakeEnv({ limiter });
  const refused = await call(env, "/inbox", { headers: { "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "198.51.100.1" } });
  assert.equal(refused.status, 429);
  assert.equal(refused.headers.get("retry-after"), "60");
  assert.deepEqual(keys, ["203.0.113.7"], "X-Forwarded-For is never read");
  assert.equal(forwarded.length, 0);
  success = true;
  assert.equal((await call(env, "/inbox", { headers: { "cf-connecting-ip": "203.0.113.7" } })).status, 200);
  await call(env, "/inbox");
  assert.equal(keys.at(-1), "unknown");
});

test("health, readiness and the page are not counted by the limiter", async () => {
  let counted = 0;
  const { env } = fakeEnv({ limiter: { limit: async () => (counted += 1, { success: true }) } });
  for (const path of ["/health", "/ready", "/", "/assets/status.js"]) await call(env, path);
  assert.equal(counted, 0);
});

test("a limiter that cannot answer does not stop the relay", async () => {
  const log = spyLog();
  const limiter = { limit: async () => { throw new Error("limiter down"); } };
  const { env, forwarded } = fakeEnv({ limiter });
  assert.equal((await call(env, "/inbox", {}, HOST, log)).status, 200);
  assert.equal(forwarded.length, 1);
  assert.equal(log.lines.length, 1);
});

test("a relay object that fails is a generic 503, and its message is not shown or logged", async () => {
  const { env } = fakeEnv({ answer: new Error("SQLITE_FULL: secret detail") });
  const log = spyLog();
  const response = await call(env, "/inbox", {}, HOST, log);
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), "5");
  const text = await response.text();
  assert.deepEqual(JSON.parse(text), { error: "relay unavailable" });
  assert.ok(!text.includes("SQLITE_FULL"));
  assert.ok(!JSON.stringify(log.lines).includes("secret detail"));
});

test("the status page is served with a locked-down policy and nothing inline or external", async () => {
  const { env } = fakeEnv();
  const page = await call(env, "/");
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-type"), /text\/html/);
  assert.equal(page.headers.get("content-security-policy"), STATUS_CSP);
  assert.equal(await page.text(), STATUS_HTML);
  assert.match((await call(env, "/assets/status.js")).headers.get("content-type"), /javascript/);
  assert.equal(await (await call(env, "/assets/status.js")).text(), STATUS_JS);
  assert.match((await call(env, "/assets/status.css")).headers.get("content-type"), /text\/css/);
  assert.equal(await (await call(env, "/assets/status.css")).text(), STATUS_CSS);
  assert.equal((await call(env, "/", { method: "POST", body: "x" })).status, 405);
});

test("the status page contract: no inline script or style, no handler, no outside origin, no innerHTML", () => {
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(STATUS_HTML), "an inline script");
  assert.ok(!/<style/i.test(STATUS_HTML), "an inline style block");
  assert.ok(!/\sstyle=/i.test(STATUS_HTML), "an inline style attribute");
  assert.ok(!/\son[a-z]+=/i.test(STATUS_HTML), "an inline event handler");
  assert.ok(!/<form|<iframe|<object|<embed/i.test(STATUS_HTML));
  for (const [name, text] of [["html", STATUS_HTML], ["css", STATUS_CSS], ["js", STATUS_JS]]) {
    assert.ok(!/https?:\/\//i.test(text), `${name} names an outside origin`);
  }
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(STATUS_JS));
  assert.ok(STATUS_CSP.includes("default-src 'none'") && STATUS_CSP.includes("frame-ancestors 'none'"));
  assert.ok(!/unsafe-inline|unsafe-eval|\*/.test(STATUS_CSP));
});

test("the default export is the same handler", async () => {
  const { env } = fakeEnv();
  const response = await worker.fetch(new Request(`https://${HOST}/relay/health`), env);
  assert.equal(response.status, 200);
});

test("another website's browser request is refused with 403 before routing, limiting or the relay", async () => {
  const limited = [];
  const { env, forwarded } = fakeEnv({ limiter: { limit: async (k) => (limited.push(k), { success: true }) } });
  const cases = [
    { "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
    { "sec-fetch-site": "same-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
    { origin: "https://bailey-forbes.com" },
    { origin: "null" },
  ];
  for (const headers of cases) {
    for (const path of ["/", "/health", "/ready", "/assets/status.js", "/inbox", "/nowhere"]) {
      const log = spyLog();
      const response = await call(env, path, { headers: { ...headers, authorization: `Bearer ${bearer()}` } }, HOST, log);
      assert.equal(response.status, 403, `${JSON.stringify(headers)} ${path}`);
      assert.deepEqual(await response.json(), { error: "cross-site requests are not served" });
      assert.equal(log.lines.length, 1);
      assert.equal(log.lines[0][0], "warn");
    }
  }
  assert.equal(forwarded.length, 0);
  assert.equal(limited.length, 0);
});

test("the site's own page, a typed address and a command-line client are served", async () => {
  const { env, forwarded } = fakeEnv();
  for (const headers of [
    {},
    { "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
    { "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty", origin: `https://${HOST}` },
  ]) {
    assert.equal((await call(env, "/health", { headers })).status, 200, JSON.stringify(headers));
  }
  assert.equal((await call(env, "/inbox", { headers: { "sec-fetch-site": "same-origin" } })).status, 200);
  assert.equal(forwarded.length, 1);
});

test("a refused host is answered as not found before the browser check says anything", async () => {
  const { env } = fakeEnv();
  const response = await call(env, "/health", { headers: { "sec-fetch-site": "cross-site" } }, "other.example");
  assert.equal(response.status, 404);
});

test("every answer forbids embedding and framing, and none carries a CORS header", async () => {
  const { env } = fakeEnv();
  for (const path of ["/", "/health", "/ready", "/assets/status.js", "/assets/status.css", "/inbox", "/nowhere"]) {
    const response = await call(env, path);
    assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin", path);
    assert.equal(response.headers.get("x-frame-options"), "DENY", path);
    assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin", path);
    for (const [name] of response.headers) assert.ok(!name.startsWith("access-control-"), `${path} ${name}`);
  }
  const refused = await call(env, "/inbox", { headers: { origin: "https://bailey-forbes.com" } });
  assert.equal(refused.headers.get("access-control-allow-origin"), null);
  assert.equal(refused.headers.get("x-frame-options"), "DENY");
});

test("a preflight from another site is refused, not answered", async () => {
  const { env, forwarded } = fakeEnv();
  const response = await call(env, "/inbox", {
    method: "OPTIONS",
    headers: { origin: "https://bailey-forbes.com", "access-control-request-method": "POST", "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors" },
  });
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("access-control-allow-origin"), null);
  assert.equal(forwarded.length, 0);
});

test("nothing outside /relay is served, so the rest of the domain is not the relay's", async () => {
  const outside = [
    ["GET", "/"],
    ["GET", "/health"],
    ["GET", "/ready"],
    ["GET", "/inbox"],
    ["POST", "/keycheck"],
    ["POST", "/provider-identity"],
    ["GET", "/assets/status.js"],
    ["GET", "/app"],
    ["GET", "/relayx/inbox"],
    ["GET", "/relay-admin/inbox"],
    ["GET", "/%72elay/inbox"],
    ["GET", "/relay%2Finbox"],
    ["GET", "/other/relay/inbox"],
    ["GET", "/RELAY/inbox"],
  ];
  for (const [method, path] of outside) {
    const { env, forwarded } = fakeEnv();
    const init = { method, headers: { authorization: `Bearer ${bearer()}` } };
    if (method !== "GET") init.body = "{}";
    const response = await callRaw(env, path, init);
    assert.equal(response.status, 404, `${method} ${path}`);
    assert.equal(forwarded.length, 0, `${method} ${path}`);
  }
});

test("the mount without its slash goes to the slash, and the relay is given the path below the mount", async () => {
  const { env, forwarded } = fakeEnv();
  const bare = await callRaw(env, "/relay?x=1");
  assert.equal(bare.status, 308);
  assert.equal(bare.headers.get("location"), "/relay/?x=1");
  assert.equal(bare.headers.get("cache-control"), "no-store");
  assert.equal((await callRaw(env, "/relay", { method: "POST", body: "{}" })).status, 405);
  const page = await callRaw(env, "/relay/");
  assert.equal(page.status, 200);
  assert.equal(await page.text(), STATUS_HTML);
  assert.equal(forwarded.length, 0);

  const response = await call(env, "/inbox?after=3&limit=10", { method: "GET" });
  assert.equal(response.status, 200);
  assert.equal(forwarded.length, 1);
  const seen = new URL(forwarded[0].url);
  assert.equal(seen.pathname, "/inbox");
  assert.equal(seen.search, "?after=3&limit=10");
});

test("the status page's links are relative, so it works under any mount", () => {
  assert.match(STATUS_HTML, /href="assets\/status\.css"/);
  assert.match(STATUS_HTML, /src="assets\/status\.js"/);
  assert.match(STATUS_JS, /check\("health"\)/);
  assert.match(STATUS_JS, /check\("ready"\)/);
  for (const text of [STATUS_HTML, STATUS_JS]) assert.doesNotMatch(text, /["'`]\/(relay|health|ready|assets)/);
});

// A staging relay sits on the same host as production, under its own path.
test("a staging relay is mounted at /relay/staging-user and answers nothing else, production's path included", async () => {
  const STAGING = "/relay/staging-user";
  const make = () => {
    const made = fakeEnv();
    made.env.MOUNT_PATH = STAGING;
    return made;
  };
  const { env, forwarded } = make();
  assert.equal((await callRaw(env, `${STAGING}/health`)).status, 200);
  assert.equal((await callRaw(env, `${STAGING}/ready`)).status, 200);
  assert.equal((await callRaw(env, `${STAGING}/`)).status, 200);
  assert.equal((await callRaw(env, STAGING)).status, 308);
  assert.equal((await callRaw(env, `${STAGING}/inbox`)).status, 200);
  assert.equal(new URL(forwarded[0].url).pathname, "/inbox");
  for (const path of ["/relay/health", "/relay/inbox", "/relay/", "/relay", "/relay/staging-userx/inbox", "/relay/staging/inbox", "/relay/staging-admin/inbox", "/inbox", "/"]) {
    const other = make();
    const response = await callRaw(other.env, path);
    assert.equal(response.status, 404, path);
    assert.equal(other.forwarded.length, 0, path);
  }
});

test("a mount that is not valid leaves the relay unconfigured, never wider", async () => {
  for (const value of ["/", "relay", "/relay/", "/relay/Staging", "/relay/a/b", "/other", "/relay/staging_user", "/relay/-x", 7, {}]) {
    const { env, forwarded } = fakeEnv();
    env.MOUNT_PATH = value;
    const response = await callRaw(env, "/relay/health");
    assert.equal(response.status, 503, String(value));
    assert.equal(forwarded.length, 0);
  }
  // Unset or empty is the default, /relay.
  for (const value of [undefined, ""]) {
    const { env } = fakeEnv();
    env.MOUNT_PATH = value;
    assert.equal((await callRaw(env, "/relay/health")).status, 200);
  }
});

// A Worker Preview has a host to itself; there the root may lead to the relay.
test("with ROOT_REDIRECT set, only a GET or HEAD of the exact root goes to the mount, and nothing else changes", async () => {
  const { env, forwarded } = fakeEnv();
  env.ROOT_REDIRECT = "1";
  const root = await callRaw(env, "/?x=1");
  assert.equal(root.status, 307);
  assert.equal(root.headers.get("location"), "/relay/?x=1");
  assert.equal(root.headers.get("cache-control"), "no-store");
  assert.equal((await callRaw(env, "/", { method: "HEAD" })).status, 307);
  assert.equal((await callRaw(env, "/", { method: "POST", body: "{}" })).status, 404);
  for (const path of ["/health", "/inbox", "/relayx", "/other", "//", "/%2F"]) {
    assert.equal((await callRaw(env, path)).status, 404, path);
  }
  assert.equal((await callRaw(env, "/relay/health")).status, 200);
  assert.equal(forwarded.length, 0);
  // A different mount is where it leads.
  env.MOUNT_PATH = "/relay/staging-user";
  assert.equal((await callRaw(env, "/")).headers.get("location"), "/relay/staging-user/");
});

test("without ROOT_REDIRECT, or with any value but 1, the root is a 404 as on a real domain", async () => {
  for (const value of [undefined, "", "0", "true", "yes", 1]) {
    const { env } = fakeEnv();
    env.ROOT_REDIRECT = value;
    assert.equal((await callRaw(env, "/")).status, 404, String(value));
  }
});

test("links and redirect chains reach only the status page, including the preview root", async () => {
  for (const site of ["cross-site", "same-site"]) {
    for (const method of ["GET", "HEAD"]) {
      const headers = { "sec-fetch-site": site, "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" };
      for (const mount of ["/relay", "/relay/staging-user"]) {
        const { env, forwarded } = fakeEnv();
        env.MOUNT_PATH = mount;
        env.ROOT_REDIRECT = "1";
        const root = await callRaw(env, "/?from=github", { method, headers });
        assert.equal(root.status, 307);
        assert.equal(root.headers.get("location"), `${mount}/?from=github`);
        const bare = await callRaw(env, mount, { method, headers });
        assert.equal(bare.status, 308);
        assert.equal(bare.headers.get("location"), `${mount}/`);
        const page = await callRaw(env, `${mount}/`, { method, headers });
        assert.equal(page.status, 200);
        assert.equal(page.headers.get("access-control-allow-origin"), null);
        for (const path of ["/inbox", "/health", "/ready", "/assets/status.js"]) {
          assert.equal((await callRaw(env, `${mount}${path}`, { method, headers })).status, 403, path);
        }
        assert.equal(forwarded.length, 0);
      }
    }
  }
});

test("status-page navigation does not permit forms, frames, fetches, or foreign Origins", async () => {
  const { env, forwarded } = fakeEnv();
  env.ROOT_REDIRECT = "1";
  const link = { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" };
  for (const path of ["/", "/relay", "/relay/"]) {
    for (const init of [
      { method: "POST", headers: link, body: "{}" },
      { headers: { ...link, "sec-fetch-dest": "iframe" } },
      { headers: { ...link, "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" } },
      { headers: { ...link, origin: "https://github.com" } },
      { headers: { ...link, origin: "null" } },
    ]) {
      assert.equal((await callRaw(env, path, init)).status, 403, path);
    }
  }
  delete env.ROOT_REDIRECT;
  assert.equal((await callRaw(env, "/", { headers: link })).status, 403);
  assert.equal(forwarded.length, 0);
});
