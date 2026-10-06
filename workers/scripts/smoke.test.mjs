import test from "node:test";
import assert from "node:assert/strict";
import { handle } from "../src/worker.js";
import { runAdminSmoke, runSmoke } from "./smoke.mjs";

// The real public Worker over a stand-in relay object: ready, 401 without a
// bearer, and a provider challenge that answers like a relay with an identity.
function relayEnv({ ready = true, identity = true } = {}) {
  const object = {
    ready: async () => ready,
    fetch: async (request) => {
      const path = new URL(request.url).pathname;
      if (path === "/inbox") return Response.json({ error: "unauthorized" }, { status: 401 });
      if (path === "/provider-identity") {
        return identity
          ? Response.json({ certificate: "AAAA", signature: "BBBB" })
          : Response.json({ error: "mailbox host is not configured with a provider identity" }, { status: 503 });
      }
      return Response.json({ error: "not found" }, { status: 404 });
    },
  };
  return { ALLOWED_HOSTS: "relay.test", RELAY: { idFromName: (name) => name, get: () => object } };
}

const silent = { warn() {}, error() {} };
const via = (env) => (url, init) => handle(new Request(url, init), env, silent);
const viaWorker = via(relayEnv());

test("the Worker passes the smoke test", async () => {
  assert.deepEqual(await runSmoke("https://relay.test", { fetchImpl: viaWorker }), []);
});

test("a relay without its identity yet is not a smoke failure, a broken one is", async () => {
  const unconfigured = via(relayEnv({ identity: false }));
  assert.deepEqual(await runSmoke("https://relay.test", { fetchImpl: unconfigured }), []);
  const broken = (url, init) =>
    new URL(url).pathname === "/provider-identity"
      ? Promise.resolve(new Response("{}", { status: 500 }))
      : viaWorker(url, init);
  const problems = await runSmoke("https://relay.test", { fetchImpl: broken });
  assert.ok(problems.some((p) => p.includes("POST /provider-identity answered 500")));
  const empty = (url, init) =>
    new URL(url).pathname === "/provider-identity"
      ? Promise.resolve(Response.json({ certificate: "AAAA" }))
      : viaWorker(url, init);
  assert.ok((await runSmoke("https://relay.test", { fetchImpl: empty })).some((p) => p.includes("without a certificate")));
});

test("the Worker answers health, refuses other methods, and routes no operator path", async () => {
  const health = await viaWorker("https://relay.test/health", { method: "GET" });
  assert.equal(health.status, 200);
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.deepEqual(await health.json(), { status: "ok" });
  const post = await viaWorker("https://relay.test/health", { method: "POST" });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("allow"), "GET, HEAD");
  for (const path of ["/api-keys", "/keys/create", "/audit", "/swagger-ui/"]) {
    assert.equal((await viaWorker(`https://relay.test${path}`, { method: "GET" })).status, 404);
  }
});

test("a public operator route is caught", async () => {
  const leaky = (url, init) =>
    new URL(url).pathname === "/api-keys"
      ? Promise.resolve(new Response("[]", { status: 200 }))
      : viaWorker(url, init);
  const problems = await runSmoke("https://relay.test", { fetchImpl: leaky });
  assert.ok(problems.some((p) => p.includes("/api-keys answered 200")));
  const docs = (url, init) =>
    new URL(url).pathname === "/swagger-ui/"
      ? Promise.resolve(new Response("<html>", { status: 200 }))
      : viaWorker(url, init);
  assert.ok((await runSmoke("https://relay.test", { fetchImpl: docs })).some((p) => p.includes("/swagger-ui/ answered 200")));
});

test("a cacheable health response, a wrong body and a successful /inbox are caught", async () => {
  const bad = (url) => {
    const path = new URL(url).pathname;
    if (path === "/health") return Promise.resolve(Response.json({ status: "degraded" }));
    if (path === "/inbox") return Promise.resolve(new Response("[]", { status: 200 }));
    return Promise.resolve(new Response("", { status: 404 }));
  };
  const problems = await runSmoke("https://relay.test", { fetchImpl: bad });
  assert.ok(problems.some((p) => p.includes('body is not {"status":"ok"}')));
  assert.ok(problems.some((p) => p.includes("no-store")));
  assert.ok(problems.some((p) => p.includes("unauthenticated GET /inbox answered 200")));
});

test("a relay whose store is not ready is caught", async () => {
  const problems = await runSmoke("https://relay.test", { fetchImpl: via(relayEnv({ ready: false })) });
  assert.ok(problems.some((p) => p.includes("GET /ready answered 503")));
});

test("a missing status page or a loose policy is caught", async () => {
  const noPage = (url, init) =>
    new URL(url).pathname === "/" ? Promise.resolve(new Response("", { status: 404 })) : viaWorker(url, init);
  assert.ok((await runSmoke("https://relay.test", { fetchImpl: noPage })).some((p) => p.includes("GET / answered 404")));
  const loose = async (url, init) => {
    const response = await viaWorker(url, init);
    if (new URL(url).pathname !== "/") return response;
    const headers = new Headers(response.headers);
    headers.set("content-security-policy", "default-src *");
    return new Response(await response.text(), { status: 200, headers });
  };
  assert.ok((await runSmoke("https://relay.test", { fetchImpl: loose })).some((p) => p.includes("content security policy")));
});

test("an unreachable hostname is reported, not thrown", async () => {
  const down = () => Promise.reject(Object.assign(new Error("down"), { name: "TypeError" }));
  const problems = await runSmoke("https://relay.test", { fetchImpl: down });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /did not answer/);
});

test("health is retried until it answers", async () => {
  let calls = 0;
  const flaky = (url, init) => {
    if (new URL(url).pathname === "/health" && (calls += 1) < 3) {
      return Promise.resolve(new Response("", { status: 503 }));
    }
    return viaWorker(url, init);
  };
  const problems = await runSmoke("https://relay.test", { fetchImpl: flaky, attempts: 5, delayMs: 0 });
  assert.deepEqual(problems, []);
  assert.equal(calls, 3);
});

test("readiness is retried too, since the object starts on its first request", async () => {
  let calls = 0;
  const warming = (url, init) => {
    if (new URL(url).pathname === "/ready" && (calls += 1) < 3) {
      return Promise.resolve(new Response("", { status: 503 }));
    }
    return viaWorker(url, init);
  };
  assert.deepEqual(await runSmoke("https://relay.test", { fetchImpl: warming, attempts: 5, delayMs: 0 }), []);
  assert.equal(calls, 3);
});

test("the admin smoke test accepts a redirect to Access, a refusal and a closed Worker", async () => {
  for (const status of [302, 401, 403, 503]) {
    const refusing = () => Promise.resolve(new Response("", { status }));
    assert.deepEqual(await runAdminSmoke("https://admin.test", { fetchImpl: refusing }), [], String(status));
  }
});

test("the admin smoke test catches a success, a 404 and a hostname that does not answer", async () => {
  const open = () => Promise.resolve(new Response("page", { status: 200 }));
  const problems = await runAdminSmoke("https://admin.test", { fetchImpl: open });
  assert.equal(problems.length, 5);
  assert.ok(problems.every((p) => p.includes("without a credential")));
  const missing = () => Promise.resolve(new Response("", { status: 404 }));
  assert.equal((await runAdminSmoke("https://admin.test", { fetchImpl: missing })).length, 5);
  const down = () => Promise.reject(Object.assign(new Error("down"), { name: "TypeError" }));
  const unreachable = await runAdminSmoke("https://admin.test", { fetchImpl: down });
  assert.equal(unreachable.length, 5);
  assert.ok(unreachable.every((p) => p.includes("did not answer")));
});
