import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";
import { runSmoke } from "./smoke.mjs";

const viaStub = (url, init) => worker.fetch(new Request(url, init));

test("the stub passes the smoke test", async () => {
  assert.deepEqual(await runSmoke("https://relay.test", { fetchImpl: viaStub }), []);
});

test("the stub answers health, refuses other methods, and exposes nothing else", async () => {
  const health = await viaStub("https://relay.test/health", { method: "GET" });
  assert.equal(health.status, 200);
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.deepEqual(await health.json(), { status: "ok" });
  const post = await viaStub("https://relay.test/health", { method: "POST" });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("allow"), "GET, HEAD");
  for (const path of ["/", "/inbox", "/api-keys", "/keys/create"]) {
    assert.equal((await viaStub(`https://relay.test${path}`, { method: "GET" })).status, 404);
  }
});

test("a public operator route is caught", async () => {
  const leaky = (url, init) =>
    new URL(url).pathname === "/api-keys"
      ? Promise.resolve(new Response("[]", { status: 200 }))
      : viaStub(url, init);
  const problems = await runSmoke("https://relay.test", { fetchImpl: leaky });
  assert.ok(problems.some((p) => p.includes("/api-keys answered 200")));
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
    return viaStub(url, init);
  };
  const problems = await runSmoke("https://relay.test", { fetchImpl: flaky, attempts: 5, delayMs: 0 });
  assert.deepEqual(problems, []);
  assert.equal(calls, 3);
});
