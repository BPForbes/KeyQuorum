import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { handle } from "./index.js";

const ENV = { ACCESS_TEAM_DOMAIN: "relay-test.cloudflareaccess.com", ACCESS_AUD: "app-aud-tag" };
const allow = (claims = { email: "operator@example.com", exp: 1_900_000_000 }) => async () => ({ ok: true, claims });
const refuse = (reason) => async () => ({ ok: false, reason });

function assetsStub() {
  const calls = [];
  return {
    calls,
    fetch: async (request) => {
      calls.push(request.url);
      return new Response("<html>page</html>", { headers: { "content-type": "text/html" } });
    },
  };
}
const get = (path, init = {}) => new Request(`https://admin.test${path}`, init);

test("without a valid token nothing is served and no asset is fetched", async () => {
  const assets = assetsStub();
  const env = { ...ENV, ASSETS: assets };
  for (const path of ["/", "/index.html", "/app.js", "/api/whoami", "/api/keys"]) {
    const response = await handle(get(path), env, { verify: refuse("no token") });
    assert.equal(response.status, 403, path);
    assert.deepEqual(await response.json(), { error: "access required" });
  }
  assert.equal(assets.calls.length, 0);
});

test("an unconfigured Worker fails closed with 503", async () => {
  const assets = assetsStub();
  const response = await handle(get("/"), { ASSETS: assets }, { verify: refuse("not configured") });
  assert.equal(response.status, 503);
  assert.equal(assets.calls.length, 0);
});

test("the refusal reason reaches the log but never the response", async () => {
  const logged = [];
  const original = console.warn;
  console.warn = (...args) => logged.push(args.join(" "));
  try {
    const response = await handle(get("/"), { ...ENV, ASSETS: assetsStub() }, { verify: refuse("wrong audience") });
    assert.ok(!(await response.text()).includes("audience"));
  } finally {
    console.warn = original;
  }
  assert.ok(logged.some((line) => line.includes("wrong audience")));
});

test("the Worker passes its configuration to the verifier", async () => {
  let seen;
  await handle(
    get("/", { headers: { "cf-access-jwt-assertion": "the-token" } }),
    { ...ENV, ASSETS: assetsStub() },
    {
      verify: async (token, config) => {
        seen = { token, config };
        return { ok: true, claims: {} };
      },
    },
  );
  assert.equal(seen.token, "the-token");
  assert.deepEqual(seen.config, { teamDomain: ENV.ACCESS_TEAM_DOMAIN, audience: ENV.ACCESS_AUD });
});

test("a verified request gets the page with strict headers", async () => {
  const assets = assetsStub();
  const response = await handle(get("/"), { ...ENV, ASSETS: assets }, { verify: allow() });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "<html>page</html>");
  const csp = response.headers.get("content-security-policy");
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|\*|https?:/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
});

test("whoami returns the verified email and expiry, and nothing else", async () => {
  const response = await handle(get("/api/whoami"), { ...ENV, ASSETS: assetsStub() }, {
    verify: allow({ email: "operator@example.com", exp: 1_900_000_000, sub: "internal-id", aud: ["x"] }),
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { email: "operator@example.com", expiresAt: "2030-03-17T17:46:40.000Z" });
  const odd = await handle(get("/api/whoami"), { ...ENV, ASSETS: assetsStub() }, { verify: allow({ email: 7 }) });
  assert.deepEqual(await odd.json(), { email: null, expiresAt: null });
});

test("an api route the console does not have is 404, and nothing is read from the assets", async () => {
  const assets = assetsStub();
  for (const path of ["/api", "/api/status", "/api/keys", "/api/audit/events"]) {
    const response = await handle(get(path), { ...ENV, ASSETS: assets }, { verify: allow() });
    assert.equal(response.status, 404, path);
    assert.deepEqual(await response.json(), { error: "not found" });
  }
  assert.equal(assets.calls.length, 0);
});

test("only GET and HEAD are allowed everywhere but the one console route, which is POST only", async () => {
  const assets = assetsStub();
  for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
    const response = await handle(get("/api/keys", { method }), { ...ENV, ASSETS: assets }, { verify: allow() });
    assert.equal(response.status, 405, method);
    assert.equal(response.headers.get("allow"), "GET, HEAD");
  }
  for (const method of ["GET", "HEAD", "PUT", "DELETE", "PATCH"]) {
    const response = await handle(get("/api/operate", { method }), { ...ENV, ASSETS: assets }, { verify: allow() });
    assert.equal(response.status, 405, method);
    assert.equal(response.headers.get("allow"), "POST");
  }
  assert.equal(assets.calls.length, 0);
});

test("the config route names the address clients load keys for, and nothing secret", async () => {
  const env = { ...ENV, ASSETS: assetsStub(), RELAY_PUBLIC_URL: "relay.example.test" };
  const response = await handle(get("/api/config"), env, { verify: allow() });
  assert.deepEqual(await response.json(), { relayUrl: "relay.example.test" });
  const none = await handle(get("/api/config"), { ...ENV, ASSETS: assetsStub() }, { verify: allow() });
  assert.deepEqual(await none.json(), { relayUrl: "" });
});

// The page contract: no inline script or style, no handler attributes, and no
// reference to any origin but the page's own, so the CSP above can stay strict.
const PUBLIC = join(fileURLToPath(new URL("..", import.meta.url)), "public");
test("the static page keeps to the CSP: no inline code, no outside origin, no innerHTML", () => {
  for (const name of readdirSync(PUBLIC)) {
    const text = readFileSync(join(PUBLIC, name), "utf8");
    assert.doesNotMatch(text, /https?:\/\//i, `${name} names an origin`);
    assert.doesNotMatch(text, /\son[a-z]+\s*=/i, `${name} has an event-handler attribute`);
    assert.doesNotMatch(text, /\sstyle\s*=/i, `${name} has an inline style`);
    assert.doesNotMatch(text, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/, `${name} writes HTML`);
    if (name.endsWith(".html")) {
      for (const script of text.matchAll(/<script\b([^>]*)>/gi)) {
        assert.match(script[1], /\ssrc="\/[^"]+"/, `${name} has an inline script`);
      }
      assert.doesNotMatch(text, /<style\b/i, `${name} has an inline style element`);
    }
  }
});

test("a fetch, frame or form from another site is refused before the token is looked at", async () => {
  const assets = assetsStub();
  let verified = 0;
  const verify = async () => (verified++, { ok: true, claims: { email: "operator@example.com", exp: 1_900_000_000 } });
  const env = { ...ENV, ASSETS: assets };
  for (const headers of [
    { "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
    { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "iframe" },
    { origin: "https://bailey-forbes.com" },
  ]) {
    const response = await handle(get("/api/whoami", { headers }), env, { verify });
    assert.equal(response.status, 403, JSON.stringify(headers));
    assert.deepEqual(await response.json(), { error: "cross-site requests are not served" });
    assert.equal(response.headers.get("x-frame-options"), "DENY");
    assert.equal(response.headers.get("access-control-allow-origin"), null);
  }
  assert.equal(verified, 0);
  assert.equal(assets.calls.length, 0);
});

test("a top-level link (the Access sign-in redirect) reaches the token check, which still decides", async () => {
  const link = { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" };
  const env = { ...ENV, ASSETS: assetsStub() };
  const signedIn = await handle(get("/", { headers: link }), env, { verify: allow() });
  assert.equal(signedIn.status, 200);
  assert.equal(signedIn.headers.get("x-frame-options"), "DENY");
  assert.equal(signedIn.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(signedIn.headers.get("cross-origin-resource-policy"), "same-origin");
  const anonymous = await handle(get("/", { headers: link }), env, { verify: refuse("no token") });
  assert.equal(anonymous.status, 403);
});
