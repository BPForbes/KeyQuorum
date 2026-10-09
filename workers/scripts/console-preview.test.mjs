import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { handle } from "../preview/worker.js";

const request = (path, options) => new Request(`https://preview.example${path}`, options);
const allow = async () => ({ ok: true, claims: { email: "operator@example.com" } });
function fixture() {
  const calls = [];
  const env = {
    CONSOLE_PREVIEW: "1", ACCESS_TEAM_DOMAIN: "test.cloudflareaccess.com", ACCESS_AUD: "preview-audience",
    ASSETS: { fetch: async r => { calls.push(r.url); return new Response("asset"); } },
    RELAY: { idFromName: name => name, get: id => ({ operate: async () => {
      calls.push(id); return { status: 200, body: JSON.stringify({ identity_configured: false }) };
    } }) },
  };
  return { env, calls };
}

test("unconfigured and normal deployments serve nothing", async () => {
  const { env, calls } = fixture();
  for (const key of ["CONSOLE_PREVIEW", "RELAY", "ACCESS_AUD", "ACCESS_TEAM_DOMAIN"]) {
    assert.equal((await handle(request("/relay/admin/"), { ...env, [key]: undefined })).status, 503);
  }
  assert.deepEqual(calls, []);
});

test("anonymous admin HTML, assets, WASM and API requests reach no resource", async () => {
  const { env, calls } = fixture();
  for (const path of ["/relay/admin/", "/relay/admin/app.js", "/relay/admin/provision-wasm/keyquorum_console_bg.wasm", "/relay/admin/api/overview"]) {
    assert.equal((await handle(request(path), env)).status, 403);
  }
  assert.deepEqual(calls, []);
});

test("authorized console mounts assets and reads only the local preview object", async () => {
  const { env, calls } = fixture();
  env.RELAY_ADMIN = { get() { throw new Error("foreign namespace must not be used"); } };
  assert.equal((await handle(request("/relay/admin/app.js"), env, { verify: allow })).status, 200);
  const response = await handle(request("/relay/admin/api/overview"), env, { verify: allow });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { identity_configured: false });
  assert.deepEqual(calls, ["https://preview.example/app.js", "relay"]);
});

test("console root and slash navigation work; relay status remains public in the handler", async () => {
  const { env } = fixture();
  assert.equal((await handle(request("/"), env)).headers.get("location"), "/relay/admin/");
  assert.equal((await handle(request("/relay/admin"), env)).headers.get("location"), "/relay/admin/");
  assert.equal((await handle(request("/relay"), env)).status, 308);
  assert.equal((await handle(request("/relay/"), env)).status, 200);
  assert.equal((await handle(request("/app.js"), env)).status, 404);
});

test("operator writes keep the Origin and operator-lock gates", async () => {
  const { env, calls } = fixture();
  assert.equal((await handle(request("/relay/admin/api/users", { method: "POST" }), env, { verify: allow })).status, 403);
  const response = await handle(request("/relay/admin/api/users", {
    method: "POST", headers: { origin: "https://preview.example", "content-type": "application/json" }, body: "{}",
  }), env, { verify: allow });
  assert.ok(response.status >= 400);
  assert.deepEqual(calls, []);
});

test("preview config has no production resources, secrets or cross-Worker bindings", () => {
  const config = JSON.parse(readFileSync(new URL("../preview/wrangler.json", import.meta.url)));
  assert.equal(config.name, "keyquorum-console-preview");
  assert.deepEqual(Object.keys(config).sort(), ["assets", "compatibility_date", "main", "migrations", "name", "preview_urls", "previews", "workers_dev"]);
  assert.equal(config.main, "index.js");
  assert.deepEqual(config.migrations, [{ tag: "v1", new_sqlite_classes: ["RelayObject"] }]);
  assert.equal(config.workers_dev, false);
  assert.equal(config.assets.run_worker_first, true);
  assert.equal(config.vars, undefined);
  assert.equal(config.durable_objects, undefined);
  assert.deepEqual(config.previews.durable_objects.bindings, [{ name: "RELAY", class_name: "RelayObject" }]);
  assert.deepEqual(Object.keys(config.previews).sort(), ["durable_objects", "ratelimits", "vars"]);
  assert.deepEqual(Object.keys(config.previews.vars).sort(), ["ACCESS_AUD", "ACCESS_TEAM_DOMAIN", "CONSOLE_PREVIEW"]);
});
