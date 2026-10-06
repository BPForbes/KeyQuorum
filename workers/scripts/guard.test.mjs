// Secrets here are drawn at run time, never written as literals, so the
// repository's secret scanners stay clean and the tests prove the guard
// catches a value it has never seen.
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkBundle, checkConfig } from "./guard.mjs";

const CLEAN = `
name = "keyquorum-relay"
main = "src/index.js"
workers_dev = false
preview_urls = false

[env.staging]
workers_dev = false
preview_urls = false
`;

test("a clean configuration passes", () => {
  assert.deepEqual(checkConfig("wrangler.toml", CLEAN), []);
});

test("a secret-like [vars] name is refused", () => {
  const text = `${CLEAN}\n[vars]\nRELAY_PRIVATE_KEY = "x"\nREGION = "eu"\n`;
  const problems = checkConfig("wrangler.toml", text);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /RELAY_PRIVATE_KEY/);
});

test("a secret-like name in an environment's vars or an inline table is refused", () => {
  const env = `${CLEAN}\n[env.staging.vars]\nPROVIDER_CERT = "x"\n`;
  assert.equal(checkConfig("wrangler.toml", env).length, 1);
  const inline = `${CLEAN}\nvars = { LOG_LEVEL = "info", API_TOKEN = "x" }\n`;
  const problems = checkConfig("wrangler.toml", inline);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /API_TOKEN/);
});

test("a secret-like name in a previews block is refused, at the top level and in an environment", () => {
  for (const table of ["previews.vars", "env.staging.previews.vars"]) {
    const problems = checkConfig("wrangler.toml", `${CLEAN}\n[${table}]\nRELAY_KEY = "x"\nREGION = "eu"\n`);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /RELAY_KEY/);
  }
  const inline = `${CLEAN}\npreviews = { vars = { PROVIDER_CERT = "x" } }\n`;
  const problems = checkConfig("wrangler.toml", inline);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /PROVIDER_CERT/);
});

test("an empty previews block and harmless previews vars are allowed", () => {
  assert.deepEqual(checkConfig("wrangler.toml", `${CLEAN}\npreviews = { }\n`), []);
  assert.deepEqual(checkConfig("wrangler.toml", `${CLEAN}\n[previews.vars]\nREGION = "eu"\n`), []);
});

test("a wildcard ALLOWED_HOSTS is refused everywhere but [previews.vars]", () => {
  for (const table of ["vars", "env.staging.vars", "env.staging.previews.vars"]) {
    const problems = checkConfig("wrangler.toml", `${CLEAN}\n[${table}]\nALLOWED_HOSTS = "*"\n`);
    assert.equal(problems.length, 1, table);
    assert.match(problems[0], /ALLOWED_HOSTS/);
    assert.match(problems[0], new RegExp(table.replace(/\./g, "\\.")));
  }
  for (const value of ["relay.example.com,*", "*.example.com", "'*'"]) {
    const quoted = value.startsWith("'") ? value : `"${value}"`;
    assert.equal(checkConfig("wrangler.toml", `${CLEAN}\n[vars]\nALLOWED_HOSTS = ${quoted}\n`).length, 1, value);
  }
  const inline = checkConfig("wrangler.toml", `${CLEAN}\nvars = { ALLOWED_HOSTS = "*" }\n`);
  assert.equal(inline.length, 1);
  assert.match(inline[0], /inline vars table/);
});

test("ALLOWED_HOSTS may be a wildcard in [previews.vars] and a hostname or empty anywhere", () => {
  assert.deepEqual(checkConfig("wrangler.toml", `${CLEAN}\n[previews.vars]\nALLOWED_HOSTS = "*"\n`), []);
  for (const table of ["vars", "env.staging.vars", "previews.vars"]) {
    for (const value of ["", "relay.example.com", "relay.example.com,relay-staging.example.com"]) {
      assert.deepEqual(checkConfig("wrangler.toml", `${CLEAN}\n[${table}]\nALLOWED_HOSTS = "${value}"\n`), [], `${table} ${value}`);
    }
  }
});

test("the real configuration passes, and its production Worker serves no wildcard", async () => {
  const { readFileSync } = await import("node:fs");
  const text = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.deepEqual(checkConfig("wrangler.toml", text, { allowPreviewUrls: true }), []);
  assert.match(text, /\[previews\.vars\]\s*\nALLOWED_HOSTS = "\*"/);
  assert.match(text, /\n\[vars\]\s*\nALLOWED_HOSTS = ""/);
  assert.match(text, /\[env\.staging\.vars\]\s*\nALLOWED_HOSTS = ""/);
});

test("a harmless [vars] name is allowed", () => {
  assert.deepEqual(checkConfig("wrangler.toml", `${CLEAN}\n[vars]\nREGION = "eu"\n`), []);
});

test("key material is refused wherever it sits, and the value is never printed", () => {
  const hex = randomBytes(32).toString("hex");
  const bearer = `kql_${randomBytes(24).toString("base64url")}`;
  for (const secret of [hex, bearer]) {
    for (const text of [`${CLEAN}\n# ${secret}\n`, `${CLEAN}\n[vars]\nREGION = "${secret}"\n`]) {
      const problems = checkConfig("wrangler.toml", text);
      assert.ok(problems.length >= 1);
      for (const problem of problems) assert.ok(!problem.includes(secret));
    }
  }
});

test("a PEM block is refused", () => {
  const body = randomBytes(24).toString("base64");
  const block = ["-----BEGIN PRIVATE KEY-----", body, "-----END PRIVATE KEY-----"].join("\n");
  assert.equal(checkConfig("wrangler.toml", `${CLEAN}\n# ${block.replace(/\n/g, " ")}\n`).length, 1);
});

test("a migration that deletes or renames a class is refused unless allowed", () => {
  const text = `${CLEAN}\n[[migrations]]\ntag = "v2"\ndeleted_classes = ["RelayDO"]\n`;
  const problems = checkConfig("wrangler.toml", text);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /destroys its data/);
  assert.deepEqual(checkConfig("wrangler.toml", text, { allowDestructive: true }), []);
  const renamed = `${CLEAN}\n[[migrations]]\ntag = "v3"\nrenamed_classes = [{ from = "A", to = "B" }]\n`;
  assert.equal(checkConfig("wrangler.toml", renamed).length, 1);
});

test("a commented-out destructive migration is not a migration", () => {
  assert.deepEqual(checkConfig("wrangler.toml", `${CLEAN}\n# deleted_classes = ["X"]\n`), []);
});

test("workers.dev and preview URLs must be off at the top level and in every environment", () => {
  const top = checkConfig("wrangler.toml", CLEAN.replace(/^workers_dev = false$/m, ""));
  assert.ok(top.some((p) => p.includes("top level must set workers_dev")));
  const env = checkConfig(
    "wrangler.toml",
    CLEAN.replace(/(\[env\.staging\]\n)workers_dev = false\n/, "$1"),
  );
  assert.ok(env.some((p) => p.includes("env.staging must set workers_dev")));
  const on = checkConfig("wrangler.toml", CLEAN.replace(/^preview_urls = false$/m, "preview_urls = true"));
  assert.ok(on.some((p) => p.includes("preview_urls")));
});

function bundleWith(files) {
  const dir = mkdtempSync(join(tmpdir(), "guard-bundle-"));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  return dir;
}

test("a clean bundle within the size limit passes", () => {
  const dir = bundleWith({ "index.js": "export default { fetch() { return new Response('ok'); } };" });
  try {
    assert.deepEqual(checkBundle(dir, { maxGzipBytes: 1024 }), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("key material in a bundle file is refused without printing it", () => {
  const secret = randomBytes(32).toString("hex");
  const dir = bundleWith({ "index.js": `const k = "${secret}";` });
  try {
    const problems = checkBundle(dir);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /index\.js/);
    assert.ok(!problems[0].includes(secret));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an oversized or empty bundle is refused", () => {
  const big = bundleWith({ "index.js": randomBytes(4096).toString("base64") });
  const empty = bundleWith({});
  try {
    assert.ok(checkBundle(big, { maxGzipBytes: 100 }).some((p) => p.includes("over the limit")));
    assert.ok(checkBundle(empty).some((p) => p.includes("empty")));
  } finally {
    rmSync(big, { recursive: true, force: true });
    rmSync(empty, { recursive: true, force: true });
  }
});

test("preview URLs on are refused unless the public Worker's file is checked with the allowance", () => {
  const on = CLEAN.replace(/preview_urls = false/g, "preview_urls = true");
  assert.ok(checkConfig("admin/wrangler.toml", on).some((p) => p.includes("preview_urls = false")));
  assert.deepEqual(checkConfig("wrangler.toml", on, { allowPreviewUrls: true }), []);
});

test("the allowance still requires preview_urls to be set and workers_dev off", () => {
  const unset = CLEAN.replace(/^preview_urls = false$/m, "");
  const problems = checkConfig("wrangler.toml", unset, { allowPreviewUrls: true });
  assert.ok(problems.some((p) => p.includes("top level must set preview_urls explicitly")));
  const devOn = CLEAN.replace(/^workers_dev = false$/m, "workers_dev = true");
  assert.ok(
    checkConfig("wrangler.toml", devOn, { allowPreviewUrls: true }).some((p) =>
      p.includes("top level must set workers_dev"),
    ),
  );
});
