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
