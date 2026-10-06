// The relay's sites are independent of the Lab and the portfolio: the Lab runs
// its own relay in the browser tab, at a name no request leaves for, and its
// sources never name a relay Worker. (The portfolio is another repository; it
// reaches the relay only through the Lab it embeds.)
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SKIP = new Set(["node_modules", "dist", "target", "pkg", ".git"]);

function* sources(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* sources(path);
    else if (/\.(rs|ts|js|mjs|html|css|json|toml)$/.test(name) && !name.endsWith("package-lock.json")) yield path;
  }
}

test("the Lab names no relay Worker, workers.dev host or the relay's custom domain variable", () => {
  const offenders = [];
  for (const dir of ["lab", "src/lab"]) {
    for (const path of sources(join(root, dir))) {
      const text = readFileSync(path, "utf8");
      if (/workers\.dev|keyquorum-relay|ALLOWED_HOSTS|RELAY_PRIVATE_KEY/.test(text)) offenders.push(path);
    }
  }
  assert.deepEqual(offenders, []);
});

test("the Lab's only relay is the in-process one at a name that is never served", () => {
  const vm = readFileSync(join(root, "src/lab/vm.rs"), "utf8");
  assert.match(vm, /pub const RELAY_URL: &str = "https:\/\/relay\.keyquorum\.lab";/);
  // It answers from `relay::service::dispatch`, never over the network.
  assert.match(vm, /relay::service::dispatch/);
});

test("no relay Worker ever sets a CORS header", () => {
  const offenders = [];
  for (const dir of ["workers/src", "workers/admin/src"]) {
    for (const path of sources(join(root, dir))) {
      if (path.endsWith(".test.mjs")) continue;
      if (/access-control-allow/i.test(readFileSync(path, "utf8"))) offenders.push(path);
    }
  }
  assert.deepEqual(offenders, []);
});
