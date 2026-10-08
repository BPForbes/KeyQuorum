// The console's package check: verified only when the core's verifier passes
// against the pinned root, unverified (with the native route) wherever it
// cannot run, and never an install.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { NO_INSTALL, checkPackage, handoff, shellWord } from "../public/package-check.js";

const PUBLIC = join(fileURLToPath(new URL("..", import.meta.url)), "public");
const ROOT = "ab".repeat(32);
const bytes = new Uint8Array([1, 2, 3]);
const checked = { purpose: "client_setup", package_id: "00".repeat(16), signed_by: "relay" };

test("a package is verified only when the core's verifier passes against the pinned root", async () => {
  const calls = [];
  const load = async () => ({ verify_package: (b, root, now) => (calls.push([b, root, now]), JSON.stringify(checked)) });
  const result = await checkPackage({ bytes, name: "alice.kqpkg", pinnedRoot: ROOT, load, now: new Date("2026-10-08T12:00:00Z") });
  assert.equal(result.state, "verified");
  assert.deepEqual(calls, [[bytes, ROOT, "2026-10-08 12:00:00"]]);
  assert.match(result.handoff.commands[1], /^keyquorum setup alice\.kqpkg --device DRIVE --label NAME --yes$/);
});

test("a refusal from the verifier is reported, with no route to install", async () => {
  const load = async () => ({ verify_package: () => { throw new Error("KeyQuorum package signer is not trusted"); } });
  const result = await checkPackage({ bytes, name: "x.kqpkg", pinnedRoot: ROOT, load });
  assert.equal(result.state, "refused");
  assert.match(result.reason, /not trusted/);
  assert.equal(result.handoff, null);
});

test("without a pinned root or a runtime that can verify, it stays unverified and points to the native command", async () => {
  let loaded = false;
  const load = async () => { loaded = true; return { verify_package: () => "{}" }; };
  for (const pinnedRoot of [null, undefined, "", "xyz", "AB".repeat(32)]) {
    const result = await checkPackage({ bytes, name: "x.kqpkg", pinnedRoot, load });
    assert.equal(result.state, "unverified");
    assert.match(result.reason, /PROVIDER_ROOT/);
  }
  assert.equal(loaded, false, "nothing runs without a root to check against");
  for (const broken of [async () => { throw new Error("no WebAssembly"); }, async () => ({})]) {
    const result = await checkPackage({ bytes, name: "x.kqpkg", pinnedRoot: ROOT, load: broken });
    assert.equal(result.state, "unverified");
    assert.match(result.reason, /native command/);
  }
});

test("each purpose has its own native route, and provider information has none", () => {
  assert.match(handoff("client_update", "u.kqpkg").commands[0], /^keyquorum setup u\.kqpkg /);
  const recovery = handoff("provider_recovery", "r.kqpkg");
  assert.match(recovery.commands[1], /^keyquorum host recovery install r\.kqpkg --recipient-key recovery\.key --out DIR --yes$/);
  assert.match(recovery.note, /never upload it/);
  assert.equal(handoff("provider_info", "p.kqpkg"), null);
  assert.equal(handoff("anything else", "p.kqpkg"), null);
});

test("a file name becomes one shell word", () => {
  assert.equal(shellWord("a-b_c.kqpkg"), "a-b_c.kqpkg");
  assert.equal(shellWord("my package.kqpkg"), "'my package.kqpkg'");
  assert.equal(shellWord("it's; rm -rf.kqpkg"), "'it'\\''s; rm -rf.kqpkg'");
});

test("the check never installs, uploads or stores: no request, storage or download in it", () => {
  const source = readFileSync(join(PUBLIC, "package-check.js"), "utf8");
  for (const forbidden of ["fetch(", "api(", "localStorage", "sessionStorage", "indexedDB", "downloadBytes", "showDirectoryPicker", "showSaveFilePicker"]) {
    assert.ok(!source.includes(forbidden), `package-check.js uses ${forbidden}`);
  }
  assert.match(NO_INSTALL, /never installs/);
});

// The real verifier, the crate's own code compiled for the console. CI builds
// it (`npm run build:console-wasm`) before the tests; a checkout without the
// build skips this one.
const WASM = join(PUBLIC, "provision-wasm", "keyquorum_console.js");
let built = false;
try {
  readFileSync(WASM);
  built = true;
} catch {}

test("the built verifier accepts a package under its own root and refuses it under another", { skip: !built && "the console WebAssembly is not built" }, async () => {
  const module = await import(WASM);
  module.initSync({ module: readFileSync(join(PUBLIC, "provision-wasm", "keyquorum_console_bg.wasm")) });
  const now = new Date();
  const stamp = now.toISOString().slice(0, 19).replace("T", " ");
  const made = JSON.parse(module.provision_identity("Acme Security Services", "KQP-TEST-1", "2099-01-01 00:00:00", stamp));
  const pkg = Uint8Array.from(Buffer.from(made.package_base64, "base64"));
  const load = async () => module;
  const ok = await checkPackage({ bytes: pkg, name: "provider-info.kqpkg", pinnedRoot: made.root_pub, load, now });
  assert.equal(ok.state, "verified");
  assert.equal(ok.checked.purpose, "provider_info");
  assert.equal(ok.checked.provider_id, "Acme Security Services");
  assert.equal(ok.handoff, null, "provider information has nothing to install");
  const other = JSON.parse(module.backup_keygen()).backup_pub;
  const wrong = await checkPackage({ bytes: pkg, name: "p.kqpkg", pinnedRoot: other, load, now });
  assert.equal(wrong.state, "refused");
  const changed = pkg.slice();
  changed[changed.length - 1] ^= 1;
  assert.equal((await checkPackage({ bytes: changed, name: "p.kqpkg", pinnedRoot: made.root_pub, load, now })).state, "refused");
});
