import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decide, relayWasmPresent } from "./ensure-relay-wasm.mjs";

test("a built core needs nothing, wherever it runs", () => {
  for (const env of [{}, { WORKERS_CI: "1" }, { CI: "true" }]) {
    assert.equal(decide({ present: true, env }), "present");
  }
});

test("a missing core is built only on Workers Builds, and is an error everywhere else", () => {
  assert.equal(decide({ present: false, env: { WORKERS_CI: "1" } }), "build");
  for (const env of [{}, { CI: "true" }, { WORKERS_CI: "0" }, { WORKERS_CI: "true" }, { GITHUB_ACTIONS: "true" }]) {
    assert.equal(decide({ present: false, env }), "missing", JSON.stringify(env));
  }
});

test("the core counts as built only when both files are there", () => {
  const dir = mkdtempSync(join(tmpdir(), "relay-wasm-"));
  try {
    assert.equal(relayWasmPresent(dir), false);
    writeFileSync(join(dir, "keyquorum_relay.js"), "");
    assert.equal(relayWasmPresent(dir), false);
    writeFileSync(join(dir, "keyquorum_relay_bg.wasm"), "");
    assert.equal(relayWasmPresent(dir), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
