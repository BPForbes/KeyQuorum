#!/usr/bin/env node
// Makes sure relay-wasm/ (the relay core compiled to WebAssembly, never
// committed) exists before a step that bundles the Worker.
//
//   present                          nothing to do
//   absent, on Workers Builds        install the pinned toolchain
//   (WORKERS_CI=1, injected by       (scripts/builds-toolchain.sh) and build it,
//   Cloudflare)                      so `npm run check` and `npm run preview`
//                                    work whichever command the dashboard names
//   absent anywhere else             stop with the command to run; it never
//                                    installs a toolchain on a developer's
//                                    machine or in GitHub, where the workflow
//                                    builds the core first with its own actions
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workersDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function relayWasmPresent(dir = join(workersDir, "relay-wasm")) {
  return existsSync(join(dir, "keyquorum_relay.js")) && existsSync(join(dir, "keyquorum_relay_bg.wasm"));
}

// -> "present" | "build" | "missing"
export function decide({ present, env }) {
  if (present) return "present";
  return env.WORKERS_CI === "1" ? "build" : "missing";
}

function main() {
  const action = decide({ present: relayWasmPresent(), env: process.env });
  if (action === "present") return 0;
  if (action === "missing") {
    console.error(
      "error: relay-wasm/ is not built. Run `npm run build:relay-wasm` first " +
        "(it needs the Rust wasm32-unknown-unknown target and the wasm-bindgen CLI at the version Cargo.lock pins).",
    );
    return 1;
  }
  console.log("relay-wasm/ is not built; building it on Workers Builds");
  execFileSync("bash", [join(workersDir, "scripts", "builds-toolchain.sh")], { stdio: "inherit" });
  const path = `${join(homedir(), ".cargo", "bin")}${delimiter}${process.env.PATH ?? ""}`;
  execFileSync("node", [join(workersDir, "scripts", "build-relay-wasm.mjs")], {
    stdio: "inherit",
    env: { ...process.env, PATH: path },
  });
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(main());
}
