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
  const consoleBuild = process.argv.includes("--console");
  const present = consoleBuild
    ? ["keyquorum_console.js", "keyquorum_console_bg.wasm"].every((file) =>
      existsSync(join(workersDir, "admin", "public", "provision-wasm", file)))
    : relayWasmPresent();
  const action = decide({ present, env: process.env });
  if (action === "present") return 0;
  if (action === "missing") {
    console.error(
      `error: WASM is not built. Run npm run build:${consoleBuild ? "console" : "relay"}-wasm first ` +
        "(it needs the Rust wasm32-unknown-unknown target and the wasm-bindgen CLI at the version Cargo.lock pins).",
    );
    return 1;
  }
  console.log(`${consoleBuild ? "console" : "relay"} WASM is not built; building it on Workers Builds`);
  execFileSync("bash", [join(workersDir, "scripts", "builds-toolchain.sh")], { stdio: "inherit" });
  const path = `${join(homedir(), ".cargo", "bin")}${delimiter}${process.env.PATH ?? ""}`;
  // The crate's bundled SQLite is C, compiled for wasm32 by the clang the
  // toolchain script installed; the build image has none of its own.
  const wasiSdk = process.env.WASI_SDK_DIR ?? join(homedir(), ".wasi-sdk");
  execFileSync("node", [join(workersDir, "scripts", `build-${consoleBuild ? "console" : "relay"}-wasm.mjs`)], {
    stdio: "inherit",
    env: {
      ...process.env,
      PATH: path,
      CC_wasm32_unknown_unknown: join(wasiSdk, "bin", "clang"),
      AR_wasm32_unknown_unknown: join(wasiSdk, "bin", "llvm-ar"),
    },
  });
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(main());
}
