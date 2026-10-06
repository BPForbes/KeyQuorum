#!/usr/bin/env node
// Build the relay core (the crate's `workers` feature only) for wasm32 and
// generate the JavaScript bindings the Durable Object imports from
// relay-wasm/. `provider` (mailbox-host code) and `lab` must never be part of
// it; build.rs and lib.rs refuse both on wasm32.
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workersDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(workersDir, "..");
const outDir = resolve(workersDir, "relay-wasm");

const lock = readFileSync(resolve(repoRoot, "Cargo.lock"), "utf8");
const locked = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
if (!locked) throw new Error("wasm-bindgen is not in Cargo.lock; is the `workers` feature wired?");

let cli = "";
try {
  cli = execFileSync("wasm-bindgen", ["--version"], { encoding: "utf8" }).trim();
} catch {
  throw new Error(
    `wasm-bindgen CLI not found. Install it with: cargo install wasm-bindgen-cli --version ${locked} --locked`,
  );
}
if (!cli.endsWith(` ${locked}`)) {
  throw new Error(`wasm-bindgen CLI is "${cli}" but Cargo.lock pins ${locked}; the two must match.`);
}

const run = (cmd, args) => execFileSync(cmd, args, { cwd: repoRoot, stdio: "inherit" });

run("cargo", [
  "rustc", "--locked", "--lib", "--release",
  "--target", "wasm32-unknown-unknown",
  "--no-default-features", "--features", "workers",
  "--crate-type", "cdylib",
]);

rmSync(outDir, { recursive: true, force: true });
run("wasm-bindgen", [
  "--target", "web",
  "--out-dir", outDir,
  "--out-name", "keyquorum_relay",
  resolve(repoRoot, "target", "wasm32-unknown-unknown", "release", "keyquorum.wasm"),
]);
console.log(`Wrote the relay WASM bindings to ${outDir}`);
