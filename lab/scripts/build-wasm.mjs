#!/usr/bin/env node
// Build the KeyQuorum crate's `lab` feature for wasm32 and generate the
// JavaScript bindings the lab imports from src/wasm/. Only `lab` is
// enabled: `provider` (mailbox-host code) must never reach the browser.
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const labDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(labDir, "..");
const outDir = resolve(labDir, "src", "wasm");

const lock = readFileSync(resolve(repoRoot, "Cargo.lock"), "utf8");
const locked = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
if (!locked) throw new Error("wasm-bindgen is not in Cargo.lock; is the `lab` feature wired?");

let cli = "";
try {
  cli = execFileSync("wasm-bindgen", ["--version"], { encoding: "utf8" }).trim();
} catch {
  throw new Error(`wasm-bindgen CLI not found. Install it with: cargo install wasm-bindgen-cli --version ${locked} --locked`);
}
if (!cli.endsWith(` ${locked}`)) {
  throw new Error(`wasm-bindgen CLI is "${cli}" but Cargo.lock pins ${locked}; the two must match.`);
}

const run = (cmd, args) => execFileSync(cmd, args, { cwd: repoRoot, stdio: "inherit" });

run("cargo", [
  "rustc", "--locked", "--lib", "--release",
  "--target", "wasm32-unknown-unknown",
  "--no-default-features", "--features", "lab",
  "--crate-type", "cdylib",
]);

rmSync(outDir, { recursive: true, force: true });
run("wasm-bindgen", [
  "--target", "web",
  "--out-dir", outDir,
  "--out-name", "keyquorum_lab",
  resolve(repoRoot, "target", "wasm32-unknown-unknown", "release", "keyquorum.wasm"),
]);
console.log(`Wrote WASM bindings to ${outDir}`);
