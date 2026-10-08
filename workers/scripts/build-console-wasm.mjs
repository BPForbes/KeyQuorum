#!/usr/bin/env node
// Build the operator console's WebAssembly (the crate's `console` feature
// only: `provider::provision`, which makes a provider identity in the
// browser) and generate the bindings the console's setup guide imports from
// admin/public/provision-wasm/. `provider`, `lab` and `workers` must never be
// part of it; build.rs and lib.rs refuse them on wasm32.
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workersDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(workersDir, "..");
const outDir = resolve(workersDir, "admin", "public", "provision-wasm");

const lock = readFileSync(resolve(repoRoot, "Cargo.lock"), "utf8");
const locked = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
if (!locked) throw new Error("wasm-bindgen is not in Cargo.lock; is the `console` feature wired?");

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

// Its own target directory, so it never shares a build with the relay core.
run("cargo", [
  "rustc", "--locked", "--lib", "--release",
  "--target", "wasm32-unknown-unknown",
  "--target-dir", resolve(repoRoot, "target", "console"),
  "--no-default-features", "--features", "console",
  "--crate-type", "cdylib",
]);

rmSync(outDir, { recursive: true, force: true });
run("wasm-bindgen", [
  "--target", "web",
  "--out-dir", outDir,
  "--out-name", "keyquorum_console",
  resolve(repoRoot, "target", "console", "wasm32-unknown-unknown", "release", "keyquorum.wasm"),
]);
console.log(`Wrote the console WASM bindings to ${outDir}`);
