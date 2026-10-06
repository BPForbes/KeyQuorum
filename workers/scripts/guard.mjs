#!/usr/bin/env node
// Guards for the Worker's configuration and built bundle.
//
//   node scripts/guard.mjs wrangler.toml
//   node scripts/guard.mjs --bundle dist --max-gzip-bytes 3145728
//
// The configuration check fails on: key material anywhere in the file, a
// secret-like [vars] or [previews.vars] name (the relay key, certificate and
// revocation list are Worker secrets, never vars), a Durable Object migration that deletes or
// renames a class (which destroys its data), and a Worker or environment that
// does not switch workers.dev off, or that leaves preview URLs on (one
// hostname carries the relay's identity). Only the public Worker's file may be
// checked with --allow-preview-urls, which accepts preview_urls = true there
// (Cloudflare Workers Builds previews, owner decision 2026-10-06); the admin
// Worker's hostname sits behind Access, which a preview hostname is outside of,
// so its file never gets that flag. The bundle check scans every text file for key material
// and bounds the gzip size. A problem names the file and the rule, never the
// matched text.

import { gzipSync } from "node:zlib";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const KEY_MATERIAL = [
  { rule: "64 or more hex characters (a key or a hash)", pattern: /\b[0-9a-fA-F]{64,}\b/ },
  { rule: "a kq_ or kql_ bearer", pattern: /\bkql?_[A-Za-z0-9_-]{16,}/ },
  { rule: "a PEM block", pattern: /-----BEGIN [A-Z0-9 ]+-----/ },
];

const SECRET_NAME = /(key|secret|token|password|passphrase|bearer|credential|cert|krl|kql)/i;
const TEXT_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".json", ".toml", ".map"]);

export function scanForKeyMaterial(label, text) {
  return KEY_MATERIAL.filter(({ pattern }) => pattern.test(text)).map(
    ({ rule }) => `${label}: contains ${rule}`,
  );
}

function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote) {
      if (ch === "\\" && quote === '"') i += 1;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "#") {
      return line.slice(0, i);
    }
  }
  return line;
}

function tableName(line) {
  const match = /^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*$/.exec(line);
  return match ? match[1] : null;
}

// [vars], an environment's, and the vars of a previews block at either level
// (a Worker Preview reads them the way production reads [vars]).
function isVarsTable(name) {
  return /^(env\.[^.]+\.)?(previews\.)?vars$/.test(name);
}

export function checkConfig(
  label,
  text,
  { allowDestructive = false, allowPreviewUrls = false } = {},
) {
  const problems = scanForKeyMaterial(label, text);
  const lines = text.split(/\r?\n/).map(stripComment);

  // The text of each table: "" is the top level, "env.staging" an environment.
  const tables = new Map([["", []]]);
  let current = "";
  for (const line of lines) {
    const name = tableName(line);
    if (name !== null) {
      current = name;
      if (!tables.has(current)) tables.set(current, []);
      continue;
    }
    tables.get(current).push(line);

    if (isVarsTable(current)) {
      const key = /^\s*"?([A-Za-z0-9_.-]+)"?\s*=/.exec(line);
      if (key && SECRET_NAME.test(key[1])) {
        problems.push(`${label}: [vars] name "${key[1]}" looks like a secret; use a Worker secret`);
      }
    }
    const inline = /\bvars\s*=\s*\{([^}]*)\}/.exec(line);
    if (inline) {
      for (const entry of inline[1].split(",")) {
        const key = /^\s*"?([A-Za-z0-9_.-]+)"?\s*=/.exec(entry);
        if (key && SECRET_NAME.test(key[1])) {
          problems.push(`${label}: vars name "${key[1]}" looks like a secret; use a Worker secret`);
        }
      }
    }
  }

  if (!allowDestructive && /\b(deleted_classes|renamed_classes)\b/.test(lines.join("\n"))) {
    problems.push(
      `${label}: a migration deletes or renames a Durable Object class, which destroys its data; ` +
        "review it, then run the guard with ALLOW_DESTRUCTIVE_MIGRATION=1",
    );
  }

  for (const [name, body] of tables) {
    if (name !== "" && !/^env\.[^.]+$/.test(name)) continue;
    const scope = name === "" ? "top level" : name;
    const joined = body.join("\n");
    if (!/^\s*workers_dev\s*=\s*false\s*$/m.test(joined)) {
      problems.push(`${label}: ${scope} must set workers_dev = false`);
    }
    const previews = allowPreviewUrls ? "(?:false|true)" : "false";
    if (!new RegExp(`^\\s*preview_urls\\s*=\\s*${previews}\\s*$`, "m").test(joined)) {
      problems.push(
        allowPreviewUrls
          ? `${label}: ${scope} must set preview_urls explicitly (true or false)`
          : `${label}: ${scope} must set preview_urls = false`,
      );
    }
  }
  return problems;
}

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

export function checkBundle(dir, { maxGzipBytes = Infinity } = {}) {
  const problems = [];
  let gzipTotal = 0;
  let files = 0;
  for (const path of walk(dir)) {
    files += 1;
    const bytes = readFileSync(path);
    gzipTotal += gzipSync(bytes).length;
    const extension = path.slice(path.lastIndexOf("."));
    if (TEXT_EXTENSIONS.has(extension)) {
      problems.push(...scanForKeyMaterial(relative(dir, path), bytes.toString("utf8")));
    }
  }
  if (files === 0) problems.push(`${dir}: the bundle is empty`);
  if (gzipTotal > maxGzipBytes) {
    problems.push(`${dir}: gzip size ${gzipTotal} bytes is over the limit of ${maxGzipBytes}`);
  }
  return problems;
}

function main(argv) {
  const args = argv.slice(2);
  let problems;
  if (args[0] === "--bundle") {
    const limit = args.indexOf("--max-gzip-bytes");
    const maxGzipBytes = limit >= 0 ? Number(args[limit + 1]) : Infinity;
    if (!args[1] || Number.isNaN(maxGzipBytes)) {
      console.error("usage: guard.mjs --bundle DIR [--max-gzip-bytes N]");
      return 2;
    }
    problems = checkBundle(args[1], { maxGzipBytes });
  } else if (args[0]) {
    const file = args.find((arg) => !arg.startsWith("--"));
    problems = checkConfig(file, readFileSync(file, "utf8"), {
      allowDestructive: process.env.ALLOW_DESTRUCTIVE_MIGRATION === "1",
      allowPreviewUrls: args.includes("--allow-preview-urls"),
    });
  } else {
    console.error("usage: guard.mjs FILE [--allow-preview-urls] | --bundle DIR [--max-gzip-bytes N]");
    return 2;
  }
  for (const problem of problems) console.error(`error: ${problem}`);
  if (problems.length === 0) console.log("guard: ok");
  return problems.length === 0 ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv));
}
