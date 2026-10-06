#!/usr/bin/env node
// Post-deploy smoke test for the public Worker:
//
//   node scripts/smoke.mjs https://relay.example.com
//
// It proves three things about what a deploy exposed: /health answers and is
// never cacheable, the public hostname has no operator or mint route (those
// belong to the Access-protected admin Worker only), and an unauthenticated
// customer route does not answer with success. It reads nothing secret and
// sends no credential.
import { fileURLToPath } from "node:url";

const OPERATOR_ROUTES = [
  ["GET", "/api-keys"],
  ["POST", "/api-keys"],
  ["POST", "/api-keys/smoke-check/revoke"],
  ["POST", "/keys"],
  ["POST", "/keys/create"],
  ["POST", "/keys/rotate"],
];

export async function runSmoke(baseUrl, { fetchImpl = fetch, attempts = 1, delayMs = 0 } = {}) {
  const base = baseUrl.replace(/\/+$/, "");
  const problems = [];
  const call = (method, path) =>
    fetchImpl(`${base}${path}`, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
    });

  let health = null;
  let healthError = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      health = await call("GET", "/health");
      if (health.status === 200) break;
    } catch (error) {
      healthError = error;
    }
    if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  if (!health) {
    return [`GET /health did not answer: ${healthError?.name ?? "no response"}`];
  }
  if (health.status !== 200) {
    problems.push(`GET /health answered ${health.status}, expected 200`);
  } else {
    const body = await health.json().catch(() => null);
    if (body?.status !== "ok") problems.push('GET /health body is not {"status":"ok"}');
    if (!(health.headers.get("cache-control") ?? "").includes("no-store")) {
      problems.push("GET /health is missing Cache-Control: no-store");
    }
  }

  for (const [method, path] of OPERATOR_ROUTES) {
    const response = await call(method, path);
    if (response.status !== 404 && response.status !== 405) {
      problems.push(`${method} ${path} answered ${response.status}; the public Worker must not route it`);
    }
  }

  const inbox = await call("GET", "/inbox");
  if (inbox.status !== 401 && inbox.status !== 404) {
    problems.push(`unauthenticated GET /inbox answered ${inbox.status}, expected 401 (or 404 before the relay exists)`);
  }
  return problems;
}

async function main(argv) {
  const url = argv[2];
  if (!url || !/^https:\/\//.test(url)) {
    console.error("usage: smoke.mjs https://HOSTNAME");
    return 2;
  }
  const problems = await runSmoke(url, { attempts: 6, delayMs: 5_000 });
  for (const problem of problems) console.error(`error: ${problem}`);
  if (problems.length === 0) console.log("smoke: ok");
  return problems.length === 0 ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv));
}
