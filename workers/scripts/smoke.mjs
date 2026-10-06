#!/usr/bin/env node
// Post-deploy smoke test for the public Worker:
//
//   node scripts/smoke.mjs https://relay.example.com
//
// It proves what a deploy exposed: /health answers and is never cacheable, the
// Durable Object answers readiness, the status page carries its locked-down
// policy, the public hostname has no operator, documentation or mint route
// (those belong to the Access-protected admin Worker only), an unauthenticated
// customer route is 401, and the provider challenge either answers with an
// identity or says the relay has none yet. It reads nothing secret and sends
// no credential.
import { fileURLToPath } from "node:url";

const OPERATOR_ROUTES = [
  ["GET", "/api-keys"],
  ["POST", "/api-keys"],
  ["POST", "/api-keys/smoke-check/revoke"],
  ["GET", "/audit"],
  ["GET", "/audit/keys"],
  ["GET", "/swagger-ui/"],
  ["GET", "/api-docs/openapi.json"],
  ["POST", "/keys"],
  ["POST", "/keys/create"],
  ["POST", "/keys/rotate"],
];

export async function runSmoke(baseUrl, { fetchImpl = fetch, attempts = 1, delayMs = 0 } = {}) {
  const base = baseUrl.replace(/\/+$/, "");
  const problems = [];
  const call = (method, path, init = {}) =>
    fetchImpl(`${base}${path}`, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
      ...init,
    });

  // A fresh deploy takes a moment to answer; retry until it does.
  async function until(path, accept) {
    let response = null;
    let failure = null;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        response = await call("GET", path);
        if (accept(response)) break;
      } catch (error) {
        failure = error;
      }
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    return { response, failure };
  }

  const health = await until("/health", (response) => response.status === 200);
  if (!health.response) {
    return [`GET /health did not answer: ${health.failure?.name ?? "no response"}`];
  }
  if (health.response.status !== 200) {
    problems.push(`GET /health answered ${health.response.status}, expected 200`);
  } else {
    const body = await health.response.json().catch(() => null);
    if (body?.status !== "ok") problems.push('GET /health body is not {"status":"ok"}');
    if (!(health.response.headers.get("cache-control") ?? "").includes("no-store")) {
      problems.push("GET /health is missing Cache-Control: no-store");
    }
  }

  // The Durable Object: readiness is the relay's store answering.
  const ready = await until("/ready", (response) => response.status === 200);
  if (!ready.response) {
    problems.push(`GET /ready did not answer: ${ready.failure?.name ?? "no response"}`);
  } else if (ready.response.status !== 200) {
    problems.push(`GET /ready answered ${ready.response.status}, expected 200 (the relay's store is not answering)`);
  } else {
    const body = await ready.response.json().catch(() => null);
    if (body?.status !== "ready") problems.push('GET /ready body is not {"status":"ready"}');
  }

  const page = await call("GET", "/");
  if (page.status !== 200 || !(page.headers.get("content-type") ?? "").includes("text/html")) {
    problems.push(`GET / answered ${page.status}, expected the status page`);
  } else {
    const policy = page.headers.get("content-security-policy") ?? "";
    if (!policy.includes("default-src 'none'") || /unsafe-|\*/.test(policy)) {
      problems.push("GET / is missing its locked-down content security policy");
    }
    if (!(page.headers.get("cache-control") ?? "").includes("no-store")) {
      problems.push("GET / is missing Cache-Control: no-store");
    }
  }

  for (const [method, path] of OPERATOR_ROUTES) {
    const response = await call(method, path);
    if (response.status !== 404 && response.status !== 405) {
      problems.push(`${method} ${path} answered ${response.status}; the public Worker must not route it`);
    }
  }

  const inbox = await call("GET", "/inbox");
  if (inbox.status !== 401) {
    problems.push(`unauthenticated GET /inbox answered ${inbox.status}, expected 401`);
  }
  if (!(inbox.headers.get("cache-control") ?? "").includes("no-store")) {
    problems.push("GET /inbox is missing Cache-Control: no-store");
  }

  // The provider challenge: a relay with its identity answers 200 with a
  // certificate and signature; one without says so with 503. Anything else is
  // a relay that is broken, not merely unconfigured.
  const challenge = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const identity = await call("POST", "/provider-identity", {
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge }),
  });
  if (identity.status === 200) {
    const body = await identity.json().catch(() => null);
    if (typeof body?.certificate !== "string" || typeof body?.signature !== "string") {
      problems.push("POST /provider-identity answered 200 without a certificate and signature");
    }
  } else if (identity.status !== 503) {
    problems.push(`POST /provider-identity answered ${identity.status}, expected 200 or 503`);
  }
  return problems;
}

// The admin hostname sits behind Cloudflare Access, and the admin Worker also
// refuses a request without a valid token. From outside, with no credential,
// nothing may answer with success: Access redirects to its login (3xx) or
// refuses, and the Worker answers 403 (or 503 while it is unconfigured).
export async function runAdminSmoke(baseUrl, { fetchImpl = fetch } = {}) {
  const base = baseUrl.replace(/\/+$/, "");
  const problems = [];
  for (const [method, path] of [
    ["GET", "/"],
    ["GET", "/index.html"],
    ["GET", "/app.js"],
    ["GET", "/api/whoami"],
    ["GET", "/api/config"],
    ["POST", "/api/operate"],
  ]) {
    let response;
    try {
      response = await fetchImpl(`${base}${path}`, {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(15_000),
        // The console's one data route, asked for a read with no credential:
        // it must not reach the relay.
        ...(method === "POST"
          ? { headers: { "content-type": "application/json" }, body: JSON.stringify({ op: "overview" }) }
          : {}),
      });
    } catch (error) {
      problems.push(`admin ${method} ${path} did not answer: ${error?.name ?? "no response"}`);
      continue;
    }
    if (response.status < 300 || response.status >= 600 || response.status === 404) {
      problems.push(`admin ${method} ${path} answered ${response.status} without a credential`);
    }
  }
  return problems;
}

async function main(argv) {
  const url = argv[2];
  const adminFlag = argv.indexOf("--admin");
  const adminUrl = adminFlag >= 0 ? argv[adminFlag + 1] : null;
  if (!url || !/^https:\/\//.test(url) || (adminFlag >= 0 && !/^https:\/\//.test(adminUrl ?? ""))) {
    console.error("usage: smoke.mjs https://HOSTNAME [--admin https://ADMIN_HOSTNAME]");
    return 2;
  }
  const problems = await runSmoke(url, { attempts: 6, delayMs: 5_000 });
  if (adminUrl) problems.push(...(await runAdminSmoke(adminUrl)));
  for (const problem of problems) console.error(`error: ${problem}`);
  if (problems.length === 0) console.log("smoke: ok");
  return problems.length === 0 ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv));
}
