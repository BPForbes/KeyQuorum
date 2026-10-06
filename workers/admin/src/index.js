// The admin Worker: the provider's console. Cloudflare Access sits in front of
// this hostname, and the Worker checks Access's signed token itself, so a
// mistake in the Access application cannot expose anything: without a valid
// token it serves no asset and no API. Only the provider's own people get past
// that; a client of the provider has no route here, and the public relay Worker
// links nothing to this one.
//
// The page is static files. Its one data route, `POST /api/operate`, hands a
// JSON request to the relay's Durable Object (the `RELAY` binding) and returns
// the answer: the relay core (`relay::operator`) decides everything, and this
// Worker only keeps the wrong things out: a request that is not JSON, too large,
// or for an operation it does not know; a caller Access did not identify as a
// person. Anything that changes the relay needs the operator lock (`kql_...`),
// which the page sends in `x-operator-lock` with that one request. The lock is
// passed on and forgotten: never stored, logged or echoed. There is no route
// that mints or voids without it, and the public Worker has no route here.
import { verifyAccessToken } from "./access.js";
import { ISOLATION_HEADERS, crossSiteRefusal } from "../../src/browser-isolation.js";
import { MAX_REQUEST_BODY_CONSOLE, readLimitedText } from "./limits.js";

// The operations the relay core answers (src/relay/operator.rs, `Request`).
const OPERATIONS = new Set([
  "overview", "keys", "licences", "activity", "events", "letters", "trees", "checkpoint",
  "bootstrap", "rotate_lock", "issue", "rotate", "void_key", "void_licence",
]);
const LOCK_PATTERN = /^kql_[A-Za-z0-9_-]{20,200}$/;
const OBJECT_NAME = "relay";

const SECURITY_HEADERS = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
  // Never loadable or framable by another site; no CORS header is ever sent.
  ...ISOLATION_HEADERS,
};

function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...SECURITY_HEADERS, ...extra },
  });
}

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function operate(request, env, claims) {
  // The console is for a person: a service token carries no email, and the
  // relay records who acted.
  const operator = typeof claims.email === "string" ? claims.email.trim() : "";
  if (operator === "" || operator.length > 320) {
    return json(403, { error: "a signed-in person is required" });
  }
  if (!/^application\/json(\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
    return json(415, { error: "send JSON" });
  }
  const lock = request.headers.get("x-operator-lock");
  if (lock !== null && !LOCK_PATTERN.test(lock)) {
    return json(400, { error: "the operator lock is malformed" });
  }
  const text = await readLimitedText(request, MAX_REQUEST_BODY_CONSOLE);
  if (text === null) return json(413, { error: "request too large" });
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return json(400, { error: "unrecognised request" });
  }
  if (!OPERATIONS.has(parsed?.op)) return json(400, { error: "unrecognised request" });
  if (!env.RELAY) return json(503, { error: "relay not connected" });

  let result;
  try {
    const stub = env.RELAY.get(env.RELAY.idFromName(OBJECT_NAME));
    result = await stub.operate({ body: text, operator, lock });
  } catch (error) {
    // The name only: never the request, the lock or what the relay said.
    console.error("admin: the relay did not answer", error?.name);
    return json(503, { error: "relay unavailable" });
  }
  if (!Number.isInteger(result?.status) || result.status < 200 || result.status > 599 || typeof result.body !== "string") {
    console.error("admin: the relay answered in an unexpected shape");
    return json(502, { error: "unexpected answer from the relay" });
  }
  return new Response(result.body, {
    status: result.status,
    headers: { "content-type": "application/json; charset=utf-8", ...SECURITY_HEADERS },
  });
}

export async function handle(request, env, { verify = verifyAccessToken } = {}) {
  // Another website, the Lab and the portfolio included, may not fetch, embed
  // or frame this console. A top-level page load is let through to the token
  // check below, because Access's sign-in redirect lands here marked cross-site;
  // it still needs a valid Access token.
  const refusal = crossSiteRefusal(request, { allowNavigation: true });
  if (refusal) {
    console.warn(`admin: refused ${refusal}`);
    return json(403, { error: "cross-site requests are not served" });
  }
  const outcome = await verify(request.headers.get("cf-access-jwt-assertion"), {
    teamDomain: env.ACCESS_TEAM_DOMAIN,
    audience: env.ACCESS_AUD,
  });
  if (!outcome.ok) {
    // The reason is for the operator's log; it never reaches the caller.
    console.warn(`admin: access refused (${outcome.reason})`);
    if (outcome.reason === "not configured") return json(503, { error: "admin not configured" });
    return json(403, { error: "access required" });
  }

  const { pathname } = new URL(request.url);
  if (pathname === "/api/operate") {
    if (request.method !== "POST") return json(405, { error: "method not allowed" }, { allow: "POST" });
    return operate(request, env, outcome.claims);
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return json(405, { error: "method not allowed" }, { allow: "GET, HEAD" });
  }
  if (pathname === "/api/whoami") {
    const { email, exp } = outcome.claims;
    return json(200, {
      email: typeof email === "string" ? email : null,
      expiresAt: typeof exp === "number" ? new Date(exp * 1000).toISOString() : null,
    });
  }
  if (pathname === "/api/config") {
    // Not secret: the address clients load their keys for, to pre-fill a form.
    return json(200, { relayUrl: typeof env.RELAY_PUBLIC_URL === "string" ? env.RELAY_PUBLIC_URL : "" });
  }
  if (pathname === "/api" || pathname.startsWith("/api/")) {
    return json(404, { error: "not found" });
  }
  return withSecurityHeaders(await env.ASSETS.fetch(request));
}

export default {
  fetch(request, env) {
    return handle(request, env);
  },
};
