// The admin Worker: the provider's console. Cloudflare Access sits in front of
// this hostname, and the Worker checks Access's signed token itself, so a
// mistake in the Access application cannot expose anything: without a valid
// token it serves no asset and no API. Only the provider's own people get past
// that; a client of the provider has no route here, and the public relay Worker
// links nothing to this one.
//
// The page is static files. The API (routes.js is its table) hands a JSON
// request to the relay's Durable Object over a private binding (`RELAY_ADMIN`)
// and returns the answer: the relay core (`relay::operator`) decides everything,
// and this Worker only keeps the wrong things out: a route or query it does not
// have, a body that is not JSON or is too large, a caller Access did not
// identify as a person, a change that did not come from this page's own origin,
// and anyone past a per-operator rate limit. Anything that changes the relay
// also needs the operator lock (`kql_...`) in `x-operator-lock` and an
// `Idempotency-Key` (the operation id that lets a lost response be reconciled).
// The lock is passed on and forgotten: never stored, logged or echoed. The
// identity sent to the relay is Access's, never one the browser claims.
import { verifyAccessToken } from "./access.js";
import { ISOLATION_HEADERS, crossSiteRefusal } from "../../src/browser-isolation.js";
import { adminMount, stripMount } from "../../src/mount.js";
import { MAX_REQUEST_BODY_CONSOLE, readLimitedText } from "./limits.js";
import { matchRoute } from "./routes.js";

const LOCK_PATTERN = /^kql_[A-Za-z0-9_-]{20,200}$/;
const OPERATION_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
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

// A change must come from this page: an `Origin` that is exactly this site's,
// and, where the browser says, a same-origin fetch. Access's cookie alone is
// not enough, so a page on another site cannot make the operator's browser
// change anything (the cross-site check above already refuses its fetches;
// this is the second, explicit one).
function changeRefusal(request) {
  const origin = request.headers.get("origin");
  if (origin === null || origin !== new URL(request.url).origin) return "a change that did not come from this site";
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin") return `a change marked ${site}`;
  return null;
}

async function limited(env, operator, change) {
  const binding = change ? env.WRITE_LIMITER : env.READ_LIMITER;
  if (!binding) return true;
  try {
    const { success } = await binding.limit({ key: operator });
    return success;
  } catch (error) {
    // A limiter that cannot answer does not lock the operator out.
    console.error("admin: the rate limiter did not answer", error?.name);
    return true;
  }
}

function stub(env) {
  return env.RELAY_ADMIN.get(env.RELAY_ADMIN.idFromName(OBJECT_NAME));
}

async function api(request, env, claims, url) {
  const route = matchRoute(request.method, url.pathname, url.searchParams);
  if (!route.ok) {
    return json(route.status, { error: route.error }, route.allow ? { allow: route.allow } : {});
  }
  const { spec, fields } = route;
  const change = spec.change === true;
  const writes = change || spec.lock === true || spec.op === "checkpoint";

  // The console is for a person: a service token carries no email, and the
  // relay records who acted.
  const operator = typeof claims.email === "string" ? claims.email.trim() : "";
  if (operator === "" || operator.length > 320) {
    return json(403, { error: "a signed-in person is required" });
  }
  if (writes) {
    const refusal = changeRefusal(request);
    if (refusal) {
      console.warn(`admin: refused ${refusal}`);
      return json(403, { error: "changes must come from this console" });
    }
  }
  if (!env.RELAY_ADMIN) return json(503, { error: "relay not connected" });
  if (!(await limited(env, operator, writes))) {
    return json(429, { error: "too many requests" }, { "retry-after": "60" });
  }

  if (spec.runtime) {
    try {
      return json(200, await stub(env).status());
    } catch (error) {
      console.error("admin: the relay did not answer", error?.name);
      return json(503, { error: "relay unavailable" });
    }
  }

  let lock = null;
  let operationId = null;
  let body = {};
  if (writes) {
    if (spec.op !== "checkpoint" && request.method === "POST") {
      const raw = request.headers.get("x-operator-lock");
      if (raw !== null) {
        if (!LOCK_PATTERN.test(raw)) return json(400, { error: "the operator lock is malformed" });
        lock = raw;
      }
    }
    if (change) {
      operationId = request.headers.get("idempotency-key");
      if (operationId === null || !OPERATION_PATTERN.test(operationId)) {
        return json(400, {
          error: "send an Idempotency-Key (8 to 64 letters, digits, - or _) so a lost response can be reconciled",
          code: "operation_id_required",
        });
      }
    }
    const type = request.headers.get("content-type") ?? "";
    const text = await readLimitedText(request, MAX_REQUEST_BODY_CONSOLE);
    if (text === null) return json(413, { error: "request too large" });
    if (text.trim() !== "") {
      if (!/^application\/json(\s*;|$)/i.test(type)) return json(415, { error: "send JSON" });
      try {
        body = JSON.parse(text);
      } catch {
        return json(400, { error: "unrecognised request" });
      }
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        return json(400, { error: "unrecognised request" });
      }
    }
  }

  // The request the relay core takes. What the browser may not decide is set
  // after its body: the operation, the operation id and the path's ids.
  const { op: _op, operation_id: _id, ...rest } = body;
  const request2 = { ...rest, ...fields, op: spec.op };
  if (operationId !== null) request2.operation_id = operationId;

  let result;
  try {
    result = await stub(env).operate({ body: JSON.stringify(request2), operator, lock });
  } catch (error) {
    // The name only: never the request, the lock or what the relay said.
    console.error("admin: the relay did not answer", error?.name);
    return json(503, { error: "relay unavailable" });
  }
  if (!Number.isInteger(result?.status) || result.status < 200 || result.status > 599 || typeof result.body !== "string") {
    console.error("admin: the relay answered in an unexpected shape");
    return json(502, { error: "unexpected answer from the relay" });
  }
  let out = result.body;
  if (spec.pick && result.status === 200) {
    try {
      const whole = JSON.parse(out);
      out = JSON.stringify({ customer: whole.customer, [spec.pick]: whole[spec.pick] });
    } catch {
      return json(502, { error: "unexpected answer from the relay" });
    }
  }
  return new Response(out, {
    status: result.status,
    headers: { "content-type": "application/json; charset=utf-8", ...SECURITY_HEADERS },
  });
}

export async function handle(incoming, env, { verify = verifyAccessToken } = {}) {
  // Another website, the Lab and the portfolio included, may not fetch, embed
  // or frame this console. A top-level page load is let through to the token
  // check below, because Access's sign-in redirect lands here marked cross-site;
  // it still needs a valid Access token.
  const refusal = crossSiteRefusal(incoming, { allowNavigation: true });
  if (refusal) {
    console.warn(`admin: refused ${refusal}`);
    return json(403, { error: "cross-site requests are not served" });
  }

  // Where this Worker is mounted on its host (MOUNT_PATH, src/mount.js): a
  // path of its own such as /relay/staging-admin, or none. The routes and
  // assets below see the path without it. A value that is not a valid mount
  // leaves the Worker unconfigured; a path outside the mount is not served,
  // and the mount without its slash goes to the slash (the page's links are
  // relative to it). None of this answers anything about the operator.
  const mount = adminMount(env.MOUNT_PATH);
  if (mount === null) return json(503, { error: "admin not configured" });
  const asked = new URL(incoming.url);
  const below = stripMount(asked.pathname, mount);
  if (below === null) return json(404, { error: "not found" });
  if (below.redirect !== undefined) {
    if (incoming.method !== "GET" && incoming.method !== "HEAD") {
      return json(405, { error: "method not allowed" }, { allow: "GET, HEAD" });
    }
    return new Response(null, {
      status: 308,
      headers: { ...SECURITY_HEADERS, location: `${below.redirect}${asked.search}` },
    });
  }
  const inner = new URL(asked);
  inner.pathname = below.path;
  const request = new Request(inner, incoming);

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

  const url = new URL(request.url);
  const { pathname } = url;
  if (pathname === "/api/whoami" && (request.method === "GET" || request.method === "HEAD")) {
    const { email, exp } = outcome.claims;
    return json(200, {
      email: typeof email === "string" ? email : null,
      expiresAt: typeof exp === "number" ? new Date(exp * 1000).toISOString() : null,
    });
  }
  if (pathname === "/api/config" && (request.method === "GET" || request.method === "HEAD")) {
    // Not secret: the address clients load their keys for, to pre-fill a form.
    return json(200, { relayUrl: typeof env.RELAY_PUBLIC_URL === "string" ? env.RELAY_PUBLIC_URL : "" });
  }
  if (pathname === "/api" || pathname.startsWith("/api/")) {
    if (pathname === "/api/whoami" || pathname === "/api/config") {
      return json(405, { error: "method not allowed" }, { allow: "GET, HEAD" });
    }
    return api(request, env, outcome.claims, url);
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return json(405, { error: "method not allowed" }, { allow: "GET, HEAD" });
  }
  return withSecurityHeaders(await env.ASSETS.fetch(request));
}

export default {
  fetch(request, env) {
    return handle(request, env);
  },
};
