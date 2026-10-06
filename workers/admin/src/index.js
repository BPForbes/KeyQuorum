// The admin Worker's front door. Cloudflare Access sits in front of this
// hostname, and the Worker checks Access's signed token itself, so a mistake in
// the Access application cannot expose anything: without a valid token it
// serves no asset and no API. The page is static files, like the portfolio is
// hosted; the relay-backed routes arrive with the relay's store, and until then
// every /api route except /api/whoami answers 503.
import { verifyAccessToken } from "./access.js";

const SECURITY_HEADERS = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cross-origin-opener-policy": "same-origin",
  "cache-control": "no-store",
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

export async function handle(request, env, { verify = verifyAccessToken } = {}) {
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

  if (request.method !== "GET" && request.method !== "HEAD") {
    return json(405, { error: "method not allowed" }, { allow: "GET, HEAD" });
  }

  const { pathname } = new URL(request.url);
  if (pathname === "/api/whoami") {
    const { email, exp } = outcome.claims;
    return json(200, {
      email: typeof email === "string" ? email : null,
      expiresAt: typeof exp === "number" ? new Date(exp * 1000).toISOString() : null,
    });
  }
  if (pathname === "/api" || pathname.startsWith("/api/")) {
    return json(503, { error: "relay not connected" });
  }
  return withSecurityHeaders(await env.ASSETS.fetch(request));
}

export default {
  fetch(request, env) {
    return handle(request, env);
  },
};
