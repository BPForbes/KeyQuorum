// The public Worker of the KeyQuorum relay.
//
// It authenticates nothing itself. It decides whether to answer at all (the
// host, the route, the method, the size), applies a per-client rate limit, and
// hands what is left to the one Durable Object that owns the relay. The relay
// core in that object decides who may do what; this file only keeps everything
// else out. Every response is `Cache-Control: no-store`.
//
// Everything is under the Worker's mount (mount.js: `/relay`, or `/relay/<name>`
// for a staging relay on the same host); a path outside it is a 404, so the rest
// of the domain belongs to other things.
//
// What it will not do: answer another website's browser (see
// browser-isolation.js: the Lab and the portfolio are other sites, and the relay
// shares no origin, hosting or code with either), serve a host other than the relay's own (a Version URL
// of a deploy shares production's bindings and secrets, so it is refused, not
// served), route an operator path (`/api-keys*`, the full `/audit/*`, anything
// that mints is not on this Worker), or keep a request waiting behind the
// object (the object refuses past `MAX_IN_FLIGHT`).
import { crossSiteRefusal } from "./browser-isolation.js";
import { relayMount } from "./mount.js";
import {
  MAX_REQUEST_BODY,
  baseHeaders,
  classify,
  hostDecision,
  jsonResponse,
  parseAllowedHosts,
} from "./policy.js";
import { STATUS_CSP, STATUS_CSS, STATUS_HTML, STATUS_JS } from "./status-page.js";

const OBJECT_NAME = "relay";

const ASSETS = new Map([
  ["/assets/status.js", ["text/javascript; charset=utf-8", STATUS_JS]],
  ["/assets/status.css", ["text/css; charset=utf-8", STATUS_CSS]],
]);

function relayObject(env) {
  return env.RELAY.get(env.RELAY.idFromName(OBJECT_NAME));
}

function unavailable(extra = {}) {
  return jsonResponse(503, { error: "relay unavailable" }, { "retry-after": "5", ...extra });
}

export async function handle(request, env, log = console) {
  const url = new URL(request.url);

  const decision = hostDecision(parseAllowedHosts(env.ALLOWED_HOSTS), url.hostname);
  if (decision === "unconfigured") return jsonResponse(503, { error: "relay not configured" });
  if (decision === "refused") {
    // Not this relay's hostname: answer as if nothing were here, and say so in
    // the log (the host is not a secret; no header or body is logged).
    log.warn("relay: refused a request for a host that is not the relay's");
    return jsonResponse(404, { error: "not found" });
  }

  // Another website, the Lab and the portfolio included, may not reach this
  // site from a browser: no fetch, frame, script, image or form from it, and no
  // link either (the relay has no sign-in redirect that would need one). A
  // person who types the address, or the site's own page, passes; so does a
  // command-line client, which sends none of these headers.
  const refusal = crossSiteRefusal(request);
  if (refusal) {
    log.warn(`relay: refused ${refusal}`);
    return jsonResponse(403, { error: "cross-site requests are not served" });
  }

  // Where this Worker is mounted (MOUNT_PATH, mount.js): a value that is not a
  // valid mount leaves it unconfigured, so a typo serves nothing.
  const mount = relayMount(env.MOUNT_PATH);
  if (mount === null) return jsonResponse(503, { error: "relay not configured" });

  const route = classify(request.method, url.pathname, mount);
  switch (route.kind) {
    case "redirect":
      // The page's links are relative, so it must be loaded with its slash.
      return new Response(null, {
        status: 308,
        headers: baseHeaders({ location: `${route.to}${url.search}` }),
      });
    case "not-found":
      return jsonResponse(404, { error: "not found" });
    case "method-not-allowed":
      return jsonResponse(405, { error: "method not allowed" }, { allow: route.allow });
    case "health":
      return jsonResponse(200, { status: "ok" });
    case "ready": {
      try {
        const ready = await relayObject(env).ready();
        return ready
          ? jsonResponse(200, { status: "ready" })
          : jsonResponse(503, { status: "unavailable" }, { "retry-after": "5" });
      } catch (error) {
        log.error("relay: the readiness check failed", error?.name);
        return jsonResponse(503, { status: "unavailable" }, { "retry-after": "5" });
      }
    }
    case "status":
      return new Response(STATUS_HTML, {
        status: 200,
        headers: baseHeaders({
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": STATUS_CSP,
          "cross-origin-opener-policy": "same-origin",
        }),
      });
    case "asset": {
      const [type, body] = ASSETS.get(route.path);
      return new Response(body, { status: 200, headers: baseHeaders({ "content-type": type }) });
    }
  }

  // A relay route. The size is checked before a body is read; the object bounds
  // the stream itself for a request that does not declare one.
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_REQUEST_BODY) {
    return jsonResponse(413, { error: "request too large" });
  }

  if (env.RATE_LIMITER) {
    const client = request.headers.get("cf-connecting-ip") ?? "unknown";
    let allowed = true;
    try {
      ({ success: allowed } = await env.RATE_LIMITER.limit({ key: client }));
    } catch (error) {
      // A limiter that cannot answer does not stop the relay; the zone's
      // rate-limit rule and the object's own bound still apply.
      log.error("relay: the rate limiter did not answer", error?.name);
    }
    if (!allowed) return jsonResponse(429, { error: "too many requests" }, { "retry-after": "60" });
  }

  // The core is given the path below the prefix, as it has always had it.
  const inner = new URL(request.url);
  inner.pathname = route.path;
  const forwarded = new Request(inner, request);

  let answer;
  try {
    answer = await relayObject(env).fetch(forwarded);
  } catch (error) {
    log.error("relay: the relay object did not answer", error?.name);
    return unavailable();
  }
  // The object's answer, with this Worker's headers laid over it.
  const headers = new Headers(answer.headers);
  for (const [name, value] of Object.entries(baseHeaders())) headers.set(name, value);
  return new Response(answer.body, { status: answer.status, headers });
}

export default {
  fetch(request, env) {
    return handle(request, env);
  },
};
