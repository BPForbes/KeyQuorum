// The relay inside one Durable Object, with nothing Cloudflare-specific in it so
// that it runs under Node's test runner over the real WebAssembly core. The
// Durable Object class (relay-object.js) hands it `ctx.storage`, the Worker's
// `env` and the wasm bindings; everything else is here.
//
// It decides no relay rule. Routing, key scopes, fingerprint binding, the audit
// chain and idempotent letter filing are the Rust core's (`RelayCore.handle`,
// the same `relay::service::dispatch` every backend runs). This module reads a
// request, bounds it, asks the core, and shapes the answer. A bearer goes to the
// core and nowhere else: it is not logged, stored or echoed.
import { createSqlAdapter } from "./sql-adapter.js";
import { baseHeaders, bearerOf, jsonResponse, readLimited } from "./policy.js";

// How many requests the object takes at once. The object is a single writer, so
// what queues behind it is bounded here: past this, a request is refused at
// once with 503 and Retry-After, never left waiting.
export const MAX_IN_FLIGHT = 32;

// How often the object's alarm purges expired letters and signs the audit
// chain heads.
export const SCAN_INTERVAL_MS = 60 * 60 * 1000;

// The time the core takes in as text, UTC, `YYYY-MM-DD HH:MM:SS.mmm`.
export function relayTime(date) {
  return date.toISOString().replace("T", " ").replace("Z", "");
}

// A Worker secret is text. The certificate (`provider.kqcert`) is binary, so it
// is set as base64. The relay key is accepted as the file `host identity
// generate` writes, a hex dump of its 32 bytes, so it can be set as it is
// (`wrangler secret put RELAY_PRIVATE_KEY < relay.key`), or as base64. A hex
// dump of 32 bytes (64 characters) and the base64 of 32 bytes (44) cannot be
// mistaken for each other. Returns null for text that is neither.
function fromBase64(text) {
  const clean = String(text).replace(/\s+/g, "");
  if (clean === "" || clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) return null;
  try {
    return Uint8Array.from(atob(clean), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function fromHexOrBase64(text) {
  const clean = String(text).replace(/\s+/g, "");
  if (/^[0-9a-fA-F]{64}$/.test(clean)) {
    return Uint8Array.from(clean.match(/../g), (pair) => parseInt(pair, 16));
  }
  return fromBase64(clean);
}

// -> { certificate, key } as bytes, both undefined when neither secret is set,
// or { error } when only one is set or either cannot be read (the value is
// never named).
function readIdentity(env) {
  const hasCertificate = typeof env.RELAY_CERTIFICATE === "string" && env.RELAY_CERTIFICATE.trim() !== "";
  const hasKey = typeof env.RELAY_PRIVATE_KEY === "string" && env.RELAY_PRIVATE_KEY.trim() !== "";
  if (!hasCertificate && !hasKey) return { certificate: undefined, key: undefined };
  if (hasCertificate !== hasKey) return { error: "relay identity misconfigured" };
  const certificate = fromBase64(env.RELAY_CERTIFICATE);
  const key = fromHexOrBase64(env.RELAY_PRIVATE_KEY);
  if (!certificate || !key || key.length !== 32) return { error: "relay identity misconfigured" };
  return { certificate, key };
}

export function createRelayService({ storage, env, bindings, clock = () => new Date(), log = console }) {
  let core = null;
  let failure = null;
  let inFlight = 0;

  const identity = readIdentity(env);
  if (identity.error) {
    // Fail closed: serve nothing rather than a relay that cannot prove who it
    // is. The reason names no value.
    failure = identity.error;
    log.error("relay: the identity secrets are set but unusable");
  } else {
    try {
      core = new bindings.RelayCore(createSqlAdapter(storage), identity.certificate, identity.key);
    } catch (error) {
      failure = "relay unavailable";
      log.error("relay: the core did not start", error?.name);
    } finally {
      // The core took its own copy; do not leave the key sitting in this one.
      identity.key?.fill(0);
    }
  }

  async function fetch(request) {
    if (failure) return jsonResponse(503, { error: failure });
    if (inFlight >= MAX_IN_FLIGHT) return jsonResponse(503, { error: "busy" }, { "retry-after": "1" });
    inFlight += 1;
    let answer = null;
    try {
      const body = await readLimited(request);
      if (body === null) return jsonResponse(413, { error: "request too large" });
      answer = core.handle(
        request.method,
        request.url,
        bearerOf(request.headers),
        request.headers.get("content-type") ?? undefined,
        body,
        relayTime(clock()),
      );
      const status = answer.status;
      const bytes = answer.body;
      if (status === 204 || (bytes.length === 0 && status < 400)) {
        return new Response(null, { status, headers: baseHeaders() });
      }
      if (bytes.length === 0) return jsonResponse(status, { error: "request refused" });
      return new Response(bytes, {
        status,
        headers: baseHeaders({ "content-type": "application/json; charset=utf-8" }),
      });
    } catch (error) {
      log.error("relay: a request failed", error?.name);
      return jsonResponse(500, { error: "internal error" });
    } finally {
      answer?.free?.();
      inFlight -= 1;
    }
  }

  // Whether the store answers (the readiness probe).
  function ready() {
    if (failure) return false;
    try {
      return core.ready();
    } catch {
      return false;
    }
  }

  // Called once when the object starts: make sure the housekeeping alarm is set.
  async function start() {
    if ((await storage.getAlarm()) === null) {
      await storage.setAlarm(clock().getTime() + SCAN_INTERVAL_MS);
    }
  }

  // The alarm: purge, sign the audit heads, and set the next one even if the
  // scan failed, so one bad run does not end the housekeeping.
  async function alarm() {
    try {
      if (core) core.scan(relayTime(clock()));
    } catch (error) {
      log.error("relay: the scheduled scan failed", error?.name);
    } finally {
      await storage.setAlarm(clock().getTime() + SCAN_INTERVAL_MS);
    }
  }

  return { fetch, ready, start, alarm, inFlight: () => inFlight };
}
