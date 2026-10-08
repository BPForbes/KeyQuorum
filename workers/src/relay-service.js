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
import { MAX_REQUEST_BODY, baseHeaders, bearerOf, bodyLimit, jsonResponse, readLimited } from "./policy.js";
import { backupBucketOf, backupSettings, createBackups } from "./backups.js";
import { bucketOf, createBlobRelay, holdFrom } from "./blobs.js";

// How many requests the object takes at once. The object is a single writer, so
// what queues behind it is bounded here: past this, a request is refused at
// once with 503 and Retry-After, never left waiting.
export const MAX_IN_FLIGHT = 32;

// The largest console request the object takes (the Rust core holds the same
// bound, `relay::operator::MAX_REQUEST_BYTES`).
export const MAX_OPERATE_BODY = 64 * 1024;

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

// The provider root this relay pins (`PROVIDER_ROOT`, a deploy variable
// holding the 64-hex public key `host provision` or the console wrote as
// root.pub; never a secret). -> { root } as bytes, undefined when unset, or
// { error } when set but not a 64-character hex key (the value is never named).
function readPinnedRoot(env) {
  const text = typeof env.PROVIDER_ROOT === "string" ? env.PROVIDER_ROOT.trim() : "";
  if (text === "") return { root: undefined };
  if (!/^[0-9a-fA-F]{64}$/.test(text)) return { error: "pinned root misconfigured" };
  return { root: Uint8Array.from(text.match(/../g), (pair) => parseInt(pair, 16)) };
}

// The relay inside one Durable Object: the core over its storage, the R2
// helpers when their buckets are bound, request admission, and the console's
// `operate` and `status`. Fails closed on an unusable identity or root.
export function createRelayService({ storage, env, bindings, clock = () => new Date(), log = console }) {
  let core = null;
  let blobs = null;
  let backups = null;
  let failure = null;
  let inFlight = 0;
  let largeBodies = 0;
  // What this object has seen since it started, for the operator's status page.
  // In memory only: it is not a record, and a restart begins it again.
  const stats = {
    startedAt: clock().toISOString(),
    admitted: 0,
    busyRefusals: 0,
    errors: 0,
    alarmLastRunAt: null,
    alarmLastFailure: null,
  };

  const identity = readIdentity(env);
  const pinned = readPinnedRoot(env);
  if (identity.error || pinned.error) {
    // Fail closed: serve nothing rather than a relay that cannot prove who it
    // is, or that would check its identity against a root it cannot read.
    // The reason names no value.
    failure = identity.error ?? pinned.error;
    log.error(identity.error ? "relay: the identity secrets are set but unusable" : "relay: PROVIDER_ROOT is set but is not a 64-character hex key");
  } else {
    try {
      core = new bindings.RelayCore(createSqlAdapter(storage), identity.certificate, identity.key, pinned.root);
      // With an R2 bucket bound (`LETTERS`), large sealed letters are held there
      // and not in the row; without one nothing is, and nothing below changes.
      const bucket = bucketOf(env);
      if (bucket) {
        core.hold_letters_from(holdFrom(env));
        blobs = createBlobRelay({ core, bucket, log });
      }
      // With a `BACKUPS` bucket and a backup public key (BACKUP_RECIPIENT), the
      // alarm writes sealed backups of the database (src/backups.js).
      const backupBucket = backupBucketOf(env);
      const settings = backupSettings(env);
      if (backupBucket && settings.enabled) {
        backups = createBackups({ core, bucket: backupBucket, storage, settings, relayTime, clock, log });
      }
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
    if (inFlight >= MAX_IN_FLIGHT) {
      stats.busyRefusals += 1;
      return jsonResponse(503, { error: "busy" }, { "retry-after": "1" });
    }
    // A large letter body (up to 16 MiB, buffered whole) is let in one at a time:
    // the isolate has 128 MB for everything in flight.
    const limit = bodyLimit(request.method, new URL(request.url).pathname, request.headers.get("content-type"), Boolean(blobs));
    const large = limit > MAX_REQUEST_BODY;
    if (large && largeBodies >= 1) {
      stats.busyRefusals += 1;
      return jsonResponse(503, { error: "busy" }, { "retry-after": "1" });
    }
    if (large) largeBodies += 1;
    inFlight += 1;
    stats.admitted += 1;
    const started = clock().getTime();
    let answer = null;
    try {
      const body = await readLimited(request, limit);
      if (body === null) return jsonResponse(413, { error: "request too large" });
      const bearer = bearerOf(request.headers);
      const contentType = request.headers.get("content-type") ?? undefined;
      const ask = () => core.handle(request.method, request.url, bearer, contentType, body, relayTime(clock()));
      // A route that carries held letters finishes its business with the bucket
      // first (src/blobs.js); every other request goes straight to the core.
      const held = blobs
        ? await blobs.around({ method: request.method, url: request.url, contentType, body }, () => {
            const reply = ask();
            try {
              return { status: reply.status, body: reply.body };
            } finally {
              reply.free?.();
            }
          })
        : null;
      if (!held) answer = ask();
      const status = held ? held.status : answer.status;
      const bytes = held ? held.body : answer.body;
      // What a known key did, for the provider's console: the key, the coarse
      // part of the API, the answer, how long it took (this clock moves only
      // when the object waits, so it is coarse) and the bytes each way. Never
      // the path past its first segment, a body or an address. A failure to
      // count never changes the answer.
      if (bearer) {
        try {
          core.record_access(
            bearer,
            request.url,
            status,
            Math.max(0, Math.min(clock().getTime() - started, 0xffffffff)),
            body.length,
            bytes.length,
          );
        } catch (error) {
          log.error("relay: the request could not be counted", error?.name);
        }
      }
      if (status === 204 || (bytes.length === 0 && status < 400)) {
        return new Response(null, { status, headers: baseHeaders() });
      }
      if (bytes.length === 0) return jsonResponse(status, { error: "request refused" });
      return new Response(bytes, {
        status,
        headers: baseHeaders({ "content-type": "application/json; charset=utf-8" }),
      });
    } catch (error) {
      stats.errors += 1;
      log.error("relay: a request failed", error?.name);
      return jsonResponse(500, { error: "internal error" });
    } finally {
      answer?.free?.();
      inFlight -= 1;
      if (large) largeBodies -= 1;
    }
  }

  // The provider's console (relay::operator in the core). Only the admin
  // Worker reaches this, through its binding to the object; nothing on the
  // public route does. `body` is the JSON request text, `operator` the identity
  // Cloudflare Access verified, `lock` the operator lock when the request
  // changes something. The lock goes to the core and nowhere else: it is not
  // logged, stored or echoed. Returns { status, body } as plain data.
  function operate({ body, operator, lock } = {}) {
    const refuse = (status, error) => ({ status, body: JSON.stringify({ error }) });
    if (failure) return refuse(503, failure);
    if (
      typeof body !== "string" ||
      typeof operator !== "string" ||
      operator.trim() === "" ||
      operator.length > 320 ||
      !(lock === undefined || lock === null || (typeof lock === "string" && lock.length <= 256))
    ) {
      return refuse(400, "malformed console request");
    }
    const bytes = new TextEncoder().encode(body);
    if (bytes.length > MAX_OPERATE_BODY) return refuse(413, "request too large");
    let answer = null;
    try {
      answer = core.operate(bytes, operator, lock ?? undefined, relayTime(clock()));
      return { status: answer.status, body: new TextDecoder().decode(answer.body) };
    } catch (error) {
      log.error("relay: a console request failed", error?.name);
      return refuse(500, "internal error");
    } finally {
      answer?.free?.();
    }
  }

  // The operator's status page: what the core knows of itself (identity,
  // certificate dates, the operator lock's state, counts) joined with what only
  // this object can see (storage use, the housekeeping alarm, overload, the
  // deployment). Observed since the object last started, and not an audit
  // record. Returns plain data.
  async function status() {
    let runtime = null;
    try {
      runtime = {
        started_at: stats.startedAt,
        requests_admitted: stats.admitted,
        busy_refusals: stats.busyRefusals,
        request_errors: stats.errors,
        in_flight: inFlight,
        max_in_flight: MAX_IN_FLIGHT,
        alarm: {
          next_at: await alarmAt(),
          last_run_at: stats.alarmLastRunAt,
          last_failure: stats.alarmLastFailure,
          interval_ms: SCAN_INTERVAL_MS,
        },
        storage_bytes: storageBytes(),
        letters_in_r2: blobs !== null,
        backups: await backupStatus(),
        deployment: deployment(),
      };
    } catch (error) {
      log.error("relay: the status could not be read", error?.name);
    }
    let known = null;
    if (!failure) {
      const answer = operate({ body: JSON.stringify({ op: "status" }), operator: "status" });
      if (answer.status === 200) known = JSON.parse(answer.body);
    }
    return {
      ready: ready(),
      failure: failure ?? null,
      runtime,
      relay: known,
      note: "Observed by the relay object since it last started. Requests the public Worker refused before the relay (wrong host or route, too large, rate limited) are not counted here.",
    };
  }

  // What the operator's status page says of the backups: off and why, or the
  // last one made and anything that went wrong since.
  async function backupStatus() {
    if (backups) return backups.status();
    const settings = backupSettings(env);
    return {
      enabled: false,
      reason: !backupBucketOf(env) ? "no backup bucket bound (BACKUPS)" : settings.reason,
    };
  }

  async function alarmAt() {
    const at = await storage.getAlarm();
    return at === null || at === undefined ? null : new Date(at).toISOString();
  }

  // The size of the object's SQLite database in bytes, where the platform tells.
  function storageBytes() {
    const size = storage.sql?.databaseSize;
    return Number.isFinite(size) ? size : null;
  }

  // Which version of the Worker this is, from the version-metadata binding when
  // it is bound. Nothing secret.
  function deployment() {
    const meta = env.CF_VERSION_METADATA;
    if (!meta || typeof meta !== "object") return null;
    return {
      id: typeof meta.id === "string" ? meta.id : null,
      tag: typeof meta.tag === "string" && meta.tag !== "" ? meta.tag : null,
      timestamp: typeof meta.timestamp === "string" ? meta.timestamp : null,
    };
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
      // The objects of letters that are gone. A bucket that is down leaves them
      // for the next run; the housekeeping and its next alarm go on regardless.
      if (blobs) await blobs.sweep();
      // A sealed backup when one is due. Its failure is recorded for the status
      // page and never stops the housekeeping or the next alarm.
      if (backups) {
        try {
          if (await backups.due()) await backups.run();
        } catch (error) {
          log.error("relay: the scheduled backup failed", error?.name);
        }
      }
      stats.alarmLastRunAt = clock().toISOString();
      stats.alarmLastFailure = null;
    } catch (error) {
      stats.alarmLastRunAt = clock().toISOString();
      stats.alarmLastFailure = error?.name ?? "Error";
      log.error("relay: the scheduled scan failed", error?.name);
    } finally {
      await storage.setAlarm(clock().getTime() + SCAN_INTERVAL_MS);
    }
  }

  return { fetch, operate, status, ready, start, alarm, inFlight: () => inFlight };
}
