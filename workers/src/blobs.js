// Sealed letters held in an R2 bucket instead of a row (docs/operator/r2-blobs.md).
//
// The relay core never opens a letter and has no network, so it only says what
// must be stored and when it is safe (src/relay/blob.rs). The transfers are
// here, because R2's API is asynchronous and the core is not. Nothing in this
// file decides a relay rule: it moves bytes the core named, checks they are the
// bytes whose SHA-256 is in the key, and tells the core how it went.
//
// Accepting a large letter is two steps (a row and an object cannot commit
// together): the core authenticates and validates the request and inserts the
// row *not ready*, answering with the key; only then is anything written to the
// bucket, so an unauthorised request can never fill it; then the row is made
// ready, or dropped if the bucket refused. Pushes and the sweep of deleted
// letters' objects run one at a time, so a letter stored anew can never meet a
// delete of its own earlier object.

// Letters at least this long are held in the bucket. Small letters stay in
// their row, atomic with everything else.
export const DEFAULT_HOLD_FROM = 64 * 1024;
export const MIN_HOLD_FROM = 4096;
// Letters under 1 MiB fit a row; one at or over it never does, so the threshold
// is never above it (the core clamps it the same way).
export const MAX_HOLD_FROM = 1024 * 1024;

// The routes whose answers carry held letters, and the mailbox each belongs to.
const PUSH = { "/inbox": "inbox", "/devices/packages": "device" };
const PULL = { "/inbox": ["inbox", "envelopes"], "/devices/packages": ["device", "packages"] };

// A held letter's place in a page while it is being assembled, and the size of
// the pieces its base64 is made in (a multiple of 3, so pieces join cleanly).
const PLACEHOLDER = "__held_letter__";
const CHUNK = 3 * 1024 * 1024;

const decoder = new TextDecoder();
const encoder = new TextEncoder();

export function holdFrom(env) {
  const raw = typeof env.HOLD_LETTERS_FROM === "string" ? env.HOLD_LETTERS_FROM.trim() : "";
  const value = /^\d{1,9}$/.test(raw) ? Number(raw) : DEFAULT_HOLD_FROM;
  return Math.min(Math.max(value, MIN_HOLD_FROM), MAX_HOLD_FROM);
}

// A bucket binding is an object with put, get and delete; anything else means
// no bucket, and nothing is held out.
export function bucketOf(env) {
  const bucket = env.LETTERS;
  const usable = bucket && ["put", "get", "delete"].every((name) => typeof bucket[name] === "function");
  return usable ? bucket : null;
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), (character) => character.charCodeAt(0));
}

function toBase64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
}

// The route a request is for, as the core sees its path.
function pathOf(url) {
  try {
    return new URL(url).pathname.replace(/\/+$/, "") || "/";
  } catch {
    return "";
  }
}

// The letter an upload carries: raw bytes, or the `bytes` of a JSON push.
function letterOf(contentType, body) {
  const json = (contentType ?? "").split(";")[0].trim().toLowerCase() === "application/json";
  if (!json) return body;
  return fromBase64(JSON.parse(decoder.decode(body)).bytes);
}

const reply = (status, object) => ({ status, body: encoder.encode(JSON.stringify(object)) });

export function createBlobRelay({ core, bucket, log = console }) {
  let tail = Promise.resolve();
  // One at a time, in the order asked. A failure does not break the chain.
  function serial(task) {
    const run = tail.then(task, task);
    tail = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  // The core's answer to a push, with the bytes stored first when it asked for
  // them. -> { status, body } (the body a Uint8Array of JSON).
  async function afterPush(table, request, answer) {
    if (answer.status < 200 || answer.status >= 300) return answer;
    let accepted;
    try {
      accepted = JSON.parse(decoder.decode(answer.body));
    } catch {
      return answer;
    }
    const held = accepted.blob;
    if (!held) return answer;
    const { blob: _internal, ...visible } = accepted;
    try {
      const letter = letterOf(request.contentType, request.body);
      const hash = String(held.key).split("/")[1];
      if (letter.length !== held.len || (await sha256Hex(letter)) !== hash) throw new Error("not the letter the core named");
      await bucket.put(held.key, letter, { sha256: hash });
      if (!core.blob_ready(table, accepted.id)) throw new Error("the row was no longer waiting");
    } catch (error) {
      log.error("relay: a held letter was not stored", error?.name);
      try {
        core.blob_abort(table, accepted.id);
      } catch (abortError) {
        log.error("relay: a held letter could not be dropped", abortError?.name);
      }
      return reply(503, { error: "letter storage unavailable, try again" });
    }
    return { status: answer.status, body: encoder.encode(JSON.stringify(visible)) };
  }

  // A page of letters with the bytes of every held one put back, or a refusal:
  // never a letter that is only its header. A held letter can be 16 MiB, so the
  // answer is built in pieces (a letter's base64 in 3 MiB steps, never one
  // string of the whole), because the isolate has 128 MB for the object, the
  // core's memory and everything in flight.
  async function afterPull(list, answer) {
    if (answer.status !== 200) return answer;
    let page;
    try {
      page = JSON.parse(decoder.decode(answer.body));
    } catch {
      return answer;
    }
    const entries = Array.isArray(page[list]) ? page[list] : [];
    if (!entries.some((entry) => entry.blob)) return answer;
    const held = new Map();
    for (const entry of entries) {
      if (!entry.blob) continue;
      const object = await bucket.get(entry.blob.key);
      const bytes = object ? new Uint8Array(await object.arrayBuffer()) : null;
      const hash = String(entry.blob.key).split("/")[1];
      if (!bytes || bytes.length !== entry.blob.len || (await sha256Hex(bytes)) !== hash) {
        log.error("relay: a held letter could not be read back");
        return reply(503, { error: "letter storage unavailable, try again" });
      }
      held.set(entry.id, bytes);
      entry.bytes = PLACEHOLDER;
      delete entry.blob;
    }
    // Serialise the page with a marker where each held letter goes, then split
    // on the markers and put the letters between the pieces.
    const text = JSON.stringify(page);
    const parts = [];
    let from = 0;
    for (const entry of entries) {
      const bytes = held.get(entry.id);
      if (!bytes) continue;
      const marker = `"${PLACEHOLDER}"`;
      const at = text.indexOf(marker, from);
      if (at < 0) return reply(503, { error: "letter storage unavailable, try again" });
      parts.push(encoder.encode(`${text.slice(from, at)}"`));
      for (let i = 0; i < bytes.length; i += CHUNK) parts.push(encoder.encode(toBase64(bytes.subarray(i, i + CHUNK))));
      parts.push(encoder.encode('"'));
      from = at + marker.length;
    }
    parts.push(encoder.encode(text.slice(from)));
    const size = parts.reduce((sum, part) => sum + part.length, 0);
    const body = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
      body.set(part, offset);
      offset += part.length;
    }
    return { status: answer.status, body };
  }

  // Runs the core for one request and finishes whatever the answer asks of the
  // bucket. `ask()` is the synchronous call into the core. Returns the answer
  // to send, or null when this route involves no held letters.
  async function around(request, ask) {
    const path = pathOf(request.url);
    if (request.method === "POST" && PUSH[path]) {
      return serial(async () => afterPush(PUSH[path], request, ask()));
    }
    if (request.method === "GET" && PULL[path]) {
      const [, list] = PULL[path];
      return afterPull(list, ask());
    }
    return null;
  }

  // Deletes the objects of letters whose rows are gone and no live row names.
  // Returns how many keys were swept.
  function sweep(limit = 500, rounds = 20) {
    return serial(async () => {
      let swept = 0;
      for (let round = 0; round < rounds; round += 1) {
        const keys = JSON.parse(core.blob_tombstones(limit));
        if (keys.length === 0) break;
        await bucket.delete(keys);
        core.blob_tombstones_done(JSON.stringify(keys));
        swept += keys.length;
        if (keys.length < limit) break;
      }
      return swept;
    });
  }

  return { around, sweep };
}
