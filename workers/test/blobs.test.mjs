// The R2 side of held letters, against a fake core and a fake bucket, so it
// runs without the WebAssembly build. The core's own half is tested in Rust
// (src/relay/blob/tests.rs); the two meet over the five calls faked here.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { DEFAULT_HOLD_FROM, MIN_HOLD_FROM, bucketOf, createBlobRelay, holdFrom } from "../src/blobs.js";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const quiet = { error() {} };
const text = (bytes) => JSON.parse(new TextDecoder().decode(bytes));
const json = (status, object) => ({ status, body: new TextEncoder().encode(JSON.stringify(object)) });

function bucket({ failPut = false, failDelete = false, gate = null } = {}) {
  const objects = new Map();
  const calls = [];
  return {
    objects,
    calls,
    async put(key, bytes, options) {
      calls.push(["put", key]);
      if (gate) await gate;
      if (failPut) throw new Error("R2 is down");
      assert.equal(options.sha256, key.split("/")[1], "the checksum travels with the put");
      objects.set(key, Uint8Array.from(bytes));
    },
    async get(key) {
      const bytes = objects.get(key);
      return bytes ? { arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) } : null;
    },
    async delete(keys) {
      calls.push(["delete", keys]);
      if (failDelete) throw new Error("R2 is down");
      for (const key of [].concat(keys)) objects.delete(key);
    },
  };
}

function core({ tombstones = [] } = {}) {
  const calls = [];
  return {
    calls,
    pending: tombstones,
    blob_ready(table, id) {
      calls.push(["ready", table, id]);
      return true;
    },
    blob_abort(table, id) {
      calls.push(["abort", table, id]);
      return true;
    },
    blob_tombstones() {
      calls.push(["tombstones"]);
      return JSON.stringify(this.pending);
    },
    blob_tombstones_done(keys) {
      calls.push(["done", JSON.parse(keys)]);
      this.pending = [];
      return JSON.parse(keys).length;
    },
  };
}

const letter = (size = 5000) => Uint8Array.from({ length: size }, (_, i) => (i * 7) % 251);
const held = (bytes, table = "inbox") => ({ key: `${table}/${sha(bytes)}`, len: bytes.length });
const push = (bytes, contentType = "application/octet-stream") => ({
  method: "POST",
  url: "https://relay.test/inbox",
  contentType,
  body: contentType.startsWith("application/json") ? new TextEncoder().encode(JSON.stringify({ bytes: b64(bytes) })) : bytes,
});

test("a held letter is stored in the bucket before its row is ready, and the client never sees the reference", async () => {
  const c = core();
  const r2 = bucket();
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  const bytes = letter();
  const answer = await relay.around(push(bytes), () => json(201, { id: 9, recipient_fingerprint: "ab", blob: held(bytes) }));
  assert.equal(answer.status, 201);
  assert.deepEqual(text(answer.body), { id: 9, recipient_fingerprint: "ab" });
  assert.deepEqual(r2.objects.get(`inbox/${sha(bytes)}`), bytes);
  assert.deepEqual(c.calls, [["ready", "inbox", 9]]);
  assert.deepEqual(r2.calls.map((call) => call[0]), ["put"]);
});

test("a JSON push carries its letter as base64 and is stored the same", async () => {
  const c = core();
  const r2 = bucket();
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  const bytes = letter(6000);
  const answer = await relay.around(push(bytes, "application/json; charset=utf-8"), () => json(201, { id: 3, recipient_fingerprint: "ab", blob: held(bytes) }));
  assert.equal(answer.status, 201);
  assert.deepEqual(r2.objects.get(`inbox/${sha(bytes)}`), bytes);
});

test("nothing is written to the bucket for a request the core refused", async () => {
  const c = core();
  const r2 = bucket();
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  for (const status of [400, 401, 403, 413, 429, 500]) {
    const bytes = letter();
    const answer = await relay.around(push(bytes), () => json(status, { error: "refused", blob: held(bytes) }));
    assert.equal(answer.status, status);
  }
  assert.equal(r2.calls.length, 0, "no put before authorisation");
  assert.deepEqual(c.calls, []);
});

test("a bucket that refuses the put drops the row and answers 503 so the sender retries", async () => {
  const c = core();
  const r2 = bucket({ failPut: true });
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  const bytes = letter();
  const answer = await relay.around(push(bytes), () => json(201, { id: 4, recipient_fingerprint: "ab", blob: held(bytes) }));
  assert.equal(answer.status, 503);
  assert.deepEqual(c.calls, [["abort", "inbox", 4]]);
  assert.equal(r2.objects.size, 0);
});

test("bytes that are not the letter the core named are never stored", async () => {
  const c = core();
  const r2 = bucket();
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  const bytes = letter();
  const other = letter(5001);
  for (const named of [held(other), { ...held(bytes), len: bytes.length + 1 }]) {
    const answer = await relay.around(push(bytes), () => json(201, { id: 5, recipient_fingerprint: "ab", blob: named }));
    assert.equal(answer.status, 503);
  }
  assert.equal(r2.calls.length, 0);
  assert.deepEqual(c.calls, [["abort", "inbox", 5], ["abort", "inbox", 5]]);
});

test("a push the core stored whole, and a duplicate, pass through unchanged", async () => {
  const relay = createBlobRelay({ core: core(), bucket: bucket(), log: quiet });
  const answer = await relay.around(push(letter(100)), () => json(201, { id: 1, recipient_fingerprint: "ab" }));
  assert.deepEqual(text(answer.body), { id: 1, recipient_fingerprint: "ab" });
  const duplicate = await relay.around(push(letter(100)), () => json(200, { id: 1, recipient_fingerprint: "ab" }));
  assert.equal(duplicate.status, 200);
});

test("a device push is held under its own prefix", async () => {
  const c = core();
  const r2 = bucket();
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  const bytes = letter();
  const request = { ...push(bytes), url: "https://relay.test/devices/packages" };
  await relay.around(request, () => json(201, { id: 2, recipient_fingerprint: "ab", blob: held(bytes, "device") }));
  assert.ok(r2.objects.has(`device/${sha(bytes)}`));
  assert.deepEqual(c.calls, [["ready", "device", 2]]);
});

const pull = (url = "https://relay.test/inbox?after=0") => ({ method: "GET", url, contentType: undefined, body: new Uint8Array() });

test("a pulled page has every held letter's bytes put back and no reference left", async () => {
  const r2 = bucket();
  const relay = createBlobRelay({ core: core(), bucket: r2, log: quiet });
  const bytes = letter(9000);
  r2.objects.set(`inbox/${sha(bytes)}`, bytes);
  const inline = letter(80);
  const answer = await relay.around(pull(), () =>
    json(200, {
      envelopes: [
        { id: 1, recipient_fingerprint: "ab", bytes: b64(inline) },
        { id: 2, recipient_fingerprint: "ab", bytes: b64(bytes.subarray(0, 42)), blob: held(bytes) },
      ],
      trees: [],
    }),
  );
  const page = text(answer.body);
  assert.equal(answer.status, 200);
  assert.equal(page.envelopes[0].bytes, b64(inline));
  assert.equal(page.envelopes[1].bytes, b64(bytes));
  assert.ok(page.envelopes.every((entry) => !("blob" in entry)));
  assert.deepEqual(page.trees, []);
});

test("a held letter that cannot be read back is a 503, never a header-only letter", async () => {
  const bytes = letter(9000);
  const entry = { id: 2, recipient_fingerprint: "ab", bytes: b64(bytes.subarray(0, 42)), blob: held(bytes) };
  const serve = () => json(200, { envelopes: [entry] });

  const missing = createBlobRelay({ core: core(), bucket: bucket(), log: quiet });
  assert.equal((await missing.around(pull(), serve)).status, 503);

  const tampered = bucket();
  tampered.objects.set(`inbox/${sha(bytes)}`, Uint8Array.from(bytes, (b, i) => (i === 100 ? b ^ 1 : b)));
  assert.equal((await createBlobRelay({ core: core(), bucket: tampered, log: quiet }).around(pull(), serve)).status, 503);

  const short = bucket();
  short.objects.set(`inbox/${sha(bytes)}`, bytes.subarray(0, 100));
  assert.equal((await createBlobRelay({ core: core(), bucket: short, log: quiet }).around(pull(), serve)).status, 503);
});

test("a pull with no held letter, an error answer and an unrelated route are left alone", async () => {
  const relay = createBlobRelay({ core: core(), bucket: bucket(), log: quiet });
  const page = json(200, { envelopes: [{ id: 1, recipient_fingerprint: "ab", bytes: "AAAA" }] });
  assert.equal(await relay.around(pull(), () => page), page);
  const refused = json(401, { error: "no" });
  assert.equal(await relay.around(pull(), () => refused), refused);
  assert.equal(await relay.around({ method: "GET", url: "https://relay.test/health", body: new Uint8Array() }, () => page), null);
  assert.equal(await relay.around({ method: "PUT", url: "https://relay.test/inbox", body: new Uint8Array() }, () => page), null);
});

test("the sweep deletes the objects of gone letters and only then forgets them", async () => {
  const c = core({ tombstones: ["inbox/aa", "device/bb"] });
  const r2 = bucket();
  r2.objects.set("inbox/aa", new Uint8Array([1]));
  r2.objects.set("device/bb", new Uint8Array([2]));
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  assert.equal(await relay.sweep(), 2);
  assert.equal(r2.objects.size, 0);
  assert.deepEqual(c.calls.map((call) => call[0]), ["tombstones", "done"]);
  assert.equal(await relay.sweep(), 0, "nothing left to do");
});

test("a bucket that cannot delete leaves the tombstones for the next sweep", async () => {
  const c = core({ tombstones: ["inbox/aa"] });
  const relay = createBlobRelay({ core: c, bucket: bucket({ failDelete: true }), log: quiet });
  await assert.rejects(relay.sweep());
  assert.deepEqual(c.calls.map((call) => call[0]), ["tombstones"], "not forgotten");
  assert.deepEqual(await createBlobRelay({ core: c, bucket: bucket(), log: quiet }).sweep(), 1);
});

test("pushes and the sweep never interleave, so a letter stored anew cannot meet its own old delete", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const c = core({ tombstones: ["inbox/old"] });
  const r2 = bucket({ gate });
  const relay = createBlobRelay({ core: c, bucket: r2, log: quiet });
  const bytes = letter();
  const first = relay.around(push(bytes), () => json(201, { id: 1, recipient_fingerprint: "ab", blob: held(bytes) }));
  const sweeping = relay.sweep();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(r2.calls.map((call) => call[0]), ["put"], "the sweep waits for the push in flight");
  release();
  await first;
  await sweeping;
  assert.deepEqual(r2.calls.map((call) => call[0]), ["put", "delete"]);
});

test("the threshold and the bucket come from non-secret settings and fall back safely", () => {
  assert.equal(holdFrom({}), DEFAULT_HOLD_FROM);
  assert.equal(holdFrom({ HOLD_LETTERS_FROM: "131072" }), 131072);
  assert.equal(holdFrom({ HOLD_LETTERS_FROM: "10" }), MIN_HOLD_FROM);
  for (const junk of ["", "abc", "-5", "1e9", "99999999999"]) assert.equal(holdFrom({ HOLD_LETTERS_FROM: junk }), DEFAULT_HOLD_FROM, junk);
  assert.equal(bucketOf({}), null);
  assert.equal(bucketOf({ LETTERS: {} }), null);
  assert.equal(bucketOf({ LETTERS: "not a bucket" }), null);
  const usable = bucket();
  assert.equal(bucketOf({ LETTERS: usable }), usable);
});
