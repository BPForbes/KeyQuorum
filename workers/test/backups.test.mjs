// The R2 side of sealed backups, against a fake core and a fake bucket, so it
// runs without the WebAssembly build. The core's half (the sealed snapshot and
// its restore) is tested in Rust (src/relay/backup/tests.rs).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { DEFAULT_EVERY_HOURS, DEFAULT_KEEP, DEFAULT_MAX_BYTES, MAX_MAX_BYTES, backupBucketOf, backupSettings, createBackups } from "../src/backups.js";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const quiet = { error() {} };
const RECIPIENT = "ab".repeat(32);
const settings = (extra = {}) => ({ enabled: true, recipient: RECIPIENT, everyHours: 24, keep: 3, maxBytes: DEFAULT_MAX_BYTES, ...extra });

function bucket({ failOn = null, failList = false } = {}) {
  const objects = new Map();
  const log = [];
  return {
    objects,
    log,
    async put(key, bytes, options) {
      log.push(["put", key]);
      if (failOn && key.includes(failOn)) throw new Error("R2 is down");
      assert.equal(options.sha256, sha(bytes), "the checksum travels with the put");
      objects.set(key, Uint8Array.from(bytes));
    },
    async get(key) {
      return objects.get(key) ?? null;
    },
    async delete(keys) {
      log.push(["delete", [].concat(keys).length]);
      for (const key of [].concat(keys)) objects.delete(key);
    },
    async list({ prefix = "", delimiter, cursor } = {}) {
      if (failList) throw new Error("R2 list failed");
      void cursor;
      const keys = [...objects.keys()].filter((key) => key.startsWith(prefix)).sort();
      if (delimiter) {
        const prefixes = new Set(keys.map((key) => prefix + key.slice(prefix.length).split(delimiter)[0] + delimiter));
        return { objects: [], delimitedPrefixes: [...prefixes], truncated: false };
      }
      return { objects: keys.map((key) => ({ key })), truncated: false };
    },
  };
}

function core({ id = "20261007120000123-aaaa1111", chunks = 2, tooLarge = false, begin } = {}) {
  const calls = [];
  return {
    calls,
    backup_begin(recipient, now, maxBytes) {
      calls.push(["begin", recipient, maxBytes]);
      if (begin) return begin();
      if (tooLarge) throw new Error("the relay database is too large to back up in one pass");
      return JSON.stringify({
        id,
        tables: 5,
        rows: 40,
        objects: Array.from({ length: chunks }, (_, i) => ({ name: `chunk-00000${i + 1}.kqbk`, bytes: 10 })),
        manifest: { name: "manifest.kqbk", bytes: 10 },
      });
    },
    backup_object(i) {
      return new Uint8Array(10).fill(i + 1);
    },
    backup_manifest() {
      return new Uint8Array(10).fill(99);
    },
    backup_end() {
      calls.push(["end"]);
    },
  };
}

function storage() {
  const map = new Map();
  return { map, get: async (k) => map.get(k), put: async (k, v) => void map.set(k, v) };
}

const relayTime = (date) => date.toISOString().replace("T", " ").replace("Z", "");
const make = (parts) => createBackups({ settings: settings(), relayTime, log: quiet, ...parts });

test("a backup uploads every chunk, then the manifest last, under its own id", async () => {
  const c = core();
  const r2 = bucket();
  const store = storage();
  const backups = make({ core: c, bucket: r2, storage: store });
  const result = await backups.run();
  assert.deepEqual(result, { id: "20261007120000123-aaaa1111" });
  assert.deepEqual(r2.log.filter((e) => e[0] === "put").map((e) => e[1]), [
    "backups/20261007120000123-aaaa1111/chunk-000001.kqbk",
    "backups/20261007120000123-aaaa1111/chunk-000002.kqbk",
    "backups/20261007120000123-aaaa1111/manifest.kqbk",
  ]);
  assert.deepEqual(c.calls.map((call) => call[0]), ["begin", "end"]);
  assert.equal(c.calls[0][1], RECIPIENT);
  assert.equal(store.map.get("backup:last").id, "20261007120000123-aaaa1111");
});

test("a failed upload leaves no manifest, ends the snapshot and keeps the earlier backups and the last-success record", async () => {
  const r2 = bucket({ failOn: "chunk-000002" });
  const store = storage();
  r2.objects.set("backups/20260101000000000-old00000/manifest.kqbk", new Uint8Array([1]));
  store.map.set("backup:last", { at: 1, id: "old" });
  const c = core();
  await assert.rejects(make({ core: c, bucket: r2, storage: store }).run());
  assert.ok(![...r2.objects.keys()].some((key) => key.endsWith("aaaa1111/manifest.kqbk")), "no manifest, so it never counts");
  assert.ok(r2.objects.has("backups/20260101000000000-old00000/manifest.kqbk"), "the earlier backup is untouched");
  assert.equal(c.calls.at(-1)[0], "end", "the snapshot is released");
  assert.equal(store.map.get("backup:last").id, "old");
});

test("a database too large for one pass is skipped and reported, and nothing is written", async () => {
  const r2 = bucket();
  const backups = make({ core: core({ tooLarge: true }), bucket: r2, storage: storage() });
  assert.deepEqual(await backups.run(), { skipped: "too_large" });
  assert.equal(r2.log.length, 0);
  const status = await backups.status();
  assert.match(status.last_skipped, /too large/);
});

test("another core failure is thrown and recorded, not mistaken for a skip", async () => {
  const backups = make({
    core: core({
      begin() {
        throw new Error("the relay has no identity to sign a backup with");
      },
    }),
    bucket: bucket(),
    storage: storage(),
  });
  await assert.rejects(backups.run());
  assert.equal((await backups.status()).last_failure, "Error");
});

test("a backup is due when none was made, or the last is older than the interval", async () => {
  const store = storage();
  let now = new Date("2026-10-07T12:00:00Z");
  const backups = make({ core: core(), bucket: bucket(), storage: store, clock: () => now });
  assert.equal(await backups.due(), true);
  await backups.run();
  assert.equal(await backups.due(), false);
  now = new Date("2026-10-08T11:59:00Z");
  assert.equal(await backups.due(), false);
  now = new Date("2026-10-08T12:00:00Z");
  assert.equal(await backups.due(), true);
});

test("only the newest few complete backups are kept, and stale unfinished ones are removed", async () => {
  const r2 = bucket();
  const complete = (id) => {
    r2.objects.set(`backups/${id}/chunk-000001.kqbk`, new Uint8Array([1]));
    r2.objects.set(`backups/${id}/manifest.kqbk`, new Uint8Array([2]));
  };
  for (const id of ["20260101000000000-a", "20260102000000000-b", "20260103000000000-c", "20260104000000000-d"]) complete(id);
  r2.objects.set("backups/20260105000000000-stale/chunk-000001.kqbk", new Uint8Array([1])); // no manifest, old
  r2.objects.set("backups/20261007115900000-fresh/chunk-000001.kqbk", new Uint8Array([1])); // no manifest, a minute old
  const now = new Date("2026-10-07T12:00:00Z");
  await make({ core: core(), bucket: r2, storage: storage(), clock: () => now }).run();
  const left = new Set([...r2.objects.keys()].map((key) => key.split("/")[1]));
  // keep = 3: the new one and the two newest older complete ones.
  assert.deepEqual([...left].sort(), ["20260103000000000-c", "20260104000000000-d", "20261007115900000-fresh", "20261007120000123-aaaa1111"]);
});

test("a failure to prune never fails a backup that was stored", async () => {
  const r2 = bucket();
  const store = storage();
  const original = r2.list;
  r2.list = async () => {
    throw new Error("R2 list failed");
  };
  const backups = make({ core: core(), bucket: r2, storage: store });
  assert.deepEqual(await backups.run(), { id: "20261007120000123-aaaa1111" });
  assert.equal((await backups.status()).last_prune_failure, "Error");
  r2.list = original;
});

test("two backups never run at once", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const r2 = bucket();
  const put = r2.put;
  r2.put = async (...args) => {
    await gate;
    return put.apply(r2, args);
  };
  const backups = make({ core: core(), bucket: r2, storage: storage() });
  const first = backups.run();
  assert.deepEqual(await backups.run(), { skipped: "already running" });
  release();
  await first;
});

test("backups are on only with a bucket and a valid backup key, and the knobs are clamped", () => {
  assert.equal(backupSettings({}).enabled, false);
  assert.match(backupSettings({}).reason, /BACKUP_RECIPIENT/);
  assert.equal(backupSettings({ BACKUP_RECIPIENT: "not hex" }).enabled, false);
  assert.equal(backupSettings({ BACKUP_RECIPIENT: "ab".repeat(31) }).enabled, false);
  const ok = backupSettings({ BACKUP_RECIPIENT: ` ${"AB".repeat(32)} ` });
  assert.equal(ok.enabled, true);
  assert.equal(ok.recipient, "ab".repeat(32));
  assert.equal(ok.everyHours, DEFAULT_EVERY_HOURS);
  assert.equal(ok.keep, DEFAULT_KEEP);
  assert.equal(ok.maxBytes, DEFAULT_MAX_BYTES);
  const tuned = backupSettings({ BACKUP_RECIPIENT: RECIPIENT, BACKUP_EVERY_HOURS: "6", BACKUP_KEEP: "30", BACKUP_MAX_BYTES: "999999999" });
  assert.deepEqual([tuned.everyHours, tuned.keep, tuned.maxBytes], [6, 30, MAX_MAX_BYTES]);
  assert.equal(backupSettings({ BACKUP_RECIPIENT: RECIPIENT, BACKUP_EVERY_HOURS: "0" }).everyHours, 1);
  assert.equal(backupSettings({ BACKUP_RECIPIENT: RECIPIENT, BACKUP_EVERY_HOURS: "x" }).everyHours, DEFAULT_EVERY_HOURS);
  assert.equal(backupBucketOf({}), null);
  assert.equal(backupBucketOf({ BACKUPS: { put() {}, get() {}, delete() {} } }), null, "list is needed too");
  const usable = bucket();
  assert.equal(backupBucketOf({ BACKUPS: usable }), usable);
});
