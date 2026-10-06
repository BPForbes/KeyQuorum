// The console's pure helpers (admin/public/format.js), which run unchanged in
// the page and under Node.
import test from "node:test";
import assert from "node:assert/strict";
import {
  describeError,
  formatBytes,
  formatDate,
  formatTime,
  hourlyBars,
  isHex,
  plural,
  scopeLabel,
  shortId,
  stateKind,
  totals,
} from "../public/format.js";

test("times and dates are shown in UTC from either form the relay uses, and a gap as a dash", () => {
  assert.equal(formatTime("2026-10-06T12:34:56.789Z"), "2026-10-06 12:34 UTC");
  assert.equal(formatTime("2026-10-06 12:34:56"), "2026-10-06 12:34 UTC");
  assert.equal(formatTime(null), "—");
  assert.equal(formatTime(""), "—");
  assert.equal(formatTime("yesterday"), "yesterday");
  assert.equal(formatDate("2999-01-01 00:00:00"), "2999-01-01");
  assert.equal(formatDate(null), "no end");
});

test("ids are cut for a table cell and hex is checked by length", () => {
  assert.equal(shortId("abcdef0123456789", 6), "abcdef…");
  assert.equal(shortId("abc", 6), "abc");
  assert.equal(shortId(undefined), "");
  assert.ok(isHex("ab".repeat(32), 64));
  assert.ok(isHex(`  ${"AB".repeat(32)} `, 64));
  assert.ok(!isHex("ab".repeat(31), 64));
  assert.ok(!isHex("zz".repeat(32), 64));
  assert.ok(!isHex(undefined, 64));
});

test("counts and sizes read plainly", () => {
  assert.equal(plural(1, "key"), "1 key");
  assert.equal(plural(2, "key"), "2 keys");
  assert.equal(plural(0, "letter"), "0 letters");
  assert.equal(plural(2, "delivery", "deliveries"), "2 deliveries");
  assert.equal(formatBytes(12), "12 B");
  assert.equal(formatBytes(2048), "2.0 KiB");
  assert.equal(formatBytes(3 * 1024 * 1024), "3.0 MiB");
  assert.equal(formatBytes(-1), "—");
  assert.equal(formatBytes("x"), "—");
});

test("a scope has a plain name and an unknown one is shown as it is", () => {
  assert.equal(scopeLabel("inbox.push"), "Send letters");
  assert.equal(scopeLabel("device.pull"), "Receive device letters");
  assert.equal(scopeLabel("other"), "other");
  assert.equal(scopeLabel(null), "");
});

test("an error is told in words the operator can act on, never raw", () => {
  assert.match(describeError(401, { code: "lock_required" }), /needs the operator lock/);
  assert.match(describeError(401, { code: "lock_refused" }), /refused.*recorded/);
  assert.match(describeError(409, { code: "no_lock" }), /Overview/);
  assert.match(describeError(409, { code: "lock_exists" }), /cannot be shown again/);
  assert.match(describeError(503, { code: "no_identity" }), /no identity/);
  assert.equal(describeError(400, { error: "licence is malformed" }), "licence is malformed");
  assert.equal(describeError(503, null), "The relay is not available right now.");
  assert.equal(describeError(403, null), "Access was refused.");
  assert.equal(describeError(500, null), "The request failed (500).");
  assert.equal(describeError(500, { code: 7, error: 9 }), "The request failed (500).");
});

test("requests are summed by hour and by served and blocked", () => {
  const rows = [
    { hour: "2026-10-06T13:00:00Z", outcome: "ok", count: 4 },
    { hour: "2026-10-06T12:00:00Z", outcome: "ok", count: 2 },
    { hour: "2026-10-06T12:00:00Z", outcome: "scope", count: 1 },
    { hour: "2026-10-06T12:00:00Z", outcome: "revoked", count: 3 },
  ];
  assert.deepEqual(hourlyBars(rows), [
    { hour: "2026-10-06T12:00:00Z", served: 2, blocked: 4 },
    { hour: "2026-10-06T13:00:00Z", served: 4, blocked: 0 },
  ]);
  assert.deepEqual(totals(rows), { served: 6, blocked: 4 });
  assert.deepEqual(hourlyBars(undefined), []);
  assert.deepEqual(totals(null), { served: 0, blocked: 0 });
});

test("a state has a badge kind", () => {
  assert.equal(stateKind("live"), "good");
  assert.equal(stateKind("active"), "good");
  assert.equal(stateKind("revoked"), "bad");
  assert.equal(stateKind("voided"), "bad");
  assert.equal(stateKind("expired"), "warn");
  assert.equal(stateKind("ended"), "warn");
  assert.equal(stateKind("?"), "plain");
});
