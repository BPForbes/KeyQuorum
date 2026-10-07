import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { issuanceBlock, setupComplete, setupSteps } from "../public/setup-state.js";

const PUBLIC = join(fileURLToPath(new URL("..", import.meta.url)), "public");
const read = (name) => readFileSync(join(PUBLIC, name), "utf8");
const statuses = (overview) => Object.fromEntries(setupSteps(overview).map((s) => [s.id, s.status]));

const fresh = { identity_configured: false, operator_lock: false, operator_lock_pending: false };

test("a fresh relay is on step 2: the offline ceremony cannot be seen, the lock and issuing wait", () => {
  assert.deepEqual(statuses(fresh), { root: "offline", identity: "todo", lock: "waiting", issue: "waiting" });
  assert.equal(setupComplete(fresh), false);
});

test("an identity moves setup to the lock, and a lock waiting for confirmation is its own state", () => {
  assert.deepEqual(statuses({ ...fresh, identity_configured: true }), { root: "done", identity: "done", lock: "todo", issue: "waiting" });
  assert.deepEqual(statuses({ ...fresh, identity_configured: true, operator_lock_pending: true }), {
    root: "done",
    identity: "done",
    lock: "pending",
    issue: "waiting",
  });
});

test("with the identity and the confirmed lock setup is complete and issuing is next", () => {
  const ready = { identity_configured: true, operator_lock: true, operator_lock_pending: false };
  assert.deepEqual(statuses(ready), { root: "done", identity: "done", lock: "done", issue: "todo" });
  assert.equal(setupComplete(ready), true);
  assert.equal(issuanceBlock(ready), null);
});

test("issuing is blocked, and says which step is missing, until both exist", () => {
  assert.match(issuanceBlock(fresh), /no identity/);
  assert.match(issuanceBlock({ ...fresh, identity_configured: true }), /has not been created/);
  assert.match(issuanceBlock({ ...fresh, identity_configured: true, operator_lock_pending: true }), /not confirmed/);
  // A lock without an identity is still blocked: the relay cannot seal.
  assert.match(issuanceBlock({ ...fresh, operator_lock: true }), /no identity/);
  assert.equal(setupComplete({ ...fresh, operator_lock: true }), false);
});

test("anything that is not exactly true counts as missing, so a malformed overview never unblocks issuing", () => {
  for (const value of [undefined, null, "true", 1, {}]) {
    const overview = { identity_configured: value, operator_lock: value };
    assert.equal(setupComplete(overview), false);
    assert.ok(issuanceBlock(overview));
  }
});

test("the Overview shows the guide until setup is complete, and Issue keys stops before its form", () => {
  const overview = read("view-overview.js");
  assert.match(overview, /if \(!setupComplete\(o\)\) out\.push\(setupGuide\(o, createLockPanel/);
  const issue = read("view-issue.js");
  assert.match(issue, /issuanceBlock\(await get\("\/api\/overview"\)\)/);
  assert.ok(issue.indexOf("issuanceBlock") < issue.indexOf("const result = h("), "the check comes before the form is built");
});

test("the guide keeps the relay's identity apart from a personal .kqkey and puts no value in a command", () => {
  const guide = read("view-setup.js");
  assert.match(guide, /not a personal \.kqkey/);
  assert.match(guide, /Never reuse one person's file for another/);
  assert.match(guide, /never goes to this relay, this console or any Worker/);
  // Commands name files and variables, never a key, certificate or lock value.
  assert.doesNotMatch(guide, /kq[lq]_[A-Za-z0-9]/);
  assert.doesNotMatch(guide, /--licensee-key\b|KEYQUORUM_LICENSEE_KEY|KEYQUORUM_PROVIDER_ROOT_KEY\b/);
  assert.match(guide, /npx wrangler secret put RELAY_PRIVATE_KEY < relay\.key/);
  assert.match(guide, /base64 < provider\.kqcert \| tr -d '\\\\n' \| npx wrangler secret put RELAY_CERTIFICATE/);
});

test("the guide generates the relay's key pair before the certificate that names its public key", () => {
  const guide = read("view-setup.js");
  const generate = guide.indexOf("host identity generate");
  const certify = guide.indexOf("host certify");
  assert.ok(generate !== -1 && certify !== -1);
  assert.ok(generate < certify, "relay.pub must exist before host certify reads it");
  assert.equal(guide.split("host identity generate").length - 1, 1, "the key pair is made once");
});
