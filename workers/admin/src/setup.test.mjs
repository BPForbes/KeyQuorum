import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { identityState, issuanceBlock, setupComplete, setupSteps, untrustedReason } from "../public/setup-state.js";

const PUBLIC = join(fileURLToPath(new URL("..", import.meta.url)), "public");
const read = (name) => readFileSync(join(PUBLIC, name), "utf8");
const statuses = (overview) => Object.fromEntries(setupSteps(overview).map((s) => [s.id, s.status]));

const ROOT = "ab".repeat(32);
const missing = { identity_configured: false, identity_check: { state: "missing", pinned_root: ROOT }, operator_lock: false, operator_lock_pending: false };
const trusted = { ...missing, identity_configured: true, identity_check: { state: "trusted", pinned_root: ROOT } };
const untrusted = (reason) => ({ ...missing, identity_configured: true, identity_check: { state: "untrusted", reason, pinned_root: ROOT } });

test("a fresh relay is on step 2: the offline ceremony cannot be seen, the lock and issuing wait", () => {
  assert.deepEqual(statuses(missing), { root: "offline", identity: "todo", lock: "waiting", issue: "waiting" });
  assert.equal(setupComplete(missing), false);
});

test("secrets that are present but not trusted never mark the ceremony done", () => {
  for (const reason of ["certificate_not_signed_by_pinned_root", "certificate_expired", "capabilities_missing"]) {
    const o = untrusted(reason);
    assert.deepEqual(statuses(o), { root: "failed", identity: "waiting", lock: "waiting", issue: "waiting" }, reason);
    assert.equal(setupComplete({ ...o, operator_lock: true }), false, reason);
    assert.match(issuanceBlock({ ...o, operator_lock: true }), /not one clients will trust/, reason);
  }
});

test("a relay that pins no root fails step 1 with the variable to set, and step 2 still says whether the secrets exist", () => {
  const unpinned = { ...missing, identity_check: { state: "untrusted", reason: "no_pinned_root", pinned_root: null } };
  assert.deepEqual(statuses(unpinned), { root: "failed", identity: "todo", lock: "waiting", issue: "waiting" });
  assert.match(untrustedReason(unpinned), /PROVIDER_ROOT/);
  assert.deepEqual(statuses({ ...unpinned, identity_configured: true }), { root: "failed", identity: "waiting", lock: "waiting", issue: "waiting" });
  assert.equal(setupComplete({ ...unpinned, identity_configured: true, operator_lock: true }), false);
});

test("a key that does not match a good certificate fails step 2, not step 1", () => {
  const o = untrusted("key_does_not_match_certificate");
  assert.deepEqual(statuses(o), { root: "done", identity: "failed", lock: "waiting", issue: "waiting" });
  assert.match(issuanceBlock(o), /different key pairs/);
});

test("an overview from a core that does not report the check is unverified, never trusted", () => {
  const o = { identity_configured: true, operator_lock: true };
  assert.equal(identityState(o), "unverified");
  assert.equal(setupComplete(o), false);
  assert.match(issuanceBlock(o), /has not been checked/);
  assert.deepEqual(statuses(o), { root: "offline", identity: "waiting", lock: "done", issue: "waiting" });
});

test("a trusted identity moves setup to the lock, and a lock waiting for confirmation is its own state", () => {
  assert.deepEqual(statuses(trusted), { root: "done", identity: "done", lock: "todo", issue: "waiting" });
  assert.deepEqual(statuses({ ...trusted, operator_lock_pending: true }), { root: "done", identity: "done", lock: "pending", issue: "waiting" });
});

test("with a trusted identity and the confirmed lock setup is complete and issuing is next", () => {
  const ready = { ...trusted, operator_lock: true };
  assert.deepEqual(statuses(ready), { root: "done", identity: "done", lock: "done", issue: "todo" });
  assert.equal(setupComplete(ready), true);
  assert.equal(issuanceBlock(ready), null);
});

test("issuing is blocked, and says which step is missing, until all of it exists", () => {
  assert.match(issuanceBlock(missing), /no identity/);
  assert.match(issuanceBlock(trusted), /has not been created/);
  assert.match(issuanceBlock({ ...trusted, operator_lock_pending: true }), /not confirmed/);
  // A lock without a trusted identity is still blocked: clients would refuse what it seals.
  assert.match(issuanceBlock({ ...missing, operator_lock: true }), /no identity/);
  assert.equal(setupComplete({ ...missing, operator_lock: true }), false);
});

test("anything that is not exactly the trusted state counts as untrusted, so a malformed overview never unblocks issuing", () => {
  for (const value of [undefined, null, "trusted", 1, {}, { state: "TRUSTED" }, { state: "trusted " }]) {
    const overview = { identity_configured: true, identity_check: value, operator_lock: true };
    assert.equal(setupComplete(overview), false);
    assert.ok(issuanceBlock(overview));
  }
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
  assert.match(guide, /never goes to this relay, this console's Worker or any Worker/);
  // Commands name files and variables, never a key, certificate or lock value.
  assert.doesNotMatch(guide, /kq[lq]_[A-Za-z0-9]/);
  assert.doesNotMatch(guide, /--licensee-key\b|KEYQUORUM_LICENSEE_KEY|KEYQUORUM_PROVIDER_ROOT_KEY\b/);
  assert.match(guide, /npx wrangler secret put RELAY_PRIVATE_KEY < relay\.key/);
  assert.match(guide, /base64 < provider\.kqcert \| tr -d '\\\\n' \| npx wrangler secret put RELAY_CERTIFICATE/);
});

test("the guide makes the identity in the browser with the console's own WebAssembly, sends nothing, and names the private files", () => {
  const guide = read("view-setup.js");
  assert.match(guide, /loadProvisioner/);
  assert.match(guide, /nothing is sent anywhere/);
  assert.match(guide, /never upload them anywhere, this console included/);
  assert.doesNotMatch(guide, /\bapi\(|fetch\(/, "the generate panel calls no endpoint");
  const provision = read("provision.js");
  assert.match(provision, /import\("\.\/provision-wasm\/keyquorum_console\.js"\)|importer\("\.\/provision-wasm\/keyquorum_console\.js"\)/);
  assert.doesNotMatch(provision, /localStorage|sessionStorage|indexedDB|fetch\(/, "nothing is stored or sent");
  assert.match(provision, /PROVIDER_ROOT/);
});

test("the guide makes the whole identity with one provision run, and certifies under an existing root only after the relay key exists", () => {
  const guide = read("view-setup.js");
  const provision = guide.indexOf("host provision --out");
  const generate = guide.indexOf("host identity generate");
  const certify = guide.indexOf("host certify");
  assert.ok(provision !== -1 && generate !== -1 && certify !== -1);
  assert.ok(provision < certify, "the one-command path comes first");
  assert.ok(generate < certify, "relay.pub must exist before host certify reads it");
  assert.equal(guide.split("host provision").length - 1, 1, "the identity is made once");
  assert.match(guide, /both private keys are written owner-only and never printed/);
});

test("the guide tells the operator to pin the production root, shows the pinned key, and the setup text names no secret", () => {
  const guide = read("view-setup.js");
  assert.match(guide, /KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY/);
  assert.match(guide, /KEYQUORUM_PROVIDER_ROOT or a git-ignored provider-root\.pub/);
  assert.match(guide, /build the clients with the public half of your root/);
  assert.match(guide, /nothing is committed/);
  assert.match(guide, /This relay pins: /);
  assert.match(guide, /\[0-9a-f\]\{64\}/, "only a 64-character hex value is shown as the pinned root");
  assert.match(guide, /done here only when the relay confirms the certificate/);
});
