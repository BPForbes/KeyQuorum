import test from "node:test";
import assert from "node:assert/strict";
import { adminMount, relayMount, stripMount } from "../src/mount.js";

test("the relay's mount is /relay or /relay/<name>, and unset is /relay", () => {
  assert.equal(relayMount(undefined), "/relay");
  assert.equal(relayMount(""), "/relay");
  assert.equal(relayMount("/relay"), "/relay");
  assert.equal(relayMount("/relay/staging-user"), "/relay/staging-user");
  for (const value of ["/", "relay", "/relay/", "/Relay", "/relay/A", "/relay/a/b", "/relay/a_b", "/relay/-a", "/relay/a-", "/other", " /relay", 1, {}, []]) {
    assert.equal(relayMount(value), null, String(value));
  }
});

test("a mount may not take a name the production relay answers at /relay/<name>", () => {
  for (const name of ["inbox", "keycheck", "provider-identity", "audit", "trees", "devices", "health", "ready", "assets"]) {
    assert.equal(relayMount(`/relay/${name}`), null, name);
    assert.equal(adminMount(`/relay/${name}`), null, name);
  }
  assert.equal(relayMount("/relay/inbox-staging"), "/relay/inbox-staging");
});

test("the console's mount is /relay/<name> or empty, never /relay, and unset is empty", () => {
  assert.equal(adminMount(undefined), "");
  assert.equal(adminMount(""), "");
  assert.equal(adminMount("/relay/staging-admin"), "/relay/staging-admin");
  for (const value of ["/", "/relay", "/relay/", "/relay/a/b", "/admin", "relay/admin", 1, {}]) {
    assert.equal(adminMount(value), null, String(value));
  }
});

test("a path is under a mount only on the raw path, and the mount alone is a redirect to its slash", () => {
  assert.deepEqual(stripMount("/relay/inbox", "/relay"), { path: "/inbox" });
  assert.deepEqual(stripMount("/relay/", "/relay"), { path: "/" });
  assert.deepEqual(stripMount("/relay", "/relay"), { redirect: "/relay/" });
  assert.deepEqual(stripMount("/relay/staging-user/inbox", "/relay/staging-user"), { path: "/inbox" });
  assert.deepEqual(stripMount("/anything", ""), { path: "/anything" });
  for (const [path, mount] of [
    ["/relayx", "/relay"],
    ["/relayx/inbox", "/relay"],
    ["/%72elay/inbox", "/relay"],
    ["/RELAY/inbox", "/relay"],
    ["/relay%2Finbox", "/relay"],
    ["/relay/staging-userx/inbox", "/relay/staging-user"],
    ["/relay/inbox", "/relay/staging-user"],
    ["/", "/relay"],
    ["", "/relay"],
  ]) {
    assert.equal(stripMount(path, mount), null, `${path} under ${mount}`);
  }
});
