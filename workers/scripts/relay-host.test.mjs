import test from "node:test";
import assert from "node:assert/strict";
import { relayHost } from "./relay-host.mjs";

test("a plain https URL gives its lowercase hostname", () => {
  assert.equal(relayHost("https://keyquorum.dev/relay"), "keyquorum.dev");
  assert.equal(relayHost("https://relay.example.com/relay"), "relay.example.com");
  assert.equal(relayHost("https://Relay.Example.COM/relay/"), "relay.example.com");
  assert.equal(relayHost("https://relay.example.com:8443/relay"), "relay.example.com");
  assert.equal(relayHost("  https://relay.example.com/relay  "), "relay.example.com");
  assert.equal(relayHost("https://relay.example.com./relay"), "relay.example.com");
  assert.equal(relayHost("https://staging.example.co.uk/relay"), "staging.example.co.uk");
});

test("a URL that is not under /relay is refused, since the Worker serves nothing else", () => {
  for (const value of [
    "https://keyquorum.dev",
    "https://keyquorum.dev/",
    "https://keyquorum.dev/health",
    "https://keyquorum.dev/relayx",
    "https://keyquorum.dev/relay/inbox",
    "https://keyquorum.dev/other/relay",
    "https://keyquorum.dev/relay?x=1",
    "https://keyquorum.dev/relay#x",
  ]) {
    assert.equal(relayHost(value), null, value);
  }
});

test("anything that could widen the served set, or is not a real hostname, is refused", () => {
  for (const value of [
    "",
    undefined,
    "relay.example.com",
    "http://relay.example.com/relay",
    "https://*.example.com/relay",
    "https://*/relay",
    "*",
    "https://a.example.com,b.example.com/relay",
    "https://user:pass@relay.example.com/relay",
    "https://user@relay.example.com/relay",
    "https://localhost/relay",
    "https://relay/relay",
    "https://203.0.113.9/relay",
    "https://[2001:db8::1]/relay",
    "https://-bad.example.com/relay",
    "https://bad-.example.com/relay",
    "https://exa mple.com/relay",
    "ftp://relay.example.com/relay",
  ]) {
    assert.equal(relayHost(value), null, String(value));
  }
});

test("an over-long hostname is refused without being matched, and a long valid one is kept", () => {
  const label = "a".repeat(63);
  assert.equal(relayHost(`https://${label}.${label}.${label}.example.com/relay`), `${label}.${label}.${label}.example.com`);
  assert.equal(relayHost(`https://${`${label}.`.repeat(5)}example.com/relay`), null);
  assert.equal(relayHost(`https://${"a-".repeat(2000)}a.example.com/relay`), null);
});
