import test from "node:test";
import assert from "node:assert/strict";
import { relayHost } from "./relay-host.mjs";

test("a plain https URL gives its lowercase hostname", () => {
  assert.equal(relayHost("https://relay.example.com"), "relay.example.com");
  assert.equal(relayHost("https://Relay.Example.COM/"), "relay.example.com");
  assert.equal(relayHost("https://relay.example.com/health?x=1"), "relay.example.com");
  assert.equal(relayHost("https://relay.example.com:8443"), "relay.example.com");
  assert.equal(relayHost("  https://relay.example.com  "), "relay.example.com");
  assert.equal(relayHost("https://relay.example.com."), "relay.example.com");
  assert.equal(relayHost("https://relay-staging.example.co.uk"), "relay-staging.example.co.uk");
});

test("anything that could widen the served set, or is not a real hostname, is refused", () => {
  for (const value of [
    "",
    undefined,
    "relay.example.com",
    "http://relay.example.com",
    "https://*.example.com",
    "https://*",
    "*",
    "https://a.example.com,b.example.com",
    "https://user:pass@relay.example.com",
    "https://user@relay.example.com",
    "https://localhost",
    "https://relay",
    "https://203.0.113.9",
    "https://[2001:db8::1]",
    "https://-bad.example.com",
    "https://bad-.example.com",
    "https://exa mple.com",
    "ftp://relay.example.com",
  ]) {
    assert.equal(relayHost(value), null, String(value));
  }
});

test("an over-long hostname is refused without being matched, and a long valid one is kept", () => {
  const label = "a".repeat(63);
  assert.equal(relayHost(`https://${label}.${label}.${label}.example.com`), `${label}.${label}.${label}.example.com`);
  assert.equal(relayHost(`https://${`${label}.`.repeat(5)}example.com`), null);
  assert.equal(relayHost(`https://${"a-".repeat(2000)}a.example.com`), null);
});
