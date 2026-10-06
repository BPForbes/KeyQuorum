#!/usr/bin/env node
// Prints the hostname of the relay from the GitHub environment variable
// RELAY_URL, for the deploy job to pass to the Worker as ALLOWED_HOSTS:
//
//   node scripts/relay-host.mjs https://relay.example.com
//
// Exits 1, printing nothing to stdout, when the value is not a plain https URL
// with a real hostname. A wildcard, a list, a credential, an IP address or a
// single-label name is never accepted, so a mistake in the variable cannot widen
// the set of hosts the Worker serves.
import { fileURLToPath } from "node:url";

const LABEL = "[a-z0-9]([a-z0-9-]*[a-z0-9])?";
const HOSTNAME = new RegExp(`^${LABEL}(\\.${LABEL})+$`);

export function relayHost(value) {
  let url;
  try {
    url = new URL(String(value).trim());
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  // A hostname is at most 253 characters; check before the pattern runs.
  if (host.length > 253 || !HOSTNAME.test(host) || /^[0-9.]+$/.test(host)) return null;
  return host;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const host = relayHost(process.argv[2] ?? "");
  if (host === null) {
    console.error("error: RELAY_URL is not an https URL with a hostname");
    process.exit(1);
  }
  console.log(host);
}
