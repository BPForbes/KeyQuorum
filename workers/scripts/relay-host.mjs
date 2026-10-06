#!/usr/bin/env node
// Prints the hostname of the relay from the GitHub environment variable
// RELAY_URL, for the deploy job to pass to the Worker as ALLOWED_HOSTS:
//
//   node scripts/relay-host.mjs https://example.com/relay
//   node scripts/relay-host.mjs --mount https://example.com/relay/staging-user
//   node scripts/relay-host.mjs --admin-mount https://example.com/relay/staging-admin
//
// The variable is the relay's URL as a client is given it: its path is the
// mount the public Worker serves under (src/mount.js: `/relay`, or
// `/relay/<name>` for a staging relay on the same host), so a URL with any
// other path is refused here, before a deploy, rather than found by the smoke
// test after. The first form prints the host (for ALLOWED_HOSTS), `--mount` the
// path (for MOUNT_PATH), and `--admin-mount` the console's mount from ADMIN_URL
// (`/relay/<name>`, or an empty line for a hostname of its own). Exits 1, printing nothing to stdout, when the value is not a plain https URL
// with a real hostname. A wildcard, a list, a credential, an IP address or a
// single-label name is never accepted, so a mistake in the variable cannot widen
// the set of hosts the Worker serves.
import { fileURLToPath } from "node:url";
import { adminMount, mountOfUrl, relayMount } from "../src/mount.js";

const LABEL = "[a-z0-9]([a-z0-9-]*[a-z0-9])?";
const HOSTNAME = new RegExp(`^${LABEL}(\\.${LABEL})+$`);

// The relay's mount in a URL: `/relay` or `/relay/<name>`, never empty.
export function relayMountOf(value) {
  return mountOfUrl(value, (path) => (path === "" ? null : relayMount(path)));
}

// The console's mount in a URL: `/relay/<name>`, or "" for a hostname of its own.
export function adminMountOf(value) {
  return mountOfUrl(value, adminMount);
}

export function relayHost(value) {
  let url;
  try {
    url = new URL(String(value).trim());
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") return null;
  if (relayMountOf(value) === null) return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  // A hostname is at most 253 characters; check before the pattern runs.
  if (host.length > 253 || !HOSTNAME.test(host) || /^[0-9.]+$/.test(host)) return null;
  return host;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const mode = args[0]?.startsWith("--") ? args.shift() : "--host";
  const value = args[0] ?? "";
  if (mode === "--admin-mount") {
    const mount = adminMountOf(value);
    if (mount === null) {
      console.error("error: ADMIN_URL is not an https URL whose path is empty or /relay/<name>");
      process.exit(1);
    }
    console.log(mount);
  } else if (mode === "--mount") {
    const mount = relayHost(value) === null ? null : relayMountOf(value);
    if (mount === null) {
      console.error("error: RELAY_URL is not an https URL with a hostname and the path /relay or /relay/<name>");
      process.exit(1);
    }
    console.log(mount);
  } else {
    const host = relayHost(value);
    if (host === null) {
      console.error("error: RELAY_URL is not an https URL with a hostname and the path /relay or /relay/<name>");
      process.exit(1);
    }
    console.log(host);
  }
}
