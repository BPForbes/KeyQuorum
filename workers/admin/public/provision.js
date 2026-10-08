// Making the provider's identity in this browser: the root keypair, the relay
// keypair, the certificate the root signs for the relay and the public
// provider package, by the crate's own `provider::provision` compiled to
// WebAssembly (provision-wasm/, built by workers/scripts/build-console-wasm.mjs
// from the `console` feature, nothing else exported). Everything is made in
// the page and handed to the operator as downloads: nothing here is sent to the
// admin Worker, the relay or anywhere else, nothing is kept in storage, and the
// private keys live only in the result object until `forget` drops it.
//
// The DOM-free parts (what the form accepts, what the result becomes, what
// comes next) are here so a test can run them; the panel itself is in
// view-setup.js.

import { makeZip } from "./zip.js";

export const SERIAL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const MAX_PROVIDER_ID = 200;

// The private files, by name, so the page can say which downloads must be
// kept off any shared folder and never uploaded.
export const PRIVATE_FILES = ["root.key", "relay.key"];

// What the form must say for the certificate; -> [] when it is good.
export function problems({ providerId, serial, expiresAt }, today = new Date()) {
  const out = [];
  const id = String(providerId ?? "").trim();
  if (id === "") out.push("A provider id is needed: the name every client will see for this relay.");
  else if (id.length > MAX_PROVIDER_ID) out.push(`The provider id is longer than ${MAX_PROVIDER_ID} characters.`);
  const s = String(serial ?? "").trim();
  if (!SERIAL_PATTERN.test(s)) out.push("A serial is needed: letters, digits, dots, dashes or underscores, up to 64, so the certificate can be revoked by it later.");
  const date = String(expiresAt ?? "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) out.push("An expiry date is needed.");
  else if (date <= today.toISOString().slice(0, 10)) out.push("The expiry must be a day after today.");
  return out;
}

// A time as the relay's certificates write it (`YYYY-MM-DD HH:MM:SS`, UTC).
export function utcText(date) {
  return date.toISOString().slice(0, 19).replace("T", " ");
}

// A `<input type="date">` value as a certificate expiry, at the end of that day.
export function expiryText(dateValue) {
  return `${dateValue} 23:59:59`;
}

const HEX_64 = /^[0-9a-f]{64}$/;

function fromBase64(text) {
  return Uint8Array.from(atob(text), (character) => character.charCodeAt(0));
}

// The result the WebAssembly returns (a JSON string), as the files
// `keyquorum host provision` would have written: the same names, the same
// bytes. Refused unless every part has the shape it must.
export function filesOf(json) {
  const made = JSON.parse(json);
  for (const name of ["root_key", "root_pub", "relay_key", "relay_pub"]) {
    if (typeof made[name] !== "string" || !HEX_64.test(made[name])) throw new Error(`${name} is not a 64-character hex key`);
  }
  const text = (hex) => new TextEncoder().encode(`${hex}\n`);
  return {
    rootPub: made.root_pub,
    files: [
      { name: "root.key", bytes: text(made.root_key), private: true },
      { name: "relay.key", bytes: text(made.relay_key), private: true },
      { name: "root.pub", bytes: text(made.root_pub), private: false },
      { name: "relay.pub", bytes: text(made.relay_pub), private: false },
      { name: "provider.kqcert", bytes: fromBase64(made.certificate_base64), private: false },
      { name: "provider-info.kqpkg", bytes: fromBase64(made.package_base64), private: false },
    ],
  };
}

// The public files as one zip, for a single download.
export function publicZip(files, date = new Date()) {
  return makeZip(
    files.filter((file) => !file.private).map((file) => ({ name: file.name, bytes: file.bytes })),
    date,
  );
}

// What to do with the downloads, in order, naming files and variables and
// never a value: the root for the deploy variable, the two secrets, the rebuild
// the clients need.
export function nextSteps(rootPub) {
  return [
    `Pin the root on the relay: set the GitHub environment variable PROVIDER_ROOT (cloudflare-staging, then cloudflare-production) to the value shown above (${rootPub.length} hex characters, the contents of root.pub; it is public), then run the workers deploy. The relay reads it as a deploy variable, never from a file in the repository.`,
    "Set the relay's two secrets from the downloaded files, in the workers/ directory (add --env staging for the staging relay): npx wrangler secret put RELAY_PRIVATE_KEY < relay.key, then base64 < provider.kqcert | tr -d '\\n' | npx wrangler secret put RELAY_CERTIFICATE.",
    "Pin the root in the clients you build: build them with KEYQUORUM_PROVIDER_ROOT set to the same value, or with root.pub copied to provider-root.pub beside Cargo.toml (git-ignored; never commit it). Every official client trusts only the root compiled in; a certificate under any other root is refused.",
    "Keep root.key offline (it signs certificates and revocations, nothing else) and delete relay.key from this computer once the secret is set. Neither was sent anywhere by this page.",
  ];
}

// Loads the WebAssembly once, from the console's own files.
let provisioner = null;
export async function loadProvisioner(importer = (path) => import(path)) {
  if (!provisioner) {
    const module = await importer("./provision-wasm/keyquorum_console.js");
    await module.default();
    provisioner = module.provision_identity;
  }
  return provisioner;
}
