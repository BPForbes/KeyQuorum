// What a file is, from its own bytes, before the console does anything with it.
// Pure: no page, no network. Nothing here verifies a signature; a package is
// verified by the core's own verifier (package-check.js), and anything else by
// the relay core when an action is taken. This only reads the public framing so the
// operator is told what they are holding and which actions apply, and refuses
// to go on with anything that is, or looks like, private key material.

export const MAX_FILE_BYTES = 16 * 1024 * 1024;

const MAGIC = {
  KQRQ: { kind: "enrollment", label: "Enrollment request (.kqreq)", visibility: "public", action: "issue" },
  KQPK: { kind: "package", label: "KeyQuorum package (.kqpkg)", visibility: "inspect", action: "inspect" },
  KQPC: { kind: "certificate", label: "Relay certificate (.kqcert)", visibility: "public", action: "inspect" },
  KQRL: { kind: "revocation", label: "Revocation list (.kqrl)", visibility: "public", action: "inspect" },
  KQPL: { kind: "policy", label: "Hardware-authority policy (.kqpolicy)", visibility: "public", action: "inspect" },
};

// Recognised, but not something this console handles.
const NOT_HERE = {
  KQTF: "a tracked file",
  KQTX: "a device transfer, which can carry slot secrets",
  KQHS: "a history snapshot",
  KQBS: "a bridge signature",
  KQBN: "a bridge eviction notice",
  KQDV: "a device descriptor",
  KQST: "a slot token",
};

const PRIVATE_NAME = /(\.key|\.skey|\.pem|\.secret|\.token|\.p12|\.pfx)$/i;

// A signed enrollment request is far smaller than this; a bigger file is not one.
export const MAX_ENROLLMENT_BYTES = 1024;

export const PRIVATE_NAME_NOTE =
  "This looks like private key material. It is never uploaded to this console: nothing here needs it, and it stays on the machine that holds it. Nothing was read or sent.";

// A file named like a private key is refused from its name alone, before any
// of its bytes are read.
export function isPrivateName(name) {
  return PRIVATE_NAME.test(String(name ?? ""));
}

// What a file refused from its name alone reports, or null for any other name.
export function refusedName(name) {
  return isPrivateName(name)
    ? { accepted: false, kind: "refused", label: "Private key material", visibility: null, action: null, note: PRIVATE_NAME_NOTE }
    : null;
}

export function magicOf(bytes) {
  return bytes.length >= 4 ? String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) : "";
}

function textOf(bytes) {
  if (bytes.length > 4096) return "";
  let text = "";
  for (const byte of bytes) {
    if (byte > 126 || (byte < 32 && byte !== 10 && byte !== 13 && byte !== 9)) return "";
    text += String.fromCharCode(byte);
  }
  return text.trim();
}

// What a pasted or saved key looks like: 64 hex characters, or 32 bytes of
// base64. A relay key, root key or slot key is never to reach this console.
export function looksLikeRawKey(bytes) {
  const text = textOf(bytes);
  return /^[0-9a-fA-F]{64}$/.test(text) || /^[A-Za-z0-9+/]{43}=$/.test(text) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text);
}

// -> { accepted, kind, label, visibility: "public" | "sealed" | "inspect" | null, action, note }
export function classify(bytes, name = "") {
  const refuse = (note, label = "Not accepted") => ({ accepted: false, kind: "refused", label, visibility: null, action: null, note });
  if (bytes.length === 0) return refuse("The file is empty.");
  if (bytes.length > MAX_FILE_BYTES) return refuse("The file is too large for this console.");
  if (isPrivateName(name) || looksLikeRawKey(bytes)) {
    return refuse(PRIVATE_NAME_NOTE, "Private key material");
  }
  const magic = magicOf(bytes);
  if (magic === "KQXB" || magic === "KQPB") {
    const kind = bytes[5];
    if (magic === "KQXB" && kind === 4) {
      return { accepted: true, kind: "sealed_key", label: "Sealed API key (.kqkey)", visibility: "sealed", action: "inspect", note: "Sealed to its recipient. It is not stored by the console." };
    }
    if (magic === "KQXB" && kind === 6) {
      return { accepted: true, kind: "setup_manifest", label: "Sealed setup steps (.kqxb, type 6)", visibility: "sealed", action: "inspect", note: "Sealed to its recipient and signed by the relay. It is not stored by the console." };
    }
    if (magic === "KQXB" && kind === 5) {
      return refuse("This is a provider recovery payload: the relay key, sealed to an operator. It travels only inside a recovery package and is installed only by `keyquorum host recovery install`, offline. It was not kept or sent.", "Sealed recovery payload, not handled here");
    }
    if (magic === "KQPB" && kind === 20) {
      return { accepted: true, kind: "sealed_key_letter", label: "Sealed API key letter (.kqpb, kind 20)", visibility: "sealed", action: "inspect", note: "Sealed to its recipient. It is not stored by the console." };
    }
    return refuse(`This is ${magic === "KQXB" ? "a sealed export bundle" : "a sealed letter"} this console does not handle. The relay carries letters; it cannot open them.`, "Sealed file, not handled here");
  }
  if (MAGIC[magic]) return { accepted: true, ...MAGIC[magic], note: "" };
  if (NOT_HERE[magic]) return refuse(`This is ${NOT_HERE[magic]}. This console does not handle it.`, "Not handled here");
  return refuse("The console does not recognise this file, so it does nothing with it.");
}

const PURPOSES = {
  1: ["client_setup", "CLIENT"],
  2: ["client_update", "CLIENT"],
  3: ["provider_info", "PROVIDER"],
  4: ["provider_recovery", "PROVIDER"],
};
const COMPONENTS = {
  1: "relay certificate",
  2: "revocation list",
  3: "hardware-authority policy",
  4: "sealed API key (.kqkey)",
  5: "sealed API key letter",
  6: "setup steps (sealed, signed)",
  7: "provider recovery payload (sealed to an operator)",
};

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const u64 = (view, at) => Number(view.getBigUint64(at, false));

// The public header of a package: purpose, whose it is (derived from the
// purpose, as the core does), validity and what it holds. Not verified.
export function readPackage(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 4 + 1 + 1 + 16 + 8 + 8 + 32 + 2 + 64 || magicOf(bytes) !== "KQPK" || bytes[4] !== 1) {
    throw new Error("not a version 1 KeyQuorum package");
  }
  const purpose = PURPOSES[bytes[5]];
  if (!purpose) throw new Error("unknown package purpose");
  const end = bytes.length - 64;
  let at = 4 + 1 + 1;
  const id = hex(bytes.subarray(at, at + 16));
  at += 16;
  const issuedAt = u64(view, at);
  const expiresAt = u64(view, at + 8);
  at += 16 + 32;
  const count = view.getUint16(at, false);
  at += 2;
  if (count > 16) throw new Error("too many components");
  const components = [];
  for (let i = 0; i < count; i += 1) {
    if (at + 1 + 32 + 4 > end) throw new Error("the package is cut short");
    const kind = bytes[at];
    const size = view.getUint32(at + 33, false);
    at += 37;
    if (at + size > end) throw new Error("the package is cut short");
    components.push({ kind: COMPONENTS[kind] ?? "unknown component", size });
    at += size;
  }
  if (at !== end) throw new Error("the package has trailing bytes");
  return { purpose: purpose[0], userType: purpose[1], id, issuedAt, expiresAt, components };
}

// An enrollment request's public fields and its fingerprint: the SHA-256 of
// everything before the signature, in groups of eight, the same value the
// client's `setup --enroll-out` prints. The client reads theirs out; the
// operator compares. The signature is verified by the relay when it is used.
export async function readEnrollment(bytes) {
  if (magicOf(bytes) !== "KQRQ" || bytes[4] !== 1 || bytes.length < 4 + 1 + 16 + 8 + 2 + 32 + 32 + 64 || bytes.length > MAX_ENROLLMENT_BYTES) {
    throw new Error("not a version 1 enrollment request");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const labelLength = view.getUint16(4 + 1 + 16 + 8, false);
  const labelAt = 4 + 1 + 16 + 8 + 2;
  if (labelAt + labelLength + 32 + 32 + 64 !== bytes.length || labelLength === 0) throw new Error("the enrollment request is malformed");
  const label = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(labelAt, labelAt + labelLength));
  const body = bytes.subarray(0, bytes.length - 64);
  const digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  return {
    label,
    deviceId: hex(bytes.subarray(5, 21)),
    fingerprint: digest.match(/.{8}/g).join(" "),
  };
}

export function toBase64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
}

export function fromBase64(text) {
  return Uint8Array.from(atob(text), (character) => character.charCodeAt(0));
}
