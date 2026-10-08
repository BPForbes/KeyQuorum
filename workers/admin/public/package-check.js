// What the console can say about a .kqpkg, and what to run to install it
// (issue #108). The check is the crate's own `package::public::verify`,
// compiled into the console's WebAssembly (`verify_package`): the signature,
// every component hash, the purpose, the validity window, the signer and the
// certificate, against the root this relay pins, and that every sealed part
// is sealed to one recipient. Until it passes, a package is only its public
// framing, and the page says "unverified".
//
// The console installs nothing. Installing writes keys into a drive's slot
// and a personal store (or, for recovery, a relay key onto a host), which a
// browser page cannot reach safely, so every supported install is a native
// command, shown here for the operator to hand on or run. Nothing is
// downloaded or run for them, nothing is uploaded, and nothing is stored.
//
// DOM-free so a test can run every branch.

import { utcText } from "./provision.js";

export const NO_INSTALL =
  "This console never installs a package: installing writes keys to a drive's slot and a personal store (or a relay key onto a provider host), which a browser page cannot safely reach. Use the command below on the machine that holds them.";

// A file name as one shell word.
export function shellWord(name) {
  const text = String(name ?? "");
  return /^[A-Za-z0-9._\/-]+$/.test(text) ? text : `'${text.replace(/'/g, "'\\''")}'`;
}

// The native command that installs a package of `purpose`, or null when there
// is nothing to install.
export function handoff(purpose, name) {
  const file = shellWord(name);
  switch (purpose) {
    case "client_setup":
    case "client_update":
      return {
        who: "the client, on the computer with their drive",
        commands: [`keyquorum setup ${file} --device DRIVE --label NAME`, `keyquorum setup ${file} --device DRIVE --label NAME --yes`],
        note: "The first shows the plan and writes nothing; the second installs it. Several packages can be given together. Their sealed keys and steps open only with the client's slot, so they are checked there.",
      };
    case "provider_recovery":
      return {
        who: "the operator, offline on the provider host",
        commands: [`keyquorum host recovery install ${file} --recipient-key recovery.key --out DIR`, `keyquorum host recovery install ${file} --recipient-key recovery.key --out DIR --yes`],
        note: "It carries the relay key sealed to the operator's recovery key: never upload it, and delete it once installed. Installing restores files only; setting Worker secrets is a separate step.",
      };
    default:
      return null;
  }
}

/**
 * -> { state: "verified" | "unverified" | "refused", reason, checked, handoff }
 * `load` gives the WebAssembly's functions (or throws where it cannot run);
 * `pinnedRoot` is the relay's `identity_check.pinned_root`.
 */
export async function checkPackage({ bytes, name, pinnedRoot, load, now = new Date() }) {
  if (typeof pinnedRoot !== "string" || !/^[0-9a-f]{64}$/.test(pinnedRoot)) {
    return { state: "unverified", reason: "This relay pins no root (its PROVIDER_ROOT deploy variable is not set), so nothing here can be verified. The native command verifies it against the root it was built with.", checked: null, handoff: null };
  }
  let verifier;
  try {
    verifier = (await load()).verify_package;
    if (typeof verifier !== "function") throw new Error("no verifier");
  } catch {
    return { state: "unverified", reason: "This browser could not run the verifier (WebAssembly). Verify it with the native command instead, which checks everything before it writes anything.", checked: null, handoff: null };
  }
  let checked;
  try {
    checked = JSON.parse(verifier(bytes, pinnedRoot, utcText(now)));
  } catch (error) {
    return { state: "refused", reason: String(error?.message ?? error), checked: null, handoff: null };
  }
  return { state: "verified", reason: null, checked, handoff: handoff(checked.purpose, name) };
}
