import { api } from "./api.js";
import { commit, operation } from "./confirm.js";
import { MAX_FILE_BYTES, classify, fromBase64, readEnrollment, readPackage, refusedName } from "./files.js";
import { formatTime } from "./format.js";
import { NO_INSTALL, checkPackage } from "./package-check.js";
import { loadProvisioner } from "./provision.js";
import { stash } from "./stash.js";
import { badge, clear, h, notice, section } from "./ui.js";
import { downloadBytes, makeZip } from "./zip.js";

const README = `KeyQuorum provider package
USR_TYPE: PROVIDER

provider.kqpkg   A signed, public package (purpose: provider_info) holding this
                 relay's certificate. It holds no key of any kind.
provider.kqcert  This relay's certificate, signed by the KeyQuorum provider root.

Everything here is public. Check the certificate against the provider root you
pinned; this archive is not stored by the console or the relay.
`;

function providerPackage() {
  const status = h("div", { class: "status" });
  const button = h("button", { type: "button", text: "Download the provider package (zip)" });
  const op = operation();
  button.addEventListener("click", async () => {
    const result = await commit(button, status, op, () => api("POST", "/api/provider-package", { body: {} }));
    if (!result) return;
    const files = [
      { name: "provider.kqpkg", bytes: fromBase64(result.package.package_base64) },
      ...result.files.map((file) => ({ name: file.name, bytes: fromBase64(file.base64) })),
      { name: "README.txt", bytes: new TextEncoder().encode(README) },
    ];
    downloadBytes("keyquorum-provider.zip", makeZip(files), "application/zip");
    status.append(notice("good", "Downloaded. Every file in it is public; nothing secret is in the archive."));
  });
  return section(
    "Provider package",
    h("p", {}, badge("USR_TYPE: PROVIDER", "plain"), " The relay's public files, signed, as one zip."),
    h("p", { class: "note", text: "It holds the relay's certificate and a signed provider package. No private key is in it or can be put in it, and no operator lock is needed. The relay key and the root key stay where they are." }),
    h("div", { class: "actions" }, button),
    status,
  );
}

// The relay's pinned root (`identity_check.pinned_root`), asked once per page.
// Only an answer is kept: a failed request is forgotten and thrown, so the next
// file asks again and a failure is never reported as "no root pinned".
let pinned = null;
function pinnedRoot() {
  pinned ??= api("GET", "/api/overview").then(
    (overview) => overview?.identity_check?.pinned_root ?? null,
    (error) => {
      pinned = null;
      throw error;
    },
  );
  return pinned;
}

const STATES = {
  verified: ["Verified", "good"],
  unverified: ["Unverified", "plain"],
  refused: ["Refused", "bad"],
};

// A dropped package: its public framing, then the core's verdict against the
// relay's pinned root, then the native command that installs it.
async function packageBody(bytes, name) {
  const read = readPackage(bytes);
  let root;
  try {
    root = await pinnedRoot();
  } catch {
    return [
      h("p", {}, badge("Unverified", "plain"), " ", badge(`USR_TYPE: ${read.userType}`, "plain"), " ", h("code", { text: read.purpose })),
      notice("warn", "Could not read the root this relay pins, so the package was not verified. Try the file again."),
    ];
  }
  const result = await checkPackage({ bytes, name, pinnedRoot: root, load: () => loadProvisioner() });
  const [label, tone] = STATES[result.state];
  const body = [
    h("p", {}, badge(label, tone), " ", badge(`USR_TYPE: ${read.userType}`, "plain"), " ", h("code", { text: read.purpose })),
    h("p", { text: `Valid until ${formatTime(new Date(read.expiresAt * 1000).toISOString())}. Holds: ${read.components.map((c) => c.kind).join(", ")}.` }),
  ];
  if (result.state === "verified") {
    const c = result.checked;
    body.push(
      h("p", { text: `Signed by the ${c.signed_by === "root" ? "provider root" : `relay of ${c.provider_id} (serial ${c.serial})`}, checked against the root this relay pins; certificate valid until ${c.certificate_expires_at}.` }),
      c.sealed_to ? h("p", {}, "Sealed to ", h("code", { text: c.sealed_to }), ". What is sealed is checked only where it is opened.") : null,
    );
  } else {
    body.push(notice(result.state === "refused" ? "bad" : "warn", result.state === "refused" ? `It did not verify: ${result.reason}` : `${result.reason} What is shown above is the public framing only.`));
  }
  if (result.handoff) {
    body.push(
      h("p", { class: "note", text: NO_INSTALL }),
      h("p", { text: `Run by ${result.handoff.who}:` }),
      ...result.handoff.commands.map((command) => h("pre", {}, h("code", { text: command }))),
      h("p", { class: "note", text: result.handoff.note }),
    );
  } else if (result.state === "verified") {
    body.push(h("p", { class: "note", text: "Provider information: public, nothing to install." }));
  }
  return body;
}

async function describe(file) {
  const refused = refusedName(file.name);
  if (refused) {
    // Refused from the name alone: the file is never read into the page.
    return { name: file.name, found: refused, body: [notice("bad", refused.note)] };
  }
  if (file.size > MAX_FILE_BYTES) {
    return { name: file.name, found: classify(new Uint8Array(0), file.name), body: [notice("bad", "The file is too large for this console, so it was not read.")] };
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const found = classify(bytes, file.name);
  const body = [];
  if (!found.accepted) {
    body.push(notice("bad", found.note));
    return { name: file.name, found, body };
  }
  if (found.note) body.push(h("p", { class: "note", text: found.note }));
  try {
    if (found.kind === "enrollment") {
      const read = await readEnrollment(bytes);
      body.push(
        h("p", {}, "Slot ", h("code", { text: read.label }), ", device ", h("code", { text: read.deviceId }), "."),
        h("p", {}, "Fingerprint: ", h("code", { text: read.fingerprint })),
        h("p", { class: "note", text: "The client reads their own fingerprint out to you by another channel. Issue only if it matches." }),
      );
      found.use = () => stash.put({ name: file.name, bytes, ...read });
    } else if (found.kind === "package") {
      body.push(...(await packageBody(bytes, file.name)));
    } else if (found.visibility === "public") {
      body.push(h("p", { class: "note", text: "Public: nothing secret is in it. Keeping public files on the relay for the account is not built yet, so this console does not store it." }));
    }
  } catch (error) {
    body.push(notice("bad", `Could not read it: ${error.message}.`));
  }
  return { name: file.name, found, body };
}

function fileTool(ctx) {
  const list = h("div", { class: "files" });
  const input = h("input", { type: "file", multiple: true, hidden: true });
  const zone = h(
    "div",
    { class: "drop", tabindex: "0", role: "button", "aria-label": "Choose files, or drop them here" },
    h("strong", { text: "Drop files here, or choose them" }),
    h("div", { class: "note", text: "Files are read in this page and go nowhere until you take an action on one." }),
  );

  async function take(files) {
    for (const file of files) {
      const { name, found, body } = await describe(file);
      const actions = [];
      if (found.use) {
        actions.push(
          h("button", {
            type: "button",
            text: "Use to issue keys",
            on: { click: () => { found.use(); ctx.navigate("issue"); } },
          }),
        );
      }
      list.prepend(
        h(
          "div",
          { class: "card" },
          h("div", { class: "card-title" }, h("code", { text: name }), " ", badge(found.label, found.accepted ? "plain" : "bad")),
          body,
          actions.length ? h("div", { class: "actions" }, actions) : null,
        ),
      );
    }
  }

  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.click();
    }
  });
  zone.addEventListener("dragover", (event) => event.preventDefault());
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    take([...(event.dataTransfer?.files ?? [])]);
  });
  input.addEventListener("change", () => {
    take([...input.files]);
    input.value = "";
  });
  const clearButton = h("button", { type: "button", text: "Clear the list", on: { click: () => clear(list) } });

  return section(
    "File tool",
    h("p", { class: "note", text: "Say what a file is, and act on it. Enrollment requests (.kqreq) go to Issue keys; packages are verified against the pinned root and shown with the native command that installs them; certificates and sealed keys are described. Files named like private keys are refused unread, key-looking content is refused once read, and anything this console does not handle is refused." }),
    zone,
    input,
    h("div", { class: "actions" }, clearButton),
    list,
  );
}

export default async function files(ctx) {
  return h("div", {}, providerPackage(), fileTool(ctx));
}
