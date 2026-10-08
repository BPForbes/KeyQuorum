import { ApiError, api, get } from "./api.js";
import { bundleList, packageResult } from "./bundles.js";
import { commit, operation } from "./confirm.js";
import { MAX_ENROLLMENT_BYTES, PRIVATE_NAME_NOTE, classify, isPrivateName, readEnrollment, toBase64 } from "./files.js";
import { isHex, scopeLabel } from "./format.js";
import { stash } from "./stash.js";
import { issuanceBlock } from "./setup-state.js";
import { clear, field, h, lockField, notice, section } from "./ui.js";

const SCOPES = ["inbox.push", "inbox.pull", "device.push", "device.pull"];

export default async function issue(ctx) {
  // The relay refuses to seal or issue without an identity and the operator lock;
  // say which is missing before the operator fills in a form it would refuse.
  const blocked = issuanceBlock(await get("/api/overview"));
  if (blocked) {
    return section("Issue keys", notice("warn", blocked), h("p", {}, h("a", { href: "#overview", text: "Go to the setup steps" }), "."));
  }
  const wantedUser = Number(ctx.params.get("user"));
  const wantedLicence = Number(ctx.params.get("licence"));
  const known = Number.isInteger(wantedUser) && wantedUser > 0 ? await get(`/api/users/${wantedUser}/licenses`) : null;
  const active = (known?.licences ?? []).filter((l) => l.status === "active");

  const result = h("div", {});
  const status = h("div", { class: "status" });
  const lock = lockField();
  const op = operation();

  // Who: an existing user (from their page) or a new one.
  const name = h("input", { type: "text", maxlength: "200", autocomplete: "off" });
  const reference = h("input", { type: "text", maxlength: "100", autocomplete: "off" });
  const who = known
    ? h("p", {}, "For ", h("a", { href: `#user?id=${known.customer.id}`, text: known.customer.name }), ".")
    : h(
        "div",
        {},
        field("User's name", name, "The licensee's name, as it appears in the signed licence statement."),
        field("Your reference (optional)", reference, "A contract or account number of your own. Must be unique."),
      );

  const mode = h(
    "select",
    {},
    h("option", { value: "new", text: "A new licence" }),
    ...active.map((l) => h("option", { value: String(l.id), text: `Add to licence #${l.id} (statement ${l.version})` })),
  );
  if (active.some((l) => l.id === wantedLicence)) mode.value = String(wantedLicence);
  const terms = h("textarea", { rows: "4", maxlength: "8000" });
  const expires = h("input", { type: "date" });
  const newOnly = h(
    "div",
    {},
    field("Terms", terms, "Plain text carried inside every key's signed licence statement (seats, term, anything you agreed)."),
    field("Licence ends", expires, "Leave empty for no fixed end. Keys end when the licence does."),
  );
  const sync = () => {
    newOnly.hidden = mode.value !== "new";
  };
  mode.addEventListener("change", sync);

  const checks = SCOPES.map((scope) => ({
    scope,
    box: h("input", { type: "checkbox", id: `scope-${scope}`, checked: scope.startsWith("inbox.") }),
  }));
  const scopeSet = h(
    "fieldset",
    {},
    h("legend", { text: "What the keys allow" }),
    checks.map(({ scope, box }) => h("div", { class: "check" }, box, h("label", { for: box.id, text: `${scopeLabel(scope)} (${scope})` }))),
  );
  const publicKey = h("input", { type: "text", class: "mono", autocomplete: "off", spellcheck: "false", minlength: "64", maxlength: "64" });
  const relayUrl = h("input", { type: "url", autocomplete: "off", value: ctx.config.relayUrl ?? "" });
  const deviceId = h("input", { type: "text", class: "mono", autocomplete: "off", spellcheck: "false", maxlength: "32" });
  // How the client is identified: by the enrollment request they made with
  // `keyquorum setup --enroll-out` (recommended: it also binds their drive and
  // returns one package), or by their public key alone.
  const how = h(
    "select",
    {},
    h("option", { value: "enrollment", text: "Their enrollment request (recommended)" }),
    h("option", { value: "key", text: "Their public key only" }),
  );
  let enrolled = stash.take();
  const enrollFile = h("input", { type: "file", accept: ".kqreq" });
  const enrollSummary = h("div", { class: "status" });
  const confirmPrint = h("input", { type: "text", class: "mono", autocomplete: "off", spellcheck: "false", maxlength: "100" });
  const showEnrolled = () => {
    clear(enrollSummary);
    if (enrolled) {
      enrollSummary.append(
        h("p", {}, "Request ", h("code", { text: enrolled.name }), ": slot ", h("code", { text: enrolled.label }), ", device ", h("code", { text: enrolled.deviceId }), "."),
        h("p", {}, "Fingerprint: ", h("code", { text: enrolled.fingerprint })),
      );
    }
  };
  enrollFile.addEventListener("change", async () => {
    const file = enrollFile.files[0];
    enrolled = null;
    clear(enrollSummary);
    if (!file) return;
    if (isPrivateName(file.name)) {
      // Refused from the name alone; the file is never read into the page.
      enrollSummary.append(notice("bad", PRIVATE_NAME_NOTE));
      return;
    }
    if (file.size > MAX_ENROLLMENT_BYTES) {
      enrollSummary.append(notice("bad", "That is not an enrollment request: it is larger than one can be, so it was not read."));
      return;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (classify(bytes, file.name).kind !== "enrollment") {
      enrollSummary.append(notice("bad", "That is not an enrollment request."));
      return;
    }
    try {
      enrolled = { name: file.name, bytes, ...(await readEnrollment(bytes)) };
      showEnrolled();
    } catch (error) {
      enrollSummary.append(notice("bad", `Could not read it: ${error.message}.`));
    }
  });
  const enrollmentPanel = h(
    "div",
    {},
    field("Their enrollment request", enrollFile, "The .kqreq file they sent. It holds only public keys and their device id. You can also drop it in Files and choose Use to issue keys."),
    enrollSummary,
    field("The fingerprint they read out to you", confirmPrint, "Ask them to read it out by another channel, such as a call, and type it here. The keys are issued only if it matches the file."),
  );
  const keyPanel = h(
    "div",
    {},
    field("Their public key", publicKey, "Their slot's public key, 64 hexadecimal characters (they read it with keyquorum device list). Every file is sealed to it, so only they can open it."),
    field("Device id (optional)", deviceId, "32 hexadecimal characters. Binds the keys to one device container."),
  );
  const syncHow = () => {
    enrollmentPanel.hidden = how.value !== "enrollment";
    keyPanel.hidden = how.value !== "key";
  };
  how.addEventListener("change", syncHow);
  showEnrolled();

  const submit = h("button", { type: "submit", text: "Issue sealed keys" });

  const form = h(
    "form",
    { novalidate: true },
    who,
    field("Licence", mode),
    newOnly,
    scopeSet,
    field("Identify the client by", how),
    enrollmentPanel,
    keyPanel,
    field("Relay address", relayUrl, "The address they load these keys for."),
    lock.node,
    h("p", { class: "note" }, "Operation ", h("code", { text: op.id })),
    h("div", { class: "actions" }, submit),
    status,
  );

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clear(result);
    const problems = [];
    const scopes = checks.filter((c) => c.box.checked).map((c) => c.scope);
    if (scopes.length === 0) problems.push("Choose at least one thing the keys allow.");
    if (how.value === "enrollment") {
      if (!enrolled) problems.push("Choose their enrollment request.");
      if (!confirmPrint.value.trim()) problems.push("Type the fingerprint they read out to you.");
    } else {
      if (!isHex(publicKey.value, 64)) problems.push("Their public key must be 64 hexadecimal characters.");
      if (deviceId.value.trim() !== "" && !isHex(deviceId.value, 32)) problems.push("The device id must be 32 hexadecimal characters.");
    }
    if (!relayUrl.value.trim()) problems.push("Enter the relay address.");
    if (!known && !name.value.trim()) problems.push("Enter the user's name.");
    if (!lock.read()) problems.push("Enter the operator lock.");
    if (problems.length) {
      clear(status);
      status.append(notice("bad", problems.join(" ")));
      return;
    }
    const keyFields = {
      scopes,
      relay_url: relayUrl.value.trim(),
      ...(how.value === "enrollment"
        ? { enrollment: toBase64(enrolled.bytes), confirm_fingerprint: confirmPrint.value.trim() }
        : {
            recipient_public_key: publicKey.value.trim(),
            ...(deviceId.value.trim() ? { device_id: deviceId.value.trim() } : {}),
          }),
      ...(mode.value === "new"
        ? {
            ...(terms.value.trim() ? { terms: terms.value.trim() } : {}),
            ...(expires.value ? { expires_at: expires.value } : {}),
          }
        : { licence_id: Number(mode.value) }),
    };
    let customerId = known?.customer.id;
    let created = null;
    // A new user is recorded first, as its own operation, so each step can be
    // told apart and repeated safely. If the keys then fail, the user stays and
    // the keys are issued from their page.
    const issued = await commit(submit, status, op, async (id) => {
      if (customerId === undefined) {
        try {
          created = await api("POST", "/api/users", {
            body: { name: name.value.trim(), ...(reference.value.trim() ? { reference: reference.value.trim() } : {}) },
            lock: lock.read(),
            operationId: `${id}-user`.slice(0, 64),
          });
          customerId = created.customer.id;
        } catch (error) {
          // A repeat after an unknown outcome: the user was recorded the first
          // time, and the relay says which.
          const recorded = error instanceof ApiError && error.body?.code === "already_done" ? error.body.operation?.result?.customer_id : null;
          if (!Number.isInteger(recorded)) throw error;
          customerId = recorded;
          created = { customer: { id: recorded } };
        }
      }
      return api("POST", `/api/users/${customerId}/keys`, { body: keyFields, lock: lock.read(), operationId: id });
    });
    lock.clear();
    if (issued) {
      clear(result);
      result.append(
        section(
          `Licence #${issued.licence.id} for ${issued.customer.name}`,
          issued.package ? packageResult(issued) : bundleList(issued.bundles),
          h("div", { class: "actions" }, h("a", { class: "button", href: `#user?id=${issued.customer.id}`, text: "Open the user's page" })),
        ),
      );
      result.scrollIntoView({ block: "nearest" });
    } else if (customerId !== undefined && known === null && created) {
      status.append(
        notice("warn", `The user was recorded (#${customerId}) but the keys were not issued. Open their page to issue them.`),
        h("a", { class: "button", href: `#user?id=${customerId}`, text: "Open the user's page" }),
      );
    }
  });

  sync();
  syncHow();
  return h(
    "div",
    {},
    section(
      "Issue a licence and its keys",
      h("p", { class: "note", text: "The user never sees this console. You issue the keys here, download the sealed files, and send them to the user." }),
      form,
    ),
    result,
  );
}
