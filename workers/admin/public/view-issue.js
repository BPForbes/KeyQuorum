import { ApiError, api, get } from "./api.js";
import { bundleList } from "./bundles.js";
import { commit, operation } from "./confirm.js";
import { isHex, scopeLabel } from "./format.js";
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
  const submit = h("button", { type: "submit", text: "Issue sealed keys" });

  const form = h(
    "form",
    { novalidate: true },
    who,
    field("Licence", mode),
    newOnly,
    scopeSet,
    field("Their public key", publicKey, "Their slot's public key, 64 hexadecimal characters (they read it with keyquorum device list). Every file is sealed to it, so only they can open it."),
    field("Relay address", relayUrl, "The address they load these keys for."),
    field("Device id (optional)", deviceId, "32 hexadecimal characters. Binds the keys to one device container."),
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
    if (!isHex(publicKey.value, 64)) problems.push("Their public key must be 64 hexadecimal characters.");
    if (deviceId.value.trim() !== "" && !isHex(deviceId.value, 32)) problems.push("The device id must be 32 hexadecimal characters.");
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
      recipient_public_key: publicKey.value.trim(),
      relay_url: relayUrl.value.trim(),
      ...(deviceId.value.trim() ? { device_id: deviceId.value.trim() } : {}),
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
          bundleList(issued.bundles),
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
