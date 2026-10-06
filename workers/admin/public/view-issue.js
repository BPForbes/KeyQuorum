import { errorText, operate } from "./api.js";
import { bundleList } from "./bundles.js";
import { isHex, scopeLabel } from "./format.js";
import { busy, clear, field, h, lockField, notice, section } from "./ui.js";

const SCOPES = ["inbox.push", "inbox.pull", "device.push", "device.pull"];

export default async function issue(ctx) {
  const { licences } = await operate("licences");
  const active = licences.filter((l) => l.status === "active");
  const wanted = Number(ctx.params.get("licence"));

  const root = h("div", {});
  const status = h("div", { class: "status" });
  const result = h("div", {});

  const mode = h(
    "select",
    {},
    h("option", { value: "new", text: "A new licence" }),
    ...active.map((l) => h("option", { value: String(l.id), text: `Add to licence #${l.id} for ${l.client}` })),
  );
  if (active.some((l) => l.id === wanted)) mode.value = String(wanted);

  const client = h("input", { type: "text", maxlength: "200", autocomplete: "off", required: true });
  const terms = h("textarea", { rows: "4", maxlength: "8000" });
  const expires = h("input", { type: "date" });
  const publicKey = h("input", {
    type: "text",
    class: "mono",
    autocomplete: "off",
    spellcheck: "false",
    required: true,
    minlength: "64",
    maxlength: "64",
  });
  const relayUrl = h("input", { type: "url", autocomplete: "off", required: true, value: ctx.config.relayUrl ?? "" });
  const deviceId = h("input", { type: "text", class: "mono", autocomplete: "off", spellcheck: "false", maxlength: "32" });
  const checks = SCOPES.map((scope) => ({
    scope,
    box: h("input", { type: "checkbox", id: `scope-${scope}`, checked: scope.startsWith("inbox.") }),
  }));
  const lock = lockField();
  const submit = h("button", { type: "submit", text: "Issue sealed keys" });

  const newOnly = [
    field("Client", client, "The licensee's name, as it appears in the signed licence statement."),
    field("Terms", terms, "Plain text carried inside every key's signed licence statement (seats, term, anything you agreed)."),
    field("Licence ends", expires, "Leave empty for no fixed end. Keys expire when the licence does."),
  ];
  const newFields = h("div", {}, newOnly);
  const syncMode = () => {
    const isNew = mode.value === "new";
    newFields.hidden = !isNew;
    client.required = isNew;
  };
  mode.addEventListener("change", syncMode);

  const scopeSet = h(
    "fieldset",
    {},
    h("legend", { text: "What the keys allow" }),
    checks.map(({ scope, box }) =>
      h("div", { class: "check" }, box, h("label", { for: box.id, text: `${scopeLabel(scope)} (${scope})` })),
    ),
  );

  const form = h(
    "form",
    { novalidate: true },
    field("Licence", mode),
    newFields,
    scopeSet,
    field("Client's public key", publicKey, "The client's slot public key, 64 hexadecimal characters (they read it with keyquorum device list). Every bundle is sealed to it, so only they can open it."),
    field("Relay address", relayUrl, "The address the client loads these keys for."),
    field("Device id (optional)", deviceId, "32 hexadecimal characters. Binds the keys to one device container."),
    lock.node,
    h("div", { class: "actions" }, submit),
    status,
  );

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clear(result);
    const problems = [];
    const scopes = checks.filter((c) => c.box.checked).map((c) => c.scope);
    if (scopes.length === 0) problems.push("Choose at least one thing the keys allow.");
    if (!isHex(publicKey.value, 64)) problems.push("The client's public key must be 64 hexadecimal characters.");
    if (deviceId.value.trim() !== "" && !isHex(deviceId.value, 32)) problems.push("The device id must be 32 hexadecimal characters.");
    if (!relayUrl.value.trim()) problems.push("Enter the relay address.");
    if (mode.value === "new" && !client.value.trim()) problems.push("Enter the client's name.");
    if (!lock.read()) problems.push("Enter the operator lock.");
    if (problems.length) {
      clear(status);
      status.append(notice("bad", problems.join(" ")));
      return;
    }
    const fields = {
      scopes,
      recipient_public_key: publicKey.value.trim(),
      relay_url: relayUrl.value.trim(),
      ...(deviceId.value.trim() ? { device_id: deviceId.value.trim() } : {}),
      ...(mode.value === "new"
        ? {
            client: client.value.trim(),
            ...(terms.value.trim() ? { terms: terms.value.trim() } : {}),
            ...(expires.value ? { expires_at: expires.value } : {}),
          }
        : { licence_id: Number(mode.value) }),
    };
    const issued = await busy(submit, status, () => operate("issue", fields, lock.read()), errorText);
    lock.clear();
    if (issued) {
      clear(result);
      result.append(
        section(`Licence #${issued.licence.id} for ${issued.licence.client}`, bundleList(issued.bundles)),
      );
      result.scrollIntoView({ block: "nearest" });
    }
  });

  syncMode();
  root.append(
    section(
      "Issue a licence and its keys",
      h("p", { class: "note", text: "The client never sees this console. You issue the keys here, download the sealed files, and send them to the client." }),
      form,
    ),
    result,
  );
  return root;
}
