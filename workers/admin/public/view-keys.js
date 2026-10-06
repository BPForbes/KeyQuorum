import { api, errorText, get } from "./api.js";
import { commit, operation } from "./confirm.js";
import { formatTime, scopeLabel, shortId, stateKind } from "./format.js";
import { keyActions } from "./key-actions.js";
import { badge, busy, clear, field, h, lockField, notice, section, table } from "./ui.js";

export default async function keys(ctx) {
  const state = h(
    "select",
    {},
    ["all", "live", "revoked", "expired"].map((v) => h("option", { value: v, text: v === "all" ? "Any state" : v })),
  );
  const assignment = h(
    "select",
    {},
    h("option", { value: "all", text: "Assigned or not" }),
    h("option", { value: "unassigned", text: "Not assigned to any user" }),
  );
  if (ctx.params.get("assignment") === "unassigned") assignment.value = "unassigned";
  const list = h("div", {});
  const more = h("div", { class: "actions" });
  const host = h("div", {});
  const shown = h("div", {});
  const status = h("div", { class: "status" });
  let rows = [];
  let cursor = null;
  const overview = await get("/api/overview");

  function assignForm(key) {
    const licenceId = h("input", { type: "number", min: "1", step: "1", required: true, "aria-label": "Licence id" });
    const lock = lockField();
    const op = operation();
    const out = h("div", { class: "status" });
    const save = h("button", { type: "submit", text: "Assign" });
    const form = h(
      "form",
      { class: "confirm", novalidate: true },
      h("h3", { text: `Assign key #${key.id} to a licence` }),
      h("p", { class: "note", text: "Only the user whose licence this is should hold the key. It is never reassigned afterwards. Find the licence id on the user's page." }),
      field("Licence id", licenceId),
      lock.node,
      h("div", { class: "actions" }, save),
      out,
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!licenceId.value || !lock.read()) {
        clear(out);
        out.append(notice("bad", "Enter the licence id and the operator lock."));
        return;
      }
      const done = await commit(save, out, op, (id) =>
        api("POST", `/api/keys/${key.id}/assign`, { body: { licence_id: Number(licenceId.value) }, lock: lock.read(), operationId: id }),
      );
      lock.clear();
      if (done) {
        clear(host);
        await load(true);
      }
    });
    clear(host);
    host.append(form);
    licenceId.focus();
  }

  function draw() {
    clear(list);
    list.append(
      table(
        [
          { label: "Key", cell: (k) => `#${k.id}` },
          { label: "User", cell: (k) => (k.customer_id ? h("a", { href: `#user?id=${k.customer_id}`, text: k.customer }) : h("em", { text: "not assigned" })) },
          { label: "Allows", cell: (k) => scopeLabel(k.scope) },
          { label: "Works?", cell: (k) => badge(k.state, stateKind(k.state)) },
          { label: "Licence", cell: (k) => (k.licence_id ? `#${k.licence_id}${k.licence_version ? ` v${k.licence_version}` : ""}` : "—") },
          { label: "Sealed to", cell: (k) => (k.delivery ? h("code", { text: shortId(k.delivery.recipient_fingerprint) }) : "—") },
          { label: "Ends", cell: (k) => formatTime(k.expires_at) },
          { label: "Last used", cell: (k) => formatTime(k.last_used_at) },
          {
            label: "",
            cell: (k) =>
              h(
                "div",
                { class: "actions tight" },
                !k.assigned && k.state !== "revoked" && k.scope !== "admin"
                  ? h("button", { type: "button", text: "Assign", "aria-label": `Assign key ${k.id}`, on: { click: () => assignForm(k) } })
                  : null,
                keyActions({ key: k, host, shown, changed: () => load(true) }),
              ),
          },
        ],
        rows,
        "No keys match.",
      ),
    );
    clear(more);
    if (cursor !== null) {
      const button = h("button", { type: "button", class: "quiet", text: "Load more" });
      button.addEventListener("click", () => load(false, button));
      more.append(button);
    }
  }

  async function load(reset, button) {
    const page = await busy(
      button ?? first,
      status,
      () =>
        get("/api/keys", {
          state: state.value === "all" ? "" : state.value,
          assignment: assignment.value === "all" ? "" : assignment.value,
          before: reset ? undefined : cursor,
          limit: 25,
        }),
      errorText,
    );
    if (!page) return;
    rows = reset ? page.keys : rows.concat(page.keys);
    cursor = page.next_before;
    draw();
  }

  const first = h("button", { type: "submit", text: "Show" });
  const filters = h("form", { class: "filters" }, field("State", state), field("Assignment", assignment), h("div", { class: "actions" }, first));
  filters.addEventListener("submit", (event) => {
    event.preventDefault();
    load(true);
  });

  await load(true);
  return h(
    "div",
    {},
    shown,
    section(
      "Keys",
      overview.keys.unassigned > 0
        ? notice("warn", `${overview.keys.unassigned} key(s) are not assigned to any user. Assigning one links it to a licence, once, by your choice; nothing is guessed.`)
        : null,
      filters,
      list,
      more,
      status,
      host,
    ),
  );
}
