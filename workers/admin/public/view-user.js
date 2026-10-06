import { api, get } from "./api.js";
import { confirmPanel, commit, operation } from "./confirm.js";
import { formatDate, formatTime, plural, scopeLabel, stateKind, totals } from "./format.js";
import { keyActions } from "./key-actions.js";
import { badge, card, clear, empty, field, h, lockField, notice, section, table } from "./ui.js";

// What a licence's status means, said once, because it is easy to mistake for
// what a key may do.
const STATUS_NOTE =
  "A licence's status is your record of the agreement. Whether a key works is the key's own state, shown beside it: a key stops when it is revoked or reaches its end date, and revoking a licence revokes its keys.";

function statements(licence) {
  return h(
    "details",
    {},
    h("summary", { text: `Statements (${licence.versions.length})` }),
    ...licence.versions
      .slice()
      .reverse()
      .map((v) =>
        h(
          "div",
          { class: "statement" },
          h("strong", { text: `Statement ${v.version}` }),
          ` – ${formatTime(v.issued_at)}, ends ${formatDate(v.expires_at)}`,
          h("pre", { text: v.terms || "(no terms text)" }),
        ),
      ),
    h("p", { class: "note", text: "Each statement is kept as it was. A key carries the statement it was issued with, so changing the terms never rewrites what a customer already holds." }),
  );
}

function renewForm(licence, ctx) {
  const terms = h("textarea", { rows: "4", maxlength: "8000" });
  terms.value = licence.terms;
  const ends = h("input", { type: "date" });
  const lock = lockField();
  const op = operation();
  const status = h("div", { class: "status" });
  const save = h("button", { type: "submit", text: "Record the new statement" });
  const form = h(
    "form",
    { novalidate: true },
    h("p", { class: "note", text: "This adds a statement version and, if you set one, a new end date. Keys already issued keep the end they were issued with: replace them to give each the new end and the new statement." }),
    field("Terms", terms),
    field("New end date", ends, `Now ${formatDate(licence.expires_at)}. Leave empty to keep it.`),
    lock.node,
    h("div", { class: "actions" }, save),
    status,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!lock.read()) {
      clear(status);
      status.append(notice("bad", "Enter the operator lock."));
      return;
    }
    const body = {};
    if (terms.value.trim() !== licence.terms) body.terms = terms.value.trim();
    if (ends.value) body.expires_at = ends.value;
    if (Object.keys(body).length === 0) {
      clear(status);
      status.append(notice("bad", "Change the terms or the end date first."));
      return;
    }
    const done = await commit(save, status, op, (id) =>
      api("POST", `/api/licenses/${licence.id}/renew`, { body, lock: lock.read(), operationId: id }),
    );
    lock.clear();
    if (done) ctx.refresh();
  });
  return form;
}

function licenceCard(ctx, data, licence, keys, host, shown) {
  const mine = keys.filter((k) => k.licence_id === licence.id);
  const holder = h("div", {});
  const open = (node) => {
    clear(holder);
    holder.append(node);
  };
  const actions = [];
  if (licence.status === "active") {
    actions.push(
      h("button", { type: "button", text: "Add keys", on: { click: () => ctx.navigate("issue", { user: data.customer.id, licence: licence.id }) } }),
      h("button", { type: "button", class: "quiet", text: "Renew or amend", on: { click: () => open(renewForm(licence, ctx)) } }),
    );
  }
  if (licence.status !== "voided") {
    actions.push(
      h("button", {
        type: "button",
        class: "danger",
        text: "Revoke licence",
        "aria-label": `Revoke licence ${licence.id}`,
        on: {
          click: () =>
            confirmPanel(host, {
              title: `Revoke licence #${licence.id} for ${data.customer.name}`,
              detail: `This revokes ${plural(licence.live_keys, "live key")} at once. Their software stops working against this relay. It cannot be undone; issue a new licence to restore access.`,
              confirmLabel: "Revoke licence and its keys",
              askReason: true,
              run: (lock, reason, operationId) =>
                api("POST", `/api/licenses/${licence.id}/revoke`, { body: reason ? { reason } : {}, lock, operationId }),
              done: () => ctx.refresh(),
            }),
        },
      }),
    );
  }
  return h(
    "div",
    { class: "licence" },
    h(
      "h3",
      {},
      `Licence #${licence.id} `,
      badge(licence.status, stateKind(licence.status)),
      licence.replaces_licence_id ? h("span", { class: "note", text: ` replaces #${licence.replaces_licence_id}` }) : null,
    ),
    h(
      "p",
      { class: "note" },
      `Statement ${licence.version}. Recorded ${formatDate(licence.created_at)}. Ends ${formatDate(licence.expires_at)}.`,
      licence.voided_at ? ` Revoked ${formatTime(licence.voided_at)}${licence.void_reason ? `: ${licence.void_reason}` : ""}.` : "",
    ),
    statements(licence),
    table(
      [
        { label: "Key", cell: (k) => `#${k.id}` },
        { label: "Allows", cell: (k) => scopeLabel(k.scope) },
        { label: "Works?", cell: (k) => badge(k.state, stateKind(k.state)) },
        { label: "Statement", cell: (k) => (k.licence_version ? `v${k.licence_version}` : "—") },
        { label: "Replaces", cell: (k) => (k.replaces_key_id ? `#${k.replaces_key_id}` : "—") },
        { label: "Ends", cell: (k) => formatTime(k.expires_at) },
        { label: "Last used", cell: (k) => formatTime(k.last_used_at) },
        { label: "", cell: (k) => keyActions({ key: k, host, shown, changed: () => ctx.refresh() }) },
      ],
      mine,
      "No keys have been issued under this licence yet.",
    ),
    h("div", { class: "actions" }, actions),
    holder,
  );
}

function createLicenceForm(ctx, data) {
  const terms = h("textarea", { rows: "3", maxlength: "8000" });
  const ends = h("input", { type: "date" });
  const replaces = h(
    "select",
    {},
    h("option", { value: "", text: "Nothing: this is an additional licence" }),
    ...data.licences
      .filter((l) => l.status === "active")
      .map((l) => h("option", { value: String(l.id), text: `Replace licence #${l.id} (it is revoked, with its keys)` })),
  );
  const lock = lockField();
  const op = operation();
  const status = h("div", { class: "status" });
  const save = h("button", { type: "submit", text: "Record the licence" });
  const form = h(
    "form",
    { novalidate: true },
    field("Terms", terms, "Plain text carried inside every key's signed statement (seats, term, anything agreed)."),
    field("Licence ends", ends, "Leave empty for no fixed end. Keys end when the licence does."),
    data.licences.some((l) => l.status === "active") ? field("Replaces", replaces) : null,
    lock.node,
    h("div", { class: "actions" }, save),
    status,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!lock.read()) {
      clear(status);
      status.append(notice("bad", "Enter the operator lock."));
      return;
    }
    const body = {
      ...(terms.value.trim() ? { terms: terms.value.trim() } : {}),
      ...(ends.value ? { expires_at: ends.value } : {}),
      ...(replaces.value ? { replaces_licence_id: Number(replaces.value) } : {}),
    };
    const done = await commit(save, status, op, (id) =>
      api("POST", `/api/users/${data.customer.id}/licenses`, { body, lock: lock.read(), operationId: id }),
    );
    lock.clear();
    if (done) ctx.refresh();
  });
  return form;
}

export default async function user(ctx) {
  const id = Number(ctx.params.get("id"));
  if (!Number.isInteger(id) || id < 1) return notice("bad", "No user was chosen. Open one from the Users page.");
  // What an action produced (a sealed file to download) stays on the page while
  // the data around it is read again, so a refresh never takes it away.
  const shown = h("div", {});
  const content = h("div", {});
  const here = { ...ctx, refresh: () => draw() };

  async function draw() {
    const data = await get(`/api/users/${id}`);
    const activity = await get(`/api/users/${id}/activity`, { hours: 168 }).catch(() => null);
    const host = h("div", {});
    const sum = activity ? totals(activity.by_hour) : null;
    const live = data.keys.filter((k) => k.state === "live").length;
    clear(content);
    content.append(
      h("p", {}, h("a", { href: "#users", text: "\u2190 All users" })),
      section(
        data.customer.name,
        h("p", { class: "note", text: `User #${data.customer.id}${data.customer.reference ? ` \u00b7 reference ${data.customer.reference}` : ""} \u00b7 added ${formatDate(data.customer.created_at)}` }),
        h(
          "div",
          { class: "cards" },
          card("Licences in force", data.licences.filter((l) => l.status === "active").length, `${data.licences.length} recorded`),
          card("Live keys", live, `${data.keys.length} issued`),
          card("Served, 7 days", sum ? sum.served : "\u2014", "requests by their keys"),
          card("Blocked, 7 days", sum ? sum.blocked : "\u2014", "revoked, expired or out of scope"),
        ),
        h("div", { class: "actions" }, h("a", { class: "button", href: `#activity?user=${data.customer.id}`, text: "Open their activity" })),
      ),
      section(
        "Licences",
        h("p", { class: "note", text: STATUS_NOTE }),
        data.licences.length === 0 ? empty("No licence is recorded for this user yet. Record one below.") : null,
        ...data.licences.map((l) => licenceCard(here, data, l, data.keys, host, shown)),
        host,
      ),
      section("Record a licence", createLicenceForm(here, data)),
    );
  }

  await draw();
  return h("div", {}, shown, content);
}
