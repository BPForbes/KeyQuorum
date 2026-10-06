import { api, downloadBase64, errorText, get } from "./api.js";
import { commit, operation } from "./confirm.js";
import { formatTime, shortId, shortOperation } from "./format.js";
import { badge, busy, clear, h, notice, section, table } from "./ui.js";

// Each feed pages back from its newest row.
const FEEDS = [
  {
    key: "actions",
    title: "What operators did",
    note: "By the identity Cloudflare Access verified. Refused attempts are listed too. A change carries its operation id, which is how a lost response is reconciled.",
    columns: [
      { label: "When", cell: (a) => formatTime(a.occurred_at) },
      { label: "Who", cell: (a) => a.operator },
      { label: "Action", cell: (a) => a.action },
      { label: "About", cell: (a) => a.subject ?? "—" },
      { label: "Operation", cell: (a) => (a.operation_id ? h("code", { title: a.operation_id, text: shortOperation(a.operation_id) }) : "—") },
      { label: "Result", cell: (a) => (a.success ? badge("done", "good") : badge("refused or failed", "bad")) },
    ],
    empty: "No operator has acted yet.",
  },
  {
    key: "auth",
    title: "Operator lock checks",
    note: "Every use of the lock, in the relay's tamper-evident chain. A refused row is a wrong lock.",
    columns: [
      { label: "When", cell: (a) => formatTime(a.attempted_at) },
      { label: "For", cell: (a) => a.operation.replace("console.", "") },
      { label: "Result", cell: (a) => (a.success ? badge("accepted", "good") : badge("refused", "bad")) },
      { label: "Chain", cell: (a) => h("code", { text: shortId(a.entry_hash) }) },
    ],
    empty: "The lock has not been used.",
  },
  {
    key: "keys",
    title: "Key changes",
    note: "Created, replaced and revoked keys, in the relay's tamper-evident chain. Customers can read the rows about their own keys. The actor is host for anyone holding the operator lock: who it was is in the operator list above.",
    columns: [
      { label: "When", cell: (e) => formatTime(e.occurred_at) },
      { label: "Key", cell: (e) => `#${e.key_id}` },
      { label: "Event", cell: (e) => e.event },
      { label: "Replaced", cell: (e) => (e.related_key_id ? `#${e.related_key_id}` : "—") },
      { label: "Chain", cell: (e) => h("code", { text: shortId(e.entry_hash) }) },
    ],
    empty: "No key has been issued yet.",
  },
];

function feedSection(feed) {
  const list = h("div", {});
  const more = h("div", { class: "actions" });
  const status = h("div", { class: "status" });
  let rows = [];
  let cursor = null;

  function draw() {
    clear(list);
    list.append(table(feed.columns, rows, feed.empty));
    clear(more);
    if (cursor !== null) {
      const button = h("button", { type: "button", class: "quiet", text: "Load older" });
      button.addEventListener("click", () => load(button));
      more.append(button);
    }
  }
  async function load(button) {
    const page = await busy(button ?? hidden, status, () => get("/api/audit", { feed: feed.key, before: rows.length ? cursor : undefined, limit: 25 }), errorText);
    if (!page) return;
    rows = rows.concat(page.rows);
    cursor = page.next_before;
    draw();
  }
  const hidden = h("button", { type: "button", hidden: true });
  return load(null).then(() => section(feed.title, h("p", { class: "note", text: feed.note }), list, more, status));
}

export default async function audit() {
  const status = h("div", { class: "status" });
  const checkpoint = h("button", { type: "button", text: "Download an audit checkpoint" });
  checkpoint.addEventListener("click", async () => {
    const result = await commit(checkpoint, status, operation(), () => api("POST", "/api/checkpoints", { body: {} }));
    if (result) downloadBase64(result.filename, result.content_base64, "application/json");
  });
  const sections = [];
  for (const feed of FEEDS) sections.push(await feedSection(feed));
  return h(
    "div",
    {},
    section(
      "Audit checkpoint",
      h("p", { text: "A checkpoint is the relay's signature over the current head of each audit chain. Its value is where you keep it: store it away from Cloudflare, so that rewriting the chain later can be proved." }),
      h("div", { class: "actions" }, checkpoint),
      status,
    ),
    ...sections,
    notice("plain", "Activity counts on the Activity page are a usage view, not part of this evidence."),
  );
}
