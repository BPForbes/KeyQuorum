import { api, errorText, get } from "./api.js";
import { commit, operation } from "./confirm.js";
import { formatTime } from "./format.js";
import { busy, clear, field, h, lockField, notice, section, table } from "./ui.js";

export default async function users(ctx) {
  const search = h("input", { type: "search", maxlength: "200", autocomplete: "off", value: ctx.params.get("search") ?? "" });
  const status = h(
    "select",
    {},
    h("option", { value: "all", text: "All users" }),
    h("option", { value: "active", text: "With a licence in force" }),
    h("option", { value: "inactive", text: "With no licence in force" }),
  );
  status.value = ["all", "active", "inactive"].includes(ctx.params.get("status")) ? ctx.params.get("status") : "all";
  const list = h("div", {});
  const more = h("div", { class: "actions" });
  const note = h("div", { class: "status" });
  let rows = [];
  let cursor = null;

  function draw() {
    clear(list);
    list.append(
      table(
        [
          {
            label: "User",
            cell: (u) => h("a", { href: `#user?id=${u.id}`, text: u.name }),
          },
          { label: "Reference", cell: (u) => u.reference ?? "—" },
          { label: "Licences in force", align: "end", cell: (u) => `${u.active_licences} of ${u.licences}` },
          { label: "Live keys", align: "end", cell: (u) => String(u.live_keys) },
          { label: "Last used", cell: (u) => formatTime(u.last_used_at) },
          { label: "Added", cell: (u) => formatTime(u.created_at) },
        ],
        rows,
        "No users match. Add one below, or clear the search.",
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
      button ?? submit,
      note,
      () =>
        get("/api/users", {
          search: search.value.trim(),
          status: status.value === "all" ? "" : status.value,
          before: reset ? undefined : cursor,
          limit: 25,
        }),
      errorText,
    );
    if (!page) return;
    rows = reset ? page.users : rows.concat(page.users);
    cursor = page.next_before;
    draw();
  }

  const submit = h("button", { type: "submit", text: "Search" });
  const form = h(
    "form",
    { class: "filters", role: "search", "aria-label": "Find users" },
    field("Search by name or reference", search),
    field("Show", status),
    h("div", { class: "actions" }, submit),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    load(true);
  });

  // Adding a user records a name and nothing else; licences and keys follow.
  const name = h("input", { type: "text", maxlength: "200", autocomplete: "off", required: true });
  const reference = h("input", { type: "text", maxlength: "100", autocomplete: "off" });
  const lock = lockField();
  const op = operation();
  const create = h("button", { type: "submit", text: "Add user" });
  const created = h("div", { class: "status" });
  const add = h(
    "form",
    { novalidate: true },
    field("Name", name, "The name that appears in the signed licence statement."),
    field("Your reference (optional)", reference, "A contract or account number of your own. Must be unique."),
    lock.node,
    h("div", { class: "actions" }, create),
    created,
  );
  add.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!name.value.trim() || !lock.read()) {
      clear(created);
      created.append(notice("bad", "Enter the user's name and the operator lock."));
      return;
    }
    const result = await commit(create, created, op, (id) =>
      api("POST", "/api/users", {
        body: { name: name.value.trim(), ...(reference.value.trim() ? { reference: reference.value.trim() } : {}) },
        lock: lock.read(),
        operationId: id,
      }),
      // A repeat after a lost response finds the user the first try recorded.
      { recover: (ids) => (Number.isInteger(ids.customer_id) ? { customer: { id: ids.customer_id } } : undefined) },
    );
    lock.clear();
    if (result) ctx.navigate("user", { id: result.customer.id });
  });

  await load(true);
  return h(
    "div",
    {},
    section("Users", form, list, more, note),
    section(
      "Add a user",
      h("p", { class: "note", text: "Record a customer, then give them a licence and keys on their page. Or issue to a new user in one go." }),
      add,
      h("div", { class: "actions" }, h("a", { class: "button", href: "#issue", text: "Issue keys to a new user" })),
    ),
  );
}
