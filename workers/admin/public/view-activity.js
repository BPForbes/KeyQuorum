import { errorText, get } from "./api.js";
import { formatBytes, formatMs, formatTime, hourlyBars, plural, scopeLabel } from "./format.js";
import { badge, busy, card, clear, empty, field, h, section, table } from "./ui.js";

const RANGES = [
  ["24", "Last 24 hours"],
  ["168", "Last 7 days"],
  ["720", "Last 30 days"],
  ["2160", "Last 90 days"],
];
const ROUTES = ["", "inbox", "devices", "trees", "audit", "other"];
const OUTCOMES = [
  ["", "Any outcome"],
  ["ok", "Served"],
  ["client_error", "Refused as a bad request"],
  ["server_error", "Failed on the relay"],
  ["scope", "Out of scope"],
  ["revoked", "Revoked key"],
  ["expired", "Expired key"],
];
const OUTCOME_NAME = Object.fromEntries(OUTCOMES);

function chart(rows) {
  const bars = hourlyBars(rows);
  if (bars.length === 0) return empty("No requests from known keys match these filters.");
  const peak = Math.max(...bars.map((b) => b.served + b.blocked), 1);
  const wrap = h("div", { class: "bars", role: "img", "aria-label": `Requests per hour, busiest hour ${peak}` });
  for (const bar of bars) {
    const column = h("div", { class: "bar", title: `${formatTime(bar.hour)}: ${bar.served} served, ${bar.blocked} not` });
    const other = h("span", { class: "blocked" });
    const served = h("span", { class: "served" });
    other.style.height = `${(bar.blocked / peak) * 100}%`;
    served.style.height = `${(bar.served / peak) * 100}%`;
    column.append(other, served);
    wrap.append(column);
  }
  return h(
    "div",
    {},
    wrap,
    h("p", { class: "legend" }, h("span", { class: "swatch served" }), " served  ", h("span", { class: "swatch blocked" }), " refused or failed"),
  );
}

export default async function activity(ctx) {
  const range = h("select", {}, RANGES.map(([v, label]) => h("option", { value: v, text: label })));
  const userSel = h("select", {}, h("option", { value: "", text: "Everyone" }));
  const route = h("select", {}, ROUTES.map((v) => h("option", { value: v, text: v === "" ? "Any part of the API" : v })));
  const outcome = h("select", {}, OUTCOMES.map(([v, label]) => h("option", { value: v, text: label })));
  const keyId = h("input", { type: "number", min: "1", step: "1", placeholder: "Any key" });
  const body = h("div", {});
  const status = h("div", { class: "status" });
  const apply = h("button", { type: "submit", text: "Show" });

  const people = await get("/api/users", { limit: 100 });
  for (const u of people.users) userSel.append(h("option", { value: String(u.id), text: u.name }));
  const wanted = ctx.params.get("user");
  if (wanted && people.users.some((u) => String(u.id) === wanted)) userSel.value = wanted;

  async function draw() {
    const query = {
      hours: range.value,
      key_id: keyId.value || undefined,
      route: route.value || undefined,
      outcome: outcome.value || undefined,
    };
    const path = userSel.value ? `/api/users/${userSel.value}/activity` : "/api/activity";
    const view = await busy(apply, status, () => get(path, query), errorText);
    if (!view) return;
    clear(body);
    const t = view.totals;
    body.append(
      section(
        "Totals",
        h(
          "div",
          { class: "cards" },
          card("Requests", t.requests, "admitted to the relay"),
          card("Served", t.ok, "answered below 400"),
          card("Refused or failed", t.client_error + t.server_error, `${t.client_error} bad requests, ${t.server_error} relay failures`),
          card("Blocked keys", t.blocked, "revoked, expired or out of scope"),
          card("Average time", formatMs(t.avg_ms), `slowest ${formatMs(t.max_ms)}`),
          card("Data", formatBytes(t.bytes_in + t.bytes_out), `${formatBytes(t.bytes_in)} in, ${formatBytes(t.bytes_out)} out`),
        ),
        h("p", { class: "note", text: view.note }),
      ),
      section("Requests per hour", chart(view.by_hour)),
      section(
        "By user",
        table(
          [
            { label: "User", cell: (u) => (u.customer_id ? h("a", { href: `#user?id=${u.customer_id}`, text: u.customer }) : h("em", { text: u.customer })) },
            { label: "Last used", cell: (u) => formatTime(u.last_used_at) },
            { label: "Requests", align: "end", cell: (u) => String(u.requests) },
            { label: "Served", align: "end", cell: (u) => String(u.ok) },
            { label: "Errors", align: "end", cell: (u) => String(u.client_error + u.server_error) },
            { label: "Blocked", align: "end", cell: (u) => (u.blocked ? badge(String(u.blocked), "warn") : "0") },
            { label: "Average", align: "end", cell: (u) => formatMs(u.avg_ms) },
          ],
          view.users,
          "No activity matches.",
        ),
      ),
      section(
        "By key and part of the API",
        table(
          [
            { label: "User", cell: (r) => r.customer ?? h("em", { text: "not assigned" }) },
            { label: "Key", cell: (r) => `#${r.key_id}` },
            { label: "Allows", cell: (r) => scopeLabel(r.scope) },
            { label: "Part of the API", cell: (r) => r.route },
            { label: "Outcome", cell: (r) => badge(OUTCOME_NAME[r.outcome] ?? r.outcome, r.outcome === "ok" ? "good" : "warn") },
            { label: "Count", align: "end", cell: (r) => String(r.count) },
            { label: "Average", align: "end", cell: (r) => formatMs(r.avg_ms) },
            { label: "Data", align: "end", cell: (r) => formatBytes(r.bytes_in + r.bytes_out) },
            { label: "Latest hour", cell: (r) => formatTime(r.last_hour) },
          ],
          view.by_key,
          "Nothing matches these filters.",
        ),
        h("p", { class: "note", text: `${plural(view.by_key.length, "row")}. A request with a bearer the relay never issued is not recorded, so it is attributed to nobody.` }),
      ),
    );
  }

  const form = h(
    "form",
    { class: "filters", "aria-label": "Filter activity" },
    field("Period", range),
    field("User", userSel),
    field("Key", keyId),
    field("Part of the API", route),
    field("Outcome", outcome),
    h("div", { class: "actions" }, apply),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    draw();
  });
  await draw();
  return h("div", {}, section("Filters", form, status), body);
}
