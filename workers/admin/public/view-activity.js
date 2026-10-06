import { operate } from "./api.js";
import { formatTime, hourlyBars, plural, scopeLabel, totals } from "./format.js";
import { badge, clear, empty, field, h, section, table } from "./ui.js";

const RANGES = [
  ["24", "Last 24 hours"],
  ["168", "Last 7 days"],
  ["720", "Last 30 days"],
];

function chart(rows) {
  const bars = hourlyBars(rows);
  if (bars.length === 0) return empty("No requests from known keys in this period.");
  const peak = Math.max(...bars.map((b) => b.served + b.blocked), 1);
  const wrap = h("div", { class: "bars", role: "img", "aria-label": `Requests per hour, busiest hour ${peak}` });
  for (const bar of bars) {
    const column = h("div", { class: "bar", title: `${formatTime(bar.hour)}: ${bar.served} served, ${bar.blocked} blocked` });
    const blocked = h("span", { class: "blocked" });
    const served = h("span", { class: "served" });
    blocked.style.height = `${(bar.blocked / peak) * 100}%`;
    served.style.height = `${(bar.served / peak) * 100}%`;
    column.append(blocked, served);
    wrap.append(column);
  }
  return h(
    "div",
    {},
    wrap,
    h("p", { class: "legend" }, h("span", { class: "swatch served" }), " served  ", h("span", { class: "swatch blocked" }), " blocked"),
  );
}

export default async function activity() {
  const range = h("select", {}, RANGES.map(([v, label]) => h("option", { value: v, text: label })));
  const body = h("div", {});

  async function draw() {
    const view = await operate("activity", { hours: Number(range.value) });
    clear(body);
    const { served, blocked } = totals(view.by_hour);
    body.append(
      section(
        "Requests",
        h("p", { text: `${plural(served, "request")} served and ${blocked} blocked in this period, by keys the relay knows.` }),
        chart(view.by_hour),
      ),
      section(
        "By client",
        table(
          [
            { label: "Client", cell: (c) => c.client },
            { label: "Last used", cell: (c) => formatTime(c.last_used_at) },
            { label: "Served", align: "end", cell: (c) => String(c.ok) },
            { label: "Revoked key", align: "end", cell: (c) => String(c.revoked) },
            { label: "Expired key", align: "end", cell: (c) => String(c.expired) },
            { label: "Out of scope", align: "end", cell: (c) => String(c.scope) },
          ],
          view.clients,
          "No clients yet.",
        ),
      ),
      section(
        "Blocked attempts",
        h("p", { class: "note", text: "Requests refused because of the key itself: it was revoked, it had expired, or it does not hold the scope the route needs. Requests with a bearer the relay has never issued are not recorded." }),
        table(
          [
            { label: "Client", cell: (r) => r.client ?? "—" },
            { label: "Key", cell: (r) => `#${r.key_id}` },
            { label: "Allows", cell: (r) => scopeLabel(r.scope) },
            { label: "Part of the API", cell: (r) => r.route },
            { label: "Why", cell: (r) => badge(r.outcome === "scope" ? "out of scope" : r.outcome, "warn") },
            { label: "Count", align: "end", cell: (r) => String(r.count) },
            { label: "Latest hour", cell: (r) => formatTime(r.last_hour) },
          ],
          view.by_key.filter((r) => r.outcome !== "ok"),
          "Nothing was blocked in this period.",
        ),
      ),
    );
  }

  range.addEventListener("change", () => {
    draw().catch(() => {
      clear(body);
      body.append(empty("Could not load activity."));
    });
  });
  await draw();
  return h("div", {}, h("section", {}, field("Period", range)), body);
}
