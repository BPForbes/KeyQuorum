import { errorText, operate } from "./api.js";
import { confirmPanel } from "./confirm.js";
import { formatDate, formatTime, plural, stateKind } from "./format.js";
import { badge, h, notice, section, table } from "./ui.js";

export default async function clients(ctx) {
  const [{ licences }, activity] = await Promise.all([operate("licences"), operate("activity", { hours: 168 })]);
  const host = h("div", {});
  const root = h("div", {});

  const byClient = activity.clients.map((c) => ({ ...c, blocked: c.revoked + c.expired + c.scope }));
  root.append(
    section(
      "Clients",
      h("p", { class: "note", text: "Activity is for the last 7 days, from the keys each client was issued." }),
      table(
        [
          { label: "Client", cell: (c) => c.client },
          { label: "Keys", cell: (c) => `${c.live_keys} live of ${c.keys}` },
          { label: "Last used", cell: (c) => formatTime(c.last_used_at) },
          { label: "Served", align: "end", cell: (c) => String(c.ok) },
          {
            label: "Blocked",
            align: "end",
            cell: (c) => (c.blocked ? badge(String(c.blocked), "warn") : "0"),
          },
        ],
        byClient,
        "No client has been issued a licence yet. Issue one from the Issue page.",
      ),
    ),
  );

  root.append(
    section(
      "Licences",
      table(
        [
          { label: "Licence", cell: (l) => `#${l.id}` },
          { label: "Client", cell: (l) => l.client },
          { label: "Status", cell: (l) => badge(l.status, stateKind(l.status)) },
          { label: "Issued", cell: (l) => formatDate(l.created_at) },
          { label: "Ends", cell: (l) => formatDate(l.expires_at) },
          { label: "Keys", cell: (l) => `${l.live_keys} live of ${l.keys.length}` },
          {
            label: "",
            cell: (l) =>
              h(
                "div",
                { class: "actions tight" },
                l.status === "active"
                  ? h("button", {
                      type: "button",
                      text: "Add keys",
                      "aria-label": `Add keys to licence ${l.id} for ${l.client}`,
                      on: { click: () => ctx.navigate("issue", { licence: l.id }) },
                    })
                  : null,
                l.voided_at
                  ? null
                  : h("button", {
                      type: "button",
                      class: "danger",
                      text: "Void",
                      "aria-label": `Void licence ${l.id} for ${l.client}`,
                      on: {
                        click: () =>
                          confirmPanel(host, {
                            title: `Void licence #${l.id} for ${l.client}`,
                            detail: `This revokes ${plural(l.live_keys, "live key")} at once. The client's software stops working against this relay. It cannot be undone; issue a new licence to restore access.`,
                            confirmLabel: "Void licence and revoke its keys",
                            askReason: true,
                            run: (lock, reason) =>
                              operate("void_licence", { licence_id: l.id, ...(reason ? { reason } : {}) }, lock),
                            done: () => ctx.refresh(),
                          }),
                      },
                    }),
              ),
          },
        ],
        licences,
        "No licences yet.",
      ),
      host,
    ),
  );
  return root;
}
