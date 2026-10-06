import { operate } from "./api.js";
import { bundleList } from "./bundles.js";
import { confirmPanel } from "./confirm.js";
import { formatTime, scopeLabel, shortId, stateKind } from "./format.js";
import { badge, clear, field, h, section, table } from "./ui.js";

export default async function keys(ctx) {
  let all = (await operate("keys")).keys;
  async function reload() {
    all = (await operate("keys")).keys;
    draw();
  }
  const filter = h(
    "select",
    {},
    ["all", "live", "revoked", "expired"].map((v) => h("option", { value: v, text: v === "all" ? "All keys" : v })),
  );
  const host = h("div", {});
  const list = h("div", {});
  const issued = h("div", {});

  function draw() {
    clear(list);
    const rows = filter.value === "all" ? all : all.filter((k) => k.state === filter.value);
    list.append(
      table(
        [
          { label: "Key", cell: (k) => `#${k.id}` },
          { label: "Client", cell: (k) => k.client ?? "—" },
          { label: "Allows", cell: (k) => scopeLabel(k.scope) },
          { label: "State", cell: (k) => badge(k.state, stateKind(k.state)) },
          { label: "Sealed to", cell: (k) => (k.delivery ? h("code", { text: shortId(k.delivery.recipient_fingerprint) }) : "—") },
          { label: "Issued", cell: (k) => formatTime(k.created_at) },
          { label: "Ends", cell: (k) => formatTime(k.expires_at) },
          { label: "Last used", cell: (k) => formatTime(k.last_used_at) },
          {
            label: "",
            cell: (k) =>
              k.state === "revoked"
                ? null
                : h(
                    "div",
                    { class: "actions tight" },
                    k.delivery && k.state === "live"
                      ? h("button", {
                          type: "button",
                          text: "Replace",
                          "aria-label": `Replace key ${k.id}`,
                          on: {
                            click: () =>
                              confirmPanel(host, {
                                title: `Replace key #${k.id}${k.client ? ` for ${k.client}` : ""}`,
                                detail: "The old key stops working at once, and a new sealed file is made for the same client. Send it to them and they load it again.",
                                confirmLabel: "Replace key",
                                run: (lock) => operate("rotate", { key_id: k.id }, lock),
                                done: (result) => {
                                  clear(issued);
                                  issued.append(section(`Replacement for key #${k.id}`, bundleList([result.bundle])));
                                  reload();
                                },
                              }),
                          },
                        })
                      : null,
                    h("button", {
                      type: "button",
                      class: "danger",
                      text: "Void",
                      "aria-label": `Void key ${k.id}`,
                      on: {
                        click: () =>
                          confirmPanel(host, {
                            title: `Void key #${k.id}${k.client ? ` for ${k.client}` : ""}`,
                            detail: "This key stops working at once. Other keys of the same licence are not affected.",
                            confirmLabel: "Void key",
                            run: (lock) => operate("void_key", { key_id: k.id }, lock),
                            done: () => reload(),
                          }),
                      },
                    }),
                  ),
          },
        ],
        rows,
        "No keys match.",
      ),
    );
  }
  filter.addEventListener("change", draw);
  draw();
  return h(
    "div",
    {},
    section("Keys", field("Show", filter), list, host),
    issued,
  );
}
