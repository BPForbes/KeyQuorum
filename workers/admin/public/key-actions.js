// What the operator can do to one key: replace it, or revoke it. Shared by the
// user page and the key list. Each opens a confirmation under `host` that asks
// for the operator lock.
import { api } from "./api.js";
import { replacement } from "./bundles.js";
import { confirmPanel } from "./confirm.js";
import { clear, field, h, section } from "./ui.js";

// The delivery choice for a replacement.
function deliveryChoice(maxGraceSeconds) {
  const via = h(
    "select",
    {},
    h("option", { value: "bundle", text: "A sealed file now (the old key stops at once)" }),
    h("option", { value: "letter", text: "A sealed letter in their mailbox (the old key lasts a short while)" }),
  );
  const hours = h("input", { type: "number", min: "1", max: String(Math.floor(maxGraceSeconds / 3600)), value: "24", step: "1" });
  const grace = field("Hours the old key keeps working", hours, "Only for a letter: how long they have to collect it. Up to a week.");
  const sync = () => {
    grace.hidden = via.value !== "letter";
  };
  via.addEventListener("change", sync);
  sync();
  return {
    node: h("div", {}, field("How the replacement reaches them", via), grace),
    read: () => ({ via: via.value, hours: Number(hours.value) }),
  };
}

// `result` renders into `shown` (an element the page keeps for it); `changed()`
// refreshes the page's own list.
export function keyActions({ key, host, shown, changed, maxGraceSeconds = 7 * 86_400 }) {
  const name = `${key.customer ? ` for ${key.customer}` : ""}`;
  const buttons = [];
  if (key.state === "live" && key.assigned) {
    buttons.push(
      h("button", {
        type: "button",
        text: "Replace",
        "aria-label": `Replace key ${key.id}`,
        on: {
          click: () =>
            confirmPanel(host, {
              title: `Replace key #${key.id}${name}`,
              detail: "A new sealed key is made for the same customer, under the licence's current statement and end date. Send it to them and they load it again.",
              confirmLabel: "Replace key",
              extra: deliveryChoice(maxGraceSeconds),
              run: (lock, _reason, operationId, choice) =>
                api("POST", `/api/keys/${key.id}/rotate`, {
                  body:
                    choice.via === "letter"
                      ? { via: "letter", grace_seconds: Math.round(choice.hours * 3600) }
                      : { via: "bundle" },
                  lock,
                  operationId,
                }),
              done: (result) => {
                clear(shown);
                shown.append(section(`Replacement for key #${key.id}`, replacement(result)));
                changed();
              },
            }),
        },
      }),
    );
  }
  if (key.state !== "revoked") {
    buttons.push(
      h("button", {
        type: "button",
        class: "danger",
        text: "Revoke",
        "aria-label": `Revoke key ${key.id}`,
        on: {
          click: () =>
            confirmPanel(host, {
              title: `Revoke key #${key.id}${name}`,
              detail: "This key stops working at once. Other keys of the same licence are not affected.",
              confirmLabel: "Revoke key",
              run: (lock, _reason, operationId) => api("POST", `/api/keys/${key.id}/revoke`, { body: {}, lock, operationId }),
              done: () => changed(),
            }),
        },
      }),
    );
  }
  return h("div", { class: "actions tight" }, buttons);
}
