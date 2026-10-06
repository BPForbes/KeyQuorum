import { errorText, operate } from "./api.js";
import { busy, card, clear, h, lockField, notice, section } from "./ui.js";
import { plural } from "./format.js";

function lockCreated(ctx, lock) {
  const input = h("input", { type: "text", readonly: true, value: lock, "aria-label": "Operator lock", class: "mono" });
  const copy = h("button", {
    type: "button",
    text: "Copy",
    on: {
      click: async () => {
        try {
          await navigator.clipboard.writeText(lock);
          copy.textContent = "Copied";
        } catch {
          input.select();
        }
      },
    },
  });
  const saved = h("button", { type: "button", text: "I have stored it", on: { click: () => ctx.refresh() } });
  return section(
    "Operator lock created",
    notice("warn", "This is the only time the lock is shown. Store it in a password manager, offline from this page. You will enter it for every issue, replacement and void; the relay keeps only a hash."),
    h("div", { class: "row" }, input, copy),
    h("div", { class: "actions" }, saved),
  );
}

function createLockPanel(ctx) {
  const status = h("div", { class: "status" });
  const create = h("button", { type: "button", text: "Create the operator lock" });
  const holder = h("div", {});
  create.addEventListener("click", async () => {
    const result = await busy(create, status, () => operate("bootstrap"), errorText);
    if (result) {
      clear(holder);
      holder.append(lockCreated(ctx, result.operator_lock));
    }
  });
  holder.append(
    section(
      "Create the operator lock",
      h("p", { text: "Issuing, replacing and voiding keys needs a lock that only you hold. It does not exist yet. Creating it is a one-time step, recorded in the audit trail." }),
      h("div", { class: "actions" }, create),
      status,
    ),
  );
  return holder;
}

function replaceLockPanel(ctx) {
  const holder = h("div", {});
  const lock = lockField();
  const status = h("div", { class: "status" });
  const replace = h("button", { type: "button", class: "danger", text: "Replace the operator lock" });
  replace.addEventListener("click", async () => {
    const typed = lock.read();
    if (!typed) {
      clear(status);
      status.append(notice("bad", "Enter the current operator lock."));
      lock.focus();
      return;
    }
    const result = await busy(replace, status, () => operate("rotate_lock", {}, typed), errorText);
    lock.clear();
    if (result) {
      clear(holder);
      holder.append(lockCreated(ctx, result.operator_lock));
    }
  });
  holder.append(
    section(
      "Replace the operator lock",
      h("p", { text: "Do this if the lock may have been seen by someone else. The current lock stops working at once and a new one is shown once." }),
      lock.node,
      h("div", { class: "actions" }, replace),
      status,
    ),
  );
  return holder;
}

export default async function overview(ctx) {
  const o = await operate("overview");
  const out = [];
  if (!o.identity_configured) {
    out.push(
      notice("bad", "The relay has no identity (its certificate and key secrets are not set). It cannot issue or seal keys until the operator sets them."),
    );
  }
  if (!o.operator_lock) out.push(createLockPanel(ctx));

  out.push(
    section(
      "Right now",
      h(
        "div",
        { class: "cards" },
        card("Live keys", o.keys.live, `${o.keys.revoked} revoked, ${o.keys.expired} expired`),
        card("Active licences", o.licences.active, `${o.licences.voided} voided, ${o.licences.ended} ended`),
        card("Served, last 24 h", o.last_24h.served, "requests by known keys"),
        card("Blocked, last 24 h", o.last_24h.blocked, "revoked, expired or out-of-scope keys"),
        card("Letters waiting", o.letters.inbox, `${plural(o.letters.devices, "device letter")} waiting`),
        card("Public trees", o.trees, "published by clients"),
      ),
    ),
  );
  out.push(
    section(
      "What this console can and cannot see",
      h("p", {
        text: "It shows what the relay holds: which keys exist and what they did, what was blocked, which letters are waiting (their kind, size and time), and the public trees. Letters are sealed to their recipients, so file contents and file histories inside them are not visible here by design.",
      }),
    ),
  );
  if (o.operator_lock && o.identity_configured) out.push(replaceLockPanel(ctx));
  return h("div", {}, out);
}
