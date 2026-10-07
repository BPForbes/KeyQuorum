import { api, get } from "./api.js";
import { commit, operation } from "./confirm.js";
import { plural } from "./format.js";
import { setupComplete } from "./setup-state.js";
import { card, clear, h, lockField, notice, section } from "./ui.js";
import { setupGuide } from "./view-setup.js";

// A new lock, shown once, then confirmed by entering it back. Until then the
// relay still has the previous lock (or none), so a lost response costs nothing.
function confirmLock(ctx, lock, heading) {
  const input = h("input", { type: "text", readonly: true, value: lock, "aria-label": "The new operator lock", class: "mono" });
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
  const again = lockField();
  const status = h("div", { class: "status" });
  const confirm = h("button", { type: "button", text: "Confirm the lock" });
  confirm.addEventListener("click", async () => {
    const typed = again.read();
    if (!typed) {
      clear(status);
      status.append(notice("bad", "Enter the lock you stored."));
      return;
    }
    const done = await commit(confirm, status, operation(), () => api("POST", "/api/operator-lock/confirm", { body: {}, lock: typed }));
    again.clear();
    if (done) ctx.refresh();
  });
  return section(
    heading,
    notice("warn", "This is the only time the lock is shown. Store it in a password manager, away from this page. It is not the lock until you confirm it below; you will enter it for every issue, replacement and revocation, and the relay keeps only a hash."),
    h("div", { class: "row" }, input, copy),
    h("p", { text: "Once it is stored, type it back to confirm. Until then the previous lock (if any) still works." }),
    again.node,
    h("div", { class: "actions" }, confirm),
    status,
  );
}

function createLockPanel(ctx, pending) {
  const status = h("div", { class: "status" });
  const create = h("button", { type: "button", text: pending ? "Create a new lock" : "Create the operator lock" });
  const holder = h("div", {});
  create.addEventListener("click", async () => {
    const result = await commit(create, status, operation(), () => api("POST", "/api/operator-lock/bootstrap", { body: {} }));
    if (result) {
      clear(holder);
      holder.append(confirmLock(ctx, result.operator_lock, "Confirm the operator lock"));
    }
  });
  holder.append(
    section(
      pending ? "The operator lock is waiting to be confirmed" : "Create the operator lock",
      h("p", {
        text: pending
          ? "A lock was created but never confirmed, perhaps because the page was closed. If you stored it, confirm it by entering it below. If not, create a new one: it replaces the waiting one."
          : "Issuing, replacing and revoking keys needs a lock that only you hold. It does not exist yet. Creating it is a recorded, two-step ceremony.",
      }),
      pending ? confirmExisting(ctx) : null,
      h("div", { class: "actions" }, create),
      status,
    ),
  );
  return holder;
}

function confirmExisting(ctx) {
  const lock = lockField();
  const status = h("div", { class: "status" });
  const confirm = h("button", { type: "button", text: "Confirm the waiting lock" });
  confirm.addEventListener("click", async () => {
    const typed = lock.read();
    if (!typed) {
      clear(status);
      status.append(notice("bad", "Enter the lock you stored."));
      return;
    }
    const done = await commit(confirm, status, operation(), () => api("POST", "/api/operator-lock/confirm", { body: {}, lock: typed }));
    lock.clear();
    if (done) ctx.refresh();
  });
  return h("div", {}, lock.node, h("div", { class: "actions" }, confirm), status);
}

function replaceLockPanel(ctx) {
  const holder = h("div", {});
  const lock = lockField();
  const status = h("div", { class: "status" });
  const replace = h("button", { type: "button", class: "danger", text: "Create a replacement lock" });
  replace.addEventListener("click", async () => {
    const typed = lock.read();
    if (!typed) {
      clear(status);
      status.append(notice("bad", "Enter the current operator lock."));
      lock.focus();
      return;
    }
    const result = await commit(replace, status, operation(), () => api("POST", "/api/operator-lock/replace", { body: {}, lock: typed }));
    lock.clear();
    if (result) {
      clear(holder);
      holder.append(confirmLock(ctx, result.operator_lock, "Confirm the replacement lock"));
    }
  });
  holder.append(
    section(
      "Replace the operator lock",
      h("p", { text: "Do this if the lock may have been seen by someone else. A new lock is shown once. The current one keeps working until you confirm the new one." }),
      lock.node,
      h("div", { class: "actions" }, replace),
      status,
    ),
  );
  return holder;
}

export default async function overview(ctx) {
  const o = await get("/api/overview");
  const out = [];
  if (!setupComplete(o)) out.push(setupGuide(o, createLockPanel(ctx, o.operator_lock_pending)));

  out.push(
    section(
      "Right now",
      h(
        "div",
        { class: "cards" },
        card("Users", o.customers, "customers you have licensed"),
        card("Live keys", o.keys.live, `${o.keys.revoked} revoked, ${o.keys.expired} expired`),
        card("Active licences", o.licences.active, `${o.licences.voided} revoked, ${o.licences.ended} ended`),
        card("Served, last 24 h", o.last_24h.served, "requests by known keys"),
        card("Blocked, last 24 h", o.last_24h.blocked, "revoked, expired or out-of-scope keys"),
        card("Letters waiting", o.letters.inbox, `${plural(o.letters.devices, "device letter")} waiting`),
        card("Public trees", o.trees, "published by clients"),
      ),
      o.keys.unassigned > 0
        ? notice("warn", `${plural(o.keys.unassigned, "key")} ${o.keys.unassigned === 1 ? "is" : "are"} not assigned to any user (issued before the console, or by the host command line). They work, but cannot be replaced from here until assigned: open Keys, then Not assigned.`)
        : null,
    ),
  );
  out.push(
    section(
      "What this console can and cannot see",
      h("p", {
        text: "It shows what the relay holds: which users and licences you have recorded, which keys exist and what they did, what was blocked, which letters are waiting (their kind, size and time), and the public trees. Letters are sealed to their recipients, so file contents and file histories inside them are not visible here by design.",
      }),
    ),
  );
  if (o.operator_lock && o.identity_configured) out.push(replaceLockPanel(ctx));
  return h("div", {}, out);
}
