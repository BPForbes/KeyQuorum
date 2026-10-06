// The two-step shape of every action that changes the relay: the operator asks
// for it, then confirms with the operator lock. The lock lives only in the
// field and is wiped after the request, whatever its outcome.
import { errorText } from "./api.js";
import { busy, clear, h, lockField, notice } from "./ui.js";

// `run(lock, reason)` performs the request and returns its result; the panel
// closes and `done(result)` runs when it succeeded.
export function confirmPanel(host, { title, detail, confirmLabel, askReason = false, run, done }) {
  clear(host);
  const lock = lockField();
  const reason = askReason
    ? h("input", { type: "text", maxlength: "500", autocomplete: "off", "aria-label": "Reason", placeholder: "Reason (optional, kept in the record)" })
    : null;
  const status = h("div", { class: "status" });
  const confirm = h("button", { type: "button", class: "danger", text: confirmLabel });
  const cancel = h("button", { type: "button", class: "quiet", text: "Cancel", on: { click: () => clear(host) } });

  confirm.addEventListener("click", async () => {
    const typed = lock.read();
    if (!typed) {
      clear(status);
      status.append(notice("bad", "Enter the operator lock."));
      lock.focus();
      return;
    }
    const result = await busy(confirm, status, () => run(typed, reason ? reason.value.trim() : ""), errorText);
    lock.clear();
    if (result !== undefined) {
      clear(host);
      done(result);
    }
  });

  host.append(
    h(
      "div",
      { class: "confirm", role: "group", "aria-label": title },
      h("h3", { text: title }),
      detail ? h("p", { text: detail }) : null,
      reason ? h("div", { class: "field" }, reason) : null,
      lock.node,
      h("div", { class: "actions" }, confirm, cancel),
      status,
    ),
  );
  lock.focus();
}
