// The shape of every action that changes the relay: asked for, then confirmed
// with the operator lock, carrying an operation id so a lost response can be
// reconciled. The lock lives only in the field and is wiped after the request,
// whatever its outcome.
import { ApiError, errorText, newOperationId } from "./api.js";
import { busy, clear, h, lockField, notice } from "./ui.js";

// One operation id per attempt. It is kept while the outcome is unknown (the
// change may have been made, so the next try repeats the same id and is told
// if it was) and renewed once the relay has answered, either way.
export function operation() {
  let id = newOperationId();
  return {
    get id() {
      return id;
    },
    settle(error) {
      if (!error || !error.unknownOutcome) id = newOperationId();
    },
  };
}

// The words for a change that failed: what went wrong, what the relay says was
// already done, and what to do when it is not known.
export function describeChange(error) {
  if (error instanceof ApiError && error.body?.code === "already_done") {
    const done = error.body.operation ?? {};
    const ids = Object.entries(done.result ?? {})
      .filter(([, value]) => value !== null && value !== undefined)
      .map(([name, value]) => `${name.replaceAll("_", " ")}: ${Array.isArray(value) ? value.join(", ") : value}`)
      .join("; ");
    return `Already done${done.occurred_at ? ` at ${done.occurred_at}` : ""}${ids ? ` (${ids})` : ""}. It was not repeated. Sealed files are not kept: replace a key to get a new file.`;
  }
  return errorText(error);
}

// The ids a change that was already made produced, if this error says so.
export function alreadyDone(error) {
  return error instanceof ApiError && error.body?.code === "already_done" ? (error.body.operation?.result ?? {}) : null;
}

// Runs a change from a form or a panel: busy state, the failure told, the id
// kept or renewed. `task(operationId)` makes the request. `recover(ids)` may
// turn "already done" into the result the caller wanted (a repeat after a lost
// response finds what the first try made); otherwise it is told as a warning,
// not an error, since nothing is wrong.
export async function commit(button, status, op, task, { recover } = {}) {
  let failed = null;
  const result = await busy(
    button,
    status,
    async () => {
      try {
        return await task(op.id);
      } catch (error) {
        const ids = alreadyDone(error);
        const recovered = ids && recover ? recover(ids) : undefined;
        if (recovered !== undefined && recovered !== null) return recovered;
        throw error;
      }
    },
    (error) => {
      failed = error;
      return { text: describeChange(error), kind: alreadyDone(error) ? "warn" : "bad" };
    },
  );
  op.settle(failed);
  return result;
}

// `run(lock, reason, operationId, extra)` performs the request and returns its
// result; the panel closes and `done(result)` runs when it succeeded. `extra` is
// an optional `{ node, read() }` of more inputs the panel shows above the lock.
export function confirmPanel(host, { title, detail, confirmLabel, askReason = false, extra = null, run, done }) {
  clear(host);
  const lock = lockField();
  const op = operation();
  const reason = askReason
    ? h("input", { type: "text", maxlength: "500", autocomplete: "off", "aria-label": "Reason", placeholder: "Reason (optional, kept in the record)" })
    : null;
  const status = h("div", { class: "status" });
  const opCode = h("code", { text: op.id });
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
    const result = await commit(confirm, status, op, (id) =>
      run(typed, reason ? reason.value.trim() : "", id, extra ? extra.read() : undefined),
    );
    lock.clear();
    opCode.textContent = op.id;
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
      extra ? extra.node : null,
      lock.node,
      h("p", { class: "note" }, "Operation ", opCode),
      h("div", { class: "actions" }, confirm, cancel),
      status,
    ),
  );
  lock.focus();
}
