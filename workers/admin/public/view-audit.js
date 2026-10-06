import { errorText, downloadBase64, operate } from "./api.js";
import { formatTime, shortId } from "./format.js";
import { badge, busy, h, notice, section, table } from "./ui.js";

export default async function audit() {
  const events = await operate("events");
  const status = h("div", { class: "status" });
  const checkpoint = h("button", { type: "button", text: "Download an audit checkpoint" });
  checkpoint.addEventListener("click", async () => {
    const result = await busy(checkpoint, status, () => operate("checkpoint"), errorText);
    if (result) downloadBase64(result.filename, result.content_base64, "application/json");
  });

  return h(
    "div",
    {},
    section(
      "Audit checkpoint",
      h("p", { text: "A checkpoint is the relay's signature over the current head of each audit chain. Its value is where you keep it: store it away from Cloudflare, so that rewriting the chain later can be proved." }),
      h("div", { class: "actions" }, checkpoint),
      status,
    ),
    section(
      "What operators did",
      h("p", { class: "note", text: "By the identity Cloudflare Access verified. Refused attempts are listed too." }),
      table(
        [
          { label: "When", cell: (a) => formatTime(a.occurred_at) },
          { label: "Who", cell: (a) => a.operator },
          { label: "Action", cell: (a) => a.action },
          { label: "About", cell: (a) => a.subject ?? "—" },
          { label: "Result", cell: (a) => (a.success ? badge("done", "good") : badge("refused or failed", "bad")) },
        ],
        events.operator_actions,
        "No operator has acted yet.",
      ),
    ),
    section(
      "Operator lock checks",
      h("p", { class: "note", text: "Every use of the lock, in the relay's tamper-evident chain. A refused row is a wrong lock." }),
      table(
        [
          { label: "When", cell: (a) => formatTime(a.attempted_at) },
          { label: "For", cell: (a) => a.operation.replace("console.", "") },
          { label: "Result", cell: (a) => (a.success ? badge("accepted", "good") : badge("refused", "bad")) },
          { label: "Chain", cell: (a) => h("code", { text: shortId(a.entry_hash) }) },
        ],
        events.auth_events,
        "The lock has not been used.",
      ),
    ),
    section(
      "Key changes",
      h("p", { class: "note", text: "Created, replaced and revoked keys, in the relay's tamper-evident chain. Clients can read the rows about their own keys." }),
      table(
        [
          { label: "When", cell: (e) => formatTime(e.occurred_at) },
          { label: "Key", cell: (e) => `#${e.key_id}` },
          { label: "Event", cell: (e) => e.event },
          { label: "Replaced", cell: (e) => (e.related_key_id ? `#${e.related_key_id}` : "—") },
          { label: "Chain", cell: (e) => h("code", { text: shortId(e.entry_hash) }) },
        ],
        events.key_events,
        "No key has been issued yet.",
      ),
    ),
    notice("plain", "Showing the newest 200 rows of each."),
  );
}
