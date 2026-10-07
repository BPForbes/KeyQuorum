import { get } from "./api.js";
import { daysUntil, formatBytes, formatTime } from "./format.js";
import { untrustedReason } from "./setup-state.js";
import { badge, card, h, notice, section } from "./ui.js";

function row(label, value) {
  return h("tr", {}, h("th", { scope: "row", text: label }), h("td", {}, value));
}

export default async function status() {
  const s = await get("/api/status");
  const known = s.relay;
  const runtime = s.runtime;
  const out = [];
  if (!s.ready) {
    out.push(notice("bad", s.failure ? `The relay is not serving: ${s.failure}.` : "The relay's storage did not answer."));
  }
  const expires = known?.identity?.expires_at;
  const left = expires ? daysUntil(expires) : null;
  if (known && !known.identity.configured) {
    out.push(notice("bad", "The relay has no identity (certificate and key secrets). It cannot issue or seal keys, and official clients will not trust it."));
  } else if (known?.identity_check?.state === "untrusted") {
    out.push(notice("bad", `The relay holds an identity that official clients would refuse. ${untrustedReason({ identity_check: known.identity_check })}`));
  } else if (left !== null && left < 0) {
    out.push(notice("bad", "The relay's provider certificate has expired. Official clients will refuse it."));
  } else if (left !== null && left < 30) {
    out.push(notice("warn", `The relay's provider certificate expires in ${left} day(s). Have a renewal issued offline and install it.`));
  }
  if (known && !known.operator_lock.exists) {
    out.push(notice("warn", known.operator_lock.pending ? "The operator lock was created but not confirmed." : "The operator lock has not been created."));
  }

  out.push(
    section(
      "The relay",
      h(
        "div",
        { class: "cards" },
        card("Readiness", s.ready ? "Ready" : "Not ready", "does the storage answer"),
        card("Users", known?.counts.customers ?? "—", "recorded"),
        card("Keys", known?.counts.keys ?? "—", "issued, in any state"),
        card("Storage used", runtime?.storage_bytes === null || runtime === null ? "—" : formatBytes(runtime.storage_bytes), "this object's database"),
      ),
      h(
        "div",
        { class: "scroll" },
        h(
          "table",
          {},
          h(
            "tbody",
            {},
            row("Identity", known?.identity?.configured ? badge("configured", "good") : badge("not configured", "bad")),
            row("Trusted by clients", known?.identity_check?.state === "trusted" ? badge("yes: signed by the pinned root, not expired, key matches", "good") : known?.identity_check?.state === "untrusted" ? badge("no", "bad") : "—"),
            row("Pinned root", known?.identity_check?.pinned_root ? h("code", { text: known.identity_check.pinned_root }) : "—"),
            row("Provider id", known?.identity?.provider_id ?? "—"),
            row("Certificate serial", known?.identity?.serial ? h("code", { text: known.identity.serial }) : "—"),
            row("Certificate expires", known?.identity?.expires_at ? `${formatTime(known.identity.expires_at)}${left !== null ? ` (${left} days)` : ""}` : "—"),
            row("Operator lock", known ? (known.operator_lock.exists ? badge("confirmed", "good") : known.operator_lock.pending ? badge("waiting to be confirmed", "warn") : badge("not created", "bad")) : "—"),
          ),
        ),
      ),
    ),
  );

  if (runtime) {
    out.push(
      section(
        "This object since it last started",
        h("p", { class: "note", text: s.note }),
        h(
          "div",
          { class: "cards" },
          card("Requests admitted", runtime.requests_admitted, "customer requests the object took"),
          card("Turned away as busy", runtime.busy_refusals, `more than ${runtime.max_in_flight} at once`),
          card("Failed inside", runtime.request_errors, "requests that ended in an error"),
          card("In flight now", runtime.in_flight, `limit ${runtime.max_in_flight}`),
        ),
        h(
          "div",
          { class: "scroll" },
          h(
            "table",
            {},
            h(
              "tbody",
              {},
              row("Started", formatTime(runtime.started_at)),
              row("Housekeeping alarm, next", formatTime(runtime.alarm.next_at)),
              row("Housekeeping alarm, last run", formatTime(runtime.alarm.last_run_at)),
              row("Housekeeping alarm, last failure", runtime.alarm.last_failure ? badge(runtime.alarm.last_failure, "bad") : "none"),
              row("Large letters in R2", runtime.letters_in_r2 ? badge("on", "good") : badge("off (letters stay in the database, up to 1 MiB)", "warn")),
              ...backupRows(runtime.backups),
              row(
                "Version",
                runtime.deployment
                  ? `${runtime.deployment.tag ?? "no tag"} · ${runtime.deployment.id ?? "unknown"} · ${formatTime(runtime.deployment.timestamp)}`
                  : "not reported",
              ),
            ),
          ),
        ),
        h("p", { class: "note", text: "These counts are what the relay object observed, not a record: they start again whenever the object restarts, and the signed audit trail is on the Audit page. Requests the public Worker refused before the relay (wrong host or route, too large, rate limited) are in Cloudflare's own analytics." }),
      ),
    );
  }
  return h("div", {}, out);
}

// The backup lines of the status page: off and why, or the last one made and
// anything that went wrong since. Nothing here is secret: ids and counts only.
function backupRows(backups) {
  if (!backups) return [row("Sealed backups", "not reported")];
  if (!backups.enabled) return [row("Sealed backups", badge(`off: ${backups.reason ?? "not configured"}`, "warn"))];
  return [
    row("Sealed backups", badge(`every ${backups.every_hours} h, newest ${backups.keep} kept`, "good")),
    row("Last backup", backups.last ? `${formatTime(backups.last.at)} · ${backups.last.tables} tables, ${backups.last.rows} rows · ${backups.last.id}` : "none yet"),
    row("Backup problems", backups.last_failure ? badge(`last attempt failed (${backups.last_failure})`, "bad") : backups.last_skipped ? badge(backups.last_skipped, "warn") : "none"),
  ];
}
