import { get } from "./api.js";
import { formatBytes, formatTime, shortId } from "./format.js";
import { h, notice, section, table } from "./ui.js";

function letterTable(group) {
  return table(
    [
      { label: "Letter", cell: (l) => `#${l.id}` },
      {
        label: "For",
        // Named only when one customer holds a key sealed to that recipient; two
        // do not say whose it is, so none is picked.
        cell: (l) =>
          l.customer ??
          (l.customers?.length > 1
            ? h("span", { text: `more than one customer: ${l.customers.join(", ")}` })
            : h("code", { text: shortId(l.recipient_fingerprint) })),
      },
      { label: "Kind", cell: (l) => l.kind_name },
      { label: "Size", align: "end", cell: (l) => formatBytes(l.size) },
      { label: "Stored", cell: (l) => formatTime(l.stored_at) },
      { label: "Expires", cell: (l) => formatTime(l.expires_at) },
    ],
    group.newest,
    "No letters are waiting.",
  );
}

export default async function letters() {
  const [view, { trees }] = await Promise.all([get("/api/letters"), get("/api/trees")]);
  return h(
    "div",
    {},
    notice(
      "plain",
      "Letters are sealed to their recipients. The relay can show who a letter is for, its kind, size and time, but not what is inside, so file contents and file histories are not visible here.",
    ),
    section(`Inbox letters (${view.inbox.total} waiting; newest ${view.inbox.newest.length} shown)`, letterTable(view.inbox)),
    section(`Device letters (${view.devices.total} waiting; newest ${view.devices.newest.length} shown)`, letterTable(view.devices)),
    section(
      "Public trees",
      h("p", { class: "note", text: "The organisation structures clients publish to the relay: a label, the generation last published and when. These are public by design." }),
      table(
        [
          { label: "Label", cell: (t) => t.label },
          { label: "Generation", align: "end", cell: (t) => String(t.generation) },
          { label: "Updated", cell: (t) => formatTime(t.updated_at) },
        ],
        trees,
        "No trees have been published.",
      ),
    ),
  );
}
