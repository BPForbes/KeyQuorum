// What the console shows after it issues or replaces a key: the sealed bundles
// to download, or the sealed letter waiting in the customer's mailbox. A bundle
// is sealed to the client's public key, so it is safe to send over any
// channel; the bearer inside is never shown here.
import { downloadBase64 } from "./api.js";
import { formatTime, scopeLabel } from "./format.js";
import { h, notice, table } from "./ui.js";

export function bundleList(bundles) {
  const rows = table(
    [
      { label: "File", cell: (b) => h("code", { text: b.filename }) },
      { label: "Allows", cell: (b) => scopeLabel(b.scope) },
      { label: "Key", cell: (b) => `#${b.key_id}` },
      { label: "Ends", cell: (b) => formatTime(b.expires_at) },
      {
        label: "",
        cell: (b) =>
          h("button", {
            type: "button",
            text: "Download",
            "aria-label": `Download ${b.filename}`,
            on: { click: () => downloadBase64(b.filename, b.bundle_base64) },
          }),
      },
    ],
    bundles,
  );
  return h(
    "div",
    {},
    notice(
      "good",
      "Issued. Each file is sealed to the client's public key, so it can be sent by any channel. The client loads it with keyquorum loadkey --bundle.",
    ),
    rows,
    h("p", { class: "note", text: "The files are not stored by this page or the relay: download them now. A lost file is replaced by replacing its key." }),
  );
}

// The result of replacing a key, by file or by letter.
export function replacement(result) {
  if (result.bundle) {
    return h(
      "div",
      {},
      notice("good", `Key #${result.replaced_key_id} was replaced by key #${result.key_id}. The old key stopped working at once.`),
      bundleList([result.bundle]),
    );
  }
  return notice(
    "good",
    `Key #${result.replaced_key_id} was replaced by key #${result.key_id}, sent as a sealed letter to the customer's own mailbox. The old key keeps working until ${formatTime(result.letter?.old_key_ends)} so they can collect it with their next keyquorum inbox open.`,
  );
}
