// What the console shows after it issues or replaces a key: the sealed bundles
// to download. A bundle is sealed to the client's public key, so it is safe to
// send over any channel; the bearer inside is never shown here.
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
    h("p", { class: "note", text: "The bundles are not stored by this page or the relay: download them now. A lost bundle is replaced by rotating its key." }),
  );
}
