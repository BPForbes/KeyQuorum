import { PRIVATE_FILES, expiryText, filesOf, loadProvisioner, nextSteps, problems, publicZip, utcText } from "./provision.js";
import { identityState, setupSteps, untrustedReason } from "./setup-state.js";
import { badge, busy, clear, field, h, notice, section } from "./ui.js";
import { downloadBytes } from "./zip.js";

// The first-time setup guide on the Overview page. It explains four distinct
// steps in order and shows where the relay stands on each. It holds, asks for and
// shows no secret: the commands name files, never values, and what the relay
// reports (an identity configured or not, a lock made or not) is all it reads.

const LABEL = {
  done: ["done", "good"],
  todo: ["do this next", "warn"],
  pending: ["started, not confirmed", "warn"],
  waiting: ["waits for an earlier step", "plain"],
  offline: ["offline, not visible from here", "plain"],
  failed: ["needs attention", "bad"],
};

function command(text) {
  return h("pre", {}, h("code", { text }));
}

// The identity made in this browser (provision.js): a form, then the
// downloads and what to do with them. The private keys exist only in `made`
// until the operator clears the panel; nothing is sent or stored.
function generatePanel() {
  const providerId = h("input", { type: "text", maxlength: "200", autocomplete: "off", placeholder: "Acme Security Services" });
  const serial = h("input", { type: "text", class: "mono", maxlength: "64", autocomplete: "off", spellcheck: "false", placeholder: "KQP-000001" });
  const expires = h("input", { type: "date" });
  const button = h("button", { type: "button", text: "Make the identity in this browser" });
  const status = h("div", {});
  const result = h("div", {});
  let made = null;
  const forget = () => {
    made = null;
    clear(result);
  };
  button.addEventListener("click", async () => {
    forget();
    const faults = problems({ providerId: providerId.value, serial: serial.value, expiresAt: expires.value });
    if (faults.length > 0) {
      clear(status);
      status.append(notice("bad", faults.join(" ")));
      return;
    }
    const outcome = await busy(
      button,
      status,
      async () => {
        const provision = await loadProvisioner();
        const json = provision(providerId.value.trim(), serial.value.trim(), expiryText(expires.value), utcText(new Date()));
        return filesOf(json);
      },
      (error) => `Could not make the identity: ${error.message}.`,
    );
    if (!outcome) return;
    made = outcome;
    const downloads = made.files
      .filter((file) => file.private)
      .map((file) =>
        h("button", { type: "button", text: `Download ${file.name}`, on: { click: () => downloadBytes(file.name, file.bytes, "text/plain") } }),
      );
    downloads.push(
      h("button", {
        type: "button",
        text: "Download the public files (zip)",
        on: { click: () => downloadBytes("provider-public.zip", publicZip(made.files), "application/zip") },
      }),
    );
    result.append(
      notice("good", "Made. Download every file now: this page keeps nothing once you leave it, and a lost private key means making a new identity."),
      h("p", {}, "The root this identity trusts (root.pub, public): ", h("code", { text: made.rootPub })),
      h("div", { class: "actions" }, downloads),
      h("p", { class: "note", text: `${PRIVATE_FILES.join(" and ")} are private: keep them off shared or synced folders and never upload them anywhere, this console included.` }),
      h("ol", {}, nextSteps(made.rootPub).map((step) => h("li", { text: step }))),
      h("div", { class: "actions" }, h("button", { type: "button", text: "Clear from this page", on: { click: forget } })),
    );
  });
  return h(
    "div",
    {},
    field("Provider id", providerId, "The name every client sees for this relay."),
    field("Certificate serial", serial, "Yours to choose; a revocation names it."),
    field("Certificate expiry", expires, "Have a new certificate issued before this day."),
    h("div", { class: "actions" }, button),
    status,
    result,
  );
}

// The root public key this relay pins, a public value, for the operator to
// compare with the one their ceremony recorded.
function pinnedRoot(overview) {
  const root = overview.identity_check?.pinned_root;
  if (typeof root !== "string" || !/^[0-9a-f]{64}$/.test(root)) return null;
  return h("p", {}, "This relay pins: ", h("code", { text: root }), ". Compare it character for character with root.pub.");
}

function step(number, title, status, ...body) {
  const [text, kind] = LABEL[status];
  return h(
    "li",
    { class: `setup-step ${status}` },
    h("h3", {}, `Step ${number}: ${title} `, badge(text, kind)),
    body,
  );
}

// `lockPanel` is the Overview's own create-the-lock panel, shown inside step 3
// only once the relay can make a lock (it refuses to without an identity).
export function setupGuide(overview, lockPanel) {
  const [root, identity, lock, issue] = setupSteps(overview);
  return section(
    "Set up this relay",
    h("p", {
      text: "This relay cannot issue or seal keys yet. Four things have to exist, in this order. They are separate: the first two make the relay trustworthy to clients, the third is your own authority to change anything here, and only then are people's keys issued.",
    }),
    h(
      "ol",
      { class: "setup-steps" },
      step(
        1,
        "The offline provider-root ceremony, and pinning the root",
        root.status,
        h("p", {
          text: "KeyQuorum's provider-root private key never goes to this relay, this console's Worker or any Worker. It signs one certificate (provider.kqcert) naming your relay's public key, a provider id, a serial you can revoke later and an expiry. Make the root, the relay's key pair and that certificate together here, in this browser, with the relay's own code: they are checked the way this relay will check them and handed to you as downloads, and nothing is sent anywhere.",
        }),
        generatePanel(),
        h("p", { text: "Or make the same files with one command on a machine of your own (the directory must be new; both private keys are written owner-only and never printed):" }),
        command(
          "keyquorum host provision --out /path/to/provider \\\n  --provider-id \"<your provider id>\" --serial <serial> --expires-at \"<expiry>\"\n# writes root.key, root.pub, relay.key, relay.pub, provider.kqcert and provider-info.kqpkg\n\n# existing root only: certify a new relay key under it (host identity generate, then)\nkeyquorum host certify --root-key /path/to/root.key --relay-public-key relay.pub \\\n  --provider-id \"<your provider id>\" --serial <serial> \\\n  --expires-at \"<expiry>\" --out provider.kqcert",
        ),
        h("p", {
          text: "Pin the root. This relay pins the root its PROVIDER_ROOT deploy variable names (a GitHub environment variable, the contents of root.pub, public; set it and run the workers deploy). Every official client trusts exactly one root too, compiled in when it is built (KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY, from KEYQUORUM_PROVIDER_ROOT or a git-ignored provider-root.pub; nothing is committed, and a client built with neither trusts no relay): build the clients with the public half of your root; a certificate under any other root is refused by every client.",
        }),
        pinnedRoot(overview),
        identityState(overview) === "untrusted" && root.status === "failed"
          ? notice("bad", untrustedReason(overview))
          : null,
        h("p", { class: "note", text: "This page cannot see the ceremony, only whether its result checks out: it is done here only when the relay confirms the certificate it holds is signed by the root it pins, has not expired and grants the provider capabilities. Whether the relay's key matches the certificate is judged at step 2." }),
      ),
      step(
        2,
        "The relay's identity (a service credential)",
        identity.status,
        h("p", {
          text: "The relay signs on its own, with no one present, so its identity is a pair of Worker secrets set on the relay Worker (not the admin Worker). It is not a personal .kqkey: a .kqkey is sealed to one person's key and opened with their passphrase, which a service cannot supply.",
        }),
        command(
          "# after step 1 returns provider.kqcert, in the workers/ directory:\nnpx wrangler secret put RELAY_PRIVATE_KEY < relay.key\nbase64 < provider.kqcert | tr -d '\\n' | npx wrangler secret put RELAY_CERTIFICATE\n# add --env staging for the staging Worker",
        ),
        h("p", {
          class: "note",
          text: "Set both together. Keep relay.key out of chat, tickets and version control, and delete the local copy once it is stored. Then reload this page. Step 2 clears when the relay's identity checks out. If the certificate is expired, or not signed by the pinned root, step 1 shows what to fix instead; if the key and the certificate do not match, this step does. The Status page shows the certificate's serial and expiry.",
        }),
        identity.status === "failed" ? notice("bad", untrustedReason(overview)) : null,
      ),
      step(
        3,
        "The operator lock (your authority)",
        lock.status,
        h("p", {
          text: "Signing in through Cloudflare Access proves who you are. The operator lock is a second thing only you hold, presented with every issue, replacement and revocation. It is made here in two steps and shown once.",
        }),
        lock.status === "waiting"
          ? notice("warn", "The relay will not make a lock without an identity, and this guide waits until that identity checks out. Finish steps 1 and 2 first.")
          : lock.status === "done"
            ? h("p", { text: "The lock exists." })
            : lockPanel,
      ),
      step(
        4,
        "Issue each person's keys",
        issue.status,
        h("p", {
          text: "A person's first credential is a sealed .kqkey file, sealed to that person's own slot public key and opened only with their passphrase. Never reuse one person's file for another: it opens for nobody else. Later rotations of their key can arrive as a sealed letter in their inbox, as long as they hold a live key that can pull it.",
        }),
        issue.status === "waiting"
          ? notice("warn", "Issuing stays blocked here until steps 1 to 3 are done. The relay itself requires the identity and the lock.")
          : h("p", {}, h("a", { href: "#issue", text: "Issue the first keys" }), "."),
      ),
    ),
  );
}
