import { setupSteps } from "./setup-state.js";
import { badge, h, notice, section } from "./ui.js";

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
};

function command(text) {
  return h("pre", {}, h("code", { text }));
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
        "The offline provider-root ceremony",
        root.status,
        h("p", {
          text: "KeyQuorum's provider-root private key stays on an offline machine. It never goes to this relay, this console or any Worker. It signs one certificate (provider.kqcert) naming your relay's public key, a provider id, a serial you can revoke later and an expiry. Make the relay's key pair first (the first command below), carry only relay.pub to the offline machine, and bring provider.kqcert back.",
        }),
        command(
          "# on your own machine: make the relay's key pair (relay.key never leaves it except as the secret in step 2)\nkeyquorum host identity generate --public-key-out relay.pub --private-key-out relay.key\n\n# on the offline machine, with relay.pub carried over:\nkeyquorum host certify --root-key /path/to/root.key --relay-public-key relay.pub \\\n  --provider-id \"<your provider id>\" --serial <serial> \\\n  --expires-at \"<expiry>\" --out provider.kqcert",
        ),
        h("p", { class: "note", text: "This page cannot see that ceremony, only its result: the certificate you install in step 2." }),
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
          text: "Set both together. Keep relay.key out of chat, tickets and version control, and delete the local copy once it is stored. Then reload this page: the warning clears when the relay reports an identity. The Status page shows the certificate's serial and expiry.",
        }),
      ),
      step(
        3,
        "The operator lock (your authority)",
        lock.status,
        h("p", {
          text: "Signing in through Cloudflare Access proves who you are. The operator lock is a second thing only you hold, presented with every issue, replacement and revocation. It is made here in two steps and shown once.",
        }),
        lock.status === "waiting"
          ? notice("warn", "The relay refuses to make a lock until it has an identity. Finish step 2 first.")
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
          ? notice("warn", "Issuing stays blocked until steps 2 and 3 are done.")
          : h("p", {}, h("a", { href: "#issue", text: "Issue the first keys" }), "."),
      ),
    ),
  );
}
