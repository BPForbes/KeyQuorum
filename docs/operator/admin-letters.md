# Provider-signed admin letters: design for review

Status: **design only. Nothing here is built, and no code should be written
until it is reviewed.** It answers one request: that most of what the operator
does in `/relay/admin` should also be doable through `.kqpb` letters once a
`.kqkey` is verified. That is a new kind of authority, so it is written down
first. It touches `CLAUDE.md` rules about who may mint keys and what the relay
may read, and says where it would not change them.

## What is being asked, and what a verified `.kqkey` can mean

A `.kqkey` proves its holder has a customer API key the relay issued. That is
customer authority, and it stays that. A customer key never authorises an admin
action: the console's own rules, issue #104 and `src/api_key_delivery.rs` all
say so, and a letter that arrives under a customer key is a customer's letter.

What "once `.kqkey` is verified" can safely mean is the operator's *own*
credential: an operator holds a hardware-backed signing key that the
provider-root-signed policy (`KQPL`) lists with the existing
`HardwareAuthority::ProviderRelayAdmin` role (`src/provider/hardware_auth.rs`).
The `.kqkey`-style verification step (relay challenge, certificate chain to the
pinned root) is how the operator's tool knows it is talking to the real relay
before it sends anything. The authority comes from the policy, not from a key
the relay minted.

## The conflict this has to avoid

The relay must never unseal a letter, hold a wrapped share or a private key
(`CLAUDE.md`, mailbox relay). An admin command the relay *executes* is a letter
the relay *reads*. So an admin command cannot be a sealed `KQPB`.

Proposal: an admin command is a **signed, unsealed artifact** with its own
magic (`KQAC`), like `KQBS` and `KQBN`: public framing, a domain-separated
signature, and no secret in the body. It carries only an operation name and
ids. Anything confidential in a result (a sealed key, a package) comes back the
way it does today, sealed to its recipient: in the reply of the call, or as an
ordinary letter in the recipient's mailbox. `envelope.rs` stays the only sealed
framing; `KQAC` is not a sealed envelope and does not belong in it.

## The command

`KQAC` v1, big-endian: magic, version, operation (a closed enum: the console's
`issue`, `rotate`, `revoke_key`, `void_licence`, `renew_licence`, `assign_key`,
never `bootstrap`, `rotate_lock` or `confirm_lock`), the relay's certificate
serial (binds it to one relay), the operator signing key's fingerprint,
an operation id (the console's idempotency key), a counter, `issued_at`,
`expires_at` (minutes, not days), the operation's arguments as the same JSON the
console sends, and the signature. Its size is bounded like the console's
request.

The relay accepts it only when **all** hold, in this order, and records a
refusal at each step (`provider_auth_events`, never the body):

1. the signer's fingerprint is in the relay's installed, root-verified policy
   with role `ProviderRelayAdmin` and has not been revoked (`KQRL`);
2. the signature verifies under that key over the domain-separated preimage;
3. the relay serial in it is this relay's, and `issued_at <= now < expires_at`;
4. the counter is strictly greater than the last accepted for that signer, and
   the operation id has not been used (the console's `operator_actions`
   uniqueness): replay of an accepted command changes nothing and answers
   `already_done`;
5. the operation is in the closed list.

Then it runs through the same `relay::operator`/`issuance` code as the console,
recorded in `operator_actions` with the signer's fingerprint as the actor
(`admin-key:<fingerprint prefix>`), in the same transaction as the change.
No rule is re-implemented: the console and the letter call one function.

## What it deliberately does not replace

- The **operator lock** stays the console's per-change control. A signed command
  is a different, hardware-backed way to authorise the same change; it does not
  weaken the lock, which still guards every console change. Whether the lock
  must also be presented with a command is a decision for review (recommended:
  not required, because the signature is stronger than a pasted secret; but the
  command must be *at least* as constrained: counter, expiry, relay-bound,
  recorded).
- **Cloudflare Access** stays in front of the console. Commands arrive on a
  different route and carry their own authority, so that route needs the
  same body limit, rate limit and `Cross-Origin-Resource-Policy` handling as
  every other, and is not reachable from a browser page.
- **Minting stays KeyQuorum's.** The relay only executes the existing issuance
  flows, which already run on the relay (the console does the same). HTTP
  still creates no bearer in a reply a customer sees; the sealed result is
  the only carrier. The `admin` scope is still never issued.
- **No private file is ever uploaded** to make this work. The operator's key
  signs locally (`keyquorum host command sign`, a new host-side verb) and only
  the signed command travels.

## Open decisions (need an owner's answer before code)

1. Is the operator lock also required on a signed command, or is the hardware
   signature enough?
2. One signer, or a threshold (the policy already has `hardware_threshold`)?
   Recommended: honour the policy's threshold for `void_licence` and
   `revoke_key`, one signer for `issue`.
3. How does the relay receive the policy and revocation list? Today the Worker
   does not consume `KQPL` or `KQRL` (`docs/operator/relay-hosting.md`); this
   needs that built and reviewed first, so it is the real prerequisite.
4. Delivery: an HTTP route for commands, or a mailbox the relay polls? A
   route is simpler; a mailbox needs its own deduplication and expiry rules.
5. The kind byte / magic is wire format: confirm `KQAC` and the operation
   numbering before anything is written with it.

## Tests this design would require

Replay, counter regression, wrong relay serial, expired and not-yet-valid
commands, a signer absent from or revoked in the policy, a customer key
presenting a command, an operation outside the closed list, a command with an
unknown field, a command that is also a valid console request replayed on both
paths (one effect), and a check that no reply holds a bearer, key hash or the
signer's secret.

Not claimed: any of this exists, that the Worker consumes the policy or the
revocation list, or that a signed command is stronger than the lock in every
respect (it is hardware-backed, but its key custody is the operator's).
