# A YubiKey for operator setup and sensitive operations: evaluation

Status: **evaluation only, nothing implemented** (issue #102). The issue asks
for feasibility, a threat model, and the enrolment, confirmation, recovery and
revocation design to be written down *before* any hardware option is built.
This is that document. It changes no code and no existing control.

Read first: `relay-deployment.md` ("Secret provisioning", "Operator console"),
`relay-secrets.md` ("Why the relay key is not a `.kq*` file") and
`relay-hosting.md` ("The operator console").

## Verdict

- A YubiKey can **add** a phishing-resistant, possession-based authorization to
  the console's per-change **operator lock**, in the browser, with no local
  helper (WebAuthn, design A below). That is the one hardware option this
  document recommends evaluating further, as an addition to the lock, not a
  replacement: once enforced, both are required, and there is no lock-only
  fallback.
- A YubiKey **cannot** hold the **relay's signing key**: the relay signs
  unattended, on every request, from a Worker. That key stays a Worker secret.
- A YubiKey **can** hold the offline **provider-root** key (Ed25519 in the PIV
  application on firmware 5.7.4 and later), but only with a local helper
  (PC/SC, PKCS#11 or `ykman`) that `host certify` does not have, and a browser
  cannot do it at all. It also raises a backup problem (below). Not
  recommended now; the root stays a file on an offline machine.
- A browser authenticator **cannot** produce a KQ signature or open a KQ
  sealed envelope. WebAuthn signs `authenticatorData ‖ SHA-256(clientDataJSON)`
  with the credential's own key, never a caller's raw bytes, and KeyQuorum's
  formats need Ed25519 signatures over their own domain-separated preimages and
  X25519 sealed boxes.
- Existing **Cloudflare Access email one-time PIN plus security-key MFA stays
  exactly as it is.** Nothing here weakens or replaces it. It protects entry to
  the console; it provisions no relay key and creates no operator lock.

## What protects what today

| Layer | What it protects | Held by | Changed by this document |
| --- | --- | --- | --- |
| Cloudflare Access: one-time PIN to the operator's email, then independent MFA with a security key | Reaching the console and its API at all (the admin Worker also verifies Access's signed token itself) | Cloudflare and the operator's key | No |
| Operator lock (`kql_…`, hash only on the relay) | Each change: issue, replace, void, replace the lock | The operator's password manager, pasted per change | Only design A would add to it |
| Relay identity (`RELAY_PRIVATE_KEY`, `RELAY_CERTIFICATE`) | The relay's ability to sign and to seal keys; whether clients trust it | Worker secrets set by the operator | No (see below) |
| Provider-root key | Signing the relay's certificate; the root of client trust | An offline machine | No |
| A person's `.kqkey` | Their own credential, sealed to their slot key, opened with their passphrase | That person | No |

Each person's bundle stays **recipient-specific**: the first credential is a
sealed `.kqkey` (`EXPORT_BUNDLE` type 4) sealed to that person's public key, and
a later rotation can arrive as a `.kqpb` letter (`KIND_API_KEY_ISSUE`, 20)
sealed to the same key. One person's bundle opens for nobody else and is never
reused. None of the options below touches that.

## What a YubiKey can do, against what KeyQuorum needs

KeyQuorum uses Ed25519 (`ed25519-dalek`) for signatures and X25519
(`x25519-dalek`) for sealing (`Cargo.toml`).

| Capability | What it gives | Fits KQ? |
| --- | --- | --- |
| FIDO2 / WebAuthn assertion, ES256 (P-256) on every YubiKey 5 and Security Key, EdDSA (Ed25519) from firmware 5.2 | A signature by a credential bound to one origin, with user presence and optionally a PIN (user verification) | Yes for authorizing a console action. **No** for KQ artifacts: the signed bytes are WebAuthn's, not a KQ preimage |
| FIDO2 `hmac-secret` (firmware 5.2) | A per-credential secret derived inside the key | Could derive a wrapping key; not needed by any design here |
| PIV, ECC P-256 and P-384, RSA | Signing and decryption through a smart-card interface, needing a helper | Wrong curves for KQ |
| PIV, Ed25519 and X25519 (firmware 5.7.4 and later) | The curves KQ uses, held in the key | Only through a local helper; `host certify` and the envelope code have no external-signer path |
| OpenPGP application (Ed25519 and X25519 from 5.2.3) | The same curves through GnuPG tooling | Same: needs a helper and new code |

Which models: ES256 WebAuthn works on any YubiKey 5 series or Security Key
series key; EdDSA and `hmac-secret` need firmware 5.2 or later; PIV Ed25519 and
X25519 need 5.7.4 or later. Other FIDO2 authenticators would also do ES256, but
only YubiKeys are in scope here and no other make is claimed or tested.

Not possible with any of these, stated plainly: a browser or a FIDO2 key
producing a `KQPC` certificate signature, a `KQBS` signature, or opening a
`KQXB` or `KQPB` envelope; and a hardware key signing for a relay that runs
unattended.

## The design options

### A. A hardware second factor on the operator lock (recommended to evaluate)

What it protects: the same operations the operator lock already gates (issue,
replace, void a key, void a licence, replace the lock). What it replaces:
nothing. The lock stays, and once enforcement is on (see "Enforcement and
recovery" below) the key is required **in addition**: every gated change needs
both, and neither alone is enough. A design in which a registered key stands in
for pasting the lock is not part of this evaluation; it would have to be argued
separately, because it changes what a lost key means.

How it would work, in the browser only:

1. **Enrolment** during the existing two-step lock ceremony: the console asks
   the browser for a WebAuthn credential (user verification required) and
   stages it with the new lock. It becomes active only when the operator
   presents an assertion from that same key back at the confirm step, the way
   `confirm_lock` already promotes a staged lock. Register at least **two**
   keys (a primary and a spare).
2. **Per change**, in two requests. First the console asks the Worker for a
   challenge for a named operation. The Worker draws **at least 32 fresh random
   bytes** from the Web Crypto random source for that attempt (never derived
   from the request, never reused, never chosen by the page) and keeps them
   server-side, with the verified operator, the environment (the mount path),
   the operation name, the operation id (the `Idempotency-Key`), a hash of the
   request body, and an **expiry of 60 seconds**. The challenge the key signs is
   `SHA-256(nonce ‖ environment ‖ operation ‖ operation id ‖ body hash)`. Then
   the console sends the change with the assertion. The Worker recomputes that
   hash from the request it actually received and the nonce it stored, verifies
   the signature with Web Crypto (Workers supports ECDSA and Ed25519
   verification), and checks that the assertion's origin and relying-party id
   match, that user verification was set, and that the stored challenge belongs
   to this operator, this environment and this operation and has not expired.
   The nonce is **single-use**: it is deleted on the first attempt to use it,
   whether the verification succeeds or not, and an expired or unknown one is
   refused. The randomness gives freshness, the expiry bounds how long a captured
   assertion could matter, and the hash over the operation makes a swapped
   operation fail. This needs a small table for outstanding challenges (the
   operator, the nonce, its context hash and expiry), swept as they expire, which
   is a schema change and carries a migration when built.
3. The change is recorded with which key authorized it (its credential id
   only) in `operator_actions`, never a signature or key material.

Three problems the design must solve before anything is built:

- **The origin is shared.** The relay, both consoles and the staging relay all
  live on `keyquorum.dev`, so a WebAuthn credential is scoped to one host, not
  one path. A staging credential would be accepted for production unless the
  signed challenge names the environment and each environment stores only its
  own credentials. That is the cost recorded in `relay-hosting.md`, surfacing
  again.
- **A key has no display.** Touching it proves presence, not intent. A
  compromised browser can show the operator one operation and ask the key to
  sign another. Binding the operation into the challenge makes a *swapped*
  operation fail verification, but it cannot make the operator read the right
  thing. This must be said in the console and not oversold as protection from
  a compromised browser.
- **Key insertion alone is not authentication.** A credential that does not
  require a PIN would let anyone with the key and a signed-in session act. User
  verification (PIN) and touch are both required, and the Worker rejects an
  assertion whose user-verified flag is not set.

### B. The relay's signing key on a YubiKey: not feasible

The relay signs unattended, for every client challenge and every sealed issue,
from a Durable Object. A YubiKey sits in a person's hand, needs a touch, and
cannot be reached from a Worker. The relay's identity remains the pair of
Worker secrets (`relay-secrets.md`), set by the operator and never in source
control, and the guided setup in the console explains this.

### C. The provider-root key on a YubiKey: possible, not recommended now

An Ed25519 root key can live in the PIV application on firmware 5.7.4 or later
and sign `provider.kqcert` through a smart-card interface. It needs a local
helper and a change to `host certify` (an external-signer path), so the offline
boundary is preserved but new code touches the most sensitive operation. A key
generated on the device cannot be exported, so there is **no backup**: losing
it loses the root, and clients compile the root's public key in, so recovery
means shipping new clients. A key imported from an offline file is as exposed
as the file was. Until that trade-off is decided on its own, the root stays a
file on an offline machine.

### D. Opening a `.kqkey` or a `.kqpb` with a YubiKey: out of scope

This would need X25519 in PIV or OpenPGP and a helper, and personal credential
ownership works today. It is listed so the boundary is explicit: a person's
sealed credentials are theirs and are not part of the operator's setup.

## Enrolment, confirmation, recovery and revocation (for A)

| Topic | Rule proposed |
| --- | --- |
| Enrolment | Staged with the lock, confirmed by an assertion from the same key (over a fresh, expiring, single-use challenge like any other), at least two keys, each labelled by the operator. A registration alone changes nothing, and enforcement stays off until at least two keys have each confirmed. |
| Explicit confirmation | Every authorized change needs user verification (PIN) and a touch, on the exact operation the server built the challenge for. Never "a key is plugged in". |
| Lost or damaged key | While enforcing, use the spare. If every key is lost there is **no lock-only fallback**: one would let anyone holding the lock defeat the key. The way out is the same unbuilt, untested recovery as a lost lock (below), which clears the enrolled keys and returns to lock-only. Enrol at least two keys and keep them apart (three if one site could be lost). |
| Lost operator lock | Not solved today and not claimed: a lost lock on the Cloudflare relay has no recovery path (`relay-deployment.md`, "Operator console", "Lost operator lock"). A hardware key does not fix that, and enforcement makes the gap matter more, because a lost key and a lost lock are both unrecoverable from the console. |
| Revocation | Removing a key is itself a gated change (lock plus a remaining key), recorded in `operator_actions` with the credential id. A removed credential never authorizes again. Removing the last enrolled key, or turning enforcement off, is also gated by the lock **and** a working key, so a stolen lock alone cannot downgrade it. |
| Backup | A FIDO2 credential cannot be exported from the key. The backup is the second enrolled key, kept apart from the first. |

### Enforcement and recovery

Two states, and the transitions between them are explicit, so recovery is never a
bypass:

1. **Lock only** (today, and the state of an operator who has enrolled nothing).
   Every gated change needs the lock.
2. **Enforcing.** Every gated change needs the lock **and** a fresh assertion
   from an enrolled key. There is no third path in which the lock alone, or a key
   alone, is enough.

Moving from 1 to 2 is itself a gated change, allowed only once at least two keys
are enrolled and each has produced a confirming assertion. Moving from 2 to 1 (or
removing the last key) needs the lock and a working key, so downgrading is no
easier than acting. The only road from 2 back to 1 without a working key is the
recovery for a lost lock: restore the Durable Object's storage from a backup, or
apply a reviewed migration that clears the lock and the enrolled keys, then
repeat the setup. **That procedure is not built or tested** (`relay-deployment.md`
says the same for the lock), so a mandatory hardware requirement should not be
switched on until it is, or until the owner has accepted that losing every key
means a recovery by hand.
| Offline root | Unchanged. No part of A reaches the root key or the root ceremony. |

## What stays true if A is ever built

- Access one-time PIN plus security-key MFA remains required to reach the
  console.
- No private root key, relay private key, token or operator-lock value appears
  in a screenshot, log, commit or issue; the assertion and the credential id
  are not secrets, but the lock still is.
- Issuance remains blocked until the relay has a trusted identity and the lock
  exists (`setup-state.js`; the relay itself enforces the identity and the lock).
- Tests live in their own files, the wire and storage changes carry a
  migration, and this document and `soc2-controls.md` are updated in the same
  change.

## Sources

Read 2026-10-07 through a web search tool; the pages themselves were **not
fetched** (the sandbox blocks `docs.yubico.com` and `w3.org`), so the lines
below are summaries of what the search returned, not verbatim quotes.
Re-verify before relying on a number.

| Claim | Source |
| --- | --- |
| PIV supports Ed25519 and X25519 on firmware 5.7.4 and later, beside P-256, P-384, RSA | https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html and https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html |
| FIDO2: ES256 on all firmware, EdDSA and `hmac-secret` from 5.2 | https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html and https://support.yubico.com/hc/en-us/articles/360016649319-YubiKey-5-2-enhancements-to-FIDO-2-support |
| A WebAuthn assertion signs `authenticatorData` with the hash of `clientDataJSON`, which carries the challenge and origin; user verification is bit 2 of the flags | https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/WebAuthn_Client_Authentication.html and https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion |
| Signing arbitrary data through the challenge is a recognised pattern, with limits | https://developers.yubico.com/WebAuthn/Concepts/Using_WebAuthn_for_Signing.html |
| Workers Web Crypto verifies ECDSA and Ed25519 signatures | https://developers.cloudflare.com/workers/runtime-apis/web-crypto/ |
