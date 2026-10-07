# Sealed letters in R2: the relay's cloud storage and data relay

Status: **built in the relay core and the Durable Object's JavaScript; tested
natively and with fakes; not deployed, and the Durable Object path has not been
run end to end** (the WebAssembly build is not available where this was
written, so `workers/test/relay-*.test.mjs` could not be run; CI's `workers`
job builds it). This is the owner's decision of 2026-10-07 (the Durable Object
plus R2 for sealed blobs), chosen over MongoDB (`mongodb-production.md`, which
this supersedes as the plan).

## What it does, and what it does not

A letter at least `HOLD_LETTERS_FROM` bytes (default 64 KiB, never below 4096) is
stored in a private R2 bucket (`LETTERS`) instead of in its table row. Smaller
letters, every key, licence, audit row and the public trees stay in the Durable
Object's SQLite, so everything that must be atomic still is. Without the
`LETTERS` binding nothing changes: no letter is held out.

## Letters over 1 MiB

Without R2 a letter is capped at 1 MiB (`MAX_ENVELOPE_BYTES`) and a row holds
2 MB. **With the bucket bound, a bridge letter may be up to 16 MiB**
(`MAX_LARGE_LETTER_BYTES`), which is also the outbox's item cap and the inbox
page budget, so one such letter is always a whole page. Device letters keep 1 MiB.
No new route and no client change: the client already pushes any size raw
(`relay::push_inbox`), the outbox already allows 16 MiB, and the relay used to
answer 413. What changed:

* **Held, always.** The threshold is never above 1 MiB (the core and the Worker
  both clamp it), so a letter that could not fit a row is always held. The cap
  itself is a store property (`RelayStore::max_letter_bytes`): 16 MiB when
  letters are held in object storage, 1 MiB otherwise, so a native host, the lab
  and a Worker without the binding refuse a larger letter as before.
* **Raw only.** Only a raw `POST /inbox` may declare a body above 2 MiB
  (`policy.js` `bodyLimit`, `worker.rs` `map_request`, both checked before a
  body is read). A JSON push (trees, an expiry) stays at 2 MiB, so a large letter
  never rides in JSON and is never base64-decoded inside the 128 MB isolate. A
  large letter therefore carries no trees; the producers that attach trees send
  small org-update letters.
* **Memory.** A push holds the body once in the object, once as the core's copy
  and once as the bytes put in R2 (about 50 MiB at the cap). A pull assembles the
  answer in pieces (a letter's base64 in 3 MiB steps), never one string of the
  whole. Workers have 128 MB per isolate, shared with the WebAssembly memory; this
  has not been measured under load (see "Not done").

## What the bucket buys

Capacity and cost. A letter of up to 1 MiB fits a row, so for those R2 only moves
the Durable Object's 10 GB limit and storage price onto R2's; for letters over
1 MiB it is what makes them possible at all.

The relay still never opens a letter. The bucket holds bytes sealed to their
recipients, and the objects are immutable: the key is `inbox/<sha256>` or
`device/<sha256>`, the same content hash that makes delivery idempotent, so one
letter is one object and a repeat is the same object.

## The two steps, and why

A row and an object cannot commit together. So accepting a large letter is:

1. **The core decides.** It authenticates the key, validates the letter and
   inserts the row *not ready* holding only the 42-byte outer header and the true
   length, and answers with the object key. Nothing has been written to R2, so an
   unauthorised or malformed request can never fill the bucket.
2. **The object stores it.** The Durable Object checks the bytes are the letter
   the core named (length and SHA-256 against the key), puts them in R2 with the
   checksum, then calls `blob_ready`. If R2 refuses, it calls `blob_abort`, the
   row is dropped, and the sender gets 503 and retries; the retry starts clean.

A not-ready row is never listed, counted or offered, so a reader never meets a
letter whose object may not exist. A crash between the steps leaves a not-ready
row; the alarm drops it after an hour. A repeat of a letter whose bytes were
never confirmed asks for them again (it resumes); a repeat of a ready one is a
duplicate, as before.

**Reading** is the reverse: the core lists ready rows with the header and a
reference, the object fetches each held letter from R2, checks its length and
SHA-256 against the key, puts the bytes back and removes the reference. A letter
that cannot be read back, or whose bytes do not match, makes the whole page a
503. A header-only letter is never returned. Paging and the summaries count a
held letter's true size, so the 16 MiB page bound and the console's sizes are
unchanged.

**Deleting** is done by a trigger: whenever a row that holds its letter out of the
table is deleted, by any path (expiry, abort, purge), its key is recorded in
`blob_tombstones`. The alarm hands the keys no live row still names to R2's
delete and then forgets them. Pushes and this sweep run one at a time, so a
letter stored anew can never meet the delete of its own earlier object; a bucket
that is down leaves the tombstones for the next sweep.

## Where each rule lives

| Concern | Owner |
| --- | --- |
| Which letters are held, the row states, tombstones | `src/relay/blob.rs`, `mailbox.rs`, `device_mail.rs`, `schema.sql` |
| The threshold (a store setting; native hosts hold nothing) | `SqlRelayStore::with_blob_threshold` / `RelayCore::hold_letters_from` |
| Moving bytes to and from R2, integrity checks, ordering | `workers/src/blobs.js` |
| The binding and its guard rules | `workers/wrangler.toml`, `workers/scripts/guard.mjs` |
| The buckets | `deploy/cloudflare/terraform/r2.tf` |

The two internal fields (`blob` on an accepted push and on a pulled entry) exist
only between the core and the Durable Object. The Worker removes them before any
client sees a reply, and they are hidden from the OpenAPI schema.

## Controls (SOC 2)

* **CC6.1, CC6.6:** the bucket is private and bound to the public Worker only.
  The guard fails CI if the admin Worker, a Worker Preview or a second binding
  name touches R2, or if staging shares production's bucket. No public-access or
  custom-domain resource exists for it.
* **C1.1, CC6.7:** only sealed bytes are stored; no key, bearer or plaintext ever
  is. Object keys are content hashes, not recipients or labels.
* **PI1.2, PI1.3:** the two-step accept, content-hash keys, checksum on put and
  the read-back check; a not-ready row is invisible; every delete path tombstones.
* **A1.2:** a stale not-ready row is dropped; a sweep is bounded (500 keys, 20
  rounds); a bucket outage fails a push with 503 and never loses a ready letter.

## Not done, and not claimed

* The path through the real Durable Object has not been run: the wasm build and
  `workers/test/relay-service.test.mjs` need CI's toolchain. The core's half is
  tested natively (`src/relay/blob/tests.rs`, `store/tests.rs` over a
  transaction-refusing executor), the object's half against a fake core and
  bucket (`workers/test/blobs.test.mjs`), the config in `guard.test.mjs`.
* No bucket exists. Create both (`letters_bucket_name`,
  `letters_bucket_name_staging`) with Terraform before the first deploy, or the
  deploy fails on the binding; the first staging deploy and a restore drill
  remain to do.
* No measurement of R2 cost, request limits or latency for this workload. The
  per-request cost of a held letter (an R2 put on push, a get per held letter on
  pull) was not estimated and needs the owner's account.
* No measurement of a 16 MiB push or pull against the isolate's memory, or of a
  Worker's request-body limit on your plan (Cloudflare documents the limit per
  plan; a plan below 16 MiB would refuse a large letter before the relay sees it).
* No backup of the letters bucket (the backups in `r2-backups.md` cover the
  database, not the objects), and nothing off Cloudflare (the single-vendor risk
  in `relay-hosting.md` is unchanged).
* Migration: the Durable Object adds `expires_at`, `blob_len` and `blob_ready` to
  an existing `mailbox` or `device_mailbox` table each time it opens
  (`mailbox::ensure_blob_columns`, called from `RelayCore::new`); the native file
  gets the same in `relay::migrate`. Nothing is deployed, so no existing Durable
  Object has been through it.
