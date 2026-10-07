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

Be clear about the gain. A letter is capped at 1 MiB (`MAX_ENVELOPE_BYTES`) and a
row holds 2 MB, so R2 is not needed to *fit* a letter. What it buys is capacity
and cost: the Durable Object's 10 GB limit and its storage price, not R2's, bound
the letters. It also leaves room, later, for sealed deliveries larger than 1 MiB,
which would need their own decision (client limits, `MAX_RESPONSE_BYTES`, a new
cap) and is not done here.

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
* No larger-than-1 MiB letters, no backup or export of the bucket, and nothing
  off Cloudflare (the single-vendor risk in `relay-hosting.md` is unchanged).
* Migration: an existing Durable Object database would need the two new columns;
  none exists yet (nothing is deployed), and the native file gets them in
  `relay::migrate`.
