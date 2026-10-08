# Sealed backups of the relay's database in R2

Status: **built in the relay core, the Durable Object's JavaScript, the host
tooling and the deploy configuration; tested natively and with fakes; not
deployed, and the Durable Object path has not been run end to end** (the
WebAssembly build is not available where this was written; CI's `workers` job
builds it). Written 2026-10-07 at the owner's request, beside `r2-blobs.md`.

## What it is for, and what it is not

The platform already keeps the Durable Object's storage for 30 days and can
restore it to a point in time (SQLite-backed objects, `getBookmarkForTime` and
`onNextSessionRestoreBookmark`; Cloudflare, Durable Objects storage API). That
is the first safety net and this does not replace it. These backups add:

* a copy that is **sealed to a key only the operator holds**, so the customer
  names, licence terms, key hashes, letters and audit chain inside are unreadable
  to R2, to Cloudflare and to the relay itself;
* a **signed manifest**, so the operator can prove a backup came from the relay,
  is whole and was not altered;
* a **restore you can run offline**, into a new database, which re-walks the
  audit chains before you trust it.

It is not off Cloudflare. The bucket lives in the same account, so a Cloudflare
account compromise or outage still reaches it. A backup you keep elsewhere is the
operator's to make: download one (`wrangler r2 object get`, rclone or the
dashboard) and store it. A retention rule or object lock on the bucket, set in
the dashboard, is what stops a compromised Worker deleting them; the Worker
itself prunes to the newest few.

## What is in a backup

A logical dump of **every table** in the Durable Object's database: keys (their
SHA-256 hashes, never a bearer), customers, licences and their immutable
versions, delivery records, activity, the operator action log, both
hash-chained audit tables and their signed anchors, the public trees and the
letters small enough to sit in their rows.

Not in it: the relay key and certificate (Worker secrets), the operator lock
(only its hash is stored, and that is in the database), the provider root, and
**the sealed letters held in the `LETTERS` bucket**. Their rows are in the
backup (naming the objects); the objects are not. That is deliberate: they are
transient mail, immutable and content-addressed, and copying them would double
the storage. A restore does not bring those rows back (see below).

## How a backup is made

The alarm (hourly) takes a backup when none has been made for `BACKUP_EVERY_HOURS`
(default 24):

1. The core builds the **whole snapshot in one synchronous turn**: nothing else
   runs between the first row and the last, so it is a consistent point in time.
   Tables are read by rowid and cut into chunks of about 4 MiB of JSON; each chunk
   is sealed to the backup key (`EXPORT_BUNDLE` type 7); a manifest names every
   chunk by its SHA-256, carries the relay's certificate, and is signed by the
   relay key over a domain-separated preimage and sealed too (type 8).
2. The Durable Object uploads the chunks to `backups/<id>/chunk-NNNNNN.kqbk`,
   each with a SHA-256 checksum R2 verifies, and the manifest **last**. A backup
   without a manifest is incomplete: never counted, never trusted, and removed
   after a day.
3. It keeps the newest `BACKUP_KEEP` (default 14) complete backups and deletes the
   rest. A failure to prune never fails the backup.

The id is `YYYYMMDDHHMMSSmmm-xxxxxxxx`, so backups sort by time.

**The limit.** The snapshot sits in the object's memory while it uploads (128 MB
per isolate, shared with the WebAssembly core), so it is capped: `BACKUP_MAX_BYTES`
(default 16 MiB of plaintext, at most 32 MiB). A larger database is **skipped**
and the status page says so; it is never half-backed-up. The control-plane data
is small; this matters only if very many small letters pile up, which the 30-day
recovery above still covers.

## Setting it up

1. Make the keypair on a machine you trust (not the relay): on the console's
   Status page, while backups are off, "Make the backup keypair in this browser"
   makes it with the relay's own code and downloads `backup.key` and `backup.pub`
   (the page sends and stores nothing); or
   `keyquorum host backup keygen --public-key-out backup.pub --private-key-out backup.key`.
   The private key is written owner-only, never printed, never overwritten. **Keep
   it offline and keep a second copy**: without it no backup can ever be read.
2. Create the buckets with Terraform (`backups_bucket_name`,
   `backups_bucket_name_staging`), private, and set retention or an object lock in
   the dashboard.
3. Set the GitHub environment variable `BACKUP_RECIPIENT` (the public key, 64 hex
   characters; a variable, not a secret) for each environment. The deploy passes it
   as `--var`; it is not in `wrangler.toml`, where the guard refuses a 64-character
   value. Without it, or without the `BACKUPS` binding, no backup is made, and the
   console's Status page says why.

## Restoring

```sh
# download the backup's objects (manifest.kqbk and chunk-*.kqbk) into one directory
keyquorum host backup inspect --dir ./dl --backup-key backup.key
keyquorum host backup restore --dir ./dl --backup-key backup.key --out relay.sqlite
```

`inspect` opens only the manifest and checks it; `restore` creates a new database
and refuses an existing file. Before it writes anything it checks that the manifest
opens with the key, that its signature verifies under the key a certificate signed
by the **pinned provider root** names (unrevoked, valid when the backup was taken),
and that the target has the same tables and columns. It then writes, checking each
chunk against the manifest (SHA-256 and size) as it is read, all in one
transaction, so a bad chunk leaves nothing, and removes the file if anything fails. Afterwards it
re-walks every audit chain and anchor and exits non-zero if one does not hold.

What a restore gives you is a **native relay database** (the reference host's
file): to verify a backup, to read it, or to run the reference host from it.
Putting it back into a Durable Object is not built; for that, use the platform's
point-in-time recovery. Rows that held a letter in object storage are not
restored and are counted.

## Controls (SOC 2)

* **C1.1, CC6.7:** the bucket holds only sealed objects; no key, bearer or
  plaintext is ever in it, the backup key never reaches a Worker, and the
  recipient is a public key.
* **CC6.1, CC6.6:** the bucket is private and bound to the public Worker only; the
  guard refuses the binding in the admin Worker, in a Preview, under another name,
  or the same bucket as the letters, or as production's in staging.
* **PI1.2, A1.2:** a consistent snapshot, per-object checksums, a manifest written
  last, a bounded size, restore checks before a write, and an audit re-walk after.
* **CC7.2, CC7.3:** success, a skip (too large) and a failure are on the Status
  page; a failed backup never stops the housekeeping alarm.

## Not done, and not claimed

* The upload path through the real Durable Object has not run: the wasm build and
  `workers/test/relay-service.test.mjs` need CI's toolchain. The core (snapshot,
  seal, sign, restore, audit re-walk, tamper cases) is tested natively
  (`src/relay/backup/tests.rs`), the uploader against a fake core and bucket
  (`workers/test/backups.test.mjs`), the config in `guard.test.mjs`, the host
  commands' arguments in `src/cli/tests/parse.rs`.
* No restore drill, no cost or storage measurement, no memory measurement of a
  16 MiB snapshot in the isolate.
* No backup of the letters bucket, no copy off Cloudflare, no restore into a
  Durable Object, no incremental backups, and no notification when a backup fails
  beyond the Status page.
