# MongoDB as the production store: decision record and plan for approval

Status: **proposed. Nothing is built.** The owner asked (2026-10-07) for MongoDB,
through the official `mongodb` Rust driver, to be the production store for the
relay's data and for the REST delivery of `.kq*` file data. That reopens the
Cloudflare-only decision (#88, `relay-hosting.md`, "MongoDB"). This records what
the change would be, what it costs, and the questions that must be answered
before code, so the owner approves the shape rather than discovering it.

A correction to the history, for the record: the removed backend (`relay::mongo`,
`MongoRelayStore`) did use the official driver (`mongodb` 3, sync API,
`rustls-tls`). AWS was dropped for cost and support burden; MongoDB was retired
in the same change because the planned host was a Worker, where the driver cannot
run. It was not a different client.

## Why the old backend cannot simply be restored

1. **The store grew.** `RelayStore` had 35 methods when `MongoRelayStore` was
   written (1,602 lines plus tests); it has 67 now. The operator console added
   customers, licences (immutable statement versions), issuance, per-key
   activity and the operator action log, and the device mailbox, directory and
   sealed key delivery were added beside the original mailbox.
2. **The seam moved.** Rules now live in table modules that take `&dyn Sql`
   (`audit`, `mailbox`, `device_mail`, `org_tree`, `device_directory`,
   `key_delivery`, `issuance`, `licence`, `customer`, `activity`,
   `operator_log`), and `SqlRelayStore<S>` is the one implementation. Rule 1 of
   the architecture is that **a backend re-implements no rule**
   (`CLAUDE.md`, `RelayStore`). The old Mongo store re-implemented them row by
   row, which is exactly what that rule now forbids. SQL strings cannot run on
   MongoDB, so the existing modules cannot be reused unchanged.
3. **Atomicity.** A key mint, its audit row and its letter are one unit of
   work, and the audit hash chain needs one serialised writer
   (`src/relay/audit.rs`). On MongoDB that means multi-document transactions,
   which need a replica set (Atlas has one), with retry on transient errors and
   a compare-and-set on each audit head, and `Error::StoreCommitUnknown` where a
   commit's result is lost. The old store solved this; it has to be solved again
   over a larger surface.
4. **The driver cannot run on a Worker** (needs tokio and raw TCP; `build.rs`
   refuses it on wasm32; the Atlas Data API ended 30 Sep 2025). So a
   MongoDB-backed relay is a native process. Cloudflare can still sit in front
   of it (DNS, TLS, Access for the console, rate limiting) but cannot run it.

## The two ways to build it

**A. A repository seam (recommended if this goes ahead).** Replace the `Sql`
seam, for the tables that matter, with a small set of typed repository traits
(one per table module: audit, mailbox, key, customer, licence, activity, ...)
that hold *no rule*. The rules (hash chaining, routing, idempotence, licence
versioning) are rewritten once against those traits; there are two
implementations, SQLite (the reference) and MongoDB (the official driver).
Cost: a refactor of roughly every file in `src/relay/` that issues SQL, and the
conformance suite (`relay::store::conformance`) must pass on both. Weeks.

**B. A second, MongoDB-only rule set.** A `MongoRelayStore` that implements
all 67 methods itself, as the old one did. Faster to write, but it duplicates
every rule, the audit chain and the licence versioning among them, and breaks
the "no backend re-rolls a rule" requirement; two implementations drift. Not
recommended.

## What stays, what goes, what is decided by the owner

Stays regardless: the offline provider root, the relay key and certificate
(never in MongoDB), the operator lock (hash only), the audit anchors and
checkpoints the operator keeps off the relay, sealed envelopes the relay cannot
open, and the rule that a bearer is never stored (only its SHA-256).

Needs an owner decision before any code:

1. **Where does the native relay run?** AWS was dropped for cost and support
   burden. Options: a small VM at another provider, a managed container, or
   Cloudflare Containers (a Cloudflare-hosted container fronted by the Worker;
   its fit, limits and cost need checking on the owner's account). This is the
   real cost of the change and it is not estimated here.
2. **Where does MongoDB run?** Atlas (managed, a second vendor and bill; needs a
   replica-set tier for transactions) or self-hosted (a second machine to
   operate, back up and patch).
3. **What happens to the Worker and Durable Object relay?** Keep it as a
   second, supported backend (more code and tests forever), keep it only as a
   public edge proxy to the native host, or retire it (the public Worker, the
   Durable Object, `workers/src/sql-adapter.js`, the wasm build and their CI
   would be removed, and `docs/operator/relay-hosting.md` rewritten).
4. **Secrets.** The MongoDB connection string carries a password. It would come
   only from a file (`--mongodb-uri-file`, `KEYQUORUM_MONGODB_URI_FILE`), never
   a flag value or raw environment variable, read with a bound and zeroized,
   exactly like the operator lock (`src/cli/host_env.rs`), and TLS to the
   cluster is required.
5. **Data in scope.** The relay stores sealed letters, public trees and key
   hashes. "kq file data" delivered over the REST API is those sealed letters
   and public artifacts; private files are never stored, and no `.kq` private
   material is ever written to MongoDB.

## Plan, once approved (stages, each its own reviewed change)

1. **Seam.** Introduce the repository traits and move the SQLite store behind
   them with no behaviour change; the conformance suite and every existing test
   stay green.
2. **MongoDB repositories** over the official driver, transactions with retry,
   CAS audit heads, unique indexes as the replay guard, TTL index for letter
   expiry; the same conformance suite on a real MongoDB in CI.
3. **Host.** `host serve` with the MongoDB store, `--mongodb-uri-file`,
   readiness probe that answers only when the store does, graceful shutdown;
   the admin console reaches it as a native service, not a Durable Object.
4. **Deployment** on the host chosen above, with the SOC 2 control map, the
   operator runbook, backup and restore drill, and the dependency policy
   (`deny.toml` for the driver's licences, `cargo audit`) updated.
5. **Migration and retirement** of whatever the owner decides for the Worker.

## What this record does not claim

That MongoDB is cheaper, faster or safer than the Durable Object path; the
reasons recorded in #88 (second vendor, one writer by construction, no tokio on
Workers) still hold and are the cost of this change. That any code for it exists.
Or that the restore drill, cost measurement or a deployment has been done.
