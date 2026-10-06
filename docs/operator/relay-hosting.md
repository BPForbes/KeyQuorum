# Hosting the KeyQuorum relay: Cloudflare only

This is the hosting plan and decision record for issue #88. The owner has
decided that Cloudflare is the sole hosting provider for the mailbox relay,
because of cost. This document records that decision, the Cloudflare
Workers design that follows from it (planned, not yet built), the controls
the earlier AWS-first plan specified and where each one lands on
Cloudflare, the gaps that remain, and the launch prerequisites from the
architecture review of PR #87 revalidated against the code as it is today.
It is written for whoever operates the relay, next to `relay-deployment.md`
(how to run it) and `relay-secrets.md` (what is secret). It is not
customer-facing.

The earlier plan chose AWS EC2 first. It was never merged and is dropped;
it is recoverable from commit `4ec4e69` (also `refs/pull/89/head` on
GitHub). Its structure and every control are kept here, with the platform
swapped. Where the old text was host-independent it is carried over with
only the platform nouns changed.

Status at the time of writing (2026-10-06):

| Item | State |
| --- | --- |
| Hosting decision | **Cloudflare only.** No other hosting provider. Reason: cost (owner decision, recorded in the #88 comment). |
| Cloudflare Workers relay (Path B) | **Planned, not implemented.** Status: **Adopt, subject to the feasibility spike (PR 3).** The reasons and the unknowns the spike must settle are in [The Workers relay](#the-workers-relay-planned-not-implemented). |
| Native `keyquorum host serve` | **Kept as the dev, test and reference host.** `SqliteRelayStore`, `src/relay/server.rs` and `host keys` stay in the code. It is not a production deployment path. |
| Deployment pipeline and Cloudflare Terraform | **Planned (PR 2); not in the repository yet.** Described in [Provisioning and the deployment pipeline](#provisioning-and-the-deployment-pipeline-planned). |
| Live deployment, restore test, overload test | **Not done.** There is nothing to deploy until the Workers relay exists; they need the operator's Cloudflare account and run against a real deployment. The [acceptance checklist](#acceptance-checklist) says which rows this document settles and which the deployment must. |

Nothing here is deployment approval, and no SOC 2 mapping below claims
compliance; `docs/soc2-controls.md` says what the software provides and
what the operator must still do.

## Sources

The review rules ask for a quoted source behind each requirement. The
container this plan was written in could not fetch `developers.cloudflare.com`,
`docs.aws.amazon.com` or `sqlite.org` directly (the egress proxy refused
them), so each source below is marked by how it was read:

- **verbatim (issue #88):** the sentence is carried word for word from
  issue #88, which quoted it from the page named.
- **search summary:** the page was found and summarised by a web search on
  2026-10-06; the wording in this document is a paraphrase of that summary,
  not a quotation. Re-read the page before relying on a number.
- **not retrieved:** named for the reader; nothing in this document rests on
  it alone.
- **not retrieved (from memory, verify):** a statement about Cloudflare's
  platform that the author believes but could not retrieve. Wherever the
  text below relies on one, it says "from memory, verify" next to the
  statement. Confirm each against the named page before the design depends
  on it; the spike (PR 3) does so for the ones it measures.

| Source | URL | Read as |
| --- | --- | --- |
| Cloudflare, WebAssembly: "You can use WebAssembly to … write an entire Cloudflare Worker in Rust." | https://developers.cloudflare.com/workers/runtime-apis/webassembly/ | verbatim (issue #88) |
| Cloudflare, Rust on Workers: every crate must build for `wasm32-unknown-unknown`; threaded runtimes such as tokio are not supported (runtime-agnostic pieces like `tokio::sync` are); an Emscripten target with Tokio support exists as an experimental preview. | https://developers.cloudflare.com/workers/languages/rust/ | search summary |
| Cloudflare, Workers limits: request body 100 MB on Free and Pro, 200 MB Business, 500 MB Enterprise; CPU time 10 ms per request on Free, 30 s by default (up to 5 min) on Paid. | https://developers.cloudflare.com/workers/platform/limits/ | search summary |
| Cloudflare, Workers limits: isolate memory (128 MB), compressed bundle size, number of Worker secrets, subrequest and CPU limits per plan. | https://developers.cloudflare.com/workers/platform/limits/ | not retrieved (from memory, verify) |
| Cloudflare, Durable Objects limits: a SQLite-backed Durable Object holds up to 10 GB; a row, string or blob at most 2 MB; writes past the limit fail with `SQLITE_FULL`. | https://developers.cloudflare.com/durable-objects/platform/limits/ | search summary |
| Cloudflare, Durable Objects SQLite storage API | https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/ | not retrieved (named in issue #88) |
| Cloudflare, Durable Objects: `transactionSync` for synchronous transactions over SQL storage, `strftime('now')` and `ALTER TABLE` behaviour, alarms for scheduled work, migrations including `deleted_classes` and renames (a deleted class destroys its data), and which plan SQLite-backed objects need. | https://developers.cloudflare.com/durable-objects/ | not retrieved (from memory, verify) |
| Cloudflare, Durable Objects point-in-time recovery for SQLite storage: the retention window and restore procedure. | https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/ | not retrieved (from memory, verify) |
| Cloudflare, data at rest: Durable Object storage is encrypted at rest by Cloudflare, with no customer-managed key. | https://developers.cloudflare.com/durable-objects/ | not retrieved (from memory, verify) |
| Cloudflare, HTTP request headers: `CF-Connecting-IP` holds the one connecting client address; `X-Forwarded-For` is appended to, so it may begin with whatever the client sent. | https://developers.cloudflare.com/fundamentals/reference/http-headers/ | search summary |
| Cloudflare, default cache behaviour: with Origin Cache Control on (the default on Free, Pro and Business), a request carrying `Authorization` is not cached unless the response's `Cache-Control` says `public`, `s-maxage` or `must-revalidate`. | https://developers.cloudflare.com/cache/concepts/default-cache-behavior/ | search summary |
| Cloudflare, Workers rate limiting binding and zone rate-limiting rules: configuration, per-key counting, and accuracy. | https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/ | not retrieved (from memory, verify) |
| Cloudflare, Workers custom domains, `workers.dev` and preview URLs can be switched off per Worker; service bindings call another Worker without a public route. | https://developers.cloudflare.com/workers/ | not retrieved (from memory, verify) |
| Cloudflare, Workers secrets (`wrangler secret put`): a secret is not readable back through the API and survives a deploy; Workers versions and `wrangler rollback`. | https://developers.cloudflare.com/workers/configuration/secrets/ | not retrieved (from memory, verify) |
| Cloudflare Access, self-hosted applications and policies: a policy can require MFA in addition to the identity provider. | https://developers.cloudflare.com/cloudflare-one/access-controls/policies/common-policies/ | search summary |
| Cloudflare Access audit logs, and Cloudflare account audit logs. | https://developers.cloudflare.com/cloudflare-one/insights/logs/ | not retrieved (from memory, verify) |
| Cloudflare, scoped API tokens, Notifications (Worker and Durable Object error alerts), Workers Logs. | https://developers.cloudflare.com/fundamentals/api/get-started/create-token/ | not retrieved (from memory, verify) |
| Cloudflare, R2 bucket lock (retention rules) | https://developers.cloudflare.com/r2/buckets/bucket-locks/ | not retrieved (from memory, verify) |
| Cloudflare Terraform provider (`cloudflare/cloudflare`): resources for Workers custom domains, DNS, Access applications and policies, rulesets, R2 buckets, notification policies. | https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs | not retrieved (from memory, verify) |
| MongoDB, Atlas Data API and custom HTTPS endpoints: end of life and deprecation (end of life 30 Sep 2025). | https://mongodb.com/community/forums/t/mongodb-atlas-data-api-and-custom-https-endpoints-end-of-life-and-deprecation/296686 | search summary (2026-10-06) |
| AICPA, 2017 Trust Services Criteria (2022 points of focus), A1.3: "The entity tests recovery plan procedures supporting system recovery to meet its objectives." | https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 | verbatim (issue #88) |

Code cited below was read in this repository at the commit this document
was written in; the file and item are named each time.

## The decision

**Cloudflare is the only hosting provider for the relay, and the relay runs
as a Cloudflare Worker over one Durable Object.** The decision is the
owner's and rests on cost: one vendor, one bill, no virtual machine to
patch, size or snapshot. It is adopted subject to the feasibility spike
(PR 3), because the Workers relay does not exist yet and several platform
facts it depends on are unverified here.

What exists today is a Tokio and axum server
(`src/bin/keyquorum/host.rs`, `serve`, starts it with `axum::serve`) over
`RelayStore` (`src/relay/store.rs`), whose reference backend is one SQLite
file behind one connection (`SqliteRelayStore`). It stays, as the dev,
test and reference host: the conformance suite, the server tests and
single-machine experiments use it. It is not a production deployment path,
and no document, chart or unit in this repository describes one.

| | AWS EC2, native relay (dropped) | Native relay behind the Cloudflare edge (not adopted) | Cloudflare Workers + Durable Object (Path B) |
| --- | --- | --- | --- |
| Code change | None. | None in the relay; proxy and tunnel configuration. | A new fetch adapter and a new `RelayStore` backend; see below. |
| Where the relay and its database run | One virtual machine and a block volume at a second vendor. | The same machine; Cloudflare in front. | Cloudflare's network; state in one SQLite-backed Durable Object. |
| Operational ownership | The operator: OS, reverse proxy, relay, backups, restores. | Same, plus a tunnel to keep alive. | Cloudflare runs the platform; the operator owns the Workers, the Durable Object data, secrets, backups and migrations. |
| Vendors and bills | Two (the VM provider and Cloudflare, if the edge is wanted). | Two. | One. |
| Limits that matter | Instance size and volume throughput; one process, one database. | The above, plus edge body and read-timeout limits. | 10 GB per Durable Object; 2 MB per row; isolate memory and CPU time per request; no tokio. |
| Estimated monthly cost | A machine, a volume and snapshots, billed separately; rejected on cost. | The same plus the edge plan. | A Workers plan plus Durable Object storage and requests; not estimated until the spike measures them (PR 3 records the estimate and the plan required). |
| Implementation effort | Days. | One or two days on top. | Weeks: adapter, store, conformance, custody, admin Worker; see the estimate below. |
| Decision | **Dropped.** | **Not adopted.** It needs the machine, so it keeps the second vendor. | **Adopt, subject to the feasibility spike (PR 3).** |

### MongoDB

MongoDB was considered for cloud storage and for moving data out, and is
kept out; the `mongodb` feature, `relay::mongo`, the `--mongodb-*` flags and
`.github/workflows/mongodb.yml` are removed in the same change as this
document.

1. **It cannot be reached from a Rust Worker.** The `mongodb` crate needs
   tokio and raw TCP, and `build.rs` refuses it on wasm32. The route that
   used to give Workers an HTTPS path to MongoDB, the Atlas Data API,
   reached end of life on 30 Sep 2025 (MongoDB forum notice, search
   summary 2026-10-06). Cloudflare's Rust support with tokio is only an
   experimental Emscripten preview (Cloudflare, Rust on Workers, search
   summary).
2. **It adds a second vendor and a second bill**, which defeats the cost
   reason for choosing Cloudflare and contradicts "sole provider".
3. **Its purpose is gone.** `MongoRelayStore` existed so several replicas
   could share one database. One Durable Object is the single writer by
   construction.
4. **Splitting a unit of work breaks guarantees.** A key mint, its audit row
   and its letter must be one atomic transaction, and the audit hash chain
   needs one serialised writer (`src/relay/audit.rs`). Spread across a
   Durable Object and an external database, both are lost.

If archival or off-Cloudflare copies are ever needed, the same-vendor
option is R2, added only when there is a concrete need.

### Single-vendor risk

With one provider, a Cloudflare outage, a Cloudflare account compromise or a
Cloudflare policy change affects the relay and its administration
together. The mitigations are the ones the rest of this document specifies:
the offline provider root, the audit checkpoints and exports the operator
keeps off Cloudflare, scoped tokens and Access with MFA, and a database
schema (`schema.sql`) that the native reference host can open, so an export
is not locked to the platform. The last is an intent of the design, not a
tested exit path; the restore drill proves it for the export the operator
actually takes.

## Gaps and limits, recorded

- **No customer-managed key for Durable Object storage.** Cloudflare
  encrypts the storage at rest and holds the keys (Cloudflare, data at
  rest, from memory, verify); the operator cannot bring or rotate one. The
  earlier AWS design had a customer-managed key, and this is a step down
  from it. It is mitigated by what the database holds: letters are sealed
  envelopes the relay cannot open, and the tables hold bearer hashes
  (`hex(SHA-256(raw))`), certificates, public topology and sealed bytes,
  never a wrapped share or a private key. The relay's own signing key is a
  Worker secret, not a database row.
- **Cloudflare terminates TLS and can see bearers in transit.** A bearer
  travels in a request header over TLS that ends at Cloudflare's edge. This
  is a subprocessor point for `docs/soc2-controls.md`, not a defect the
  relay can remove; KeyQuorum's own trust does not rest on it, because
  clients verify the relay by the provider challenge (below), and a
  bearer's exposure is bounded by scope, expiry and revocation.
- **The Cloudflare account is now the root of hosting trust.** Whoever can
  edit Workers, Access or the zone can change what runs. The roles table
  below and MFA on every account user are the controls; they are the
  operator's, as `docs/soc2-controls.md`, "Operator responsibilities",
  says.
- **One Durable Object, one writer, 10 GB.** Acceptable for one
  organization or one group of mutually trusting organizations; there is no
  sharding, because it would break the single audit chain.

## Provisioning and the deployment pipeline (planned)

None of this exists in the repository yet; PR 2 adds it, and nothing here
may be read as a statement that it does.

- **Infrastructure as code:** `deploy/cloudflare/terraform/`, with the
  `cloudflare/cloudflare` provider (from memory, verify): custom domain and
  DNS, Access applications and the MFA policy for the admin Worker, the
  rate-limit and WAF rules, an optional R2 bucket for archival copies, and
  notification policies. CI runs `terraform fmt -check` and `terraform
  validate`, which need no credentials, and a committed
  `.terraform.lock.hcl` pins the provider. The operator runs `terraform
  apply` locally with their own Cloudflare credentials; those never enter
  GitHub or an agent session.
- **Workers:** `workers/` holds the wrangler configuration, with no
  `[vars]` entry that holds anything secret, a `package.json` and
  `package-lock.json` with wrangler pinned, and, until the relay exists, a
  stub fetch handler that answers `GET /health` only.
- **CI:** `.github/workflows/workers.yml` with the jobs `workers build`
  (pull requests and `main`: locked wasm32 build, `npm ci`, a `wrangler
  deploy --dry-run` bundle, a bundle-size assertion, and a guard that fails
  if the wrangler configuration or the bundle holds key material),
  `workers deploy staging` (`main` only, GitHub environment
  `cloudflare-staging`, a smoke test of `/health`, of 401 on
  unauthenticated routes and of the absence of a mint route), and `workers`,
  the one stable required check. Production is a separate job in GitHub
  environment `cloudflare-production` with a required reviewer. Actions are
  pinned by full SHA and the workflow runs with `contents: read`; it uses
  the lockfile-pinned wrangler rather than a third-party deploy action.
- **Secrets:** the relay private key, `provider.kqcert` and `provider.kqrl`
  are Worker secrets that the operator sets locally with `wrangler secret
  put`; they are never GitHub secrets and survive a deploy. The `kql_…`
  operator lock and the provider-root private key are never on a Worker. The
  only Cloudflare credential in GitHub is the narrow Workers-deploy token
  (Workers Scripts edit only) and the account id, scoped to the two
  environments.

### Roles: least privilege

| Role | Who | Allowed | Not allowed |
| --- | --- | --- | --- |
| Deploy | the Workers-deploy API token in the GitHub environments (production behind a required reviewer) | edit the Workers scripts | read Worker secrets or Durable Object data, change Access, DNS, WAF rules or the Terraform-managed zone settings |
| Operate | the operator's day-to-day identity, through Cloudflare Access with MFA | reach the admin Worker (list, revoke, mint, rotate, events, checkpoint), read Access and account audit logs and the notifications | change Access policies, change the zone, delete Durable Object data |
| Backup | a write-only export credential (an R2 token limited to the archive bucket's write, if the optional bucket is used; otherwise none, and the operator pulls exports and checkpoints) | write an export object | read or delete other objects |
| Restore | a separate identity used in the restore drill, in a test account or a test Worker | create and fill a test Durable Object from an export, run the verification | reach the production Workers, hold the production relay key |

Record each role's token scopes and policy with the deployment;
`docs/soc2-controls.md`, "Operator responsibilities", names these as the
operator's controls.

## The Workers relay (planned, not implemented)

**The relay does not run on Workers today.** The `provider` feature (axum,
tokio, rusqlite) cannot build for wasm32, and `build.rs` refuses it there.
What is portable is `relay::service::dispatch` (`src/relay/service.rs`), the
synchronous, runtime-independent request router that the browser lab
already runs in process on wasm32. The Workers relay is therefore a new
store and a thin fetch adapter around it, not a rewrite. Everything in this
section is a design, to be proven by the spike.

### Architecture

- **Public Worker `keyquorum-relay`.** A fetch handler that maps a request
  to `RelayHttpRequest` (`src/relay/client.rs`; its `method` and
  `content_type` would have to become static literals), enforces the
  2 MiB body cap (`MAX_ENVELOPE_BYTES` is 1 MiB per envelope), reads
  `Authorization: Bearer` or `x-api-key`, applies a rate limit keyed on
  `CF-Connecting-IP`, sets `Cache-Control: no-store` on every response,
  answers `/health` (the Worker alone) and `/ready` (only when the Durable
  Object answers), and calls the Durable Object. It does no redirects and
  no challenge on API paths: the client uses `max_redirects(0)` and treats a
  503 from `/provider-identity` as an untrusted relay (`src/relay/client.rs`,
  `http_agent_config`, `authenticate_provider`).
- **One SQLite-backed Durable Object.** It holds the whole relay and runs
  `relay::service::dispatch(&DoRelayStore, Some(&identity), &req)`. One
  object is the single writer, which the audit hash chain, the key tables
  and the key-delivery letters need because they are written together
  (`src/relay/audit.rs`); the synchronous `RelayStore` trait fits only
  inside it, where SQL execution is synchronous.
- **`DoRelayStore`.** A new `RelayStore` backend in `src/relay/`, generic
  over a small `SqlExec` seam: rusqlite implements it for native tests, and
  the Durable Object SQL API for Workers. It reuses `schema.sql` and the
  rules every backend already shares: `audit::{entry_hash, verify_table,
  sign_anchor, sign_checkpoint}`, `mailbox::{routing_of, bound_page}`,
  `device_mail::check_package`, `org_tree::merge_into_existing`,
  `device_directory`, the API-key hashing, and the `key_delivery::*_with`
  flows through `DeliveryOps`. It re-rolls no rule. It must pass
  `relay::store::conformance` (run against `DoRelayStore` over rusqlite in
  `cargo test`, as `SqliteRelayStore` does today) before it is trusted. If
  the existing modules' direct use of `rusqlite::Connection` is too wide to
  put behind `SqlExec`, the fallback is to reimplement key lifecycle,
  letter filing and ids over the Durable Object and reuse the pure
  functions; the spike decides.
- **Clock.** The native host's time source uses `SystemTime`, which cannot
  run on wasm. A clock is injected and times are passed into the SQL that
  uses `'now'` today.
- **Admin Worker `keyquorum-relay-admin`.** No public route (`workers.dev`
  and preview URLs off, from memory, verify), behind Cloudflare Access with
  MFA, and service-bound to the same Durable Object (from memory, verify).
  It exposes list, revoke, mint, rotate, events and checkpoint, and nothing
  else. For a mint or rotation the Durable Object seals the `.kqkey` with
  the relay key and returns only sealed bytes; the native `host keys` CLI
  writes the file. A response lost after the commit can leave a key with no
  bundle; that is handled as `Error::StoreCommitUnknown` already is
  (`src/bin/keyquorum/host.rs`: keep what was written, check `keys list`
  and `keys events` before retrying).
- **Which routes are public.** Customer routes (`/inbox`, `/keycheck`,
  `/provider-identity`, `/devices/*`, `/trees/*`, `GET /audit/api-keys`)
  are on the public Worker. The operator routes (`/api-keys*`, the full
  `/audit/*`, anything that mints) are on the admin Worker only, and the
  public Worker serves no console and no `/swagger-ui/*`. Whether an admin
  API key may still revoke over the public Worker, as it can on the native
  router today, is a PR 4 decision; until it is made, the public Worker
  does not route it.
- **Secrets on the Worker.** The relay private key, `provider.kqcert` and
  `provider.kqrl`, as Worker secrets (not readable back through the API,
  survive a deploy; from memory, verify), used by the same `signing` code,
  so signatures, sealed key delivery (`KQPB` kind 20, `.kqkey`) and audit
  anchors stay byte-compatible: the formats are the crate's, not the
  host's. Never on a Worker: the provider-root private key and the `kql_…`
  operator lock.
- **Build guards.** A new `workers` cargo feature excludes tokio and axum.
  `build.rs` and `lib.rs` keep refusing `lab` with `provider` and also
  refuse `workers` with `provider` or `lab`; the new dependency (the
  `worker` crate) must clear `deny.toml` (licences, no git sources, no
  yanked) before it lands.
- **Backups and migration.** The Durable Object's point-in-time recovery
  (from memory, verify) plus operator-run `host keys checkpoint` files kept
  off Cloudflare, with a restore drill into a separate test Worker (below).
  Rollback of the code is a Worker version rollback (`wrangler rollback`,
  from memory, verify); the existing schema-version guard refuses a
  database written by a newer `SCHEMA_VERSION`. Nothing is deployed
  anywhere today, so there is no data to migrate.

### What the spike must measure (PR 3)

Each of these is unverified here, and each has a stated consequence:

| Unknown | What to measure | If it fails |
| --- | --- | --- |
| Build and bundle | the `workers` feature builds for wasm32 with the SQLite-facing code and fits the Workers bundle size limit (from memory, verify) | reduce the dependency set, or reopen the design with the owner |
| Durable Object SQLite behaviour | `transactionSync` replaces `BEGIN IMMEDIATE` for each unit of work; `strftime('now')` and the schema and migration statements (`ALTER TABLE` in `migrate`) work; `getrandom` works under the Workers Rust runtime; point-in-time recovery window and restore | pass times in explicitly; rewrite the migration statements; if recovery cannot meet the 1 h RPO, add a cron export |
| Peak memory | a 16 MiB inbox page (`mailbox::MAX_INBOX_PAGE_BYTES`) against the isolate memory limit (from memory, 128 MB, verify), counting every copy | a smaller Workers-specific page budget through `mailbox::bound_page`, which `next_after` already tolerates |
| Row size | whether public tree documents (one unbounded `TEXT` column, `org_tree_docs`) stay under the 2 MB row limit | chunk the document across rows inside the store, or cap its size at publish |
| Cost and plan | the plan SQLite-backed Durable Objects require, request and storage cost for a pilot's traffic and retained letters, CPU time per request against the plan's limit | record the figure; if the Free plan's CPU limit is too small, the paid plan is the cost |

The spike's output is this document, revised with the measured values and a
recorded adopt or defer decision, and a comment on issue #88. A failure
that cannot be mitigated inside Cloudflare reopens the hosting decision with
the owner; it does not default to another provider.

### Estimate

| Item | Effort |
| --- | --- |
| Feasibility spike (PR 3) | about 1 week |
| Workers adapter over `service::dispatch`, feature gating, build | 1 week |
| `DoRelayStore` to conformance | 2 to 3 weeks |
| Admin Worker: mint, rotate, events, checkpoint, export and restore commands | 1 to 2 weeks |
| Load, limits and custody review; runbook | 1 week |
| Cost | a Workers plan plus Durable Object storage and requests; measured by the spike |

These are the author's estimates, not measurements.

## Provider-only issuance on every path

The hosting platform does not decide who can mint. These do, on the native
reference host or in a Worker alike:

- **The provider-root private key stays offline.** `host certify`, `host
  krl` and `host policy issue` are run on the offline machine
  (`relay-deployment.md`, "Offline provider certificate issuance"); nothing
  on a Worker holds it. The compiled-in root public key
  (`src/provider.rs`, `KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY`) must be replaced
  with the key from that ceremony before any production credential is
  issued, and that replacement recorded.
- **The relay identity key** is the only secret the running relay has. On
  Workers it is a Worker secret set by the operator with `wrangler secret
  put`; it is never in the wrangler configuration, a `[vars]` entry, a
  GitHub secret or a log (`relay-secrets.md`).
- **The operator lock (`kql_…`)** is separate from the relay service. It is
  never stored on a Worker: it is presented with each admin request and only
  its hash is held, and the native `host keys create|rotate` read it from
  `--licensee-key-file` (`src/cli/host_env.rs`), never from the running
  relay's files. Bootstrap it before the first customer key, in a recorded
  ceremony: `host keys` on an empty issuer store mints and prints it once.
  The bootstrap path for the Workers relay is part of PR 4 and must keep
  the same property.
- **No public minting endpoint.** The public Worker has no create or rotate
  route; minting is only on the Access-protected admin Worker. On the
  native router the same rule holds today: the HTTP API lists and revokes
  keys and nothing more (`src/relay/server.rs`, `router`: `GET /api-keys`,
  `POST /api-keys/{id}/revoke`; there is no create or rotate route), which
  `src/relay/server/tests.rs` (`router_enforces_scopes_and_returns_opaque_bytes`)
  pins. For the Workers relay, the staging smoke test and the miniflare
  checks in PR 4 must pin it again.
- **Customers receive bearers sealed**, as a `.kqkey` bundle or a mailbox
  letter signed by the relay key (`src/api_key_delivery.rs`,
  `src/relay/key_delivery.rs`); a bearer is never printed by the host.
- **Licence statements are signed text, not enforcement.** `KeyIssue.licence`
  travels signed; the relay meters no seats and suspends nothing by
  subscription. The initial service offers manually issued, scoped
  credentials; revocation and expiry are the controls. Do not describe it
  as subscription enforcement.

## Availability and recovery

### Objectives

| Objective | Value | Why |
| --- | --- | --- |
| RPO | 1 hour (backup interval), 24 hours for the audit checkpoint | letters are re-sendable by their senders (`outbox send`), keys re-issuable; the audit trail is what must not be lost |
| RTO | 2 hours | restore the Durable Object's data into a replacement object and redeploy the Worker from the pinned bundle; no cluster to rebuild |

### Backups

- **Durable Object point-in-time recovery**, if the spike confirms that it
  covers the 1 hour RPO (from memory, verify: the retention window and the
  restore procedure). If it cannot, a scheduled export of the database
  (a cron-triggered Worker writing to the optional R2 bucket, or the admin
  Worker's export pulled by the operator) is added, hourly, kept 7 days
  (daily kept 90); the spike decides which. Either way the export is a SQLite file in the schema the native
  host reads, kept owner-only wherever the operator stores it, and taken
  under the Backup role.
- **Audit checkpoints** (`host keys checkpoint --out FILE`, through the admin
  Worker; the native CLI writes the file) at least daily and after every key
  ceremony, kept off Cloudflare by the operator, and optionally copied to an
  R2 bucket with a retention lock (from memory, verify) that the Backup role
  can only write; `host keys events --verify --checkpoint <newest>` is what
  bounds a backdated anchor (`relay-deployment.md`, "Verification").
- Keep a copy of the export outside Cloudflare only if the operator's
  objectives need it (the single-vendor risk above); the relay has no
  multi-region feature to use, and Durable Object placement is Cloudflare's.

### Restoration drill (A1.3)

Before launch and then on a schedule:

1. Restore into a **separate test Durable Object**, in a test Worker (or a
   test account) with no route from the production hostname and no customer
   DNS pointing at it.
2. Never give the restored copy the production relay key: a Worker that
   could sign anchors production would trust is not isolated. Verification
   needs no relay key, so run `host keys events --verify --checkpoint
   <newest>` against the restored file first. To exercise serving, generate
   a test relay identity and have a test certificate issued for it from a
   test root (the production root never signs for a drill); clients built
   against the production root will refuse it, which is correct.
3. Verify: the audit chains re-walk and match the newest checkpoint; rows
   after the checkpoint are listed and compared with the live relay's.
4. Reconcile issuance: compare `host keys list` and `host keys events`
   between the restored copy and the live relay. Keys created, rotated or
   revoked after the restore point are missing from the copy; if the copy
   is promoted, re-apply the revocations first (a revoked key must not come
   back to life), then re-issue the missing keys sealed to their customers.
   Letters pushed after the restore point are gone from the copy; their
   senders' outboxes can send them again (delivery is idempotent by
   recipient and content hash).
5. Record the drill: restore point, restore time, verification output,
   discrepancies, time to serve.

### Alerts

| Signal | Source | Threshold |
| --- | --- | --- |
| health and readiness | an external probe of `GET /health` and `GET /ready` over the public hostname | 3 failures in a row |
| provider identity | a synthetic client that runs `keyquorum loadkey` with a throwaway store and key (only this proves the identity; `/ready` does not) | daily, any failure |
| certificate expiry | the external probe's TLS check (the edge certificate's renewal is Cloudflare's), and the expiry date of `provider.kqcert` known from issuance and checked by the operator on a schedule | 30 days before either |
| storage | the database size against the Durable Object's 10 GB limit, from the admin Worker or Cloudflare's Durable Object metrics (from memory, verify which is available) | 70 % warn, 85 % page |
| Worker and Durable Object errors | Cloudflare Notifications on error rate for both Workers and the object (from memory, verify) | a sustained rise |
| audit verification | `host keys events --verify --checkpoint` on a schedule, output kept | any row not "ok" or "pending" |
| denials and rate limits | Workers logs: the authentication-denied, scope-denied and rate-limit-exceeded lines (`src/relay/service.rs`, `src/relay/server.rs` write them through `tracing` today; the Workers relay must emit the same events to its log) | a sustained rise |

### Incident response and key compromise

`relay-deployment.md`, "Incident recovery", is the procedure: stop serving
(remove the Worker's route, or replace the Worker secrets, so the hostname no
longer answers with the compromised identity), preserve evidence (export the
database and the Access and account audit logs before changing anything),
revoke the certificate serial offline, issue a new relay identity, rotate
every customer key minted while the compromise was possible, verify the
chains against the checkpoints kept off Cloudflare. Record who did each step
and when. A suspected Cloudflare account compromise adds: revoke the API
tokens, review the Access policies and the Worker versions for changes, and
treat every Worker secret as exposed.

## Launch prerequisites, revalidated

Each concern from the PR #87 review, checked against the code now:

| Concern | State in the code | Decision for launch |
| --- | --- | --- |
| Tree-level authorization and customer isolation | **Open.** Any `inbox.push` key may publish a public tree for a label and the relay merges it (`src/relay/service.rs`, `inbox_push`; `src/relay/org_tree.rs`, `merge_into_existing`); letters stay sealed to their recipient, but the public topology is shared. | **Scope decision:** one organization (or one group of mutually trusting organizations) per relay, as `relay-deployment.md`, "Before opening a relay to customers", states. Per-customer namespacing and an authenticated tree publisher are a separate design before a shared relay. |
| Byte-bounded inbox responses | **Done in the library.** `MAX_INBOX_PAGE_BYTES` (16 MiB) in `src/relay/mailbox.rs`, `bound_page`, shared by every backend; at least one letter per page, `next_after` stateless. **Unverified on Workers:** whether a 16 MiB page fits the isolate memory. | Spike item (peak memory); a smaller Workers page budget through `bound_page` if it does not fit. |
| Bounded database admission | **Done for the native host.** `DEFAULT_STORE_CONCURRENCY` (64) and `STORE_ADMISSION_WAIT` (5 s, then 503) in `src/relay/server.rs`, two separate slots for `/ready`; the permit is held until the store call returns. **Not carried over:** the Durable Object serialises requests through its single writer, and what bounds the queue in front of it is unverified. | The Workers relay must name and test its own bound (a queue limit and a 503 answer); measure under the overload test. |
| Provider-controlled retention and storage quotas | **Partly.** Letters expire when pushed with `--expires`, device letters after `DEVICE_PACKAGE_TTL_DAYS` (30, `src/relay/device_mail.rs`), and the native scan purges both; the Workers relay needs a Durable Object alarm for the scan (from memory, verify). Nothing caps a customer's stored bytes or count. | **Scope decision:** alert on database size (above) and revoke a key that fills it; a per-key quota is a follow-up. |
| Trusted client-IP handling | **Changed by the platform.** There is no proxy chain to trust: the Worker reads `CF-Connecting-IP` for its rate limit and ignores `X-Forwarded-For` altogether. The native router's rule (the last `X-Forwarded-For` entry, only with `--behind-tls-proxy`; `src/relay/server.rs`, `RateLimiter::client`; test `behind_a_proxy_the_last_forwarded_address_is_the_client`) stays for the reference host. | Test forged headers at deployment (the edge section lists the commands). |
| Recoverable key issuance when a transaction outcome is indeterminate | **The error exists, the Workers use does not.** `Error::StoreCommitUnknown` keeps the sealed `.kqkey` and tells the operator to check `keys list` and `keys events` before retrying (`src/bin/keyquorum/host.rs`). On Workers the same situation arises when the admin Worker's response is lost after the Durable Object commits. **SQLite native:** a bundle is written while the transaction is open; a crash between the write and the commit can leave an orphan that opens nothing (`src/relay/key_delivery.rs`). | The admin client must map a lost response to `StoreCommitUnknown` (PR 4); the runbook already says to remove an orphan bundle before retrying. |
| SIGTERM handling | **Done for the native host** (`host.rs`, `shutdown_signal`). **Not applicable to Workers**, which have no process to stop; a deploy replaces the version and the platform handles in-flight requests (from memory, verify). | None for Workers. |

## Edge behavior of the public Worker

The relay no longer sits behind a proxy; the Worker is the edge. The
controls the earlier plan specified for a Cloudflare proxy in front of an
origin (trusted client identity, cache bypass, protocol limits, layered
rate limits, private operator access) now describe the Worker's own
behavior and the zone's settings.

### TLS and certificates

- Cloudflare terminates TLS at the edge for the custom domain, and renews
  its certificate. There is no origin leg, so no Full (strict) mode, no
  origin certificate and no tunnel to keep alive. The consequence for
  confidentiality is in [Gaps and limits](#gaps-and-limits-recorded).
- Nothing changes for KeyQuorum's own trust: clients verify the relay by the
  provider challenge over whatever TLS is in front (`src/relay/client.rs`,
  `authenticate_provider`), so a Cloudflare edge cannot impersonate a relay
  without its signing key.
- The relay's URL is the custom domain. Switch `workers.dev` and preview
  URLs off for both Workers (from memory, verify) so there is one hostname
  that carries the relay's identity.

### DNS and client identity

Client → Cloudflare edge → public Worker → Durable Object.

The client identity is taken from one place only:

- Cloudflare sets `CF-Connecting-IP` to the one connecting client address
  and **appends** to `X-Forwarded-For`, which may therefore begin with
  values the client sent (Cloudflare, HTTP headers, search summary).
- The Worker keys its rate limit on `CF-Connecting-IP` and never reads
  `X-Forwarded-For`. Whether a client can supply its own `CF-Connecting-IP`
  through the edge is a platform fact to confirm (from memory, verify:
  Cloudflare overwrites it), which the forged-header test below checks.
- The custom domain and its DNS are managed as code (`deploy/cloudflare/terraform/`).

**Tests at deployment** (record the output with the deployment):

```sh
# Forged forwarding headers are not believed: the Worker's limiter must
# count these against the real client, so enough of them from one address
# still end in a 429 (set the limit low for the test).
curl -sS -H 'X-Forwarded-For: 203.0.113.9' -H 'CF-Connecting-IP: 203.0.113.9' https://relay.example.com/health
# There is no second way in: the workers.dev and preview hostnames do not
# answer, and the admin Worker has no route from the public hostname.
curl -sS --connect-timeout 5 https://keyquorum-relay.<account>.workers.dev/health
curl -sS -o /dev/null -w '%{http_code}\n' https://relay.example.com/api-keys
# The provider challenge still passes through the edge.
keyquorum --db ./check.sqlite loadkey --url https://relay.example.com
```

### Cache

Authenticated relay responses must never enter a shared cache. The Worker
sets `Cache-Control: no-store` on every response and does not use the
Cache API. By default Cloudflare does not cache a response to a request
carrying `Authorization` unless the response's `Cache-Control` opts in
(search summary), and the relay's JSON is not a cacheable file type by
default. Do not rely on defaults alone: add a cache rule, in the Terraform,
that **bypasses cache for the whole hostname**, and confirm with
`cf-cache-status: DYNAMIC` or `BYPASS` on `GET /inbox` and `POST
/provider-identity` responses. Sealed letters, key metadata and recipient
fingerprints must show `BYPASS`.

### Limits against the protocol

| Limit | Cloudflare | Relay | Fit |
| --- | --- | --- | --- |
| request body | 100 MB (Free, Pro), 200 MB (Business), 500 MB (Enterprise) | 1 MiB per envelope, 2 MiB per request (`MAX_ENVELOPE_BYTES`), enforced by the Worker before it calls the Durable Object | fine on any plan |
| response | not a plan limit for a non-cached response | an inbox page is at most 16 MiB of sealed bytes plus encoding | fits the edge; the isolate's memory is the open question (spike) |
| CPU time | 10 ms per request on Free, 30 s by default on Paid | signature and certificate checks and SQL work per request | unmeasured; the spike decides the plan |
| time | the client gives up at 30 s (`http_agent_config`) | `REQUEST_TIMEOUT`, 30 s, on the native host | the Worker must answer, or fail with a 5xx, inside the client's 30 s |
| WebSockets, HTTP/2 | not used by the relay | | |

### Rate limits, layered

Zone rate-limiting rules (per IP on `/inbox`, `/keycheck`,
`/provider-identity`, managed in the Terraform) absorb floods before the
Worker runs; the Worker's own rate limit on `CF-Connecting-IP` (a Workers
rate limiting binding, from memory, verify its accuracy and scope) still
applies in the Worker; the Durable Object's single writer and its admission
bound limit the database; the storage alert bounds retention. None replaces
another.

### Private operator access

The admin Worker has **no public route**. It is reached through a
**Cloudflare Access** self-hosted application whose policy requires the
operators' identity provider **and MFA**, and it is service-bound to the
Durable Object. The public Worker has no route to any operator path, and no
other hostname reaches them. Customer routes (`/inbox`, `/keycheck`,
`/provider-identity`, `/devices/*`, `/trees/*`) stay outside Access: a
`keyquorum` client cannot answer an Access login. Record the Access
application and policy with the deployment; Access and account audit logs
are the record of operator sessions (from memory, verify).

### Monitoring, incidents, rollback, cost

- Monitor the Workers and the Durable Object through Cloudflare Notifications
  and analytics (error rate, 5xx), and the relay as in the alerts above.
- An edge or platform outage is a Cloudflare incident, and with one provider
  there is no second path to fail over to; the operator's recourse is the
  export and the native reference host for a read of the data, not a
  production fallback.
- Rollback is a Worker version rollback (`wrangler rollback`, from memory,
  verify), which the operator should rehearse once; across a schema
  migration, restore the pre-upgrade point-in-time state first.
- A change to the wrangler configuration that adds a `deleted_classes` or a
  rename migration would destroy the Durable Object's data (from memory,
  verify), so CI fails any such change unless it has been reviewed. This is
  the replacement for termination protection.
- Cloudflare API tokens and Worker secrets: rotate them when a person who
  could read them leaves. A Worker secret is not readable back, so rotation
  means putting a new value.
- Cost: not estimated until the spike measures the plan and traffic
  (above); the Free plan's CPU limit is the first thing to check.

## Acceptance checklist

| Criterion (issue #88) | Settled by this document | Needs the deployment |
| --- | --- | --- |
| Hosting decision records the provider, ownership, limits, cost basis, effort, and the disposition of AWS and MongoDB | yes (cost estimate comes from the spike) | none |
| Workers architecture maps atomicity (one Durable Object) and provider-only signing and minting (admin Worker, Worker secrets) to a runtime and a backend, with an adopt/defer decision | yes: adopt, subject to the spike | record the decision after PR 3 |
| The feasibility spike answers each unknown with a measured value | the unknowns and their consequences are listed | run the spike (PR 3) |
| An unauthorized client cannot mint provider-issued keys or licences | design: no public mint route; native router test pinned | re-run against the public Worker (staging smoke test, miniflare) |
| The admin Worker cannot be reached without Access and MFA | design | test it against the live Access application |
| Provider-root custody and operator credential separation documented and verified | documented | verify at the ceremony and record it |
| Launch prerequisites revalidated and linked to fixes or scope decisions | yes (table above) | none |
| HTTPS, readiness and health operate as documented | plan and probes | observe them |
| Edge behavior records client identity, cache policy, limits, private administration | yes | run the commands and record the output |
| Overload and storage-limit tests show bounded resource use | the bounds are named | run the tests, record memory, the 503 and 429 behaviour and the Durable Object's storage |
| Backup restoration meets the objectives and reconciles credential state | procedure | run the drill |
| Upgrade, rollback, incident response demonstrated | procedures | demonstrate |
| `DoRelayStore` passes `relay::store::conformance` | not applicable until it exists (PR 4) | PR 4 |
| The pipeline builds, deploys to staging, and gates production | design (PR 2) | prove with a run on staging |
| Gaps (no customer-managed key, Cloudflare sees bearers in transit, one vendor) recorded | yes | the owner accepts them; `docs/soc2-controls.md` carries the subprocessor point |
| Runbooks distinguish hosting-provider controls from relay authorization | yes (this document and `relay-deployment.md`) | none |
