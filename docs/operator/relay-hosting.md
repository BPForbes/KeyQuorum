# Hosting the KeyQuorum relay: Cloudflare only

This is the hosting plan and decision record for issue #88. The owner has
decided that Cloudflare is the sole hosting provider for the mailbox relay,
because of cost. This document records that decision, the Cloudflare
Workers design that follows from it (the public Worker and its Durable Object are built and
not yet deployed; the admin Worker's console and its back end are built and
not yet deployed either), the controls
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
| Cloudflare Workers relay (Path B) | **The runtime and the provider's console are built; nothing has been deployed.** The public Worker (`workers/src/worker.js`) and the one SQLite-backed Durable Object (`workers/src/relay-object.js`, around the Rust relay core compiled to WebAssembly) are in this repository. They are tested over the real core under Node and were run under local workerd (`wrangler dev --local`); they have never been deployed to a Cloudflare account. **Missing:** the account setup and a first deploy, and the production-only checks. A customer key is minted from the operator console (below), through the admin Worker's private binding to the same Durable Object, with the operator lock presented per change; the public Worker still has no create or rotate route. Status: **Adopt** (decided 2026-10-06 on the stage 3 spike). The design is in [The Workers relay](#the-workers-relay) and the measurements in [What the spike measured](#what-the-spike-measured-stage-3). |
| Native `keyquorum host serve` | **Kept as the dev, test and reference host.** `SqliteRelayStore`, `src/relay/server.rs` and `host keys` stay in the code. It is not a production deployment path. |
| Deployment pipeline and Cloudflare Terraform | **Stage 2, in this repository; not yet exercised against a Cloudflare account.** `workers/` (the public Worker and its Durable Object), `.github/workflows/workers.yml` and `deploy/cloudflare/terraform/` exist and are described in [Provisioning and the deployment pipeline](#provisioning-and-the-deployment-pipeline-stage-2). Honest limits: nothing has been deployed; the Terraform passes CI's `terraform validate` against the pinned provider (`.terraform.lock.hcl`, `cloudflare/cloudflare` 5.27.0) but the repository's authors have never planned or applied it against a real account; Cloudflare Notifications and the R2 retention lock are dashboard steps, not Terraform; and the owner's GitHub and Cloudflare setup is still to be done. |
| Admin Worker and operator console (stage 4a, issue #99) | **In this repository; never deployed, and Access has never been configured on an account.** `workers/admin/` holds the Worker `keyquorum-relay-admin` (`[env.staging]` is `keyquorum-relay-admin-staging`): it verifies Cloudflare Access's signed token itself and serves the provider's console, a static page and a documented `/api` that reaches the relay only through the private binding `RELAY_ADMIN`. Customers, licences (immutable statement versions), keys with lineage, per-key activity, status, audit and checkpoint, and the two-step operator lock are built; see [The operator console](#the-operator-console-issue-99). Its Terraform (`admin_environments`: a custom domain and an Access application with an MFA policy per environment) and workflow steps exist; CI's `terraform` job checks the whole directory on every push. **Not done:** every check on a real account (Access and MFA, the binding on Cloudflare, staging, restore, overload, cost); see the console section's list. |
| Relay domain and operator page | **Decided 2026-10-06 (owner).** The relay and the console are mounted under paths of `keyquorum.dev` (`/relay`, `/relay/staging-user`, `/relay/admin`, `/relay/staging-admin`), through Workers routes (owner decision, revised 2026-10-06); the operator page is static files served from the admin Worker behind Access. See [Domain and operator page](#domain-and-operator-page-owner-decisions-2026-10-06). |
| Live deployment, restore test, overload test | **Not done.** Nothing has been deployed. They need the operator's Cloudflare account and run against a real deployment. The [acceptance checklist](#acceptance-checklist) says which rows this document settles and which the deployment must. |

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
- **docs search (2026-10-06):** the page's text was returned by Cloudflare's
  own documentation search (the `search_cloudflare_documentation` tool of the
  Cloudflare Developer Platform MCP server) on 2026-10-06; a sentence in
  quotation marks is verbatim from that text, the rest paraphrases it.
- **not retrieved:** named for the reader; nothing in this document rests on
  it alone.
- **not retrieved (from memory, verify):** a statement about Cloudflare's
  platform that the author believes but could not retrieve. Wherever the
  text below relies on one, it says "from memory, verify" next to the
  statement. Confirm each against the named page before the design depends
  on it; the stage 3 spike did so for the ones a local run can measure.

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
| Cloudflare Access, validating the signed token Access adds to a request: the `Cf-Access-Jwt-Assertion` header, the team's key set at `https://<team domain>/cdn-cgi/access/certs`, and the claims (`iss`, `aud`, `exp`, `nbf`, `email`). The admin Worker's check is written from this. | https://developers.cloudflare.com/cloudflare-one/ (the page's path is not recorded) | not retrieved (from memory, verify) |
| Cloudflare Access audit logs, and Cloudflare account audit logs. | https://developers.cloudflare.com/cloudflare-one/insights/logs/ | not retrieved (from memory, verify) |
| Cloudflare, scoped API tokens, Notifications (Worker and Durable Object error alerts), Workers Logs. | https://developers.cloudflare.com/fundamentals/api/get-started/create-token/ | not retrieved (from memory, verify) |
| Cloudflare, R2 bucket lock (retention rules) | https://developers.cloudflare.com/r2/buckets/bucket-locks/ | not retrieved (from memory, verify) |
| Cloudflare Terraform provider (`cloudflare/cloudflare`): resources for Workers custom domains, DNS, Access applications and policies, rulesets, R2 buckets, notification policies. | https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs | not retrieved (from memory, verify) |
| Cloudflare, Workers Builds configuration: a push runs the build command, then the deploy command (default `npx wrangler deploy`) on the production branch or the Preview command (default `npx wrangler preview`) on another branch; root directory for a monorepo; build variables; "Workers Builds will use the Wrangler version set in your package.json"; the token Builds creates holds Account Settings read, Workers Scripts edit, Workers KV Storage edit, Workers R2 Storage edit, Workers Routes edit, User Details read, Memberships read; "For new Workers Builds projects, preview builds use `wrangler preview` by default". | https://developers.cloudflare.com/workers/ci-cd/builds/configuration/ | docs search (2026-10-06) |
| Cloudflare, Builds, connecting an existing Worker: "When connecting a repository to a Workers project, the Worker name in the Cloudflare dashboard must match the `name` in the Wrangler configuration file in the specified root directory, or the build will fail." | https://developers.cloudflare.com/workers/ci-cd/builds/ | docs search (2026-10-06) |
| Cloudflare, Build branches: "Preview builds are builds for branches that are not your production branch. New Workers use Worker Previews for preview builds by default. Their Preview command is `npx wrangler preview`."; "Enable Preview Builds" under Settings, Build, Branch control. | https://developers.cloudflare.com/workers/ci-cd/builds/build-branches/ | docs search (2026-10-06) |
| Cloudflare, Build image: Node.js 24.18.0 by default, overridden by `NODE_VERSION` or a `.nvmrc` or `.node-version` file in the root directory; Ubuntu 24.04 with `build-essential`; Go, Python and Ruby are listed, Rust is not. | https://developers.cloudflare.com/workers/ci-cd/builds/build-image/ | docs search (2026-10-06) |
| Cloudflare, GitHub integration: one check run per connected Worker, "only projects that trigger a build will generate a check run" when watch paths are set; Cloudflare recommends limiting the Workers & Pages GitHub App to the repositories it builds. | https://developers.cloudflare.com/workers/ci-cd/builds/git-integration/github-integration/ | docs search (2026-10-06) |
| Cloudflare, Builds advanced setups: a monorepo connects the repository to each Worker with its own root directory and watch paths; a Wrangler environment's Worker is connected separately with `--env <name>` in its deploy and Preview commands. | https://developers.cloudflare.com/workers/ci-cd/builds/advanced-setups/ | docs search (2026-10-06) |
| Cloudflare, Builds API reference: a user-scoped token with Workers Builds Configuration edit and Workers Scripts read; after the GitHub App is installed in the dashboard, `PUT /builds/repos/connections`, then `POST /builds/triggers` with `trigger_name`, `build_token_uuid`, `build_command`, `deploy_command`, `root_directory`, `path_includes`, `path_excludes`, `build_caching_enabled`, `environment_variables`; at most two triggers per Worker, production and preview. | https://developers.cloudflare.com/workers/ci-cd/builds/api-reference/ | docs search (2026-10-06) |
| Cloudflare, Worker Previews: "Previews do not inherit production settings."; "Cloudflare automatically provisions a new Durable Object namespace and container instances for each Preview."; a Preview URL on workers.dev is `<preview-name>-<worker-name>.<subdomain>.workers.dev`; "Preview URLs are public by default. Use Cloudflare Access to require sign-in." | https://developers.cloudflare.com/workers/previews/ | docs search (2026-10-06) |
| Cloudflare, Worker Previews configuration: "The `previews` block is required, but it can be empty if your Preview does not need separate settings."; secrets reach a Preview only through `wrangler preview base-config secret put` (every new Preview) or `wrangler preview secret put --name <preview>` (one); an environment's Previews are configured under `env.<name>.previews` and run with `--env <name>`. | https://developers.cloudflare.com/workers/previews/configuration/ | docs search (2026-10-06) |
| Cloudflare, Worker Previews custom domains: "Preview URLs can use a custom domain, `workers.dev`, or both. Enable at least one host to get a Preview URL."; `preview_urls = true` in the configuration turns on the workers.dev Preview host, separately from production's `workers_dev`; Cloudflare adds `X-Robots-Tag: noindex` to workers.dev Preview URLs. | https://developers.cloudflare.com/workers/previews/custom-domains/ | docs search (2026-10-06) |
| Cloudflare changelog, one-click Access for Workers: every Preview URL of an account shares one "Cloudflare Workers Preview URLs" Access policy, enabled from the Worker's Settings, Domains & Routes. | https://developers.cloudflare.com/changelog/ (Workers, Access for workers.dev and Preview URLs) | docs search (2026-10-06) |
| Cloudflare, Version URLs: "Version URLs, previously called preview URLs, let you access an uploaded version of your Worker before deploying it to production. A Version URL uses that Worker version's existing configuration and resources instead of creating a separate environment."; new versions are created by `wrangler deploy`, `wrangler versions upload` and dashboard code edits; "If Version URLs are enabled, the URL is public and available after version creation."; "The Wrangler configuration field is still named `preview_urls`."; "Access can protect Version URLs for one Worker or every Worker in an account." | https://developers.cloudflare.com/workers/versions-and-deployments/version-urls/ | docs search (2026-10-06) |
| MongoDB, Atlas Data API and custom HTTPS endpoints: end of life and deprecation (end of life 30 Sep 2025). | https://mongodb.com/community/forums/t/mongodb-atlas-data-api-and-custom-https-endpoints-end-of-life-and-deprecation/296686 | search summary (2026-10-06) |
| AICPA, 2017 Trust Services Criteria (2022 points of focus), A1.3: "The entity tests recovery plan procedures supporting system recovery to meet its objectives." | https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 | verbatim (issue #88) |

Code cited below was read in this repository at the commit this document
was written in; the file and item are named each time.

## The decision

**Cloudflare is the only hosting provider for the relay, and the relay runs
as a Cloudflare Worker over one Durable Object.** The decision is the
owner's and rests on cost: one vendor, one bill, no virtual machine to
patch, size or snapshot. It is adopted on the stage 3 feasibility spike
(below), which settled what a local run can; the Workers relay does not
exist yet, and the production-only checks that remain gate launch, not the
build.

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
| Estimated monthly cost | A machine, a volume and snapshots, billed separately; rejected on cost. | The same plus the edge plan. | A Workers plan plus Durable Object storage and requests; not estimated: the plan, request and storage cost need the owner's account (a production-only check, above). |
| Implementation effort | Days. | One or two days on top. | Weeks: adapter, store, conformance, custody, admin Worker; see the estimate below. |
| Decision | **Dropped.** | **Not adopted.** It needs the machine, so it keeps the second vendor. | **Adopt** (stage 3 spike; production-only checks before launch). |

### MongoDB

> **Reopened 2026-10-07 at the owner's request:** MongoDB through the
> official `mongodb` driver as the production store is proposed in
> `mongodb-production.md`, with the changes it needs and the questions to
> answer first. Nothing below has been reversed; this section records why it
> was removed.

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

### Domain and operator page (owner decisions, 2026-10-06)

Two decisions of the owner, recorded as decisions:

1. **The relay and the console live under paths of `keyquorum.dev`.** The
   owner's domain `keyquorum.dev` (bought to carry a customer app as well)
   hosts everything under paths, so a path says what each thing is, and
   Workers routes carry them, not custom domains (a custom domain takes a whole
   hostname). Revised three times on 2026-10-06: a separate new domain, then
   subdomains of `bailey-forbes.com` (dropped: that domain's DNS is not on
   Cloudflare, and a Worker can be served only on a zone that is), then the
   relay under `/relay` with the console on a hostname of its own, then, at the
   owner's request, all four under paths:

   | Path on `keyquorum.dev` | What | Worker |
   | --- | --- | --- |
   | `/relay` | the production relay | `keyquorum-relay` |
   | `/relay/staging-user` | the staging relay, for ordinary users | `keyquorum-relay-staging` |
   | `/relay/admin` | the production console (Access) | `keyquorum-relay-admin` |
   | `/relay/staging-admin` | the staging console (Access) | `keyquorum-relay-admin-staging` |

   (The production console path, `/relay/admin`, is the repository's default,
   not an owner decision; it is a Terraform input and a `MOUNT_PATH`.) A
   client's relay URL is the relay's path: `https://keyquorum.dev/relay` or
   `https://keyquorum.dev/relay/staging-user`; the client already adds each route
   to a URL's path (`src/relay/client/tests.rs`,
   `a_relay_url_with_a_path_prefix_keeps_it_in_front_of_every_route`), so no
   client changed. **Each Worker serves only below its own mount**
   (`workers/src/mount.js`, from the non-secret variable `MOUNT_PATH`, which the
   deploy takes from the path of `RELAY_URL` or `ADMIN_URL` so a URL and its
   Worker cannot disagree): it strips the mount, so the relay core and the
   console's routes see the paths they always had, answers 404 to everything
   else (a mount without its slash is redirected to the slash, because the pages
   use relative links), and is unconfigured, serving nothing, if the value is
   not exactly `/relay` or `/relay/<name>` (for the console `/relay/<name>`, or
   empty for a hostname of its own); a name may not be one of the relay's own
   routes (`inbox`, `keycheck`, `provider-identity`, `audit`, `trees`,
   `devices`, `health`, `ready`, `assets`). Where routes overlap, Cloudflare uses
   the more specific one (from memory, verify at the first apply); a request that
   reaches the wrong Worker is a 404 there. The zone's rate-limit and
   cache-bypass rules match only paths under `/relay`
   (`deploy/cloudflare/terraform/rules.tf`). The hostname must be proxied in the
   zone's DNS, which Terraform does not create. The native host is unchanged and
   has no prefix. `keyquorum.dev` must be a zone on the owner's Cloudflare
   account. The root of the hostname has no site yet, so until the customer app
   exists a request to `https://keyquorum.dev/` is not answered by these Workers.

   **One origin.** All four share the origin `https://keyquorum.dev`, which the
   earlier plan of a hostname of its own for the console avoided, and which the
   owner chose knowing it. Access's session cookie is scoped to the host, not
   the path, so the browser sends it to every path on the host: the relay
   Workers, and later the customer app, receive the operator's `HttpOnly` Access
   cookie, and a script flaw in anything else on the origin (the customer app
   above all) runs on the console's origin and can call its API as the signed-in
   operator, although a change still needs the operator lock, which the page
   never keeps. Staging and production also share the origin. What still holds:
   the console's Access token check, its lock and same-origin `Origin` checks,
   and the relay Workers ignoring cookies. The cost is real and the remedy is a
   configuration change: put the console on a hostname of its own again before
   the customer app is built (`deploy/cloudflare/terraform/README.md`, "One
   origin").
2. **The operator page is hosted the way the portfolio is hosted.** It is
   static files served from the admin Worker on its own path (decision 1),
   simply styled. The path is behind Cloudflare Access
   (operator identity plus MFA), and the Worker verifies Access's token
   itself rather than trusting the Access configuration alone.

### Workers Builds and previews (owner decisions, 2026-10-06)

The portfolio site is connected to Cloudflare Workers Builds, Cloudflare's Git
integration: its Worker `bailey-forbes-portfolio-site-github-io` builds from
the repository on every push, and each pull request carries a check named
"Workers Builds: bailey-forbes-portfolio-site-github-io" (read from the check
runs of that repository's pull request #20 on 2026-10-06). The owner wants the
same here for the relay Worker, **in addition to** the `workers` check of
`workers.yml`, which stays the stable required check and keeps the staging and
production deploy jobs. The connection itself is made outside the repository:
the Cloudflare Workers & Pages GitHub App is installed and the repository is
connected in the dashboard, or through the Builds API with a user-scoped token
the operator holds (neither GitHub Actions nor an agent session holds one).
The repository holds everything the connection needs; this section is the
procedure and the settings, so the connection is made once and the same way.

**What the repository holds for it** (`workers/`):

- `wrangler.toml` names the Worker `keyquorum-relay` (the dashboard name and
  the `name` under the root directory must match, or the build fails), keeps
  `workers_dev = false`, sets `preview_urls = true` (the workers.dev host for
  Previews, separate from production's) and carries the `[previews.vars]` and
  `[[previews.durable_objects.bindings]]` tables a Preview starts with, since
  "Previews do not inherit production settings" and the `previews` block is
  required ("it can be empty if your Preview does not need separate
  settings"; Cloudflare, Worker Previews and its configuration, read
  2026-10-06). Classes and migrations stay at the top level, as Cloudflare
  asks. The staging environment has no `previews` block: it is not connected.
- `.node-version` pins Node 22, the version `workers.yml` runs; Builds reads
  it from the root directory (its default is Node 24).
- `npm run builds:build` is the build command (`scripts/ensure-relay-wasm.mjs`).
  Cloudflare's build image has
  Node, Go, Python and Ruby but no Rust, and the relay core must be compiled to
  WebAssembly first, so `scripts/builds-toolchain.sh` installs a pinned Rust
  toolchain with the wasm32 target (`rustup-init` 1.28.2, Rust 1.97.0) and the
  prebuilt `wasm-bindgen` CLI at the version `Cargo.lock` pins (0.2.127), and
  clang, which the image also lacks and which `sqlite-wasm-rs` (the crate's
  bundled SQLite, compiled from C for wasm32 by its build script) needs: it
  comes from the wasi-sdk 25.0 release, of which only the compiler, its shared
  libraries, `llvm-ar` and clang's headers are kept. `ensure-relay-wasm.mjs`
  points `CC_wasm32_unknown_unknown` and `AR_wasm32_unknown_unknown` at it. A
  first Workers Builds run failed with `failed to find tool "clang"` before
  this was added. Each
  download is checked against a SHA-256 written in the script, then `npm run
  build:relay-wasm` runs. (Follow-up: gate rusqlite out of the Worker build,
  since the Durable Object supplies the SQL, which would drop the C build and
  shrink the module.) The script refuses to run when `Cargo.lock` pins a
  different `wasm-bindgen` than the one it has a hash for, so a lockfile bump
  forces the pin to be raised on purpose. Measured in a clean container with no clang (not on
  Cloudflare's image, where the corrected script has not yet been seen to
  pass): toolchain, clang and a cold build of the core take about 95 seconds
  together. GitHub's workflow
  installs the same things with its own SHA-pinned actions and never runs this
  script.
- `npm run check` is the `main` deploy command: the configuration guard, the
  four dry-run builds and the bundle guard, which need the compiled core.
  `npm run preview` is `wrangler preview --env=""`, which needs it too. Both
  begin with the same step as the build command, so a dashboard that still
  names `npm run check` as its build command works: when the core is missing
  and the variable `WORKERS_CI=1`, which Workers Builds injects, is set, the
  step installs the toolchain and builds it; anywhere else (a developer's
  machine, GitHub, where the workflow builds the core first) a missing core is
  an error that names the command to run, and no toolchain is ever installed.
- `scripts/guard.mjs` refuses a secret-like name in a `previews` block as it
  does in `[vars]`, refuses a wildcard `ALLOWED_HOSTS` anywhere but
  `[previews.vars]` (below), and still refuses `preview_urls = true` anywhere
  but the one file checked with `--allow-preview-urls` (`guard.test.mjs`).

**Settings** (Worker `keyquorum-relay`, Settings, Builds; the same fields as
`POST /builds/triggers`):

| Setting | Value | Why |
| --- | --- | --- |
| Repository | `BPForbes/KeyQuorum`; the GitHub App's repository access limited to the repositories it builds | Cloudflare's own recommendation (GitHub integration, "Organizational access"). |
| Production branch | `main` | |
| Root directory | `workers` | Where `wrangler.toml`, `package.json` and `.node-version` are; Builds runs `npm ci` there itself. |
| Build command | `npm run builds:build` | Installs the pinned toolchain and compiles the relay core. (`npm run check` works too, since it does the same first.) |
| Deploy command (`main`) | `npm run check` | **Not** `wrangler deploy`: `workers.yml` deploys `main` (staging on push, production on a reviewed manual run), and two deployers of one Worker would race. A Builds run on `main` is a check only. |
| Preview command (other branches) | `npm run preview` | Worker Previews, Cloudflare's default for a Worker connected now. Never `wrangler versions upload`: a version shares the production bindings and secrets, a Preview does not. |
| Preview builds | on (Settings, Build, Branch control) | The check and the Preview URL on every pull request. |
| Build watch paths | include `workers/**`, `src/**`, `build.rs`, `Cargo.toml` and `Cargo.lock` | The Worker bundles the relay core, so a change to the crate changes it. A build, and so a check run, only then. |
| Build variables | `CI=true`, `WRANGLER_SEND_METRICS=false` | As `workers.yml`. No secret: the build needs none, and none is set. |
| Build token | the one Builds creates (Workers Scripts edit among its permissions), or an existing Workers-deploy token | It deploys nothing while the deploy command is `npm run check`; Previews are uploaded with it. |
| Build caching | on | |

**Order:**

1. The Worker must exist before it is connected. Deploy it once: by the
   `workers` workflow's staging and production jobs once the GitHub
   environments hold their secrets (`relay-deployment.md`), or, before that,
   by the operator from `workers/` with `npx wrangler deploy --env=""` under
   their own token. Do not create it through "Import a repository": that path
   deploys with the default deploy command.
2. Install the Cloudflare Workers & Pages GitHub App for `BPForbes`, limited to
   `KeyQuorum` (and the portfolio, which the same installation serves): the
   dashboard, any Worker, Settings, Builds, Connect, GitHub.
3. Connect `keyquorum-relay` with the settings above: in the dashboard, or
   with the Builds API (`PUT /builds/repos/connections`, then
   `POST /builds/triggers` twice, production and preview, under a user-scoped
   token with Workers Builds Configuration edit and Workers Scripts read; the
   API reference is in the sources table).
4. Push a branch and open a pull request. The check "Workers Builds:
   keyquorum-relay" appears, and the pull request comment carries the Preview
   URL (`<branch>-keyquorum-relay.<subdomain>.workers.dev`). Confirm on it what
   `smoke.mjs` confirms on a deploy, with `/relay` on the Preview URL
   (`https://<preview host>/relay/...`): `/relay/health` answers, the operator
   and mint routes answer 404 or 405, `/relay/ready` answers 200 through the
   Preview's own Durable Object, and a request for `/relay/inbox` is 401: the
   Preview's object is empty and no key can be in it. Confirm in the Worker's
   Settings, Builds that the build command is `npm run builds:build`, the
   deploy command on `main` is `npm run check` and the Preview command is `npm
   run preview`: the repository cannot check any of them. The first build is
   also the first time `builds-toolchain.sh` runs on Cloudflare's image.
5. Only after that run, add "Workers Builds: keyquorum-relay" to the required
   checks beside `workers`, `test` and `codeql gate`.
6. The staging Worker and the admin Worker are not connected. Staging is
   deployed by `workers.yml` from `main` and needs no Preview; the admin
   Worker keeps previews off (its hostname sits behind Access, a Preview
   hostname would not), so a connection to it would only build, which
   `workers build` already does.

**Previews** (owner decision: preview URLs on for the public Worker only):

- `preview_urls = true` with `workers_dev = false`: "Preview URLs can use a
  custom domain, `workers.dev`, or both. Enable at least one host to get a
  Preview URL." (Cloudflare, Worker Previews custom domains, read 2026-10-06).
  Production stays off workers.dev. The admin Worker and the spike keep both
  off, and the guard refuses `preview_urls = true` anywhere but a file checked
  with `--allow-preview-urls`, which only `npm run guard` passes, for
  `wrangler.toml`.
- A Preview is isolated by the platform: "Previews do not inherit production
  settings." and "Cloudflare automatically provisions a new Durable Object
  namespace and container instances for each Preview." (Cloudflare, Worker
  Previews, read 2026-10-06). A Preview's secrets come only from the Previews
  base configuration (`wrangler preview base-config secret put`) or from one
  Preview (`wrangler preview secret put`); none is set, and the relay key and
  `provider.kqcert` are never to be set there. So a Preview of the relay Worker
  holds no relay key, no certificate and no letter, and every customer route on
  it is 401; with no identity it refuses the provider challenge, so an official
  client disconnects from it.
- **Version URLs of the public Worker: refused by the Worker.** That isolation
  belongs to Previews. It does not make `preview_urls = true` safe, because the
  same Wrangler field controls Cloudflare's Version URLs ("previously called
  preview URLs"), which `wrangler deploy` creates as well as `wrangler versions
  upload`, which use "that Worker version's existing configuration and
  resources", and which are public when enabled ("If Version URLs are enabled,
  the URL is public"; Cloudflare, Version URLs, read 2026-10-06). So each
  `wrangler deploy` of `workers.yml` publishes a public workers.dev hostname
  for its version, and that version has the production object and secrets.
  The Worker therefore serves only the hosts named by the non-secret variable
  `ALLOWED_HOSTS` (`policy.js`: `parseAllowedHosts`, `hostDecision`) and answers
  404 on any other, logging the refusal without a header, bearer or body. A
  Version URL is a workers.dev host, so it is refused before the relay is asked
  anything. Empty or unset, the Worker is unconfigured and serves nothing (503).
  The deploy jobs of `workers.yml` set it from the environment's `RELAY_URL`
  (`scripts/relay-host.mjs` takes `https://<domain>/relay` or
  `https://<domain>/relay/<name>` and returns the host (`--mount`: the path, for
  `MOUNT_PATH`; `--admin-mount`: the console's, from `ADMIN_URL`), refusing
  anything else: a URL with another path, a wildcard, a
  list, a credential, an address or a single label). Only
  `[previews.vars]` sets `*`, because a Preview has its own empty object and no
  secrets; `scripts/guard.mjs` fails CI on a wildcard in `[vars]`,
  `[env.<name>.vars]` or an environment's previews. Tested:
  `test/worker.test.mjs` (a Version URL, a lookalike, a suffix and a subdomain
  are refused and never reach the relay; an unset, empty or comma-only variable
  is 503), `scripts/relay-host.test.mjs` and `scripts/guard.test.mjs`; and run
  under local workerd with a forged `Host` header (404). **Not covered:** that
  Cloudflare shows a Version URL's workers.dev host in the request URL (from
  memory, verify at the first deploy: fetch a Version URL and expect 404), and
  Access in front of the Version URLs (Cloudflare, Version URLs: "Access can
  protect Version URLs for one Worker or every Worker in an account"), which
  stays available as a second layer. `wrangler versions upload` is still never
  the Preview command.
- What else remains, recorded: a Preview or Version URL hostname is outside
  the zone's rate-limit and cache rules for the relay's hostname and outside
  the admin Worker's Access application, and a Preview is public (Cloudflare
  adds `X-Robots-Tag: noindex` to workers.dev Preview URLs). The operator can
  put Cloudflare Access in front of every Preview URL of the account with one
  setting (the Worker, Settings, Domains & Routes, Preview URLs, Enable
  Cloudflare Access; all Preview URLs share one "Cloudflare Workers Preview
  URLs" policy). A Preview answers `/relay/health`, `/relay/ready`, the status page at
  `/relay/`, 401 for a customer route under `/relay` and 404 for the rest; its
  root (`/`) is sent on to `/relay/` (the non-secret `ROOT_REDIRECT = "1"` in
  `[previews.vars]`, which `scripts/guard.mjs` refuses anywhere else, because on
  a real domain the root belongs to other things and the relay never answers
  it).
- "Pages" is not used: static assets on the admin Worker already serve the
  operator page, and a Pages project would be a second product and hostname.

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

## Provisioning and the deployment pipeline (stage 2)

Stage 2 is in the repository: the Worker project, the workflow and the
Terraform below exist. What they deploy is the public Worker and its Durable
Object (stage 4c, below), and none of it has yet run against a Cloudflare
account. Stage 4a added the admin Worker's front door to the same directories
(below). What is still missing is listed under "Not yet, and honest limits" at
the end of this section.

- **Infrastructure as code:** `deploy/cloudflare/terraform/`, with the
  `cloudflare/cloudflare` provider (`versions.tf`, `~> 5.0`). `main.tf` has
  one `cloudflare_workers_custom_domain` per environment. `access.tf` is
  empty until `admin_environments` is set (a map of `{hostname, worker}`,
  default empty; it replaced the earlier single `admin_hostname`). Then it
  has one shared Access allow policy (the operator emails, with MFA
  required; a precondition requires at least one operator email) and, per
  environment, a self-hosted Access application and a
  `cloudflare_workers_custom_domain` for the admin Worker. The outputs
  `admin_urls` and `admin_access_aud` give each admin URL and each
  application's audience tag, which is set as the GitHub environment
  variable `ACCESS_AUD`; Terraform does not output the Access team domain
  (for `ACCESS_TEAM_DOMAIN`), which is read from the Zero Trust dashboard.
  The relay's hostnames and the admin hostname belong to the owner's
  domain (see the decisions above). `main.tf` has two Workers routes per
  environment for the relay and for the console (`<host><path>` and
  `<host><path>/*`), and `access.tf` the console's Access application on its
  path. `rules.tf` has the zone rate-limit ruleset on every route under
  `/relay` except a health check, and a ruleset that bypasses the cache under
  `/relay`. `r2.tf` has an optional archive bucket
  (created only when `archive_bucket_name` is set). `variables.tf`,
  `outputs.tf`, `terraform.tfvars.example` and a `README.md` complete it. CI
  runs `terraform fmt -check`, `terraform init -backend=false -lockfile=readonly` and `terraform
  validate`, which need no credentials, and the committed
  `.terraform.lock.hcl` (checked to be tracked) pins the provider (`cloudflare/cloudflare` 5.27.0).
  The `terraform` job checks the whole directory on every push and accepted
  the admin resources and the `admin_access_aud` output against the same
  provider (commit `86bbb8f`).
  The operator runs `terraform apply`
  locally with their own Cloudflare credentials; those never enter GitHub or
  an agent session.
- **Workers:** `workers/` holds `wrangler.toml` (the top level is the
  production Worker `keyquorum-relay`; `[env.staging]` is
  `keyquorum-relay-staging`; `workers_dev = false` and `preview_urls = true` at
  both levels, public Worker only, see Workers Builds above; no routes, because
  the routes are the Terraform's; the Durable Object binding
  `RELAY` with class `RelayObject` and its `new_sqlite_classes` migration, the
  rate-limit binding `RATE_LIMITER` and the non-secret `ALLOWED_HOSTS`, each
  repeated for staging because wrangler does not inherit them, and the
  `[previews]` tables), `src/` (below), `package.json` and `package-lock.json`
  with wrangler pinned to an exact version and `sharp`, which wrangler's
  `miniflare` pins below a fixed advisory, overridden to 0.35.5 (drop the
  override when wrangler ships a `miniflare` that depends on 0.35.5 or later),
  `.node-version` (22, what Workers Builds runs) and the `builds:build`,
  `check` and `preview` scripts Workers Builds runs (above); the admin Worker
  is in `workers/admin/` (below). `src/index.js` exports the handler and the
  `RelayObject` class; `src/worker.js` is the public Worker; `src/policy.js`
  holds the host, route, bearer and size rules as pure functions;
  `src/relay-service.js` is the relay inside the object, over the WebAssembly
  core; `src/relay-object.js` is the Durable Object class around it;
  `src/status-page.js` is the status page; `src/sql-adapter.js` is the storage
  adapter. Scripts, each with `node:test` tests (`npm test`), back the
  pipeline. `scripts/guard.mjs` is the configuration guard (it fails on
  key-material patterns, on a secret-like `[vars]` or `[previews.vars]` name,
  on a wildcard `ALLOWED_HOSTS` outside `[previews.vars]`, on a
  `deleted_classes` or `renamed_classes` migration unless
  `ALLOW_DESTRUCTIVE_MIGRATION=1` is set, on a missing `workers_dev = false`
  at the top level or in any environment, and on `preview_urls` other than
  `false` everywhere except a file checked with `--allow-preview-urls`, which
  `npm run guard` passes for `wrangler.toml` only and never for
  `admin/wrangler.toml` or `spike/wrangler.toml`) and the
  bundle guard (key material in the bundle's text files, and a gzip size
  bound of 3 MiB; the bundle with the WebAssembly core is about 810 KiB
  gzipped). `scripts/relay-host.mjs` turns the environment's `RELAY_URL` into
  the hostname the Worker serves. `scripts/smoke.mjs` is the post-deploy check:
  the URL is the relay's, ending in `/relay` (the script refuses another),
  and every path below is under it: `/health` must answer 200 with the expected
  body and `no-store`; `/ready` must answer 200 through the Durable Object; `/`
  (that is, `/relay/`) must be the status page with its
  locked-down policy; the operator, documentation and mint routes (`/api-keys`,
  `/api-keys/<id>/revoke`, `/audit`, `/swagger-ui/`, `/keys`, `/keys/create`,
  `/keys/rotate`) must answer 404 or 405; an unauthenticated `GET /inbox` must
  answer 401; and a provider challenge must answer 200 with a certificate and
  signature, or 503 while the relay has no identity yet. With `--admin <url>`
  it also sends anonymous `GET /`, `/index.html`, `/app.js` and `/api/whoami`
  and `POST /api/keys` to the admin hostname; each must be a redirect or a
  refusal, never a success and never a 404.
- **CI:** `.github/workflows/workers.yml` with the jobs `workers build`
  (pull requests, `main` and manual runs: `npm ci`, the script tests, the
  configuration guard, `wrangler deploy --dry-run` for four configurations
  (the public and the admin Worker, each production and staging), and
  the bundle guard; no credentials), `terraform` (the lock file is tracked, `fmt -check`, `init
  -backend=false -lockfile=readonly` and `validate` in the pinned `hashicorp/terraform` Docker
  image, the way `security.yml` runs gitleaks, so no third-party action),
  `workers deploy staging` (a push to `main` only; GitHub environment
  `cloudflare-staging`; it compiles the relay core, then `wrangler deploy --env
  staging --var ALLOWED_HOSTS:<the RELAY_URL host>`, or deploys unconfigured
  with a warning when `RELAY_URL` is not a usable https URL; then the admin Worker, `wrangler deploy
  -c admin/wrangler.toml --env staging`; then the smoke test
  against the environment variable `RELAY_URL`, and against `ADMIN_URL` when
  it is set), `workers deploy production`
  (a manual run on `main` with the `production` input; GitHub environment
  `cloudflare-production`, which is intended to have a required reviewer;
  the same two deploys, public Worker first; missing secrets or an unusable
  `RELAY_URL` are an error), and `workers`, the one stable required
  check: `workers build` and `terraform` must pass, and each deploy job must
  pass or be skipped on purpose. The staging job warns and passes when its
  environment lacks the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`
  secrets, and warns and skips the smoke test when `RELAY_URL` is unset, so a
  green `workers` check does not by itself show that anything was deployed.
  Each deploy job passes `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` to the admin
  Worker from GitHub environment variables; when either is empty it warns
  and deploys the admin Worker unconfigured, which serves nothing.
  Actions are pinned by full SHA and the workflow runs with `contents:
  read`; wrangler comes from the lockfile, with no `cloudflare/wrangler-action`.
- **Other checks and repository settings:** `security.yml` has a job
  `workers dependencies` (`npm audit --audit-level=high` over all
  dependencies, because wrangler is a development dependency).
  `dependabot.yml` covers npm in `/workers` and Terraform in
  `/deploy/cloudflare/terraform`; cargo, npm and Terraform updates wait for
  a person. `.gitignore` covers `.dev.vars*`, `.wrangler/`, `*.tfstate*`,
  `.terraform/` and `terraform.tfvars`, and CodeQL ignores `workers/dist`.
- **Secrets:** the relay private key, `provider.kqcert` and `provider.kqrl`
  are Worker secrets that the operator sets locally with `wrangler secret
  put`; they are never GitHub secrets and survive a deploy. The `kql_…`
  operator lock and the provider-root private key are never on a Worker. The
  only Cloudflare credential in GitHub is the narrow Workers-deploy token
  (Workers Scripts edit only) and the account id, scoped to the two
  environments. Three further values are GitHub environment **variables**,
  not secrets: `ACCESS_TEAM_DOMAIN` (the Access team's domain) and
  `ACCESS_AUD` (the admin application's audience tag) name the Access team
  and application the admin Worker trusts, and are written into the Worker
  as plain `[vars]`; `ADMIN_URL` (optional) is the admin hostname the smoke
  test probes. None of them is a credential: a token still needs Access's
  signature.

### The admin Worker's front door (stage 4a)

Stage 4a is in the repository and has never been deployed. It is the admin
Worker's front door: the Access token check and the headers around it. The
console and API it serves are described in [The operator
console](#the-operator-console-issue-99); this section is what stood before the
console and is still true of the front door.

- **Configuration:** `workers/admin/wrangler.toml` is the Worker
  `keyquorum-relay-admin`, with `[env.staging]` as
  `keyquorum-relay-admin-staging`. `workers_dev = false` and `preview_urls =
  false` at both levels; no routes (the hostname is the Terraform's custom
  domain); `[assets]` serves `./public` through the binding `ASSETS` with
  `run_worker_first = true`, so the Worker sees a request for a static file
  before the asset layer does (observed under local workerd; that this is
  how Cloudflare's asset routing works in production is from memory,
  verify). Two non-secret `[vars]`, `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD`,
  are empty in the file and filled by the deploy job.
- **The token check:** `workers/admin/src/access.js` verifies the
  `Cf-Access-Jwt-Assertion` token: RS256 only; the signature against the key
  set fetched from `https://<team domain>/cdn-cgi/access/certs` and cached
  for an hour; the issuer `https://<team domain>`; the audience equal to the
  application's AUD tag; expiry and not-before with 60 seconds of skew. Any
  failure, a missing configuration or an unreachable key set refuses. The
  header name, the key-set URL and the claim layout are from memory, verify
  them against Cloudflare's page on validating the Access token.
- **The front door:** `workers/admin/src/index.js` (`handle`) answers a
  request with no valid token 403 `{"error":"access required"}` and fetches
  no asset; an unconfigured Worker answers 503 `{"error":"admin not
  configured"}`. Outside `/api` only `GET` and `HEAD` are served (405 otherwise); `/api` is
  the console's route table (`src/routes.js`), and a route or method not in it is
  404 or 405 with the methods it has. `/api/whoami` returns only the verified
  email and the token's expiry. Without the binding or while the relay's store
  is unavailable a data route answers a sanitized 503.
  Everything else is the static asset, with the content security policy
  `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src
  'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action
  'none'; frame-ancestors 'none'` (`'wasm-unsafe-eval'` lets the page compile
  its own WebAssembly, the identity maker in `public/provision-wasm/`, and
  allows no JavaScript `eval`), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`
  and `Cache-Control: no-store`. The refusal reason goes to the Worker's
  log and never to the caller.
- **The page:** `workers/admin/public/` is the console (`index.html`, `app.js`,
  one `view-*.js` module per page, `style.css`). It has no inline code, names no
  outside origin, writes no HTML (text is set with `textContent`, styles
  through the CSSOM) and keeps no lock or token in storage.
- **Tests:** `npm test` runs the Worker's `node:test` suite (the first 18 were
  the front door's; the console added the route, API, limits, format and
  confirmation tests).
  `src/access.test.mjs` covers a valid token, the wrong audience, the wrong
  issuer, an expired and a not-yet-valid token, a forged signature, tampered
  claims, an unknown key, HS256 and `alg: none`, a key set that is down or
  malformed, and the cache; its keys and tokens are generated at run time.
  `src/admin.test.mjs` covers nothing served without a token, failing
  closed when unconfigured, the reason logged and never returned, the
  headers, whoami, the 503 API routes, the 405 methods and a page-contract
  test that scans `public/` for inline code, handlers, inline styles,
  outside origins and `innerHTML`. Run once under local workerd (not
  repeated in CI), the Worker with `run_worker_first` answered 503
  unconfigured and 403 configured without a token, on `/`, `/index.html`,
  `/app.js` and the API.
- **Built since:** the relay-backed pages, the `/api` routes behind them and
  the binding to the Durable Object (issue #99, below). The Worker has never
  been deployed, and Access has never been configured on an account.

**Not yet, and honest limits:**

- Nothing is deployed. The public Worker and its Durable Object (stage 4c) are
  built and tested but have never run on a Cloudflare account, and a Durable
  Object migration has never been applied. The admin Worker and its console
  (stage 4a and issue #99, above) have never been deployed, and Access has never
  been configured on an account.
- **Keys are minted only from the console.** The relay has no create or rotate
  route, by design. A deployed relay answers every customer route with 401 until
  the operator, signed in through Access, creates the operator lock and issues a
  key (`relay-deployment.md`, "Operator console").
- The Terraform has been validated only by CI: the `terraform` job ran
  `fmt -check`, `init -backend=false` and `validate` on commit `f73223f` and
  reported "The configuration is valid" against provider 5.27.0. The
  repository's authors have never planned or applied it against a real
  account (none was available), so the first `terraform plan` is the
  first check of its behaviour. The admin resources (`admin_environments`)
  came after that commit; the `terraform` job accepted them too (commit
  `86bbb8f`), which again proves syntax and schema only.
- Cloudflare Notifications (Worker and Durable Object error alerts) and the
  R2 bucket's retention lock are not in Terraform; they are dashboard steps
  for now.
- The wasm32 build runs in `workers.yml` (the `workers build` job and both
  deploy jobs) and in Workers Builds (`builds:build`); the latter has never run
  on Cloudflare's image.
- The admin Worker's routes and Access application are in `access.tf`,
  created only once `admin_environments` is set, and have never been applied.
- The owner must create the GitHub environments `cloudflare-staging` and
  `cloudflare-production` with their `CLOUDFLARE_API_TOKEN` and
  `CLOUDFLARE_ACCOUNT_ID` secrets and the `RELAY_URL` variable (and the
  production required reviewer), add `workers` to the required checks, and
  have a Cloudflare account, the `keyquorum.dev` zone on it, a proxied DNS
  record for each relay hostname (Terraform does not create it) and the admin
  hostname chosen (check the zone's existing rate-limit and cache rules first:
  the Terraform replaces them in those two phases). The
  Worker must be
  deployed before `terraform apply`, because a route names an existing
  Worker. For the admin Worker the order is: deploy it (it serves
  nothing while unconfigured), `terraform apply`, read the application's
  audience tag from the `admin_access_aud` output and the team domain from
  the Zero Trust dashboard, set the variables `ACCESS_AUD`,
  `ACCESS_TEAM_DOMAIN` and `ADMIN_URL` on the GitHub environment, and
  deploy again.
- `terraform apply` of the two rulesets replaces any rules already in the
  zone's `http_ratelimit` and `http_request_cache_settings` entry-point
  phases; import existing ones first.

### Roles: least privilege

| Role | Who | Allowed | Not allowed |
| --- | --- | --- | --- |
| Deploy | the Workers-deploy API token (`CLOUDFLARE_API_TOKEN`, Workers Scripts edit only, with `CLOUDFLARE_ACCOUNT_ID`) held as secrets in the GitHub environments `cloudflare-staging` and `cloudflare-production` (production intended to have a required reviewer) | edit the Workers scripts | read Worker secrets or Durable Object data, change Access, DNS, WAF rules or the Terraform-managed zone settings |
| Operate | the operator's day-to-day identity, through Cloudflare Access with MFA | reach the admin Worker and use the console (users, licences, keys, activity, status, audit, checkpoint; every change also needs the operator lock), read Access and account audit logs and the notifications | change Access policies, change the zone, delete Durable Object data |
| Backup | a write-only export credential (an R2 token limited to the archive bucket's write, if the optional bucket is used; otherwise none, and the operator pulls exports and checkpoints) | write an export object | read or delete other objects |
| Restore | a separate identity used in the restore drill, in a test account or a test Worker | create and fill a test Durable Object from an export, run the verification | reach the production Workers, hold the production relay key |

Record each role's token scopes and policy with the deployment;
`docs/soc2-controls.md`, "Operator responsibilities", names these as the
operator's controls.

## The operator console (issue #99)

The provider's console is built in the repository and has never run on a
Cloudflare account. It is for the service provider's own people only: a customer
never reaches it, holds no Access membership and receives no `admin` key. It
lets the provider record customers (the console calls them users), record the
licence terms each one holds, issue, replace, assign and revoke their API keys,
see what each key did, and download evidence. It extends the admin Worker
(`workers/admin/`); the public Worker gained no management route.

```text
Operator browser
  -> keyquorum.dev/relay/admin (staging: /relay/staging-admin), a Workers route
  -> Cloudflare Access (operator identity + MFA)
  -> admin Worker (Access token check, Fetch Metadata and Origin checks,
                   per-operator rate limits, route table, bounded bodies)
  -> binding RELAY_ADMIN (cross-Worker Durable Object, script_name = the relay)
  -> RelayObject.operate / status -> Rust core (relay::operator) -> SQLite

Customer API client
  -> keyquorum.dev/relay (staging: /relay/staging-user), a Workers route
  -> public Worker (host, mount and route allowlists)
  -> the same RelayObject -> relay::service::dispatch
```

### What the core holds (`src/relay/`)

- **Customers** (`customer.rs`, table `customers`): an id the provider
  assigns, a name and an optional reference of the provider's own. Ownership of
  a key is never inferred from its label, an address or a recipient
  fingerprint; a push key has no fingerprint at all.
- **Licences and statement versions** (`licence.rs`, tables `licences`,
  `licence_versions`): one customer may hold several licences. A licence's
  statement is signed into every key issued under it. Versions are immutable (a
  database trigger refuses an update or delete), so a statement already signed
  and delivered is never rewritten: renewal adds a version.
- **Key links and lineage** (`licence.rs`, table `licence_keys`): a key belongs
  to a licence by an explicit link, and a replacement records `replaces_key_id`,
  so ownership and history follow a key through rotation. A key with no link is
  **unassigned**, never guessed; `assign_key` is the operator's explicit act.
  Existing keys (made before the console, or by the native `host keys`) stay
  unassigned after the additive schema upgrade, so none is attached to the wrong
  customer.
- **Issuance** (`issuance.rs`): issue, replace (by bundle, or by mailbox letter
  where the customer can collect it), void a key and void a licence, each in one
  `SqlRelayStore` unit of work with the link, the key change, its
  `api_key_events` row and the operation record. The sealed bundle comes from
  `key_delivery`; no function returns a bearer, and no bearer or key hash is in
  any reply.
- **Activity** (`activity.rs`, table `access_activity`): hourly counts of what
  a *known* key did, by route category and outcome, with the time requests took
  and the bytes each way. Only a bearer that matches a stored key is recorded,
  so an anonymous caller cannot grow the table and an unknown credential is never
  attributed to anyone; a refusal is recorded only when the key was the reason
  (`revoked`, `expired`, a `scope` it does not hold). No bearer, hash, address,
  query, body or path past its first segment is kept (no IP is retained, by
  default and by decision). Rows older than `RETENTION_DAYS` (90) are dropped by
  the housekeeping scan. It is a usage view, **not evidence**: it is not in the
  audit chain, its durations are coarse (a Durable Object's clock moves only when
  it waits), and the console labels it so.
- **Operator log** (`operator_log.rs`, table `operator_actions`): which Access
  identity asked for which change, the operation id, the outcome and the ids it
  produced, written in the same transaction as the change. Refused lock checks
  are recorded in the existing hash-chained `provider_auth_events`; key changes
  in the hash-chained `api_key_events` (actor `host`, which the core already
  uses; the Access identity is in `operator_actions`, linked by the operation).
  The console does **not** claim that every core event carries an Access
  identity: the two records are linked, not merged.

### Decisions recorded (issue #99, section 7, step 1)

| Question | Decision |
| --- | --- |
| Licence semantics | **Signed terms, an end date and revocation.** A licence enforces nothing by itself: what stops a client is a revoked or expired *key*. No seats, features, metering, billing, payment or automatic suspension; adding any is a separate decision and would be enforced in the Rust core. The console shows licence status (administration) apart from each key's state (what the relay will actually authorize). |
| Does voiding a licence revoke its keys? | Yes: all keys linked to it, in the same transaction. Voiding one key revokes only that key. |
| Renewal and key expiry | Renewal adds a statement version and may set a new end date. Keys already issued keep the end they were issued with; replacing a key gives the replacement the licence's current end and statement. Clients need a new sealed issue only to get the new end or statement. |
| Replacing a licence | `replaces_licence_id` voids the old licence (and its keys) in the same transaction as creating the new. |
| Old sealed bundles | Unchanged: no wire format changed (`KeyIssue.licence` is still signed text). |
| Operator login and second factor | **Recommended (owner, 2026-10-06): a hardware security key.** Login is the Cloudflare identity provider or a one-time PIN to the operator's own address, then Access's *independent MFA* with a security key (a Zero Trust organisation setting, enrolled at `<team>.cloudflareaccess.com/AddMfaDevice`, with a spare key). Terraform creates the application and the allow policy for `operator_emails` but not the second factor, which is a dashboard step this repository cannot create or verify; the former `auth_method = "mfa"` requirement is now the opt-in `idp_mfa_required`, because it can be satisfied only by Okta, Entra ID, generic OIDC or generic SAML. Sign in with Apple is not recommended (not a built-in provider, an expiring client secret, and a private-relay address that the email match would miss). A later design could ask for the security key on each change inside the console itself. Source: Cloudflare, Enforce MFA and Independent MFA (read 2026-10-06 through the documentation search, not run). |
| Role model | **One role: operator.** Cloudflare Access decides who is in (the Terraform policy lists the emails; the second factor is the row above); the Worker then applies the same rules to all of them, and every change is attributed to the verified email. There is no read-only or per-customer role. Role policy inputs for `access.tf` are not added; they would follow an approved design. |
| Customer self-service | Not built. It would need its own authentication and object-level authorization. |
| Bundle recovery contract | The operation id is the recovery contract; **sealed bundles are not retained** (nothing to expire, store or leak). A lost download is reconciled by sending the same `Idempotency-Key` again: the answer is `409 already_done` with the ids the first attempt made, and nothing is made twice. The key then exists but its file was lost, so the operator **replaces** it (a new key and file; the old one is revoked). Nothing automatically mints again after an uncertain outcome. |
| Operator-lock custody | The `kql_` lock is presented with each change (`x-operator-lock`), checked against the hash the relay holds and never stored, logged or echoed; it is not a Worker secret and the browser keeps it only in the form field (no storage, cookie or URL). The bootstrap is explicit and in two steps: see below. |
| Activity retention | 90 days, hourly aggregates, no IP. |

### The operator lock ceremony

A normal request on an empty store cannot become the issuer. The operator
presents Access (MFA) and chooses **Create the lock** (`bootstrap`, only while
no lock exists) or **Replace the lock** (`rotate_lock`, with the current one).
Either stages a new lock in `licensee_pending` and shows it **once**;
`confirm_lock` (the lock presented back) promotes it. Until confirmation the
previous lock (or none) stands, so a lost response cannot lock the provider out:
the operator repeats the step and a new pending lock replaces the old pending
one. **Gap:** if the confirmed lock itself is lost there is no console recovery;
there is no recovery path on the Cloudflare relay today other than restoring
storage or a reviewed migration that clears the lock row, and that is not built
or tested (`relay-deployment.md`, "Operator console", "Lost operator lock"). The two lock records are the `licensee_issuer` and
`licensee_pending` tables.

### Admin API

Every route is JSON, answered by `relay::operator` through the binding. The
Worker keeps out anything not in `workers/admin/src/routes.js`, takes digits-only
ids from the path, refuses a query parameter a route does not list, and refuses
a body over 64 KiB before reading it (the core holds the same cap).

| Route | Purpose |
| --- | --- |
| `GET /api/overview`, `GET /api/status` | counts, the lock state, identity and certificate, readiness; status adds storage use, the housekeeping alarm, overload refusals and the deployed version where the Durable Object can see them. Its counters are the object's own since it last started, and a figure it cannot read is shown as unavailable |
| `GET /api/users` (`search`, `status`, `before`, `limit`), `GET /api/users/:id`, `GET /api/users/:id/licenses` | users with cursor pagination, detail with licences, versions and keys |
| `POST /api/users`, `POST /api/users/:id/licenses`, `POST /api/licenses/:id/renew`, `POST /api/licenses/:id/revoke` | create a user, record a licence, renew it (new version), void it |
| `GET /api/users/:id/keys`, `GET /api/keys` (`state`, `assignment`) | key metadata only: id, label, scope, recipient binding, created, expiry, revoked, last use, licence, lineage |
| `POST /api/users/:id/keys`, `POST /api/keys/:id/rotate`, `POST /api/keys/:id/revoke`, `POST /api/keys/:id/assign` | issue (sealed `.kqkey` bundle), replace (bundle or letter, bounded grace for a letter), revoke, assign an unassigned key; `admin` scope is not offered by the issue form or the route |
| `GET /api/users/:id/activity`, `GET /api/activity` (`hours`, `key_id`, `route`, `outcome`) | counts, errors, latency, bytes, last activity |
| `GET /api/audit` (`feed`), `POST /api/checkpoints` | key events, lock checks and the operator log, paged; a signed checkpoint to keep off the relay |
| `GET /api/letters`, `GET /api/trees` | letters by kind, size and time, and public tree labels and generations |
| `POST /api/operator-lock/{bootstrap,replace,confirm}` | the lock ceremony |

A change is a `POST` with an `Idempotency-Key` (the operation id, which the page
makes once per attempt and reuses on a retry), the lock in `x-operator-lock` and
a body the core validates (scope, expiry, recipient key, sizes). Errors are
sanitized and carry a stable `code`. Reads need only the verified identity.

### Request protections (admin Worker)

The Access token is verified before any asset or API is served. Fetch Metadata
and `Origin` refusals run before that (a top-level link is let through only to
the token check). A change must carry an `Origin` equal to the Worker's own, so
a page on another site cannot cause one; there is no cookie or ambient
credential for it to ride, since the lock is a header the page sets. The
operator's identity is taken from the verified token, never from the request. A
per-operator limit applies to reads (`READ_LIMITER`, 120 a minute) and to
changes (`WRITE_LIMITER`, 20 a minute), keyed on the verified email; a limiter
that cannot answer lets the request through (the operator is behind Access and
the lock, so locking the provider out was judged worse), and the count behind
the limit is Cloudflare's, so it is approximate. The page
keeps to the CSP (no inline code or style, same origin only, no `innerHTML`), and
a test scans the assets for it.

### What the console cannot show, by design

File contents, tracked-file histories, user histories and anything else inside a
sealed letter. The relay stores sealed envelopes it cannot open, so it can show
only a letter's kind, size, time and recipient, and the console says so. It also
cannot see what a client did locally, and a request the public Worker refused
before it reached the core (a bad host, an unlisted route, a rate limit) is not
counted: the activity page counts requests the core admitted and attributed.

### Verification so far, and what is still owed

Done in this repository: the core's unit tests and the store conformance suite
(`relay::store::conformance`, including an executor that refuses transaction
statements) cover ownership, versions, lineage, void and renew effects,
operation ids and replays, the two-step lock, activity attribution (unknown
bearers unrecorded), pagination and retention; `workers/test/relay-service.test.mjs`
runs the built core over a Durable Object-shaped storage; `workers/admin` tests
cover the routes, the Access and Origin checks, limits and the page contract;
the cross-Worker binding was exercised under local workerd; and a headless
Chromium walkthrough drove the real page against the built core, including a
response lost after the commit that was reconciled with the same
`Idempotency-Key`.

**Not done, and not claimed** (they need the operator's Cloudflare account and
the staging setup of "Provisioning and the deployment pipeline"):

- A deploy to isolated staging, and with it the checks #99 asks for there:
  Access with and without MFA, asset protection, the private binding on
  Cloudflare, sealed issue, replacement and revocation end to end, the
  housekeeping alarm, overload, and a real Version URL answering 404.
- The restore drill, including that a restore must not reactivate a key revoked
  after the restore point (reconcile against a checkpoint taken later).
- Measured storage growth, write amplification, query latency and Cloudflare
  cost. The activity table is bounded by keys, hours and routes rather than by
  traffic, but that is a design bound, not a measurement.
- The status page's storage, alarm and overload figures depend on what the
  Durable Object and Workers runtime expose; each is shown as unavailable rather
  than guessed.
- Request metrics at the public Worker (rejections before the core).
- A second role, customer self-service, and any enforced licence limit.
- Admin previews stay off. A Preview's binding does not necessarily point at a
  matching downstream Preview, so none is enabled until that is proved.

Deploy order: the public Worker first (the console's binding needs its class),
then `terraform apply`, then the admin Worker with its variables (the existing
order in "Provisioning"). The binding names this environment's relay only
(`keyquorum-relay` or `keyquorum-relay-staging`), which `guard.mjs` checks, and
the admin file carries no Durable Object migration.

## The Workers relay

**The public Worker and its Durable Object are built, and have never been
deployed.** The `provider` feature (axum, tokio, rusqlite) cannot build for
wasm32, and `build.rs` refuses it there, so the Worker runs the part that is
portable: `relay::service::dispatch` (`src/relay/service.rs`), the synchronous,
runtime-independent request router that the browser lab already runs in process
on wasm32, behind `SqlRelayStore` over the Durable Object's SQL
(`src/relay/worker.rs`, `RelayCore`, compiled to WebAssembly by `npm run
build:relay-wasm`). Around it, `workers/src/` holds the public Worker and the
Durable Object. It is a new store and a thin fetch adapter around the existing
router, not a rewrite, and it re-rolls no relay rule. The relay has no create
or rotate route by design (HTTP never mints); a key is minted by the admin
Worker's console through a private binding to the same Durable Object, with the
operator lock presented per change ([The operator
console](#the-operator-console-issue-99)). Neither Worker has been deployed.
The architecture below says which parts are built.

### Architecture

- **Public Worker `keyquorum-relay` (built: `workers/src/worker.js`).**
  Serves only the hosts in `ALLOWED_HOSTS` and answers 404 on any other (a
  Version URL included, above). Routes only the customer routes, an allowlist
  in `policy.js`: `POST /provider-identity`, `POST /keycheck`, `POST` and `GET
  /inbox`, `GET /audit/api-keys`, `PUT /trees`, `GET /trees/<label>/context`,
  `POST` and `GET /devices/packages`, `PUT /devices` and `GET /devices/<id>`;
  every other path is 404 and a known path with another method is 405, so
  `/api-keys*`, the full `/audit/*`, `/swagger-ui/*` and anything that mints are
  not on this Worker, whatever the core's own router would do with them. Splits
  a path the way the core does, so a path means the same in both. Refuses a
  declared body over 2 MiB (`MAX_ENVELOPE_BYTES` is 1 MiB per envelope) before
  reading it and bounds an undeclared one while reading. Applies a per-client
  limit keyed on `CF-Connecting-IP` through a Workers rate-limiting binding
  (`RATE_LIMITER`, 300 per 60 seconds, never reading `X-Forwarded-For`); a
  missing or failing limiter does not stop the relay, since the zone rule and
  the object's bound still apply. Sets `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff` on every response, including the object's.
  Serves only under `/relay` (everything else is 404). Answers `/relay/health`
  (the Worker alone), `/relay/ready` (only when the Durable
  Object's store answers) and a status page at `/relay/` with its two asset files
  (no inline code, no outside origin, a locked-down policy). Hands everything
  else to the Durable Object. It does no redirects and no challenge on API
  paths: the client uses `max_redirects(0)` and treats a 503 from
  `/provider-identity` as an untrusted relay (`src/relay/client.rs`,
  `http_agent_config`, `authenticate_provider`).
- **The relay inside the object (built: `workers/src/relay-service.js`,
  `relay-object.js`).** It reads the bearer as the native router does
  (`Authorization: Bearer <token>` with that exact prefix, else a non-empty
  `x-api-key`; `src/relay/server.rs`, `token_from_headers`) and hands it to the
  core, never logging, storing or echoing it. It bounds the object's queue:
  past `MAX_IN_FLIGHT` (32) concurrent requests a new one is refused at once
  with 503 and `Retry-After: 1`, so nothing waits behind the single writer
  unbounded. It takes the identity from two Worker secrets, `RELAY_PRIVATE_KEY`
  (the file `host identity generate` writes, a hex dump of 32 bytes, or its
  base64) and `RELAY_CERTIFICATE` (`provider.kqcert`, base64). With neither,
  the relay answers its routes and refuses the provider challenge, so no
  official client trusts it; with only one, or a certificate that is not valid
  base64, or a key that is not 32 bytes, it fails closed with 503 `relay
  identity misconfigured` and names no value; the copy of the key in JavaScript
  is zeroed once the core has taken its own. A core that throws is a generic 500,
  and nothing it says is logged beyond the error's name. Its alarm runs hourly:
  the core's `scan` drops expired letters and signs the audit heads, and the
  next alarm is set even if the scan failed. The core takes no revocation list
  yet, so `provider.kqrl` is not read by the Worker.
- **One SQLite-backed Durable Object.** It holds the whole relay and runs
  `relay::service::dispatch(&DoRelayStore, Some(&identity), &req)`. One
  object is the single writer, which the audit hash chain, the key tables
  and the key-delivery letters need because they are written together
  (`src/relay/audit.rs`); the synchronous `RelayStore` trait fits only
  inside it, where SQL execution is synchronous.
- **`DoRelayStore`.** `SqlRelayStore<S>` (`src/relay/store.rs`) over the
  Durable Object's SQL API. The seam is built (stage 4b): every relay table
  module (`api_key`, `audit`, `mailbox`, `device_mail`, `device_directory`,
  `org_tree`, `key_delivery`) takes `&dyn relay::sql::Sql` and never a
  `rusqlite::Connection`, and none opens `BEGIN` or `COMMIT` itself; a unit of
  work is `Sql::transaction`, which nests (rusqlite: `BEGIN IMMEDIATE`; a
  Durable Object: `transactionSync`). `Sql` carries no rule. It binds values,
  runs a statement, streams rows (a 16 MiB inbox page is decided as rows are
  read, by `mailbox::PageBuilder`, never collected first), reports
  `last_insert_rowid` and `changes`, and nests a transaction; the SQL stays
  SQLite's own. `SqliteRelayStore` is `SqlRelayStore<rusqlite::Connection>`.
  The remaining work is the Durable Object's executor (a JavaScript-backed
  `Sql` for wasm32, where a `Mutex` is uncontended) and the Worker around it.
  The store re-rolls no rule, and it passes `relay::store::conformance` and
  the concurrent-writers test twice in `cargo test`: over a `rusqlite`
  connection, and over an executor that refuses transaction statements as a
  Durable Object does (`store/tests.rs`, `HostTransactions`).
- **Clock.** Times that SQL takes from `'now'` and from column defaults need
  no change: the spike measured them to agree with `Date.now()` in a Durable
  Object. Only times Rust takes from `SystemTime` (`provider::system_now_utc`:
  the audit anchor's `signed_at`, which `anchor_audit` already takes as a
  parameter, and certificate validity) need an injected clock on wasm.
- **Admin Worker `keyquorum-relay-admin`.** Its front door exists (stage
  4a, `workers/admin/`, described under Provisioning); the relay-backed part
  is planned. Its only path is a Workers route behind an Access
  self-hosted application (operator identity plus MFA), no route bypasses
  Access, and `workers.dev` and preview URLs are off (that this switches
  them off is from memory, verify; `scripts/guard.mjs` fails CI if either
  setting is missing or `preview_urls` is on for this Worker). A preview
  hostname is outside the Access application, so this Worker never gets one. The Worker verifies the Access token itself (the
  `Cf-Access-Jwt-Assertion` request header, checked against the Access
  team's published key set for its signature, and for the application's
  audience tag, issuer and expiry; from memory, verify the header and
  key-set details), so that a mistake in the Access application does not
  expose it; that check is implemented and tested (`src/access.js`), not
  planned. The Worker serves the console and its route table, and reaches the
  relay through the binding `RELAY_ADMIN` to the same Durable Object, calling
  only `operate` and `status` (a cross-Worker Durable Object binding, which
  needs the public Worker to be deployed first; the exact Cloudflare behavior
  is from memory, verify on staging). For a mint or replacement the Durable
  Object seals the `.kqkey` with the relay key and returns only sealed bytes,
  which the page offers as a download. A response lost after the commit can
  leave a key with no file; the operation id reconciles it (the console
  section: sent again, it says "already done" with the ids, never mints twice),
  and the operator replaces the key. The native `host keys` CLI keeps
  `Error::StoreCommitUnknown` for the same case on the reference host.
- **Which routes are public.** Customer routes (`/inbox`, `/keycheck`,
  `/provider-identity`, `/devices/*`, `/trees/*`, `GET /audit/api-keys`)
  are on the public Worker. The operator routes (`/api-keys*`, the full
  `/audit/*`, anything that mints) are for the admin Worker only (the public Worker's
  allowlist routes none of them), and the
  public Worker serves no console and no `/swagger-ui/*`. Whether an admin
  API key may still revoke over the public Worker, as it can on the native
  router today, is a PR 4 decision; until it is made, the public Worker
  does not route it. The admin Worker's only path is a Workers route
  behind an Access application; no route bypasses Access, and the Worker
  verifies the token itself.
- **Secrets on the Worker.** The relay private key, `provider.kqcert` and
  `provider.kqrl`, as Worker secrets (not readable back through the API,
  survive a deploy; from memory, verify), used by the same `signing` code,
  so signatures, sealed key delivery (`KQPB` kind 20, `.kqkey`) and audit
  anchors stay byte-compatible: the formats are the crate's, not the
  host's. They are set as `npx wrangler secret put RELAY_PRIVATE_KEY <
  relay.key` and `base64 < provider.kqcert | tr -d '\n' | npx wrangler secret
  put RELAY_CERTIFICATE`. Never on a Worker: the provider-root private key and the `kql_…`
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

### Front ends, and independence from the Lab and the portfolio

The relay has its own front ends and shares nothing with the Lab
(`lab/`, published to GitHub Pages) or the portfolio
(`bailey-forbes.com`), which embeds the Lab. The relay's domain,
`keyquorum.dev`, is a different site from both.

- **Public site (built).** The public Worker's own pages, `/relay/` (a status page
  with a policy that allows no inline code and no outside origin) and
  `/relay/health` and `/relay/ready`, on the relay's hostname only. Customers do not use a web
  page to send letters: `keyquorum` does, with a `kq_…` bearer, and a browser
  client would need the sealing and signing done in the page, which is not built.
- **Operator console (built, not deployed).** The admin Worker, on its own
  hostname behind a Cloudflare Access application with MFA, which verifies
  Access's token itself (`workers/admin/`). Nothing it serves is reachable
  without that token. It is for the provider only; see [The operator
  console](#the-operator-console-issue-99).
- **No path from the Lab or the portfolio to either.** The Lab's relay is
  `relay::service::dispatch` running in the visitor's browser tab at
  `https://relay.keyquorum.lab`, a name no network request ever leaves for
  (`src/lab/vm.rs`); the Lab bundle and the portfolio name no relay host
  (`workers/test/independence.test.mjs` reads `lab/` and `src/lab/`). Neither
  Worker sets a CORS header, so a page on another origin cannot read an answer.
  Both refuse a browser request that comes from another site before routing it,
  by Fetch Metadata and `Origin` (`workers/src/browser-isolation.js`): a fetch,
  frame, script, image or form post from the Lab or the portfolio is 403, and
  every answer carries `Cross-Origin-Resource-Policy: same-origin`,
  `X-Frame-Options: DENY` and `Cross-Origin-Opener-Policy: same-origin`, so
  neither site can embed or script them. Typing the address, a bookmark, the
  site's own page and a command-line client (which sends none of those headers)
  are served. Top-level GET/HEAD links and redirect chains from another site may
  reach the public status page, its mount-to-slash redirect, and the preview-only
  root redirect. API paths remain refused, even for a top-level navigation;
  fetches, forms, frames and foreign/null Origin headers remain refused everywhere.
  On the admin Worker a top-level link is let through to the token check,
  because Cloudflare Access sends the operator back through a redirect that
  starts on Access's own domain and a refusal would lock the operator out; the
  Worker still serves nothing without a valid token.
- **What this is not.** It is a browser-side control, not authentication: a
  person or script outside a browser can set any header, and who may use the
  relay is decided by the bearer (public Worker) or the Access token (admin
  Worker). Separate DNS names, Access and the zone's own rules are the operator's
  to keep (the relay's hostnames are subdomains of the portfolio's zone, so its existing rules matter; see the domain decision).

### What the spike measured (stage 3)

Run on 2026-10-06 with `workers/spike/` (a throwaway Durable Object probe;
see its README) under local `wrangler dev --local`, wrangler 4.147.0 and
workerd 1.20261001.1, plus a release build of the library for
`wasm32-unknown-unknown` for size. Local workerd is the real SQLite and
Durable Object API, but it is not Cloudflare's production limits or billing,
and the table says where that matters.

| Question | Measured | What follows |
| --- | --- | --- |
| The relay's schema | `src/relay/schema.sql` applied verbatim as one multi-statement `exec` on an empty Durable Object and created every relay table; `PRAGMA foreign_keys = ON` was accepted and read back | Works. A new Durable Object needs only the current schema: `migrate` (`ALTER TABLE`, the `api_keys` rebuild) only upgrades old files and nothing is deployed. Its statements (`PRAGMA table_info`, `ADD COLUMN`, `RENAME`, `DROP`) also ran, should that change. |
| Transactions | `BEGIN IMMEDIATE` is refused with an error that points to `transactionSync`; `transactionSync` commits and returns the callback's value, rolls back when the callback throws, and nests | Works, with a design consequence: `with_immediate_transaction` cannot be used. The `Sql` seam has a `transaction` method (rusqlite: `BEGIN IMMEDIATE`; Durable Object: `transactionSync`), built in stage 4b. |
| SQL time | `strftime('%Y-%m-%dT%H:%M:%fZ','now')` and `datetime('now')` returned the same instant as `Date.now()`, and a column `DEFAULT` that uses it filled in | The SQL-side `'now'` needs no change. Times the Rust code takes from `SystemTime` (anchor `signed_at`, certificate validity) still need an injected clock, because `SystemTime` cannot run on wasm. |
| Row ids and errors | `RETURNING id`, `last_insert_rowid()` and `changes()` agree; a UNIQUE or CHECK violation is a thrown exception whose message carries `SQLITE_CONSTRAINT_UNIQUE` or `SQLITE_CONSTRAINT_CHECK` | Works. The store must map exceptions to the crate's errors by that text; idempotent letter push relies on the UNIQUE (recipient, content hash) key. |
| Write amplification | `UPDATE api_keys SET last_used_at ...` wrote one row | Every authenticated request writes a row, and Durable Object SQLite bills rows written (from memory, verify). Stage 4 decides whether `last_used_at` may be stamped at most once per interval, which changes its precision. |
| Storage size | `sql.databaseSize` is readable inside the object | The storage alert has a source, through the admin Worker. |
| Scheduling and randomness | an alarm set 300 ms ahead fired; `crypto.getRandomValues` returned 32 bytes | The purge scan can be a Durable Object alarm, and the source the `getrandom` `wasm_js` backend calls exists. Not yet exercised from Rust under workerd. |
| A 16 MiB inbox page | 16 letters of 1 MiB were read, base64 encoded and JSON encoded: a 22.4 MB body in about 1.15 s | Works locally. Memory was not measured: local workerd does not enforce the production isolate limit. |
| Row size | a 4 MiB blob and a text value of 2 MiB plus one byte were accepted | Local workerd does not enforce production's 2 MB row limit (from memory, verify), so this run proves nothing about it. The design stays under it regardless: a letter is capped at 1 MiB, and tree documents must be capped or chunked. |
| Bundle size | a release build of the library for wasm32 with the `lab` feature (the relay core, SQLite and the whole CLI) is 6.65 MiB raw and 2.02 MiB gzip, before `wasm-opt` | An upper bound for a relay-only Worker. It is under the compressed limits remembered for the Free and Paid plans (from memory, verify), so size is not the risk; confirm it at the first real deploy. |

Not settled by a local run, because each needs Cloudflare's production
limits or the owner's account: row-size enforcement; peak memory against the
isolate limit (from memory, 128 MB); the compressed bundle limit; the
point-in-time recovery window; which plan SQLite-backed Durable Objects need,
and the cost; and a first build of the relay as a Rust Worker, including
`getrandom` from Rust under workerd.

### Decision (2026-10-06): adopt

**Adopt the Workers relay on one SQLite-backed Durable Object.** The local
evidence removes the risks that could have ended the design: the relay's real
schema, transactions through `transactionSync`, SQL time, constraint errors,
alarms and a 16 MiB page all work, and the size upper bound sits well inside
the limits as remembered. What remains are production-only checks. They gate
launch, not the build, in this order:

1. The owner's Cloudflare plan, the cost, and the point-in-time recovery
   window (from memory, verify); if it cannot meet the 1 hour RPO, add the
   cron export.
2. Peak memory of a 16 MiB page on a real deployment; if it does not fit, a
   smaller Workers-specific page budget through `mailbox::bound_page`, which
   `next_after` already tolerates.
3. Row size at the production limit; the design already stays under it.
4. The first build of the relay as a Rust Worker, and `getrandom` from Rust
   under workerd; if the Rust path fails, a thin JavaScript shim around the
   wasm-bindgen output.

A failure that cannot be mitigated inside Cloudflare reopens the hosting
decision with the owner; it does not default to another provider.

### Estimate

| Item | Effort |
| --- | --- |
| Feasibility spike (stage 3) | done |
| Workers adapter over `service::dispatch`, feature gating, build | 1 week |
| `DoRelayStore` to conformance | 2 to 3 weeks |
| Admin Worker: mint, rotate, events, checkpoint, export and restore commands | 1 to 2 weeks |
| Load, limits and custody review; runbook | 1 week |
| Cost | a Workers plan plus Durable Object storage and requests; needs the owner's account to measure |

These are the author's estimates, not measurements.

## Provider-only issuance on every path

The hosting platform does not decide who can mint. These do, on the native
reference host or in a Worker alike:

- **The provider-root private key stays offline.** `host certify`, `host
  krl` and `host policy issue` are run on the offline machine
  (`relay-deployment.md`, "Offline provider certificate issuance"); nothing
  on a Worker holds it. The root the relay pins is its `PROVIDER_ROOT`
  deploy variable (public, from `root.pub`); a client build compiles its
  root into `KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY` from `KEYQUORUM_PROVIDER_ROOT`
  or a git-ignored `provider-root.pub`, and one built with neither carries a
  placeholder whose private half nobody holds and trusts no relay. No root is
  committed; the clients handed out must be built with that ceremony's
  `root.pub`, and that build recorded.
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
  The Workers relay's bootstrap is the console's two-step ceremony (staged,
  shown once, confirmed; the console section) and keeps the same property: the
  lock is a hash in the store and a value the operator holds, never a Worker
  secret.
- **No public minting endpoint.** The public Worker has no create or rotate
  route; minting is only on the Access-protected admin Worker, which also needs
  the operator lock for each change. On the
  native router the same rule holds today: the HTTP API lists and revokes
  keys and nothing more (`src/relay/server.rs`, `router`: `GET /api-keys`,
  `POST /api-keys/{id}/revoke`; there is no create or rotate route), which
  `src/relay/server/tests.rs` (`router_enforces_scopes_and_returns_opaque_bytes`)
  pins. For the Workers relay, the staging smoke test
  (`workers/scripts/smoke.mjs`, which asserts that the operator, documentation
  and mint routes answer 404 or 405 on the deployed Worker) and the route
  allowlist test (`workers/test/worker.test.mjs`) pin it.
- **Customers receive bearers sealed**, as a `.kqkey` bundle or a mailbox
  letter signed by the relay key (`src/api_key_delivery.rs`,
  `src/relay/key_delivery.rs`); a bearer is never printed by the host.
- **Licence statements are signed text, not enforcement.** `KeyIssue.licence`
  travels signed; the relay meters no seats and suspends nothing by
  subscription. The initial service offers manually issued, scoped
  credentials; revocation and expiry are the controls. Statements are versioned
  and immutable, and the console records a licence per customer with its keys.
  Voiding a licence revokes its keys (the revocation is the enforcement). Do not
  describe it as subscription enforcement.

## Availability and recovery

### Objectives

| Objective | Value | Why |
| --- | --- | --- |
| RPO | 1 hour (backup interval), 24 hours for the audit checkpoint | letters are re-sendable by their senders (`outbox send`), keys re-issuable; the audit trail is what must not be lost |
| RTO | 2 hours | restore the Durable Object's data into a replacement object and redeploy the Worker from the pinned bundle; no cluster to rebuild |

### Backups

- **Durable Object point-in-time recovery**, if the production check confirms
  that it covers the 1 hour RPO (from memory, verify: the retention window and the
  restore procedure). If it cannot, a scheduled export of the database
  (a cron-triggered Worker writing to the optional R2 bucket, or the admin
  Worker's export pulled by the operator) is added, hourly, kept 7 days
  (daily kept 90); the production check decides which. Either way the export is a SQLite file in the schema the native
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
| health and readiness | an external probe of `GET /relay/health` and `GET /relay/ready` over the public hostname | 3 failures in a row |
| provider identity | a synthetic client that runs `keyquorum loadkey` with a throwaway store and key (only this proves the identity; `/ready` does not) | daily, any failure |
| certificate expiry | the external probe's TLS check (the edge certificate's renewal is Cloudflare's), and the expiry date of `provider.kqcert` known from issuance and checked by the operator on a schedule | 30 days before either |
| storage | the database size against the Durable Object's 10 GB limit, from the console's status page (`storage_bytes`, read by the Durable Object; unverified on Cloudflare) or Cloudflare's Durable Object metrics (from memory, verify which is available) | 70 % warn, 85 % page |
| Worker and Durable Object errors | Cloudflare Notifications on error rate for both Workers and the object (from memory, verify); a dashboard step, not in the Terraform yet | a sustained rise |
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
| Byte-bounded inbox responses | **Done in the library.** `MAX_INBOX_PAGE_BYTES` (16 MiB) in `src/relay/mailbox.rs`, `bound_page`, shared by every backend; at least one letter per page, `next_after` stateless. **Unverified on Workers:** whether a 16 MiB page fits the isolate memory. | Production-only check (peak memory); a smaller Workers page budget through `bound_page` if it does not fit. |
| Bounded database admission | **Done for the native host.** `DEFAULT_STORE_CONCURRENCY` (64) and `STORE_ADMISSION_WAIT` (5 s, then 503) in `src/relay/server.rs`, two separate slots for `/ready`; the permit is held until the store call returns. **Workers:** the Durable Object serialises requests through its single writer, and `MAX_IN_FLIGHT` (32, `workers/src/relay-service.js`) bounds what is in it: past that a request is refused at once with 503 and `Retry-After`, tested with stalled bodies. Not measured under real overload. | Measure under the overload test, and tune the bound. |
| Provider-controlled retention and storage quotas | **Partly.** Letters expire when pushed with `--expires`, device letters after `DEVICE_PACKAGE_TTL_DAYS` (30, `src/relay/device_mail.rs`), and the native scan purges both; the Workers relay needs a Durable Object alarm for the scan (from memory, verify). Nothing caps a customer's stored bytes or count. | **Scope decision:** alert on database size (above) and revoke a key that fills it; a per-key quota is a follow-up. |
| Trusted client-IP handling | **Changed by the platform.** There is no proxy chain to trust: the Worker reads `CF-Connecting-IP` for its rate limit and ignores `X-Forwarded-For` altogether. The native router's rule (the last `X-Forwarded-For` entry, only with `--behind-tls-proxy`; `src/relay/server.rs`, `RateLimiter::client`; test `behind_a_proxy_the_last_forwarded_address_is_the_client`) stays for the reference host. | Test forged headers at deployment (the edge section lists the commands). |
| Recoverable key issuance when a transaction outcome is indeterminate | **Built; not exercised on Cloudflare.** Every console change carries an operation id recorded in the same transaction as the change; a repeat id answers `409 already_done` with the ids and makes nothing (tests in `src/relay/operator/tests.rs`, `workers/test/relay-service.test.mjs`, and a browser run that dropped the response after the commit). Sealed bundles are not retained, so a lost file is recovered by replacing the key. `Error::StoreCommitUnknown` keeps the sealed `.kqkey` on the native host (`src/bin/keyquorum/host.rs`). **SQLite native:** a bundle is written while the transaction is open; a crash between the write and the commit can leave an orphan that opens nothing (`src/relay/key_delivery.rs`). | Run the lost-response case against staging, and record it. |
| SIGTERM handling | **Done for the native host** (`host.rs`, `shutdown_signal`). **Not applicable to Workers**, which have no process to stop; a deploy replaces the version and the platform handles in-flight requests (from memory, verify). | None for Workers. |
| Public Version URLs of the Worker | **Closed in the Worker; to verify at the first deploy.** `preview_urls = true` (`workers/wrangler.toml`) also enables Version URLs, so each `wrangler deploy` of `workers.yml` publishes a public workers.dev hostname that uses the version's own bindings and secrets (Cloudflare, Version URLs). The Worker serves only the hosts in `ALLOWED_HOSTS` and answers 404 on any other; empty, it serves nothing (`policy.js`, `worker.test.mjs`); a wildcard is refused by the guard outside `[previews.vars]`. | At the first deploy, fetch a Version URL and expect 404, and record it. Access in front of the Version URLs stays available as a second layer. |
| Customer API keys on the Workers relay | **Built, not deployed.** The Access-protected admin routes reach the Durable Object through the private binding, with the operator-lock (`kql_`) ceremony, the sealed `.kqkey` output, and licences and per-key activity (issue #99; [The operator console](#the-operator-console-issue-99)). No public route mints. | Deploy to staging, run the lifecycle (create the lock, issue, load with `keyquorum loadkey --bundle`, replace, revoke) and record it; `relay-deployment.md`, "Operator console". |

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
- The relay's URL is the custom domain. `workers/wrangler.toml` sets
  `workers_dev = false` for the production and staging Workers and
  `preview_urls = true` (owner decision 2026-10-06; that these switches behave
  as described is from memory, verify), and `scripts/guard.mjs` fails CI if
  `workers_dev = false` is missing at the top level or
  in an environment, so there is one hostname that carries the relay's
  identity. The admin Worker's `workers/admin/wrangler.toml` sets both off,
  and the guard checks it without the allowance.

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
curl -sS -H 'X-Forwarded-For: 203.0.113.9' -H 'CF-Connecting-IP: 203.0.113.9' https://example.com/relay/health
# There is no second way in: the workers.dev hostname does not answer, the
# admin Worker has no workers.dev or preview hostname and no route from the
# public hostname, and the public Worker's preview hostnames (only while
# Workers Builds previews are on) must answer /relay/health or 404 and nothing else.
curl -sS --connect-timeout 5 https://keyquorum-relay.<account>.workers.dev/relay/health
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/relay/api-keys
# Nothing outside /relay is the relay's: this must not be the relay's answer.
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/health
# The provider challenge still passes through the edge.
keyquorum --db ./check.sqlite loadkey --url https://example.com/relay
```

### Cache

Authenticated relay responses must never enter a shared cache. The Worker
sets `Cache-Control: no-store` on every response and does not use the
Cache API. By default Cloudflare does not cache a response to a request
carrying `Authorization` unless the response's `Cache-Control` opts in
(search summary), and the relay's JSON is not a cacheable file type by
default. Do not rely on defaults alone: the Terraform adds a cache rule
(`rules.tf`, `relay_cache_bypass`) that **bypasses cache for the whole relay
hostname**, whatever the response headers say, and you confirm with
`cf-cache-status: DYNAMIC` or `BYPASS` on `GET /inbox` and `POST
/provider-identity` responses. Sealed letters, key metadata and recipient
fingerprints must show `BYPASS`.

### Limits against the protocol

| Limit | Cloudflare | Relay | Fit |
| --- | --- | --- | --- |
| request body | 100 MB (Free, Pro), 200 MB (Business), 500 MB (Enterprise) | 1 MiB per envelope, 2 MiB per request (`MAX_ENVELOPE_BYTES`), enforced by the Worker before it calls the Durable Object | fine on any plan |
| response | not a plan limit for a non-cached response | an inbox page is at most 16 MiB of sealed bytes plus encoding | fits the edge; the isolate's memory is the open question (a production-only check) |
| CPU time | 10 ms per request on Free, 30 s by default on Paid | signature and certificate checks and SQL work per request | unmeasured; the production plan check decides |
| time | the client gives up at 30 s (`http_agent_config`) | `REQUEST_TIMEOUT`, 30 s, on the native host | the Worker must answer, or fail with a 5xx, inside the client's 30 s |
| WebSockets, HTTP/2 | not used by the relay | | |

### Rate limits, layered

Zone rate-limiting rules (`rules.tf`, `relay_rate_limit`: counted per
client address and Cloudflare data centre on every path under `/relay` except
one ending in `/health`, 100 requests per 10 seconds by default, then a block
for 10 seconds, managed in the Terraform) absorb floods before the Worker runs.
These are the values the Cloudflare **Free** zone plan allows: one rule, a
10-second counting period and a 10-second block (Cloudflare, rate limiting
rules, plan availability table, read 2026-10-06 through the documentation
search). The rule matches on the path only, because a Free-plan expression is
reported not to allow a Host match (taken from the pull request that made the
change; not checked against Cloudflare's page here), so it covers `/relay` on
every hostname of the zone, which is acceptable only while the zone is the
relay's own. It limits bursts and is not an exact 600-request rolling minute,
and it has not been measured against live traffic. A longer window or block
needs a paid zone plan, which is the owner's call, not this repository's. The
Worker's own rate limit on `CF-Connecting-IP` (a Workers rate limiting binding,
from memory, verify its accuracy and scope) still applies in the Worker; the
Durable Object's single writer and its admission bound limit the database; the
storage alert bounds retention. None replaces another.

### Private operator access

The admin Worker has **no route that bypasses Access**. Its only path
(`/relay/admin`, staging `/relay/staging-admin`, decision 1 above) is a Workers
route behind a **Cloudflare Access** self-hosted application whose policy lists
the operators' identity (`access.tf`, created only once `admin_environments` is
set); the second factor is Access's independent MFA with a security key, a
dashboard setting (see "Operator login and second factor" above); and
`workers.dev` and preview URLs are off for the admin Worker.
The Worker also verifies the Access token (`Cf-Access-Jwt-Assertion`)
itself, as defence in depth, so that a mistake in the Access application
does not expose it; this is implemented in `workers/admin/src/access.js`
and tested, and a request without a valid token gets no page and no API
answer (from memory, verify the header and key-set details). The
service binding from the admin Worker to the Durable Object (`RELAY_ADMIN`) is
built. Nothing of this has run against a live Access application. The operator
page is static files served by the admin Worker itself, on its own path, as
decided on 2026-10-06; it shares the origin of the relay (the accepted cost in
decision 1). The public Worker has
no route to any operator path, and no other hostname reaches them. Customer routes (`/inbox`, `/keycheck`,
`/provider-identity`, `/devices/*`, `/trees/*`) stay outside Access: a
`keyquorum` client cannot answer an Access login. Record the Access
application and policy with the deployment; Access and account audit logs
are the record of operator sessions (from memory, verify).

### Monitoring, incidents, rollback, cost

- Monitor the Workers and the Durable Object through Cloudflare Notifications
  and analytics (error rate, 5xx), and the relay as in the alerts above. The
  Notifications are set up in the Cloudflare dashboard; they are not in the
  Terraform.
- An edge or platform outage is a Cloudflare incident, and with one provider
  there is no second path to fail over to; the operator's recourse is the
  export and the native reference host for a read of the data, not a
  production fallback.
- Rollback is a Worker version rollback (`wrangler rollback`, from memory,
  verify), which the operator should rehearse once; across a schema
  migration, restore the pre-upgrade point-in-time state first.
- A change to the wrangler configuration that adds a `deleted_classes` or a
  rename migration would destroy the Durable Object's data (from memory,
  verify), so `workers/scripts/guard.mjs` fails CI on any such change unless
  the run sets `ALLOW_DESTRUCTIVE_MIGRATION=1` after review. This is the
  replacement for termination protection.
- Cloudflare API tokens and Worker secrets: rotate them when a person who
  could read them leaves. A Worker secret is not readable back, so rotation
  means putting a new value.
- Cost: not estimated until the plan and traffic are measured on the owner's
  account (a production-only check)
  (above); the Free plan's CPU limit is the first thing to check.

## Acceptance checklist

| Criterion (issue #88) | Settled by this document | Needs the deployment |
| --- | --- | --- |
| Hosting decision records the provider, ownership, limits, cost basis, effort, and the disposition of AWS and MongoDB | yes (the cost estimate needs the owner's account) | none |
| Workers architecture maps atomicity (one Durable Object) and provider-only signing and minting (admin Worker, Worker secrets) to a runtime and a backend, with an adopt/defer decision | yes: adopt (stage 3) | record the production-only checks when they are run |
| The feasibility spike answers each unknown with a measured value | yes for what a local run can measure; the production-only items are listed | run the production-only checks |
| An unauthorized client cannot mint provider-issued keys or licences | design: no public mint route; native router test pinned; the route allowlist (`workers/test/worker.test.mjs`) and the smoke test assert the operator, documentation and mint routes answer 404 or 405 | re-run the smoke test against the deployed public Worker; run the console's issue flow on staging |
| The admin Worker cannot be reached without Access and MFA | design plus the token check and its tests: its only hostname is to sit behind the Access application and MFA policy in `access.tf`, and the Worker verifies the Access token itself (`workers/admin/src/access.js`, 18 `node:test` tests, stage 4a); the Access application has not been created | deploy the admin Worker, create the live Access application, and test it with and without MFA, and with a forged or missing token (`smoke.mjs --admin` covers the anonymous cases) |
| Provider-root custody and operator credential separation documented and verified | documented | verify at the ceremony and record it |
| Launch prerequisites revalidated and linked to fixes or scope decisions | yes (table above) | none |
| HTTPS, readiness and health operate as documented | plan and probes | observe them |
| Edge behavior records client identity, cache policy, limits, private administration | yes | run the commands and record the output |
| Overload and storage-limit tests show bounded resource use | the bounds are named | run the tests, record memory, the 503 and 429 behaviour and the Durable Object's storage |
| Backup restoration meets the objectives and reconciles credential state | procedure | run the drill |
| Upgrade, rollback, incident response demonstrated | procedures | demonstrate |
| `DoRelayStore` passes `relay::store::conformance` | `SqlRelayStore` over the Durable Object's executor passes it on an executor that refuses transaction statements (`src/relay/store/tests.rs`), and `workers/test/relay-core.test.mjs` and `relay-service.test.mjs` run the built core over a Durable Object-shaped storage | a run on a real Durable Object |
| The pipeline builds, deploys to staging, and gates production | design and workflow (`.github/workflows/workers.yml`, stage 2) | prove with a run on staging once the owner's setup exists (environments, secrets, `RELAY_URL`, and for the admin Worker `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` and `ADMIN_URL`, Cloudflare account, zone and custom domain) |
| Gaps (no customer-managed key, Cloudflare sees bearers in transit, one vendor) recorded | yes | the owner accepts them; `docs/soc2-controls.md` carries the subprocessor point |
| Runbooks distinguish hosting-provider controls from relay authorization | yes (this document and `relay-deployment.md`) | none |

### Issue #99 acceptance criteria

| Criterion | In the repository | Needs the deployment |
| --- | --- | --- |
| List users and manage licence records; documented effects on linked keys | yes (console section, decisions table; core tests) | none |
| Generate, rotate and revoke customer keys from the console; sealed bundles or letters only | yes (`src/relay/issuance.rs`; no reply carries a bearer or key hash) | run it on staging |
| Letter rotation enforces collectability and bounded grace; bundle rotation revokes the old key under the existing rule | yes (the existing `key_delivery` rules, unchanged) | staging |
| Revoked or expired key fails authentication; rotation preserves scope, binding and ownership | yes (core tests; lineage in `licence_keys`) | staging |
| Per-user activity through stable ids, push keys included; unknown credentials never attributed | yes (`activity.rs`, keyed by key id) | staging, with a real client |
| Bounded filters and retention; telemetry kept apart from signed audit | yes (90 days, bounded hours, paging; not in the audit chain) | measure cost and growth |
| Unauthorized callers get no assets, data or changes; forged, expired or wrong-audience tokens and cross-origin changes fail closed | yes (`workers/admin` tests) | test with the real Access application and MFA |
| Roles; object-ownership violations | one operator role (decision above); ids are checked in the core | a second role would need a design |
| No bearer, hash, lock, token, key or payload in GUI, logs, errors or exports | yes (tests and the page contract; `guard.mjs` on the bundle) | inspect staging logs |
| Explicit lock bootstrap; an empty store cannot claim issuer authority | yes (two-step ceremony; `bootstrap` only on Access-verified console requests) | staging |
| Atomic licence, key and audit changes; tests for rollback, duplicates and lost responses | yes (core and conformance tests; real-workerd binding run; browser run) | concurrent rotation and revocation on a real object |
| No public route exposes management; Version URLs refused | yes (route allowlist tests; unchanged `ALLOWED_HOSTS`) | fetch a real Version URL |
| Environments cannot cross-bind | yes (`guard.mjs` checks the binding name per environment) | verify on staging |
| SQL upgrades preserve keys, deliveries and audit; old bundles load | additive `CREATE ... IF NOT EXISTS` tables; unlinked keys stay unassigned; no wire format changed | upgrade a populated object |
| Restore drill reconciles later revocations | procedure only | run the drill |
| Staging verification of Access, assets, binding, issuance, alarm, overload | not possible here | all of it |
| Storage, write amplification, latency and cost measured | not measured | all of it |
