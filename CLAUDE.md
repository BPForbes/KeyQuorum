# CLAUDE.md

Guidance for Claude Code (and other Claude-based agents) working in this repository.

## Project overview

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are
encrypted and bound to registered physical tokens (e.g. USB devices). Unlocking a
protected file requires presenting a quorum of the registered hardware keys, providing
layered, hardware-backed access control.

The project is a Rust Cargo crate (see `.gitignore` for Cargo-related patterns).
Private sign bridges live in `src/private_bridge.rs` and the `keyquorum` CLI.
`create` and `remove-member` generate delivery packages first and commit only after
those files are written — do not persist a live bridge before the envelopes exist.
The two must stay in step in both directions: if the commit fails, the CLI deletes
the `.kqpb` files it just wrote, because `write_owner_only` refuses to overwrite and
leftovers would block the retry.

`src/envelope.rs` is the crate's **only** sealed-envelope framing (magic,
version, kind byte, recipient X25519 public key, sealed length) and the
only copy of the length-prefixed byte codec and preimage hashing that go
with it. Two formats share it, named by `envelope::Format`: `PACKAGE`
(`KQPB`, the `.kqpb` files the relay carries, for `private_bridge` and
`org_update`) and `EXPORT_BUNDLE` (`KQXB`, `export`'s portable bundles).
Do not re-roll either in a new module — add a `Format`. Device copy, move,
and relocate letters are additional `PACKAGE` kind bytes, not a new format.
Those bytes are wire format. `.kqbn` eviction notices, the `KQBS` signature artifact, `device.kq`
(`KQDV`), slot tokens (`KQST`), and transfer packages (`KQTX`) have their
own magic and version because they are not sealed envelopes, and
`key_tree`/`private_bridge` seal raw blobs into database columns with no
header at all; none of those belong in `envelope.rs`.
`src/package.rs` is `.kqpkg` (`KQPK` v1, issue #104), a signed setup package, and is not a
sealed envelope either: an issuer signature over a purpose (`ClientSetup`, `ClientUpdate`,
`ProviderInfo`, `ProviderRecovery`), a validity window and components that are the unchanged
bytes of artifacts other modules own (`KQPC`, `KQRL`, `KQPL`, `KQXB` type 4, `KQPB` kind 20, `KQXB` type 6, the setup manifest, and `KQXB` type 5, the provider recovery payload).
A client package carries its **setup manifest** (`src/setup_manifest.rs`, `KQXB` type 6, `package::issue_client_package` builds it):
the steps `setup` runs, as a closed enum of typed operations (`ensure_identity`, `install_certificate`, `install_key`, `use_relay`;
`deny_unknown_fields`, never shell text), each part named by SHA-256, listed in dependency order and every non-manifest part used by
exactly one step. The relay signs it (`signing::relay_setup_manifest_preimage`, certificate embedded) and seals it to the recipient, so
it is bound to the package id, purpose, recipient, device and expiry; `cli/setup_package.rs` opens it with the slot, checks the signer
is the package issuer and runs the steps in order, all checks before any write. A package with no manifest keeps the fixed plan.

Components are dispatched by their own magic and kind, never by a name or the package's claim,
and anything else, or anything the purpose does not allow, is refused before any write. It
decodes, bounds and authenticates only (enrollment is `src/enrollment.rs`, the generators are
`package::issue_client_package` and `issue_provider_info_package`; the wizard is not built), and the
outer signature never replaces a component's own checks. Purpose and
kind bytes are wire format: append, never renumber.
`keyquorum setup <file.kqpkg> --device DIR --label NAME` (`src/cli/setup_package.rs`, a native
everyday command) opens one: it decodes, checks the validity window and that the signer is the
relay a root-verified, unrevoked certificate names, and that no file it would write conflicts,
all before any write; without `--yes` it prints the plan and changes nothing; the package file is read with a size bound (`Env::read_bounded`) and each component has its own cap (`ComponentKind::max_bytes`); the slot must already exist (`setup --enroll-out` first; a package never makes an identity), and the plan first opens every sealed key with it (`precheck_key_component`: it must verify, be for this drive and have been issued by the relay that signed the package), refuses to replace a different key already stored for that relay and scope, prints each key's scope, relay, expiry and licence, and stops before anything is written if one cannot install. A client manifest is `KQXB` type 6 version 2: it also signs a `package_generation` (the relay's per recipient and device counter, `package_generations`, `RelayStore::next_package_generation`, taken by `host keys create --enrollment` (`--update` makes a `ClientUpdate`) and the console before minting; gaps are harmless) and the SHA-256 of the certificate it travels with. The personal store keeps an install ledger (`src/db/package_ledger.rs`: `package_installs`, `package_baselines`, `package_retired_keys`), keyed by stream (provider id, recipient, device, slot label and container): the same package id and hash already complete is a no-op, a pending one resumes, a different hash under a known id is refused, a generation at or below the stream's baseline is refused, a second package while one is pending is refused (one pending per stream, a unique index) until `setup --abandon ID`, and only a newer `ClientUpdate` may replace a stored key (a `ClientSetup` never does; a `ClientUpdate` without a signed generation is refused). `begin` reserves the generation, raising the baseline (never lowered), before the first write; each step is checked in place, run only if missing, checked again and marked; a replaced key is retired and never reinstalled; the final state is checked before the install is complete. A restored or erased personal store loses its baseline. Several packages in one run (`setup A.kqpkg B.kqpkg`, `cli::setup_package::run_batch`, at most 16 files and 64 MiB together) are all verified and planned before any write (`package_ledger::decide_in_batch` lets a pending package of the same batch pass the preflight), identical files count once, the order is fixed (stream, then signed generation, a setup before its updates), and two files with one id, two packages of one stream at one generation, a setup after another package of its stream, different certificates or default relays, and non-client packages are refused up front (one certificate and one slot make a batch one stream); each package then goes through the same ledger and executor, re-planned against what the ones before it left, with a per-package result, and it is not one transaction. With `--yes` it
runs `setup`'s identity steps, places the certificate as `provider.kqcert` beside the container
(identical bytes are kept, different bytes refused) and installs each sealed key through
`install_key_component`, the path `loadkey --bundle` and `inbox open` use. It is refused where
`Env::package_setup` is false: the browser lab says no, and the lab must not offer or document
it. `ProviderRecovery` packages are not installed by `setup` (it names the command below). `src/provider/recovery.rs` (issue #107) is provider recovery: a root-signed `ProviderRecovery` `.kqpkg` holding the relay's `KQPC` and a recovery payload (`KQXB` type 5, `ComponentKind::RecoveryPayload` tag 7, allowed in that purpose only, which carries nothing else) sealed to an operator X25519 key and holding the relay's private key and a context the root signs (`signing::provider_recovery_preimage`: purpose, package id, operator key, provider id, serial, relay public key, certificate SHA-256, validity and its own closed operation list, `install_relay_key` then `install_certificate`, `deny_unknown_fields`; it does not use the client setup manifest or its signer). No root key or other secret is in it, and sealing is custody only: `recovery::open` trusts it only under the root the build pins, with every context field matching the package and certificate, the certificate unrevoked and valid now, and `provider::self_check` on the recovered key. `host recovery keygen` makes the operator key (fingerprint printed), `host recovery issue` (root key, relay key, certificate, `--recipient`, `--confirm-fingerprint`, 1 to 7 days, the root must be the pinned one) seals it, and `host recovery install PKG --recipient-key --out DIR [--yes]` writes `relay.key` and `provider.kqcert` into a new or owner-only, non-link directory through a `.part` file and a hard link that never replaces a file (identical files are kept, different ones refused, the directory re-checked before each write, leftovers of a cut-short run removed by the rerun) and checks the result with `self_check` before success, then overwrites and removes the package (`install_and_dispose`; a shown plan or a failed install keeps it). It configures no Worker secret, deploy variable or platform credential.
`keyquorum setup --enroll-out FILE` writes `.kqreq` (`KQRQ` v1, `src/enrollment.rs`), the client's
public request: device id, label and the slot's public keys, signed by the slot's signing key,
no secret. The provider verifies it, compares its fingerprint with the client out of band
(`host keys create --enrollment FILE --confirm-fingerprint ...`, hidden `host`, never in
customer docs) and the key is minted, sealed to that request and device, and written into a
`.kqpkg` inside the key's own transaction (`package::issue_client_package`), so a package that
cannot be written leaves no key. Like package setup it is refused in the lab. The provider
`KQPC`/`KQRL`/`KQPL` blobs are signed certificates, not envelopes, and
keep their own offset-cursor parsers and error variants.
`src/org_update.rs` adds the two authenticated update
kinds from issue #10 — hardware-key reissue and key-tree restructure. A
store applies one only when it is addressed to a label that store holds
under the sealed-to key, signed by the subject or a dotted-label ancestor
whose signing key that store already has, verified against a
domain-separated preimage covering the recipient, and in order (a reissue
exactly one past the last for that subject; a restructure strictly past
the stored public generation). Accepted updates land in `org_updates`,
whose UNIQUE key is the last-resort replay guard. Keep the producers
plan-then-commit like `private_bridge::create`, and never widen the
authorization rule without updating the tests that pin it. `org_update.rs`
itself stays orchestration: `key_tree.rs` is the only place in the crate
that ever mutates `key_nodes` (`adopt_reissued_hardware_key` sits next to
`rebind_leaf`; `active_encryption_leaves` next to `active_leaves_for_hardware`;
`load_for_visibility` backs `visible_labels` itself now, not just the
restructure loop), `authority.rs` owns the dotted-label hierarchy
(`parent_node_label`, `is_ancestor_or_self`, `ancestry_distance`,
`relationship`, `lowest_common_ancestor`, `direct_parent`;
`private_bridge.rs` re-exports the first two), `private_bridge.rs` owns
bridge-roster queries (`bridge_notify_targets`), and `keys.rs` owns the hardware-key
registry (`active_keys_for`, `get_or_register`, `revoke_superseded`,
`unrevoke_key`). A new authenticated-update primitive belongs in the
module that owns the table it reads or writes, not in `org_update.rs`,
even when `org_update.rs` is its only caller today.

The operator console (`workers/admin/`) issues the same package: `issue` accepts an `enrollment` (base64 `.kqreq`) and
`confirm_fingerprint` in place of a public key and device id, and returns one `ClientSetup` `.kqpkg` and key metadata, no loose
bundle (`relay::operator`, `resolve_recipient`, `package::issue_client_package`); `provider_package` (a POST that takes no lock,
like `checkpoint`) returns a `ProviderInfo` package and the relay certificate, which the page zips. `package::UserType`
(`CLIENT` or `PROVIDER`) is derived from `Purpose`, never stored. The page's file tool (`files.js`) only reads public framing
and refuses private key file names unread and key-looking content once read; no private file is ever uploaded. A dropped `.kqpkg` is verified by `package::public::verify` (signature, hashes, purpose, window, signer and certificate against the relay's `pinned_root`, one recipient for every sealed part; nothing sealed opened, no revocation list) through the console wasm's `verify_package` (`package-check.js`): *Unverified* until it passes, and the page shows the native install command and installs nothing, in any browser. Storing public
files online, and operator actions by signed letter (`docs/operator/admin-letters.md`, a design only), are not built.
Large sealed letters can be held in a private R2 bucket (`LETTERS`) instead of their row (`docs/operator/r2-blobs.md`, built, not
deployed or run end to end): the core (`relay::blob`, `SqlRelayStore::with_blob_threshold`) authenticates, validates and inserts the
row not ready with only the 42-byte header and the true length, the Durable Object's `workers/src/blobs.js` then stores the bytes (checked
against the SHA-256 in the key) and marks it ready or aborts it, a pull puts held letters back and refuses to return a header-only one, and
a trigger tombstones every dropped held row for the sweep. Native hosts, and a Worker without the binding, hold nothing out. Only the
public Worker may bind R2; the guard refuses it in the admin Worker, in a Preview, under another name, and a staging bucket shared with
production.
Sealed backups of the relay's database can be written to a second private R2 bucket (`BACKUPS`, `docs/operator/r2-backups.md`, built,
not deployed or run end to end): the core (`relay::backup`) dumps every table in one synchronous turn, seals each chunk to an
operator-held backup public key (`EXPORT_BUNDLE` types 7 and 8) and signs the manifest with the relay key; `workers/src/backups.js`
uploads the chunks and the manifest last from the alarm, keeping the newest few; `keyquorum host backup keygen|inspect|restore` is the
operator's offline side (the console's Status page makes the same keypair in the browser, `provision_wasm::backup_keygen`, while backups are off) (restore checks the signature against the pinned root and every chunk's hash before writing, then re-walks the
audit chains). The backup public key is the `BACKUP_RECIPIENT` deploy variable (never in `wrangler.toml`, whose guard refuses a 64-hex
value); the private key never reaches a Worker. Letters held in `LETTERS` are not in a backup.

The mailbox relay (`src/relay/`) stores opaque `.kqpb` envelopes and
the canonical *public* split-tree as JSON documents (full context). It must never
unseal envelopes or hold wrapped shares or private keys. `relay push` merges
the sender's public topology into those documents and leaves nodes the sender
does not hold in place; `tree publish` (admin) replaces a document. `relay pull`
returns a sliced copy that the personal SQLite file translates. A personal SQLite
file should keep only the subgraph that person needs (own lineage, siblings,
descendants, and established-bridge peers plus those peers' ancestors). API keys
are shown once; the relay persists only `hex(SHA-256(raw))`. Customer API keys
are minted only by KeyQuorum (host-local `keys create|rotate` on a relay
that already holds a signed `provider.kqcert` and matching relay key).
HTTP cannot create or rotate bearers. Customers never mint keys; they
receive a `kq_…` bearer. The `kql_…` issuer is an internal operator lock
created only after that identity check, not a customer credential and not
proof of authorization by itself. Official clients still only talk to a
relay that proves a KeyQuorum-root-signed cert. The mailbox host is a
**hidden** `keyquorum host` subcommand, compiled only with `--features
provider`. That feature is a build capability, not authorization. A trusted
relay also requires a KeyQuorum-signed `provider.kqcert` and the matching
relay private key; official clients challenge `POST /provider-identity` and
disconnect if the certificate, signature, expiry, capabilities, or
revocation check fails. Do not document
`host` in README or other customer-facing docs — buyers get
a URL and an API key and use `keyquorum loadkey` / `relay push` /
`relay pull`. Default `cargo build` produces `keyquorum` without that
subcommand. `keyquorum loadkey` authenticates the relay, then calls
`POST /keycheck` (no auth) and stores that hash plus a sealed bearer in the
personal SQLite file. Later commands re-check the hash and inject the
bearer. Never commit bearers, `.kqpb` files, `*.kqcert`, `*.kqrl`,
`*.kqpolicy`, provider root keys, or the relay database.

Where the relay keeps that state is `src/relay/store.rs`: `RelayStore` is the
persistence boundary every route handler (`relay::service`), the HTTP server,
the host `keys` commands and the browser lab speak to, drawn at the relay's
units of work (push a letter with its trees, rotate a key with its sealed
replacement, grace period, delivery record and audit event), never at rows.
`SqlRelayStore<S>` is the one `RelayStore` implementation: one `relay::sql::Sql`
executor behind a mutex, delegating to the modules that own each table, all of
which take `&dyn Sql` and never a `rusqlite::Connection`. `Sql` carries no
rule (bind values, run a statement, stream rows, `transaction`, which nests);
SQL stays SQLite's own (`'now'`, `INSERT OR IGNORE`, `ON CONFLICT`), and a
table module never opens `BEGIN` or `COMMIT` itself, because a Durable Object
refuses them and runs a unit of work as `transactionSync`. `SqliteRelayStore`
is `SqlRelayStore<rusqlite::Connection>`, the original owner-only SQLite file;
it stays the reference backend and the one tests, the lab and the native host
use. A backend reimplements no rule: audit hashing and verification
(`audit::entry_hash`, `verify_table`, `sign_anchor`, `sign_checkpoint`),
letter routing (`mailbox::routing_of`, `device_mail::check_package`), tree
merging (`org_tree::merge_into_existing`), descriptor checks and the sealed
key-delivery flow (`key_delivery::DeliveryOps` over `create_as_bundle_with`,
`rotate_as_letter_with`, `rotate_as_bundle_with`) are the same code every
backend calls. A store refuses a personal store's tables
(`OrganizationDatabase`) and a database written by a newer `SCHEMA_VERSION`.
Every backend passes `relay::store::conformance` (the SQLite store on every
`cargo test`, and again over an executor that refuses transaction statements,
as a Durable Object's does). The planned Cloudflare backend (not implemented:
`SqlRelayStore` over a Durable Object's SQL API, `DoRelayStore` in
`docs/operator/relay-hosting.md`) must pass the same suite and re-roll no rule
that lives in `audit`, `mailbox`, `device_mail`, `org_tree`,
`device_directory` or `key_delivery`.
`GET /ready` answers only when the store answers (the readiness probe);
`GET /health` is the process alone. The personal and organization SQLite
stores never pass through `RelayStore`.
`src/cli/host_env.rs` resolves what the host reads from files rather than
flags or the environment: the operator lock (`--licensee-key-file`,
`KEYQUORUM_LICENSEE_KEY_FILE`, then `--licensee-key`, `KEYQUORUM_LICENSEE_KEY`,
then a prompt; both flags at once is refused) and the provider root key
(`--root-key`, `KEYQUORUM_PROVIDER_ROOT_KEY_FILE`, then the raw
`KEYQUORUM_PROVIDER_ROOT_KEY`), each read with a bound, one trailing line
ending removed, zeroized, and named only by path in errors.
No container, chart or unit is shipped: production hosting is Cloudflare only
(plan of record `docs/operator/relay-hosting.md`), and native `host serve` is
the dev, test and reference host. `workers/` holds the public Worker and its Durable Object, which serves only below its mount (`src/mount.js`, the non-secret `MOUNT_PATH`: `/relay`, or `/relay/staging-user` for the staging relay on the same host; the core is given the path without it, every other path is 404, and a client's relay URL is that path on `keyquorum.dev`; the console is mounted the same way at `/relay/admin` or `/relay/staging-admin`, so all four share one origin, an accepted cost recorded in `relay-hosting.md`, and the routes are Workers routes in `deploy/cloudflare/terraform`, not custom domains) (JavaScript around the WebAssembly relay core: `src/worker.js`, `policy.js`, `relay-service.js`, `relay-object.js`), its `wrangler.toml` (production at the top level, `[env.staging]`, wrangler pinned by `package-lock.json`, `sharp` overridden to a fixed version) and the `scripts/guard.mjs`, `scripts/smoke.mjs` and `scripts/relay-host.mjs` scripts with their `node:test` tests. Preview URLs are on for the public Worker only (the guard's `--allow-preview-urls` is passed for that one file) and serve Worker Previews: what Cloudflare Workers Builds runs for a branch (`npm run preview`, that is `wrangler preview`, with the `[previews]` tables a Preview starts with, since it inherits no production setting) once the owner connects the repository to the Worker, the way the portfolio site is connected (`docs/operator/relay-hosting.md`, "Workers Builds and previews": root directory `workers`, build command `npm run builds:build` (a pinned, hash-checked Rust toolchain, then the WebAssembly build), `main` deploy command `npm run check` so that `workers.yml` stays the only deployer, `.node-version` 22). A Preview inherits no production setting, secret or Durable Object namespace; `wrangler versions upload`, whose version would share them, is never the preview command; `preview_urls = true` also makes the URL of every `wrangler deploy` version public (Cloudflare Version URLs, which use the version's own bindings and secrets), so the Worker serves only the hosts in its non-secret `ALLOWED_HOSTS` (set at deploy from the environment's `RELAY_URL`) and answers 404 on any other, a Version URL included, and only `[previews.vars]` may set it to `*` (the guard enforces both); and the guard checks a `previews` block's vars like `[vars]`. The relay's sites are independent of the Lab and the portfolio: the Lab's relay is `relay::service::dispatch` in process at a name that is never served (`relay.keyquorum.lab`), no relay Worker sets a CORS header, and both refuse another website's browser request (`workers/src/browser-isolation.js`: `Sec-Fetch-Site` cross-site or same-site and a foreign or `null` `Origin` are 403, top-level GET/HEAD links and redirects allowed only to the public status page and its mount/preview-root redirects; the admin Worker allowing navigation through to its Access token check), and every answer carries `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY` and `Cross-Origin-Opener-Policy: same-origin`; neither the Lab nor the portfolio may name a relay host. `src/relay/worker.rs` (feature `workers`, built for wasm32 by
`workers/scripts/build-relay-wasm.mjs` into the git-ignored `workers/relay-wasm/`, and
refused together with `provider` or `lab` by `build.rs` and `lib.rs`) is the relay core
for a Durable Object: `RelayCore` is `SqlRelayStore` over `worker::do_sql::DoSql`, the
Durable Object's SQL reached through `workers/src/sql-adapter.js` (a cursor per query,
`transactionSync` per unit of work), running `relay::service::dispatch`. It reads no
clock (the Worker passes the time in as text), has no mint or rotate route, and holds the
relay key and certificate only as the bytes the Worker's secrets give it; the public Worker and the Durable Object class around it are built (`workers/src/`) and never deployed. `workers/test/` runs the built module over a Durable
Object-shaped storage on Node's SQLite. `workers/admin/` is
the admin Worker: the provider's console (`public/`, no inline
code, no outside origin, no `innerHTML`) served by the Worker on its own path (`MOUNT_PATH`) behind a
Cloudflare Access application with MFA, and the `/api` behind it; its page names no absolute path, so it works under any mount. `src/access.js` verifies Access's signed
token itself (RS256, the team's key set, issuer, audience, expiry), so a mistake
in the Access application cannot expose it; without a valid token, or while its
two non-secret variables `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are empty, it
serves nothing. Outside `/api` only GET and HEAD are allowed, and `/api` is the
route table in `src/routes.js` (anything not in it is refused before the relay).
The guard checks its config, `npm run build` dry-runs it,
the smoke test (`--admin`) requires anonymous requests to its hostname to be
refused, and `workers.yml` deploys it with the two variables taken from GitHub
environment variables, not secrets.
`deploy/cloudflare/terraform/` holds the Cloudflare infrastructure as code
(custom domains, edge rate-limit and cache-bypass rulesets, a custom domain and
an Access application with MFA per admin environment (`admin_environments`), an
optional R2 bucket); the operator runs `terraform
apply` locally with their own credentials, and `.terraform.lock.hcl` pins the
provider. `.github/workflows/workers.yml` builds and dry-runs the Worker,
formats and validates the Terraform, deploys to the `cloudflare-staging`
environment from `main` (production is a manual run into
`cloudflare-production`) and gates everything behind the one stable check
`workers`; it uses no third-party deploy action, and the only Cloudflare
credential in GitHub is the Workers-deploy token and account id per
environment. Nothing has been deployed. The relay key and certificate (`RELAY_PRIVATE_KEY`, `RELAY_CERTIFICATE`) are Worker secrets the operator sets with `wrangler secret put`, never GitHub secrets; the `kql_` lock and the provider
root key never go on a Worker. `docs/operator/relay-deployment.md` is the operator runbook
(secrets, certificates, bootstrap, rotation, the dev host) and
`docs/operator/relay-secrets.md` the secret classification; neither is
customer-facing, and the README still does not document `host`.

The operator console (issue #99, `docs/operator/relay-hosting.md`, "The operator
console") is for the provider's own people only and never for customers. The
admin Worker reaches the relay's Durable Object through the private binding
`RELAY_ADMIN` (`script_name` names this environment's relay only, no migration
in the admin file; `guard.mjs` checks both) and calls only `RelayObject.operate`
and `status`; no public route leads there. The core side is `src/relay/operator.rs`
(orchestration only), over `customer.rs` (customers), `licence.rs` (licences,
**immutable** statement versions, key links and `replaces_key_id` lineage),
`issuance.rs` (issue, replace, void a key, void a licence, each one unit of
work), `activity.rs` (hourly per-known-key counts, latency and bytes; unknown
bearers are never recorded; 90 days; no address, query or body; not in the audit
chain) and `operator_log.rs` (`operator_actions`: the verified Access identity,
the operation id, its result). Rules to keep: a licence is signed terms, an end
date and revocation, enforcing nothing itself, and voiding it revokes its keys in
the same transaction; renewal adds a version and never rewrites a delivered one,
and keys already issued keep their end until replaced; a key's owner is an
explicit link and a key with none is unassigned, never guessed from a label,
fingerprint or address; every change needs the verified identity, a same-origin
`Origin`, the operator lock in `x-operator-lock` (checked against the stored
hash, never stored, logged or echoed) and an `Idempotency-Key` operation id that
is recorded in the change's own transaction, so a repeat answers `already_done`
with ids and changes nothing; a sealed bundle is never retained (a lost file is
recovered by replacing the key) and no reply holds a bearer or key hash; the
operator lock is made in two steps (`bootstrap` or `rotate_lock` stages it in
`licensee_pending` and shows it once, `confirm_lock` promotes it), and an empty
store cannot be claimed by an ordinary request; the `admin` scope is not issued
from the console. Until the relay has a trusted identity and the lock, the Overview opens with a four-step first-time setup guide (`workers/admin/public/setup-state.js`, `view-setup.js`: the offline root ceremony with the root pinned, the relay's identity as Worker secrets, the operator lock, then issuing) and Issue keys shows the missing step instead of its form; "trusted" is `operator::identity_check` (`provider::self_check` against the root the Worker's `PROVIDER_ROOT` deploy variable names, `operator::Context::pinned_root`, never a compiled constant: signed by it, unexpired, provider capabilities, names the held key), reported as `identity_check` with a reason (`no_pinned_root` while the variable is unset) and a `pinned_root` field that is null in that case or otherwise holds the pinned root's public value, and a core that reports no check is unverified; the relay itself requires only an identity and the lock, and a YubiKey option is evaluated, not built (`docs/operator/yubikey-evaluation.md`). There is one operator role (Access decides who is in), and the
console cannot show letter contents or file histories, which are sealed. What has
not been done and must not be claimed: a deploy to staging, the restore drill, a
cost or storage measurement, any enforced licence limit, a second role, and a
recovery path for a lost operator lock on the Cloudflare relay.

The relay host's own operating controls: the relay database is owner-only
(0600, journal sidecars too, like the personal store). It serves plain HTTP,
so `serve` refuses a non-loopback `--bind` unless `--behind-tls-proxy` says a
TLS-terminating proxy forwards to it; every request is cut off at
`relay::REQUEST_TIMEOUT` (30 s, answered 408) inside the body limit. Every
API-key change (created, rotated, revoked, by `host` or by `admin:<id>` over
HTTP) lands in `api_key_events`, which `host keys events` prints; every mint
authorization (`keys.create`, `keys.rotate`), granted or refused, lands in
`provider_auth_events`. Authentication and scope denials are logged at WARN by
reason, and the host logs at INFO unless `RUST_LOG` says otherwise. None of
those records or logs holds a bearer, a key hash or a challenge. Both tables
are hash-chained (`prev_hash`, `entry_hash`) by `src/relay/audit.rs`, which
owns the chain and `audit_anchors`: the relay signs each chain head with its
relay key (`signing::relay_audit_anchor_preimage`) at startup, on every scan,
after each host `keys` command and after an HTTP revocation, and
`audit::verify` (`host keys events --verify`) trusts an anchor only when its
certificate chains to the provider root, is not revoked, and was valid at
`signed_at`; rows after the newest trusted anchor are pending. `signed_at` is
the signer's word, so `host keys checkpoint` signs every table's count and head
into an owner-only file the operator keeps off the relay, and `--checkpoint` on
`--verify` requires the chain to match it and refuses an anchor over rows past
it dated before it (`signing::relay_audit_checkpoint_preimage`).
`GET /audit/api-keys` takes any live key and returns only the events that
pertain to it (`api_key::events_visible_to`; an admin key sees all). Each
client gets `--rate-limit-per-minute` requests (600 by default, 0 is off; 429
with `Retry-After`), keyed by peer address (an IPv6 one by its /64), or by the last `X-Forwarded-For`
entry behind `--behind-tls-proxy`, in a table capped at
`MAX_RATE_LIMITED_CLIENTS`. An inbox read is also capped at
`mailbox::MAX_INBOX_PAGE_BYTES` (16 MiB of sealed bytes, never fewer than one
letter; `mailbox::bound_page`, shared by both mailboxes and every backend, reads
rows as a stream and stops at the budget plus one letter, with `next_after`
pointing at the last letter kept), so a page can neither outgrow the relay's
memory nor `relay::client::MAX_RESPONSE_BYTES` once encoded. Store
work runs on the blocking pool behind an admission pool
(`DEFAULT_STORE_CONCURRENCY`, 64 slots, `STORE_ADMISSION_WAIT` 5 s, then 503),
and the slot is held until the store call itself returns, since a timed-out
request cannot cancel it; `GET /ready` has its own two slots. `host serve` ends
gracefully on SIGINT or SIGTERM. A commit whose result stays unknown on a
store reached over a network is `Error::StoreCommitUnknown`, not a failure:
`host keys` keeps the sealed `.kqkey` it wrote (the key may exist; check `keys list`
and `keys events` before retrying) and removes it only on a failure that is
certain. `identity
generate` and `root generate` write the private key only to
`--private-key-out` (owner-only, never overwritten) and never print it;
`provider::provision` is the whole ceremony in one step (root keypair, relay
keypair, the certificate the root signs, a `ProviderInfo` package), built in
memory and passed through `provider::self_check` before it is handed back;
`host provision --out DIR` writes it, every file created new in an owner-only
directory, a failed write removing what the run wrote, and the console's setup
guide makes the same files in the browser (`provider::provision_wasm`, the
`console` feature's one export, built by `workers/scripts/build-console-wasm.mjs`
into the admin Worker's `public/provision-wasm/`, never committed, loaded under
`script-src 'self' 'wasm-unsafe-eval'`; `workers/admin/public/provision.js`
turns the result into downloads and sends, stores and keeps nothing). The relay
pins the root its `PROVIDER_ROOT` deploy variable names (a GitHub environment
variable like `BACKUP_RECIPIENT`, public, validated as 64 hex by `workers.yml`,
never in `wrangler.toml`); a client build compiles its root into
`KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY` from `KEYQUORUM_PROVIDER_ROOT` (the same
value), else a git-ignored `provider-root.pub` beside `Cargo.toml` (the
generated `root.pub` copied there), else a placeholder whose private half nobody
holds, so a client built with neither trusts no relay; no root is ever
committed, and the relay never reads any of it. The `console` feature stands alone on
wasm32 (`build.rs`, `lib.rs` refuse it with `provider`, `lab` or `workers`).
Prompted passphrases, passwords, PINs and pasted API keys are
`Zeroizing<String>` (`cli::env::prompt_secret`, `transfer::Passphrases`), and
so are the vault password and the stored relay bearer (whose `Debug` is
redacted); decrypted plaintext (`crypto::decrypt`, `envelope::open`, the
quorum and password-locked unlocks) is `Zeroizing<Vec<u8>>`.
The relay client reads at most `relay::client::MAX_RESPONSE_BYTES` (256 MiB)
of any response, the provider challenge included, and quotes a relay's error
body only through `relay_error_text` (control characters dropped, 512 chars).

`src/outbox.rs` owns each person's outbox ring buffer (`outbox_rings`,
`outbox_slots` in the personal store) and `keyquorum outbox`
(`src/cli/outbox_cmd.rs`, an everyday command) drives it. A ring has a
capacity (32 by default, 1 to 1024, changed only while empty), a write
pointer, a read pointer, a `size` of held slots and `sent_total`; its state is
`Empty`, `Partial` or `Full`. `push` writes at the write pointer and a full
ring refuses rather than overwrite an unsent letter. Only `send_next` moves
the read pointer: it claims the head in one short immediate transaction that
re-checks trust, hands the letter to the sender with no transaction open (an
upload never holds the store's one write lock), and, if that succeeds, wipes
the slot (zeroblob plus `secure_delete`) and advances in another, only while the
head still carries its claim; a failed or refused send moves nothing and frees
the claim. A claim younger than `outbox::CLAIM_LEASE_SECS` (120) keeps a second
send and `drop_next` off the head; a crashed send's claim lapses, a release
that fails (it runs in its own immediate transaction) is reported with the way
out, and `send_next_taking_over` / `drop_next_taking_over` (`outbox send|drop
--take-over`) take a stuck head at once. That is safe because delivery is
idempotent: the relay keeps one row per recipient and content hash and answers
a repeat with the same letter id, and `outbox_cmd::publish_letter` writes a
private `.part` sibling and moves it into place with `Storage::rename_new`
(a hard link natively, or a `create_new` copy where hard links are missing, so
never replacing a file; only an identical one counts as written, any other
file at the name is refused and never removed, and `.part` leftovers of this
letter are removed), so a repeated or overlapping delivery is still one letter; only the
send whose claim the head carries frees the slot, and a published letter is
never taken back.
`drop_next` discards the head unsent. A `KQPB` is the passport: the ring
holds nothing else (raw `KQXB`, `KQBS`, `KQBN`, `KQHS`, `KQTF` are refused and
travel inside a letter), and device kinds 9 to 12 are refused
(`envelope::is_device_workflow_kind`). The letter must be sealed to an active
encryption key the store holds for the recipient (`keys::is_active_key`, the
same check `org_update` and `file_delivery::recipient_owns_key` use). Every
letter turned away at departure, by `push` or at `send_next`'s gate, is recorded
in `outbox_refusals` (`outbox::Refusal`: `no_passport`, `device_letter`,
`unrecognised_destination`, `out_of_order`, `ring_full`, `oversized`,
`tampered`; recipient, kind and missing step, never the letter or its hash; the
newest `MAX_REFUSALS_KEPT` per owner), after the rolled-back transaction, in
one transaction with its timeline event, and `outbox refusals` lists them; a
refusal that cannot be recorded is still refused and its error says so. A
delivery that fails in transit is not a refusal.
The ring is the default way out: `send` (files, tracked files, `--quorum-file`)
seals as `deliver send` / `file share` would and then, through
`outbox_cmd::carry_via_outbox` (the `via_outbox` field only `send` sets), queues
the letter and sends the ring oldest first through it; a failed upload leaves it
queued for `outbox send`. Through `send` a tracked file needs its visa only once
asked (`exchange::Visa::IfRequested`: the recipient's latest file request must be
accepted); `outbox add --file` stays `Visa::Required`. The legacy commands carry
directly as before. `src/ring.rs` is the one copy of the ring arithmetic (ensure,
advance the write pointer, release a slot and move the read pointer past released
ones, resize when empty), used by the outbox and by each store's inbox ring
(`inbox_rings`, `inbox_slots`, `db::inbox`, one ring per relay,
`db::inbox::RING_CAPACITY` 256): a pulled letter stays a file in the inbox
directory and its slot keeps its hash, so a changed file is not opened; a
delivered letter's slot is released and marked handled in one transaction,
then its file deleted (`inbox open`, and `inbox drop <id>` unopened); a file a
failed delete left behind is deleted by the next inbox command (`sweep`, keyed
on the handled mark, never re-delivering); a full ring stops the pull with the
cursor at the last letter held, so the rest stay on the relay, and the note
names the oldest letter when it alone holds the ring's span. Each ring also
keeps a timeline (`src/ring/history.rs`, tables `ring_histories` and
`ring_events`): every queue, send, drop and refusal (outbox) and every receipt,
open and drop (inbox) is a `file_history` event (`LETTER_QUEUED` 42 to
`LETTER_OPENED` 47, appended) stamped by the store's clock, recorded in the
same transaction as the slot change and hash-chained from the ring's own
genesis, so the timeline is a `KQHS` snapshot (`HistoryEvent::chained`,
`HistorySnapshot::from_events`). It holds slots, labels, letter ids, kinds and
rule names only, never a letter or its hash; `outbox history` / `inbox history`
print it, `--snapshot` writes it and `--check` confirms the timeline still
passes through an earlier one.
`src/file_delivery/exchange.rs` owns the order of a tracked file's letters:
request (18), answer (19), file (15, only after an accepted file request from
that person and a `file share` after it), receipt (16, only for a file
received from them), snapshot (17, after a completed delivery). It stores
nothing: `require_step` reads the sender's own copy (`outbox add --file`), whose
history already records each step. It cannot open the sealed letter, so it
confirms only that the named copy shows the step before with that peer, not
that the letter is about that copy or request; the receiving commands bind
those when they open it. `request_event` and `REQUEST_EVENTS` are
the helpers `file_cmd` uses too. A `KQXB` is not a step (unsigned, every
revision) and a `KQTX` never travels with a file. The `./outbox` directory
`send --offline` writes is unrelated.

A hardware key with no `device_placements` row is its own device: that is the
original one-key one-device exchange, and distinct key files count as distinct
devices. `src/device.rs` owns containers, placements, and custody policy.
`keyquorum-device` (and `keyquorum device`) stores several passphrase-wrapped
identities as logical slots in one directory. A placement, written only from a
container the library opened, ties those keys to that container's `device_id`.
`keys.custody_mode` is `hardware` (one key per device) or `logical` (several
slots may satisfy Shamir together). `minimum_physical_devices` counts distinct
device ids either way, so slots on one container cannot satisfy a multi-device
policy. Logical slots are not a hardware quorum. Reconstruction searches
threshold-sized subsets for one that meets that minimum; unused extra shares
are not counted. `src/authority.rs` owns the delegated-signature rule: a
non-root `tree restructure` stays a proposal until the parent countersigns, a
direct tree update from that authorizer is refused, and employee reissue by
the direct parent stays a single signature. `unlock_approval = parent` is
opt-in. `device.kq` (`KQDV`) is signed by `device.skey`, and each slot token
(`KQST`) seals that same device id. `src/transfer.rs` owns `keyquorum transfer
copy|move`. A ghost keeps hierarchy and provenance without a private key, and
cannot sign, satisfy quorum, authorize an import, or be exported. An active
child under a ghost ancestor stays usable. COPY leaves the source active.
MOVE leaves the source row active until the destination commits and the
source slot token is gone; the ghost row is written only after that deletion,
so a crash cannot leave a ghost that `keyquorum-device` can still open.
`KQTX` packages are signed by the source device, bound to the destination
device id, and are not sealed envelopes. An empty receiver accepts a package.
A receiver that already holds active identities accepts an incoming key only
when it is a descendant of one of those identities. The same identity with
the same public keys reconciles; the same id or label with different material
is refused. When the devices are not open together, `src/device_relay.rs`
seals that `KQTX` package, a slot relocate, or the destination's
acknowledgement into a `PACKAGE` letter (`KIND_DEVICE_TRANSFER`,
`KIND_DEVICE_TRANSFER_ACK`, `KIND_DEVICE_RELOCATE`,
`KIND_DEVICE_RELOCATE_ACK`). The relay stores those letters opaquely in
`device_mailbox` and a public descriptor (device id, verify key, slot
public keys, signed by the device key) in `device_directory`. `device.push`
and `device.pull` are required the same way as inbox scopes: no bearer is
401, the wrong scope is 403, `device.pull` is bound to the recipient
fingerprint, and HTTP does not mint keys. The relay rejects raw `KQTX` and
never unseals a letter. A relocate letter carries a random relocate id that
the source signs and the destination's acknowledgement signs back;
`relay-drop` deletes the source slot only for the id it is given, so an old
acknowledgement cannot remove a slot relocated again later. Device letters
expire `DEVICE_PACKAGE_TTL_DAYS` after they are stored and are never deleted
on acknowledgement. `src/relay/device_mail.rs` owns the device mailbox;
`src/relay/device_directory.rs` owns the public descriptor.

`src/api_key_delivery.rs` owns a relay-issued customer API key as it travels
sealed (issue #86): a `KeyIssue` (relay URL, key id, scope, bearer, issued
and optional expiry times, optional device id, the relay's `KQPC`
certificate, an optional licence statement), signed by the relay key over
`signing::relay_key_issue_preimage` (which also binds the recipient's
X25519 public key) and sealed either as `PACKAGE` kind `KIND_API_KEY_ISSUE`
(20) for a rotated key the mailbox carries, or as `EXPORT_BUNDLE` type
`export::BUNDLE_TYPE_API_KEY` (4), written as `<customer>.kqkey`, for a
first key handed over as a file. Both carry the same signed payload; `open`
accepts either only when it was sealed to the key that opened it, the
certificate chains to the provider root unrevoked and valid now, the
signature verifies under the key that certificate names, and the issue has
not expired. `src/relay/key_delivery.rs` is the host side: `create_as_bundle`,
`rotate_as_bundle` and `rotate_as_letter` mint the key and produce the
sealed issue in one immediate transaction (a bundle is written while it is
open and removed if the command survives a failed commit, which is
compensation, not crash-atomicity: a crash between the write and the commit
can leave an orphan bundle that opens nothing and that the operator removes
before retrying; a letter goes into this relay's own mailbox in the same
transaction), record whom it was sealed to in
`api_key_deliveries` (never a bearer, only a letter id or bundle SHA-256)
and, for a letter, leave the old key usable for `--grace-seconds`
(`DEFAULT_GRACE_SECONDS`, 24 h) so its holder can still pull, then expire it
(`api_key::rotate_with`, `OldKey`); `keys revoke` ends it sooner.
`rotate_as_letter` refuses a key the customer cannot collect the letter with
(`Error::DeliveryNotCollectable`: only an `inbox.pull` key can read that
mailbox, so any other scope needs a live `inbox.pull` key bound to the
recipient, `api_key::has_live_pull_key`) before it changes anything; the rest
rotate by bundle. `host keys
create --recipient-key --relay-url --out` and `host keys rotate` drive it
and never print a sealed bearer. On the client, `loadkey --bundle` (with
`--slot` or `--share-file`) and `inbox open` on kind 20 share
`cli::install_key_issue`: the issue's relay URL must be the one being loaded
for, a device-bound issue loads only from that container, and then the full
provider challenge runs exactly as for a typed key, and the relay that
answers it must be the one whose signing key signed the issue (else
`KeyIssueRelayMismatch`, before any bearer is sent); only then does
`POST /keycheck` run and `relay_credentials` get written. The `kql_…`
operator lock and the `KQPL` policy never travel this way.

`src/storage.rs` is where container files and quorum ciphertext live:
`NativeStorage` is plain `std::fs` (new files still go through
`write_owner_only`), and `device::*_in` / `quorum::lock_bytes_in` /
`quorum::complete_unlock_in` take any `Storage`, which is how the browser lab
runs the same container and unlock code in memory. The original
path-based functions are thin wrappers over `NativeStorage`; keep them.
`src/file_delivery.rs` owns sealed file delivery between labels:
`KIND_FILE_DELIVERY` / `KIND_FILE_DELIVERY_ACK` `PACKAGE` letters, signed by
the sender and answered with a signed accept/reject, both checked against
the signing key the opening store has registered for the claimed label.
The bridge inbox carries them like any other non-device letter. Tracked
files travel as `KIND_FILE_HISTORY` / `KIND_FILE_HISTORY_ACK` (15, 16) in the
same module: the sender signs the header and a keyed commitment to the container (`crypto::commit`
under a random key sealed in the letter; protected content is never hashed bare, and a
commitment is only ever compared, `HistoryAck::confirms`), and the
container carries only the delivered revision and its ancestors
(`TrackedFile::extract_revision`, which also keeps events that name no
revision, such as a rename), so an untrusted newer revision never
leaves. Both `file receive` and `deliver open` require the letter's recipient
label to own the key that opened it (`deliver_cmd::require_recipient_key`). That signature authenticates transport only; the receiver judges
the revision by the file's own policy (`keyquorum file receive`) and
answers with a signed accept or reject. Receipt is idempotent by delivery id:
receiving the same letter again (`--into` or the same `--out`) records nothing new and only reseals the answer.
The letter's signed header also binds `content_proof`, the
`policy::proof_descriptor` of the delivered revision (every proof the
container holds for it, in order), which `select_shareable_revision` returns
in `DeliveryDecision` and `file receive` recomputes from the container,
refusing a mismatch. It names the proofs that travelled; it decides no trust.
`KIND_FILE_HISTORY_SNAPSHOT` (17) carries a `KQHS` history snapshot (no content)
to a label, its file id, root and event count signed by the sender (`file send-history`);
`file open-history` checks the signature, the recipient key and the snapshot, and
compares it with a local copy (`SAME`, `LOCAL_AHEAD`, `REMOTE_AHEAD`, `DIVERGED`). It is
not answered. Every letter kind and answer in `file_delivery` opens through the same
helpers (`open_kind`, `take_head`, `take_signature`, `verify_signed_by`), and
`file_delivery::recipient_owns_key` is the one recipient-key check both commands use.
Freshness is never assumed: `file_delivery::freshness` compares a letter's
revision and signed history root with `tracked_seen_roots` (what this store
accepted before for that file) and says `FIRST`, `REPLAYED`, `NEWER` (its
event chain passes through every root accepted before, `TrackedFile::passes_through`,
and it holds those revisions and adds one) or `NOT_NEWER`; `file
receive` prints it and records it on `SHARE_DELIVERED`, then records the
accepted root. That table is store state, not a cache over `.kqtf` files.
`src/file_history.rs` owns the tracked-file container (`KQTF`, its own
magic and version, not a sealed envelope) and the hash-chained event history
that travels with it; SQLite may only index it. It frames and chains events
and reuses `envelope`'s length-prefixed codec. It must not re-decide anything
another module owns: signatures go through `signing`, ancestry through
`authority`, quorum through `quorum`. Event type and outcome codes are wire
format: append, never renumber. History never records secrets. Every detail key
an event may carry is listed in `event::SAFE_DETAIL_KEYS`; `append` refuses any other, so a new
producer adds its key there. The quorum gate records only counts and policy words (`shares`,
`threshold`, `devices`, `minimum_devices`, `custody`, `approval`, `approvals`), and `file share`
names a fallback's `candidate` and `fallback_reason`.
`file_history/merge.rs` owns the automatic three-way text merge of divergent
heads: UTF-8 text only, by line, against the nearest common ancestor. A merge
is a new two-parent revision with no proofs, so it starts untrusted and goes
through `policy`; overlapping edits, other content, a criss-cross history or
a policy that disables it stop for a human. HCP seniority never chooses a
winning line.
`file_history/resolve.rs` picks the human reviewer for a conflict the merge
could not settle (prior neutral owner, then seniority, sector size, common
ancestor), from owners whose revisions are trusted under policy; conflicting
authors never review their own collision, a private bridge is never named
in history, and nothing is guessed when no one qualifies. `resolve_conflict`
settles the open conflict (`open_conflict`: two diverged heads that need a
person, or a sole head that is a rejected proposed merge) with a new revision
by the reviewer: `KeepLeft`, `KeepRight` or `Edited` content, recorded as
`CONFLICT_RESOLVED` (34). Only the selected reviewer or an ancestor of theirs
may decide (`may_decide`); when no reviewer qualifies, the scope owner or an
ancestor does; a conflicting author never does. `reject_merge` records
`MERGE_REJECTED` (35) against an untrusted proposed merge at the head; the
revision stays, `file sign` refuses it, and the resolution builds on it.
`keyquorum file resolve --keep left|right | --from FILE | --reject` is the
command: it signs the result as the reviewer's content signature, and the
normal trust policy judges it. `file merge` opens the interactive review
when a person must decide and the terminal is interactive (`Env::interactive`).
`src/cli/file_cmd.rs` is the `keyquorum file` command layer over `file_history`
(track, checkin, sign, countersign, rename, merge, review, graph, diff,
checkout, status, history, verify). Signing a native file with `--scope` is
the first content signature and starts tracking (the same steps as `track`);
`rename` changes only `logical_name` and appends `FILE_RENAMED`, never the
file or revision ids. `status` derives `current_revision_id` and
`trusted_revision_id` from the store's keys; the container never stores them. A file's rules are fixed at
`track` (`--owner-rule` and friends, checked by `FilePolicy::with_rules`; `policy`
shows them and the hash); revisions are stamped to the millisecond through
`Env::now_utc_precise`, while events keep whole seconds. It decides no
trust: it calls `file_history` and prints the result. The `.kqtf` container
carries its own policy; the store only supplies signing keys, through
`StoreTrust`, which accepts a key only for the identity the store knows for
that label (the enrolled identity from `transfer`, else one derived from the
label). Containers are replaced by writing a sibling and renaming, under an exclusive `<file>.lock` and only if the file is still the one the command read (`save` refuses a changed file rather than overwrite it).
`file_history/index.rs` keeps `tracked_files`, `tracked_revisions` and
`tracked_history_index` as a rebuildable cache over `.kqtf` files: metadata
only, no payload and no trust state, and `file reindex` restores it from the
containers, which remain the authority.
`src/cli/review_view.rs` is the review's view model and key handler (Vim keys,
`/` search with `n`/`N` repeat, `:` commands, per-line provenance for the cursor
or pointer) with no terminal and no dependencies; `keyquorum file review` prints from the same
`ReviewView`. `src/cli/review_tui.rs` (feature `tui`, `ratatui`, native-only,
refused by `build.rs` on wasm32) only draws it and reads keys and the mouse.
It decides no trust and edits no history: `:sign`, `:accept`, `:reject` and
`:finalize` run the real `file sign`, `file resolve` (or, for a result on a clean merge with no conflict, `file checkin`) and `file finalize`
only after `:as`/`:slot` (or `review --as --slot`) name who is acting; the review
never judges authority itself. It shows two unchanged context lines around each change (`ViewLine::context`; `c` toggles them, the printed review omits them). Hunks fold (`za`/`zc`/`zo`, `zM`/`zR`), `Space`
picks a change, `:compose` applies the picked changes to the common ancestor
(`file_history::apply_hunks`), and `:edit` opens the result in `$VISUAL`/`$EDITOR`.
A clean merge waiting at the sole head opens the same review (`ReviewView::pending_merge`).
`src/cli/gate_link.rs` ties a quorum-protected or password-locked file to a
tracked `.kqtf` (`keyquorum file link --quorum-file|--locked-file`, table `tracked_gate_links`, deliberately without a
foreign key to the gate so a purged gate keeps its link) and appends what
happened at the gate to that file's history: the attempt and its outcome,
the labels presented on success, and, when the TTL destroys the file,
`FILE_EXPIRED`, `CONTENT_DESTROYED` and `EXPIRED_ACCESS_ATTEMPT`. The CLI
calls it only after `quorum`, `locked_files` (PIN check included) or `sharing` (file share create, redeem, revoke; the share's id, never its token) has answered; the gates never read the link,
recording is best-effort and cannot change an outcome, and no share,
password, PIN or plaintext is ever recorded. A PIN check
leaves only its outcome (`pin=asked|verified|mismatch|locked|failed`, none when no PIN applies), and a share-link
redemption is recorded as `redeemer=UNKNOWN_BEARER`, since a token proves no identity.
`file finalize` (scope owner or an ancestor, by slot) adds a `Finalization`
proof (`ProofKind` 3, container v6, event `REVISION_FINALIZED` = 33) to a revision that is
already trusted; `policy::is_finalized` and `latest_finalized_ancestor` derive it per store
(never stored), and `status` shows it.
The bridge-or-owner rule accepts a private bridge's signed approval of the
revision itself (`keyquorum file bridge-approve`, `signing::file_bridge_approval_preimage`,
a KQBS artifact kept only in this store's `tracked_bridge_approvals`, never in the
`.kqtf`): `StoreTrust::revision_bridge_evidence` asks `private_bridge::revision_approved`,
which re-verifies it against the live bridge (current generation, signer still a
member) and accepts it only when the bridge's members reach from the author to the
scope (`authority::bridge_connects`; supervisors do not count). A bridge merely
existing between labels (a tree link or a roster) approves nothing; tree links are
review-path evidence only (`bridge_between`).
The stricter `author+bridge+owner` cross-branch rule requires that same live,
revision-specific bridge approval and a countersignature by the file scope owner;
neither approval can substitute for the other.
A trusted cross-branch `POLICY_DECISION` records only `satisfied_by=BRIDGE`,
`SCOPE_OWNER`, or `BRIDGE_AND_SCOPE_OWNER`; it never names a bridge id,
generation, signer, member, or roster.
A revision stamped with a topology generation this store never held (`tree_generations_seen`, recorded by every file
command and on both sides of an applied restructure) is `Pending(MissingTopologyEvidence)`,
never judged against today's topology; generation 0 means no published topology.
Container v7 adds optional `EventProof`s after the events (the event's own actor
signing `signing::file_history_event_preimage`), written only when one exists;
`rename`, `expire` and `resolve --reject` sign the events they append, and
`policy::event_attested` / `file history` report a signature only where this store's
key for that actor verifies it. Unsigned events stay hash-chained, never attested. `file checkout`, `file verify` and `export tracked-file` append
`REVISION_CHECKED_OUT` (36), `VERIFICATION_RUN` (37) and `HISTORY_EXPORTED` (38)
only under `--record`, attributed only to the label `--as` names; that label is a
claim, so the event is hash-chained and never attested. `label_authority_evidence` (owned by `authority`: `record_label_evidence`,
`historical_signing_publics`) is what every file command records, from the store's own
registry, of the identity and signing key each label held per topology generation;
`TrustContext::historical_signing_publics` lets a revision or event stamped with an
older generation verify against that key after a reissue. It is the store's own
observation, never taken from a `.kqtf`.
Terms for proposing a change: a **merge proposal** is prepared changes submitted for
review (the pending merge revision and its reviewer resolution); a **change request**
(ask someone to change a file, `file request --change`) and a **file request** (ask the
holder to send a file, `file request`) are signed request letters (`KIND_FILE_REQUEST` 18,
answered by `KIND_FILE_REQUEST_ANSWER` 19, `file_delivery::request`), opened with
`file open-request` and answered with `file answer-request` / `file open-answer`. A request
only asks: it delivers and changes nothing, `file share` serves an accepted file request,
and a change arrives as an ordinary revision. `FILE_REQUESTED` (39), `CHANGE_REQUESTED` (40)
and `REQUEST_ANSWERED` (41) record the id, kind and decision in a copy named with `--file`;
a change request's message is shown to the holder and never recorded. This version states
two limits: historical authority is local key history, not a complete generation-specific
identity, relationship or reviewer-authority record, and `satisfied_by` discloses bridge
participation in portable history pending the owner's acceptance.
`file_history/expiry.rs` ends a tracked file: an `EXPIRY_SCHEDULED` event
sets the time, and destruction removes every retained revision's payload at
once (container v5 lets a payload be absent; v4 still decodes).
`verify_structure` makes that all-or-nothing and recorded: a payload may be
missing only when the chain holds this container's `CONTENT_DESTROYED` (one
without a `gate` detail; a linked gate's purge names its gate and leaves the
revisions alone), and then none may remain. The tombstone keeps the graph, proofs and history, verifies, takes no
new revision, and is neither imported nor extracted. `keyquorum file expire`
(scope owner or an ancestor, proven by signing a challenge with that label's registered key via `--slot`) schedules it or destroys now; commands that need
content load through `load_live`, which destroys on the first touch after the
time and records each later attempt as `EXPIRED_ACCESS_ATTEMPT`, attributed
only to a label the command names. Copies already held elsewhere are their own
files.
`file_history/sync.rs` imports another copy of the same file (same id and
policy, and it must verify): revisions and proofs are unioned, a fork stays as
two heads, and the importer records one `HISTORY_IMPORTED` event in its own
chain; two diverged event chains are never joined. `file_history/snapshot.rs`
is `KQHS`, a verifiable event-history snapshot (its own magic, not a sealed
envelope) that can be checked as a point in a file's history.

`src/lab/` (feature `lab`) is KeyQuorum Lab, the public browser
demonstration published from `lab/` to GitHub Pages and embedded by
bailey-forbes.com. It is a sandboxed machine, not a second implementation:
`src/cli/` hosts the whole `keyquorum` and `keyquorum-device` CLI in the
library behind `cli::env::Env` (stdout/stderr, filesystem `Storage`,
prompts, SQLite stores, relay transport, provider root, clock), and
`src/lab/vm.rs` (`LabVm`) implements that `Env` with an in-memory
filesystem, mock USB drives mounted under `/media` (real `device`
containers, with published demo passphrases answering the prompts), one
SQLite store per path (`/srv/keyquorum/org.sqlite` for the org, one per
person in their home), and `relay::service::dispatch` answering relay
requests in process against a per-session relay certificate. Seeding and
every GUI or terminal action run real command lines there
(`src/lab/state.rs`); the transcript is the trace. The lab must not
reimplement quorum, custody, approval, visibility, bridge, or delivery
rules, and must not add gates of its own in front of them: if the CLI
would allow it on a real machine, the lab allows it. Read-only library
calls are fine for rendering views. `src/lab/wasm.rs` is the only
JavaScript surface. The lab WASM must never include `provider`: `build.rs`
refuses a wasm32 build with both features (native `--all-features` builds
may combine them); the in-process relay uses the non-provider
`relay::service`, never the axum host. Nothing secret may be seeded:
everything in the bundle is public. The lab's ready handshake posts only
to `https://bailey-forbes.com` (or a loopback origin for tests), never `*`.

Every seeded person starts on their own personal mock drive (`src/lab/seed.rs`
`DRIVES`), not a shared department one — `LabState::move_slot` (`keyquorum-device
relocate` plus a `keyquorum device bind` re-bind, so `device_placements`
follows immediately) is what puts more than one slot on
one drive, which is when they start counting as a single physical device.
Both drives must be inserted to move a slot between them, matching the
physical requirement of moving a token between two USB drives. Quorum-locked
files (the `files` table) can carry a UTC `expires_at` the same way
`password_locked_files` does (`quorum::lock_bytes_until_in`,
`quorum::set_expires_at`, `quorum::is_expired`, `quorum::purge_if_expired_in`
— the destructive purge, wired into `quorum::complete_unlock_in`, deletes the
ciphertext and the `files` row on first touch past the TTL); the lab resolves
a few seeded files' TTLs relative to load time via SQLite's own clock
(`strftime('now', modifier)`) so a couple of them expire while the tab is
open. `legacy-migration-notes.txt` seeds a real ghost through
`keyquorum transfer enroll` and then `keyquorum transfer move` to a
throwaway archive device before the lab starts, so `transfer::possession`
genuinely reports `Possession::Ghost` for that label, not a UI-only flag. She stays an ordinary leaf in
`legacy-migration-notes.txt`'s tree; `device::leaf_is_ghost` refuses her
share the moment anyone presents it. `RequirementNode.ghost` (`view.rs`)
is how the frontend marks it.

`src/lab/state/history.rs` is the lab's tracked-file layer. `LabState::seed_tracked`
builds three tracked files with real `keyquorum file` commands in Sarah's own
store while every drive is connected: an unsigned newer edit whose sharing falls
back to the last trusted revision, two edits that auto-merge, and two edits to
one line that go to a named reviewer. The lab follows a registry of containers
(those seeded, those the Activity page's buttons create, and any `.kqtf` a
terminal command names) and `LabState::log` re-reads them before it records each
action, appending unseen events as `ActivityView` entries (`kind == "history"`,
with `fileId`, `revisionId`, `generatedLabel`, `historyRoot`,
`finalizationState`, ...) beneath the action's own entry, which stays newest
because tutorial gates read `activity[0]`. The Activity page's tracked-file
buttons (track, check in signed or unsigned, sign, countersign, merge, review, resolve,
verify, share, receive or refuse, record the answer, ask for a file or a change
(`file request`, `--change`), accept or decline a request (`inbox open <id> --accept|--decline`),
record a request's answer (`inbox open <id> --file`), expire, view a revision,
diff, export and check a snapshot, import another copy, link or unlink a quorum
or password gate) each run one `keyquorum file` command as the active person against their own store with their own slot
(a quorum gate is linked in the org store and a password gate in its owner's
store, where each gate runs); letters and answers travel through the relay (`send`, then `inbox open <id>` with
`--into`, `--out`, `--file`, `--accept` or `--decline`), never a shared folder. `Snapshot::tracked_files` judges revisions with that store's
`StoreTrust`; the lab adds no gate or rule of its own, event categories come
from `HistoryEventType::category`, and entries without a history serialize
exactly as before. The terminal does not expand `~` inside command arguments.

The everyday commands (`src/cli/{profile,send,inbox,setup,doctor}.rs`: `use`,
`cache`, `send`, `inbox`, `setup`, `doctor`) add no rule of their own. `send`
builds the command `deliver send` or `file share` would (marked `via_outbox`, so
the letter goes through the sender's outbox ring), and `inbox open` calls
those commands' own handlers (`deliver_cmd::run`, `file_cmd::run`,
`org_update::import_any`) and judges nothing; `inbox open <id>` takes `--into`/`--out`
(a tracked file), `--file` (the copy an acknowledgement, request answer, request or snapshot
concerns) and `--accept`/`--decline` (a request); the copy is always named by the person, never chosen
from the letter (its file id is the sender's claim, and the handlers refuse a wrong copy). The
sweep (`inbox open` with no id) leaves acknowledgements, requests and request answers, and device
letters, listed with the command that opens them. `inbox --api-key` is the pull key; answers upload with
the stored push key. The `profile`, `recent_params`,
`relay_trust_cache`, `verified_cache` and `inbox_letters` tables hold no secret
(no passphrase, key, bearer or plaintext). The three caches share one flat
`db::cache::TTL_MINUTES` (15), are never an input to a signature, quorum,
custody, approval, freshness or trust decision, and turn off with `--no-cache`,
`KEYQUORUM_NO_CACHE` or `use --cache off`; the relay trust entry is bound to the
revocation list, the stored key hash and the certificate expiry, never records a
failure, and `loadkey` always runs the full challenge. A left-out flag resolves
explicit argument, then recent parameter, then profile, then the command's own
behaviour or error, and a command that acts outward or cannot be undone (`send`,
`--push`, `transfer move`, `revoke`, `expire`) never takes its target from a
recent parameter. A slot's passphrase is prompted once per command
(`cli::profile::RunScope`), held in memory and zeroized when it ends. The
producers (`reissue`, `tree restructure`, `tree countersign`,
`bridge private create`, `bridge private remove-member`) upload with `--push`
through `deliver_commit_push`: prove the relay and key, write the envelopes,
commit, then upload, so a failed commit still removes the files and a failed
upload leaves the change saved with the files in place and the retry command in
the error. `deliver send|open|ack`, `file share|receive|ack` and `relay pull`
are legacy: they behave as before and a stderr note names the replacement. The
everyday commands are dispatched from `cli::run`, outside `run_in_store`, and
take boxed option structs, because debug-build test threads have little stack;
keep new commands out of that frame.
The lab's mailbox runs `send` and `inbox` with an explicit `--slot` (a slot moves
between drives, and an explicit flag beats the profile) and keeps the output lines
it parses (`(delivery <id>)`, `Relay stored letter`, `From X to Y`, `Delivery <id>
accepted|rejected`) stable. Switching user, inserting a drive and receiving a letter
settle mail in the lab (`LabState::settle_mail_and_answers`: `inbox list`, `inbox open`
for answers, then `inbox open <id> --file` for the tracked files and requests
the person sent, only while their slot is in); a quorum file is sent by one
`send --quorum-file` run against the org store (it holds the file's shares and its own push key),
unlocking through the same `unlock_quorum_file` as `access quorum --state 1`, so nothing is written to disk.
Each seeded person has `use` and `device bind` run for their own slot (re-run for the owner by
`move_slot`), and the lab can run `doctor`, `use` and `device bind` for the active person.

## Working conventions

- Keep changes minimal and scoped to what's requested — don't scaffold unrelated
  modules, abstractions, or tooling ahead of need.
- When the current branch already has an open pull request, ask before creating another branch or opening another pull request. No answer is a denial. On a denial, stay on the current branch and update the open pull request. Create a new branch and pull request only after an explicit yes.
- After Rust work, run `cargo build` (and `cargo build --features provider`
  when touching the mailbox host), `cargo fmt`,
  `cargo clippy --locked --all-targets --all-features -- -D warnings`, and
  `cargo test --locked --all-targets --all-features` before considering a change
  complete.
- After lab changes (`src/lab/`, `lab/`), also run, from `lab/`:
  `npm run build:wasm`, `npm run build`, and `npm run test:browser`.
- Match existing code style; this repo has no established style guide yet, so follow
  standard Rust conventions (`rustfmt` defaults) unless told otherwise.
- Put tests in their own file next to the module they cover, not in an inline
  `#[cfg(test)]` module inside the implementation. Use `src/<module>/tests.rs`
  (directory module: `#[cfg(test)] mod tests;`) or `src/<module>.rs` with
  `#[cfg(test)] #[path = "<module>/tests.rs"] mod tests;`. Nested files such as
  `src/relay/client.rs` load `src/relay/client/tests.rs` the same way. Shared
  test helpers belong in a `#[cfg(test)]` module, not in production code.
- Tests never write a secret as a literal: passphrases, passwords, PINs and
  nonces come from `crate::test_secrets` (`passphrase`, `other_passphrase`,
  `pin`, `other_pin`, `bytes32`, `shared_passphrase`), drawn at run time. A
  test's assertion message never formats a command's `Result`, error or
  output: name the command line instead. Both keep CodeQL
  (`rust/hard-coded-cryptographic-value`, `rust/cleartext-logging`) clean.
- CodeQL's generated model of `std` counts `VecDeque::push_back`,
  `push_front`, `insert`, `append` and `remove`, and `Vec::insert`, `remove`
  and `swap_remove`, as log writes (`log-injection` sinks on the receiver),
  and its name heuristics make any binding, field or called function named
  `*secret*`, `*cert*`, `*password*` or `*api_key*` a source, as is every
  value reached from one (so everything `provider::verify_certificate`
  returns). A queue of prompted answers (`LabVm::staged_answers`,
  `MemoryEnv::answer_prompt`) is therefore a `Vec<Zeroizing<String>>` popped
  from the end, and the host reports the checked certificate's public id,
  serial and expiry through `tracing::info!` like its other operating lines,
  never `eprintln!`; keep both that way rather than suppressing the query.

## Security

This project deals directly with cryptographic key material, hardware tokens, and
encrypted user files. Treat it as security-sensitive:

- Never commit private keys, tokens, `.env` files, secrets, or plaintext copies of
  protected/test files. See `.gitignore` for patterns already excluded (`*.key`,
  `*.pem`, `*.secret`, `*.token`, `*.kqkey`, `*.kqpb`, `*.kqbn`, `*.kqcert`,
  `*.kqrl`, `*.kqpolicy`, `device.kq`, `device.skey`, `*.kqst`, `secrets/`,
  `keys/`, `test-keys/`, `provider-secrets/`, etc.).
- Be extra careful with any code touching key derivation, encryption/decryption, or
  quorum/threshold logic — correctness bugs here are security bugs.
- Flag anything that looks like a hardcoded secret or credential before committing.

## Review guidelines (strict, SOC 2)

These apply to every automated reviewer (CodeRabbit, Codex, Claude) and to humans.
Review as if an auditor will read the finding. KeyQuorum handles key material, so a
finding that is only a nit is still reported, but marked as one.

### Every finding must carry all five parts

A finding that lacks any part is not posted.

1. **Source** — why it is a violation, as a pointer that can be checked: a rule in
   `CLAUDE.md` / `AGENTS.md` (name the section), a file and line in this repository, or an
   official external source (RFC and section, NIST SP number, RustSec or CVE id, the AICPA
   Trust Services Criteria, vendor or language documentation). Reviewers may and should
   search the web for it, and prefer primary and official sources over blogs or forums.
   Never "best practice" with no source.
2. **Source quote** — quote the source itself: the sentence or clause that states the
   requirement, copied verbatim in a block quote, with its URL (or file and line) and the
   date it was read. A link alone is not a quote. If the source cannot be retrieved, say
   "source not retrieved" and do not rate the finding above minor.
3. **Quote** — the exact offending lines from the diff, in a code block, copied
   verbatim with their file path and line numbers. Do not paraphrase code.
4. **SOC 2** — the Trust Services Criterion it affects (id and name, from the table
   below) and one sentence on how this change weakens that control. If no criterion
   applies, write `SOC 2: none (correctness)` and mark the finding minor. Do not
   stretch a criterion to fit.
5. **Fix** — the concrete change, as a diff or replacement lines.

There is no length limit on a finding or a review: use as many words, quotes and
links as the evidence needs. A one-line headline first, then the detail, is
recommended so the finding can still be skimmed.

Format:

````
**<severity>: <title>**
Source: <rule, file:line or official source with URL>
Source quote: > <verbatim sentence from the source> (<URL or file:line>, read <date>)
Quote (`path:line`):
```<lang>
<verbatim lines>
```
SOC 2: <id> <name> — <how this weakens it>
Fix: <change>
````

Severity: **blocker** (secret exposure, broken or bypassed quorum, custody, approval or
signature check, plaintext at rest, authentication bypass), **high** (a SOC 2 control
is missing or weakened, data loss, replay or freshness gap), **major** (wrong
behavior, a missing test for changed behavior, docs that contradict code),
**minor** (style, naming, comments). Verify every claim against the current code
before posting, and do not repeat a finding that was already fixed or answered.

### SOC 2 criteria to check against

| Criterion | What to look for in KeyQuorum |
| --- | --- |
| CC6.1 Logical access | A key, slot, bridge, relay or API-key check that is skipped, widened or decided by the caller; scope or fingerprint binding removed; a trust decision taken from a cache. |
| CC6.2 / CC6.3 Provisioning and removal | Revocation, reissue, eviction or key rotation that leaves old access working; keys minted over HTTP or by a customer. |
| CC6.6 System boundaries | New relay routes without auth, scope checks, body or rate limits; plaintext listeners; unvalidated input from the network or a letter. |
| CC6.7 Transmission and removal of information | Anything that sends or writes plaintext, keys, bearers or passphrases outside the sealed envelope, the owner-only file or memory; weakened TLS or certificate checks. |
| CC6.8 Unauthorized or malicious software | New dependencies or build steps without `deny.toml` / audit coverage; unpinned or unreviewed third-party actions; code that runs untrusted input. |
| CC7.1 Vulnerability detection | Dependency or config changes that bypass `cargo audit`, `cargo deny`, `gitleaks`, `npm audit` or CodeQL. |
| CC7.2 Monitoring | Security-relevant events (auth, key lifecycle, denied scope, tamper detection) that are not recorded, or records that hold secrets. |
| CC7.3 / CC7.4 Incident response | Failures swallowed silently, errors that hide the cause, or no way to revoke or recover after a compromise. |
| CC8.1 Change management | Behavior changes without tests in their own file, wire-format codes renumbered, wire or schema changes without migration, docs or agent files not updated, CI weakened. |
| CC9.1 Risk and vendors | New external services, endpoints or data flows not documented in the security model. |
| C1.1 / C1.2 Confidentiality | Secrets in logs, errors, history events (`SAFE_DETAIL_KEYS`), tests or fixtures; missing `zeroize`; no deletion path for expired or revoked data. |
| A1.2 Availability and recovery | Unbounded reads or loops, missing size limits or timeouts, no backup or restore path for stored state, retry loops that never end. |
| PI1.2 – PI1.5 Processing integrity | Signature, freshness, ordering, replay or idempotence checks removed or reordered; partial writes with no rollback (plan-then-commit broken). |

### KeyQuorum-specific rules to enforce

Report a finding, with the rule as its Source, for any of these:

- Private keys, bearers, `.kqpb`, `*.kqcert`, `*.kqrl`, `*.kqpolicy`, provider root keys or
  relay databases committed, logged or printed. Never log secrets; only the published
  Lab demo values are allowed.
- Plaintext of a protected file written to disk (the Lab and `send --quorum-file` unlock
  in memory only), or a passphrase held after its command ends.
- A second sealed-envelope framing outside `src/envelope.rs`; a kind byte, event type or
  outcome code that is renumbered rather than appended.
- `key_nodes` mutated outside `key_tree.rs`; hierarchy rules outside `authority.rs`;
  signatures outside `signing`; quorum rules outside `quorum`.
- A relay that unseals envelopes, holds wrapped shares or private keys, or mints API keys
  over HTTP; `keyquorum host` documented in customer-facing docs.
- A `RelayStore` backend that persists a raw bearer, unseals a letter, splits one unit of
  work across transactions, or re-rolls a rule that lives in `audit`, `mailbox`,
  `device_mail`, `org_tree`, `device_directory` or `key_delivery`; a personal or
  organization store reached through `RelayStore` or moved to another database; a relay
  credential (relay key, operator lock, provider root key)
  taken from a flag value, written into `wrangler.toml` `[vars]`, a `.dev.vars` file,
  Terraform state or `terraform.tfvars`, a GitHub Actions secret or log, a unit file or an
  image layer; the provider root key or the operator lock given to a running relay.
- The operator console (`src/relay/{operator,issuance,customer,licence,activity,operator_log}.rs`,
  `workers/admin/`): a change that skips the operator lock, the operation id, the
  same-origin check or the verified identity; ownership of a key inferred from a
  label, fingerprint or address; a licence statement version updated or deleted;
  a licence void that leaves its keys usable; a sealed bundle or bearer retained
  or returned in a reply; activity recorded for an unknown bearer or holding an
  address, query or body; the operator lock stored, logged or put in a Worker
  secret, browser storage or a URL; a lock bootstrap that an ordinary request on
  an empty store can claim; the `admin` scope issued from the console; a public
  route to a management operation; the console documented as enforcing licence
  limits, as showing file contents, or as deployed.
- The Worker's deployment (`workers/`, `deploy/cloudflare/**`,
  `.github/workflows/workers.yml`) letting the admin Worker serve anything without a
  verified Access token, or gaining a route that bypasses Access to an operator
  path, re-enabling `workers.dev`, preview URLs on the admin Worker or on anything but the
  public Worker (or a public Worker preview that reaches relay data or secrets), a migration that deletes or renames a
  Durable Object class without review, key material in `wrangler.toml` or the bundle, or a
  deploy credential broader than Workers Scripts edit.
- A cache (`recent_params`, `relay_trust_cache`, `verified_cache`) used as an input to
  a signature, quorum, custody, approval, freshness or trust decision.
- Producers (`reissue`, `tree restructure`, `tree countersign`, `bridge private ...`) that
  upload or persist before the envelopes and the commit are in step.
- The Lab reimplementing quorum, custody, approval, visibility, bridge or delivery rules,
  or adding a gate in front of them; the Lab bundle containing anything secret; the
  `provider` feature in a wasm32 build.
- Tests placed inline in implementation files instead of a `tests.rs` next to the module;
  a changed behavior with no test; a `--features provider,lab,tui` build or clippy
  warning left behind.
- Documentation (README, `docs/latex`, Lab manual, agent files) that contradicts the code:
  a command, flag, default, path, legacy note or limit that no longer matches. Check
  examples against `--help`, and keep `CLAUDE.md`, `AGENTS.md` and `.cursorrules` identical.
- Legacy commands (`deliver`, `file share|receive|ack`, `relay pull`) changed in behavior,
  or a new command printing a legacy note it should not.

## Other agent instruction files

This repo also carries `AGENTS.md` (Codex and other agent tooling) and `.cursorrules`
(Cursor). Keep guidance consistent across these files when updating one.

- Legacy checks: tests of deprecated verbs (`deliver`, `file receive|ack`, `relay pull` spellings) sit behind the `legacy-tests` feature and the `legacy` workflow (`.github/workflows/legacy.yml`), whose single job is skipped by default and run on the `legacy` PR label or a manual dispatch. `--all-features` includes them; the everyday CI gate is the `Native KeyQuorum tests` job in `.github/workflows/deploy-lab.yml`, which calls the parallel test groups of `.github/workflows/tests.yml` (lab, cli, file_history, relay+provider+db, and everything else, so a new module needs no workflow edit) with `--features provider,lab,tui`; its `test` job is the one stable check, and the lab build and the Pages publish follow it. The Worker has its own stable check, `workers` (`.github/workflows/workers.yml`: it builds the Worker, validates the Terraform and gates the staging and production deploys), beside `test` and `codeql gate`. There is no separate compile workflow: those groups and the lint job build every target. The legacy run uses the same groups with `--all-features`.
- Security checks: `.github/workflows/security.yml` runs `cargo audit`, `cargo deny --locked check` (policy in `deny.toml`), `gitleaks` over the full history (allowlist in `.gitleaks.toml`, which passes only the published Lab demo passphrases and lockfile checksums), `npm audit` for `lab/` and `workers/` and CodeQL (security-and-quality suite from `.github/codeql/codeql-config.yml`, for Rust, the Lab's TypeScript, the Worker's JavaScript and the workflows; `.github/scripts/codeql_report.py` prints each finding as source, source quote, quoted lines, SOC 2 criterion and fix, and the `codeql gate` check fails on a high or critical finding in shipped code), on every PR, on `main` and weekly; `.github/workflows/sbom.yml` keeps CycloneDX SBOMs as artifacts. A new dependency must satisfy `deny.toml` (add a licence only after checking it). Dependabot covers Actions, Cargo, npm (`/lab`, `/workers`) and Terraform, but only Actions updates auto-merge; cargo, npm and Terraform updates (which include the cryptographic crates and the deploy tooling) wait for a person. Vulnerabilities are reported privately as `SECURITY.md` describes.
- SOC 2: `docs/soc2-controls.md` maps each Trust Services Criterion to the control in this repository, its evidence (test or workflow) and what the operator must still provide (TLS termination, rate limiting, backups, log retention). Update it with any change to a control it names.
- Review rules: the "Review guidelines (strict, SOC 2)" section above is also loaded by CodeRabbit (`.coderabbit.yaml` points its per-path checks at it and runs a "SOC 2 evidence" pre-merge check) and by Codex review. Change the rules in all three agent files together, and keep `.coderabbit.yaml` consistent with them.
