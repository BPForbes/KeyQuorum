# Relay secrets: what is secret, where it lives, where it never goes

A classification of every artifact a relay deployment touches. "Not secret"
never means "safe to modify": the signed artifacts (`provider.kqcert`,
`provider.kqrl`, `provider-policy.kqpolicy`, `device.kq`) are public but
integrity-sensitive, and a changed one is simply untrusted. Secrets are
never injected into them: they are signed public formats, not sealed
carriers. A secret that must move between principals goes inside an
existing sealed carrier (`KQPB` letter or `KQXB` bundle); a secret a
process needs for itself arrives as a file through the platform's
credential mechanism.

Hosting status: Cloudflare is the sole production hosting provider. The
public Worker and its Durable Object (`workers/`) are built and tested and have
never been deployed. A customer API key is minted from the provider's console on
the admin Worker, through a private binding to the same Durable Object, with the
operator lock presented per change. Rows marked
"(built, not deployed)" below describe code the repository now contains, rows
marked "(code exists, nothing deployed)" the admin Worker's front door
(`workers/admin/`: the provider's console and its API, behind Cloudflare Access
with MFA, the Worker verifying Access's token itself; it holds no secret, and
reaches the relay only through the binding `RELAY_ADMIN`), and rows marked "(planned)" the plan
of record in `relay-hosting.md`. No deployment has run, and the owner's GitHub
and Cloudflare setup is not done. The native `keyquorum host serve` is the
development, test and reference host.

| Artifact | Secret? | On the relay? | Persistence | Source | Never |
| --- | ---: | ---: | --- | --- | --- |
| provider-root private key | **yes** | **no** | offline machine only (`host root generate --private-key-out`, owner-only) | KeyQuorum root ceremony | a relay, Worker, CI secret, state file, database, unit file, environment, or `.kq*` file |
| provider-root public key | no | compiled into clients and relays | source and binary (`KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY`) | KeyQuorum | — |
| relay private key (`relay.key`) | **yes** | **yes**, in memory and as a runtime credential file | an owner-only file on the development or reference host (optionally handed to the process as a service credential file you configure); Cloudflare relay: the Worker secret `RELAY_PRIVATE_KEY`, see below | `host identity generate --private-key-out` | the environment, a flag value (`ps`), a log, version control, a `.kqcert` |
| relay public key (`relay.pub`) | no | yes | file | `host identity generate` | — |
| `provider.kqcert` (`KQPC`) | no (signed) | yes, read-only | file, root-owned; Cloudflare relay: the Worker secret `RELAY_CERTIFICATE` (base64) | offline root (`host certify`) | being edited; being treated as a secret carrier |
| `provider.kqrl` (`KQRL`) | no (signed) | yes, read-only | file; the Cloudflare relay's core takes no revocation list yet, so the Worker does not read it | offline root (`host krl`) | the same |
| `provider-policy.kqpolicy` (`KQPL`) | no (signed; it authorizes) | only where the hardware-authority policy is checked | file | offline root (`host policy issue`) | a relay that does not need it; the environment |
| relay SQLite database (`relay.sqlite`) | sensitive (key hashes, audit trail, every stored letter) | yes | `/var/lib/keyquorum`, 0600 with its journal sidecars | the relay | a personal store's path; a shared or world-readable location; the repository (`*.sqlite` is ignored) |
| `kql_…` operator lock | **yes** | operator only: for `host keys create\|rotate` on the native host, and presented with each change from the console (hash held by the relay, value never) | a file on the operator's session (`--licensee-key-file`, `KEYQUORUM_LICENSEE_KEY_FILE`), or a file that exists only for that session; for the console, the operator's password manager, pasted into the form for each change | native: minted once by the first host `keys` command on an empty issuer store. Console: staged by *Create/Replace the lock* (`licensee_pending`, shown once) and made the lock only when presented back (`confirm_lock`) | the long-running relay service; any Worker (not a Worker secret or `[vars]`); the browser's storage, cookies or URL; a unit file; the environment of the service; a log; the activity or operator tables |
| customer `kq_…` bearer | **yes** | never raw at rest (only `hex(SHA-256(raw))`) | the customer's own store, sealed (`relay_credentials`) | minted by `host keys create\|rotate` | a log, an audit row, a database document, a ticket or chat; the environment |
| Console data: customers, licence terms, key links, activity (built, not deployed) | sensitive customer metadata (names, references, terms, which key did what); no secret | the Durable Object's tables `customers`, `licences`, `licence_versions`, `licence_keys`, `access_activity`, `operator_actions` | the relay's database (activity is dropped after 90 days; the rest stays until the operator removes it) | the operator, through the console | a bearer, a key hash, a sealed bundle, an address, a query, a request or response body, the operator lock or an Access token in any of them |
| `.kqkey` produced by the console | sealed secret carrier | **not retained**: sealed in the request and returned once | the operator's download, then the customer | the console's issue and replace | being stored on the relay or the Worker (a lost download is replaced, not recovered) |
| Worker binding `RELAY_ADMIN` (built, not deployed) | no (a capability, not a secret) | the admin Worker's configuration | `workers/admin/wrangler.toml` (production binds `keyquorum-relay`, staging `keyquorum-relay-staging`; `guard.mjs` refuses any other name and any migration in that file) | the operator | a public route, a preview of the admin Worker, a binding to another environment |
| `.kqkey` bootstrap bundle (`KQXB` type 4) | sealed secret carrier | handoff only | temporary, owner-only, never overwritten; deleted once loaded | `host keys create --recipient-key --out` (#86) | the repository (`*.kqkey` is ignored); being left on the relay; being opened by anyone but the recipient key |
| `.kqpb` key-rotation letter (`KQPB` kind 20) | sealed secret carrier | opaque, in the mailbox until collected or expired | the mailbox, with the old key's grace period as its TTL | `host keys rotate` (#86) | being unsealed by the relay |
| audit checkpoint file | not secret, but the evidence | **no** (that is its point) | write-once storage the operator controls | `host keys checkpoint --out` | the relay host or database |
| Worker secrets: `RELAY_PRIVATE_KEY` and `RELAY_CERTIFICATE` (built, not deployed) | relay key **yes**; certificate no (signed) | the Worker's Durable Object, at run time | Cloudflare Worker secrets, set by the operator with `wrangler secret put` (the key as the hex file `host identity generate` wrote, or its base64; the certificate as base64); readable by the Worker at run time and by Cloudflare account members who may edit the Worker. Each environment has its own. Both or neither: one without the other, or an unreadable value, makes the relay fail closed (503) and never repeats the value | the operator (relay key from `host identity generate`; certificate from the offline root) | GitHub secrets, `wrangler.toml` or any committed file, `[vars]`, Terraform state or `terraform.tfvars`, a log, a response; the `kql_` lock or the provider-root private key on a Worker. `workers/scripts/guard.mjs` fails CI on key-like material or a secret-like `[vars]` or `[previews.vars]` name in `wrangler.toml` or the built bundle (a pattern check, not proof). The key's copy in JavaScript is zeroed once the core has its own; a Worker Preview gets none of these unless the operator sets them for Previews, which they must not |
| `ALLOWED_HOSTS` (built, not deployed) | **no** (public, but integrity-sensitive: it decides which hosts the public Worker answers, so a changed value changes whether a Version URL, which shares the Worker's bindings and secrets, is served) | the public Worker's `[vars]`, at run time | empty in `workers/wrangler.toml`; set by `workers.yml` at deploy from the GitHub environment variable `RELAY_URL` (`workers/scripts/relay-host.mjs` takes `https://<domain>/relay` or `/relay/<name>` and returns the host; it refuses any other path, a wildcard, a list, an address or a credential). `*` appears only in `[previews.vars]`, where a Preview has its own empty Durable Object. Empty or unset, the Worker serves nothing (503) | the operator (the relay's domain, `keyquorum.dev`) | a wildcard outside `[previews.vars]` (`workers/scripts/guard.mjs` fails CI), a list that includes a workers.dev host, anything secret |
| Admin Worker Access settings: `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` (code exists, nothing deployed or configured) | **no** (public, but integrity-sensitive: they decide which Access tokens the admin Worker accepts, so a changed value changes who gets in) | the admin Worker's `[vars]`, at run time | GitHub environment **variables** (not secrets) in `cloudflare-staging` and `cloudflare-production`, passed to `wrangler deploy` by `workers.yml`; empty in `workers/admin/wrangler.toml`. `ACCESS_TEAM_DOMAIN` comes from the Zero Trust dashboard, `ACCESS_AUD` from the Terraform output `admin_access_aud`. While either is empty the Worker is unconfigured and serves nothing (503) | the operator (dashboard and Terraform output) | anything secret: no key, token, bearer or password goes in either. `workers/scripts/guard.mjs` also refuses a secret-like `[vars]` name |
| Cloudflare Access JWT (`Cf-Access-Jwt-Assertion`), presented per request to the admin Worker (code exists, nothing deployed) | short-lived credential of the signed-in operator (signed by Access, valid until its own expiry claim) | the admin Worker, for the length of one request | nowhere: verified (RS256, issuer, audience, expiry, not-before, against the team's public key set from `https://<team>/cdn-cgi/access/certs`, cached an hour), then discarded | Cloudflare Access, after the operator's identity and MFA | a log (the refusal reason is logged, never the token), storage of any kind, a response body (`/api/whoami` returns only the email and expiry), a `[vars]` entry |
| Cloudflare API token for deploy (process exists, not configured) | **yes** | no | a GitHub environment secret (`CLOUDFLARE_API_TOKEN`, with `CLOUDFLARE_ACCOUNT_ID`) in `cloudflare-staging` and `cloudflare-production`, scoped to Workers Scripts edit only, readable by the deploy jobs of `workers.yml` for that environment; the owner has not created the environments or secrets, and until they exist the staging job warns and passes | the Cloudflare account owner | broader scopes (DNS, account, Access, zone); the repository; a log; a Worker; the relay key or any row above |
| Terraform state and `terraform.tfvars` (process exists, never applied) | **yes** (state can hold resource attributes and variables in plain text) | no | the operator's own encrypted, access-controlled backend (local state by default, git-ignored); `terraform.tfvars` only on the operator's machine, owner-only (git-ignored); the operator runs `terraform apply` with their own `CLOUDFLARE_API_TOKEN`, a different token from the deploy token, never in GitHub | the operator | version control (`*.tfstate`, `*.tfvars`), CI logs or artifacts, a shared or world-readable location |
| slot passphrases, PINs, vault passwords | **yes** | never | the person's memory; prompted and zeroized | the person | the relay, a file the relay reads, an environment variable |

## Where each secret enters a process

| Process | Needs | Through |
| --- | --- | --- |
| `keyquorum host serve` | relay key | `--relay-key PATH` / `KEYQUORUM_RELAY_KEY` (a path) |
| `keyquorum host keys create\|rotate` | relay key; operator lock | the same, plus `--licensee-key-file PATH` / `KEYQUORUM_LICENSEE_KEY_FILE` (then `--licensee-key`, `KEYQUORUM_LICENSEE_KEY`, a prompt) |
| `keyquorum host keys list\|events\|revoke\|checkpoint` | relay key only for `checkpoint` and to sign a revocation at once | `--relay-key PATH` |
| `keyquorum host certify\|krl\|policy issue` (offline) | provider-root private key | `--root-key PATH` / `KEYQUORUM_PROVIDER_ROOT_KEY_FILE` (then the raw `KEYQUORUM_PROVIDER_ROOT_KEY`) |
| a customer's `keyquorum loadkey --bundle` | their slot passphrase | a prompt, zeroized |
| the admin Worker (built, not deployed) | nothing secret: its Access settings are variables; it receives the operator's lock only as a request header it forwards to the Durable Object and never stores or logs | the console form's header `x-operator-lock`, one request at a time |
| the Cloudflare relay's Durable Object (built, not deployed) | relay key, certificate | Worker secrets `RELAY_PRIVATE_KEY` and `RELAY_CERTIFICATE`, set with `wrangler secret put` (`relay-deployment.md`, "Secret provisioning") |
| `workers deploy staging` / `workers deploy production` (`workers.yml`; exist, environments not configured) | Cloudflare API token (Workers Scripts edit only) and account id | GitHub environment secrets, injected into that job only; the Terraform token never enters GitHub. The admin Worker's two Access settings are not secrets and travel as GitHub environment variables |

Every file source, the relay and provider-root key files included
(`host_env::read_key_file`), is read with a bound
(`MAX_CREDENTIAL_FILE_BYTES`, 8 KiB), loses only one trailing line ending, is
held in zeroizing memory for the command's lifetime, and an error about it
names the path, never the contents (`src/cli/host_env.rs`).

## Why the relay key is not a `.kq*` file

Issue #86's bootstrap bundle works because the customer already holds the
private key that opens it. A new relay host holds no such provisioning
identity, so a relay key inside a sealed bundle would need a key to open
it, and that key would need provisioning in turn; without one, a `.kq*`
file holding the relay key would only be plaintext secret storage under a
new name. The platform's credential facility is the right carrier for the relay's own
key: an owner-only file (or a service credential file) on the native
development host, and, in the plan, a Worker secret on Cloudflare. A sealed relay-provisioning
bundle (a new `KQXB` type sealed to a dedicated host key) is a separate
design with its own wire format, not part of this deployment path.

A YubiKey cannot hold this key either: the relay signs unattended on every
request, and a hardware key needs a person's touch. The hardware options that
are feasible (a second factor on the operator lock, and, with a helper, the
offline root) are evaluated in `yubikey-evaluation.md`; none is built.
