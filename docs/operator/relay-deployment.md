# Running a KeyQuorum relay

This is the operator runbook for the mailbox relay. It is written for
whoever runs the relay, not for customers; customers get a URL and a sealed
`.kqkey` and use `keyquorum loadkey`, `send` and `inbox`, as the README
describes.

**Hosting status.** Cloudflare is the sole production hosting provider for
the relay. The relay that runs on Cloudflare (a Worker plus one SQLite-backed
Durable Object running `relay::service::dispatch`, with an admin Worker behind
Cloudflare Access) is **planned and not yet implemented**; the plan of record
is `relay-hosting.md` next to this file. Nothing in this repository deploys a
relay to Cloudflare yet, and this runbook does not describe a running
production deployment. What exists (stage 2) is the pipeline around a
health-only stub Worker: `workers/`, the `workers` workflow
(`.github/workflows/workers.yml`) and the Terraform in
`deploy/cloudflare/terraform/`. Stage 4a adds the admin Worker's front door
(`workers/admin/`): static operator page files on its own hostname, which sits
behind a Cloudflare Access application with MFA (Terraform,
`admin_environments`); no route bypasses Access, and the Worker verifies
Access's token itself. It only shows who is signed in, it is not connected to a
relay, and it has never been deployed or configured on a real account. The
relay uses its own dedicated Cloudflare domain, not the portfolio's. CI's `terraform validate` accepts the
Terraform, but the authors never planned or applied it against a real account,
and the owner's GitHub and Cloudflare setup (environments, secrets,
`RELAY_URL`, the `workers` required check, account, zone, domain) is not done.
No deployment has run.

What exists today is the native host, `keyquorum host serve` (feature
`provider`), backed by `SqliteRelayStore`, the relay's own owner-only SQLite
file. It is the **development, test and reference** host: run it on loopback,
or behind a TLS proxy you run yourself. It is not a supported production
deployment path, and this repository ships no unit file, container image,
chart or proxy configuration for it. The certificate ceremony, the host
`keys` commands, rotation, revocation, audit verification, checkpoints and
incident recovery below apply to it, and are the same controls the planned
Cloudflare relay is meant to keep.

Read `relay-secrets.md` next to this file first: it says which artifact is
secret, where each one lives, and where it never goes.

## The two persistence domains

KeyQuorum keeps two kinds of state, and this runbook never mixes them:

- **Customer and local state** stays in the personal or organization SQLite
  store on the person's own drive or device (`keyquorum --db ...`): their
  profile, registered keys, device placements, local topology, loaded relay
  credentials, tracked-file indexes and history. It is never migrated to the
  cloud, and a relay database is never substituted for it. A relay that is
  handed a personal store refuses to start (`OrganizationDatabase`).
- **Relay state** is what `src/relay/store.rs` (`RelayStore`) describes:
  API-key hashes and their audit trail, opaque sealed letters, the canonical
  public trees, public device descriptors and device letters, audit anchors,
  and whom each sealed key was issued to. It lives in the relay's own
  owner-only SQLite file (`SqliteRelayStore`). It never holds a raw `kq_…`
  bearer (only `hex(SHA-256(raw))`), a wrapped share, a private key, the
  plaintext of a letter, or the provider root.

Sealed KeyQuorum artifacts (`KQPB` letters, `KQXB` bundles such as
`.kqkey`) are how secrets move between principals; a credential file (for the
native host) or a Worker secret (planned, see `relay-hosting.md`) is how the
relay process gets its own key; and the provider root never leaves the
offline machine. Keep those three mechanisms apart.

## Build

```sh
# Customer binary: no host subcommand.
cargo build --release
# Native relay host (development, test, reference; SQLite store).
cargo build --release --features provider
```

`--features provider` compiles the hidden `keyquorum host` command; it is a
build capability, not authorization. A relay is trusted by official clients
only when it presents a KeyQuorum-root-signed `provider.kqcert` and holds
the matching relay private key.

The build downloads the Swagger UI assets for `/swagger-ui` once (the
`utoipa-swagger-ui` build script). On a host without GitHub access, point
`SWAGGER_UI_DOWNLOAD_URL` at a local copy of the archive
(`file:///path/to/v5.x.y.zip`).

## Host identity

On the relay host (or the operator's workstation):

```sh
keyquorum host identity generate \
  --public-key-out relay.pub --private-key-out relay.key
```

`relay.key` is created owner-only, is never overwritten and is never
printed. Only `relay.pub` leaves the host, for the certificate ceremony
below. Keep `relay.key` out of version control, shell history and tickets;
`.gitignore` already excludes `*.key`.

## Offline provider certificate issuance

The provider-root private key is KeyQuorum's and stays on an offline
machine. Nothing on a relay, on a Worker, in a CI secret, in a state file or
in a database ever holds it. What crosses the air gap:

1. **In:** the relay public key (`relay.pub`), the provider id, a serial
   you will be able to revoke later, and an expiry.
2. On the offline machine:

   ```sh
   keyquorum host certify \
     --root-key /media/root/root.key \
     --relay-public-key relay.pub \
     --provider-id "Acme Security Services" \
     --serial KQP-000184 \
     --expires-at "2027-10-01 00:00:00" \
     --out provider.kqcert
   ```

   `--root-key` names the key file (`host root generate --private-key-out`
   wrote it). `KEYQUORUM_PROVIDER_ROOT_KEY_FILE` may name it instead; the
   raw `KEYQUORUM_PROVIDER_ROOT_KEY` text variable still works for existing
   ceremonies but is not recommended, because an environment variable is
   visible to every process of that session.
3. **Out:** `provider.kqcert` returns to the relay host. A revocation list
   (`provider.kqrl`, from `host krl --serial ...`) travels the same way when
   one exists.

The certificate is public: every client reads it from
`POST /provider-identity`. It is still integrity-sensitive, because a relay
that presents a certificate for a key it does not hold fails the challenge,
and a changed certificate is simply an untrusted relay. Install it from a
source you verified and keep the ceremony's record (who held the root key,
when, which serial).

## Secret provisioning

The native host needs exactly one secret to serve: its relay private key. It
is read from a **file**, so that it never sits in the process environment, a
shell history or a unit file you wrote:

| Secret | Flag | File variable | Raw variable (compatibility) |
| --- | --- | --- | --- |
| relay private key | `--relay-key PATH` | `KEYQUORUM_RELAY_KEY` (a path) | none |
| operator lock (`kql_…`, host `keys create\|rotate` only) | `--licensee-key-file PATH` | `KEYQUORUM_LICENSEE_KEY_FILE` | `--licensee-key`, `KEYQUORUM_LICENSEE_KEY`, then a prompt |
| provider root key (offline only) | `--root-key PATH` | `KEYQUORUM_PROVIDER_ROOT_KEY_FILE` | `KEYQUORUM_PROVIDER_ROOT_KEY` |

The file sources win over the raw ones. Passing both `--licensee-key` and
`--licensee-key-file` is refused rather than guessed. A credential file, and
every key file the host reads (the relay key and public key, the root key),
is read with a bound (8 KiB), only one trailing line ending is removed, the
value is zeroized when the command ends, and an error names the path, never
the contents.

On a development host, keep `relay.key` owner-only (0600) in a directory only
the service user can read. If you run the host under systemd yourself, a
`LoadCredential=relay-key:/path/to/relay.key` line in your own unit and
`--relay-key ${CREDENTIALS_DIRECTORY}/relay-key` hand the file to the process
for its lifetime; this repository ships no unit.

**Why not environment variables for long-lived secrets:** the environment
of a process is readable by anything that can read `/proc/<pid>/environ`
(every process of the same user, and any debugger or crash dump), it is
inherited by every child process, it ends up in unit files that are stored
and reviewed, and it is easily printed by a startup script or a crash
handler. A file with the right owner and mode, handed to one process for its
lifetime, has none of those paths.

What is **not** given to a running relay: the provider-root key (offline
only), customer bearers (the relay stores hashes; bearers travel sealed),
and the `kql_…` operator lock (only host `keys create|rotate` need it, run
by an operator, not by the service).

**Planned Cloudflare relay (not yet implemented).** The plan of record
(`relay-hosting.md`) has the operator set the relay key, `provider.kqcert`
and `provider.kqrl` as Worker secrets with `wrangler secret put`, never as
GitHub secrets, and keeps the `kql_` operator lock and the provider-root
private key off any Worker. Treat that as a plan until the code exists.

## State

The relay's state is its SQLite file:

`keyquorum host --mailbox-db /var/lib/keyquorum/relay.sqlite serve ...`
creates the file owner-only (0600, journal sidecars too), refuses a file
that is a personal store, and serializes every write through one
connection. (`--mailbox-db` is the only store option `host` takes, and it
defaults to `keyquorum-relay.sqlite` in the working directory.) Back it up
with SQLite's online backup and keep the copy owner-only:

```sh
sqlite3 /var/lib/keyquorum/relay.sqlite ".backup /var/backups/keyquorum/relay-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
```

Test a restore: copy the backup into place, start the relay, and run
`host --mailbox-db ... keys events --verify --checkpoint <newest checkpoint>`.
A restore must bring back the whole file: the audit chains and anchors only
verify against the keys and letters they describe.

Retention: letters expire (the push's `expires_at`, and
`DEVICE_PACKAGE_TTL_DAYS` for device letters); the audit tables are never
deleted by the relay. Whoever can write the database can rewrite everything
but cannot forge anchors without the relay key, so keep the newest checkpoint
off the relay (below).

The `RelayStore` boundary is deliberately narrow, so that another backend can
be added without touching a rule. The planned Cloudflare relay is meant to be
such a backend (a SQLite-backed Durable Object) behind the same
`relay::service::dispatch`; it is described in `relay-hosting.md` and is not
implemented here.

## TLS

The native host serves plain HTTP. It refuses to bind a non-loopback address
unless `--behind-tls-proxy` says a TLS-terminating proxy forwards to it, and
official clients refuse plain HTTP to any host but loopback, so a bearer
never crosses a network in the clear. If you expose the dev or test host
beyond loopback, TLS is a proxy you run and configure yourself; this
repository ships none. `--behind-tls-proxy` makes the per-client rate limit
count the last `X-Forwarded-For` entry rather than the proxy's own address,
so the proxy must overwrite that header with the one address it resolved, and
the relay must stay reachable only through the proxy: the flag trusts the
header, so a directly reachable relay could be told any client address.

## Startup

Run the native host in the foreground or under a supervisor you manage:

```sh
keyquorum host --mailbox-db ./relay.sqlite serve \
  --bind 127.0.0.1:8787 \
  --cert provider.kqcert --relay-key relay.key --krl provider.kqrl
```

`--cert`, `--relay-key` and `--krl` may instead come from
`KEYQUORUM_PROVIDER_CERT`, `KEYQUORUM_RELAY_KEY` (a path) and
`KEYQUORUM_PROVIDER_KRL`; `--krl` is optional. Other flags: `--scan-db`,
`--scan-interval-seconds` (60 by default), `--behind-tls-proxy` and
`--rate-limit-per-minute` (600 by default, 0 is off).

The relay logs at INFO to stderr unless `RUST_LOG` says otherwise: the
provider id, serial and expiry it checked at startup, the store it uses,
denials by reason, purges and anchors. Never a bearer, a key hash or a
challenge. `host serve` ends gracefully on SIGINT or SIGTERM.

## Before opening a relay to customers

These apply to any host, native or the planned Cloudflare relay. What an
operator must settle for the deployment is below. None of it is a feature a
hosting vendor supplies on its own.

- **One organization per relay.** A relay does not separate customers from
  one another. Any `inbox.push` key can publish a public tree for a label,
  and the relay merges it into the stored document for that label (the
  topology it holds is public, and a letter's contents stay sealed to its
  recipient). A relay is therefore one customer's, or a group of mutually
  trusting organizations'. Per-customer namespacing and an authenticated
  publisher for tree changes are a separate design, to be done before one
  relay serves unrelated customers. `tree publish` and `inbox.push` keys
  should only go to people who may change the topology.
- **No storage quotas.** A letter without an expiry stays until it is
  collected, and nothing caps a customer's stored bytes or count. Size the
  database volume (or the platform's storage allowance) for the customers
  you issue keys to, alert on its use (`docs/soc2-controls.md`), and revoke a
  key that fills it.
- **Memory sizing.** One inbox read returns at most `MAX_INBOX_PAGE_BYTES`
  (16 MiB) of retained sealed letters in the response. The page always
  includes at least one letter (the first-letter exception), and `next_after`
  points to the next unpulled letter so the page boundary is stateless. The
  16 MiB is the sealed payload budget only: database buffers, Base64 encoding,
  JSON serialization, tree context, and concurrent requests add memory beyond
  that. The relay admits `DEFAULT_STORE_CONCURRENCY` (64) store calls at once.
  Size the host's memory for concurrent readers and their response
  serialization, and watch actual memory use under load to confirm capacity.
  The planned Cloudflare relay runs under the platform's own memory limits;
  size it against `relay-hosting.md` once it exists.
- **Licence statements are signed text.** `KeyIssue.licence` is carried and
  signed; the relay does not meter seats, suspend by subscription or
  enforce features. Revoking or letting a key expire is the control.
- **Production trust root.** Confirm that the compiled provider-root public
  key (`KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY`, `src/provider.rs`) is the key
  from your offline ceremony before you issue anything. Clients trust only
  that root.
- **Recovery.** Restore a backup into an isolated environment and verify the
  audit chains against the checkpoint for that restore point before you rely
  on it; run a synthetic client that completes the provider challenge, since
  `/ready` does not.

## Verification

- `GET /health` says the process is up. It proves nothing about the
  provider identity or the store.
- `GET /ready` says the store answered too (`{"status":"ok","store":"sqlite"}`);
  it is the readiness probe. It still proves nothing about the identity.
- The provider identity is proved only by a real client:

  ```sh
  keyquorum --db ./check.sqlite loadkey --url https://relay.example.com
  ```

  (the bearer is prompted, so it stays out of shell history). `loadkey` challenges `POST /provider-identity`, checks the certificate
  against the compiled-in KeyQuorum root (signature, expiry, capabilities,
  revocation), then calls `POST /keycheck`. A relay with the wrong key,
  an expired or revoked certificate, or another root fails here. Use a
  throwaway store and a throwaway key for the check.
- Audit verification, on the host:

  ```sh
  keyquorum host --mailbox-db /var/lib/keyquorum/relay.sqlite keys events --verify --krl provider.kqrl
  ```

  Every chain is re-walked and every relay-key anchor checked against the
  root; rows after the newest trusted anchor are "pending" until the next
  scan signs them.
- Checkpoints: on a schedule (at least daily, and after every key
  ceremony) sign the chain heads into a file and keep it **off the relay**
  in write-once storage you control:

  ```sh
  keyquorum host --mailbox-db ... keys checkpoint --out /mnt/wo/relay-$(date -u +%Y%m%dT%H%M%SZ).checkpoint \
    --cert provider.kqcert --relay-key ...
  keyquorum host --mailbox-db ... keys events --verify --checkpoint /mnt/wo/<newest>.checkpoint
  ```

  An anchor's `signed_at` is the signer's own word; the checkpoint is what
  bounds a backdated anchor to the time since it was taken.

## Customer API-key bootstrap

Customers never see a bearer (issue #86):

1. The customer sends the operator the X25519 encryption public key of
   their slot (`keyquorum device list` prints it) and, if the key is to be
   bound to one container, its device id.
2. The operator mints the first key sealed to that public key, by running
   `host keys` locally against the relay's SQLite file, with the relay
   certificate, the relay key and the operator lock to hand:

   ```sh
   keyquorum host --mailbox-db /var/lib/keyquorum/relay.sqlite keys create \
     --scope inbox.pull \
     --recipient-key <hex public key> --relay-url https://relay.example.com \
     --out acme.kqkey --licensee-key-file /run/user/1000/kq-lock \
     --cert provider.kqcert --relay-key relay.key --krl provider.kqrl
   ```

   The bearer is minted, sealed to the customer's key and signed by the
   relay key in one unit of work, written as a `KQXB` bundle (`.kqkey`,
   owner-only, never overwritten) and never printed. The file is outside
   the database transaction: a failed mint the process survives removes it,
   but a crash between the write and the commit can leave an orphan bundle
   that opens nothing (the key was never created); remove it before
   retrying. The long-running relay never carries the operator lock.
3. The customer loads it: `keyquorum loadkey --url https://relay.example.com --bundle acme.kqkey --slot ./usb=M.S`.
   The issue's relay URL must be the one being loaded for, a device-bound
   issue loads only from that container, the full provider challenge runs,
   and the relay that answers must be the one whose key signed the issue.
4. A later rotation (`host keys rotate <id>`) stores the replacement as a
   sealed `KQPB` letter (kind 20) in the customer's mailbox when they can
   collect it (an `inbox.pull` key, or any key whose recipient holds a live
   one); the old key stays usable for `--grace-seconds` (24 h by default)
   and then expires. `keys rotate --out` writes a bundle instead and revokes
   the old key at once. The customer's next `keyquorum inbox open` loads the
   letter.

For the planned Cloudflare relay, minting and rotation are meant to go
through an admin Worker behind Cloudflare Access, never over the public
Worker and never by a customer (`relay-hosting.md`). The admin Worker's front
door exists (it checks Access's token itself and answers every `/api` route but
`/api/whoami` with 503); the minting and rotation routes are not implemented.

Do not copy plaintext `kq_…` bearers between people. The unsealed path
(`keys create` without `--recipient-key`, which prints the bearer once) is
kept only for keys that were never sealed to anyone; treat it as legacy.

## Rotation and revocation

- **Customer bearer:** `host keys rotate <id>` as above; `host keys revoke
  <id>` ends a key now (an admin key can also revoke over HTTP, and the
  relay signs the revocation into the audit chain at once). Every change is
  an `api_key_events` row.
- **Provider certificate renewal:** issue a new certificate for the **same**
  relay key before the old one expires (the serial changes), install it
  (replace the file) and restart. Clients compare the challenged relay's
  signing key with the one that signed their issue, so a renewed certificate
  under the same key changes nothing for them; cached trust entries are bound
  to the certificate expiry and refresh on their own.
- **Revocation list:** `host krl --root-key ... --serial <revoked serial>
  ... --out provider.kqrl` offline, then install it on the relay and give it
  to clients that pin one (`--krl`). Revoking a serial distrusts every audit
  anchor that certificate signed, which is the point.
- **Relay identity replacement:** generate a new keypair, have a new
  certificate issued offline, revoke the old serial, install the new key as
  the relay's credential file, and restart. Keys already loaded by customers
  keep working: they are checked against the root, not against a particular
  relay key. Sealed issues not yet opened (`.kqkey` files not yet loaded,
  rotation letters not yet collected) were signed by the old key and will be
  refused (`KeyIssueRelayMismatch`); reissue them. New anchors are signed by
  the new key; old anchors stay valid for their certificate's period unless
  its serial is revoked.
- **Operator lock:** it has no rotation command; it is the hash in
  `licensee_issuer` in the relay's SQLite file. To replace it, stop minting,
  delete that one row, and run a host `keys` command: the empty issuer store
  mints a fresh lock once and prints it once. Record the change.

## Incident recovery

If the relay key, the host or the database may have been compromised:

1. **Stop serving.** Stop the `keyquorum host serve` process (or the
   supervisor running it). Leave any proxy in front up only if you want
   clients to see a clean failure rather than a timeout.
2. **Preserve evidence** before changing anything: the host's logs, a copy of
   the relay database (the SQLite file), the `audit_anchors` and both event
   tables, and every checkpoint you kept off the relay. Run `host keys events
   --verify --checkpoint <newest>` on the copy and keep the output.
3. **Revoke the certificate serial** offline (`host krl`) and distribute
   `provider.kqrl`. From then on no client trusts the old key, and no
   anchor it signed counts.
4. **Generate a new relay identity** (`host identity generate`) on a clean
   host or workstation.
5. **Issue a new certificate** offline for the new key.
6. **Rotate what the relay could reach:** every customer key minted while the
   compromise was possible (`host keys rotate`, sealed to each customer; a
   bearer itself was never on the relay, but a relay key can mint and seal
   issues), and the operator lock.
7. **Restore state only after the identity is corrected:** reinstall the new
   key and certificate, verify the database against the newest checkpoint,
   and only then start the relay. If the database cannot be trusted,
   restore from a backup taken before the incident and verify that against
   its contemporary checkpoint.
8. **Record** what was done, in the audit log of `docs/soc2-controls.md`.

What the code can and cannot give you here: the audit chain proves what
was anchored by a trusted key within its certificate's period; the
checkpoint bounds backdating to the time since it was taken; a leaked relay
key can sign anchors and mint keys until its serial is revoked; and a
customer's loaded bearer is in their own store, not on the relay. There is
no remote kill switch for a running relay other than revoking its serial.
