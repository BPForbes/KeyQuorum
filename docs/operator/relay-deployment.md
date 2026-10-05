# Running a KeyQuorum relay

This is the operator runbook for the mailbox relay: the hosted deployment
on Kubernetes with MongoDB (the primary path), and a single-node deployment
on Linux with systemd and the relay's SQLite file (development, on-premises,
emergency). It is written for whoever runs the relay, not for customers;
customers get a URL and a sealed `.kqkey` and use `keyquorum loadkey`,
`send` and `inbox`, as the README describes.

Read `relay-secrets.md` next to this file first: it says which artifact is
secret, where each one lives, and where it never goes.

## The two persistence domains

KeyQuorum keeps two kinds of state, and this runbook never mixes them:

- **Customer and local state** stays in the personal or organization SQLite
  store on the person's own drive or device (`keyquorum --db ...`): their
  profile, registered keys, device placements, local topology, loaded relay
  credentials, tracked-file indexes and history. It is never migrated to the
  cloud, and the cloud database is never substituted for it. A relay that
  is handed a personal store refuses to start (`OrganizationDatabase`),
  whether that store is a SQLite file or a MongoDB database holding a
  personal store's collections.
- **Relay state** is what `src/relay/store.rs` (`RelayStore`) describes:
  API-key hashes and their audit trail, opaque sealed letters, the canonical
  public trees, public device descriptors and device letters, audit anchors,
  and whom each sealed key was issued to. It lives in the relay's own
  owner-only SQLite file (`SqliteRelayStore`) or, for the hosted relay, in
  a MongoDB replica set (`MongoRelayStore`, feature `mongodb`). Neither
  backend ever holds a raw `kq_…` bearer (only `hex(SHA-256(raw))`), a
  wrapped share, a private key, the plaintext of a letter, or the provider
  root.

Sealed KeyQuorum artifacts (`KQPB` letters, `KQXB` bundles such as
`.kqkey`) are how secrets move between principals; runtime secret injection
(systemd credentials, Kubernetes secrets) is how the relay process gets its
own key; and the provider root never leaves the offline machine. Keep those
three mechanisms apart.

## Build

```sh
# Customer binary: no host subcommand.
cargo build --release
# Single-node relay host (SQLite store).
cargo build --release --features provider
# Hosted relay (SQLite or MongoDB store, chosen at run time).
cargo build --release --features provider,mongodb
```

`--features provider` compiles the hidden `keyquorum host` command; it is a
build capability, not authorization. A relay is trusted by official clients
only when it presents a KeyQuorum-root-signed `provider.kqcert` and holds
the matching relay private key. The `mongodb` feature is the same: a
persistence backend, not a credential.

The build downloads the Swagger UI assets for `/swagger-ui` once (the
`utoipa-swagger-ui` build script). On a host without GitHub access, point
`SWAGGER_UI_DOWNLOAD_URL` at a local copy of the archive
(`file:///path/to/v5.x.y.zip`).

## Host identity

On the relay host (or the operator's workstation for the hosted relay):

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
machine. Nothing on a relay, in a container image, in a cluster or in a
database ever holds it. What crosses the air gap:

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
source you verified, root-owned and world-readable, and keep the ceremony's
record (who held the root key, when, which serial).

## Secret provisioning

The relay process needs exactly one secret to serve: its relay private key.
The MongoDB connection string is a second, when that store is used. Both
are read from **files** so that they never sit in the process environment,
a unit file, a pod spec or a shell history:

| Secret | Flag | File variable | Raw variable (compatibility) |
| --- | --- | --- | --- |
| relay private key | `--relay-key PATH` | `KEYQUORUM_RELAY_KEY` (a path) | none |
| MongoDB connection string | `--mongodb-uri-file PATH` | `KEYQUORUM_MONGODB_URI_FILE` | `KEYQUORUM_MONGODB_URI` |
| operator lock (`kql_…`, host `keys create\|rotate` only) | `--licensee-key-file PATH` | `KEYQUORUM_LICENSEE_KEY_FILE` | `--licensee-key`, `KEYQUORUM_LICENSEE_KEY`, then a prompt |
| provider root key (offline only) | `--root-key PATH` | `KEYQUORUM_PROVIDER_ROOT_KEY_FILE` | `KEYQUORUM_PROVIDER_ROOT_KEY` |

The file sources win over the raw ones. Passing both `--licensee-key` and
`--licensee-key-file` is refused rather than guessed. A credential file, and
every key file the host reads (the relay key and public key, the root key),
is read with a bound (8 KiB), only one trailing line ending is removed, the
value is zeroized when the command ends, and an error names the path, never
the contents. The connection string is never accepted as a flag value
because it may carry a password and `ps` shows flags.

**systemd (production):** encrypt the relay key once with `systemd-creds`
and let the unit decrypt it into the service's private credential directory:

```sh
systemd-creds encrypt --name=relay-key relay.key \
  /etc/credstore.encrypted/keyquorum-relay-key.cred
shred -u relay.key
```

Add `--with-key=tpm2` to bind the credential to this host's TPM. The unit
(`deploy/systemd/keyquorum-relay.service`) carries
`LoadCredentialEncrypted=relay-key:/etc/credstore.encrypted/keyquorum-relay-key.cred`
and passes `--relay-key ${CREDENTIALS_DIRECTORY}/relay-key`. The decrypted
file exists only in that directory, only for that service, and is gone when
it stops.

**systemd (development, or no `systemd-creds`):** keep `relay.key` as
`/etc/keyquorum/relay.key` (root:root 0600) and use
`LoadCredential=relay-key:/etc/keyquorum/relay.key` instead. The relay
still reads it from `$CREDENTIALS_DIRECTORY`.

**Kubernetes:** the key and the connection string are Secrets (created by
the External Secrets Operator from your secret manager, or mounted straight
from it by the Secrets Store CSI driver), mounted as files with mode 0400
into the pod; see the chart. They are never `env:` values.

**Why not environment variables for long-lived secrets:** the environment
of a process is readable by anything that can read `/proc/<pid>/environ`
(every process of the same user, and any debugger or crash dump), it is
inherited by every child process, it ends up in unit files and pod specs
that are stored and reviewed, and it is easily printed by a startup script
or a crash handler. A file with the right owner and mode, handed to one
process for its lifetime, has none of those paths.

What is **not** given to the running relay: the provider-root key (offline
only), customer bearers (the relay stores hashes; bearers travel sealed),
and the `kql_…` operator lock (only host `keys create|rotate` need it, run
by an operator, not by the service).

## State

### Single node: the relay's SQLite file

`keyquorum --mailbox-db /var/lib/keyquorum/relay.sqlite host serve ...`
creates the file owner-only (0600, journal sidecars too), refuses a file
that is a personal store, and serializes every write through one
connection. Back it up with SQLite's online backup and keep the copy
owner-only:

```sh
sqlite3 /var/lib/keyquorum/relay.sqlite ".backup /var/backups/keyquorum/relay-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
```

Test a restore: copy the backup into place, start the relay, and run
`host keys events --verify --checkpoint <newest checkpoint>`.

### Hosted: MongoDB

With a connection string configured (`--mongodb-uri-file`,
`KEYQUORUM_MONGODB_URI_FILE` or `KEYQUORUM_MONGODB_URI`), every relay
replica and every host `keys` command uses the database
`KEYQUORUM_MONGODB_DB` (`keyquorum` by default) of that deployment, and the
SQLite file is not opened at all. The database holds these collections
(`src/relay/mongo.rs`):

| Collection | Holds | Never holds |
| --- | --- | --- |
| `api_keys` | key id, `hex(SHA-256(bearer))`, scope, bound fingerprint, label, created/expires/revoked/last-used times | a bearer |
| `api_key_events` | the hash-chained lifecycle trail (created, rotated, revoked; actor `host` or `admin:<id>`) | a bearer or its hash |
| `provider_auth_events` | the hash-chained record of every mint authorization, granted or refused | a key, bearer or challenge |
| `audit_heads` | each chain's row count and head hash, advanced by compare-and-set | — |
| `audit_anchors` | relay-key signatures over chain heads with the signing certificate | the relay key |
| `counters` | the next id for keys, letters and anchors | — |
| `mailbox` | opaque `KQPB` letters by recipient fingerprint and content hash, with their expiry | an unsealed letter |
| `device_mailbox` | opaque device letters (kinds 9 to 12), each with the device TTL | a raw `KQTX` |
| `device_directory` | signed public device descriptors | a slot secret |
| `public_trees` | the canonical public tree per label (labels, thresholds, public keys, policy) as JSON | a wrapped share or private key |
| `operator_issuer` | the hash of the `kql_…` operator lock | the lock |
| `api_key_deliveries` | whom a sealed key was issued to (recipient public key, relay URL, device binding, licence, letter id or bundle digest) | a bearer or the sealed bytes |
| `schema_meta` | the layout version this build writes | — |

Collections the handoff reserved for later (`customers`, `licenses`,
`relay_instances`, `relay_assignments`) do not exist yet: nothing in the
code models a customer or a licence beyond the signed licence statement
inside a sealed key issue, and the relay has no administration API. Add
them with their own change, never by widening these.

**Requirements.** Transactions need a **replica set** (a managed deployment
such as MongoDB Atlas is one; a single `mongod` must be started with
`--replSet` and initiated). Every unit of work that writes (a push with its
trees, a key rotation with its sealed letter, grace period, delivery record
and audit event, a revocation with its event) is one multi-document
transaction with snapshot reads and majority writes, retried from the start
on a write conflict, so several replicas never commit against the same
previous state. Audit rows are chained onto the head the transaction read
and the head is advanced by compare-and-set (`audit_heads`), so two replicas
cannot append from the same previous hash; ids are allocated inside the
transaction, so a client paging with `after` never skips a letter. Each
replica also runs its own scan (purges and anchors); every step is
idempotent and an anchor for a head another replica already signed is
skipped (`audit_anchors` is unique per table and row count).

**Indexes** are created by the relay on startup (idempotently): unique
`key_hash`; unique `(recipient_fingerprint, content_hash)` on both
mailboxes; `(recipient_fingerprint, _id)` for paging; TTL indexes on
`purge_at` so an expired letter is removed by the server even between
scans; `(api_key_id, _id)`, `related_key_id` and `actor` on the events;
unique `(table_name, row_count)` on anchors. A relay user needs `readWrite`
on the database (index creation included); it needs nothing on `admin` or
`local`.

**Schema versioning.** `schema_meta` records the layout version
(`SCHEMA_VERSION`, now 1). A relay refuses a database written by a newer
build; an older layout is migrated on open by the build that introduces
the change, which also bumps the version. Roll out a schema change by
deploying the new build to all replicas; the first to start migrates, the
rest find the new version.

**Production guidance** (the operator's controls, in SOC 2 terms):

- Authentication: a dedicated database user per relay deployment, with
  `readWrite` on the relay database only; SCRAM or X.509, never an
  unauthenticated listener. The connection string carries that user and
  travels as a mounted secret file.
- TLS: `tls=true` in the connection string (`mongodb+srv://` deployments
  default to it), with the server's certificate chain trusted by the
  container's CA bundle.
- High availability: a three-member replica set across zones, or a
  managed cluster of the same shape. `w: majority` is what the relay asks
  for, so a lost member does not lose a committed key change.
- Backups: continuous backups with point-in-time recovery where the
  provider offers it (Atlas: Cloud Backup with PIT; self-managed: a
  scheduled `mongodump --oplog` plus oplog archiving). A restore must bring
  back every collection together: the audit chains and anchors only verify
  against the keys and letters they describe. After a restore, run
  `host keys events --verify --checkpoint <newest checkpoint>` against the
  restored database before serving.
- Retention: letters expire (the push's `expires_at`, and
  `DEVICE_PACKAGE_TTL_DAYS` for device letters); audit collections are
  never deleted by the relay.
- Access: whoever can write the database can rewrite everything but cannot
  forge anchors without the relay key; keep the newest checkpoint off the
  deployment (below) and restrict database administrators to the people
  the audit names.

## TLS

The relay serves plain HTTP. It refuses to bind a non-loopback address
unless `--behind-tls-proxy` says a TLS-terminating proxy forwards to it,
and official clients refuse plain HTTP to any host but loopback, so a
bearer never crosses a network in the clear:

- **Single node:** Caddy (or another proxy) listens on 443 and forwards to
  `127.0.0.1:8787`; `deploy/caddy/Caddyfile.example` is a complete example
  and explains when `--behind-tls-proxy` is needed (a relay bound to a
  non-loopback address for a proxy on another host, over a private
  network) and when it is not.
- **Kubernetes:** the Ingress terminates HTTPS (the chart leaves the
  certificate to cert-manager or your issuer) and forwards only to the
  relay Service over the cluster network; the relay is started with
  `--behind-tls-proxy` so it trusts the ingress's `X-Forwarded-For` for
  rate limiting. Keep the cluster network private, or add a service mesh
  with mTLS for that leg.

## Startup

### Single node (systemd)

1. Build and install the binary: `install -m 0755 target/release/keyquorum /usr/local/bin/keyquorum`.
2. Create the service user: `useradd --system --home /var/lib/keyquorum --shell /usr/sbin/nologin keyquorum`.
3. Install the unit, the tmpfiles entry and the settings:

   ```sh
   install -m 0644 deploy/systemd/keyquorum-relay.service /etc/systemd/system/
   install -m 0644 deploy/systemd/keyquorum-relay.tmpfiles.conf /etc/tmpfiles.d/keyquorum-relay.conf
   systemd-tmpfiles --create /etc/tmpfiles.d/keyquorum-relay.conf
   install -d -m 0755 /etc/keyquorum
   install -m 0644 provider.kqcert /etc/keyquorum/provider.kqcert
   install -m 0644 provider.kqrl /etc/keyquorum/provider.kqrl     # when one exists
   install -m 0640 -g keyquorum deploy/keyquorum-relay.env.example /etc/keyquorum/relay.env
   ```

   `/etc/keyquorum` is created here by hand, not by the tmpfiles entry,
   because it holds root-owned trust material the operator installs
   deliberately. Edit `/etc/keyquorum/relay.env` (bind address, cert and
   KRL paths, rate limit, scan interval, log level); it holds no secret.
4. Provision the relay key as a systemd credential (above).
5. `systemctl daemon-reload && systemctl enable --now keyquorum-relay`.
6. Install Caddy with `deploy/caddy/Caddyfile.example` as `/etc/caddy/Caddyfile`
   (hostname replaced) and `systemctl enable --now caddy`.

The relay logs at INFO to the journal (`journalctl -u keyquorum-relay`):
the provider id, serial and expiry it checked at startup, the store it
uses, denials by reason, purges and anchors. Never a bearer, a key hash or
a challenge.

### Hosted (Kubernetes)

1. Build and push the image: `docker build -t ghcr.io/<you>/keyquorum-relay:<tag> .`
   (the Dockerfile builds with `--features provider,mongodb` and runs as
   uid 65532 on a distroless base; the `deploy.yml` workflow checks both).
   Pin the digest in `values.yaml` (`image.digest`).
2. Create the trust ConfigMap from the files the ceremony returned:

   ```sh
   kubectl -n keyquorum create configmap keyquorum-provider \
     --from-file=provider.kqcert --from-file=provider.kqrl
   ```

3. Put the relay key and the connection string in your secret manager and
   let the External Secrets Operator (`secrets.externalSecrets.enabled`) or
   the Secrets Store CSI driver (`secrets.csi.enabled`) deliver them; or,
   for a first deployment, create the Secrets directly from files:

   ```sh
   kubectl -n keyquorum create secret generic keyquorum-relay-key --from-file=relay.key
   kubectl -n keyquorum create secret generic keyquorum-mongodb --from-file=uri=mongodb-uri.txt
   ```

   Delete the local files afterwards.
4. `helm upgrade --install relay deploy/kubernetes/keyquorum-relay --namespace keyquorum --create-namespace --set ingress.host=relay.example.com`.
5. Watch the rollout: `kubectl -n keyquorum rollout status deploy/relay-keyquorum-relay`.
   A replica becomes ready only when `/ready` succeeds, which needs the
   store to answer; the rollout keeps every existing replica until its
   replacement is ready (`maxUnavailable: 0`), and a replaced pod loses
   nothing because it held nothing.

**Rollback:** `helm rollback relay <revision>`; state is in MongoDB, so a
rollback of the image changes no data. A rollback across a schema version
is refused by the older build (it finds a newer `schema_meta`), which is
the intended protection: restore the database from before the migration if
you must run the older build.

**Minting keys for the hosted relay:** host `keys` commands need the relay
certificate, the relay key and the operator lock, and they talk to the
same MongoDB database. Run them from an operator workstation that can reach
the deployment (the same connection string file), or as a one-off
Kubernetes Job from the image with the relay key and connection string
mounted and the operator lock mounted from a Secret that exists only for
that Job; copy the `.kqkey` out with `kubectl cp` and delete the Job. The
long-running relay pods never carry the operator lock.

## Verification

- `GET /health` says the process is up. It proves nothing about the
  provider identity or the store.
- `GET /ready` says the store answered too (`{"status":"ok","store":"mongodb"}`);
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
- Audit verification, on the host (single node) or against the deployment
  (hosted):

  ```sh
  keyquorum --mailbox-db /var/lib/keyquorum/relay.sqlite host keys events --verify --krl /etc/keyquorum/provider.kqrl
  ```

  Every chain is re-walked and every relay-key anchor checked against the
  root; rows after the newest trusted anchor are "pending" until the next
  scan signs them.
- Checkpoints: on a schedule (at least daily, and after every key
  ceremony) sign the chain heads into a file and keep it **off the relay**
  in write-once storage you control:

  ```sh
  keyquorum --mailbox-db ... host keys checkpoint --out /mnt/wo/relay-$(date -u +%Y%m%dT%H%M%SZ).checkpoint \
    --cert /etc/keyquorum/provider.kqcert --relay-key ...
  keyquorum --mailbox-db ... host keys events --verify --checkpoint /mnt/wo/<newest>.checkpoint
  ```

  An anchor's `signed_at` is the signer's own word; the checkpoint is what
  bounds a backdated anchor to the time since it was taken.

## Customer API-key bootstrap

Customers never see a bearer (issue #86):

1. The customer sends the operator the X25519 encryption public key of
   their slot (`keyquorum device list` prints it) and, if the key is to be
   bound to one container, its device id.
2. The operator mints the first key sealed to that public key:

   ```sh
   keyquorum host keys create --scope inbox.pull \
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
   retrying.
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
  (replace the file; replace the ConfigMap and restart the pods) and
  restart. Clients compare the challenged relay's signing key with the one
  that signed their issue, so a renewed certificate under the same key
  changes nothing for them; cached trust entries are bound to the
  certificate expiry and refresh on their own.
- **Revocation list:** `host krl --root-key ... --serial <revoked serial>
  ... --out provider.kqrl` offline, then install it on the relay (file or
  ConfigMap) and give it to clients that pin one (`--krl`). Revoking a
  serial distrusts every audit anchor that certificate signed, which is
  the point.
- **Relay identity replacement:** generate a new keypair, have a new
  certificate issued offline, revoke the old serial, install the new key as
  a new credential (systemd) or Secret (Kubernetes), and restart. Keys
  already loaded by customers keep working: they are checked against the
  root, not against a particular relay key. Sealed issues not yet opened
  (`.kqkey` files not yet loaded, rotation letters not yet collected) were
  signed by the old key and will be refused (`KeyIssueRelayMismatch`);
  reissue them. New anchors are signed by the new key; old anchors stay
  valid for their certificate's period unless its serial is revoked.
- **Operator lock:** it has no rotation command; it is the hash in
  `operator_issuer` (`licensee_issuer` in SQLite). To replace it, stop
  minting, delete that one row or document, and run a host `keys` command:
  the empty issuer store mints a fresh lock once and prints it once. Record
  the change.
- **MongoDB user password:** rotate it in the deployment, update the
  secret, and roll the pods (the connection string file is read at
  startup).

## Incident recovery

If the relay key, the host or the database may have been compromised:

1. **Stop serving.** `systemctl stop keyquorum-relay`, or scale the
   Deployment to zero (`kubectl -n keyquorum scale deploy/... --replicas=0`).
   Leave the ingress or proxy up only if you want clients to see a clean
   failure rather than a timeout.
2. **Preserve evidence** before changing anything: the journal or pod
   logs, a copy of the relay database (SQLite file, or `mongodump` of the
   relay database), the `audit_anchors` and both event tables, and every
   checkpoint you kept off the relay. Run `host keys events --verify
   --checkpoint <newest>` on the copy and keep the output.
3. **Revoke the certificate serial** offline (`host krl`) and distribute
   `provider.kqrl`. From then on no client trusts the old key, and no
   anchor it signed counts.
4. **Generate a new relay identity** (`host identity generate`) on a clean
   host or workstation.
5. **Issue a new certificate** offline for the new key.
6. **Rotate what the relay could reach:** the MongoDB user password (hosted),
   every customer key minted while the compromise was possible (`host keys
   rotate`, sealed to each customer; a bearer itself was never on the relay,
   but a relay key can mint and seal issues), and the operator lock.
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
