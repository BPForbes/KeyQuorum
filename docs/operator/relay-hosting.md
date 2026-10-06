# Hosting the KeyQuorum relay: AWS, Cloudflare edge, Cloudflare Workers

This is the hosting plan and decision record for issue #88. It compares
three ways to run the mailbox relay, records the AWS design for the first
controlled deployment, specifies the Cloudflare edge design for when one is
wanted, assesses a Cloudflare Workers port, and revalidates the launch
prerequisites from the architecture review of PR #87 against the code as it
is today. It is written for whoever operates the relay, next to
`relay-deployment.md` (how to run it) and `relay-secrets.md` (what is
secret). It is not customer-facing.

Status at the time of writing (2026-10-06):

| Item | State |
| --- | --- |
| Hosting decision | **AWS EC2, native relay, SQLite on encrypted EBS** for the first controlled deployment. |
| Cloudflare edge (Path A) | **Specified, optional.** Add it for DDoS absorption, edge rate limits and Cloudflare Access on the operator paths; not required to launch. |
| Cloudflare Workers (Path B) | **Deferred.** The reasons and the follow-up scope are in [Path B](#path-b-cloudflare-workers-hosting-feasibility). |
| Live deployment, restore test, overload test | **Not done.** They need the operator's AWS account and run against a real instance; the [acceptance checklist](#acceptance-checklist) says which rows this document settles and which the deployment must. |

Nothing here is deployment approval, and no SOC 2 mapping below claims
compliance; `docs/soc2-controls.md` says what the software provides and
what the operator must still do.

## Sources

The review rules ask for a quoted source behind each requirement. The
container this plan was written in could not fetch `docs.aws.amazon.com`,
`developers.cloudflare.com` or `sqlite.org` directly (the egress proxy
refused them), so each source below is marked by how it was read:

- **verbatim (issue #88):** the sentence is carried word for word from
  issue #88, which quoted it from the page named.
- **search summary:** the page was found and summarised by a web search on
  2026-10-06; the wording in this document is a paraphrase of that summary,
  not a quotation. Re-read the page before relying on a number.
- **not retrieved:** named for the reader; nothing in this document rests on
  it alone.

| Source | URL | Read as |
| --- | --- | --- |
| AWS, EC2 User Guide: "An EC2 instance is a virtual server in the AWS Cloud." | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ | verbatim (issue #88) |
| AWS, EBS volumes "persist independently from the instance." | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/storage_ebs.html | verbatim (issue #88) |
| AWS, Amazon EBS encryption: encryption operations happen on the servers that host EC2 instances, protecting data at rest and in transit between an instance and its volume; snapshots of encrypted volumes are encrypted; keys come from AWS KMS; encryption by default can be turned on per account and Region. | https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html | search summary |
| AWS, preserving volumes on termination: a root volume attached at launch is deleted on termination by default; a data volume attached after launch is preserved by default; `DeleteOnTermination` can be set at launch. | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/preserving-volumes-on-termination.html | search summary |
| AWS, Systems Manager Session Manager: node access without opening inbound ports, maintaining bastion hosts or managing SSH keys; sessions can be logged. | https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html | search summary |
| AWS, EC2 on-demand prices, us-east-1 (third-party price tables citing AWS): t4g.small about $0.0168/h, m7g.medium about $0.0408/h. | https://aws.amazon.com/ec2/pricing/on-demand/ | search summary (third-party tables); verify on the AWS page |
| SQLite, "How To Corrupt An SQLite Database File", section on file locking: SQLite relies on the filesystem's locks, and some filesystems, network filesystems and NFS in particular, do not implement them correctly, so concurrent access can corrupt the database. | https://www.sqlite.org/howtocorrupt.html | search summary |
| Cloudflare, WebAssembly: "You can use WebAssembly to … write an entire Cloudflare Worker in Rust." | https://developers.cloudflare.com/workers/runtime-apis/webassembly/ | verbatim (issue #88) |
| Cloudflare, Tunnel: "outbound-only" connections, an origin "without a publicly routable IP address". | https://developers.cloudflare.com/learning-paths/prevent-ddos-attacks/advanced/prevent-external-connections/ | verbatim (issue #88) |
| Cloudflare, Tunnel overview: `cloudflared` opens outbound-only connections from the origin to Cloudflare's network; the firewall can then block all inbound traffic. | https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/ | search summary |
| Cloudflare, Full (strict): "With an encryption mode of Full (strict), your application encrypts traffic going to and coming from Cloudflare." | https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/ | verbatim (issue #88) |
| Cloudflare, Authenticated Origin Pulls: the origin verifies a Cloudflare client certificate so requests must come through Cloudflare; the global certificate only proves "from Cloudflare's network", not "from your zone", so use a zone or per-hostname certificate for stricter checks. | https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/ | search summary |
| Cloudflare, default cache behaviour: with Origin Cache Control on (the default on Free, Pro and Business), a request carrying `Authorization` is not cached unless the response's `Cache-Control` says `public`, `s-maxage` or `must-revalidate`. | https://developers.cloudflare.com/cache/concepts/default-cache-behavior/ | search summary |
| Cloudflare, HTTP request headers: `CF-Connecting-IP` holds the one connecting client address; `X-Forwarded-For` is appended to, so it may begin with whatever the client sent. | https://developers.cloudflare.com/fundamentals/reference/http-headers/ | search summary |
| Cloudflare, error 524: the origin did not answer within the default 100 s proxy read timeout; Enterprise can raise it. | https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524/ | search summary |
| Cloudflare, Workers limits: request body 100 MB on Free and Pro, 200 MB Business, 500 MB Enterprise; CPU time 10 ms per request on Free, 30 s by default (up to 5 min) on Paid. | https://developers.cloudflare.com/workers/platform/limits/ | search summary |
| Cloudflare, Rust on Workers: every crate must build for `wasm32-unknown-unknown`; threaded runtimes such as tokio are not supported (runtime-agnostic pieces like `tokio::sync` are); an Emscripten target with Tokio support exists as an experimental preview. | https://developers.cloudflare.com/workers/languages/rust/ | search summary |
| Cloudflare, Durable Objects limits: a SQLite-backed Durable Object holds up to 10 GB; a row, string or blob at most 2 MB; writes past the limit fail with `SQLITE_FULL`. | https://developers.cloudflare.com/durable-objects/platform/limits/ | search summary |
| Cloudflare, Durable Objects SQLite storage API | https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/ | not retrieved (named in issue #88) |
| Cloudflare Access, self-hosted applications and policies: a policy can require MFA in addition to the identity provider. | https://developers.cloudflare.com/cloudflare-one/access-controls/policies/common-policies/ | search summary |
| AICPA, 2017 Trust Services Criteria (2022 points of focus), A1.3: "The entity tests recovery plan procedures supporting system recovery to meet its objectives." | https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 | verbatim (issue #88) |

Code cited below was read in this repository at the commit this document
was written in; the file and item are named each time.

## The decision

**Run the native relay on AWS EC2 first.** The relay is a Tokio and axum
server (`src/bin/keyquorum/host.rs`, `serve`, starts it with `axum::serve`)
over `RelayStore` (`src/relay/store.rs`), whose reference backend is one
SQLite file behind one connection (`SqliteRelayStore`). A virtual machine
runs that as it is: no runtime port, no second persistence backend, and the
`SqliteRelayStore` conformance suite already covers the store it will use.
The Kubernetes and MongoDB path in `relay-deployment.md` stays the hosted
multi-replica option for later.

| | AWS EC2, native relay | Cloudflare edge in front of EC2 (Path A) | Cloudflare Workers (Path B) |
| --- | --- | --- | --- |
| Code change | None. | None in the relay; proxy and tunnel configuration. | A new runtime adapter and a new `RelayStore` backend; see Path B. |
| Where the relay and its database run | One EC2 instance, SQLite on an encrypted EBS volume. | The same instance; Cloudflare in front. | Cloudflare's network; state in Durable Objects. |
| Operational ownership | The operator: OS, Caddy, relay, backups, restores. | Same, plus a Cloudflare account, DNS at Cloudflare, a tunnel to keep alive. | Cloudflare runs the platform; the operator owns the Worker, the Durable Object data, backups and migrations. |
| Limits that matter | Instance size and EBS throughput; one process, one database. | Edge body limit (100 MB on Free and Pro) and 100 s read timeout, both above the relay's own 2 MiB and 30 s; Access seats. | 10 GB per Durable Object; 2 MB per row (a letter is at most 1 MiB); CPU time per request; no tokio. |
| Estimated monthly cost (compute only, before support, data transfer and backups; see each section) | about $12 (t4g.small) to $30 (m7g.medium) plus EBS and snapshots. | Same, plus $0 on the Free plan for proxy, Tunnel and up to the free Access seats, or the paid plan the operator chooses. | A Workers Paid subscription plus Durable Objects storage and requests; not estimated until the port exists. |
| Implementation effort | Days: provisioning, hardening, backup and restore drills. | One or two days on top. | Weeks: adapter, store, conformance, custody, migration; see Path B. |
| Decision | **Adopt.** | **Specified; adopt when its controls are wanted.** | **Defer.** |

## AWS design (adopted)

Every value here is a design choice to be confirmed when the account is
set up; the ones that depend on the customer base (instance size, volume
size, alert thresholds) are starting points, not measurements.

### Region and instance

- **Region:** the region where the customers and the operator are, with
  the compliance scope the operator needs. Pick one and record it; the
  relay has no cross-region feature to use.
- **Instance:** one ARM instance. The relay is a single process with one
  SQLite writer and the blocking pool of `DEFAULT_STORE_CONCURRENCY` (64)
  store operations (`src/relay/server.rs`); it is bound by memory for
  concurrent inbox pages (each at most `MAX_INBOX_PAGE_BYTES`, 16 MiB of
  sealed bytes, `src/relay/mailbox.rs`) more than by CPU. Start with
  `t4g.small` (2 vCPU, 2 GiB) for a pilot of a few organizations, or
  `m7g.medium` (1 vCPU, 4 GiB) when steady traffic is expected; the
  on-demand prices found were about $0.0168/h and $0.0408/h in us-east-1,
  that is roughly $12 and $30 a month before storage, transfer and support.
  Verify on the AWS pricing page when ordering.
- **Expected load:** a customer's `keyquorum inbox` pull is one `GET /inbox`
  page and one `POST /provider-identity` challenge; a `send` is one
  `POST /inbox`. Budget by requests per customer per day, and size the
  volume by retained letters: a letter without `--expires` stays until it is
  collected (`relay-deployment.md`, "No storage quotas").

### Storage: SQLite on encrypted EBS

- One `gp3` data volume, separate from the root volume, mounted at
  `/var/lib/keyquorum`, holding `relay.sqlite` and its journal. Start at
  20 GiB; `gp3` can be grown without downtime.
- **Encrypted** with a customer-managed KMS key (so key policy and rotation
  are the operator's), and account-level EBS encryption by default turned
  on so no unencrypted volume or snapshot can be created by mistake. EBS
  encryption covers the volume at rest, the path between the instance and
  the volume, and every snapshot of it (AWS, EBS encryption, search
  summary).
- **Local block storage only.** The relay's SQLite file must never sit on a
  network filesystem: SQLite depends on the filesystem's locks, and network
  filesystems, NFS in particular, are the ones whose locking is known to be
  wrong (SQLite, "How To Corrupt", search summary). EBS is a block device
  attached to one instance, which is what SQLite expects.
- **Retention on termination:** set `DeleteOnTermination=false` on the data
  volume at launch (a data volume attached after launch is preserved by
  default; a volume attached at launch via the CLI is not, so set it
  explicitly; AWS, search summary). Enable termination protection on the
  instance. A terminated instance then leaves its database to be
  re-attached to a replacement.
- **Ownership on disk:** the relay opens its database owner-only (0600,
  journal sidecars too; `src/relay/mod.rs`, `open`), and the systemd unit
  (`deploy/systemd/keyquorum-relay.service`) runs it as the `keyquorum`
  user with `UMask=0077` and a read-only system except `/var/lib/keyquorum`.

### Network, DNS, TLS

- **Security group:** inbound 443/tcp from the internet (or only from
  Cloudflare's ranges under Path A), nothing else inbound; no 22/tcp at
  all (administration is Session Manager, below). Outbound: 443 to the
  package repositories, Let's Encrypt and AWS endpoints; cloudflared's
  outbound connections under Path A.
- **Relay binding:** the relay binds `127.0.0.1:8787` and is started with
  `--behind-tls-proxy` by the unit; it refuses a non-loopback bind without
  that flag (`src/relay/server.rs`, `check_bind`). Caddy
  (`deploy/caddy/Caddyfile.example`) listens on 443, obtains and renews the
  certificate from Let's Encrypt on its own, and forwards to loopback with
  `X-Forwarded-For` overwritten to the one client address it resolved.
- **DNS:** an `A`/`AAAA` record for `relay.example.com` to the instance's
  Elastic IP, at the registrar or Route 53. Under Path A the record is
  proxied at Cloudflare instead (see there).
- **Certificate renewal:** Caddy's, automatic; alert on the certificate's
  days-to-expiry from outside (below) so a renewal that stops is noticed.

### Administration: private, MFA, no SSH

- **Session Manager** for shell access: no inbound port, no bastion, no SSH
  key to manage, and every session logged to CloudWatch Logs or S3 (AWS,
  Session Manager, search summary). The instance profile needs only the
  SSM managed policy; the operator's IAM identity needs
  `ssm:StartSession` on this instance and MFA enforced by the account's
  IAM policy (`aws:MultiFactorAuthPresent`).
- **Operator commands** (`host keys create|rotate`, `host keys checkpoint`,
  `host keys events --verify`) run in such a session, with the operator lock
  read from a file the operator brings for that session and removes after
  (`relay-secrets.md`). The lock never lives on the instance.
- **The operator console** (`/console/`, `relay-deployment.md`, "Operator
  console") is reached over the proxy's TLS from operator addresses only,
  or through Cloudflare Access under Path A. It needs an admin key and can
  list, revoke and read the audit trail; it cannot mint.

### IAM: least privilege by role

| Role | Who | Allowed | Not allowed |
| --- | --- | --- | --- |
| Deploy | the operator's deployment identity (a person with MFA, or a CI role with OIDC) | launch and replace the instance, attach the data volume, write the security group, upload the binary | read the data volume's snapshots, use the KMS key for decrypt |
| Operate | the operator's day-to-day identity (MFA) | `ssm:StartSession` on this instance, read CloudWatch logs and alarms | change IAM, change the KMS key policy, delete snapshots |
| Backup | the instance profile | `ec2:CreateSnapshot` on its own data volume, `s3:PutObject` into the checkpoint bucket's prefix (write-once, see below) | `s3:DeleteObject`, `s3:GetObject` on other prefixes |
| Restore | a separate identity used in the restore drill | create a volume from a snapshot into the isolated test VPC, decrypt with the KMS key | reach the production instance |

Record each role's policy document with the deployment; `docs/soc2-controls.md`,
"Operator responsibilities", names these as the operator's controls.

### Install, start, upgrade, roll back, shut down

- **Install and start:** `relay-deployment.md`, "Startup, single node
  (systemd)". The binary is built with `--features provider` after
  `relay-console/` is built, so the console is embedded (`build.rs`); the
  unit decrypts the relay key from `systemd-creds` into the service's
  private credential directory and never into the environment.
- **Upgrade:** build the new binary, `install -m 0755` it next to the old
  one under a versioned name, switch the symlink `/usr/local/bin/keyquorum`,
  `systemctl restart keyquorum-relay`. The relay refuses a database written
  by a newer `SCHEMA_VERSION`, so a downgrade across a schema change is
  caught at startup rather than corrupting the file (`src/relay/store.rs`).
- **Roll back:** switch the symlink back and restart. Across a schema
  migration, restore the pre-upgrade snapshot first (below).
- **Shut down:** `systemctl stop keyquorum-relay`. systemd sends SIGTERM;
  the relay stops accepting connections and lets in-flight requests finish
  (`host.rs`, `shutdown_signal`, listens for SIGTERM and SIGINT; the unit
  allows `TimeoutStopSec=30s`, the relay's own request timeout). A store
  operation that already started runs to completion on the blocking pool
  (`src/relay/server.rs`, `run_blocking`: the admission permit is held until
  the call returns), so a stop does not leave a half-written unit of work:
  every write is one SQLite transaction. There is no queue to drain.

## Provider-only issuance on every path

The hosting platform does not decide who can mint. These do, on EC2, behind
Cloudflare, or in a Worker alike:

- **The provider-root private key stays offline.** `host certify`, `host
  krl` and `host policy issue` are run on the offline machine
  (`relay-deployment.md`, "Offline provider certificate issuance"); nothing
  on the instance holds it. The compiled-in root public key
  (`src/provider.rs`, `KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY`) must be replaced
  with the key from that ceremony before any production credential is
  issued, and that replacement recorded.
- **The relay identity key** is the only secret the running relay has. On
  EC2 it is a systemd encrypted credential (optionally TPM-bound); its file
  is never in the unit, the environment or a log (`relay-secrets.md`).
- **The operator lock (`kql_…`)** is separate from the relay service: `host
  keys create|rotate` read it from `--licensee-key-file` on the operator's
  session (`src/cli/host_env.rs`), never from the running relay's files.
  Bootstrap it before the first customer key, in a recorded ceremony:
  `host keys` on an empty issuer store mints and prints it once.
- **No public minting endpoint.** The HTTP API lists and revokes keys and
  nothing more (`src/relay/server.rs`, `router`: `GET /api-keys`, `POST
  /api-keys/{id}/revoke`; there is no create or rotate route), which
  `src/relay/server/tests.rs` (`router_enforces_scopes_and_returns_opaque_bytes`)
  pins. The console drives the same routes (`src/relay/console.rs`).
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
| RPO | 1 hour (snapshot interval), 24 hours for the audit checkpoint | letters are re-sendable by their senders (`outbox send`), keys re-issuable; the audit trail is what must not be lost |
| RTO | 2 hours | re-attach or restore the volume to a replacement instance from the same AMI; no cluster to rebuild |

### Backups

- **EBS snapshots** of the data volume, hourly, kept 7 days (daily kept 90),
  by Amazon Data Lifecycle Manager under the Backup role. A snapshot of an
  encrypted volume is encrypted under the same key. A crash-consistent
  snapshot of a SQLite file in WAL or rollback-journal mode is recoverable
  by SQLite on open; for a known-good copy also take SQLite's online backup
  (`sqlite3 relay.sqlite ".backup /var/lib/keyquorum/backup/relay-<ts>.sqlite"`)
  before each snapshot, as `docs/soc2-controls.md` asks, and keep that copy
  owner-only.
- **Audit checkpoints** (`host keys checkpoint --out FILE`) at least daily
  and after every key ceremony, copied to an S3 bucket with Object Lock
  (write-once) that the Backup role can only write; `host keys events
  --verify --checkpoint <newest>` is what bounds a backdated anchor
  (`relay-deployment.md`, "Verification").
- Copy snapshots to a second region only if the operator's objectives need
  it; the relay has no multi-region feature.

### Restoration drill (A1.3)

Before launch and then on a schedule:

1. Create a volume from a snapshot into an **isolated** VPC with no route to
   production and no customer DNS pointing at it.
2. Never give the restored copy the production relay key: an instance that
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
5. Record the drill: snapshot id, restore time, verification output,
   discrepancies, time to serve.

### Alerts

| Signal | Source | Threshold |
| --- | --- | --- |
| health and readiness | an external probe of `GET /health` and `GET /ready` over the public hostname | 3 failures in a row |
| provider identity | a synthetic client that runs `keyquorum loadkey` with a throwaway store and key (only this proves the identity; `/ready` does not) | daily, any failure |
| certificate expiry | the external probe's TLS check, and the relay's own `provider identity … expires` startup line | 30 days before either |
| storage | CloudWatch disk-used on `/var/lib/keyquorum` | 70 % warn, 85 % page |
| audit verification | `host keys events --verify --checkpoint` on a schedule, output kept | any row not "ok" or "pending" |
| denials and rate limits | the journal: `relay authentication denied`, `relay scope denied`, `relay rate limit exceeded` (`src/relay/service.rs`, `src/relay/server.rs`) | a sustained rise |

### Incident response and key compromise

`relay-deployment.md`, "Incident recovery", is the procedure: stop serving,
preserve evidence, revoke the certificate serial offline, issue a new relay
identity, rotate every customer key minted while the compromise was
possible, verify the chains against the checkpoints kept off the host.
Record who did each step and when.

## Launch prerequisites, revalidated

Each concern from the PR #87 review, checked against the code now:

| Concern | State in the code | Decision for launch |
| --- | --- | --- |
| Tree-level authorization and customer isolation | **Open.** Any `inbox.push` key may publish a public tree for a label and the relay merges it (`src/relay/service.rs`, `inbox_push`; `src/relay/org_tree.rs`, `merge_into_existing`); letters stay sealed to their recipient, but the public topology is shared. | **Scope decision:** one organization (or one group of mutually trusting organizations) per relay, as `relay-deployment.md`, "Before opening a relay to customers", states. Per-customer namespacing and an authenticated tree publisher are a separate design before a shared relay. |
| Byte-bounded inbox responses | **Done.** `MAX_INBOX_PAGE_BYTES` (16 MiB) in `src/relay/mailbox.rs`, `bound_page`, shared by both backends; at least one letter per page, `next_after` stateless. | Size memory for concurrent pages (the chart's 512 MiB note applies to the instance too). |
| Bounded database admission | **Done.** `DEFAULT_STORE_CONCURRENCY` (64) and `STORE_ADMISSION_WAIT` (5 s, then 503) in `src/relay/server.rs`, two separate slots for `/ready`; the permit is held until the store call returns. | Keep; measure under the overload test. |
| Provider-controlled retention and storage quotas | **Partly.** Letters expire when pushed with `--expires`, device letters after `DEVICE_PACKAGE_TTL_DAYS` (30, `src/relay/device_mail.rs`), and the scan purges both; nothing caps a customer's stored bytes or count. | **Scope decision:** alert on volume use (above) and revoke a key that fills it; a per-key quota is a follow-up. |
| Trusted client-IP handling through the proxy chain | **Done for one trusted proxy.** The relay trusts only the last `X-Forwarded-For` entry and only with `--behind-tls-proxy` (`src/relay/server.rs`, `RateLimiter::client`; test `behind_a_proxy_the_last_forwarded_address_is_the_client`); Caddy overwrites the header with the one address it resolved. Behind Cloudflare the chain is longer: see Path A. | Test forged headers and direct-origin access at deployment (Path A lists the commands). |
| Recoverable key issuance when a transaction outcome is indeterminate (MongoDB) | **Done for MongoDB:** `Error::StoreCommitUnknown` keeps the sealed `.kqkey` and tells the operator to check `keys list` and `keys events` before retrying (`src/relay/mongo.rs`, `src/bin/keyquorum/host.rs`). **SQLite:** a bundle is written while the transaction is open; a crash between the write and the commit can leave an orphan that opens nothing (`src/relay/key_delivery.rs`). | Not needed for the SQLite launch; the runbook already says to remove an orphan bundle before retrying. |
| SIGTERM handling (container hosting) | **Done.** `host.rs`, `shutdown_signal`: SIGTERM and SIGINT end `axum::serve` gracefully. | Applies to systemd too (`TimeoutStopSec=30s`). |

## Path A: Cloudflare edge with a native relay origin

The relay and its database stay on the EC2 instance; Cloudflare sits in
front for DDoS absorption, edge rate limits and Cloudflare Access on the
operator paths. This is a proxy deployment, not Workers hosting.

### Two ways to reach the origin

- **Proxied DNS with a public origin.** The `A` record is proxied (orange
  cloud). The origin keeps 443 open, but its security group admits only
  Cloudflare's published ranges, and Caddy additionally verifies a
  Cloudflare client certificate (Authenticated Origin Pulls, with a zone or
  per-hostname certificate, since the global one only proves "from
  Cloudflare's network"; Cloudflare, search summary). Full (strict) means
  Cloudflare encrypts to the origin and checks the origin's certificate; it
  does not by itself stop someone who knows the origin IP from connecting
  directly, which is what the security group and AOP are for.
- **Cloudflare Tunnel.** `cloudflared` runs on the instance and opens
  outbound-only connections to Cloudflare, so the origin needs no publicly
  routable address and no inbound port at all (Cloudflare, Tunnel, verbatim
  and search summary). `deploy/cloudflare/cloudflared-config.example.yml`
  is the configuration: it forwards to Caddy's loopback listener, never
  straight to the relay, so Caddy still decides the client address and
  restricts `/console/`. Prefer the tunnel for a new deployment: it removes
  the direct-origin problem instead of mitigating it.

### TLS and certificates

- Encryption mode **Full (strict)**. With a public origin, Caddy presents a
  publicly trusted certificate (Let's Encrypt) or a Cloudflare origin CA
  certificate; with a tunnel, the leg from `cloudflared` to Caddy is on
  loopback and the tunnel itself is TLS to Cloudflare.
- The customer-facing certificate is Cloudflare's edge certificate; its
  renewal is Cloudflare's. The origin certificate's renewal stays Caddy's;
  alert on both expiries.
- Nothing changes for KeyQuorum's own trust: clients verify the relay by the
  provider challenge over whatever TLS is in front (`src/relay/client.rs`,
  `authenticate_provider`), so a Cloudflare edge cannot impersonate a relay
  without its signing key.

### DNS and the proxy chain

Client → Cloudflare edge → (tunnel or AOP) → Caddy → relay on loopback.

The client identity must be taken only from the immediate authorized peer
at each hop:

- Cloudflare sets `CF-Connecting-IP` to the one connecting client address
  and **appends** to `X-Forwarded-For`, which may therefore begin with
  values the client sent (Cloudflare, HTTP headers, search summary).
- Caddy must trust Cloudflare's ranges only (`trusted_proxies`, with the
  Cloudflare IP module or static ranges) and take the client from
  `CF-Connecting-IP` (`client_ip_headers CF-Connecting-IP`), then overwrite
  `X-Forwarded-For` with that single `{client_ip}` for the relay, as the
  Caddyfile's comment already says. With a tunnel, Caddy's trusted proxy is
  loopback (`cloudflared`), and the headers it forwards came from Cloudflare.
- The relay reads the last `X-Forwarded-For` entry only
  (`RateLimiter::client`), which is now the one Caddy wrote.

A Caddy site block for this chain (the rest as in
`deploy/caddy/Caddyfile.example`):

```caddyfile
{
	servers {
		trusted_proxies static 127.0.0.1/8 ::1   # the tunnel; or Cloudflare's ranges for a public origin
		client_ip_headers CF-Connecting-IP
	}
}

http://relay.example.com:8080 {           # the tunnel's loopback target; https:// with AOP for a public origin
	request_body {
		max_size 3MB
	}
	reverse_proxy 127.0.0.1:8787 {
		header_up X-Forwarded-For {client_ip}
	}
}
```

**Tests at deployment** (record the output with the deployment):

```sh
# Forged forwarding headers are not believed: the relay's limiter must
# count these against the real client, so 600 of them from one address
# still end in a 429 (set --rate-limit-per-minute low for the test).
curl -sS -H 'X-Forwarded-For: 203.0.113.9' -H 'CF-Connecting-IP: 203.0.113.9' https://relay.example.com/health
# Direct origin access is refused (public origin: connection refused or a
# TLS client-certificate failure; tunnel: no listener at all).
curl -sS --connect-timeout 5 https://<origin-ip>/health --resolve relay.example.com:443:<origin-ip>
# The provider challenge still passes through the edge.
keyquorum --db ./check.sqlite loadkey --url https://relay.example.com
```

### Cache

Authenticated relay responses must never enter a shared cache. By default
Cloudflare does not cache a response to a request carrying `Authorization`
unless the response's `Cache-Control` opts in (search summary), and the
relay's JSON is not a cacheable file type by default. Do not rely on
defaults alone: add a cache rule that **bypasses cache for the whole
hostname** except `/console/assets/*` (the console's hashed bundle, served
`immutable`, which carries no data), and confirm with `cf-cache-status:
DYNAMIC` or `BYPASS` on `GET /inbox`, `GET /api-keys` and `POST
/provider-identity` responses. Sealed letters, key metadata and recipient
fingerprints must show `BYPASS`.

### Limits against the protocol

| Limit | Cloudflare | Relay | Fit |
| --- | --- | --- | --- |
| request body | 100 MB (Free, Pro), 200 MB (Business), 500 MB (Enterprise) | 1 MiB per envelope, 2 MiB per request (`MAX_ENVELOPE_BYTES`) | fine on any plan |
| response | not a plan limit for a non-cached response | an inbox page is at most 16 MiB of sealed bytes plus encoding | fine |
| timeout | 100 s proxy read timeout (524), Enterprise can raise | 30 s (`REQUEST_TIMEOUT`, answered 408) | the relay's 408 arrives first; keep the tunnel's keep-alive below 100 s |
| WebSockets, HTTP/2 | not used by the relay | | |

### Rate limits, layered

Edge rate-limiting rules (per IP on `/inbox`, `/keycheck`, `/provider-identity`)
absorb floods before the origin; the relay's per-client limiter
(`--rate-limit-per-minute`, keyed by the client Caddy named) still applies
per bearer holder; the admission pool bounds the database; the storage
alert bounds retention. None replaces another.

### Private operator access

Put `/console/*`, `/api-keys*`, `/audit/*` and `/swagger-ui/*` behind a
**Cloudflare Access** self-hosted application whose policy requires the
operators' identity provider **and MFA**, and make sure no other hostname or
path reaches those routes unprotected (the origin admits only Cloudflare,
and the tunnel ingress names one hostname). Customer routes (`/inbox`,
`/keycheck`, `/provider-identity`, `/devices/*`, `/trees/*`) stay outside
Access: a `keyquorum` client cannot answer an Access login. Record the Access
application and policy with the deployment.

### Monitoring, incidents, rollback, cost

- Monitor the edge (Cloudflare analytics and the 5xx rate), the tunnel
  (`cloudflared` health and reconnects in the journal; alert when all
  connections are down), and the origin as above.
- An edge outage is a Cloudflare incident; a tunnel outage looks like 530
  errors at the edge with a healthy origin. Rollback is DNS: un-proxy the
  record (grey cloud) and open 443 on the security group, a change the
  operator should rehearse once.
- Tunnel credentials are a secret file on the instance; rotate them from
  the dashboard when a person who could read them leaves.
- Cost: the proxy, the tunnel and a small number of Access seats are on
  Cloudflare's Free plan at the time of writing (not retrieved; confirm on
  Cloudflare's pricing page); a paid plan buys higher body limits, longer
  timeouts and more seats, none of which the relay needs.

## Path B: Cloudflare Workers hosting, feasibility

### What would have to change

- **Runtime.** The relay's HTTP host is Tokio and axum (`host.rs`,
  `src/relay/server.rs`), and `build.rs` refuses the `provider` feature on
  wasm32 outright. Workers run WebAssembly built for
  `wasm32-unknown-unknown`, and threaded runtimes such as tokio are not
  supported there (Cloudflare, Rust on Workers, search summary); an
  Emscripten target with Tokio support exists only as an experimental
  preview. What *is* portable is `relay::service::dispatch`
  (`src/relay/service.rs`), the runtime-independent request router that
  the browser lab already runs in process on wasm32: a Worker would be a
  new, small adapter from the Workers request type to `RelayHttpRequest`,
  behind a new feature that excludes the axum host. The rate limiter, the
  admission pool, the request timeout and the TTL scan are axum-host
  concerns that would need Workers equivalents (edge rate limiting, Durable
  Object alarms for the scan).
- **Persistence.** The local SQLite connection cannot run unchanged. The
  candidate is a `RelayStore` backend over a Durable Object's SQLite
  storage: one Durable Object per relay keeps every unit of work inside one
  object, where storage operations are serialised and transactional, which
  is what `RelayStore` promises (push a letter with its trees, rotate a key
  with its sealed replacement, grace period, delivery record and audit
  event, each as one unit). Spreading state across several objects would
  lose that atomicity and is not proposed. The 10 GB per-object limit and
  the 2 MB row limit (a letter is at most 1 MiB) fit a single
  organization's relay; a relay that outgrows 10 GB would need sharding by
  customer, which is the same isolation design Path A leaves open. The
  counters, audit chaining and anchoring would be the SQLite statements the
  reference store already uses, run through the Durable Object API rather
  than rusqlite, and `relay::store::conformance` would have to pass against
  it before it is trusted.
- **Signer custody.** The relay private key would be a Workers secret
  (provider-controlled, not readable back through the API) used by the same
  `signing` code, so signatures, sealed key delivery (`KQPB` kind 20,
  `.kqkey`) and audit anchors stay byte-compatible: the formats are the
  crate's, not the host's. The provider root stays offline; the operator
  lock must not be a Worker secret, because `host keys` would then run in
  the public Worker. Minting would instead run on an operator machine
  against the Durable Object through an authenticated internal route,
  which is a new privileged surface the current design does not have.
- **Backups and migration.** Durable Object SQLite has point-in-time
  recovery on Cloudflare's side; an export to a file the operator controls
  (for checkpoint verification off-platform, and for leaving the platform)
  would be a new host command. Moving a SQLite relay into a Durable Object
  is a row copy per table; the audit chains carry over unchanged because
  the hashes are over row contents.

### Estimate

| Item | Effort |
| --- | --- |
| Workers adapter over `service::dispatch`, feature gating, build | 1 week |
| Durable Object `RelayStore` backend to conformance | 2 to 3 weeks |
| Minting path, export, migration and rollback commands | 1 to 2 weeks |
| Load, limits and custody review; runbook | 1 week |
| Cost | a Workers Paid subscription plus Durable Object storage and requests; not estimated further without the port |

### Decision: defer

Workers hosting is a runtime and persistence port of three to six weeks,
with a new privileged minting surface to design, for a service whose first
deployment serves one organization from one process. The native deployment
needs none of it, and Path A gives the edge benefits without it. Revisit
when a shared multi-tenant relay is designed (the isolation work is common
to both) or when the operator does not want to run a VM. Follow-up scope,
when taken up: the adapter, the store with conformance, custody and
minting design, export and migration commands, then this assessment
rewritten from measurements.

## Acceptance checklist

| Criterion (issue #88) | Settled by this document | Needs the deployment |
| --- | --- | --- |
| AWS design records region, instance size, cost, IAM boundaries, network exposure | yes (region to be named at setup) | record the chosen values |
| A controlled EC2 deployment runs the native relay with one SQLite database on encrypted EBS | plan | run it |
| HTTPS, renewal, health and store-backed readiness operate as documented | plan and probes | observe them |
| An unauthorized client cannot mint provider-issued keys or licences | yes: no HTTP route exists; test pinned | re-run the test against the live host |
| Provider-root custody and operator credential separation documented and verified | documented | verify at the ceremony and record it |
| Launch prerequisites revalidated and linked to fixes or scope decisions | yes (table above) | none |
| Overload and storage-limit tests show bounded resource use | the bounds are named | run the tests, record memory and the 503/429 behaviour |
| Backup restoration meets the objectives and reconciles credential state | procedure | run the drill |
| Upgrade, rollback, shutdown, incident response demonstrated | procedures | demonstrate |
| Hosting decision compares the three options with cost, ownership, limits, effort | yes | none |
| Cloudflare edge design records DNS, TLS, trusted proxy identity, cache policy, origin restrictions, private administration, tunnel lifecycle | yes | none |
| If the edge path is deployed, tests verify origin restriction, forged headers, cache bypass, limits, outage recovery | commands given | run them if Path A is deployed |
| Workers assessment maps atomicity and provider-only signing to a runtime and backend, with an adopt/defer decision | yes: defer | none |
| If a Workers backend is implemented, conformance and the rest | not applicable (deferred) | |
| Runbooks distinguish hosting-provider controls from relay authorization | yes (this document and `relay-deployment.md`) | none |
