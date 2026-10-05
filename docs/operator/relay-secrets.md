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

| Artifact | Secret? | On the relay? | Persistence | Source | Never |
| --- | ---: | ---: | --- | --- | --- |
| provider-root private key | **yes** | **no** | offline machine only (`host root generate --private-key-out`, owner-only) | KeyQuorum root ceremony | a relay, image, cluster, database, unit file, environment, or `.kq*` file |
| provider-root public key | no | compiled into clients and relays | source and binary (`KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY`) | KeyQuorum | — |
| relay private key (`relay.key`) | **yes** | **yes**, in memory and as a runtime credential file | systemd encrypted credential (`LoadCredentialEncrypted=`), a Kubernetes Secret or CSI mount, or an owner-only file on a development host | `host identity generate --private-key-out` | the environment, a flag value (`ps`), a log, version control, a `.kqcert` |
| relay public key (`relay.pub`) | no | yes | file | `host identity generate` | — |
| `provider.kqcert` (`KQPC`) | no (signed) | yes, read-only | file or ConfigMap, root-owned | offline root (`host certify`) | being edited; being treated as a secret carrier |
| `provider.kqrl` (`KQRL`) | no (signed) | yes, read-only | file or ConfigMap | offline root (`host krl`) | the same |
| `provider-policy.kqpolicy` (`KQPL`) | no (signed; it authorizes) | only where the hardware-authority policy is checked | file | offline root (`host policy issue`) | a relay that does not need it; the environment |
| relay SQLite database (`relay.sqlite`) | sensitive (key hashes, audit trail, every stored letter) | yes | `/var/lib/keyquorum`, 0600 with its journal sidecars | the relay | a personal store's path; a shared or world-readable location; the repository (`*.sqlite` is ignored) |
| relay MongoDB database | sensitive (the same) | reached over the network | the deployment's replica set with authentication, TLS and backups | the relay | raw bearers (only hashes), unsealed letters, the provider root, a personal store's collections |
| MongoDB connection string | **yes** (it carries the database user's password) | yes, as a mounted file | Kubernetes Secret or CSI mount; a 0640 root:keyquorum file on a host | the database administrator | a flag value, a ConfigMap, `values.yaml`, a log |
| `kql_…` operator lock | **yes** | operator only, for `host keys create\|rotate` | a file on the operator's session (`--licensee-key-file`, `KEYQUORUM_LICENSEE_KEY_FILE`), or a Secret that exists only for a one-off Job | minted once by the first host `keys` command on an empty issuer store | the long-running relay service or pod; a unit file; the environment of the service; a log |
| customer `kq_…` bearer | **yes** | never raw at rest (only `hex(SHA-256(raw))`) | the customer's own store, sealed (`relay_credentials`) | minted by `host keys create\|rotate` | a log, an audit row, a database document, a ticket or chat; the environment |
| `.kqkey` bootstrap bundle (`KQXB` type 4) | sealed secret carrier | handoff only | temporary, owner-only, never overwritten; deleted once loaded | `host keys create --recipient-key --out` (#86) | the repository (`*.kqkey` is ignored); being left on the relay; being opened by anyone but the recipient key |
| `.kqpb` key-rotation letter (`KQPB` kind 20) | sealed secret carrier | opaque, in the mailbox until collected or expired | the mailbox, with the old key's grace period as its TTL | `host keys rotate` (#86) | being unsealed by the relay |
| audit checkpoint file | not secret, but the evidence | **no** (that is its point) | write-once storage the operator controls | `host keys checkpoint --out` | the relay host or database |
| relay settings (`relay.env`, the chart's ConfigMap) | no | yes | file or ConfigMap | the operator | any value from the rows above marked secret |
| slot passphrases, PINs, vault passwords | **yes** | never | the person's memory; prompted and zeroized | the person | the relay, a file the relay reads, an environment variable |

## Where each secret enters a process

| Process | Needs | Through |
| --- | --- | --- |
| `keyquorum host serve` | relay key; MongoDB connection string (hosted) | `--relay-key PATH` / `KEYQUORUM_RELAY_KEY` (a path); `--mongodb-uri-file PATH` / `KEYQUORUM_MONGODB_URI_FILE` |
| `keyquorum host keys create\|rotate` | relay key; operator lock; MongoDB connection string (hosted) | the same, plus `--licensee-key-file PATH` / `KEYQUORUM_LICENSEE_KEY_FILE` (then `--licensee-key`, `KEYQUORUM_LICENSEE_KEY`, a prompt) |
| `keyquorum host keys list\|events\|revoke\|checkpoint` | relay key only for `checkpoint` and to sign a revocation at once | `--relay-key PATH` |
| `keyquorum host certify\|krl\|policy issue` (offline) | provider-root private key | `--root-key PATH` / `KEYQUORUM_PROVIDER_ROOT_KEY_FILE` (then the raw `KEYQUORUM_PROVIDER_ROOT_KEY`) |
| a customer's `keyquorum loadkey --bundle` | their slot passphrase | a prompt, zeroized |

Every file source is read with a bound (`MAX_CREDENTIAL_FILE_BYTES`, 8 KiB),
loses only one trailing line ending, is held in zeroizing memory for the
command's lifetime, and an error about it names the path, never the
contents (`src/cli/host_env.rs`).

## Why the relay key is not a `.kq*` file

Issue #86's bootstrap bundle works because the customer already holds the
private key that opens it. A new relay host holds no such provisioning
identity, so a relay key inside a sealed bundle would need a key to open
it, and that key would need provisioning in turn; without one, a `.kq*`
file holding the relay key would only be plaintext secret storage under a
new name. The operating system's credential facility (systemd credentials,
Kubernetes Secrets with an external secret manager, the CSI secrets store)
is the right carrier for the relay's own key. A sealed relay-provisioning
bundle (a new `KQXB` type sealed to a dedicated host key) is a separate
design with its own wire format, not part of this deployment path.
