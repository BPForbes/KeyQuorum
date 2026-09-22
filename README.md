# KeyQuorum

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are encrypted and bound to registered physical tokens, such as USB devices. Access requires the necessary hardware keys to be presented before a protected file can be unlocked, providing layered, hardware-backed access control.

## Status

Early scaffolding, though the CLI now covers most of what the concept below describes.
Hardware-key quorum splitting/reconstruction is implemented in software. A key
file with no container placement is still one device: that is the original
one-key one-device exchange, and distinct key files count as distinct devices.
`split` and `tree` set `--custody` and `--minimum-physical-devices`. Commands
that unwrap a key take `--slot container=label` beside `--share-file`.
`keyquorum-device` can also put several identities in logical slots on one
directory (a mounted USB, or a stand-in). Those slots share one device id.
Logical mode is for development and constrained hardware; it is not a hardware
quorum. A tree can require `minimum_physical_devices` so co-resident slots
cannot satisfy a multi-device policy. `device.kq` is signed by `device.skey`,
and each slot token seals that same device id, so rewriting the descriptor
cannot make one container count as two devices. `keyquorum transfer copy` and
`transfer move` carry an active identity to a second device that is open at
the same time. The source stays active on a copy. A move stays active on the
source until the destination commits, then the source keeps a ghost: hierarchy
and provenance without the private key. A ghost cannot sign, satisfy a quorum,
authorize an import, or be exported. The `KQTX` package is signed by the
source device; it is not a sealed envelope.

## Concept

- A key — the data key protecting a file, or a secret split for its own sake — can be
  divided recursively: split into parts, any of which can itself be split further,
  forming a tree (e.g. a company master key splits across departments, and one
  department's own share splits again across its team). A flat "M-of-N hardware keys"
  quorum is just the simplest one-level tree.
- Unlocking a protected file means reconstructing its key's tree: presenting a quorum of
  the registered keys, rather than a single token or password.
- The goal is layered, hardware-backed access control that resists single-point
  compromise (a lost or stolen key alone should not be enough to unlock protected data).

## Getting Started

Build the customer CLI with `cargo build --release`; the binary is `target/release/keyquorum`.
`--features provider` compiles mailbox-host capabilities into the same crate. That
flag is not authorization: official clients trust a relay only when it presents a
KeyQuorum-signed provider certificate and proves possession of the matching key.
Passwords, PINs, and hardware-key material are always prompted for interactively (or read
from a `--share-file` key path) rather than taken as plain arguments. Run `keyquorum --help` for
the full command list.

### Hardware keys

Hardware and tree verbs are top-level (`generate`, `split`, `bind`, …).

```sh
# Generate a keypair. The private key is printed to stdout ONCE and never
# written to disk by this tool — redirect it yourself.
keyquorum generate --type encryption --public-key-out alice.pub --label alice --register > alice.key
keyquorum register --type encryption --label bob --public-key-file bob.pub
keyquorum list
```

`generate --register` writes the public key and records it in one step.
`list` shows hardware keys and every live split tree.

### Splitting a secret (standalone escrow, or protecting a file)

The live SQLite tree **is** the spec for whoever holds that store. An operator
or publisher may keep the full org tree. A personal store should hold only the
nodes that person needs for signing and RBAC: their lineage, their descendants,
siblings of their node, and the fixpoint of *established* bridge peers (the
peer and the peer's ancestors — not the peer's unrelated siblings). Pushing
from a personal store merges that subgraph into the relay; it does not replace
the canonical document. `split`,
`bind`, `add`, `revoke`, `bridge`, and `access quorum --state 0 --leaf` write
that tree in place. There is no JSON file to author first. `tree --output`
writes a snapshot of whatever is stored now. `--tree-spec FILE` remains only
for a nested one-shot tree.

Leaves that exist only as topology (a sibling or bridge peer whose sealed share
lives on their device) may have `wrapped_share` NULL.

Labels must be unique within a tree. `tree <id> --node A B` prints that
set's lowest common ancestor; `reconstruct --node A B` starts recovery
at that ancestor. `tree` with no id lists every stored spec.

`split --source master.pub` escrows that key file (hex, PEM, or OpenSSH).
`--leaf` builds a one-level tree and binds every sibling pair (so `M.S <-> M.A`
is recorded even after later refreshes). Reconstruct with the holders' key
files and `--output`. A 2-of-2 department tree (`M` = `master.pub`,
`M.S` = `SoftwareDepartment.pub`, `M.A` = `AccountingDepartment.pub`)
reassembles the master from the two department keys:

```sh
keyquorum split --label master --threshold 2 \
  --leaf M.S=SoftwareDepartment.pub --leaf M.A=AccountingDepartment.pub \
  --source master.pub --generate-keys --register
keyquorum reconstruct <key-id> \
  --share-file SoftwareDepartment.pub --share-file AccountingDepartment.pub \
  --output master.pub
# same thing, naming the nodes:
# keyquorum reconstruct <key-id> --node M.S M.A \
#   --share-file SoftwareDepartment.pub --share-file AccountingDepartment.pub \
#   --output master.pub
keyquorum tree
keyquorum tree <key-id> --output org.json
```

`--generate-keys` creates each leaf's `.pub` / `.key` pair; `--register`
records those public keys. Dotted leaf labels (`M.S`, `M.A`) infer the
root node `M`. `--bind M.S=M.A` adds an extra pairing; `--leaf` already
binds sibling leaves.

A `.pub` share file uses the sibling `.key` (or a private-key prompt) to
unwrap that department's sealed share. Both departments are required
because `M`'s threshold is 2.

Later commands keep changing that same tree. Pairings are stored by node
id, so they survive a secret refresh, a new leaf, or a leaf moving to a
new public key:

```sh
# Pair two nodes (whitelist both ways + establish the link)
keyquorum bind <key-id> --node M.S --peer M.A

# Move M.S onto a new token; node id — and the bind — stay put
keyquorum bind <key-id> --node M.S \
  --public-key-file NewSoftware.pub --share-file SoftwareDepartment.key --register

# Grow M to 2-of-3; survivor node ids (and M.S <-> M.A) stay put
keyquorum add <key-id> --parent M --node M.F \
  --public-key-file FinanceDepartment.pub \
  --share-file SoftwareDepartment.pub --share-file AccountingDepartment.pub \
  --generate-keys --register
```

```sh
keyquorum tree 1 --node alice bob
keyquorum reconstruct 1 --node alice bob --share-file alice.pub --share-file bob.key
keyquorum bridge allow 1 --node alice --peer it
keyquorum bridge add 1 --from alice --to it
keyquorum bridge list 1
keyquorum bridge remove 1 --from alice --to it
keyquorum bridge deny 1 --node alice --peer it
```

`bind --peer` is the usual way to stand up `A <-> B`. `bridge allow` /
`deny` change the whitelist only. `bridge add` / `remove` stand up or
tear down an established pairing (add requires a whitelist hit on either
side; deny also drops any pairing).

The relay stores the **full** public tree as a JSON document. Sending
data (`relay push`, including private-bridge envelopes) merges the
sender's public topology into that document; nodes the sender does not
hold stay in place, so a personal subgraph cannot replace canonical
context. Fetching data (`relay pull`) returns the slice this device's
encryption fingerprint is allowed to see, and the CLI merges it into
local SQLite before importing envelopes. A later push that adds a bridge
such as `M.S.2 ↔ M.A.1` expands the next pull for `M.S.2` to include
`M.A.1` as topology-only (no sealed share).

`tree fetch` refreshes topology without downloading envelopes. `tree
publish` remains if you need to replace the document without an envelope.

```sh
# Person: envelopes plus the slice this pull key is allowed to see
keyquorum --db alice.sqlite relay pull --import --share-file alice.key

# Topology only (no envelopes), including first fetch onto an empty store:
keyquorum tree fetch <key-id>
keyquorum tree fetch --label master
```
### Private sign bridges (per-person stores)

A private sign bridge is an N-person group that can co-sign files. Each
node is its own storage: `M.A.1` is an employee, `M.A` is the accounting
manager, `M` is a cross-department manager (CXO). A bridge of `M.S.2`,
`M.S.3`, and `M.A.2` therefore notifies **five** stores — those three
employees plus department managers `M.S` and `M.A`. The CXO is not in
that set unless a member is itself a department manager.

Members receive a sealed copy of a shared Ed25519 key (plus salts).
Managers receive roster metadata only so they can track the live
standard. This database never keeps another person's sealed secret;
`create` / `remove-member` write one `.kqpb` **envelope** per store.

Those two commands use the same plan-then-commit pattern: they generate
every envelope first, write the files, then persist the new (or rotated)
bridge in this database. Either both land or neither does: a failed write
leaves no live row for that change, and a failed commit deletes the
envelopes it just wrote — they describe a bridge this store never
recorded, and `.kqpb` files are never overwritten, so leaving them behind
would block the retry. Either way, run the command again. There is no
separate "redeliver initial packages" command because a failed create
never commits.

Each `--member` must already have a registered **signing** public key
under that label (`generate --type signing --label M.S.2 --register`).
The roster stores that key. `verify` checks the artifact against the
roster-bound personal key, not a pub declared only on the signature.

Each `.kqpb` is a cryptographic envelope (same idea as `KQXB` export
bundles): the outside names the recipient’s X25519 public key; the inside
is `crypto_box`-sealed so only that store’s encryption private key can
open it. A mailbox, USB drop, or email can carry the envelope without
being able to read the letter. `.kqbn` eviction notices are the
exception — they are public routing slips, not sealed envelopes.

```text
outside (anyone can see)     inside (recipient only)
-------------------------    --------------------------------
KQPB magic, kind             wrap_salt || bridge secret (members)
recipient encryption pub     or roster + salts (managers)
                             roster includes each member's
                             personal signing pub
                             + rotate/destroy auth sig
```

Five people in the example means five envelopes, each addressed to a
different pub. Operators can copy those files out of band, or push them
through the mailbox relay (`keyquorum relay push`) so each store can
`relay pull --import` locally.

```sh
# Each member needs a registered signing public key under their label:
keyquorum generate --type signing --label M.S.2 --register \
  --public-key-out M.S.2.sign.pub > M.S.2.sign.key
# …same for M.S.3 and M.A.2

# On any machine that can see the tree (and manager encryption pubs):
keyquorum bridge private create 1 \
  --member M.S.2 --member M.S.3 --member M.A.2 \
  --supervisor M.S=SoftwareManager.pub --supervisor M.A=AccountingManager.pub \
  --self M.S.2 --output-dir ./bridge-packages --label eng-acct

# Each other person imports into *their* database:
keyquorum --db ma2.sqlite bridge private import \
  --file ./bridge-packages/M.A.2.kqpb --share-file Accounting2.key

# Sign with the bridge key + the member's personal signing key:
keyquorum sign --bridge-uid <uid> --node M.A.2 \
  --signing-key-file Accounting2.sign.key --share-file Accounting2.key \
  --message-file report.pdf --signature-out report.kqbs

# Peer verifies with their membership and the artifact:
keyquorum --db ms2.sqlite verify --bridge-uid <uid> --as-node M.S.2 \
  --message-file report.pdf --signature-file report.kqbs
```

If `M.S` revokes `M.S.3`'s hardware key, that label is dropped from
every live private bridge. Ordinary `revoke` (not only `--evict`)
prints the notify list and writes a `.kqbn` notice **after** the
hardware revoke commits. Remaining members must rotate (the departed
person still holds the old bridge secret). A remaining member then:

```sh
keyquorum bridge private remove-member <uid> --member M.S.3 \
  --node M.S.2 --share-file Software2.key --output-dir ./bridge-packages
# Copy the new packages to M.S.2, M.A.2, M.S, M.A, and M.S.3
# (or `keyquorum relay push --dir ./bridge-packages`).
```

A two-person bridge is destroyed when one member is removed.

Banning a hardware key is `revoke <hardware-id>`. That always drops
pairings and whitelist rows for every live leaf sealed to that token,
and drops that label from every live private sign bridge. `--evict`
PSS-refreshes survivors of that leaf (`--key-id` / `--node`, or the
unique leaf the token backs). Eviction needs a parent threshold of at
least 2, and every remaining active sibling must be a hardware-backed
leaf — a 1-of-N parent is refused. Binds between survivors stay.
`--share-file` is that sibling's actual key file (`.pub` / `.key` from
`generate` or `split --generate-keys`, or a PEM / OpenSSH public key).
A `.pub` file uses a sibling `.key` when present.

```sh
keyquorum split --label "team escrow" --threshold 2 \
  --leaf alice=alice.pub --leaf bob=bob.pub --leaf carol=carol.pub \
  --generate-keys --register
keyquorum tree <key-id>
keyquorum revoke <carol-hardware-id> --evict \
  --share-file alice.key --share-file bob.pub
# pin a leaf when the token backs more than one:
#   --key-id <key-id> --node carol
```

```sh
keyquorum split --label "escrow demo" --threshold 2 \
  --leaf alice=alice.pub --leaf bob=bob.pub
keyquorum tree <key-id>
keyquorum reconstruct <key-id> --share-file alice.key --share-file bob.pub

keyquorum access quorum --state 0 --source ./secret.txt --encrypted-path ./secret.txt.kqenc \
  --leaf alice=alice.pub --leaf bob=bob.pub --generate-keys --register
keyquorum access quorum --status --id <file-id>
keyquorum access quorum --state 1 --id <file-id> --share-file alice.key --share-file bob.pub
```

`<key-id>` and `<file-id>` are printed by `split` / `access quorum
--state 0` ("Split key 1" / "Locked file 1"). `--share-file` takes the
same key files `generate` wrote (`alice.pub` / `alice.key`) or another
standard public-key file (PEM, OpenSSH `.pub`). The private key unwraps
every leaf sealed to that hardware key. `tree` still prints leaf node
ids for inspection.

### Password-protected files and credentials

```sh
keyquorum access password --state 0 --source ./secret.txt --encrypted-path ./secret.txt.kqenc
keyquorum access password --state 0 --source ./secret.txt --encrypted-path ./secret.txt.kqenc \
  --expires "2026-12-31 23:59"
keyquorum access password --state 1 --id 1 --output ./secret.txt

keyquorum vault add "Email" --username alice
keyquorum vault get 1
```

Either can also take `--pin` to require a 4-digit PIN (attempt-limited, FIDO2-PIN-style)
alongside the password. A successful one-time PIN check is cached for one hour; end that
window early with, for example, `keyquorum pin relock --resource credential --id 1`.

### Signature verification, export, and sharing

```sh
keyquorum verify --public-key-file signer.pub --message-file msg.txt --signature-file msg.sig
keyquorum sign --bridge-uid <uid> --node M.A.2 \
  --signing-key-file ma2.sign.key --share-file ma2.key \
  --message-file msg.txt --signature-out msg.kqbs
keyquorum verify --bridge-uid <uid> --as-node M.S.2 \
  --message-file msg.txt --signature-file msg.kqbs

keyquorum export credential 1 --recipient-key-file bob.pub --output cred.kqxb
keyquorum export file 1 --recipient-key-file bob.pub --output file.kqxb

keyquorum share create-file 1 --ttl-seconds 3600 --pin
keyquorum share create-file 1 --expires "2026-12-31 23:59"
keyquorum share redeem-file
```

`--expires` is UTC (`yyyy-mm-dd hh:mm`). After that instant, redeem, unlock, or a
scan deletes the ciphertext from disk and drops the file's database row.
`--ttl-seconds` is a relative share-link lifetime and does not remove the file.

`relay push --expires "2026-12-31 23:59"` stamps the same UTC cutoff on each
uploaded envelope. Inbox pull skips expired rows and removes them from the
mailbox so the recipient cannot fetch the file after the date.

### Authenticated updates (key reissue and tree restructure)

Replacing someone's token, or changing the shape of the split tree, has to
reach every store that held the old picture. Both changes ship as the same
sealed `.kqpb` envelope a private bridge uses, so the mailbox routes them
without being able to read them — but the letter inside is *signed* by an
authorizing label, so each store decides for itself whether to apply it.

A store applies an update only when all four hold:

- **Addressed here** — the envelope's recipient key is an unrevoked
  encryption key this store has registered under the label named inside
  the letter. Re-addressing a letter to another mailbox gets it rejected.
- **Authorized** — the signer is the subject itself or one of its
  ancestors in the dotted hierarchy (`M` over `M.S` over `M.S.2`), and
  this store already holds a registered signing key for that label. A peer
  branch cannot restructure your tree or swap your token.
- **Signed** — Ed25519 over a domain-separated hash that covers every
  field, including the recipient label and its public key.
- **In order** — a reissue must be exactly one past the last one this
  store applied for that person; a restructure must carry a public
  generation strictly greater than the one stored. Replays, stale
  envelopes, and skipped sequences change nothing.

```sh
# The authorizing label needs a registered signing key:
keyquorum generate --type signing --label M --register --public-key-out M.sign.pub > M.sign.key

# Restructure: after `add`, `revoke --evict`, or `bind`, announce the new
# shape. Each active leaf gets its own visible slice at the next generation.
keyquorum tree restructure 1 --as M   --signing-key-file M.sign.key --output-dir ./updates

# Reissue: M.S.2 lost their token and generated a replacement.
keyquorum reissue --node M.S.2 --key-id 1   --encryption-public-key-file M.S.2.new.pub   --as M --signing-key-file M.sign.key --revoke-previous   --output-dir ./updates

keyquorum relay push --dir ./updates
```

Each store applies them the same way it applies a bridge envelope — the
kind byte in the header decides which it is:

```sh
keyquorum --db M.S.1.sqlite relay pull --import --share-file M.S.1.key
keyquorum --db M.S.1.sqlite bridge private import --file M.S.1.kqpb --share-file M.S.1.key
keyquorum --db M.S.1.sqlite updates    # what this store has applied
```

A reissue reaches every store whose own slice named that person, plus
every party of every live private bridge they are on — nobody else, since
nobody else held the key. It repoints that person's tree leaves and bridge
roster entries, and drops the leaf's sealed share, which was wrapped to
the retired token and cannot be opened by its replacement (recover it from
the quorum, or reseal with `bind --public-key-file`). The shared secret of
a private bridge is *not* rotated by a reissue: run
`bridge private remove-member` to roll that generation if the retired
token could have been compromised.

The subject's own copy is addressed to the **incoming** encryption key, so
their replacement device must have registered it (`generate --register`, or
`register`) before importing — which is also what lets it open the letter.

`tree restructure` differs from `tree publish` in exactly this way: publish
replaces a relay document with a store's own view, while a restructure
hands each person a slice they can verify the authority for.

### Mailbox

The hosted mailbox carries sealed `.kqpb` envelopes and public-tree slices.
It indexes packages by the recipient fingerprint in the outer header and
never unseals them. Wrapped shares and private keys stay on the device.
Your provider gives you a URL and an API key; you do not run the mailbox or
mint keys. Official `loadkey` / `relay` commands authenticate that host
with a KeyQuorum-signed provider certificate before sending a bearer.

```sh
export KEYQUORUM_RELAY_URL=https://relay.example.com
# Load once; omit the key so it is prompted (stays out of shell history).
keyquorum loadkey --url https://relay.example.com
keyquorum relay push --dir ./bridge-packages
keyquorum relay pull --output-dir ./inbox
keyquorum --db alice.sqlite relay pull --import --share-file alice.key
# --api-key still works for scripts and is stored after a successful check.
keyquorum relay push --dir ./bridge-packages --api-key "$PUSH_KEY"
```

`loadkey` first verifies the relay's KeyQuorum-signed identity, then checks
the key with the mailbox, then stores the key hash and a sealed copy of the
bearer in the personal database. Later `relay` / `tree fetch` commands
repeat that identity check and re-check the hash before using the key.
An optional signed revocation list can be pointed at with
`KEYQUORUM_PROVIDER_KRL`.

`relay push` also uploads every public tree in `--db` and **merges** it
into the mailbox (unrelated nodes stay put). `relay pull` merges the
returned slices into `--db` (then `--import` opens envelopes).
`tree fetch` syncs topology without an envelope. Remote mailboxes must
be `https://`; `http://` is accepted only for loopback.

If a key is lost or rotated, load the replacement your provider issues.
Envelopes already delivered are unchanged. Missed pulls: `relay pull
--after <id>` replays anything not yet downloaded; `bridge private import`
still rejects stale generations.

## Roadmap

[#10](https://github.com/BPForbes/KeyQuorum/issues/10) is implemented:
mailbox transport (API keys, `relay push` / `relay pull --import`),
private-bridge create/rotate/remove-member envelopes, and the
authenticated update envelopes for hardware-key reissue (`reissue`) and
key-tree restructure (`tree restructure`) described above.

Private-key custody is the key file (one key, one device) or a `keyquorum-device`
container (one directory, many passphrase-wrapped slots). `generate` still
prints a private key once and does not write it. Real USB token protocols are
not implemented; a container is a directory, not an OS partition.

- **Persisted private-key custody** for `generate` beyond the key file and the
  slot token (for example an OS keychain).
- **`import`** of password-vault / locked-file `export` bundles (the bundle format
  and encoder are already final). Private-bridge `.kqpb` import is implemented.

## Security

This project handles cryptographic key material and encrypted user data. Never commit private keys, tokens, secrets, API key bearers, provider certificates, revocation lists, or plaintext copies of protected files to this repository — see `.gitignore` for patterns already excluded. Compiling with `--features provider` does not make a host a trusted KeyQuorum provider.

The hosted mailbox cannot decrypt `.kqpb` envelopes and must not be given wrapped shares or private keys. It stores the canonical *public* tree as JSON documents (labels, fingerprints, public keys, policy). Sending envelopes with `relay push` updates those documents from the sender's `--db`. Pulling returns a sliced copy for the pull-key fingerprint, which the CLI translates into local SQLite. Personal devices load a bearer with `keyquorum loadkey` (or `--api-key` once); they keep the hash and a sealed copy of the bearer in the owner-only org database. Recover a lost bearer by loading the replacement your provider issues; recover a missed update by pulling again and importing on the device that holds the matching decryption key.

## Contributing

AI coding agents working in this repository should read the relevant instructions file for their tool:

- `CLAUDE.md` for Claude
- `AGENTS.md` for Codex and other agent tooling
- `.cursorrules` for Cursor

Code review automation is configured via `.coderabbit.yaml`.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
