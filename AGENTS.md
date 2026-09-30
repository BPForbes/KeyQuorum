# AGENTS.md

Instructions for AI coding agents (Codex, and similar agent tooling) working in this
repository.

## Project overview

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are
encrypted and bound to registered physical tokens (e.g. USB devices). Unlocking a
protected file requires presenting a quorum of the registered hardware keys, providing
layered, hardware-backed access control.

The project is a Rust Cargo crate. Private sign bridges live in `src/private_bridge.rs`
and the `keyquorum` CLI. `create` and `remove-member` generate delivery packages first
and commit only after those files are written — do not persist a live bridge before
the envelopes exist. The two must stay in step in both directions: if the commit
fails, the CLI deletes the `.kqpb` files it just wrote, because `write_owner_only`
refuses to overwrite and leftovers would block the retry.

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
header at all; none of those belong in `envelope.rs`. The provider
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
same module: the sender signs the header and the container's hash, and the
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
never judges authority itself. Hunks fold (`za`/`zc`/`zo`, `zM`/`zR`), `Space`
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
verify, share, receive or refuse, record the answer, expire, view a revision,
diff, export and check a snapshot, import another copy, link or unlink a quorum
or password gate) each run one `keyquorum file` command as the active person against their own store with their own slot
(a quorum gate is linked in the org store and a password gate in its owner's
store, where each gate runs); letters and acknowledgements pass through `/srv/keyquorum/tracked/letters` and
`acks`. `Snapshot::tracked_files` judges revisions with that store's
`StoreTrust`; the lab adds no gate or rule of its own, event categories come
from `HistoryEventType::category`, and entries without a history serialize
exactly as before. The terminal does not expand `~` inside command arguments.

## Setup / build / test

- Build (customer CLI): `cargo build --release` (no mailbox host subcommand)
- Build (provider-capable binary): `cargo build --release --features provider`
  (compiles host capabilities; authorization is a signed `provider.kqcert`)
- Test: `cargo test --locked --all-targets --all-features`
- Lint: `cargo clippy --locked --all-targets --all-features -- -D warnings`
- Lab (`src/lab/`, `lab/`), from `lab/`: `npm run build:wasm`, `npm run build`, `npm run test:browser`
- Format: `cargo fmt`

Run format, lint, and tests before considering any change complete.

## Code style

- Follow standard Rust conventions and `rustfmt` defaults; no project-specific style
  guide exists yet.
- Keep changes minimal and scoped to the request. Avoid speculative abstractions or
  unrelated scaffolding.
- Put tests in their own file next to the module they cover, not in an inline
  `#[cfg(test)]` module inside the implementation. Use `src/<module>/tests.rs`
  (directory module: `#[cfg(test)] mod tests;`) or `src/<module>.rs` with
  `#[cfg(test)] #[path = "<module>/tests.rs"] mod tests;`. Nested files such as
  `src/relay/client.rs` load `src/relay/client/tests.rs` the same way. Shared
  test helpers belong in a `#[cfg(test)]` module, not in production code.

## Security

This project handles cryptographic key material, hardware tokens, and encrypted user
files, so treat it as security-sensitive:

- Never commit private keys, tokens, `.env` files, secrets, or plaintext copies of
  protected/test files. See `.gitignore` for excluded patterns (`*.key`, `*.pem`,
  `*.secret`, `*.token`, `*.kqkey`, `*.kqpb`, `*.kqbn`, `*.kqcert`, `*.kqrl`,
  `*.kqpolicy`, `device.kq`, `device.skey`, `*.kqst`, `secrets/`, `keys/`,
  `provider-secrets/`, `test-keys/`, etc.).
- Take extra care with code touching key derivation, encryption/decryption, or
  quorum/threshold logic — bugs there are security bugs, not just correctness bugs.

## Pull requests

- Write clear, descriptive commit messages explaining why a change was made.
- Keep PRs focused on a single logical change where possible.
- When the current branch already has an open pull request, ask before creating another branch or opening another pull request. No answer is a denial. On a denial, stay on the current branch and update the open pull request. Create a new branch and pull request only after an explicit yes.

## Other agent instruction files

This repo also carries `CLAUDE.md` (Claude) and `.cursorrules` (Cursor). Keep guidance
consistent across these files when updating one.
