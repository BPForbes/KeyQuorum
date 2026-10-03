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
`MAX_RATE_LIMITED_CLIENTS`. `identity
generate` and `root generate` write the private key only to
`--private-key-out` (owner-only, never overwritten) and never print it.
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
ring refuses rather than overwrite an unsent letter. Only `send_next`, inside
one immediate transaction that re-checks trust, hands the read-pointer letter
to the sender and, if that succeeds, wipes the slot (zeroblob plus
`secure_delete`) and advances; a failed or refused send moves nothing.
`drop_next` discards the head unsent. A `KQPB` is the passport: the ring
holds nothing else (raw `KQXB`, `KQBS`, `KQBN`, `KQHS`, `KQTF` are refused and
travel inside a letter), and device kinds 9 to 12 are refused
(`envelope::is_device_workflow_kind`). The letter must be sealed to an active
encryption key the store holds for the recipient (`keys::is_active_key`, the
same check `org_update` and `file_delivery::recipient_owns_key` use).
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
builds the command `deliver send` or `file share` would, and `inbox open` calls
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
- Tests never write a secret as a literal: passphrases, passwords, PINs and
  nonces come from `crate::test_secrets` (`passphrase`, `other_passphrase`,
  `pin`, `other_pin`, `bytes32`, `shared_passphrase`), drawn at run time. A
  test's assertion message never formats a command's `Result`, error or
  output: name the command line instead. Both keep CodeQL
  (`rust/hard-coded-cryptographic-value`, `rust/cleartext-logging`) clean.

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

This repo also carries `CLAUDE.md` (Claude) and `.cursorrules` (Cursor). Keep guidance
consistent across these files when updating one.

- Legacy checks: tests of deprecated verbs (`deliver`, `file receive|ack`, `relay pull` spellings) sit behind the `legacy-tests` feature and the `legacy` workflow (`.github/workflows/legacy.yml`), whose single job is skipped by default and run on the `legacy` PR label or a manual dispatch. `--all-features` includes them; the everyday CI gate is `--features provider,lab,tui`. Both run the same parallel test groups (`.github/workflows/tests.yml`: lab, cli, file_history, relay+provider+db, and everything else), so a new module needs no workflow edit.
- Security checks: `.github/workflows/security.yml` runs `cargo audit`, `cargo deny --locked check` (policy in `deny.toml`), `gitleaks` over the full history (allowlist in `.gitleaks.toml`, which passes only the published Lab demo passphrases and lockfile checksums), `npm audit` for `lab/` and CodeQL (security-and-quality suite from `.github/codeql/codeql-config.yml`, for Rust, the Lab's TypeScript and the workflows; `.github/scripts/codeql_report.py` prints each finding as source, source quote, quoted lines, SOC 2 criterion and fix, and the `codeql gate` check fails on a high or critical finding in shipped code), on every PR, on `main` and weekly; `.github/workflows/sbom.yml` keeps CycloneDX SBOMs as artifacts. A new dependency must satisfy `deny.toml` (add a licence only after checking it). Dependabot covers Actions, Cargo and npm, but only Actions updates auto-merge; cargo and npm updates (which include the cryptographic crates) wait for a person. Vulnerabilities are reported privately as `SECURITY.md` describes.
- SOC 2: `docs/soc2-controls.md` maps each Trust Services Criterion to the control in this repository, its evidence (test or workflow) and what the operator must still provide (TLS termination, rate limiting, backups, log retention). Update it with any change to a control it names.
- Review rules: the "Review guidelines (strict, SOC 2)" section above is also loaded by CodeRabbit (`.coderabbit.yaml` points its per-path checks at it and runs a "SOC 2 evidence" pre-merge check) and by Codex review. Change the rules in all three agent files together, and keep `.coderabbit.yaml` consistent with them.
