# KeyQuorum SOC 2 control map

This maps the AICPA Trust Services Criteria (2017, revised points of focus
2022) to the technical controls this repository implements, and to the
evidence an auditor can check: a test, a workflow, or a file and line. It is
**not** a SOC 2 report. A report covers an operating organisation over a
period. Most of the common criteria (CC1 to CC5: governance, people, risk
assessment, monitoring of controls) and the physical controls belong to
whoever runs KeyQuorum. The [operator responsibilities](#operator-responsibilities)
section lists what the software relies on the operator to provide.

Keep this file in step with the code. A change to a control named here
updates its row in the same pull request (see "Other agent instruction files"
in `AGENTS.md`).

## Controls by criterion

| Criterion | Control in KeyQuorum | Where | Evidence |
| --- | --- | --- | --- |
| CC6.1 Logical access | Files open only when the configured key-tree quorum and custody policy are satisfied. With `hardware` custody each key is its own device; `logical` custody lets several slots on one container satisfy Shamir together and does not guarantee a hardware quorum. `minimum_physical_devices` counts distinct device ids under either mode, and a ghost cannot satisfy quorum. | `src/quorum.rs`, `src/device.rs`, `src/transfer.rs` | `src/quorum/tests.rs`, `src/device/`, `src/transfer/tests.rs` |
| CC6.1 | Relay API keys are 256-bit random bearers. Only `hex(SHA-256(raw))` is stored, each key is scoped (`inbox.push`, `inbox.pull`, `admin`, `device.push`, `device.pull`), and pull keys are bound to one recipient fingerprint. | `src/relay/api_key.rs`, `src/relay/service.rs` | `src/relay/tests.rs` (`api_key_lifecycle_create_validate_rotate_revoke`, `pull_key_requires_fingerprint_and_cannot_bind_push`), `src/relay/server/tests.rs` (`router_enforces_scopes_and_returns_opaque_bytes`) |
| CC6.1 | Official clients talk only to a relay that proves a KeyQuorum-root-signed certificate (signature, expiry, capabilities, revocation list) over a fresh challenge. | `src/provider.rs`, `src/relay/client.rs` (`authenticate_provider`) | `src/provider/`, `src/relay/client/tests.rs` |
| CC6.1 | Ed25519 signatures are checked with `verify_strict`, in one place. | `src/signing.rs` | `src/signing/` |
| CC6.1 | PINs: Argon2id-hashed, compared in constant time, and locked after 8 failed attempts. | `src/pin.rs` | `src/pin/tests.rs` |
| CC6.1 | Caches (`recent_params`, `relay_trust_cache`, `verified_cache`) never feed a signature, quorum, custody, approval, freshness or trust decision. | `src/db/cache.rs` | `src/db/cache/` |
| CC6.1 / C1.1 | Personal stores and the relay database are owner-only (0600), journal sidecars included. | `src/db/mod.rs` (`restrict_db_files`), `src/relay/mod.rs` (`open`) | `src/db/tests.rs` (`open_restricts_permissions_*`), `src/relay/tests.rs` (`relay_open_restricts_the_database_to_its_owner`) |
| CC6.2 / CC6.3 Provisioning and removal | API keys are minted only on the host, after a certificate and relay-key self-check. HTTP can list and revoke them but never create or rotate them. Rotation revokes the old key in the same transaction. | `src/relay/api_key.rs`, `src/relay/server.rs` (no create or rotate route) | `src/relay/tests.rs` |
| CC6.2 / CC6.3 | Hardware-key reissue, eviction (`.kqbn`), bridge member removal and provider certificate revocation (`.kqrl`) end the old access. | `src/org_update.rs`, `src/private_bridge.rs`, `src/provider.rs` | `src/org_update/tests.rs`, `src/private_bridge/tests.rs` |
| CC6.6 System boundaries | Every relay route except `/health`, `/keycheck`, `/provider-identity` and the OpenAPI document needs a bearer with the right scope. Bodies are capped (`MAX_ENVELOPE_BYTES`, 1 MiB per envelope, 2 MiB per request), pages are 1 to 500, each request must finish within `REQUEST_TIMEOUT` (30 s) or gets a 408, and each client (an IPv6 client by its /64 network) gets a per-minute request allowance (600 by default) before a 429 with `Retry-After`, in a client table capped at `MAX_RATE_LIMITED_CLIENTS`; new clients past the cap share an overflow bucket kept apart from requests with no peer address. | `src/relay/server.rs`, `src/relay/service.rs` | `src/relay/server/tests.rs` (`rate_limited_requests_get_429_with_retry_after`, `behind_a_proxy_the_last_forwarded_address_is_the_client`) |
| CC6.6 | The relay client follows no redirects, times out (10 s connect, 30 s total), refuses URLs with userinfo or backslashes, reads at most 256 MiB of any response, and strips control characters from relay error text before showing it. | `src/relay/client.rs` | `src/relay/client/tests.rs` (`response_reads_are_bounded`, `relay_error_text_drops_control_characters_and_caps_length`) |
| CC6.7 Transmission | Clients accept only `https://` relay URLs (plain HTTP only to loopback). The relay host refuses to serve plain HTTP on a non-loopback address unless the operator states that TLS terminates in front of it. | `src/relay/client.rs` (`parse_relay_url`), `src/relay/server.rs` (`check_bind`) | `src/relay/client/tests.rs` (`rejects_remote_http_and_allows_loopback_and_https`), `src/relay/server/tests.rs` (`plain_http_binds_only_to_loopback_unless_tls_terminates_in_front`) |
| CC6.7 | Relay letters are sealed envelopes (`src/envelope.rs`) and stay opaque: the relay never unseals one and never holds a wrapped share or a private key. The relay also stores the canonical public tree (labels, fingerprints, public keys, policy) as JSON documents, which are not sealed. New files are created owner-only and never overwritten (`write_owner_only`). | `src/envelope.rs`, `src/relay/`, `src/locked_files.rs` | `src/envelope/`, `src/relay/server/tests.rs` (`device_routes_are_api_blocked_and_keep_packages_opaque`) |
| CC6.7 / C1.1 | Generated relay and provider-root private keys are written only to an owner-only file, never printed. | `src/bin/keyquorum/host.rs` (`write_keypair`) | `src/cli/tests/parse.rs` (`provider_host_identity_and_certify_parse`) |
| CC6.8 Malicious software | Dependencies come only from crates.io and must pass the licence policy. Every Action reference, GitHub's own included, is pinned to a full commit SHA with its release in a comment, and only Actions updates merge automatically. | `deny.toml`, `.github/workflows/*.yml`, `.github/dependabot.yml` | `security.yml` (`cargo deny`) |
| CC7.1 Vulnerability detection | RustSec (`cargo audit`), `cargo deny`, `gitleaks` over the full history, `npm audit` and CodeQL run on every PR, on `main`, and weekly. CycloneDX SBOMs are kept for 90 days. | `.github/workflows/security.yml`, `.github/workflows/sbom.yml` | workflow runs |
| CC7.2 Monitoring | Every API-key change (created, rotated, revoked) is recorded in `api_key_events` with its actor (`host`, or `admin:<id>` over HTTP). Every mint authorization, granted or refused, is recorded in `provider_auth_events`. The relay logs authentication, scope and rate-limit denials at WARN, and logs at INFO by default. None of these holds a bearer, a key hash or a challenge. | `src/relay/api_key.rs`, `src/relay/schema.sql`, `src/relay/service.rs`, `src/bin/keyquorum/host.rs` | `src/relay/tests.rs` (`api_key_lifecycle_is_recorded_without_bearers`, `http_revocation_records_the_admin_key_that_revoked`, `provider_auth_audit_has_no_secrets`) |
| CC7.2 / PI1.2 | Both audit tables are hash-chained. The relay signs each chain head with its relay key, together with the KeyQuorum-signed certificate that names that key. An anchor is trusted only if that certificate chains to the provider root, is not revoked, and was valid when the anchor was signed, so only a trusted relay can vouch for the trail, and only during its certificate's period. Editing, reordering or deleting a row, or rebuilding the chain without the relay key, is detected. An anchor's `signed_at` is the signer's own word, so the operator also keeps a signed checkpoint off the relay (`host keys checkpoint`): verified against it (`keys events --verify --checkpoint`), the chain must still reach the checkpoint's head, and an anchor that covers rows past the checkpoint but is dated before it is refused, so a key that has since expired cannot backdate a rewritten trail. | `src/relay/audit.rs`, `src/signing.rs` (`relay_audit_anchor_preimage`, `relay_audit_checkpoint_preimage`) | `src/relay/audit/tests.rs` (`an_expired_key_cannot_backdate_an_anchor_past_a_checkpoint`, `rewriting_rows_a_checkpoint_covers_is_detected_even_with_a_fresh_anchor`), `src/relay/server/tests.rs` (`audit_events_are_scoped_to_the_caller_and_revocations_are_signed_at_once`) |
| C1.1 / CC6.1 | Audit records are released only to whom they pertain: `GET /audit/api-keys` returns a key's own events (all events for an admin key), and mint attempts are readable only on the host. | `src/relay/api_key.rs` (`events_visible_to`), `src/relay/service.rs` | `src/relay/server/tests.rs` |
| CC7.2 | Tracked files carry a hash-chained, optionally signed history: gate attempts, deliveries, expiry, verification. Event detail keys are allow-listed (`SAFE_DETAIL_KEYS`). | `src/file_history/`, `src/cli/gate_link.rs` | `src/file_history/tests*`, `src/cli/tests/gate_link.rs` |
| CC7.3 / CC7.4 Incident response | Revoke an API key (host or HTTP admin), revoke a provider certificate (`.kqrl`), reissue a hardware key, evict a bridge member. Vulnerabilities are reported privately (`SECURITY.md`). | as above, `SECURITY.md` | as above |
| CC8.1 Change management | Every PR runs compile, tests (`--features provider,lab,tui`), fmt and clippy with `-D warnings`, and the security workflow. Wire-format codes are appended, never renumbered. Tests sit in their own files. Reviews follow the strict SOC 2 rules in `AGENTS.md`. | `.github/workflows/{compile,test,tests,lint,security}.yml`, `AGENTS.md`, `.coderabbit.yaml` | workflow runs |
| C1.1 / C1.2 Confidentiality | Derived keys, slot secrets, prompted passphrases, passwords, PINs, pasted and stored API keys, and decrypted plaintext (`crypto::decrypt`, `envelope::open`, quorum and password-locked unlocks) are zeroized on drop (`Zeroizing`). The stored bearer's `Debug` is redacted. Protected plaintext goes to stdout or a new owner-only file, never to a shared temporary file. TTLs destroy quorum files, password-locked files, tracked files and relay letters. | `src/crypto.rs`, `src/envelope.rs`, `src/cli/env.rs`, `src/db/relay_credential.rs`, `src/transfer.rs`, `src/quorum.rs`, `src/locked_files.rs`, `src/file_history/expiry.rs`, `src/relay/mailbox.rs`, `src/relay/device_mail.rs` | `src/crypto/tests.rs` (`decrypted_plaintext_is_zeroed_on_drop`), `src/db/tests.rs` (`relay_credential_roundtrip_seals_the_bearer`), `src/quorum/tests.rs`, `src/locked_files/tests.rs` |
| C1.1 / CC6.7 | Protected content is never hashed bare. A delivered file or tracked container is named in signatures, answers and history by a keyed commitment (`crypto::commit`, HMAC-SHA256) under a random key sealed in the letter, and a commitment is only compared, in constant time (`crypto::commitments_match`, `DeliveryAck::confirms`, `HistoryAck::confirms`). | `src/crypto.rs`, `src/file_delivery.rs`, `src/cli/file_cmd.rs` | `src/crypto/tests.rs` (`a_commitment_depends_on_its_key_domain_and_content`), `src/file_delivery/tests.rs` (`contents_are_committed_under_a_per_letter_key_never_hashed_bare`), `src/cli/tests/file.rs` (`a_trusted_revision_is_delivered_accepted_and_acknowledged`) |
| C1.1 / C1.2 / CC6.1 / A1.2 / PI1.3 | Each person's outbox is a fixed-size ring buffer in their own store. Only a sealed, signed `KQPB` letter (the passport) crosses from one person's ring to another's; any other `.kq` file goes inside one, and device letters are refused. A letter must be sealed to the recipient's active registered encryption key, checked when it is queued and again before it is sent. A tracked file's letters must also follow their exchange order (request, answer, file, receipt, snapshot), read from the sender's own copy of the file. The ring cannot open a sealed letter, so this confirms the previous step exists in the named copy with that recipient, not that the letter belongs to that copy or request; the receiving commands bind each letter to its file and request. Only a successful send moves the read pointer, and the sent slot is wiped. A full ring refuses new letters rather than overwrite, and letter size is capped at 16 MiB. | `src/outbox.rs`, `src/file_delivery/exchange.rs`, `src/cli/outbox_cmd.rs`, `src/db/schema.sql` | `src/outbox/tests.rs`, `src/file_delivery/exchange/tests.rs`, `src/cli/tests/outbox.rs` (`a_tracked_file_crosses_rings_only_in_its_exchange_order`) |
| A1.2 Availability | Bounded request bodies, page sizes, request time, client response size and client timeouts. SQLite `busy_timeout` is 5 s. Device letters expire after `DEVICE_PACKAGE_TTL_DAYS`. | as above | as above |
| PI1.2 to PI1.5 Processing integrity | Producers plan, write their envelopes, then commit, and remove the envelopes if the commit fails. Relay pushes and API-key changes run in one immediate transaction. Org updates are ordered and replay-guarded (`org_updates` UNIQUE). File freshness is checked against `tracked_seen_roots`. | `src/private_bridge.rs`, `src/org_update.rs`, `src/db/mod.rs` (`with_immediate_transaction`), `src/file_delivery.rs` | `src/org_update/tests.rs`, `src/relay/server/tests.rs` (`push_rolls_back_trees_and_envelope_when_a_later_tree_is_invalid`) |

## Operator responsibilities

The software relies on whoever runs it for these. An auditor should look for
them in the operator's own controls.

- **TLS** (CC6.7): terminate TLS 1.2 or later in front of every relay that is
  not on loopback, with a publicly trusted certificate. The relay itself
  serves plain HTTP.
- **Rate limiting** (CC6.6, A1.2): the relay limits requests per client per
  minute. Behind a proxy it trusts only the last `X-Forwarded-For` entry, so
  the proxy must set that header. Add connection limits and a global request
  ceiling in front of the relay; its limiter does not cover those.
- **Backups** (A1.2): back up the relay database and personal stores with
  SQLite's online backup (`sqlite3 <db> ".backup <file>"`), keep the copies
  owner-only, and test a restore. `file reindex` rebuilds the tracked-file
  index from `.kqtf` containers, but the containers themselves need backing up.
- **Log retention** (CC7.2): keep the relay's stderr log (WARN denials, TTL
  purges) and the `api_key_events`, `provider_auth_events` and
  `audit_anchors` tables for the period the audit requires. Run the
  verification regularly and keep its output. Take a checkpoint
  (`host keys checkpoint --out FILE`) on a schedule, at least daily and
  after every key ceremony, and keep each one off the host in write-once
  storage you control; verify with the newest (`keys events --verify
  --checkpoint FILE`). A chain is tamper-evident, but someone who can write
  the database could delete the newest rows along with their anchors, and
  an anchor's own date is only its signer's word: the checkpoint is what
  bounds both, to the time since it was taken.
- **Key ceremonies** (CC6.1): generate the provider root key offline, keep its
  owner-only file off networked hosts, and record who held it.
- **Branch protection** (CC8.1): require the `compile`, `test`, `lint`,
  `rust dependencies`, `secret scan`, `lab dependencies` and `codeql gate`
  checks, and a human review, before merging to `main`.
- **Host access** (CC6.1, CC6.2): limit shell access to the relay host. Anyone
  with it can read the relay database and, given the relay key, mint API keys.

## Known limitations

These are stated so an auditor need not discover them:

- The audit chain proves what was anchored. Rows written after the newest
  anchor are reported as pending until the relay signs them (at the next scan
  at the latest). Removing the newest rows together with their anchors can
  only be detected against an anchor kept elsewhere.
- An anchor's `signed_at` is the relay's own clock. A relay key that leaks
  while its certificate is valid can sign anchors until the certificate is
  revoked (`.kqrl`), and revocation then distrusts every anchor that
  certificate signed.
- The relay's rate limit is per process and per client address. It is not a
  defence against a distributed flood.
- Copies of plaintext that leave the process (stdout, an output file the user
  chose) are outside what zeroization can reach.
- Lab demo passphrases and seeded data are public on purpose
  (`.gitleaks.toml`) and protect nothing.

## Audit log

### 2026-10-03: repository audit against the criteria above

Fixed in the same change:

| Severity | Criterion | Finding | Fix |
| --- | --- | --- | --- |
| high | CC6.1, C1.1 | The relay database was created with the process umask (often world-readable), unlike the personal store. | `relay::open` restricts it and its sidecars to 0600. |
| high | CC7.2 | API-key creation, rotation and revocation left no record. `provider_auth_events` existed but nothing wrote to it. Relay authentication denials were not logged, and the host's default log level (ERROR) hid WARN and INFO. | `api_key_events` table, readable on the relay host. Mint authorizations go to `provider_auth_events`. Denials are logged at WARN. The default log level is INFO. |
| high | CC6.7 | The relay served plain HTTP on any address it was told to bind. | Non-loopback binds are refused unless the operator states that TLS terminates upstream. |
| major | A1.2 | The relay had no request timeout, so a slow client could hold a connection and the database lock. | 30 s `TimeoutLayer` (408). |
| major | A1.2, CC6.6 | The relay client read response bodies with no size limit, the provider challenge included, and printed relay error bodies raw to the terminal. | 256 MiB cap. Error text is stripped of control characters and capped at 512 characters. |
| major | C1.1 | The relay host's key-generation commands printed private keys to stdout. | Written only to a new owner-only file. The host's key readers zeroize. |
| major | C1.1 | Prompted passphrases, passwords, PINs and API keys were plain `String`s, not zeroized. | `Zeroizing<String>` from `cli::env::prompt_secret`, `prompt_passphrase` and `confirm_passphrase`, and `transfer::Passphrases`. |
| major | CC8.1 | No workflow ran `cargo fmt` or clippy, though `security.yml` said `tests.yml` did. | `.github/workflows/lint.yml`. |
| minor | CC6.1 | The PIN hash was compared with `!=`. | `subtle::ConstantTimeEq`. |
| minor | C1.1 | `.gitignore` missed `.kqtf` (which holds file content), `.kqenc`, `.kqxb`, `.kqhs`, `.kqbs`, `.kqtx` and SQLite `-journal`/`-wal`/`-shm` sidecars. | Added. |

### 2026-10-03 (second pass): the limitations the first pass left open

| Severity | Criterion | Finding | Fix |
| --- | --- | --- | --- |
| high | CC7.2, PI1.2 | Anyone who could write the relay database could change the audit tables undetected. | Hash chain over every row, plus relay-key anchors that are trusted only within the certificate's validity period (`relay::audit`, with verification on the relay host). |
| major | C1.1 | Audit records had no read path that limited a reader to their own data. | `GET /audit/api-keys`: a key sees only its own events, and an admin key sees all. |
| major | A1.2, CC6.6 | The relay did not rate-limit. | Per-client fixed-window limiter (default 600 per minute), 429 with `Retry-After`, and a bounded client table. |
| major | C1.1 | Decrypted plaintext and unsealed letters were plain `Vec<u8>`, the vault password and stored bearer were plain `String`s, and the stored bearer appeared in `Debug` output. | `Zeroizing` throughout, and a redacted `Debug`. |
| major | C1.1, C1.2, A1.2 | `.kq*` working files had no bounded, per-person place to wait for a trusted recipient. | The outbox ring buffer (`src/outbox.rs`, `keyquorum outbox`). |
| minor | CC8.1 | `clippy::drop_non_drop` fired on the wasm32 Lab build, which no workflow linted. | `write_owner_only` closes the handle by scope, and `lint.yml` now runs clippy for wasm32 as well. |

### 2026-10-03 (third pass): exchange order and duplicate code

| Severity | Criterion | Finding | Fix |
| --- | --- | --- | --- |
| major | PI1.3, CC6.1 | The outbox carried raw `KQXB`, `KQBS`, `KQBN` and `KQHS` files, which are unsigned outside a letter, and placed no order on a tracked file's letters. | Only `KQPB` letters cross between rings. Tracked-file letters follow request, answer, file, receipt, snapshot, checked against the sender's own copy (`file_delivery::exchange`). |
| minor | CC8.1 | Three copies of "is this key one of the label's active keys" existed (`org_update`, `file_delivery`, `outbox`), the host duplicated the CLI's key reader and hex writer, and `ApiKeyEventView` duplicated `ApiKeyEvent`. | `keys::is_active_key` and `keys::parse_key_32`. The host uses `cli::read_key_array_32` and `cli::write_hex_file`. `ApiKeyEvent` is serialized directly. `EventDetails::get` and `exchange::request_event` replace the private helpers in `file_cmd`. Helpers used only for raw kinds were removed. |

### 2026-10-03 (fourth pass): CodeQL `rust/weak-sensitive-data-hashing` and PR review

| Severity | Criterion | Finding | Fix |
| --- | --- | --- | --- |
| high | C1.1, CC6.7 | A delivery letter signed, and its answer echoed, a bare SHA-256 of the file's plaintext (reached from a quorum unlock, so derived from passphrase-protected shares); a tracked-file letter did the same for its container, and the sender's and receiver's histories recorded it as `container_hash`. A bare digest lets anyone who holds it confirm a guess at the content, including after the content is destroyed. | A keyed commitment under a random per-letter key sealed in the letter (`crypto::commit`), compared only for a yes or a no (`confirms`). History records `container_commitment`. The signing domains moved to `-v2`, so v1 letters and answers no longer open. |
| high | CC7.2, PI1.2 | An audit anchor's `signed_at` is chosen by its signer, so someone holding a relay key after its certificate expired, with write access to the relay database, could rebuild the chain and sign an anchor dated inside the old validity window. | Signed checkpoints kept off the relay (`host keys checkpoint`); `--verify --checkpoint` requires the chain to match the checkpoint and refuses anchors over later rows dated before it. |
| major | PI1.2 | The outbox's exchange-order check was documented as binding a letter to its file and request, which it cannot do without opening the letter. | Docs narrowed: it confirms the previous step exists in the named copy with that recipient; the receiving commands bind the letter. |
| major | CC6.8 | GitHub's own Actions were referenced by mutable tags. | Every Action is pinned to a full commit SHA. |
| minor | A1.2 | The rate limiter counted each IPv6 address separately, and new clients past the cap shared a bucket with requests that had no peer address. | IPv6 clients are keyed by /64; overflow has its own bucket. |
| minor | A1.2 | `outbox send --output-dir` could leave a letter behind after a failed dequeue, blocking the retry, and used the recipient label unsanitized in the file name. | The label is sanitized; a letter this send wrote is removed on failure, and an identical leftover counts as written. |
| major | CC8.1 | Three control statements overstated the code (memory overwrite, hardware-only custody, relay data all sealed). | Reworded to match the code. |
| minor | C1.1, CC7.1 | Tests wrote passphrases, passwords, PINs and nonces as literals (128 CodeQL `rust/hard-coded-cryptographic-value` findings), and test helpers formatted a command's `Result` and output into assertion messages (43 `rust/cleartext-logging` findings). | `crate::test_secrets` draws every test secret at run time, and assertion messages name only the command line. |
