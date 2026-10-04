-- KeyQuorum local storage schema.
--
-- A splittable secret ("key") is organized as a tree of `key_nodes`: a
-- SPLIT node divides its value via Shamir's Secret Sharing among its
-- children with its own threshold, recursively, down to LEAF nodes, each
-- of which is a share sealed to one registered hardware key. A protected
-- file references a key's root and is unlocked by reconstructing that
-- key's tree.

CREATE TABLE IF NOT EXISTS hardware_keys (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL,
    key_type      TEXT NOT NULL CHECK (key_type IN ('encryption', 'signing')),
    fingerprint   TEXT NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_at    TEXT
);

-- A splittable secret in its own right, independent of any file — "key
-- split" is a capability on its own, not just a mechanism for protecting
-- files (see key_nodes below).
CREATE TABLE IF NOT EXISTS keys (
    id                 INTEGER PRIMARY KEY,
    label              TEXT NOT NULL,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    public_generation  INTEGER NOT NULL DEFAULT 1 CHECK (public_generation > 0),
    -- hardware: one key is one device unless a placement says otherwise.
    -- logical: several slots on one container may satisfy Shamir together.
    custody_mode       TEXT NOT NULL DEFAULT 'hardware'
                       CHECK (custody_mode IN ('hardware', 'logical')),
    minimum_physical_devices INTEGER NOT NULL DEFAULT 1
                       CHECK (minimum_physical_devices >= 1),
    -- none: Shamir (and the device count) is enough.
    -- parent: each contributing leaf also needs its direct parent's signature.
    unlock_approval    TEXT NOT NULL DEFAULT 'none'
                       CHECK (unlock_approval IN ('none', 'parent'))
);

-- Binds a registered hardware key to a physical container. Absent row:
-- the key is its own device (the original one-key one-device exchange).
-- Written only from a container descriptor this process opened.
CREATE TABLE IF NOT EXISTS device_placements (
    hardware_key_id INTEGER PRIMARY KEY REFERENCES hardware_keys(id) ON DELETE CASCADE,
    device_id       BLOB NOT NULL CHECK (length(device_id) = 16),
    slot_label      TEXT NOT NULL
);

-- A restructure a non-root authorizer has signed but that is not effective
-- until the parent countersigns. `org_updates` is written only then.
CREATE TABLE IF NOT EXISTS pending_org_actions (
    id                   INTEGER PRIMARY KEY,
    key_id               INTEGER REFERENCES keys(id) ON DELETE CASCADE,
    tree_label           TEXT NOT NULL,
    authorizer_label     TEXT NOT NULL,
    countersigner_label  TEXT NOT NULL,
    generation           INTEGER NOT NULL CHECK (generation > 0),
    proposal_hash        BLOB NOT NULL UNIQUE,
    proposal             BLOB NOT NULL,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- One row per node in a key's split tree. A node is either a SPLIT node
-- (threshold set, hardware_key_id/wrapped_share NULL — reconstructing it
-- means Shamir-recovering at least `threshold` of its children's values)
-- or a LEAF (hardware_key_id set, threshold NULL — a share sealed to one
-- specific hardware key). wrapped_share may be NULL on a leaf when this
-- store only holds topology for that person (a peer or sibling whose
-- sealed share lives on their device). parent_id NULL marks a key's root
-- node. A flat "M-of-N hardware keys" quorum is just a one-level tree: a
-- single SPLIT root with N LEAF children.
CREATE TABLE IF NOT EXISTS key_nodes (
    id                INTEGER PRIMARY KEY,
    key_id            INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    parent_id         INTEGER REFERENCES key_nodes(id) ON DELETE CASCADE,
    label             TEXT NOT NULL,
    threshold         INTEGER CHECK (threshold IS NULL OR threshold > 0),
    hardware_key_id   INTEGER REFERENCES hardware_keys(id) ON DELETE RESTRICT,
    wrapped_share     BLOB,
    -- 0 after a PSS eviction; reconstruct ignores inactive children.
    is_active         INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    CHECK (
        (threshold IS NOT NULL AND hardware_key_id IS NULL AND wrapped_share IS NULL)
        OR (threshold IS NULL AND hardware_key_id IS NOT NULL)
    )
);

-- A signing-purpose hardware key must never become a quorum leaf: nobody
-- could ever unwrap it, since it isn't an encryption key. key_type isn't
-- checked anywhere else at the SQL layer, so this is load-bearing.
CREATE TRIGGER IF NOT EXISTS trg_key_nodes_guard_key_type
BEFORE INSERT ON key_nodes
FOR EACH ROW
WHEN NEW.hardware_key_id IS NOT NULL
AND (SELECT key_type FROM hardware_keys WHERE id = NEW.hardware_key_id) != 'encryption'
BEGIN
    SELECT RAISE(ABORT, 'cannot make a signing-only hardware key a quorum leaf');
END;

-- Same guard when `bind --public-key-file` reassigns a leaf's
-- hardware_key_id (node id stays put so pairings survive the rebind).
CREATE TRIGGER IF NOT EXISTS trg_key_nodes_guard_key_type_on_update
BEFORE UPDATE OF hardware_key_id ON key_nodes
FOR EACH ROW
WHEN NEW.hardware_key_id IS NOT NULL
AND (SELECT key_type FROM hardware_keys WHERE id = NEW.hardware_key_id) != 'encryption'
BEGIN
    SELECT RAISE(ABORT, 'cannot make a signing-only hardware key a quorum leaf');
END;

CREATE INDEX IF NOT EXISTS idx_key_nodes_parent ON key_nodes (parent_id);
CREATE INDEX IF NOT EXISTS idx_key_nodes_key ON key_nodes (key_id);
CREATE INDEX IF NOT EXISTS idx_key_nodes_hardware_key ON key_nodes (hardware_key_id);

-- Supervisor whitelist: node `node_id` may form a cross-branch pairing
-- with the node whose label is `peer_label` in the same key tree.
CREATE TABLE IF NOT EXISTS key_node_bridges (
    node_id     INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
    peer_label  TEXT NOT NULL,
    PRIMARY KEY (node_id, peer_label)
);

CREATE INDEX IF NOT EXISTS idx_key_node_bridges_peer
    ON key_node_bridges (peer_label);

-- Established undirected pairing (no channel key material).
-- node_a_id < node_b_id so each pair has one row.
CREATE TABLE IF NOT EXISTS key_node_links (
    node_a_id       INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
    node_b_id       INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
    established_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (node_a_id, node_b_id),
    CHECK (node_a_id < node_b_id)
);

-- A hardware-key-quorum-protected file. No content hash is stored: an
-- unkeyed hash of the plaintext would leak a fingerprint of it
-- independent of whatever protects the file — AES-256-GCM's own
-- authentication tag is what verifies integrity on unlock.
CREATE TABLE IF NOT EXISTS files (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    encrypted_path    TEXT NOT NULL UNIQUE,
    key_id            INTEGER NOT NULL REFERENCES keys(id) ON DELETE RESTRICT,
    nonce             BLOB NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- UTC cutoff `YYYY-MM-DD HH:MM:00`. NULL means the file does not expire.
    -- Same convention as `password_locked_files.expires_at`; see quorum.rs.
    expires_at        TEXT
);

-- Audit log of unlock attempts, successful or not.
CREATE TABLE IF NOT EXISTS unlock_events (
    id              INTEGER PRIMARY KEY,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    attempted_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    success         INTEGER NOT NULL CHECK (success IN (0, 1)),
    keys_presented  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_unlock_events_file
    ON unlock_events (file_id);

-- Password manager: each entry is encrypted independently with a key
-- derived (Argon2id) from the vault master password and this row's own
-- salt, so nonces and salts never need to be coordinated across rows.
CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL,
    username      TEXT,
    kdf_salt      BLOB NOT NULL,
    nonce         BLOB NOT NULL,
    ciphertext    BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- A file locked with a single password rather than a hardware-key quorum:
-- a lighter-weight protection tier, independent of the `files` / `keys`
-- quorum mechanism above. No separate content hash is stored: AES-256-GCM's
-- own authentication tag already proves the decrypted plaintext is intact,
-- and an unkeyed hash of the plaintext would otherwise leak a
-- password-independent fingerprint of it.
CREATE TABLE IF NOT EXISTS password_locked_files (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    encrypted_path    TEXT NOT NULL UNIQUE,
    kdf_salt          BLOB NOT NULL,
    nonce             BLOB NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- UTC cutoff `YYYY-MM-DD HH:MM:00`. NULL means the file does not expire.
    -- A late unlock or share redemption deletes the ciphertext from disk.
    expires_at        TEXT
);

-- Time-limited, revocable share links. Only a hash of each share's bearer
-- token is stored, matching how the token is looked up on redemption; the
-- raw token itself is never persisted, only handed to the caller once.
CREATE TABLE IF NOT EXISTS credential_shares (
    id              INTEGER PRIMARY KEY,
    credential_id   INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at      TEXT NOT NULL,
    max_uses        INTEGER CHECK (max_uses IS NULL OR max_uses > 0),
    use_count       INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS file_shares (
    id              INTEGER PRIMARY KEY,
    file_id         INTEGER NOT NULL REFERENCES password_locked_files(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at      TEXT NOT NULL,
    max_uses        INTEGER CHECK (max_uses IS NULL OR max_uses > 0),
    use_count       INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    revoked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_credential_shares_credential
    ON credential_shares (credential_id);

CREATE INDEX IF NOT EXISTS idx_file_shares_file
    ON file_shares (file_id);

-- Optional 4-digit-PIN gate on a resource, layered on top of (never
-- instead of) that resource's real protection (master password, quorum,
-- or a recipient's real public key for shared content) — see pin.rs for
-- the honest caveat on what the attempt-lockout below can and can't
-- guarantee against an attacker with an offline copy of this database.
-- One generic table rather than duplicating these columns across five
-- different resource tables, since SQLite has no clean polymorphic FK;
-- mirrors how credential_shares/file_shares already are structurally
-- the same shape.
CREATE TABLE IF NOT EXISTS pins (
    id                  INTEGER PRIMARY KEY,
    resource_type       TEXT NOT NULL CHECK (resource_type IN (
        'credential', 'locked_file', 'quorum_file',
        'credential_share', 'file_share'
    )),
    resource_id         INTEGER NOT NULL,
    pin_hash            BLOB NOT NULL,
    pin_salt            BLOB NOT NULL,
    require_every_use   INTEGER NOT NULL DEFAULT 0 CHECK (require_every_use IN (0, 1)),
    ttl_seconds         INTEGER NOT NULL CHECK (ttl_seconds > 0),
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    locked_at           TEXT,
    unlocked_until       TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (resource_type, resource_id)
);

-- Private N-member sign bridges. Each person owns their node keys in their
-- own storage: this database holds public roster metadata plus at most the
-- sealed bridge secret for *local* members. Other members receive a
-- per-recipient package (KQPB) sealed to their encryption public key.
-- `uid` is stable across machines and key rotations; `salt` is redrawn
-- with the Ed25519 keypair on every membership-loss rotation.
CREATE TABLE IF NOT EXISTS private_bridges (
    id            INTEGER PRIMARY KEY,
    uid           TEXT NOT NULL UNIQUE,
    key_id        INTEGER REFERENCES keys(id) ON DELETE SET NULL,
    label         TEXT,
    generation    INTEGER NOT NULL CHECK (generation > 0),
    public_key    BLOB NOT NULL,
    salt          BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    destroyed_at  TEXT
);

-- Signing members (`member`) and department/CXO supervisors who must be
-- notified but do not hold the shared signing secret (`supervisor`).
-- Direct parents of members are always on this roster (e.g. M.S.2 implies M.S).
CREATE TABLE IF NOT EXISTS private_bridge_members (
    bridge_id               INTEGER NOT NULL REFERENCES private_bridges(id) ON DELETE CASCADE,
    node_label              TEXT NOT NULL,
    encryption_public_key   BLOB NOT NULL,
    signing_public_key      BLOB,
    role                    TEXT NOT NULL CHECK (role IN ('member', 'supervisor')),
    is_local                INTEGER NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1)),
    PRIMARY KEY (bridge_id, node_label),
    CHECK (
        (role = 'member' AND signing_public_key IS NOT NULL
            AND length(signing_public_key) = 32)
        OR (role = 'supervisor' AND signing_public_key IS NULL)
    )
);

-- Sealed `wrap_salt || bridge_ed25519_sk` for a local member only.
-- wrap_salt binds the ciphertext to this member row so a copied blob fails.
CREATE TABLE IF NOT EXISTS private_bridge_sealed_keys (
    bridge_id       INTEGER NOT NULL,
    node_label      TEXT NOT NULL,
    wrap_salt       BLOB NOT NULL,
    wrapped_secret  BLOB NOT NULL,
    PRIMARY KEY (bridge_id, node_label),
    FOREIGN KEY (bridge_id, node_label)
        REFERENCES private_bridge_members(bridge_id, node_label)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bridge_events (
    id            INTEGER PRIMARY KEY,
    bridge_id     INTEGER NOT NULL REFERENCES private_bridges(id) ON DELETE CASCADE,
    event_type    TEXT NOT NULL CHECK (event_type IN (
        'created', 'imported', 'member_removed', 'rotated', 'destroyed'
    )),
    detail        TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_private_bridges_key ON private_bridges (key_id);
CREATE INDEX IF NOT EXISTS idx_bridge_events_bridge ON bridge_events (bridge_id);

-- Relay API key loaded via `keyquorum loadkey` (or first `--api-key` use).
-- The service stores only `hex(SHA-256(raw))`. This personal DB stores that
-- same hash for `POST /keycheck` revalidation, plus the bearer (needed to
-- call authenticated routes) sealed with a random AES-256-GCM wrapping key
-- kept in this owner-only file. Never commit this database.
CREATE TABLE IF NOT EXISTS relay_credentials (
    relay_url       TEXT NOT NULL,
    scope           TEXT NOT NULL CHECK (scope IN (
        'inbox.push', 'inbox.pull', 'admin', 'device.push', 'device.pull'
    )),
    key_hash        TEXT NOT NULL,
    wrap_key        BLOB NOT NULL,
    wrap_nonce      BLOB NOT NULL,
    wrapped_token   BLOB NOT NULL,
    remote_id       INTEGER,
    label           TEXT,
    stored_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_checked_at TEXT,
    PRIMARY KEY (relay_url, scope)
);

-- Authenticated organization updates applied from a `.kqpb` envelope:
-- hardware-key reissue and key-tree restructure. One row per accepted
-- update, which is also the replay guard — the UNIQUE constraint makes a
-- re-delivered envelope a no-op at the SQL layer even if the sequence
-- check above it were ever bypassed. `sequence` is the reissue counter for
-- a key reissue and the tree's public generation for a restructure.
CREATE TABLE IF NOT EXISTS org_updates (
    id                INTEGER PRIMARY KEY,
    kind              TEXT NOT NULL CHECK (kind IN ('key_reissue', 'tree_restructure')),
    -- `keys.label` this update is scoped to, or '' for a store-wide reissue
    -- that is not tied to one split tree.
    tree_label        TEXT NOT NULL,
    subject_label     TEXT NOT NULL,
    sequence          INTEGER NOT NULL CHECK (sequence > 0),
    authorizer_label  TEXT NOT NULL,
    detail            TEXT NOT NULL,
    applied_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (kind, tree_label, subject_label, sequence)
);

CREATE INDEX IF NOT EXISTS idx_org_updates_subject
    ON org_updates (kind, tree_label, subject_label);

-- Stable cryptographic identity, independent of the dotted tree path and
-- of which device currently holds the private keys. `id` is random, not a
-- rowid, so a copy on another store is the same identity.
CREATE TABLE IF NOT EXISTS key_identities (
    id               BLOB PRIMARY KEY CHECK (length(id) = 16),
    label            TEXT NOT NULL UNIQUE,
    parent_label     TEXT,
    enc_public       BLOB NOT NULL CHECK (length(enc_public) = 32),
    sign_public      BLOB NOT NULL CHECK (length(sign_public) = 32),
    enc_fingerprint  TEXT NOT NULL,
    sign_fingerprint TEXT NOT NULL
);

-- Device-local possession. A ghost keeps the hierarchy row and has no
-- usable private key. Absence of a row means the identity is unknown here.
CREATE TABLE IF NOT EXISTS key_possession (
    identity_id BLOB PRIMARY KEY REFERENCES key_identities(id) ON DELETE CASCADE,
    state       TEXT NOT NULL CHECK (state IN ('active', 'ghost')),
    generation  INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0)
);

-- What this store has learned about where an identity is held. Not a
-- global registry: each device records the copies it has seen.
CREATE TABLE IF NOT EXISTS key_provenance (
    identity_id BLOB NOT NULL REFERENCES key_identities(id) ON DELETE CASCADE,
    device_id   BLOB NOT NULL CHECK (length(device_id) = 16),
    state       TEXT NOT NULL CHECK (state IN ('active', 'ghost')),
    PRIMARY KEY (identity_id, device_id)
);

-- In-progress and finished transfers. The package bytes are not stored.
-- `package_hash` is SHA-256 of the signed KQTX bundle.
CREATE TABLE IF NOT EXISTS transfer_transactions (
    id                BLOB PRIMARY KEY CHECK (length(id) = 16),
    operation         TEXT NOT NULL CHECK (operation IN ('copy', 'move')),
    role              TEXT NOT NULL CHECK (role IN ('source', 'destination')),
    state             TEXT NOT NULL CHECK (state IN (
        'prepared', 'transferred', 'writing', 'destination_committed',
        'acknowledged', 'source_finalized', 'completed', 'aborted', 'needs_admin'
    )),
    peer_device_id    BLOB NOT NULL CHECK (length(peer_device_id) = 16),
    root_label        TEXT NOT NULL,
    descendant_mode   TEXT NOT NULL,
    package_hash      BLOB NOT NULL CHECK (length(package_hash) = 32),
    detail            TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- One row per transfer attempt. Detail is labels and reasons only.
CREATE TABLE IF NOT EXISTS transfer_audit (
    id                    INTEGER PRIMARY KEY,
    transaction_id        BLOB NOT NULL,
    operation_type        TEXT NOT NULL,
    source_device_id      BLOB NOT NULL,
    destination_device_id BLOB NOT NULL,
    key_id                BLOB NOT NULL,
    tree_path             TEXT NOT NULL,
    descendant_mode       TEXT NOT NULL,
    result                TEXT NOT NULL,
    detail                TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- A rebuildable cache over `.kqtf` tracked files. The container is the
-- authority for identity, revisions and history; these rows only make them
-- listable and can be dropped and rebuilt from the containers at any time.
-- They hold metadata only: never payload bytes, and no trust state (that
-- depends on keys and changes).
CREATE TABLE IF NOT EXISTS tracked_files (
    file_id      BLOB PRIMARY KEY CHECK (length(file_id) = 16),
    logical_name TEXT NOT NULL,
    scope_root   TEXT,
    history_root BLOB NOT NULL CHECK (length(history_root) = 32),
    head_count   INTEGER NOT NULL CHECK (head_count >= 0),
    event_count  INTEGER NOT NULL CHECK (event_count >= 0)
);

CREATE TABLE IF NOT EXISTS tracked_revisions (
    revision_id     BLOB PRIMARY KEY CHECK (length(revision_id) = 32),
    file_id         BLOB NOT NULL REFERENCES tracked_files(file_id) ON DELETE CASCADE,
    ordinal         INTEGER NOT NULL CHECK (ordinal >= 0),
    parent_ids      BLOB NOT NULL,
    generated_label TEXT NOT NULL,
    user_label      TEXT,
    author_label    TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    is_head         INTEGER NOT NULL CHECK (is_head IN (0, 1))
);

-- The cascade from tracked_files finds a file's revisions through this.
CREATE INDEX IF NOT EXISTS tracked_revisions_by_file ON tracked_revisions (file_id);

CREATE TABLE IF NOT EXISTS tracked_history_index (
    file_id     BLOB NOT NULL REFERENCES tracked_files(file_id) ON DELETE CASCADE,
    sequence    INTEGER NOT NULL CHECK (sequence >= 0),
    event_type  TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    revision_id BLOB,
    actor_label TEXT,
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (file_id, sequence)
);

-- Ties an existing protection gate (a quorum file or a password-locked
-- file) to a tracked `.kqtf`, so the CLI can append what happened at the
-- gate to that file's history. Deliberately no foreign key to the gate
-- tables: a purged gate row must not take its link, and so the record of
-- its expiry, with it. The gates never read this table.
CREATE TABLE IF NOT EXISTS tracked_gate_links (
    id              INTEGER PRIMARY KEY,
    tracked_file_id BLOB NOT NULL,
    gate            TEXT NOT NULL CHECK (gate IN ('quorum', 'password')),
    gate_file_id    INTEGER NOT NULL,
    -- The gate row's ciphertext path and creation time when linked: what
    -- tells the linked file from a later one that was given the same id.
    gate_ref        TEXT NOT NULL,
    kqtf_path       TEXT NOT NULL,
    linked_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tracked_file_id, gate, gate_file_id)
);

CREATE INDEX IF NOT EXISTS tracked_gate_links_by_gate
    ON tracked_gate_links (gate, gate_file_id);

-- Tracked-file histories this store has authenticated: the revision and
-- history root a sender signed in a letter this store accepted. Not a cache
-- over `.kqtf` files (it is not rebuildable from them): it is what a later
-- letter's history is compared against before anyone calls it newer.
CREATE TABLE IF NOT EXISTS tracked_seen_roots (
    file_id      BLOB NOT NULL CHECK (length(file_id) = 16),
    revision_id  BLOB NOT NULL CHECK (length(revision_id) = 32),
    history_root BLOB NOT NULL CHECK (length(history_root) = 32),
    sender_label TEXT NOT NULL,
    seen_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (file_id, revision_id, history_root, sender_label)
);

-- Topology generations this store has held for each tree: the one current
-- when a file command ran, and both sides of every applied restructure. A
-- tracked revision stamped with a generation this store never held is not
-- judged against today's topology (see `file_history::policy`).
CREATE TABLE IF NOT EXISTS tree_generations_seen (
    key_id     INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    seen_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (key_id, generation)
);

-- Which identity and signing key this store saw holding each label, and for
-- which topology generations of the tree (first through last observed).
-- Recorded by every file command from this store's own key registry, so a
-- revision stamped with an older generation can still be checked against the
-- key its author held then, after the label was reissued or reassigned. A
-- store that never ran a file command while a key was current has no
-- evidence for it. See `authority::record_label_evidence`.
CREATE TABLE IF NOT EXISTS label_authority_evidence (
    scope_root      TEXT NOT NULL,
    label           TEXT NOT NULL,
    identity        BLOB NOT NULL CHECK (length(identity) = 16),
    signing_public  BLOB NOT NULL CHECK (length(signing_public) = 32),
    first_generation INTEGER NOT NULL CHECK (first_generation >= 0),
    last_generation  INTEGER NOT NULL CHECK (last_generation >= first_generation),
    PRIMARY KEY (scope_root, label, identity, signing_public)
);

-- Private-bridge approvals of tracked revisions, held only in this store:
-- the KQBS artifact names the bridge, so it never travels in a `.kqtf`.
-- `private_bridge::revision_approved` re-verifies each against the live
-- bridge (same generation, signer still a member) every time it is asked.
CREATE TABLE IF NOT EXISTS tracked_bridge_approvals (
    revision_id BLOB NOT NULL CHECK (length(revision_id) = 32),
    bridge_uid  TEXT NOT NULL,
    artifact    BLOB NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (revision_id, bridge_uid)
);

-- Non-secret defaults the CLI falls back on when a flag is omitted (see
-- `keyquorum use`). Pointers only: the device container, `.kqst` slot tokens,
-- and `relay_credentials` stay the authority for identity and relay auth.
-- Never store passphrases, keys, or bearers here.
CREATE TABLE IF NOT EXISTS profile (
    key   TEXT PRIMARY KEY CHECK (key IN (
        'default_label', 'default_slot_label', 'default_container',
        'default_relay_url', 'cache_enabled'
    )),
    value TEXT NOT NULL
);

-- Parameters a command was last given, reused while they are fresh
-- (`db::cache::TTL_MINUTES`). Non-secret and never an authorization input.
CREATE TABLE IF NOT EXISTS recent_params (
    name    TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    used_at TEXT NOT NULL
);

-- A relay identity check that passed recently, so a following command can
-- skip the provider challenge. Bound to the certificate, the revocation list
-- and the stored key hash; never records a failure or a bearer.
CREATE TABLE IF NOT EXISTS relay_trust_cache (
    relay_url        TEXT PRIMARY KEY,
    cert_fingerprint TEXT NOT NULL,
    krl_digest       TEXT NOT NULL,
    key_hash         TEXT NOT NULL,
    verified_at      TEXT NOT NULL,
    valid_until      TEXT NOT NULL
);

-- Non-secret facts a preflight already looked up (a slot exists, a label's
-- keys are registered), tied to a fingerprint of what they were read from.
-- A mismatch invalidates the row. Never read for a trust decision.
CREATE TABLE IF NOT EXISTS verified_cache (
    kind        TEXT NOT NULL,
    subject     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    PRIMARY KEY (kind, subject)
);

-- Letters `keyquorum inbox` has pulled from a relay, so a later pull resumes
-- after the newest one and a letter is opened once. The sealed bytes stay in
-- the inbox directory; nothing here is secret.
CREATE TABLE IF NOT EXISTS inbox_letters (
    relay_url TEXT NOT NULL,
    letter_id INTEGER NOT NULL,
    kind      INTEGER NOT NULL,
    status    TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'handled')),
    PRIMARY KEY (relay_url, letter_id)
);

-- Each store's inbox ring for one relay (`db::inbox`, `src/ring.rs`): the
-- pulled letters held unopened, at most `db::inbox::RING_CAPACITY`. The sealed
-- letter is a file in the inbox directory; its slot keeps the hash, so a file
-- changed on disk is refused before it is opened. Opening a letter (or
-- `inbox drop`) releases its slot and deletes the file. A full ring stops the
-- pull; the rest stay on the relay for the next one.
CREATE TABLE IF NOT EXISTS inbox_rings (
    relay_url   TEXT PRIMARY KEY,
    capacity    INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 1024),
    read_index  INTEGER NOT NULL DEFAULT 0,
    write_index INTEGER NOT NULL DEFAULT 0,
    size        INTEGER NOT NULL DEFAULT 0,
    CHECK (read_index >= 0 AND read_index < capacity),
    CHECK (write_index >= 0 AND write_index < capacity),
    CHECK (size >= 0 AND size <= capacity),
    CHECK ((read_index + size) % capacity = write_index)
);

CREATE TABLE IF NOT EXISTS inbox_slots (
    relay_url     TEXT NOT NULL REFERENCES inbox_rings (relay_url) ON DELETE CASCADE,
    slot_index    INTEGER NOT NULL,
    letter_id     INTEGER NOT NULL,
    envelope_kind INTEGER NOT NULL CHECK (envelope_kind BETWEEN 0 AND 255),
    content_hash  TEXT NOT NULL,
    received_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (relay_url, slot_index),
    UNIQUE (relay_url, letter_id)
);

-- Per-person outbox ring buffer (`src/outbox.rs`): a fixed number of slots
-- holding the sealed letters (.kqpb) a person has queued for trusted
-- recipients. The
-- write pointer takes new items; only a send to the trusted recipient moves
-- the read pointer, and a sent slot is wiped and freed. `size` is how many
-- slots are held (queued, not yet sent); a full ring refuses new items and
-- never overwrites one that has not been sent.
CREATE TABLE IF NOT EXISTS outbox_rings (
    owner_label TEXT PRIMARY KEY,
    capacity    INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 1024),
    read_index  INTEGER NOT NULL DEFAULT 0,
    write_index INTEGER NOT NULL DEFAULT 0,
    size        INTEGER NOT NULL DEFAULT 0,
    sent_total  INTEGER NOT NULL DEFAULT 0,
    CHECK (read_index >= 0 AND read_index < capacity),
    CHECK (write_index >= 0 AND write_index < capacity),
    CHECK (size >= 0 AND size <= capacity),
    CHECK ((read_index + size) % capacity = write_index)
);

CREATE TABLE IF NOT EXISTS outbox_slots (
    owner_label     TEXT NOT NULL REFERENCES outbox_rings (owner_label) ON DELETE CASCADE,
    slot_index      INTEGER NOT NULL,
    -- The letter's kind byte (`envelope::KIND_*`); only KQPB letters are held.
    envelope_kind   INTEGER NOT NULL CHECK (envelope_kind BETWEEN 0 AND 255),
    recipient_label TEXT NOT NULL,
    content         BLOB NOT NULL,
    content_hash    TEXT NOT NULL,
    queued_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- A send's claim on the head while it delivers outside any transaction
    -- (`outbox::send_next`): a random token and when it was taken (Unix
    -- seconds). It lapses after `outbox::CLAIM_LEASE_SECS`.
    claim_token     TEXT,
    claimed_at      INTEGER,
    PRIMARY KEY (owner_label, slot_index)
);

-- Letters the outbox turned away at departure (`src/outbox.rs`,
-- `outbox::Refusal`): who it was for, its kind and exchange step when known,
-- and the rule it broke. Never the letter, its hash or anything sealed in it.
-- Only the newest `outbox::MAX_REFUSALS_KEPT` per owner are kept.
CREATE TABLE IF NOT EXISTS outbox_refusals (
    id              INTEGER PRIMARY KEY,
    owner_label     TEXT NOT NULL,
    recipient_label TEXT NOT NULL,
    envelope_kind   INTEGER CHECK (envelope_kind BETWEEN 0 AND 255),
    step            TEXT,
    rule            TEXT NOT NULL CHECK (rule IN ('no_passport', 'device_letter',
                        'unrecognised_destination', 'out_of_order', 'ring_full',
                        'oversized', 'tampered')),
    refused_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS outbox_refusals_owner ON outbox_refusals (owner_label, id);
