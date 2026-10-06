-- Server-only mailbox + public-tree database. Never store wrapped shares
-- or private key material here. Envelopes are opaque blobs indexed by the
-- recipient encryption-key fingerprint from the outer .kqpb header.
-- `device_mailbox` is the same idea for device copy, move, and relocate
-- letters (KQPB kinds 9–12 only). `device_directory` is a public descriptor
-- (device id, verify key, slot public keys) and never a slot secret.
-- `org_tree_docs` is a document store: one JSON public tree per label
-- (the full org context). Pushing envelopes updates those documents.
-- Personal devices translate a sliced copy into local SQLite.

-- Legacy single-row issuer table. New mailboxes leave this empty.
-- API keys are not minted over HTTP.
CREATE TABLE IF NOT EXISTS licensee_issuer (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    key_hash    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id                      INTEGER PRIMARY KEY,
    key_hash                TEXT NOT NULL UNIQUE,
    scope                   TEXT NOT NULL CHECK (scope IN (
        'inbox.push', 'inbox.pull', 'admin', 'device.push', 'device.pull'
    )),
    recipient_fingerprint   TEXT,
    label                   TEXT,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at              TEXT,
    revoked_at              TEXT,
    last_used_at            TEXT,
    CHECK (
        (scope IN ('inbox.pull', 'device.pull') AND recipient_fingerprint IS NOT NULL)
        OR (scope NOT IN ('inbox.pull', 'device.pull') AND recipient_fingerprint IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS mailbox (
    id                      INTEGER PRIMARY KEY,
    recipient_fingerprint   TEXT NOT NULL,
    envelope                BLOB NOT NULL,
    content_hash            TEXT NOT NULL,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- UTC cutoff `YYYY-MM-DD HH:MM:00`. NULL means the envelope does not expire.
    -- The host scan (and inbox pull) delete expired rows so they cannot be fetched.
    expires_at              TEXT,
    UNIQUE (recipient_fingerprint, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_mailbox_recipient
    ON mailbox (recipient_fingerprint, id);

-- Opaque device-workflow letters. Same indexing rule as `mailbox`:
-- fingerprint from the outer header, payload stored verbatim.
CREATE TABLE IF NOT EXISTS device_mailbox (
    id                      INTEGER PRIMARY KEY,
    recipient_fingerprint   TEXT NOT NULL,
    package                 BLOB NOT NULL,
    content_hash            TEXT NOT NULL,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- UTC `YYYY-MM-DD HH:MM:SS`. Every device letter expires; the host scan
    -- and device pulls delete expired rows so storage stays bounded.
    expires_at              TEXT,
    UNIQUE (recipient_fingerprint, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_device_mailbox_recipient
    ON device_mailbox (recipient_fingerprint, id);

-- Public device descriptor. The document is signed by the device key.
-- Slot rows are public keys only.
CREATE TABLE IF NOT EXISTS device_directory (
    device_id     TEXT PRIMARY KEY,
    document      TEXT NOT NULL,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Full public split-tree as a JSON document (no wrapped shares, no private keys).
CREATE TABLE IF NOT EXISTS org_tree_docs (
    label         TEXT PRIMARY KEY,
    generation    INTEGER NOT NULL CHECK (generation > 0),
    document      TEXT NOT NULL,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Privileged provider-auth attempts. Never store bearers, private keys,
-- challenge nonces, or other reusable secrets.
CREATE TABLE IF NOT EXISTS provider_auth_events (
    id                      INTEGER PRIMARY KEY,
    operation               TEXT NOT NULL,
    provider_id             TEXT,
    network_id              TEXT,
    hardware_fingerprints   TEXT,
    success                 INTEGER NOT NULL CHECK (success IN (0, 1)),
    attempted_at            TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    -- Hash chain (`relay::audit`): hex SHA-256 of the previous row and of
    -- this row's fields chained onto it.
    prev_hash               TEXT,
    entry_hash              TEXT
);

-- API-key lifecycle audit trail: one row each time a key is created,
-- rotated or revoked, by the host CLI or by an admin key over HTTP.
-- `actor` is `host` or `admin:<api_keys.id>`. Never stores a bearer or
-- its hash; `related_key_id` is the key a rotation replaced.
CREATE TABLE IF NOT EXISTS api_key_events (
    id              INTEGER PRIMARY KEY,
    api_key_id      INTEGER NOT NULL,
    event           TEXT NOT NULL CHECK (event IN ('created', 'rotated', 'revoked')),
    actor           TEXT NOT NULL,
    related_key_id  INTEGER,
    occurred_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    prev_hash       TEXT,
    entry_hash      TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_key_events_key
    ON api_key_events (api_key_id, id);

-- Relay-key signatures over each audit table's chain head (`relay::audit`).
-- `certificate` is the public KeyQuorum-signed `provider.kqcert` naming the
-- signing key; an anchor counts only if that certificate was valid at
-- `signed_at`. Nothing secret is stored here.
CREATE TABLE IF NOT EXISTS audit_anchors (
    id          INTEGER PRIMARY KEY,
    table_name  TEXT NOT NULL CHECK (table_name IN ('api_key_events', 'provider_auth_events')),
    row_count   INTEGER NOT NULL CHECK (row_count > 0),
    head_hash   TEXT NOT NULL,
    signed_at   TEXT NOT NULL,
    certificate BLOB NOT NULL,
    signature   BLOB NOT NULL
);

-- Whom a customer key was sealed to when the host issued it
-- (`relay::key_delivery`): the recipient's X25519 public key, the relay URL
-- the issue names, the device it is bound to if any, the licence statement
-- it carried, and how it travelled (`bundle`, by the file's SHA-256, or a
-- mailbox `letter`, by its id). A rotation reuses the row of the key it
-- replaces. Never a bearer, a hash of one, or the sealed bytes.
CREATE TABLE IF NOT EXISTS api_key_deliveries (
    api_key_id            INTEGER PRIMARY KEY REFERENCES api_keys(id),
    recipient_public_key  BLOB NOT NULL CHECK (length(recipient_public_key) = 32),
    relay_url             TEXT NOT NULL,
    device_id             BLOB CHECK (device_id IS NULL OR length(device_id) = 16),
    licence               TEXT,
    via                   TEXT NOT NULL CHECK (via IN ('bundle', 'letter')),
    letter_id             INTEGER,
    bundle_sha256         TEXT,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- The provider's own records of whom it licensed (the operator console,
-- `relay::operator`). A licence is the provider's record of terms for one
-- client; the signed statement each issued key carries is rendered from it
-- (`licence::statement`). Voiding a licence revokes the keys linked to it. No
-- bearer, key hash or sealed bytes here, and nothing a client ever reads.
CREATE TABLE IF NOT EXISTS licences (
    id           INTEGER PRIMARY KEY,
    client       TEXT NOT NULL CHECK (length(client) BETWEEN 1 AND 200),
    terms        TEXT NOT NULL CHECK (length(terms) <= 8192),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- UTC `YYYY-MM-DD HH:MM:SS`, like `api_keys.expires_at`. NULL: no end.
    expires_at   TEXT,
    voided_at    TEXT,
    void_reason  TEXT CHECK (void_reason IS NULL OR length(void_reason) <= 500)
);

-- Which licence a key was issued under. Additive: `api_keys` is unchanged.
CREATE TABLE IF NOT EXISTS licence_keys (
    api_key_id  INTEGER PRIMARY KEY REFERENCES api_keys(id),
    licence_id  INTEGER NOT NULL REFERENCES licences(id)
);

CREATE INDEX IF NOT EXISTS idx_licence_keys_licence
    ON licence_keys (licence_id);

-- What the relay saw each known key do, by hour: requests it served and
-- requests it refused because of the key itself (`revoked`, `expired`,
-- `scope`). One row per key, hour, route and outcome, counted in place, so the
-- rows are bounded by the keys the provider issued, not by traffic. Unknown
-- bearers are never recorded (an anonymous caller could grow the table). The
-- scan drops rows past `activity::RETENTION_DAYS`. Not part of the audit
-- chain: it is a usage view, not evidence.
CREATE TABLE IF NOT EXISTS access_activity (
    api_key_id  INTEGER NOT NULL REFERENCES api_keys(id),
    hour        TEXT NOT NULL,
    route       TEXT NOT NULL CHECK (route IN (
        'inbox', 'devices', 'trees', 'audit', 'other'
    )),
    outcome     TEXT NOT NULL CHECK (outcome IN ('ok', 'revoked', 'expired', 'scope')),
    count       INTEGER NOT NULL CHECK (count > 0),
    PRIMARY KEY (api_key_id, hour, route, outcome)
);

-- What each operator did in the console, by the identity Cloudflare Access
-- verified. The key lifecycle itself is in the hash-chained `api_key_events`
-- (whose actor is `host` for anyone holding the operator lock); this adds who.
-- Never a lock, bearer, hash or sealed bytes. Not hash-chained.
CREATE TABLE IF NOT EXISTS operator_actions (
    id           INTEGER PRIMARY KEY,
    operator     TEXT NOT NULL CHECK (length(operator) BETWEEN 1 AND 320),
    action       TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
    subject      TEXT CHECK (subject IS NULL OR length(subject) <= 200),
    success      INTEGER NOT NULL CHECK (success IN (0, 1)),
    occurred_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
