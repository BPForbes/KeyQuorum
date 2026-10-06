// Mirrors the JSON the relay's routes return (src/relay/server.rs,
// src/relay/service.rs, src/relay/client.rs, src/key_tree.rs and
// src/relay/device_directory.rs in the KeyQuorum crate). The Rust side is
// the source of truth; these types only describe what it sends. None of
// them ever carries a bearer: the relay stores and returns key ids, scopes
// and hashes of the audit chain, never the `kq_…` token itself.

export interface HealthResponse {
  status: string;
}

export interface ReadyResponse {
  status: string;
  /** The persistence backend the relay reached (`sqlite` or `mongodb`). */
  store: string;
}

export interface ErrorBody {
  error: string;
}

export interface KeyCheckResponse {
  valid: boolean;
  id?: number;
  scope?: string;
  label?: string;
  recipient_fingerprint?: string;
}

export interface ApiKeyView {
  id: number;
  scope: string;
  recipient_fingerprint: string | null;
  label: string | null;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface ApiKeyEvent {
  id: number;
  key_id: number;
  event: string;
  actor: string;
  related_key_id: number | null;
  occurred_at: string;
  /** This row's link in the relay's hash-chained audit trail. */
  entry_hash: string;
}

export interface ProviderIdentityResponse {
  /** Standard base64 of the `provider.kqcert` bytes. */
  certificate: string;
  /** Standard base64 of the 64-byte Ed25519 signature over the challenge. */
  signature: string;
}

export interface PublicNode {
  label: string;
  parent_label: string | null;
  threshold: number | null;
  is_active: boolean;
  encryption_fingerprint: string | null;
  encryption_public_key: string | null;
}

export interface PublicEdge {
  from: string;
  to: string;
}

export interface PublicTree {
  label: string;
  generation: number;
  nodes: PublicNode[];
  whitelist: PublicEdge[];
  links: PublicEdge[];
}

export interface DeviceSlotDescriptor {
  label: string;
  encryption_public: string;
  signing_public: string;
}

export interface DeviceDescriptor {
  device_id: string;
  verify_key: string;
  slots: DeviceSlotDescriptor[];
  signature: string;
}

/** The key this tab signed in with, as `POST /keycheck` described it. */
export interface Session {
  id: number | null;
  scope: string;
  label: string | null;
  recipientFingerprint: string | null;
}

/** One request the console made, for the Activity panel. Never the bearer. */
export interface RequestRecord {
  seq: number;
  at: string;
  method: string;
  path: string;
  /** HTTP status, or null when the request never reached the relay. */
  status: number | null;
  ok: boolean;
  ms: number;
  note: string;
}
