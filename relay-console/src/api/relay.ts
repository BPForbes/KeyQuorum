// The only bridge to the relay: one `fetch` per console action against the
// origin this page was served from, with the signed-in key as a bearer.
// The key lives in this object's memory for the life of the tab and is
// never written to localStorage, sessionStorage, a cookie or the URL.
// Every request is recorded for the Activity panel by method, path,
// status and duration, never by header or body.
import type {
  ApiKeyEvent,
  ApiKeyView,
  DeviceDescriptor,
  ErrorBody,
  HealthResponse,
  KeyCheckResponse,
  ProviderIdentityResponse,
  PublicTree,
  ReadyResponse,
  RequestRecord,
} from "./types";

export class RelayError extends Error {
  constructor(
    readonly status: number | null,
    message: string,
    readonly retryAfterSeconds: number | null = null,
  ) {
    super(message);
    this.name = "RelayError";
  }

  get unauthorized(): boolean {
    return this.status === 401;
  }

  get forbidden(): boolean {
    return this.status === 403;
  }
}

/** Standard base64 of a fresh 32-byte challenge for `POST /provider-identity`. */
export function randomChallenge(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

/** Hex SHA-256 of standard-base64 bytes, so the operator can compare the
 * certificate the relay presents with the file they installed. */
export async function sha256OfBase64(base64: string): Promise<string> {
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Length in bytes of standard-base64 content. */
export function base64Length(base64: string): number {
  return atob(base64).length;
}

const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

export class RelayClient {
  private seq = 0;

  constructor(
    private token: string | null,
    private readonly record: (entry: RequestRecord) => void,
  ) {}

  /** Replace the bearer this client sends (null signs out). */
  setToken(token: string | null): void {
    this.token = token;
  }

  get signedIn(): boolean {
    return this.token !== null;
  }

  private async request<T>(method: string, path: string, options: { body?: unknown; auth?: boolean; expectBody?: boolean } = {}): Promise<T> {
    const { body, auth = true, expectBody = true } = options;
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (auth && this.token) headers.authorization = `Bearer ${this.token}`;
    const started = performance.now();
    const seq = ++this.seq;
    const at = new Date().toISOString();
    const done = (status: number | null, ok: boolean, note: string) =>
      this.record({ seq, at, method, path, status, ok, ms: Math.round(performance.now() - started), note });
    let response: Response;
    try {
      response = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      done(null, false, `no answer from the relay: ${message}`);
      throw new RelayError(null, `The relay did not answer (${message}).`);
    }
    const length = Number(response.headers.get("content-length") ?? "0");
    if (length > MAX_RESPONSE_BYTES) {
      done(response.status, false, "response too large");
      throw new RelayError(response.status, "The relay's answer was too large to show.");
    }
    const text = await response.text();
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const parsed = JSON.parse(text) as ErrorBody;
        if (parsed && typeof parsed.error === "string") message = parsed.error;
      } catch {
        // A proxy's own error page: the status is all we show.
      }
      const retry = response.headers.get("retry-after");
      done(response.status, false, message);
      throw new RelayError(response.status, message, retry ? Number(retry) : null);
    }
    done(response.status, true, "ok");
    if (!expectBody || text.length === 0) return undefined as T;
    return JSON.parse(text) as T;
  }

  health(): Promise<HealthResponse> {
    return this.request("GET", "/health", { auth: false });
  }

  ready(): Promise<ReadyResponse> {
    return this.request("GET", "/ready", { auth: false });
  }

  /** The relay's identity over a fresh challenge. This page shows what was
   * presented; verifying it against the KeyQuorum root is the client's job
   * (`keyquorum loadkey`), not this page's. */
  providerIdentity(): Promise<ProviderIdentityResponse> {
    return this.request("POST", "/provider-identity", { auth: false, body: { challenge: randomChallenge() } });
  }

  /** `POST /keycheck` with the bearer this tab is signing in with. */
  checkToken(token: string): Promise<KeyCheckResponse> {
    return this.request("POST", "/keycheck", { auth: false, body: { token } });
  }

  /** `POST /keycheck` with a stored `hex(SHA-256(raw))`, never a bearer. */
  checkHash(keyHash: string): Promise<KeyCheckResponse> {
    return this.request("POST", "/keycheck", { auth: false, body: { key_hash: keyHash } });
  }

  listKeys(): Promise<ApiKeyView[]> {
    return this.request("GET", "/api-keys");
  }

  revokeKey(id: number): Promise<void> {
    return this.request("POST", `/api-keys/${encodeURIComponent(String(id))}/revoke`, { expectBody: false });
  }

  auditEvents(): Promise<ApiKeyEvent[]> {
    return this.request("GET", "/audit/api-keys");
  }

  treeContext(label: string): Promise<PublicTree> {
    return this.request("GET", `/trees/${encodeURIComponent(label)}/context`);
  }

  device(deviceId: string): Promise<DeviceDescriptor> {
    return this.request("GET", `/devices/${encodeURIComponent(deviceId)}`);
  }
}
