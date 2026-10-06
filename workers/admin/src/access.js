// Verifies the signed login token Cloudflare Access adds to every request it
// lets through (the Cf-Access-Jwt-Assertion header). The admin Worker checks it
// itself, so a mistake in the Access application's policy or hostname cannot
// expose the operator routes: with no valid token the Worker serves nothing.
//
// Checked: an RS256 signature by a key in the team's published key set, the
// issuer (the team domain), the audience (this application's AUD tag) and the
// expiry. Anything else, including a missing configuration, is a refusal.

const CLOCK_SKEW_SECONDS = 60;
const JWKS_TTL_MS = 60 * 60 * 1000;

let cached = { teamDomain: null, keys: null, fetchedAt: 0 };

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function parseJson(bytes) {
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function loadKeys(teamDomain, fetchImpl, now) {
  if (cached.teamDomain === teamDomain && cached.keys && now - cached.fetchedAt < JWKS_TTL_MS) {
    return cached.keys;
  }
  const response = await fetchImpl(`https://${teamDomain}/cdn-cgi/access/certs`, {
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error("key set unavailable");
  const body = await response.json();
  if (!Array.isArray(body.keys)) throw new Error("key set malformed");
  cached = { teamDomain, keys: body.keys, fetchedAt: now };
  return body.keys;
}

export function resetKeyCache() {
  cached = { teamDomain: null, keys: null, fetchedAt: 0 };
}

// Returns { ok: true, claims } or { ok: false, reason }. The reason is for the
// operator's log and is never shown to the caller; it never holds the token.
export async function verifyAccessToken(token, config, { fetchImpl = fetch, now = Date.now() } = {}) {
  const { teamDomain, audience } = config;
  if (!teamDomain || !audience) return { ok: false, reason: "not configured" };
  if (!token) return { ok: false, reason: "no token" };
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "not a token" };

  let header;
  let claims;
  try {
    header = parseJson(base64UrlToBytes(parts[0]));
    claims = parseJson(base64UrlToBytes(parts[1]));
  } catch {
    return { ok: false, reason: "not a token" };
  }
  if (header.alg !== "RS256") return { ok: false, reason: "unexpected algorithm" };
  if (typeof header.kid !== "string") return { ok: false, reason: "no key id" };

  let keys;
  try {
    keys = await loadKeys(teamDomain, fetchImpl, now);
  } catch {
    return { ok: false, reason: "key set unavailable" };
  }
  const jwk = keys.find((key) => key.kid === header.kid && key.kty === "RSA");
  if (!jwk) return { ok: false, reason: "unknown key" };

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      base64UrlToBytes(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    return { ok: false, reason: "bad signature" };
  }
  if (!valid) return { ok: false, reason: "bad signature" };

  const seconds = Math.floor(now / 1000);
  if (claims.iss !== `https://${teamDomain}`) return { ok: false, reason: "wrong issuer" };
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(audience)) return { ok: false, reason: "wrong audience" };
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_SECONDS < seconds) {
    return { ok: false, reason: "expired" };
  }
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_SECONDS > seconds) {
    return { ok: false, reason: "not yet valid" };
  }
  return { ok: true, claims };
}
