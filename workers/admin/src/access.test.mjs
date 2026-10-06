// The signing key and every token are made at run time; nothing here is a
// literal secret. The key set is served by a stub instead of the network.
import test from "node:test";
import assert from "node:assert/strict";
import { verifyAccessToken, resetKeyCache } from "./access.js";

const TEAM = "relay-test.cloudflareaccess.com";
const AUD = "app-aud-tag";
const NOW = 1_800_000_000_000;

const b64url = (input) =>
  Buffer.from(typeof input === "string" ? input : JSON.stringify(input)).toString("base64url");

async function makeKey(kid = "key-1") {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { kid, privateKey: pair.privateKey, jwk: { ...jwk, kid } };
}

async function sign(key, claims, header = {}) {
  const head = b64url({ alg: "RS256", kid: key.kid, typ: "JWT", ...header });
  const body = b64url(claims);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key.privateKey,
    new TextEncoder().encode(`${head}.${body}`),
  );
  return `${head}.${body}.${Buffer.from(signature).toString("base64url")}`;
}

const good = (overrides = {}) => ({
  iss: `https://${TEAM}`,
  aud: [AUD],
  exp: Math.floor(NOW / 1000) + 3600,
  nbf: Math.floor(NOW / 1000) - 10,
  email: "operator@example.com",
  ...overrides,
});

const keySet = (...keys) => async () => Response.json({ keys: keys.map((k) => k.jwk) });
const config = { teamDomain: TEAM, audience: AUD };

test("a valid token is accepted and its claims are returned", async () => {
  resetKeyCache();
  const key = await makeKey();
  const result = await verifyAccessToken(await sign(key, good()), config, { fetchImpl: keySet(key), now: NOW });
  assert.equal(result.ok, true);
  assert.equal(result.claims.email, "operator@example.com");
});

test("a string audience is accepted when it matches", async () => {
  resetKeyCache();
  const key = await makeKey();
  const token = await sign(key, good({ aud: AUD }));
  assert.equal((await verifyAccessToken(token, config, { fetchImpl: keySet(key), now: NOW })).ok, true);
});

test("a missing configuration or token refuses", async () => {
  resetKeyCache();
  const key = await makeKey();
  const token = await sign(key, good());
  const opts = { fetchImpl: keySet(key), now: NOW };
  assert.equal((await verifyAccessToken(token, { teamDomain: "", audience: AUD }, opts)).reason, "not configured");
  assert.equal((await verifyAccessToken(token, { teamDomain: TEAM, audience: "" }, opts)).reason, "not configured");
  assert.equal((await verifyAccessToken("", config, opts)).reason, "no token");
  assert.equal((await verifyAccessToken("a.b", config, opts)).reason, "not a token");
  assert.equal((await verifyAccessToken("not.base64.json", config, opts)).reason, "not a token");
});

test("the wrong audience, issuer, expiry and not-before are refused", async () => {
  resetKeyCache();
  const key = await makeKey();
  const opts = { fetchImpl: keySet(key), now: NOW };
  const attempt = async (claims) => verifyAccessToken(await sign(key, claims), config, opts);
  assert.equal((await attempt(good({ aud: ["other"] }))).reason, "wrong audience");
  assert.equal((await attempt(good({ iss: "https://elsewhere.cloudflareaccess.com" }))).reason, "wrong issuer");
  assert.equal((await attempt(good({ exp: Math.floor(NOW / 1000) - 3600 }))).reason, "expired");
  assert.equal((await attempt(good({ exp: undefined }))).reason, "expired");
  assert.equal((await attempt(good({ nbf: Math.floor(NOW / 1000) + 3600 }))).reason, "not yet valid");
});

test("a token signed by another key, or altered after signing, is refused", async () => {
  resetKeyCache();
  const key = await makeKey();
  const other = await makeKey();
  const opts = { fetchImpl: keySet(key), now: NOW };
  const forged = await sign({ ...other, kid: key.kid }, good());
  assert.equal((await verifyAccessToken(forged, config, opts)).reason, "bad signature");
  const real = await sign(key, good());
  const [head, , sig] = real.split(".");
  const tampered = `${head}.${b64url(good({ email: "attacker@example.com" }))}.${sig}`;
  assert.equal((await verifyAccessToken(tampered, config, opts)).reason, "bad signature");
});

test("an unknown key id, a non-RS256 algorithm and alg none are refused", async () => {
  resetKeyCache();
  const key = await makeKey();
  const opts = { fetchImpl: keySet(key), now: NOW };
  const stranger = await makeKey("key-9");
  assert.equal((await verifyAccessToken(await sign(stranger, good()), config, opts)).reason, "unknown key");
  assert.equal(
    (await verifyAccessToken(await sign(key, good(), { alg: "HS256" }), config, opts)).reason,
    "unexpected algorithm",
  );
  const none = `${b64url({ alg: "none", kid: key.kid })}.${b64url(good())}.`;
  assert.equal((await verifyAccessToken(none, config, opts)).reason, "unexpected algorithm");
});

test("a key set that cannot be fetched fails closed", async () => {
  resetKeyCache();
  const key = await makeKey();
  const token = await sign(key, good());
  const down = async () => new Response("", { status: 503 });
  assert.equal((await verifyAccessToken(token, config, { fetchImpl: down, now: NOW })).reason, "key set unavailable");
  const broken = async () => Response.json({ nope: true });
  resetKeyCache();
  assert.equal((await verifyAccessToken(token, config, { fetchImpl: broken, now: NOW })).reason, "key set unavailable");
  const throws = async () => {
    throw new Error("network");
  };
  resetKeyCache();
  assert.equal((await verifyAccessToken(token, config, { fetchImpl: throws, now: NOW })).reason, "key set unavailable");
});

test("the key set is cached for an hour and refetched after", async () => {
  resetKeyCache();
  const key = await makeKey();
  const token = await sign(key, good({ exp: Math.floor(NOW / 1000) + 86_400 }));
  let fetches = 0;
  const counting = async () => {
    fetches += 1;
    return Response.json({ keys: [key.jwk] });
  };
  await verifyAccessToken(token, config, { fetchImpl: counting, now: NOW });
  await verifyAccessToken(token, config, { fetchImpl: counting, now: NOW + 60_000 });
  assert.equal(fetches, 1);
  await verifyAccessToken(token, config, { fetchImpl: counting, now: NOW + 2 * 3_600_000 });
  assert.equal(fetches, 2);
});

test("a refusal reason never contains the token", async () => {
  resetKeyCache();
  const key = await makeKey();
  const token = await sign(key, good({ aud: ["other"] }));
  const result = await verifyAccessToken(token, config, { fetchImpl: keySet(key), now: NOW });
  assert.equal(result.ok, false);
  assert.ok(!JSON.stringify(result).includes(token.split(".")[2]));
});
