// Edge unit tests — run with `node --test` (no extra deps; uses node:test).
//
// These pin the pure edge helpers, especially `isCacheableRead`, which must
// follow the data-plane API: KV keys are a `?key=` query param (never a path
// segment), and a `watch` stream must never be cached.

import { test } from "node:test";
import assert from "node:assert/strict";

import { authenticate, isCacheableRead, loadRegions, pickRegions, verifyJwt } from "./index.mjs";

const req = (url, method = "GET") => new Request(url, { method });

// Mint a real ES256 JWT with a fresh WebCrypto key; returns the token + public JWK.
async function mintEs256(payload) {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  Object.assign(jwk, { kid: "test-kid", alg: "ES256", use: "sig" });
  delete jwk.key_ops; delete jwk.ext;
  const u = (s) => Buffer.from(s).toString("base64url");
  const head = u(JSON.stringify({ alg: "ES256", kid: "test-kid", typ: "JWT" }));
  const body = u(JSON.stringify(payload));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    privateKey, new TextEncoder().encode(`${head}.${body}`));
  return { token: `${head}.${body}.${Buffer.from(sig).toString("base64url")}`, jwk };
}

test("isCacheableRead: only an explicit, non-watch KV read is cacheable", () => {
  const base = "https://api.fiducia.cloud";

  // Cacheable: GET /v1/kv?key=...&cache=...
  assert.equal(isCacheableRead(req(`${base}/v1/kv?key=flags/x&cache=30`)), true);

  // Not cacheable without an explicit opt-in.
  assert.equal(isCacheableRead(req(`${base}/v1/kv?key=flags/x`)), false);
  // Not cacheable without a key (a list/scan).
  assert.equal(isCacheableRead(req(`${base}/v1/kv?cache=30`)), false);
  // A watch stream must NEVER be cached.
  assert.equal(isCacheableRead(req(`${base}/v1/kv?key=x&cache=30&watch=true`)), false);
  // Writes are never cacheable.
  assert.equal(isCacheableRead(req(`${base}/v1/kv?key=x&cache=30`, "PUT")), false);
  // The OLD path-key shape is no longer KV and must not be cached.
  assert.equal(isCacheableRead(req(`${base}/v1/kv/flags/x?cache=30`)), false);
  // Other primitives are never cached (locks/semaphores/etc.).
  assert.equal(isCacheableRead(req(`${base}/v1/locks?key=x&cache=30`)), false);
});

test("loadRegions: parses the env JSON, tolerates bad/missing config", () => {
  const regions = [
    { name: "us-east", url: "https://us-east.lb.fiducia.cloud" },
    { name: "eu-west", url: "https://eu-west.lb.fiducia.cloud" },
  ];
  assert.deepEqual(loadRegions({ FIDUCIA_REGIONS: JSON.stringify(regions) }), regions);
  assert.deepEqual(loadRegions({ FIDUCIA_REGIONS: "not json" }), []);
  assert.deepEqual(loadRegions({}), []);
});

test("pickRegions: preserves the configured primary→fallback order", () => {
  const regions = [{ name: "a", url: "https://a" }, { name: "b", url: "https://b" }];
  // Failover relies on order: primary first, fallback next.
  assert.deepEqual(pickRegions(req("https://api.fiducia.cloud/v1/status"), regions), regions);
});

const authed = (url, token) =>
  new Request(url, { method: "POST", headers: token ? { authorization: `Bearer ${token}` } : {} });

test("authenticate: permissive allows anonymous; enforce rejects it", async () => {
  const r1 = await authenticate(authed("https://x/v1/locks/acquire"), {});
  assert.deepEqual(r1, { ok: true, identity: null });

  const r2 = await authenticate(authed("https://x/v1/locks/acquire"), { FIDUCIA_AUTH_MODE: "enforce" });
  assert.equal(r2.ok, false);
  assert.equal(r2.status, 401);
});

test("authenticate: a garbage JWT is rejected (no JWKS fetch needed)", async () => {
  const r = await authenticate(authed("https://x/v1/locks/acquire", "aaaa.bbbb.cccc"), { FIDUCIA_AUTH_URL: "http://auth.test" });
  assert.equal(r.ok, false);
  assert.equal(r.status, 401);
});

test("authenticate: verifies a real ES256 JWT OFFLINE against the JWKS", async () => {
  const now = Math.floor(Date.now() / 1000);
  const { token, jwk } = await mintEs256({ iss: "fiducia-auth", org_id: "org_x", scopes: ["locks:write"], exp: now + 900 });
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/.well-known/jwks.json")) {
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  try {
    const r = await authenticate(authed("https://x/v1/locks/acquire", token), { FIDUCIA_AUTH_URL: "http://auth.test" });
    assert.equal(r.ok, true);
    assert.equal(r.identity.org, "org_x");
    assert.equal(r.identity.via, "jwt");

    // A token with the wrong issuer must fail even though the signature is valid.
    const bad = await mintEs256({ iss: "evil", org_id: "org_x", exp: now + 900 });
    globalThis.fetch = async () => new Response(JSON.stringify({ keys: [bad.jwk] }), { status: 200 });
    // (force a JWKS refresh by using a different kid is not needed; verifyJwt checks iss)
    assert.equal(await verifyJwt(bad.token, { FIDUCIA_AUTH_URL: "http://auth.test" }), null);
  } finally {
    globalThis.fetch = origFetch;
  }
});
