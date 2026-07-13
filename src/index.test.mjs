// Edge unit tests — run with `node --test` (no extra deps; uses node:test).
//
// These pin the pure edge helpers, especially `isCacheableRead`, which must
// follow the data-plane API: KV keys are a `?key=` query param (never a path
// segment), and a `watch` stream must never be cached.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  checkAuth,
  checkRateLimit,
  extractCredential,
  forwardWithFailover,
  headersForOrigin,
  isApiKeyCredential,
  isCacheableRead,
  isReplaySafeMethod,
  loadRegions,
  looksLikeJwt,
  pickRegions,
  RateLimiter,
} from "./index.mjs";

const req = (url, method = "GET") => new Request(url, { method });

test("only read-only methods are replay-safe across regions", () => {
  for (const method of ["GET", "HEAD", "OPTIONS"]) {
    assert.equal(isReplaySafeMethod(method), true);
  }
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    assert.equal(isReplaySafeMethod(method), false);
  }
});

test("configured rate limiting fails closed without its Durable Object binding", async () => {
  const result = await checkRateLimit(
    new Request("https://api.example/v1/kv?key=x"),
    { FIDUCIA_RATE_LIMIT_PER_MINUTE: "1" },
  );
  assert.deepEqual(result, { ok: false, configurationError: true });
});

test("Durable Object rate-limit increments are serialized", async () => {
  let counter;
  let transactionTail = Promise.resolve();
  const storage = {
    transaction(fn) {
      const run = transactionTail.then(() => fn({
        get: async () => counter,
        put: async (_key, value) => { counter = value; },
      }));
      transactionTail = run.then(() => undefined, () => undefined);
      return run;
    },
    setAlarm: async () => {},
    deleteAll: async () => { counter = undefined; },
  };
  const limiter = new RateLimiter({ storage });
  const request = () => new Request("https://rate-limiter.internal/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ limit: 1, windowSeconds: 60, now: 120 }),
  });

  const responses = await Promise.all([limiter.fetch(request()), limiter.fetch(request())]);
  assert.deepEqual(responses.map((response) => response.status).sort(), [200, 429]);
});

test("read failover advances regions but mutation transport failure does not replay", async () => {
  const originalFetch = globalThis.fetch;
  const regions = [
    { name: "first", url: "https://first.example" },
    { name: "second", url: "https://second.example" },
  ];
  const env = {};

  try {
    const readTargets = [];
    globalThis.fetch = async (target) => {
      readTargets.push(String(target));
      if (readTargets.length === 1) throw new Error("timeout");
      return Response.json({ value: "ok" });
    };
    const read = await forwardWithFailover(
      new Request("https://api.example/v1/kv?key=x"),
      regions,
      null,
      env,
    );
    assert.equal(read.status, 200);
    assert.equal(readTargets.length, 2);

    const writeTargets = [];
    globalThis.fetch = async (target) => {
      writeTargets.push(String(target));
      throw new Error("response lost after send");
    };
    const write = await forwardWithFailover(
      new Request("https://api.example/v1/kv?key=x", {
        method: "PUT",
        body: JSON.stringify({ value: "new" }),
      }),
      regions,
      null,
      env,
    );
    assert.equal(write.status, 502);
    assert.equal((await write.json()).error, "ambiguous_upstream_result");
    assert.equal(writeTargets.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("forwardWithFailover returns a generic 502 without leaking region names or transport errors", async () => {
  const originalFetch = globalThis.fetch;
  const originalWarn = console.warn;
  const regions = [
    { name: "secret-region-a", url: "https://a.internal.example" },
    { name: "secret-region-b", url: "https://b.internal.example" },
  ];

  try {
    globalThis.fetch = async () => {
      throw new Error("connect ECONNREFUSED 10.0.0.9:8443");
    };
    console.warn = () => {}; // silence the expected server-side log line

    const resp = await forwardWithFailover(
      new Request("https://api.example/v1/kv?key=x"),
      regions,
      null,
      {},
    );

    assert.equal(resp.status, 502);
    const body = await resp.json();
    assert.equal(body.error, "no_region");
    // Client-facing detail must not disclose internal region names or the raw
    // transport error (host/IP), only a generic message.
    assert.equal(body.detail, "no healthy region could serve the request");
    const serialized = JSON.stringify(body);
    assert.ok(!serialized.includes("secret-region"), "must not leak region names");
    assert.ok(!serialized.includes("ECONNREFUSED"), "must not leak transport error");
    assert.ok(!serialized.includes("10.0.0.9"), "must not leak internal host/ip");
  } finally {
    globalThis.fetch = originalFetch;
    console.warn = originalWarn;
  }
});

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

test("pickRegions: prefers healthy nearby regions over unhealthy primaries", () => {
  const request = req("https://api.fiducia.cloud/v1/status");
  request.cf = { continent: "EU" };
  const regions = [
    { name: "us-east", url: "https://us", continent: "NA" },
    { name: "eu-west", url: "https://eu", continent: "EU" },
    { name: "eu-down", url: "https://down", continent: "EU" },
  ];

  assert.deepEqual(
    pickRegions(request, regions, { "eu-down": "unhealthy" }).map((region) => region.name),
    ["eu-west", "us-east", "eu-down"],
  );
});

test("extractCredential accepts bearer or x-api-key", () => {
  assert.equal(
    extractCredential(new Request("https://api.fiducia.cloud/v1/status", {
      headers: { authorization: "Bearer fdc_live_id.secret" },
    })),
    "fdc_live_id.secret",
  );
  assert.equal(
    extractCredential(new Request("https://api.fiducia.cloud/v1/status", {
      headers: { "x-api-key": "fdc_live_other.secret" },
    })),
    "fdc_live_other.secret",
  );
});

test("credential helpers classify fiducia keys and JWTs", () => {
  assert.equal(isApiKeyCredential("fdc_live_id.secret"), true);
  assert.equal(isApiKeyCredential("header.payload.signature"), false);
  assert.equal(looksLikeJwt("header.payload.signature"), true);
  assert.equal(looksLikeJwt("fdc_live_id.secret"), false);
});

test("headersForOrigin strips raw credentials and injects verified identity", () => {
  const headers = headersForOrigin(
    new Headers({
      authorization: "Bearer fdc_live_id.secret",
      "x-api-key": "fdc_live_id.secret",
      cookie: "sb-access-token=secret",
      "proxy-authorization": "Basic secret",
      "x-fiducia-org-id": "spoofed",
      "x-fiducia-scopes": "spoofed",
      "x-fiducia-internal-auth": "spoofed-trusted-hop",
      "idempotency-key": "cust-key-1",
      "x-request-id": "req_1",
    }),
    {
      kind: "api_key",
      orgId: "org_1",
      keyId: "key_1",
      scopes: ["kv:read", "locks:write"],
    },
  );

  assert.equal(headers.get("authorization"), null);
  assert.equal(headers.get("x-api-key"), null);
  assert.equal(headers.get("cookie"), null);
  assert.equal(headers.get("proxy-authorization"), null);
  assert.equal(headers.get("x-fiducia-auth-kind"), "api_key");
  assert.equal(headers.get("x-fiducia-org-id"), "org_1");
  assert.equal(headers.get("x-fiducia-key-id"), "key_1");
  assert.equal(headers.get("x-fiducia-scopes"), "kv:read locks:write");
  assert.equal(headers.get("x-fiducia-internal-auth"), null);
  assert.equal(headers.get("idempotency-key"), "cust-key-1");
  assert.equal(headers.get("x-request-id"), "req_1");
});

test("headersForOrigin sets the edge->LB secret and strips a spoofed copy", () => {
  const headers = headersForOrigin(
    new Headers({
      // A client tries to forge the trusted-hop proof; it must be dropped and
      // replaced with the edge's own secret alongside the verified identity.
      "x-fiducia-edge-auth": "spoofed-edge-secret",
    }),
    {
      kind: "api_key",
      orgId: "org_1",
      keyId: "key_1",
      scopes: ["kv:write"],
    },
    { FIDUCIA_INTERNAL_SECRET: "real-edge-secret" },
  );

  assert.equal(headers.get("x-fiducia-edge-auth"), "real-edge-secret");
  assert.equal(headers.get("x-fiducia-org-id"), "org_1");
});

test("headersForOrigin omits the edge->LB secret when none is configured", () => {
  const headers = headersForOrigin(
    new Headers({ "x-fiducia-edge-auth": "spoofed-edge-secret" }),
    { kind: "api_key", orgId: "org_1", keyId: null, scopes: [] },
    {},
  );

  // No secret configured → the spoofed client copy is still stripped and no
  // trusted-hop header is emitted, so the LB treats the request as anonymous.
  assert.equal(headers.get("x-fiducia-edge-auth"), null);
});

test("checkAuth rejects missing credentials when auth is required", async () => {
  const auth = await checkAuth(
    new Request("https://api.fiducia.cloud/v1/kv?key=x"),
    { FIDUCIA_AUTH_REQUIRED: "true" },
  );

  assert.equal(auth.ok, false);
  assert.equal(auth.response.status, 401);
  assert.equal((await auth.response.json()).error, "missing_credentials");
});

test("checkAuth rejects disabled API keys without introspection", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("introspection must not be called");
  };

  try {
    const auth = await checkAuth(
      new Request("https://api.fiducia.cloud/v1/kv?key=x", {
        headers: { authorization: "Bearer fdc_live_disabled.secret" },
      }),
      {
        FIDUCIA_AUTH_REQUIRED: "true",
        FIDUCIA_AUTH_ALLOW_API_KEYS: "false",
      },
    );

    assert.equal(auth.ok, false);
    assert.equal(auth.response.status, 401);
    assert.equal((await auth.response.json()).error, "api_keys_disabled");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("checkAuth returns a generic 503 without leaking the upstream auth status", async () => {
  const originalFetch = globalThis.fetch;
  const originalWarn = console.warn;
  globalThis.fetch = async () => new Response("boom", { status: 500 });
  console.warn = () => {}; // silence the expected server-side log line

  try {
    const auth = await checkAuth(
      new Request("https://api.fiducia.cloud/v1/kv?key=x", {
        headers: { authorization: "Bearer fdc_live_upstream.secret" },
      }),
      { FIDUCIA_AUTH_REQUIRED: "true", FIDUCIA_AUTH_URL: "https://auth.test" },
    );

    assert.equal(auth.ok, false);
    assert.equal(auth.response.status, 503);
    const body = await auth.response.json();
    assert.equal(body.error, "auth_unavailable");
    // The client-facing detail must not disclose the upstream auth status code.
    assert.equal(body.detail, "auth service unavailable");
    assert.ok(!JSON.stringify(body).includes("500"), "must not leak upstream status");
  } finally {
    globalThis.fetch = originalFetch;
    console.warn = originalWarn;
  }
});

test("checkAuth introspects API keys once and then serves from cache", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls += 1;
    assert.equal(url, "https://auth.test/v1/introspect");
    assert.equal(init.method, "POST");
    const body = JSON.parse(init.body);
    assert.equal(body.api_key, "fdc_live_cache.secret");
    return Response.json({
      valid: true,
      org_id: "org_cache",
      key_id: "key_cache",
      scopes: ["kv:read"],
    });
  };

  try {
    const env = {
      FIDUCIA_AUTH_REQUIRED: "true",
      FIDUCIA_AUTH_URL: "https://auth.test",
      FIDUCIA_AUTH_CACHE_TTL_SECONDS: "60",
    };
    const request = new Request("https://api.fiducia.cloud/v1/kv?key=x", {
      headers: { authorization: "Bearer fdc_live_cache.secret" },
    });
    const first = await checkAuth(request, env);
    const second = await checkAuth(request, env);
    assert.equal(first.ok, true);
    assert.equal(second.ok, true);
    assert.equal(second.cache, "hit");
    assert.equal(first.identity.orgId, "org_cache");
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
