// Edge unit tests — run with `node --test` (no extra deps; uses node:test).
//
// These pin the pure edge helpers, especially `isCacheableRead`, which must
// follow the data-plane API: KV keys are a `?key=` query param (never a path
// segment), and a `watch` stream must never be cached.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  checkAuth,
  extractCredential,
  headersForOrigin,
  isApiKeyCredential,
  isCacheableRead,
  loadRegions,
  looksLikeJwt,
  pickRegions,
} from "./index.mjs";

const req = (url, method = "GET") => new Request(url, { method });

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
  assert.equal(headers.get("idempotency-key"), "cust-key-1");
  assert.equal(headers.get("x-request-id"), "req_1");
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
