// Edge unit tests — run with `node --test` (no extra deps; uses node:test).
//
// These pin the pure edge helpers, especially `isCacheableRead`, which must
// follow the data-plane API: KV keys are a `?key=` query param (never a path
// segment), and a `watch` stream must never be cached.

import { test } from "node:test";
import assert from "node:assert/strict";

import { isCacheableRead, loadRegions, pickRegions } from "./index.mjs";

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
