// Client -> edge Worker -> real regional/auth HTTP listeners.
// Proves no cross-origin redirect follow, no auth-bypass on control-plane outage,
// and sanitized failover exhaustion without leaking internal region details.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import worker from "../src/worker.mjs";

async function listen(handler) {
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((err) => {
      if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ fixture_error: err.message }));
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    url: "http://127.0.0.1:" + server.address().port,
    close: () => new Promise((resolve, reject) =>
      server.close((err) => err ? reject(err) : resolve())),
  };
}
function env(regions, extra = {}) {
  return {
    FIDUCIA_DEPLOYMENT_MODE: "production",
    FIDUCIA_REGIONS: JSON.stringify(regions.map((region, i) => ({
      name: "sensitive-region-" + i,
      url: region.url,
    }))),
    FIDUCIA_AUTH_REQUIRED: "false",
    FIDUCIA_RATE_LIMIT_PER_MINUTE: "0",
    ...extra,
  };
}

test("GET never follows a regional redirect into an attacker-controlled HTTP server", async (t) => {
  let attackerHits = 0;
  let regionalHits = 0;
  const attacker = await listen((_req, res) => {
    attackerHits++;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ stolen: true }));
  });
  t.after(attacker.close);
  const region = await listen((req, res) => {
    regionalHits++;
    assert.equal(req.method, "GET");
    res.writeHead(302, {
      location: attacker.url + "/steal?request=private",
      server: "hidden-internal-service",
    });
    res.end("redirect");
  });
  t.after(region.close);
  const response = await worker.fetch(
    new Request("https://api.fiducia.test/v1/kv?key=orders%2Fprivate", {
      headers: { "x-request-id": "redirect-e2e" },
    }),
    env([region]),
    {},
  );
  assert.equal(response.status, 302);
  assert.equal(regionalHits, 1);
  assert.equal(attackerHits, 0, "edge must not perform egress to redirect target");
  assert.equal(response.headers.get("server"), null, "upstream server identity stripped");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
});

test("auth-introspection 503 fails closed before regional forwarding even with forged identity", async (t) => {
  let authHits = 0;
  let regionalHits = 0;
  const auth = await listen(async (_req, res) => {
    authHits++;
    res.writeHead(503, { "content-type": "application/json" });
    res.end(JSON.stringify({ secret_internal_failure: "postgres password=hidden" }));
  });
  t.after(auth.close);
  const region = await listen((_req, res) => {
    regionalHits++;
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"unauthorized":true}');
  });
  t.after(region.close);
  const credential = "fdc_e2e_" + randomUUID().replaceAll("-", "") + ".secret";
  const response = await worker.fetch(
    new Request("https://api.fiducia.test/v1/locks?key=sensitive", {
      headers: {
        authorization: "Bearer " + credential,
        "x-fiducia-org-id": "forged-admin",
        "x-fiducia-edge-auth": "forged-internal-secret",
        "x-fiducia-scopes": "*",
      },
    }),
    env([region], {
      FIDUCIA_AUTH_REQUIRED: "true",
      FIDUCIA_AUTH_INTROSPECT_URL: auth.url + "/v1/introspect",
      FIDUCIA_INTROSPECT_SECRET: "local-test-server-proof",
    }),
    {},
  );
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.error, "auth_unavailable");
  assert.doesNotMatch(JSON.stringify(body), /postgres|password|hidden|forged-admin/);
  assert.equal(authHits, 1);
  assert.equal(regionalHits, 0, "edge must not route when identity verification is unavailable");
});

test("GET exhausting independent 503 regions returns a bounded sanitized client error", async (t) => {
  const requests = [[], []];
  const regions = [];
  for (let i = 0; i < 2; i++) {
    const index = i;
    const region = await listen((req, res) => {
      requests[index].push([req.method, req.url]);
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ region_secret: "private-control-plane-" + index }));
    });
    regions.push(region);
    t.after(region.close);
  }
  const response = await worker.fetch(
    new Request("https://api.fiducia.test/v1/kv?key=shared%2Fsecret"),
    env(regions),
    {},
  );
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.error, "no_region");
  assert.doesNotMatch(JSON.stringify(body), /private-control-plane|sensitive-region|127\.0\.0\.1/);
  assert.deepEqual(requests, [
    [["GET", "/v1/kv?key=shared%2Fsecret"]],
    [["GET", "/v1/kv?key=shared%2Fsecret"]],
  ]);
});
