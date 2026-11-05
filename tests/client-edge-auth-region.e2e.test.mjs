// Real TCP integration: client -> Wrangler entry -> auth introspection -> regional LB.
// Unlike the helper unit tests, no upstream fetch is replaced with a mock.
// All listeners use ephemeral loopback ports; no credentials or cloud resources.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import worker from "../src/worker.mjs";

async function listen(handler) {
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((error) => {
      if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ fixture_error: error.message }));
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    url: "http://127.0.0.1:" + server.address().port,
    close: () => new Promise((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve())),
  };
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

test("client -> edge -> auth -> regional LB: tenant authority, failover and at-most-once mutation forwarding", async (t) => {
  const authHits = [];
  const regionHits = [];
  const suffix = randomUUID().replaceAll("-", "");
  const goodKey = "fdc_e2e_" + suffix + ".good";
  const badKey = "fdc_e2e_" + suffix + ".invalid";
  const auth = await listen(async (req, res) => {
    const payload = JSON.parse(await readBody(req));
    authHits.push({ path: req.url, headers: req.headers, payload });
    json(res, 200, {
      valid: payload.api_key === goodKey,
      org_id: payload.api_key === goodKey ? "org_verified" : null,
      key_id: payload.api_key === goodKey ? "key_verified" : null,
      scopes: ["kv:read", "locks:write"],
    });
  });
  t.after(auth.close);

  const primary = await listen(async (req, res) => {
    regionHits.push({
      region: "primary", method: req.method, path: req.url,
      headers: req.headers, body: await readBody(req),
    });
    json(res, 503, { error: "primary_unavailable" });
  });
  t.after(primary.close);

  const secondary = await listen(async (req, res) => {
    regionHits.push({
      region: "secondary", method: req.method, path: req.url,
      headers: req.headers, body: await readBody(req),
    });
    json(res, 200, { ok: true, region: "secondary" });
  });
  t.after(secondary.close);

  const env = {
    FIDUCIA_DEPLOYMENT_MODE: "production",
    FIDUCIA_AUTH_REQUIRED: "true",
    FIDUCIA_AUTH_INTROSPECT_URL: auth.url + "/v1/introspect",
    FIDUCIA_INTROSPECT_SECRET: "local-e2e-introspection-secret",
    FIDUCIA_INTERNAL_SECRET: "local-e2e-edge-to-lb-secret",
    FIDUCIA_RATE_LIMIT_PER_MINUTE: "0",
    FIDUCIA_REGIONS: JSON.stringify([
      { name: "primary", url: primary.url },
      { name: "secondary", url: secondary.url },
    ]),
  };

  // The client uses a *real HTTP socket* to the edge entry. The bridge is only
  // the Node adapter for a Cloudflare fetch handler; outbound calls use Node's
  // real fetch to the separate auth/LB servers.
  const edge = await listen(async (req, res) => {
    const body = await readBody(req);
    const request = new Request("https://api.fiducia.test" + req.url, {
      method: req.method,
      headers: req.headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
    });
    const response = await worker.fetch(request, env, { waitUntil() {} });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  });
  t.after(edge.close);

  const send = (path, options = {}) => fetch(edge.url + path, {
    redirect: "manual",
    signal: AbortSignal.timeout(5_000),
    ...options,
  });

  await t.test("unauthenticated and invalid clients cannot reach either region", async () => {
    const missing = await send("/v1/kv?key=private");
    assert.equal(missing.status, 401);
    assert.equal((await missing.json()).error, "missing_credentials");
    assert.equal(authHits.length, 0);
    assert.equal(regionHits.length, 0);

    const denied = await send("/v1/kv?key=private", {
      headers: { authorization: "Bearer " + badKey },
    });
    assert.equal(denied.status, 401);
    assert.equal((await denied.json()).error, "invalid_api_key");
    assert.equal(regionHits.length, 0);
    assert.equal(authHits.length, 1);
    assert.equal(authHits[0].path, "/v1/introspect");
    assert.equal(authHits[0].headers["x-server-auth"], env.FIDUCIA_INTROSPECT_SECRET);
  });

  await t.test("GET fails over through real HTTP while replacing forged tenant/trust headers", async () => {
    const response = await send("/v1/kv?key=orders%2F42", {
      headers: {
        authorization: "Bearer " + goodKey,
        cookie: "session=attacker",
        "x-fiducia-org-id": "org_attacker",
        "x-fiducia-scopes": "*",
        "x-fiducia-edge-auth": "forged-edge-auth",
        "x-fiducia-internal-auth": "forged-node-auth",
        "x-request-id": "e2e-request",
      },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, region: "secondary" });
    assert.deepEqual(regionHits.map((hit) => hit.region), ["primary", "secondary"]);
    assert.deepEqual(regionHits.map((hit) => hit.path), [
      "/v1/kv?key=orders%2F42", "/v1/kv?key=orders%2F42",
    ]);
    for (const hit of regionHits) {
      assert.equal(hit.headers.authorization, undefined);
      assert.equal(hit.headers.cookie, undefined);
      assert.equal(hit.headers["x-api-key"], undefined);
      assert.equal(hit.headers["x-fiducia-internal-auth"], undefined);
      assert.equal(hit.headers["x-fiducia-edge-auth"], env.FIDUCIA_INTERNAL_SECRET);
      assert.equal(hit.headers["x-fiducia-org-id"], "org_verified");
      assert.equal(hit.headers["x-fiducia-key-id"], "key_verified");
      assert.equal(hit.headers["x-fiducia-scopes"], "kv:read locks:write");
      assert.equal(hit.headers["x-request-id"], "e2e-request");
    }
    assert.equal(authHits.at(-1).payload.api_key, goodKey);
  });

  await t.test("POST is sent once despite a 503 after possible commit", async () => {
    const payload = JSON.stringify({ key: "orders/42", holder: "worker-a", ttl_ms: 5000 });
    const response = await send("/v1/locks/acquire", {
      method: "POST",
      headers: {
        authorization: "Bearer " + goodKey,
        "content-type": "application/json",
        "idempotency-key": "e2e-idempotency-" + suffix,
      },
      body: payload,
    });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, "primary_unavailable");
    assert.deepEqual(regionHits.map((hit) => hit.region), [
      "primary", "secondary", "primary",
    ]);
    const write = regionHits.at(-1);
    assert.equal(write.method, "POST");
    assert.equal(write.path, "/v1/locks/acquire");
    assert.equal(write.body, payload);
    assert.equal(write.headers["idempotency-key"], "e2e-idempotency-" + suffix);
    assert.equal(write.headers["x-fiducia-org-id"], "org_verified");
  });
});
