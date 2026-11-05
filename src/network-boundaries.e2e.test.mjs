import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";

import worker from "./worker.mjs";

// Unlike fetch-stub tests, these exercise the real HTTP transport on both
// client->edge->regional-LB and edge->auth authority boundaries. No cloud
// credentials, external services, ports, or mutable shared fixture data.
async function listen(handler) {
  const server = createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch(() => {
      if (!response.headersSent) response.writeHead(500);
      response.end("local test server error");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function bodyOf(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function respond(response, status, data) {
  response.writeHead(status, {
    "content-type": "application/json",
    server: "regional-internal-server",
    "x-powered-by": "upstream-framework",
  });
  response.end(JSON.stringify(data));
}

function envFor(regions, extra = {}) {
  return {
    FIDUCIA_DEPLOYMENT_MODE: "test",
    FIDUCIA_REGIONS: JSON.stringify(regions.map((region, i) => ({
      name: `region-${i + 1}`,
      url: region.url,
    }))),
    FIDUCIA_AUTH_REQUIRED: "false",
    FIDUCIA_RATE_LIMIT_PER_MINUTE: "0",
    ...extra,
  };
}

test("client -> edge -> auth -> regional server: identity is re-minted, not spoofed", async (t) => {
  const credential = `fdc_e2e_${randomUUID()}.secret`;
  const introspections = [];
  const regionalCalls = [];
  const auth = await listen(async (request, response) => {
    introspections.push({
      method: request.method,
      url: request.url,
      secret: request.headers["x-server-auth"],
      body: JSON.parse(await bodyOf(request)),
    });
    respond(response, 200, {
      valid: true,
      org_id: "tenant-verified",
      key_id: "key-verified",
      scopes: ["kv:write", "locks:write"],
    });
  });
  t.after(auth.close);
  const regional = await listen(async (request, response) => {
    regionalCalls.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: await bodyOf(request),
    });
    respond(response, 201, { committed: true, revision: 41 });
  });
  t.after(regional.close);

  const payload = JSON.stringify({ key: "orders/42", value: "hello" });
  const request = new Request("https://edge.fiducia.test/v1/kv?key=orders%2F42", {
    method: "PUT",
    headers: {
      authorization: `Bearer ${credential}`,
      "x-api-key": "client-should-not-reach-region",
      cookie: "session=private-client-cookie",
      "x-fiducia-org-id": "forged-tenant",
      "x-fiducia-scopes": "admin",
      "x-fiducia-edge-auth": "forged-edge-proof",
      "x-fiducia-internal-auth": "forged-node-proof",
      "idempotency-key": "put-orders-42",
      "content-type": "application/json",
    },
    body: payload,
  });
  const result = await worker.fetch(request, envFor([regional], {
    FIDUCIA_AUTH_REQUIRED: "true",
    FIDUCIA_AUTH_INTROSPECT_URL: `${auth.url}/v1/introspect`,
    FIDUCIA_INTROSPECT_SECRET: "test-introspection-proof",
    FIDUCIA_INTERNAL_SECRET: "real-edge-proof",
  }), {});

  assert.equal(result.status, 201);
  assert.deepEqual(await result.json(), { committed: true, revision: 41 });
  assert.equal(result.headers.get("server"), null);
  assert.equal(result.headers.get("x-powered-by"), null);
  assert.equal(result.headers.get("x-content-type-options"), "nosniff");

  assert.equal(introspections.length, 1);
  assert.equal(introspections[0].method, "POST");
  assert.equal(introspections[0].url, "/v1/introspect");
  assert.equal(introspections[0].secret, "test-introspection-proof");
  assert.deepEqual(introspections[0].body, { api_key: credential });
  assert.equal(regionalCalls.length, 1);
  const call = regionalCalls[0];
  assert.equal(call.method, "PUT");
  assert.equal(call.url, "/v1/kv?key=orders%2F42");
  assert.equal(call.body, payload);
  assert.equal(call.headers["authorization"], undefined);
  assert.equal(call.headers["x-api-key"], undefined);
  assert.equal(call.headers["cookie"], undefined);
  assert.equal(call.headers["x-fiducia-internal-auth"], undefined);
  assert.equal(call.headers["x-fiducia-org-id"], "tenant-verified");
  assert.equal(call.headers["x-fiducia-auth-kind"], "api_key");
  assert.equal(call.headers["x-fiducia-key-id"], "key-verified");
  assert.equal(call.headers["x-fiducia-scopes"], "kv:write locks:write");
  assert.equal(call.headers["x-fiducia-edge-auth"], "real-edge-proof");
  assert.equal(call.headers["idempotency-key"], "put-orders-42");
});

test("real regional HTTP 503 retries GET but never replays a possibly committed PUT", async (t) => {
  const primaryCalls = [];
  const backupCalls = [];
  const primary = await listen(async (request, response) => {
    primaryCalls.push({ method: request.method, url: request.url, body: await bodyOf(request) });
    respond(response, 503, { error: "primary_unavailable" });
  });
  t.after(primary.close);
  const backup = await listen(async (request, response) => {
    backupCalls.push({ method: request.method, url: request.url, body: await bodyOf(request) });
    respond(response, 200, { value: "from-backup" });
  });
  t.after(backup.close);
  const env = envFor([primary, backup]);

  const read = await worker.fetch(
    new Request("https://edge.fiducia.test/v1/kv?key=tenant%2Falpha"),
    env,
    {},
  );
  assert.equal(read.status, 200);
  assert.deepEqual(await read.json(), { value: "from-backup" });
  assert.deepEqual(primaryCalls.map((call) => [call.method, call.url]), [
    ["GET", "/v1/kv?key=tenant%2Falpha"],
  ]);
  assert.deepEqual(backupCalls.map((call) => [call.method, call.url]), [
    ["GET", "/v1/kv?key=tenant%2Falpha"],
  ]);

  const write = await worker.fetch(
    new Request("https://edge.fiducia.test/v1/locks/acquire", {
      method: "PUT",
      headers: { "idempotency-key": "attempt-a" },
      body: JSON.stringify({ key: "locks/a", holder: "worker-a" }),
    }),
    env,
    {},
  );
  assert.equal(write.status, 503);
  assert.deepEqual(await write.json(), { error: "primary_unavailable" });
  assert.equal(write.headers.get("cache-control"), "no-store");
  assert.equal(primaryCalls.length, 2, "mutation hits primary once");
  assert.equal(primaryCalls[1].method, "PUT");
  assert.deepEqual(JSON.parse(primaryCalls[1].body), {
    key: "locks/a",
    holder: "worker-a",
  });
  assert.equal(backupCalls.length, 1, "mutation must never be replayed to backup");
});

test("lost upstream response after a received mutation is ambiguous and not replayed", async (t) => {
  const primaryCalls = [];
  let backupCalls = 0;
  const primary = await listen(async (request, response) => {
    primaryCalls.push({ method: request.method, body: await bodyOf(request) });
    response.destroy(); // Mutation already reached origin; response was lost.
  });
  t.after(primary.close);
  const backup = await listen(async (_request, response) => {
    backupCalls++;
    respond(response, 200, { duplicated: true });
  });
  t.after(backup.close);

  const result = await worker.fetch(new Request("https://edge.fiducia.test/v1/kv?key=critical", {
    method: "PUT",
    headers: { "idempotency-key": "unique-mutation-1" },
    body: JSON.stringify({ value: "one" }),
  }), envFor([primary, backup]), {});
  assert.equal(result.status, 502);
  assert.equal(result.headers.get("cache-control"), "no-store");
  const error = await result.json();
  assert.equal(error.error, "ambiguous_upstream_result");
  assert.match(error.detail, /same Idempotency-Key/);
  assert.deepEqual(primaryCalls, [{ method: "PUT", body: '{"value":"one"}' }]);
  assert.equal(backupCalls, 0);
});

test("missing credentials are rejected before either auth or regional network access", async (t) => {
  let regionalCalls = 0;
  const regional = await listen(async (_request, response) => {
    regionalCalls++;
    respond(response, 200, { leaked: true });
  });
  t.after(regional.close);

  const result = await worker.fetch(new Request("https://edge.fiducia.test/v1/kv?key=x", {
    headers: {
      "x-fiducia-org-id": "forged-tenant",
      "x-fiducia-edge-auth": "forged-proof",
    },
  }), envFor([regional], { FIDUCIA_AUTH_REQUIRED: "true" }), {});
  assert.equal(result.status, 401);
  assert.equal((await result.json()).error, "missing_credentials");
  assert.equal(regionalCalls, 0);
  assert.equal(result.headers.get("cache-control"), "no-store");
});


test("client -> edge -> auth: 307/308 cannot redirect customer API keys or server-only auth", async (t) => {
  let intercepted = 0;
  let regionalWrites = 0;
  const attacker = await listen(async (request, response) => {
    intercepted++;
    await bodyOf(request);
    respond(response, 200, { valid: true, org_id: "forged-tenant", scopes: ["admin"] });
  });
  t.after(attacker.close);

  let status = 307;
  let introspected = 0;
  const auth = await listen(async (request, response) => {
    introspected++;
    assert.equal(request.method, "POST");
    assert.equal(request.headers["x-server-auth"], "server-only-introspection-proof");
    const body = JSON.parse(await bodyOf(request));
    assert.match(body.api_key, /^fdc_e2e_/);
    response.writeHead(status, {
      location: `${attacker.url}/capture`,
      "content-type": "application/json",
    });
    response.end('{"error":"misdirected_auth_request"}');
  });
  t.after(auth.close);
  const regional = await listen(async (_request, response) => {
    regionalWrites++;
    respond(response, 200, { committed: true });
  });
  t.after(regional.close);

  for (const code of [307, 308]) {
    status = code;
    const customerKey = `fdc_e2e_${randomUUID()}.secret`;
    const result = await worker.fetch(
      new Request("https://edge.fiducia.test/v1/locks/acquire", {
        method: "POST",
        headers: { authorization: `Bearer ${customerKey}` },
        body: JSON.stringify({ key: "org/private", holder: "worker-secret" }),
      }),
      envFor([regional], {
        FIDUCIA_AUTH_REQUIRED: "true",
        FIDUCIA_AUTH_INTROSPECT_URL: `${auth.url}/v1/introspect`,
        FIDUCIA_INTROSPECT_SECRET: "server-only-introspection-proof",
      }),
      {},
    );
    assert.equal(result.status, 503, "redirect must be treated as auth authority failure");
    assert.equal((await result.json()).error, "auth_unavailable");
    assert.equal(result.headers.get("cache-control"), "no-store");
    assert.equal(intercepted, 0, "untrusted redirect may never be followed");
    assert.equal(regionalWrites, 0, "failed authentication may never reach regional servers");
  }
  assert.equal(introspected, 2);
});

test("client -> edge -> auth: upstream 500 never becomes authorization or an echoed authority body", async (t) => {
  let regionalCalls = 0;
  const regional = await listen(async (_request, response) => {
    regionalCalls++;
    respond(response, 200, { committed: true });
  });
  t.after(regional.close);
  const auth = await listen(async (request, response) => {
    assert.equal(request.url, "/v1/introspect");
    await bodyOf(request);
    respond(response, 500, {
      error: "private_auth_failure",
      debug: "should-not-be-exposed-to-customer",
    });
  });
  t.after(auth.close);

  const credential = `fdc_e2e_${randomUUID()}.secret`;
  const result = await worker.fetch(
    new Request("https://edge.fiducia.test/v1/kv?key=private", {
      headers: { authorization: `Bearer ${credential}` },
    }),
    envFor([regional], {
      FIDUCIA_AUTH_REQUIRED: "true",
      FIDUCIA_AUTH_INTROSPECT_URL: `${auth.url}/v1/introspect`,
    }),
    {},
  );
  assert.equal(result.status, 503);
  const body = await result.text();
  assert.match(body, /auth_unavailable/);
  assert.doesNotMatch(body, /private_auth_failure|should-not-be-exposed|fdc_e2e_/);
  assert.equal(regionalCalls, 0);
});
