import assert from "node:assert/strict";
import { test } from "node:test";

import {
  authorizeRevocation,
  enforceJwtRevocationBoundary,
  resetRevocationBoundaryForTest,
} from "./jwt-revocation-boundary.mjs";

const readerSecret = "r".repeat(48);
const baseClaims = Object.freeze({
  sub: "org-1",
  org_id: "org-1",
  scopes: ["kv:read"],
  iss: "fiducia-auth",
  aud: "fiducia-api",
  iat: 900,
  exp: 1_800,
  jti: "token-1",
});

function env(overrides = {}) {
  return {
    FIDUCIA_DEPLOYMENT_MODE: "test",
    FIDUCIA_REVOCATION_READER_SECRET: readerSecret,
    FIDUCIA_REVOCATION_CHECK_URL: "http://revocation.test/v1/revocations/check",
    FIDUCIA_REVOCATION_CACHE_TTL_SECONDS: "10",
    FIDUCIA_REVOCATION_TIMEOUT_MS: "50",
    ...overrides,
  };
}

function authority(decision, calls, delayMs = 0) {
  return async (_url, init) => {
    calls.count += 1;
    assert.equal(init.headers["x-revocation-reader-auth"], readerSecret);
    const request = JSON.parse(init.body);
    assert.equal(request.claims.jti, baseClaims.jti);
    if (delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs));
    return Response.json({ decision });
  };
}

const allowDecision = {
  revoked: false,
  matched_target: null,
  generation: null,
  expires_at: null,
};

function denyDecision(matchedTarget = "token_id") {
  return {
    revoked: true,
    matched_target: matchedTarget,
    generation: 7,
    expires_at: 1_700,
  };
}

test("fresh negative avoids a second authority call", async () => {
  resetRevocationBoundaryForTest();
  const calls = { count: 0 };
  const fetchImpl = authority(allowDecision, calls);
  const first = await authorizeRevocation(baseClaims, env(), { nowMs: 1_000_000, fetchImpl });
  const second = await authorizeRevocation(baseClaims, env(), { nowMs: 1_001_000, fetchImpl });
  assert.equal(first.kind, "allow");
  assert.equal(second.kind, "allow");
  assert.equal(second.cache, "fresh_negative");
  assert.equal(calls.count, 1);
});

test("exact-token and subject revocations deny without logging identity", async () => {
  for (const matchedTarget of ["token_id", "subject"]) {
    resetRevocationBoundaryForTest();
    const calls = { count: 0 };
    const result = await authorizeRevocation(baseClaims, env(), {
      nowMs: 1_000_000,
      fetchImpl: authority(denyDecision(matchedTarget), calls),
    });
    assert.equal(result.kind, "deny");
    assert.equal(result.matchedTarget, matchedTarget);
    assert.equal(calls.count, 1);
  }
});

test("stale negative denies when refresh times out", async () => {
  resetRevocationBoundaryForTest();
  const calls = { count: 0 };
  await authorizeRevocation(baseClaims, env(), {
    nowMs: 1_000_000,
    fetchImpl: authority(allowDecision, calls),
  });
  const result = await authorizeRevocation(baseClaims, env({ FIDUCIA_REVOCATION_TIMEOUT_MS: "5" }), {
    nowMs: 1_011_000,
    fetchImpl: authority(allowDecision, calls, 30),
  });
  assert.equal(result.kind, "unavailable");
  assert.equal(result.reason, "timeout");
});

test("stale positive remains denied when authority is unavailable", async () => {
  resetRevocationBoundaryForTest();
  const calls = { count: 0 };
  await authorizeRevocation(baseClaims, env(), {
    nowMs: 1_000_000,
    fetchImpl: authority(denyDecision(), calls),
  });
  const result = await authorizeRevocation(baseClaims, env({ FIDUCIA_REVOCATION_TIMEOUT_MS: "5" }), {
    nowMs: 1_011_000,
    fetchImpl: authority(allowDecision, calls, 30),
  });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "stale_revocation_unconfirmed");
  assert.equal(result.refreshFailure, "timeout");
});

test("malformed authority decision fails closed", async () => {
  resetRevocationBoundaryForTest();
  const result = await authorizeRevocation(baseClaims, env(), {
    nowMs: 1_000_000,
    fetchImpl: async () => Response.json({ decision: { revoked: "no" } }),
  });
  assert.equal(result.kind, "unavailable");
  assert.equal(result.reason, "malformed_decision");
});

test("concurrent misses coalesce to one authority request", async () => {
  resetRevocationBoundaryForTest();
  const calls = { count: 0 };
  const fetchImpl = authority(allowDecision, calls, 10);
  const results = await Promise.all(
    Array.from({ length: 12 }, () => authorizeRevocation(baseClaims, env(), {
      nowMs: 1_000_000,
      fetchImpl,
    })),
  );
  assert.ok(results.every((result) => result.kind === "allow"));
  assert.equal(calls.count, 1);
});

test("clock regression denies without an authority request", async () => {
  resetRevocationBoundaryForTest();
  const calls = { count: 0 };
  const fetchImpl = authority(allowDecision, calls);
  assert.equal((await authorizeRevocation(baseClaims, env(), {
    nowMs: 1_000_000,
    fetchImpl,
  })).kind, "allow");
  const result = await authorizeRevocation(baseClaims, env(), {
    nowMs: 999_999,
    fetchImpl,
  });
  assert.equal(result.kind, "unavailable");
  assert.equal(result.reason, "clock_regression");
  assert.equal(calls.count, 1);
});

async function mintEs256(payload) {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  Object.assign(jwk, { kid: "boundary-test-kid", alg: "ES256", use: "sig" });
  delete jwk.key_ops;
  delete jwk.ext;
  const encode = (value) => Buffer.from(value).toString("base64url");
  const header = encode(JSON.stringify({ alg: "ES256", kid: jwk.kid, typ: "JWT" }));
  const body = encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(`${header}.${body}`),
  );
  return { token: `${header}.${body}.${Buffer.from(signature).toString("base64url")}`, jwk };
}

test("worker boundary performs offline validation before revocation", async () => {
  resetRevocationBoundaryForTest();
  const nowSeconds = Math.floor(Date.now() / 1_000);
  const claims = {
    ...baseClaims,
    iat: nowSeconds - 10,
    exp: nowSeconds + 300,
    jti: "integration-token",
  };
  const { token, jwk } = await mintEs256(claims);
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    if (String(url).endsWith("/.well-known/jwks.json")) return Response.json({ keys: [jwk] });
    return Response.json({ decision: denyDecision("subject") });
  };
  const response = await enforceJwtRevocationBoundary(
    new Request("https://api.fiducia.cloud/v1/kv?key=x", {
      headers: { authorization: `Bearer ${token}` },
    }),
    env({ FIDUCIA_AUTH_URL: "https://auth.test" }),
    { nowMs: nowSeconds * 1_000, fetchImpl },
  );
  assert.equal(response.status, 401);
  assert.deepEqual(calls, [
    "https://auth.test/.well-known/jwks.json",
    "http://revocation.test/v1/revocations/check",
  ]);
});
