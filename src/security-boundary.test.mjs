import assert from "node:assert/strict";
import test from "node:test";

import worker from "./worker.mjs";
import {
  buildApiCsp,
  parseConnectSources,
  secureResponse,
  sessionCookieViolation,
} from "./security-boundary.mjs";

const productionEnv = {
  FIDUCIA_DEPLOYMENT_MODE: "production",
  FIDUCIA_AUTH_REQUIRED: "true",
  FIDUCIA_RATE_LIMIT_PER_MINUTE: "1",
};

test("builds a strict API CSP from normalized secure origins", () => {
  const csp = buildApiCsp({
    ...productionEnv,
    FIDUCIA_CSP_CONNECT_SRC:
      "wss://events.fiducia.cloud https://auth.fiducia.cloud https://auth.fiducia.cloud",
  });

  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /form-action 'none'/);
  assert.match(csp, /script-src 'none'/);
  assert.match(
    csp,
    /connect-src 'self' https:\/\/auth\.fiducia\.cloud wss:\/\/events\.fiducia\.cloud/,
  );
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|\*/);
});

test("rejects CSP directive injection, wildcards, credentials, paths, and insecure production origins", () => {
  for (const value of [
    "https://auth.fiducia.cloud; script-src *",
    "https://*.fiducia.cloud",
    "https://user:password@auth.fiducia.cloud",
    "https://auth.fiducia.cloud/path",
    "http://auth.fiducia.cloud",
  ]) {
    assert.throws(
      () => parseConnectSources({ ...productionEnv, FIDUCIA_CSP_CONNECT_SRC: value }),
      /CSP connect source|insecure CSP connect source/,
      value,
    );
  }
});

test("allows explicit localhost HTTP only in a non-production environment", () => {
  assert.deepEqual(
    parseConnectSources({
      FIDUCIA_DEPLOYMENT_MODE: "development",
      FIDUCIA_CSP_CONNECT_SRC: "http://localhost:8787 ws://127.0.0.1:8788",
    }),
    ["http://localhost:8787", "ws://127.0.0.1:8788"],
  );
  assert.throws(
    () =>
      parseConnectSources({
        ...productionEnv,
        FIDUCIA_CSP_CONNECT_SRC: "http://localhost:8787",
      }),
    /insecure CSP connect source/,
  );
});

test("enforces every __Host session-cookie invariant", () => {
  assert.equal(
    sessionCookieViolation(
      "__Host-session=opaque; Secure; HttpOnly; SameSite=Strict; Path=/",
    ),
    null,
  );
  assert.equal(
    sessionCookieViolation("session=opaque; Secure; HttpOnly; SameSite=Strict; Path=/"),
    "host_prefix_required",
  );
  assert.equal(
    sessionCookieViolation("__Host-session=opaque; HttpOnly; SameSite=Strict; Path=/"),
    "secure_required",
  );
  assert.equal(
    sessionCookieViolation("__Host-session=opaque; Secure; SameSite=Strict; Path=/"),
    "http_only_required",
  );
  assert.equal(
    sessionCookieViolation("__Host-session=opaque; Secure; HttpOnly; SameSite=Lax; Path=/"),
    "same_site_strict_required",
  );
  assert.equal(
    sessionCookieViolation("__Host-session=opaque; Secure; HttpOnly; SameSite=Strict; Path=/app"),
    "root_path_required",
  );
  assert.equal(
    sessionCookieViolation(
      "__Host-session=opaque; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=fiducia.cloud",
    ),
    "domain_forbidden",
  );
});

test("adds security headers, strips implementation headers, and disables caching for auth failures", async () => {
  const request = new Request("https://api.fiducia.cloud/v1/me");
  const upstream = new Response("denied", {
    status: 401,
    headers: {
      server: "upstream-server",
      "x-powered-by": "framework",
    },
  });

  const response = secureResponse(request, upstream, productionEnv);
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("server"), null);
  assert.equal(response.headers.get("x-powered-by"), null);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("pragma"), "no-cache");
  assert.match(
    response.headers.get("strict-transport-security") ?? "",
    /max-age=63072000; includeSubDomains/,
  );
  assert.match(response.headers.get("content-security-policy") ?? "", /default-src 'none'/);
  assert.equal(await response.text(), "denied");
});

test("returns a stable Retry-After value for rate limits", () => {
  const response = secureResponse(
    new Request("https://api.fiducia.cloud/v1/locks"),
    Response.json({ error: "rate_limited" }, { status: 429 }),
    {
      ...productionEnv,
      FIDUCIA_RATE_LIMIT_WINDOW_SECONDS: "90",
    },
  );

  assert.equal(response.status, 429);
  assert.equal(response.headers.get("retry-after"), "90");
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("blocks an upstream response that tries to emit a weak session cookie", async () => {
  const response = secureResponse(
    new Request("https://api.fiducia.cloud/v1/session"),
    Response.json(
      { ok: true },
      {
        headers: {
          "set-cookie": "session=opaque; Secure; HttpOnly; SameSite=Lax; Path=/",
        },
      },
    ),
    productionEnv,
  );

  assert.equal(response.status, 502);
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { error: "invalid_session_cookie_contract" });
});

test("preserves a conforming __Host session cookie while forcing no-store", () => {
  const response = secureResponse(
    new Request("https://api.fiducia.cloud/v1/session"),
    Response.json(
      { ok: true },
      {
        headers: {
          "set-cookie":
            "__Host-session=opaque; Secure; HttpOnly; SameSite=Strict; Path=/",
        },
      },
    ),
    productionEnv,
  );

  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie") ?? "", /^__Host-session=/);
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("the Wrangler entry wrapper applies headers and fails closed on invalid policy configuration", async () => {
  const request = new Request("https://api.fiducia.cloud/_edge/healthz");
  const healthy = await worker.fetch(request, productionEnv, {});
  assert.equal(healthy.status, 200);
  assert.match(healthy.headers.get("content-security-policy") ?? "", /default-src 'none'/);

  const rejected = await worker.fetch(
    request,
    {
      ...productionEnv,
      FIDUCIA_CROSS_ORIGIN_RESOURCE_POLICY: "permit-everything",
    },
    {},
  );
  assert.equal(rejected.status, 503);
  assert.equal(rejected.headers.get("cache-control"), "no-store");
  assert.deepEqual(await rejected.json(), { error: "security_boundary_misconfigured" });
});
