import assert from "node:assert/strict";
import test from "node:test";

import {
  parseConnectSources,
  secureResponse,
} from "./security-boundary.mjs";
import worker from "./worker.mjs";

const productionEnv = {
  FIDUCIA_DEPLOYMENT_MODE: "production",
  FIDUCIA_AUTH_REQUIRED: "true",
  FIDUCIA_RATE_LIMIT_PER_MINUTE: "1",
};

test("CSP connect origins are canonicalized deduplicated and sorted", () => {
  const sources = parseConnectSources({
    ...productionEnv,
    FIDUCIA_CSP_CONNECT_SRC: [
      "https://zeta.fiducia.test:443",
      "https://alpha.fiducia.test/",
      "wss://events.fiducia.test:443",
      "https://alpha.fiducia.test",
    ].join(" "),
  });

  assert.deepEqual(sources, [
    "https://alpha.fiducia.test",
    "https://zeta.fiducia.test",
    "wss://events.fiducia.test",
  ]);
});

test("generated Retry-After is finite rounded and bounded while upstream values win", () => {
  for (const [configured, expected] of [
    [undefined, "60"],
    ["not-a-number", "60"],
    ["0", "60"],
    ["0.1", "1"],
    ["89.1", "90"],
    ["86401", "86400"],
  ]) {
    const env = { ...productionEnv };
    if (configured !== undefined) {
      env.FIDUCIA_RATE_LIMIT_WINDOW_SECONDS = configured;
    }
    const response = secureResponse(
      new Request("https://api.fiducia.test/v1/locks"),
      new Response(null, { status: 429 }),
      env,
    );
    assert.equal(
      response.headers.get("retry-after"),
      expected,
      `configured=${configured}`,
    );
  }

  const preserved = secureResponse(
    new Request("https://api.fiducia.test/v1/locks"),
    new Response(null, {
      status: 429,
      headers: { "retry-after": "7" },
    }),
    {
      ...productionEnv,
      FIDUCIA_RATE_LIMIT_WINDOW_SECONDS: "90",
    },
  );
  assert.equal(preserved.headers.get("retry-after"), "7");
});

test("HSTS is emitted only for production-like HTTPS requests", () => {
  const spoofed = { "strict-transport-security": "max-age=1" };

  const plainHttp = secureResponse(
    new Request("http://api.fiducia.test/healthz"),
    new Response("ok", { headers: spoofed }),
    productionEnv,
  );
  assert.equal(plainHttp.headers.get("strict-transport-security"), null);

  const development = secureResponse(
    new Request("https://api.fiducia.test/healthz"),
    new Response("ok", { headers: spoofed }),
    { FIDUCIA_DEPLOYMENT_MODE: "development" },
  );
  assert.equal(development.headers.get("strict-transport-security"), null);

  const production = secureResponse(
    new Request("https://api.fiducia.test/healthz"),
    new Response("ok", { headers: spoofed }),
    { ...productionEnv, FIDUCIA_HSTS_PRELOAD: "true" },
  );
  assert.equal(
    production.headers.get("strict-transport-security"),
    "max-age=63072000; includeSubDomains; preload",
  );
});

test("the public Worker boundary fails closed for every invalid security configuration class", async () => {
  const request = new Request("https://api.fiducia.test/_edge/healthz");
  const invalidEnvironments = [
    {
      ...productionEnv,
      FIDUCIA_CSP_CONNECT_SRC: "https://auth.fiducia.test; script-src *",
    },
    {
      ...productionEnv,
      FIDUCIA_CROSS_ORIGIN_RESOURCE_POLICY: "same-universe",
    },
    {
      ...productionEnv,
      FIDUCIA_HSTS_PRELOAD: "sometimes",
    },
  ];

  for (const env of invalidEnvironments) {
    const response = await worker.fetch(request, env, {});
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("x-frame-options"), "DENY");
    assert.match(
      response.headers.get("content-security-policy") ?? "",
      /default-src 'none'/,
    );
    assert.deepEqual(await response.json(), {
      error: "security_boundary_misconfigured",
    });
  }
});
