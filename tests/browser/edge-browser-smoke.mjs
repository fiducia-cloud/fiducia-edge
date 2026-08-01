import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import worker from "../../src/worker.mjs";

const ARTIFACT_DIR = resolve(
  process.env.BROWSER_ARTIFACT_DIR || "artifacts/browser-smoke",
);
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

// Define the protocol client before any top-level browser work. Class bindings
// are not hoisted like function declarations; keeping this first prevents a
// temporal-dead-zone regression from failing only on the hosted runner.
class CdpClient {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.waiters = new Set();
    socket.addEventListener("message", (event) => this.handleMessage(event));
    socket.addEventListener("close", () => {
      this.failPending(new Error("DevTools websocket closed"));
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`DevTools command timed out: ${method}`));
      }, 15_000);
      this.pending.set(id, { resolvePromise, reject, timer, method });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  waitFor(method, predicate = () => true, timeoutMs = 10_000) {
    return new Promise((resolvePromise, reject) => {
      const waiter = { method, predicate, resolvePromise, reject, timer: null };
      waiter.timer = setTimeout(() => {
        this.waiters.delete(waiter);
        reject(new Error(`DevTools event timed out: ${method}`));
      }, timeoutMs);
      this.waiters.add(waiter);
    });
  }

  handleMessage(event) {
    const message = JSON.parse(String(event.data));
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      if (message.error) {
        pending.reject(new Error(`${pending.method}: ${message.error.message}`));
      } else {
        pending.resolvePromise(message.result || {});
      }
      return;
    }

    for (const waiter of [...this.waiters]) {
      if (waiter.method !== message.method) continue;
      try {
        if (!waiter.predicate(message.params || {})) continue;
      } catch (error) {
        clearTimeout(waiter.timer);
        this.waiters.delete(waiter);
        waiter.reject(error);
        continue;
      }
      clearTimeout(waiter.timer);
      this.waiters.delete(waiter);
      waiter.resolvePromise(message.params || {});
    }
  }

  failPending(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    for (const waiter of this.waiters) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    this.waiters.clear();
  }

  close() {
    this.socket.close();
  }
}

await run();

async function run() {
  const report = {
    startedAt: new Date().toISOString(),
    browser: null,
    scenarios: [],
  };
  let fixture;
  let chrome;
  let cdp;

  try {
    await mkdir(ARTIFACT_DIR, { recursive: true });
    fixture = await startFixtureServer();
    chrome = await startChrome();
    report.browser = chrome.version;
    cdp = await connectCdp(chrome.debugPort);
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Network.enable");

    const visit = async (name, extraHeaders = {}) => {
      const result = await visitScenario(cdp, fixture.origin, name, extraHeaders);
      report.scenarios.push(result);
      return result;
    };

    const health = await visit("health");
    assert.equal(health.status, 200);
    assert.match(health.bodyText, /fiducia-edge/);
    assertHardenedHeaders(health.headers);

    const missing = await visit("missing-credentials");
    assert.equal(missing.status, 401);
    assert.match(missing.bodyText, /missing_credentials/);
    assertNoStore(missing.headers);
    assertHardenedHeaders(missing.headers);

    const invalidToken = "header.payload.signature";
    const invalid = await visit("invalid-jwt", {
      Authorization: `Bearer ${invalidToken}`,
    });
    assert.equal(invalid.status, 401);
    assert.match(invalid.bodyText, /invalid_jwt/);
    assert.doesNotMatch(invalid.bodyText, /header\.payload\.signature/);
    assertNoStore(invalid.headers);
    assertHardenedHeaders(invalid.headers);

    const misconfigured = await visit("misconfigured-policy");
    assert.equal(misconfigured.status, 503);
    assert.match(misconfigured.bodyText, /security_boundary_misconfigured/);
    assert.doesNotMatch(misconfigured.bodyText, /default-src|allowed\.example/);
    assertNoStore(misconfigured.headers);
    assertHardenedHeaders(misconfigured.headers);

    const upstreamFailure = await visit("upstream-failure");
    assert.equal(upstreamFailure.status, 502);
    assert.match(upstreamFailure.bodyText, /no_region/);
    assert.doesNotMatch(
      upstreamFailure.bodyText,
      /secret-region-a|10\.0\.0\.9|ECONNREFUSED|internal\.example/,
    );
    assertNoStore(upstreamFailure.headers);
    assertHardenedHeaders(upstreamFailure.headers);

    const csp = await visit("csp-enforcement");
    assert.equal(csp.status, 200);
    assert.match(csp.bodyText, /browser-policy-probe/);
    assert.equal(
      csp.scriptRan,
      false,
      "the browser executed inline script despite the edge CSP",
    );
    assertHardenedHeaders(csp.headers);

    report.finishedAt = new Date().toISOString();
    report.ok = true;
    await writeReport(report);
    console.log(`browser boundary smoke passed (${report.scenarios.length} scenarios)`);
  } catch (error) {
    report.finishedAt = new Date().toISOString();
    report.ok = false;
    report.error = serializeError(error);
    report.chromeStderr = chrome?.stderrTail || [];
    await captureFailureScreenshot(cdp);
    await writeReport(report);
    console.error(error);
    process.exitCode = 1;
  } finally {
    cdp?.close();
    if (chrome) await chrome.stop();
    if (fixture) await fixture.stop();
  }
}

async function visitScenario(cdp, origin, name, extraHeaders) {
  const url = `${origin}/scenario/${name}`;
  await cdp.send("Network.setExtraHTTPHeaders", { headers: extraHeaders });
  try {
    const responsePromise = cdp.waitFor(
      "Network.responseReceived",
      (event) => event.type === "Document" && event.response.url === url,
      15_000,
    );
    const navigation = await cdp.send("Page.navigate", { url });
    if (navigation.errorText) {
      throw new Error(`navigation failed: ${navigation.errorText}`);
    }

    const event = await responsePromise;
    await waitForDocumentReady(cdp);
    return {
      name,
      status: event.response.status,
      bodyText: await evaluate(cdp, "document.body?.innerText || ''"),
      scriptRan: await evaluate(cdp, "globalThis.__fiduciaScriptRan === true"),
      headers: normalizeHeaders(event.response.headers),
    };
  } finally {
    await cdp.send("Network.setExtraHTTPHeaders", { headers: {} });
  }
}

async function waitForDocumentReady(cdp) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (await evaluate(cdp, "document.readyState === 'complete'")) return;
    await delay(50);
  }
  throw new Error("browser document did not reach readyState=complete");
}

async function evaluate(cdp, expression) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails) {
    throw new Error(`browser evaluation failed: ${expression}`);
  }
  return result.result.value;
}

function assertHardenedHeaders(headers) {
  assert.match(headers["content-security-policy"] || "", /default-src 'none'/);
  assert.match(headers["content-security-policy"] || "", /script-src 'none'/);
  assert.equal(headers["x-content-type-options"], "nosniff");
  assert.equal(headers["x-frame-options"], "DENY");
  assert.equal(headers["referrer-policy"], "no-referrer");
  assert.match(headers["permissions-policy"] || "", /camera=\(\)/);
  assert.equal(headers["cross-origin-opener-policy"], "same-origin");
  assert.equal(headers["cross-origin-resource-policy"], "same-site");
  assert.match(
    headers["strict-transport-security"] || "",
    /max-age=63072000; includeSubDomains/,
  );
  assert.equal(headers.server, undefined);
  assert.equal(headers["x-powered-by"], undefined);
}

function assertNoStore(headers) {
  assert.match(headers["cache-control"] || "", /(?:^|,)\s*no-store(?:,|$)/);
  assert.equal(headers.pragma, "no-cache");
}

async function startFixtureServer() {
  const server = createServer(async (request, response) => {
    const incoming = new URL(request.url || "/", "http://127.0.0.1");
    if (!incoming.pathname.startsWith("/scenario/")) {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("not found");
      return;
    }

    try {
      const scenario = incoming.pathname.slice("/scenario/".length);
      const config = scenarioConfig(scenario);
      const originalFetch = globalThis.fetch;
      globalThis.fetch = config.fetchImpl || originalFetch;
      try {
        const workerRequest = new Request(
          `https://api.fiducia.test${config.targetPath}`,
          { method: request.method, headers: requestHeaders(request.headers) },
        );
        const workerResponse = await worker.fetch(
          workerRequest,
          config.env,
          { waitUntil: () => {} },
        );
        response.statusCode = workerResponse.status;
        for (const [name, value] of workerResponse.headers) {
          response.setHeader(name, value);
        }
        response.end(Buffer.from(await workerResponse.arrayBuffer()));
      } finally {
        globalThis.fetch = originalFetch;
      }
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({
        error: "fixture_failure",
        type: error?.name || "Error",
      }));
    }
  });

  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("fixture server has no TCP address");
  }
  return {
    origin: `http://127.0.0.1:${address.port}`,
    stop: () => new Promise((resolvePromise) => server.close(resolvePromise)),
  };
}

function scenarioConfig(scenario) {
  const production = {
    FIDUCIA_DEPLOYMENT_MODE: "production",
    FIDUCIA_AUTH_REQUIRED: "true",
    FIDUCIA_RATE_LIMIT_PER_MINUTE: "0",
    FIDUCIA_REGIONS: JSON.stringify([
      { name: "secret-region-a", url: "https://internal.example" },
    ]),
  };

  switch (scenario) {
    case "health":
      return { env: production, targetPath: "/_edge/healthz" };
    case "missing-credentials":
    case "invalid-jwt":
      return { env: production, targetPath: "/v1/status" };
    case "misconfigured-policy":
      return {
        env: {
          ...production,
          FIDUCIA_CSP_CONNECT_SRC: "https://allowed.example; default-src *",
        },
        targetPath: "/_edge/healthz",
      };
    case "upstream-failure":
      return {
        env: { ...production, FIDUCIA_AUTH_REQUIRED: "false" },
        targetPath: "/v1/status",
        fetchImpl: async () => {
          throw new Error("connect ECONNREFUSED 10.0.0.9:8443");
        },
      };
    case "csp-enforcement":
      return {
        env: { ...production, FIDUCIA_AUTH_REQUIRED: "false" },
        targetPath: "/v1/status",
        fetchImpl: async () => new Response(
          "<!doctype html><main>browser-policy-probe</main>" +
            "<script>globalThis.__fiduciaScriptRan=true</script>",
          {
            status: 200,
            headers: {
              "content-type": "text/html; charset=utf-8",
              server: "private-upstream",
              "x-powered-by": "private-framework",
            },
          },
        ),
      };
    default:
      throw new Error(`unknown browser scenario: ${scenario}`);
  }
}

function requestHeaders(nodeHeaders) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(nodeHeaders)) {
    if (HOP_BY_HOP_HEADERS.has(name.toLowerCase()) || value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else {
      headers.set(name, value);
    }
  }
  return headers;
}

async function startChrome() {
  const executable = findChromeExecutable();
  const version = spawnSync(executable, ["--version"], { encoding: "utf8" });
  if (version.status !== 0) {
    throw new Error(`unable to execute browser: ${executable}`);
  }

  const profile = await mkdtemp(join(tmpdir(), "fiducia-edge-chrome-"));
  const stderrTail = [];
  const child = spawn(executable, [
    "--headless=new",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-debugging-address=127.0.0.1",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe"] });

  child.stderr.on("data", (chunk) => {
    stderrTail.push(String(chunk).trim());
    if (stderrTail.length > 50) stderrTail.shift();
  });

  const activePortFile = join(profile, "DevToolsActivePort");
  const deadline = Date.now() + 15_000;
  let debugPort;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`browser exited before DevTools startup: ${child.exitCode}`);
    }
    try {
      const [port] = (await readFile(activePortFile, "utf8")).trim().split(/\r?\n/);
      debugPort = Number(port);
      if (Number.isSafeInteger(debugPort) && debugPort > 0) break;
    } catch {
      // Chrome writes the port file only after DevTools is ready.
    }
    await delay(50);
  }
  if (!debugPort) throw new Error("browser DevTools endpoint did not start");

  return {
    debugPort,
    stderrTail,
    version: version.stdout.trim(),
    async stop() {
      if (child.exitCode === null) child.kill("SIGTERM");
      await delay(50);
      await rm(profile, { recursive: true, force: true });
    },
  };
}

function findChromeExecutable() {
  const candidates = [
    process.env.CHROME_PATH,
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (spawnSync(candidate, ["--version"], { stdio: "ignore" }).status === 0) {
      return candidate;
    }
  }
  throw new Error(`no supported Chrome/Chromium executable found (${candidates.join(", ")})`);
}

async function connectCdp(debugPort) {
  const response = await fetch(
    `http://127.0.0.1:${debugPort}/json/new?about:blank`,
    { method: "PUT" },
  );
  if (!response.ok) {
    throw new Error(`DevTools target creation failed: ${response.status}`);
  }
  const target = await response.json();
  if (!target.webSocketDebuggerUrl) {
    throw new Error("DevTools target has no websocket URL");
  }

  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await Promise.race([
    new Promise((resolvePromise, reject) => {
      socket.addEventListener("open", resolvePromise, { once: true });
      socket.addEventListener(
        "error",
        () => reject(new Error("DevTools websocket failed")),
        { once: true },
      );
    }),
    delay(10_000).then(() => {
      throw new Error("DevTools websocket timed out");
    }),
  ]);
  return new CdpClient(socket);
}

function normalizeHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers || {}).map(([name, value]) => [
      name.toLowerCase(),
      String(value),
    ]),
  );
}

async function captureFailureScreenshot(cdp) {
  if (!cdp) return;
  try {
    const screenshot = await cdp.send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: true,
    });
    if (screenshot.data) {
      await writeFile(
        join(ARTIFACT_DIR, "failure.png"),
        Buffer.from(screenshot.data, "base64"),
      );
    }
  } catch {
    // Preserve the primary failure if Chrome has already exited.
  }
}

async function writeReport(report) {
  await writeFile(
    join(ARTIFACT_DIR, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
  );
}

function serializeError(error) {
  return {
    name: error?.name || "Error",
    message: error?.message || String(error),
    stack: error?.stack || null,
  };
}

function delay(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}
