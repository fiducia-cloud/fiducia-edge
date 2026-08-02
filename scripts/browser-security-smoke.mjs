import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { resolve } from "node:path";

import { chromium } from "playwright";

import { secureResponse } from "../src/security-boundary.mjs";

const artifactDir = resolve(
  process.env.FIDUCIA_BROWSER_ARTIFACT_DIR || "artifacts/browser-security",
);
const productionEnv = {
  FIDUCIA_DEPLOYMENT_MODE: "production",
  FIDUCIA_AUTH_REQUIRED: "true",
  FIDUCIA_RATE_LIMIT_PER_MINUTE: "60",
};

await mkdir(artifactDir, { recursive: true });

let beaconHits = 0;
const server = createServer((request, response) => {
  void handleRequest(request)
    .then((fetchResponse) => writeFetchResponse(response, fetchResponse))
    .catch((error) => {
      console.error("browser smoke harness failed:", error instanceof Error ? error.message : error);
      response.statusCode = 500;
      response.setHeader("content-type", "application/json; charset=utf-8");
      response.end(JSON.stringify({ error: "test_harness_failure" }));
    });
});

await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});

const address = server.address();
assert(address && typeof address === "object", "browser harness did not bind a TCP port");
const baseUrl = `http://127.0.0.1:${address.port}`;

let browser;
try {
  browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const context = await browser.newContext({
    serviceWorkers: "block",
    viewport: { width: 1280, height: 720 },
  });
  const page = await context.newPage();
  const browserConsole = [];
  page.on("console", (message) => browserConsole.push(`${message.type()}: ${message.text()}`));

  const cspResponse = await page.goto(`${baseUrl}/csp`, { waitUntil: "networkidle" });
  assert(cspResponse, "Chromium did not produce a response for the CSP route");
  assert.equal(cspResponse.status(), 200);
  assert.equal(await page.locator("#safe-content").textContent(), "safe content rendered");
  assert.equal(
    await page.locator("body").getAttribute("data-inline-executed"),
    null,
    "Chromium executed an inline script despite script-src 'none'",
  );
  assert.equal(beaconHits, 0, "blocked inline script reached the beacon endpoint");
  assert.match(cspResponse.headers()["content-security-policy"] || "", /script-src 'none'/);
  assert.equal(cspResponse.headers()["x-frame-options"], "DENY");
  await page.screenshot({ path: `${artifactDir}/csp.png`, fullPage: true });

  const weakCookieResponse = await page.goto(`${baseUrl}/weak-cookie`, {
    waitUntil: "networkidle",
  });
  assert(weakCookieResponse, "Chromium did not produce a response for the cookie route");
  assert.equal(weakCookieResponse.status(), 502);
  assert.match(await page.locator("body").innerText(), /invalid_session_cookie_contract/);
  assert.doesNotMatch(await page.locator("body").innerText(), /opaque-session-value/);
  assert.equal(weakCookieResponse.headers()["cache-control"], "no-store");
  assert.equal(weakCookieResponse.headers()["set-cookie"], undefined);
  assert.equal((await context.cookies()).length, 0, "browser accepted a blocked session cookie");
  await page.screenshot({ path: `${artifactDir}/weak-cookie.png`, fullPage: true });

  await writeFile(
    `${artifactDir}/browser-console.log`,
    `${browserConsole.join("\n")}\n`,
  );
  await writeFile(
    `${artifactDir}/summary.json`,
    `${JSON.stringify({
      ok: true,
      cases: ["csp-inline-script-blocked", "weak-cookie-fails-closed"],
      browserConsoleEntries: browserConsole.length,
    }, null, 2)}\n`,
  );
  console.log("browser security smoke passed");
} catch (error) {
  await writeFile(
    `${artifactDir}/summary.json`,
    `${JSON.stringify({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }, null, 2)}\n`,
  );
  throw error;
} finally {
  await browser?.close();
  await new Promise((resolveClose) => server.close(resolveClose));
}

async function handleRequest(nodeRequest) {
  const target = new URL(nodeRequest.url || "/", baseUrl);
  const boundaryRequest = new Request(`https://api.fiducia.cloud${target.pathname}`);

  if (target.pathname === "/beacon") {
    beaconHits += 1;
    return new Response(null, { status: 204 });
  }

  if (target.pathname === "/csp") {
    const upstream = new Response(
      `<!doctype html>
<meta charset="utf-8">
<title>Fiducia CSP browser smoke</title>
<body>
  <p id="safe-content">safe content rendered</p>
  <script>
    document.body.setAttribute("data-inline-executed", "yes");
    fetch("/beacon", { method: "POST" }).catch(() => {});
  </script>
</body>`,
      { headers: { "content-type": "text/html; charset=utf-8" } },
    );
    return secureResponse(boundaryRequest, upstream, productionEnv);
  }

  if (target.pathname === "/weak-cookie") {
    const upstream = Response.json(
      { ok: true, secret: "opaque-session-value" },
      {
        headers: {
          "set-cookie":
            "session=opaque-session-value; Secure; HttpOnly; SameSite=Lax; Path=/",
        },
      },
    );
    return secureResponse(boundaryRequest, upstream, productionEnv);
  }

  return secureResponse(
    boundaryRequest,
    Response.json({ error: "not_found" }, { status: 404 }),
    productionEnv,
  );
}

async function writeFetchResponse(nodeResponse, fetchResponse) {
  nodeResponse.statusCode = fetchResponse.status;
  for (const [name, value] of fetchResponse.headers) {
    nodeResponse.setHeader(name, value);
  }
  nodeResponse.end(Buffer.from(await fetchResponse.arrayBuffer()));
}
