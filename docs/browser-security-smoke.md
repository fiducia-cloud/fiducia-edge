# Browser security smoke

The edge response boundary is covered at two levels:

1. deterministic `node:test` cases validate policy construction, cookie invariants, status codes, and headers;
2. `scripts/browser-security-smoke.mjs` drives a real Chromium browser through an HTTP harness backed by `secureResponse()`.

The browser layer exists for behavior that string assertions cannot prove. It verifies that Chromium actually refuses to execute an inline script under the emitted `script-src 'none'` policy, that the blocked script cannot call a beacon endpoint, and that a weak session cookie is replaced by the stable fail-closed response before the browser can store it.

## Run locally

Install the repository dependencies and a matching Playwright release, install Chromium, then run:

```bash
npm ci --ignore-scripts
npm install --no-save --ignore-scripts playwright@1.56.0
npx playwright install chromium
npm run test:browser-security
```

The script writes screenshots, browser console output, and a machine-readable summary to `artifacts/browser-security/`. The GitHub Actions workflow uploads that directory even when the smoke test fails.

## Scope and safety

The harness binds only to `127.0.0.1` on an ephemeral port. It does not call production services, accept credentials, or log cookie values. Its intentionally weak cookie contains a fixed test marker and must never appear in the browser-visible failure response.

The workflow pins checkout, setup-node, actionlint, artifact upload, and the Playwright container image. Playwright is installed at the exact version matching the container rather than floating to the newest release.
