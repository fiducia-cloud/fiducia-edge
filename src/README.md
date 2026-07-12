# src — fiducia-edge Worker

The Cloudflare Worker source for the global edge entry of fiducia.cloud. It is
tier 1 of a two-tier router: it picks the target **region** (by geo + health) and
handles edge concerns, then forwards to the regional load balancer (tier 2) which
picks the node.

- `index.mjs` — the Worker: request handling, region selection, auth/caching edge
  logic, and forwarding.
- `index.test.mjs` — unit tests for the pure edge helpers (e.g. `isCacheableRead`);
  run with `node --test`, no extra dependencies.
