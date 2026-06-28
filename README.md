# fiducia-edge

The global **edge entry** for [fiducia.cloud](https://fiducia.cloud) — a
Cloudflare Worker that runs at CF PoPs close to clients.

## Two-tier routing

| Tier | Component | Decides |
|------|-----------|---------|
| 1 — global edge | **fiducia-edge** (this Worker) | which **region** (geo + health) + edge concerns |
| 2 — regional | [`fiducia-load-balance`](https://github.com/fiducia-cloud/fiducia-load-balance.rs) | which **node** (key → shard → leader) |

**Region at the edge, node at the LB.** The Worker is intentionally
shard-agnostic: it forwards to a region's load balancer, which owns
`key → shard → leader` routing.

## What the edge does

- **Region selection** — pick the healthiest/nearest region's LB (using
  `request.cf` geo + a health view); fail over to the next region on 5xx/error.
- **Auth** — validate Fiducia API keys through `fiducia-auth` once, cache the
  introspection result briefly, verify Fiducia JWTs offline via JWKS, and reject
  early before the cluster.
- **Rate limiting** — per-client/tenant quotas to shield the cluster.
- **DDoS / WAF / TLS** — handled natively by Cloudflare in front of the Worker.
- **Opt-in read caching** — only for explicitly cacheable config reads
  (`GET /v1/kv/...?cache=...`). **Never** caches writes or locks.

## Hard rules

- **The edge is not consensus.** It cuts client↔front-door RTT, but a
  strongly-consistent write still has to reach the shard leader + a quorum in its
  region. Don't try to serve writes/locks from the edge.
- **Don't reimplement the hash in JS.** If the edge ever needs `key → shard`
  (e.g. to route to a geo-pinned shard's home region), compile the
  [`fiducia-routing`](https://github.com/fiducia-cloud/fiducia-routing.rs) crate
  to **WASM** and import it — so the mapping can't drift from the data plane.
  (See the commented `wasm_modules` binding in `wrangler.toml`.)

## Layout

| File             | Responsibility                                            |
|------------------|-----------------------------------------------------------|
| `src/index.mjs`  | the Worker: region pick, failover forward, edge concerns  |
| `wrangler.toml`  | Worker config: regions, optional KV / DO / WASM bindings  |

## Develop & deploy

```bash
npm install
npm run check     # node --check (syntax)
npm run dev       # wrangler dev (local edge)
npm run deploy    # wrangler deploy
```

Config:

- `FIDUCIA_REGIONS` — JSON array of `{name, url}` regional LB origins.
- `FIDUCIA_AUTH_REQUIRED` — set `true` for public deployments.
- `FIDUCIA_AUTH_URL` — base URL of `fiducia-auth`; defaults to
  `https://auth.fiducia.cloud`.
- `FIDUCIA_AUTH_CACHE_TTL_SECONDS` — positive API-key introspection cache TTL.
- `FIDUCIA_AUTH_NEGATIVE_CACHE_TTL_SECONDS` — invalid credential cache TTL.
- `FIDUCIA_AUTH_JWKS_TTL_SECONDS` — Fiducia JWT JWKS cache TTL.
- `FIDUCIA_AUTH_JWT_CACHE_TTL_SECONDS` — verified JWT decision cache TTL.
- `FIDUCIA_JWT_ISSUER` / `FIDUCIA_JWT_AUDIENCE` — expected Fiducia JWT claims.

The Worker strips `Authorization`, `x-api-key`, and caller-supplied
`x-fiducia-*` identity headers before forwarding. Regional LBs and nodes should
trust only the identity headers injected by the edge/LB boundary.

Optionally add a `FIDUCIA_CONFIG` KV namespace for live health/routing.

## Related

- [`fiducia-load-balance.rs`](https://github.com/fiducia-cloud/fiducia-load-balance.rs) — the regional LB this forwards to.
- [`fiducia-routing.rs`](https://github.com/fiducia-cloud/fiducia-routing.rs) — shared `key → shard` (WASM-able for the edge).
- [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) — control plane (region health / placement source).
