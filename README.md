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
  `request.cf` geo + a health view). Reads may fail over to the next region on
  5xx/error; mutations never auto-replay after an ambiguous response.
- **Auth** — validate Fiducia API keys through `fiducia-auth` once, cache the
  introspection result briefly, verify Fiducia JWTs offline via JWKS, and reject
  early before the cluster.
- **Rate limiting** — atomic per-client/tenant quotas through a Durable Object;
  a configured positive limit fails closed if that binding is unavailable.
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
- `FIDUCIA_RATE_LIMIT_PER_MINUTE` / `FIDUCIA_RATE_LIMIT_WINDOW_SECONDS` — atomic
  quota and window. A positive limit requires the `RATE_LIMITER` Durable Object
  binding declared in `wrangler.toml`; KV is intentionally not used for counters
  because read/modify/write is not atomic.

The Worker strips `Authorization`, `x-api-key`, and caller-supplied
`x-fiducia-*` identity headers before forwarding. Regional LBs and nodes should
trust only the identity headers injected by the edge/LB boundary. The Worker
does preserve `Idempotency-Key`; the regional LB consumes that customer header,
hashes it into an internal idempotency record, and strips it before the node hop.

Optionally add a `FIDUCIA_CONFIG` KV namespace for live health/routing.

## Security posture

- **Identity-header stripping.** Before forwarding, the Worker deletes
  caller-supplied `Authorization`, `x-api-key`, `cookie`, `proxy-authorization`,
  and every `x-fiducia-*` identity/trust header (including the internal
  `x-fiducia-edge-auth` / `x-fiducia-internal-auth` hop proofs), then re-injects
  only the identity it verified. Downstream LBs/nodes trust `x-fiducia-*` only
  when the shared `FIDUCIA_INTERNAL_SECRET` proof is present, so a client cannot
  spoof identity.
- **No SSRF / no open redirect.** Forward targets are built only from the
  operator-configured `FIDUCIA_REGIONS` (or `FIDUCIA_CONFIG` KV) origins — never
  from client input — and upstream responses use `redirect: "manual"`, so the
  edge never follows a redirect to an attacker-chosen host.
- **No ambiguous write replay.** Cross-region retries are restricted to
  `GET`/`HEAD`/`OPTIONS`. A mutation timeout returns
  `502 ambiguous_upstream_result`; the client may retry with the same
  `Idempotency-Key` so the regional LB can replay its durable result.
- **Auth at the edge.** API keys are introspected against `fiducia-auth` (with
  short positive/negative caching); JWTs are verified offline against JWKS with
  `RS256`/`ES256` only, plus issuer/audience/expiry checks. Per-tenant rate
  limiting shields the cluster.
- **Atomic quotas.** Rate-limit increments execute in a Durable Object storage
  transaction. Cloudflare KV is never used as a counter; if a positive quota is
  configured but the object cannot be reached, requests fail closed with 503.
- **Secrets are Worker secrets, never logged.** `FIDUCIA_INTERNAL_SECRET` and
  `FIDUCIA_INTROSPECT_SECRET` are injected as Wrangler secrets (not committed to
  `wrangler.toml`) and are never written to logs or responses. Credentials are
  cached by SHA-256 hash, never in cleartext. `npm audit --omit=dev` reports 0
  vulnerabilities.

> Note (non-blocking): a few `authFailure` paths echo the upstream error string
> (`auth service unavailable: <err>`, `invalid or expired jwt: <msg>`) to the
> client. These are low-signal but could be tightened to avoid surfacing any
> internal detail; tracked as a follow-up, not applied here to avoid changing
> response contracts.

## Related

- [`fiducia-load-balance.rs`](https://github.com/fiducia-cloud/fiducia-load-balance.rs) — the regional LB this forwards to.
- [`fiducia-routing.rs`](https://github.com/fiducia-cloud/fiducia-routing.rs) — shared `key → shard` (WASM-able for the edge).
- [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) — control plane (region health / placement source).
