/**
 * fiducia-edge — Cloudflare Worker, the global edge entry for fiducia.cloud.
 *
 * Tier 1 of a two-tier router:
 *   - THIS worker (global, at CF PoPs): pick the right *region* (geo + health),
 *     handle edge concerns (auth, rate limit, opt-in read caching, DDoS/WAF via
 *     Cloudflare), then forward to that region's load balancer.
 *   - fiducia-load-balance (regional): picks the right *node* within the region
 *     (key -> shard -> leader). The edge stays shard-agnostic.
 *
 * If you ever need shard-awareness at the edge (e.g. route straight to a
 * geo-pinned shard's home region), do NOT reimplement the hash in JS — compile
 * the `fiducia-routing` crate to WASM and import it here, so `key -> shard` can
 * never drift from the data plane.
 *
 * Caveats baked in below:
 *   - never cache writes or locks; only explicitly opt-in config reads;
 *   - the edge cuts client<->front-door RTT, but a strongly-consistent write
 *     still has to reach the shard leader + a quorum. Edge != consensus.
 *
 * Skeleton: region selection + failover forwarding are real; auth, rate limit,
 * and health are stubbed (they need KV / Durable Object bindings).
 */

/** Parse the configured regional load-balancer origins from env. */
function loadRegions(env) {
  try {
    return JSON.parse(env.FIDUCIA_REGIONS ?? "[]");
  } catch {
    return [];
  }
}

/**
 * Order candidate regions for this request: healthy first, then by proximity to
 * the client's Cloudflare colo.
 *
 * TODO: real health from KV (env.FIDUCIA_CONFIG) + a colo/continent -> region
 * proximity table using request.cf.{colo,continent,country}.
 */
function pickRegions(request, regions) {
  const _cf = request.cf ?? {};
  // Skeleton: forward in configured order (already a sane primary/secondary).
  return regions;
}

/** Reject unauthenticated requests at the edge. TODO: real verification. */
function checkAuth(_request, _env) {
  // TODO: validate Authorization / API key (JWT verify or KV lookup).
  return { ok: true };
}

/** Per-client/tenant API rate limit, to protect the cluster. TODO. */
async function checkRateLimit(_request, _env) {
  // TODO: Durable Object or KV counter keyed by token/IP.
  return { ok: true };
}

/**
 * Is this request safe to serve from the edge cache? Default: no.
 * Coordination state is consistency-sensitive — NEVER cache writes or locks.
 * Only explicitly opt-in config reads (`GET /v1/kv/...?cache=...`).
 */
function isCacheableRead(request) {
  if (request.method !== "GET") return false;
  const url = new URL(request.url);
  return url.pathname.startsWith("/v1/kv/") && url.searchParams.has("cache");
}

/** Forward to the first region that answers; fail over to the next on 5xx/error. */
async function forwardWithFailover(request, regions) {
  const url = new URL(request.url);
  // Buffer the body once so we can retry against another region.
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  let lastErr = "no regions configured";
  for (const region of regions) {
    const target = new URL(url.pathname + url.search, region.url);
    const headers = new Headers(request.headers);
    headers.set("x-fiducia-edge-region", region.name);
    try {
      const resp = await fetch(target, {
        method: request.method,
        headers,
        body,
        redirect: "manual", // let the LB/node own NotLeader redirects internally
      });
      // A region-level failure (5xx, but not a deliberate 501 stub) -> next region.
      if (resp.status >= 500 && resp.status !== 501) {
        lastErr = `region ${region.name} -> ${resp.status}`;
        continue;
      }
      return resp;
    } catch (e) {
      lastErr = `region ${region.name} unreachable: ${e}`;
    }
  }
  return Response.json({ error: "no_region", detail: lastErr }, { status: 502 });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // The edge's own liveness (not proxied).
    if (url.pathname === "/_edge/healthz") {
      return Response.json({ status: "ok", service: "fiducia-edge" });
    }

    // 1. Auth + rate limit at the edge — reject early, shield the cluster.
    if (!checkAuth(request, env).ok) {
      return new Response("unauthorized", { status: 401 });
    }
    if (!(await checkRateLimit(request, env)).ok) {
      return new Response("rate_limited", { status: 429 });
    }

    // 2. Opt-in, idempotent reads may be served from the edge cache.
    if (isCacheableRead(request)) {
      const cached = await caches.default.match(request);
      if (cached) return cached;
      // TODO: on miss, cache the LB response via ctx.waitUntil(cache.put(...))
      // honoring the requested TTL.
    }

    // 3. Pick regions (healthy + nearest) and forward to that region's LB,
    //    which routes key -> shard -> leader within the region.
    const regions = pickRegions(request, loadRegions(env));
    if (regions.length === 0) {
      return Response.json({ error: "no_regions_configured" }, { status: 503 });
    }
    return forwardWithFailover(request, regions);
  },
};
