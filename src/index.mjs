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

/**
 * Error/response shapes are defined once in `@fiducia/interfaces` (the shared
 * contract). The edge forwards node/LB responses through untouched (it owns
 * redirects internally), but pins the types it reasons about from that source.
 *
 * @typedef {import("@fiducia/interfaces/typescript").ProposeError} ProposeError
 * @typedef {import("@fiducia/interfaces/typescript").Introspection} Introspection
 */

/** Parse the configured regional load-balancer origins from env. */
export function loadRegions(env) {
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
export function pickRegions(request, regions) {
  const _cf = request.cf ?? {};
  // Skeleton: forward in configured order (already a sane primary/secondary).
  return regions;
}

// --- edge auth: verify Fiducia JWTs OFFLINE (WebCrypto + cached JWKS) and
// introspect API keys via auth (cached). Both keep the hot path off auth. ---

const ISSUER = "fiducia-auth";
const JWKS_TTL_MS = 10 * 60 * 1000;
const INTROSPECT_TTL_MS = 30 * 1000;
const NEGATIVE_TTL_MS = 5 * 1000;

// Per-isolate caches (Workers reuse an isolate across requests).
let _jwks = { keys: null, at: 0 };
const _keyCache = new Map(); // kid -> CryptoKey
const _introCache = new Map(); // api key -> { identity, exp }

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJSON(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

async function fetchJwks(env) {
  const now = Date.now();
  if (_jwks.keys && now - _jwks.at < JWKS_TTL_MS) return _jwks.keys;
  const base = (env.FIDUCIA_AUTH_URL ?? "").replace(/\/$/, "");
  if (!base) return _jwks.keys ?? [];
  try {
    const r = await fetch(`${base}/.well-known/jwks.json`);
    if (r.ok) {
      const set = await r.json();
      _jwks = { keys: set.keys ?? [], at: now };
      _keyCache.clear();
    }
  } catch {
    /* serve stale on a transient failure */
  }
  return _jwks.keys ?? [];
}

/** Verify a Fiducia-issued ES256 JWT offline against the published JWKS. */
export async function verifyJwt(token, env) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header = b64urlToJSON(parts[0]);
    payload = b64urlToJSON(parts[1]);
  } catch {
    return null;
  }
  if (header.alg !== "ES256") return null;

  const jwk = (await fetchJwks(env)).find((k) => k.kid === header.kid);
  if (!jwk) return null;
  let key = _keyCache.get(header.kid);
  if (!key) {
    try {
      key = await crypto.subtle.importKey(
        "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      _keyCache.set(header.kid, key);
    } catch {
      return null;
    }
  }
  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, b64urlToBytes(parts[2]), data);
  if (!ok) return null;

  if (payload.iss !== ISSUER) return null;
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp < now) return null;
  return { org: payload.org_id ?? payload.sub ?? "", scopes: payload.scopes ?? [], via: "jwt" };
}

/** Validate an API key via auth introspection, caching the result. */
async function introspectKey(token, env) {
  const now = Date.now();
  const hit = _introCache.get(token);
  if (hit && hit.exp > now) return hit.identity;
  const base = (env.FIDUCIA_AUTH_URL ?? "").replace(/\/$/, "");
  if (!base) return null;
  try {
    const headers = { "content-type": "application/json" };
    if (env.FIDUCIA_INTROSPECT_SECRET) headers["x-server-auth"] = env.FIDUCIA_INTROSPECT_SECRET;
    const r = await fetch(`${base}/v1/introspect`, {
      method: "POST", headers, body: JSON.stringify({ api_key: token }),
    });
    if (!r.ok) return null;
    const intro = await r.json();
    if (!intro.valid) {
      _introCache.set(token, { identity: null, exp: now + NEGATIVE_TTL_MS });
      return null;
    }
    const identity = { org: intro.org_id ?? "", scopes: intro.scopes ?? [], via: "api_key" };
    _introCache.set(token, { identity, exp: now + INTROSPECT_TTL_MS });
    return identity;
  } catch {
    return null;
  }
}

/**
 * Authenticate at the edge. Permissive by default (absent creds allowed, no
 * identity); `FIDUCIA_AUTH_MODE=enforce` requires valid creds. Present-but-invalid
 * is always rejected.
 */
export async function authenticate(request, env) {
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  const enforce = (env.FIDUCIA_AUTH_MODE ?? "").toLowerCase() === "enforce";
  if (!token) {
    return enforce ? { ok: false, status: 401, error: "authentication required" } : { ok: true, identity: null };
  }
  const identity = token.startsWith("fdc_") ? await introspectKey(token, env) : await verifyJwt(token, env);
  return identity ? { ok: true, identity } : { ok: false, status: 401, error: "invalid credentials" };
}

/** Per-client/tenant API rate limit, to protect the cluster. TODO. */
async function checkRateLimit(_request, _env) {
  // TODO: Durable Object or KV counter keyed by token/IP.
  return { ok: true };
}

/**
 * Is this request safe to serve from the edge cache? Default: no.
 * Coordination state is consistency-sensitive — NEVER cache writes or locks.
 * Only explicitly opt-in config reads (`GET /v1/kv?key=...&cache=...`).
 */
export function isCacheableRead(request) {
  if (request.method !== "GET") return false;
  const url = new URL(request.url);
  // KV keys are a `?key=` query param (never a path segment), and a `watch`
  // stream must never be cached. Cache only an explicit, non-watch KV read.
  return (
    url.pathname === "/v1/kv" &&
    url.searchParams.has("key") &&
    url.searchParams.has("cache") &&
    !url.searchParams.has("watch")
  );
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
    const authResult = await authenticate(request, env);
    if (!authResult.ok) {
      return Response.json({ error: "unauthorized", detail: authResult.error }, { status: authResult.status });
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
    return forwardWithFailover(request, regions, authResult.identity);
  },
};
