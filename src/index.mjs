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
 * Region selection, failover forwarding, auth, rate limiting, live region
 * health, and opt-in read caching are wired. Bind KV namespaces for live config
 * (`FIDUCIA_CONFIG`) and rate limiting (`FIDUCIA_RATE_LIMIT_KV`) when deployed.
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
 * the client's Cloudflare colo/continent.
 */
export function pickRegions(request, regions, health = {}) {
  const cf = request.cf ?? {};
  const continent = String(cf.continent || "").toUpperCase();
  return [...regions].sort((a, b) => {
    const aHealthy = regionIsHealthy(a, health);
    const bHealthy = regionIsHealthy(b, health);
    return Number(bHealthy) - Number(aHealthy)
      || regionDistance(a, continent) - regionDistance(b, continent)
      || String(a.name || "").localeCompare(String(b.name || ""));
  });
}

const DEFAULT_AUTH_URL = "https://auth.fiducia.cloud";
const DEFAULT_AUTH_CACHE_TTL_SECONDS = 60;
const DEFAULT_NEGATIVE_AUTH_CACHE_TTL_SECONDS = 5;
const DEFAULT_JWKS_TTL_SECONDS = 600;
const DEFAULT_JWT_CACHE_TTL_SECONDS = 60;
const DEFAULT_JWT_ISSUER = "fiducia-auth";
const DEFAULT_JWT_AUDIENCE = "fiducia-api";
const DEFAULT_EDGE_CONFIG_KEY = "fiducia-edge/config";
const DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60;
const DEFAULT_CACHE_TTL_SECONDS = 30;
const MAX_CACHE_TTL_SECONDS = 300;

const authCache = new Map();
const jwksCache = new Map();

/** Extract the public client credential without logging or storing the raw value. */
export function extractCredential(request) {
  const authorization = request.headers.get("authorization") ?? "";
  const bearer = authorization.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  if (bearer) return bearer;

  const apiKey = request.headers.get("x-api-key")?.trim();
  return apiKey || null;
}

export function isApiKeyCredential(value) {
  return value.startsWith("fdc_") && value.includes(".");
}

export function looksLikeJwt(value) {
  return value.split(".").length === 3;
}

/** Reject unauthenticated requests at the edge, with hot-path caching. */
export async function checkAuth(request, env) {
  const credential = extractCredential(request);
  const required = envBool(env, "FIDUCIA_AUTH_REQUIRED", false);

  if (!credential) {
    return required
      ? authFailure(401, "missing_credentials", "send Authorization: Bearer <api-key-or-token>")
      : { ok: true, identity: null };
  }

  if (isApiKeyCredential(credential)) {
    if (!envBool(env, "FIDUCIA_AUTH_ALLOW_API_KEYS", true)) {
      return authFailure(401, "api_keys_disabled", "api key authentication is disabled");
    }
    return checkApiKey(credential, env);
  }

  if (looksLikeJwt(credential)) {
    if (!envBool(env, "FIDUCIA_AUTH_ALLOW_JWTS", true)) {
      return authFailure(401, "jwt_disabled", "jwt authentication is disabled");
    }
    return verifyFiduciaJwt(credential, env);
  }

  return authFailure(401, "unsupported_credentials", "credential must be a fiducia API key or JWT");
}

async function checkApiKey(apiKey, env) {
  const cacheKey = await credentialCacheKey("api_key", apiKey);
  const cached = getCachedAuth(cacheKey);
  if (cached !== undefined) {
    return cached ? { ok: true, identity: cached, cache: "hit" } : authFailure(401, "invalid_api_key", "invalid api key");
  }

  const authUrl = normalizedAuthUrl(env);
  const introspectUrl = env.FIDUCIA_AUTH_INTROSPECT_URL || `${authUrl}/v1/introspect`;
  let response;
  try {
    const headers = { "content-type": "application/json" };
    if (env.FIDUCIA_INTROSPECT_SECRET) {
      headers["x-server-auth"] = env.FIDUCIA_INTROSPECT_SECRET;
    }
    response = await fetch(introspectUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ api_key: apiKey }),
    });
  } catch (err) {
    return authFailure(503, "auth_unavailable", `auth service unavailable: ${err}`);
  }

  if (!response.ok) {
    return authFailure(503, "auth_unavailable", `auth service returned ${response.status}`);
  }

  const intro = await response.json();
  if (!intro.valid || !intro.org_id) {
    setCachedAuth(cacheKey, null, envNumber(env, "FIDUCIA_AUTH_NEGATIVE_CACHE_TTL_SECONDS", DEFAULT_NEGATIVE_AUTH_CACHE_TTL_SECONDS));
    return authFailure(401, "invalid_api_key", "invalid api key");
  }

  const identity = {
    kind: "api_key",
    orgId: String(intro.org_id),
    keyId: intro.key_id ? String(intro.key_id) : null,
    scopes: Array.isArray(intro.scopes) ? intro.scopes.map(String) : [],
  };
  setCachedAuth(cacheKey, identity, envNumber(env, "FIDUCIA_AUTH_CACHE_TTL_SECONDS", DEFAULT_AUTH_CACHE_TTL_SECONDS));
  return { ok: true, identity, cache: "miss" };
}

async function verifyFiduciaJwt(jwt, env) {
  const cacheKey = await credentialCacheKey("jwt", jwt);
  const cached = getCachedAuth(cacheKey);
  if (cached !== undefined) {
    return cached ? { ok: true, identity: cached, cache: "hit" } : authFailure(401, "invalid_jwt", "invalid jwt");
  }

  try {
    const parts = jwt.split(".");
    const header = JSON.parse(base64UrlDecodeToText(parts[0]));
    const claims = JSON.parse(base64UrlDecodeToText(parts[1]));
    const alg = String(header.alg || "");
    const kid = String(header.kid || "");
    if (!kid) throw new Error("missing kid");
    if (!["RS256", "ES256"].includes(alg)) throw new Error(`unsupported alg ${alg}`);

    const jwk = await jwkForKid(kid, env);
    const validSignature = await verifyJwtSignature(alg, jwk, `${parts[0]}.${parts[1]}`, parts[2]);
    if (!validSignature) throw new Error("bad signature");
    validateClaims(claims, env);

    const identity = {
      kind: "jwt",
      orgId: String(claims.org_id || claims.sub),
      keyId: claims.key_id ? String(claims.key_id) : null,
      scopes: normalizeScopes(claims.scopes),
    };
    const ttl = Math.min(
      Math.max(1, Number(claims.exp) - nowSeconds()),
      envNumber(env, "FIDUCIA_AUTH_JWT_CACHE_TTL_SECONDS", DEFAULT_JWT_CACHE_TTL_SECONDS),
    );
    setCachedAuth(cacheKey, identity, ttl);
    return { ok: true, identity, cache: "miss" };
  } catch (err) {
    setCachedAuth(cacheKey, null, envNumber(env, "FIDUCIA_AUTH_NEGATIVE_CACHE_TTL_SECONDS", DEFAULT_NEGATIVE_AUTH_CACHE_TTL_SECONDS));
    return authFailure(401, "invalid_jwt", `invalid or expired jwt: ${err.message}`);
  }
}

/** Per-client/tenant API rate limit, to protect the cluster. */
export async function checkRateLimit(request, env, identity = null) {
  const limit = envNumber(env, "FIDUCIA_RATE_LIMIT_PER_MINUTE", 0);
  if (limit <= 0 || !env.FIDUCIA_RATE_LIMIT_KV) {
    return { ok: true, remaining: null };
  }

  const windowSeconds = envNumber(
    env,
    "FIDUCIA_RATE_LIMIT_WINDOW_SECONDS",
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
  );
  const now = nowSeconds();
  const windowId = Math.floor(now / windowSeconds);
  const subject = identity?.orgId
    || extractCredential(request)
    || request.headers.get("cf-connecting-ip")
    || "anonymous";
  const key = `rl:${await toSha256Hex(subject)}:${windowId}`;
  const current = Number(await env.FIDUCIA_RATE_LIMIT_KV.get(key) || "0");
  if (current >= limit) {
    return {
      ok: false,
      remaining: 0,
      resetSeconds: (windowId + 1) * windowSeconds - now,
    };
  }
  await env.FIDUCIA_RATE_LIMIT_KV.put(String(key), String(current + 1), {
    expirationTtl: Math.max(1, windowSeconds + 5),
  });
  return {
    ok: true,
    remaining: Math.max(0, limit - current - 1),
    resetSeconds: (windowId + 1) * windowSeconds - now,
  };
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
async function forwardWithFailover(request, regions, auth, env) {
  const url = new URL(request.url);
  // Buffer the body once so we can retry against another region.
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  let lastErr = "no regions configured";
  for (const region of regions) {
    const target = new URL(url.pathname + url.search, region.url);
    const headers = headersForOrigin(request.headers, auth?.identity ?? null, env);
    headers.set("x-fiducia-edge-region", region.name);
    try {
      const resp = await fetch(target, {
        method: request.method,
        headers,
        body,
        redirect: "manual", // let the LB/node own NotLeader redirects internally
      });
      // A region-level failure (5xx, but not a deliberate 501 capability response) -> next region.
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
    const auth = await checkAuth(request, env);
    if (!auth.ok) {
      return auth.response;
    }
    const rate = await checkRateLimit(request, env, auth.identity);
    if (!rate.ok) {
      return Response.json(
        { error: "rate_limited", reset_seconds: rate.resetSeconds },
        { status: 429 },
      );
    }

    // 2. Opt-in, idempotent reads may be served from the edge cache.
    const cacheKey = isCacheableRead(request) ? cacheKeyFor(request, auth.identity) : null;
    if (isCacheableRead(request)) {
      const cached = await caches.default.match(cacheKey);
      if (cached) return cached;
    }

    // 3. Pick regions (healthy + nearest) and forward to that region's LB,
    //    which routes key -> shard -> leader within the region.
    const edgeConfig = await loadEdgeConfig(env);
    const regions = pickRegions(
      request,
      edgeConfig.regions.length ? edgeConfig.regions : loadRegions(env),
      edgeConfig.health,
    );
    if (regions.length === 0) {
      return Response.json({ error: "no_regions_configured" }, { status: 503 });
    }
    const response = await forwardWithFailover(request, regions, auth, env);
    if (cacheKey && response.ok) {
      const ttl = cacheTtlSeconds(request, env);
      const cachedResponse = new Response(response.clone().body, response);
      cachedResponse.headers.set("cache-control", `public, max-age=${ttl}`);
      ctx?.waitUntil?.(caches.default.put(cacheKey, cachedResponse));
    }
    return response;
  },
};

export async function loadEdgeConfig(env) {
  const staticRegions = loadRegions(env);
  const staticHealth = parseJsonObject(env.FIDUCIA_REGION_HEALTH_JSON);
  const kv = env.FIDUCIA_CONFIG;
  if (!kv?.get) {
    return { regions: staticRegions, health: staticHealth };
  }

  try {
    const raw = await kv.get(env.FIDUCIA_CONFIG_KEY || DEFAULT_EDGE_CONFIG_KEY);
    if (!raw) return { regions: staticRegions, health: staticHealth };
    const parsed = JSON.parse(raw);
    return {
      regions: Array.isArray(parsed.regions) ? parsed.regions : staticRegions,
      health: parsed.health || parsed.region_health || staticHealth,
    };
  } catch {
    return { regions: staticRegions, health: staticHealth };
  }
}

function regionIsHealthy(region, health) {
  const name = String(region.name || "");
  const value = health?.[name] ?? region.health ?? "healthy";
  return !["0", "false", "down", "dead", "unhealthy"].includes(String(value).toLowerCase());
}

function regionDistance(region, continent) {
  if (!continent) return 50;
  const regionName = String(region.name || region.region || "").toLowerCase();
  const hint = String(region.continent || "").toUpperCase();
  if (hint && hint === continent) return 0;
  if (continent === "NA" && /(us|ca|america|iad|sfo|ord|dfw|atl)/.test(regionName)) return 1;
  if (continent === "EU" && /(eu|europe|fra|ams|lhr|par|nbg|hel)/.test(regionName)) return 1;
  if (continent === "AS" && /(asia|ap-|sin|hkg|nrt|bom)/.test(regionName)) return 1;
  if (continent === "SA" && /(south|gru|scl)/.test(regionName)) return 1;
  if (continent === "OC" && /(syd|mel|australia)/.test(regionName)) return 1;
  if (continent === "AF" && /(africa|jnb|cpt)/.test(regionName)) return 1;
  return 10;
}

function parseJsonObject(value) {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function cacheKeyFor(request, identity) {
  const url = new URL(request.url);
  url.searchParams.set("__fiducia_org", identity?.orgId || "anonymous");
  url.searchParams.set("__fiducia_auth", identity?.keyId || identity?.kind || "public");
  return new Request(url.toString(), { method: "GET" });
}

function cacheTtlSeconds(request, env) {
  const url = new URL(request.url);
  const requested = Number(url.searchParams.get("cache"));
  const defaultTtl = envNumber(env, "FIDUCIA_EDGE_CACHE_TTL_SECONDS", DEFAULT_CACHE_TTL_SECONDS);
  const maxTtl = envNumber(env, "FIDUCIA_EDGE_MAX_CACHE_TTL_SECONDS", MAX_CACHE_TTL_SECONDS);
  const ttl = Number.isFinite(requested) && requested > 0 ? requested : defaultTtl;
  return Math.max(1, Math.min(ttl, maxTtl));
}

export function headersForOrigin(sourceHeaders, identity) {
  const headers = new Headers(sourceHeaders);
  for (const name of [
    "authorization",
    "x-api-key",
    "cookie",
    "proxy-authorization",
    "x-fiducia-auth-kind",
    "x-fiducia-org-id",
    "x-fiducia-key-id",
    "x-fiducia-scopes",
    // Trusted-hop secret between the LB and nodes; a client must never inject it.
    "x-fiducia-internal-auth",
  ]) {
    headers.delete(name);
  }

  if (identity) {
    headers.set("x-fiducia-auth-kind", identity.kind);
    headers.set("x-fiducia-org-id", identity.orgId);
    headers.set("x-fiducia-scopes", identity.scopes.join(" "));
    if (identity.keyId) headers.set("x-fiducia-key-id", identity.keyId);
  }

  return headers;
}

async function jwkForKid(kid, env) {
  const jwksUrl = env.FIDUCIA_AUTH_JWKS_URL || `${normalizedAuthUrl(env)}/.well-known/jwks.json`;
  const cached = jwksCache.get(jwksUrl);
  if (cached && cached.expiresAt > Date.now()) {
    const jwk = cached.keys.find((key) => key.kid === kid);
    if (jwk) return jwk;
  }

  const response = await fetch(jwksUrl);
  if (!response.ok) throw new Error(`jwks ${response.status}`);
  const jwks = await response.json();
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  jwksCache.set(jwksUrl, {
    keys,
    expiresAt: Date.now() + envNumber(env, "FIDUCIA_AUTH_JWKS_TTL_SECONDS", DEFAULT_JWKS_TTL_SECONDS) * 1000,
  });
  const jwk = keys.find((key) => key.kid === kid);
  if (!jwk) throw new Error(`missing jwk ${kid}`);
  return jwk;
}

async function verifyJwtSignature(alg, jwk, signingInput, signaturePart) {
  const signature = base64UrlDecodeToBytes(signaturePart);
  const data = new TextEncoder().encode(signingInput);
  const params = alg === "RS256"
    ? { importAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verifyAlg: "RSASSA-PKCS1-v1_5" }
    : { importAlg: { name: "ECDSA", namedCurve: "P-256" }, verifyAlg: { name: "ECDSA", hash: "SHA-256" } };
  const key = await crypto.subtle.importKey("jwk", jwk, params.importAlg, false, ["verify"]);
  return crypto.subtle.verify(params.verifyAlg, key, signature, data);
}

function validateClaims(claims, env) {
  const now = nowSeconds();
  if (!claims.sub && !claims.org_id) throw new Error("missing subject");
  if (!claims.exp || Number(claims.exp) <= now) throw new Error("expired");
  const issuer = env.FIDUCIA_JWT_ISSUER || DEFAULT_JWT_ISSUER;
  if (claims.iss !== issuer) throw new Error("bad issuer");
  const expectedAud = env.FIDUCIA_JWT_AUDIENCE || DEFAULT_JWT_AUDIENCE;
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expectedAud)) throw new Error("bad audience");
}

function normalizeScopes(value) {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "string") return value.split(/\s+/).filter(Boolean);
  return [];
}

async function credentialCacheKey(kind, credential) {
  return `${kind}:${await toSha256Hex(credential)}`;
}

async function toSha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(new Uint8Array(digest));
}

function getCachedAuth(cacheKey) {
  const cached = authCache.get(cacheKey);
  if (!cached) return undefined;
  if (cached.expiresAt <= Date.now()) {
    authCache.delete(cacheKey);
    return undefined;
  }
  return cached.identity;
}

function setCachedAuth(cacheKey, identity, ttlSeconds) {
  if (ttlSeconds <= 0) return;
  authCache.set(cacheKey, {
    identity,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
}

function authFailure(status, error, detail) {
  return { ok: false, response: Response.json({ error, detail }, { status }) };
}

function normalizedAuthUrl(env) {
  return String(env.FIDUCIA_AUTH_URL || DEFAULT_AUTH_URL).replace(/\/+$/, "");
}

function envBool(env, name, defaultValue) {
  const value = env[name];
  if (value === undefined || value === null || value === "") return defaultValue;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function envNumber(env, name, defaultValue) {
  const n = Number(env[name]);
  return Number.isFinite(n) && n >= 0 ? n : defaultValue;
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64UrlDecodeToText(value) {
  return new TextDecoder().decode(base64UrlDecodeToBytes(value));
}

function base64UrlDecodeToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
