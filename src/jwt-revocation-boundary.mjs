const DEFAULT_AUTH_URL = "https://auth.fiducia.cloud";
const DEFAULT_JWKS_TTL_SECONDS = 600;
const DEFAULT_JWT_CACHE_TTL_SECONDS = 60;
const DEFAULT_REVOCATION_CACHE_TTL_SECONDS = 30;
const DEFAULT_REVOCATION_TIMEOUT_MS = 2_000;
const DEFAULT_REVOCATION_CACHE_CAPACITY = 10_000;
const DEFAULT_JWT_ISSUER = "fiducia-auth";
const DEFAULT_JWT_AUDIENCE = "fiducia-api";
const MAX_ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

const revocationCache = new Map();
const refreshes = new Map();
const jwksCache = new Map();
const verifiedJwtCache = new Map();
let clockHighWaterMs = 0;

export async function enforceJwtRevocationBoundary(request, env, options = {}) {
  const credential = extractBearer(request);
  if (!credential || !looksLikeJwt(credential)) return null;

  let claims;
  try {
    claims = await verifyJwt(credential, env, options);
  } catch (error) {
    emitMetric(env, "jwt_offline_validation", "invalid", 0);
    logSafeWarning("jwt offline validation failed", error);
    return failureResponse(401, "invalid_jwt", "invalid or expired jwt");
  }

  const decision = await authorizeRevocation(claims, env, options);
  if (decision.kind === "allow") return null;
  if (decision.kind === "deny") {
    return failureResponse(401, "invalid_jwt", "invalid or expired jwt");
  }
  return failureResponse(503, "auth_unavailable", "auth service unavailable");
}

export async function authorizeRevocation(claims, env, options = {}) {
  const nowMs = options.nowMs ?? Date.now();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const clock = observeClock(nowMs);
  if (!clock.ok) {
    emitMetric(env, "revocation_lookup", "clock_regression", 0);
    return { kind: "unavailable", reason: "clock_regression", cache: "error" };
  }

  let cacheKey;
  try {
    cacheKey = await revocationCacheKey(claims);
  } catch {
    emitMetric(env, "revocation_lookup", "invalid_claims", 0);
    return { kind: "unavailable", reason: "invalid_claims", cache: "error" };
  }

  const cached = lookupCached(cacheKey, nowMs);
  emitMetric(env, "revocation_lookup", cached.outcome, cached.staleAgeMs ?? 0);
  if (cached.outcome === "fresh_negative") {
    return { kind: "allow", cache: cached.outcome };
  }
  if (cached.outcome === "fresh_positive") {
    return denyFromEntry(cached.entry, cached.outcome);
  }

  const priorPositive = cached.entry?.revoked === true;
  const startedAt = Date.now();
  const refreshed = await refreshSingleFlight(cacheKey, claims, env, nowMs, fetchImpl);
  emitMetric(
    env,
    "revocation_refresh",
    refreshed.ok ? "success" : refreshed.reason,
    Math.max(0, Date.now() - startedAt),
  );

  if (!refreshed.ok) {
    if (priorPositive) {
      return denyFromEntry(cached.entry, "stale_positive", refreshed.reason);
    }
    return { kind: "unavailable", reason: refreshed.reason, cache: cached.outcome };
  }
  if (refreshed.entry.revoked) {
    return denyFromEntry(refreshed.entry, "refreshed");
  }
  return { kind: "allow", cache: "refreshed" };
}

async function refreshSingleFlight(cacheKey, claims, env, nowMs, fetchImpl) {
  const existing = refreshes.get(cacheKey);
  if (existing) return existing;

  const refresh = refreshAuthority(claims, env, nowMs, fetchImpl)
    .then((result) => {
      if (result.ok) installDecision(cacheKey, result.entry, env);
      return result;
    })
    .finally(() => {
      if (refreshes.get(cacheKey) === refresh) refreshes.delete(cacheKey);
    });
  refreshes.set(cacheKey, refresh);
  return refresh;
}

async function refreshAuthority(claims, env, nowMs, fetchImpl) {
  const readerSecret = String(env.FIDUCIA_REVOCATION_READER_SECRET || "");
  if (readerSecret.length < 32 || /\s/.test(readerSecret)) {
    return { ok: false, reason: "reader_credentials_unavailable" };
  }

  const authUrl = String(env.FIDUCIA_AUTH_URL || DEFAULT_AUTH_URL).replace(/\/+$/, "");
  const endpoint = String(
    env.FIDUCIA_REVOCATION_CHECK_URL || `${authUrl}/v1/revocations/check`,
  );
  let parsedEndpoint;
  try {
    parsedEndpoint = new URL(endpoint);
  } catch {
    return { ok: false, reason: "invalid_endpoint" };
  }
  if (parsedEndpoint.protocol !== "https:" && !allowInsecureTestEndpoint(env, parsedEndpoint)) {
    return { ok: false, reason: "invalid_endpoint" };
  }

  const timeoutMs = positiveNumber(
    env.FIDUCIA_REVOCATION_TIMEOUT_MS,
    DEFAULT_REVOCATION_TIMEOUT_MS,
  );
  const controller = new AbortController();
  let timeout;
  const timedOut = new Promise((resolve) => {
    timeout = setTimeout(() => {
      controller.abort("revocation timeout");
      resolve({ timedOut: true });
    }, timeoutMs);
  });
  try {
    const request = fetchImpl(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-revocation-reader-auth": readerSecret,
      },
      body: JSON.stringify({ claims: normalizedClaims(claims) }),
      signal: controller.signal,
    });
    const response = await Promise.race([request, timedOut]);
    if (response?.timedOut) return { ok: false, reason: "timeout" };
    if (!response?.ok) return { ok: false, reason: "authority_error" };

    let body;
    try {
      body = await response.json();
    } catch {
      return { ok: false, reason: "malformed_decision" };
    }
    const decision = parseDecision(body?.decision);
    if (!decision) return { ok: false, reason: "malformed_decision" };

    const freshnessMs = positiveNumber(
      env.FIDUCIA_REVOCATION_CACHE_TTL_SECONDS,
      DEFAULT_REVOCATION_CACHE_TTL_SECONDS,
    ) * 1_000;
    return {
      ok: true,
      entry: {
        ...decision,
        observedAtMs: nowMs,
        freshUntilMs: nowMs + freshnessMs,
      },
    };
  } catch (error) {
    return {
      ok: false,
      reason: error?.name === "AbortError" ? "timeout" : "authority_unavailable",
    };
  } finally {
    clearTimeout(timeout);
  }
}

function lookupCached(cacheKey, nowMs) {
  const entry = revocationCache.get(cacheKey);
  if (!entry) return { outcome: "miss", entry: null, staleAgeMs: 0 };

  const authorityExpired = entry.revoked
    && entry.expiresAt !== null
    && Math.floor(nowMs / 1_000) >= entry.expiresAt;
  const fresh = nowMs < entry.freshUntilMs && !authorityExpired;
  if (fresh) {
    return {
      outcome: entry.revoked ? "fresh_positive" : "fresh_negative",
      entry,
      staleAgeMs: 0,
    };
  }
  return {
    outcome: entry.revoked ? "stale_positive" : "stale_negative",
    entry,
    staleAgeMs: Math.max(0, nowMs - entry.freshUntilMs),
  };
}

function installDecision(cacheKey, entry, env) {
  const capacity = Math.max(
    1,
    Math.floor(positiveNumber(
      env.FIDUCIA_REVOCATION_CACHE_CAPACITY,
      DEFAULT_REVOCATION_CACHE_CAPACITY,
    )),
  );
  if (!revocationCache.has(cacheKey) && revocationCache.size >= capacity) {
    let oldestKey = null;
    let oldestTime = Number.POSITIVE_INFINITY;
    for (const [key, value] of revocationCache) {
      if (value.observedAtMs < oldestTime) {
        oldestKey = key;
        oldestTime = value.observedAtMs;
      }
    }
    if (oldestKey !== null) revocationCache.delete(oldestKey);
  }
  revocationCache.set(cacheKey, entry);
}

function parseDecision(value) {
  if (!value || typeof value !== "object" || typeof value.revoked !== "boolean") return null;
  const matchedTarget = value.matched_target ?? null;
  const generation = value.generation ?? null;
  const expiresAt = value.expires_at ?? null;
  if (![null, "token_id", "subject"].includes(matchedTarget)) return null;
  if (generation !== null && (!Number.isSafeInteger(generation) || generation < 0)) return null;
  if (expiresAt !== null && (!Number.isSafeInteger(expiresAt) || expiresAt < 0)) return null;
  if (value.revoked && (matchedTarget === null || generation === null || expiresAt === null)) {
    return null;
  }
  if (!value.revoked && (matchedTarget !== null || expiresAt !== null)) return null;
  return { revoked: value.revoked, matchedTarget, generation, expiresAt };
}

function denyFromEntry(entry, cache, refreshFailure = null) {
  return {
    kind: "deny",
    reason: refreshFailure ? "stale_revocation_unconfirmed" : "revoked",
    matchedTarget: entry?.matchedTarget ?? null,
    generation: entry?.generation ?? null,
    cache,
    refreshFailure,
  };
}

function observeClock(nowMs) {
  if (!Number.isFinite(nowMs) || nowMs < 0) return { ok: false };
  if (nowMs < clockHighWaterMs) return { ok: false };
  clockHighWaterMs = nowMs;
  return { ok: true };
}

async function verifyJwt(jwt, env, options) {
  const nowMs = options.nowMs ?? Date.now();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const cacheKey = `jwt:${await sha256Hex(jwt)}`;
  const cached = verifiedJwtCache.get(cacheKey);
  if (cached && cached.expiresAtMs > nowMs) return cached.claims;
  if (cached) verifiedJwtCache.delete(cacheKey);

  const parts = jwt.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) throw new Error("invalid jwt shape");
  const header = JSON.parse(base64UrlDecodeToText(parts[0]));
  const claims = JSON.parse(base64UrlDecodeToText(parts[1]));
  const alg = String(header.alg || "");
  const kid = String(header.kid || "");
  if (!kid) throw new Error("missing kid");
  if (!["RS256", "ES256"].includes(alg)) throw new Error("unsupported algorithm");

  const jwk = await jwkForKid(kid, env, fetchImpl, nowMs);
  const valid = await verifyJwtSignature(alg, jwk, `${parts[0]}.${parts[1]}`, parts[2]);
  if (!valid) throw new Error("invalid signature");
  validateClaims(claims, env, nowMs);

  const ttlMs = Math.min(
    Number(claims.exp) * 1_000 - nowMs,
    positiveNumber(env.FIDUCIA_AUTH_JWT_CACHE_TTL_SECONDS, DEFAULT_JWT_CACHE_TTL_SECONDS) * 1_000,
  );
  verifiedJwtCache.set(cacheKey, { claims, expiresAtMs: nowMs + Math.max(1, ttlMs) });
  return claims;
}

async function jwkForKid(kid, env, fetchImpl, nowMs) {
  const authUrl = String(env.FIDUCIA_AUTH_URL || DEFAULT_AUTH_URL).replace(/\/+$/, "");
  const jwksUrl = String(env.FIDUCIA_AUTH_JWKS_URL || `${authUrl}/.well-known/jwks.json`);
  const cached = jwksCache.get(jwksUrl);
  if (cached && cached.expiresAtMs > nowMs) {
    const key = cached.keys.find((candidate) => candidate.kid === kid);
    if (key) return key;
  }

  const response = await fetchImpl(jwksUrl);
  if (!response?.ok) throw new Error("jwks unavailable");
  const jwks = await response.json();
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  jwksCache.set(jwksUrl, {
    keys,
    expiresAtMs: nowMs + positiveNumber(
      env.FIDUCIA_AUTH_JWKS_TTL_SECONDS,
      DEFAULT_JWKS_TTL_SECONDS,
    ) * 1_000,
  });
  const key = keys.find((candidate) => candidate.kid === kid);
  if (!key) throw new Error("missing jwk");
  return key;
}

async function verifyJwtSignature(alg, jwk, signingInput, signaturePart) {
  const signature = base64UrlDecodeToBytes(signaturePart);
  const data = new TextEncoder().encode(signingInput);
  const params = alg === "RS256"
    ? {
        importAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        verifyAlgorithm: "RSASSA-PKCS1-v1_5",
      }
    : {
        importAlgorithm: { name: "ECDSA", namedCurve: "P-256" },
        verifyAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      };
  const key = await crypto.subtle.importKey("jwk", jwk, params.importAlgorithm, false, ["verify"]);
  return crypto.subtle.verify(params.verifyAlgorithm, key, signature, data);
}

function validateClaims(claims, env, nowMs) {
  const requiredStrings = ["sub", "org_id", "iss", "aud", "jti"];
  for (const field of requiredStrings) {
    if (typeof claims[field] !== "string" || !claims[field] || /\s/.test(claims[field])) {
      throw new Error(`invalid ${field}`);
    }
  }
  if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)) {
    throw new Error("invalid token time");
  }
  const nowSeconds = Math.floor(nowMs / 1_000);
  if (claims.exp <= nowSeconds || claims.exp <= claims.iat) throw new Error("expired");
  if (claims.exp - claims.iat > MAX_ACCESS_TOKEN_TTL_SECONDS) throw new Error("token ttl too long");
  const issuer = String(env.FIDUCIA_JWT_ISSUER || DEFAULT_JWT_ISSUER);
  const audience = String(env.FIDUCIA_JWT_AUDIENCE || DEFAULT_JWT_AUDIENCE);
  if (claims.iss !== issuer || claims.aud !== audience) throw new Error("wrong token class");
  if (!Array.isArray(claims.scopes) || claims.scopes.some((scope) => typeof scope !== "string")) {
    throw new Error("invalid scopes");
  }
}

function normalizedClaims(claims) {
  return {
    sub: String(claims.sub),
    org_id: String(claims.org_id),
    scopes: claims.scopes.map(String),
    iss: String(claims.iss),
    aud: String(claims.aud),
    iat: Number(claims.iat),
    exp: Number(claims.exp),
    jti: String(claims.jti),
  };
}

async function revocationCacheKey(claims) {
  const normalized = normalizedClaims(claims);
  for (const value of [normalized.iss, normalized.aud, normalized.org_id, normalized.jti]) {
    if (!value || /\s/.test(value)) throw new Error("invalid cache identity");
  }
  return sha256Hex([
    normalized.iss,
    normalized.aud,
    normalized.org_id,
    normalized.jti,
  ].join("\u0000"));
}

function extractBearer(request) {
  const authorization = request.headers.get("authorization") || "";
  return authorization.match(/^Bearer\s+(.+)$/i)?.[1]?.trim() || null;
}

function looksLikeJwt(value) {
  return value.split(".").length === 3;
}

function allowInsecureTestEndpoint(env, endpoint) {
  return String(env.FIDUCIA_DEPLOYMENT_MODE || "").toLowerCase() === "test"
    && ["localhost", "127.0.0.1", "revocation.test"].includes(endpoint.hostname);
}

function positiveNumber(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function emitMetric(env, metric, outcome, value) {
  const binding = env?.REVOCATION_METRICS;
  if (!binding?.writeDataPoint) return;
  try {
    binding.writeDataPoint({
      blobs: [metric, outcome],
      doubles: [Number(value) || 0],
      indexes: [metric],
    });
  } catch {
    // Metrics must never change authorization behavior.
  }
}

function logSafeWarning(message, error) {
  const errorClass = error instanceof SyntaxError
    ? "syntax_error"
    : error instanceof Error
      ? error.name
      : "unknown_error";
  console.warn(`${message}: ${errorClass}`);
}

function failureResponse(status, error, detail) {
  return Response.json({ error, detail }, { status });
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64UrlDecodeToText(value) {
  return new TextDecoder().decode(base64UrlDecodeToBytes(value));
}

function base64UrlDecodeToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function resetRevocationBoundaryForTest() {
  revocationCache.clear();
  refreshes.clear();
  jwksCache.clear();
  verifiedJwtCache.clear();
  clockHighWaterMs = 0;
}
