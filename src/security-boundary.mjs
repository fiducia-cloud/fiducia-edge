const DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60;
const MAX_RETRY_AFTER_SECONDS = 24 * 60 * 60;
const STATIC_FAIL_CLOSED_CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; font-src 'none'; media-src 'none'; worker-src 'none'; manifest-src 'none'; connect-src 'none'";

const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "autoplay=()",
  "camera=()",
  "display-capture=()",
  "geolocation=()",
  "gyroscope=()",
  "magnetometer=()",
  "microphone=()",
  "payment=()",
  "usb=()",
].join(", ");

/** Production is the default because Workers have no reliable startup hook. */
export function isProductionLike(env = {}) {
  const mode = String(env.FIDUCIA_DEPLOYMENT_MODE ?? "production")
    .trim()
    .toLowerCase();
  return !["development", "dev", "local", "test"].includes(mode);
}

/**
 * Build an API-oriented CSP. Additional connect sources must be complete origins;
 * directives, wildcards, credentials, paths, fragments, and query strings are
 * rejected so an environment value cannot inject a weaker policy.
 */
export function buildApiCsp(env = {}) {
  const connectSources = ["'self'", ...parseConnectSources(env)];
  const directives = [
    "default-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'",
    "object-src 'none'",
    "script-src 'none'",
    "style-src 'none'",
    "img-src 'none'",
    "font-src 'none'",
    "media-src 'none'",
    "worker-src 'none'",
    "manifest-src 'none'",
    `connect-src ${connectSources.join(" ")}`,
  ];
  return directives.join("; ");
}

export function parseConnectSources(env = {}) {
  const raw = String(env.FIDUCIA_CSP_CONNECT_SRC ?? "").trim();
  if (!raw) return [];

  const production = isProductionLike(env);
  const sources = new Set();
  for (const token of raw.split(/[\s,]+/).filter(Boolean)) {
    if (token.includes(";") || token.includes("'") || token.includes("*")) {
      throw new Error("invalid CSP connect source");
    }

    let url;
    try {
      url = new URL(token);
    } catch {
      throw new Error("invalid CSP connect source");
    }

    if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
      throw new Error("CSP connect sources must be origin-only");
    }

    const secureProtocol = url.protocol === "https:" || url.protocol === "wss:";
    const localProtocol = url.protocol === "http:" || url.protocol === "ws:";
    const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (!secureProtocol && !(localProtocol && localHost && !production)) {
      throw new Error("insecure CSP connect source");
    }

    sources.add(url.origin);
  }
  return [...sources].sort();
}

/**
 * Return a stable reason code when a session/auth cookie violates the production
 * contract, otherwise null. Cookie values are never returned or logged.
 */
export function sessionCookieViolation(setCookieValue) {
  const cookie = String(setCookieValue ?? "");
  const firstPart = cookie.split(";", 1)[0] ?? "";
  const separator = firstPart.indexOf("=");
  const name = separator >= 0 ? firstPart.slice(0, separator).trim() : "";
  if (!name || !isSessionCookieName(name)) return null;

  if (!name.startsWith("__Host-")) return "host_prefix_required";
  if (!/(?:^|;)\s*secure\s*(?:;|$)/i.test(cookie)) return "secure_required";
  if (!/(?:^|;)\s*httponly\s*(?:;|$)/i.test(cookie)) return "http_only_required";
  if (!/(?:^|;)\s*samesite\s*=\s*strict\s*(?:;|$)/i.test(cookie)) {
    return "same_site_strict_required";
  }
  if (!/(?:^|;)\s*path\s*=\s*\/\s*(?:;|$)/i.test(cookie)) return "root_path_required";
  if (/(?:^|;)\s*domain\s*=/i.test(cookie)) return "domain_forbidden";
  return null;
}

export function responseSessionCookieViolation(headers, env = {}) {
  if (!shouldEnforceCookieContract(env)) return null;
  for (const cookie of getSetCookieValues(headers)) {
    const violation = sessionCookieViolation(cookie);
    if (violation) return violation;
  }
  return null;
}

/** Apply the browser/proxy security boundary to one upstream response. */
export function secureResponse(request, response, env = {}) {
  let csp;
  try {
    csp = buildApiCsp(env);
  } catch (error) {
    console.error(
      "fiducia-edge security boundary configuration rejected:",
      error instanceof Error ? error.message : "invalid configuration",
    );
    return failClosedConfigurationResponse(request);
  }

  const cookieViolation = responseSessionCookieViolation(response.headers, env);
  if (cookieViolation) {
    console.warn(
      "fiducia-edge blocked an upstream response with an insecure session cookie contract:",
      cookieViolation,
    );
    response = Response.json(
      { error: "invalid_session_cookie_contract" },
      { status: 502 },
    );
  }

  const headers = new Headers(response.headers);
  headers.delete("server");
  headers.delete("x-powered-by");
  headers.set("content-security-policy", csp);
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "no-referrer");
  headers.set("permissions-policy", PERMISSIONS_POLICY);
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", resourcePolicy(env));

  const requestUrl = new URL(request.url);
  if (requestUrl.protocol === "https:" && isProductionLike(env)) {
    headers.set("strict-transport-security", hstsValue(env));
  } else {
    headers.delete("strict-transport-security");
  }

  const hasSetCookie = getSetCookieValues(headers).length > 0;
  if (
    hasSetCookie ||
    response.status === 401 ||
    response.status === 403 ||
    response.status === 429 ||
    response.status >= 500
  ) {
    headers.set("cache-control", "no-store");
    headers.set("pragma", "no-cache");
  }

  if (response.status === 429 && !headers.has("retry-after")) {
    headers.set("retry-after", String(retryAfterSeconds(env)));
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function failClosedConfigurationResponse(request) {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    pragma: "no-cache",
    "content-security-policy": STATIC_FAIL_CLOSED_CSP,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": PERMISSIONS_POLICY,
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-site",
  });
  if (new URL(request.url).protocol === "https:") {
    headers.set("strict-transport-security", "max-age=63072000; includeSubDomains");
  }
  return new Response(JSON.stringify({ error: "security_boundary_misconfigured" }), {
    status: 503,
    headers,
  });
}

function shouldEnforceCookieContract(env) {
  if (isProductionLike(env)) return true;
  return envBoolean(env.FIDUCIA_ENFORCE_SESSION_COOKIE_INVARIANTS, false);
}

function isSessionCookieName(name) {
  return name.startsWith("__Host-") || /(?:session|auth|token|access|refresh|csrf)/i.test(name);
}

function getSetCookieValues(headers) {
  if (typeof headers?.getSetCookie === "function") {
    return headers.getSetCookie();
  }
  const value = headers?.get?.("set-cookie");
  return value ? [value] : [];
}

function resourcePolicy(env) {
  const value = String(env.FIDUCIA_CROSS_ORIGIN_RESOURCE_POLICY ?? "same-site")
    .trim()
    .toLowerCase();
  if (!["same-origin", "same-site", "cross-origin"].includes(value)) {
    throw new Error("invalid cross-origin resource policy");
  }
  return value;
}

function hstsValue(env) {
  const preload = envBoolean(env.FIDUCIA_HSTS_PRELOAD, false);
  return `max-age=63072000; includeSubDomains${preload ? "; preload" : ""}`;
}

function retryAfterSeconds(env) {
  const value = Number(
    env.FIDUCIA_RATE_LIMIT_WINDOW_SECONDS ?? DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
  );
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_RATE_LIMIT_WINDOW_SECONDS;
  return Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, Math.ceil(value)));
}

function envBoolean(value, defaultValue) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return defaultValue;
  }
  switch (String(value).trim().toLowerCase()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
    case "0":
    case "false":
    case "no":
    case "off":
      return false;
    default:
      throw new Error("invalid boolean security-boundary configuration");
  }
}
