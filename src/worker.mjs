import edgeWorker from "./index.mjs";
import { enforceJwtRevocationBoundary } from "./jwt-revocation-boundary.mjs";
import {
  failClosedConfigurationResponse,
  secureResponse,
} from "./security-boundary.mjs";

// Wrangler must see the Durable Object class at the configured module entry.
export { RateLimiter } from "./index.mjs";

export default {
  async fetch(request, env, ctx) {
    try {
      // The module entry is the true public boundary. JWTs are independently
      // verified offline here and then checked against bounded revocation state
      // before the existing edge router can authorize or forward the request.
      // API keys continue through the existing introspection path unchanged.
      const revocationFailure = await enforceJwtRevocationBoundary(request, env);
      if (revocationFailure) {
        return secureResponse(request, revocationFailure, env);
      }

      const response = await edgeWorker.fetch(request, env, ctx);
      return secureResponse(request, response, env);
    } catch (error) {
      // Report only a bounded error class. Never include request headers,
      // credential values, claims, authority bodies, or upstream URLs.
      console.error(
        "fiducia-edge request boundary failed closed:",
        error instanceof SyntaxError ? "syntax_error" : "boundary_error",
      );
      return failClosedConfigurationResponse(request);
    }
  },
};
