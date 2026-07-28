import edgeWorker from "./index.mjs";
import {
  failClosedConfigurationResponse,
  secureResponse,
} from "./security-boundary.mjs";

// Wrangler must see the Durable Object class at the configured module entry.
export { RateLimiter } from "./index.mjs";

export default {
  async fetch(request, env, ctx) {
    const response = await edgeWorker.fetch(request, env, ctx);
    try {
      return secureResponse(request, response, env);
    } catch (error) {
      // Report only the configuration/error class. Never include request headers,
      // cookie values, authorization material, or upstream response bodies.
      console.error(
        "fiducia-edge security boundary failed closed:",
        error instanceof Error ? error.message : "invalid configuration",
      );
      return failClosedConfigurationResponse(request);
    }
  },
};
