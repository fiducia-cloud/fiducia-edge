# syntax=docker/dockerfile:1
# Cloudflare Worker tooling / deploy image for fiducia-edge.
FROM node:24-slim
WORKDIR /app
COPY package.json package-lock.json wrangler.toml ./
COPY src src
# Deterministic, lockfile-pinned install; syntax-check the Worker entrypoint.
RUN npm ci && npm run check
# Drop root — wrangler needs no privileges. Give the unprivileged `node` user
# (present in the official image) ownership so `wrangler deploy` can write its
# build output under /app/.wrangler at run time.
RUN chown -R node:node /app
USER node
# The Worker runs on Cloudflare's edge, not inside this container, so there is no
# long-running server to expose. The production entrypoint publishes the Worker
# (needs CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID at run time) instead of
# shipping the insecure `wrangler dev --ip 0.0.0.0` dev server.
CMD ["npm", "run", "deploy"]
