# syntax=docker/dockerfile:1
# Cloudflare Worker tooling / deploy image for fiducia-edge.
FROM node:24-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git

ARG INTERFACES_REF=bbd8b52ce729ec34b0a9bff4dda6d0a448181797
WORKDIR /build
# package-lock.json resolves @fiducia/interfaces through
# file:../fiducia-interfaces. Fetch only the requested immutable commit, then
# verify that the checkout resolved to that exact full SHA (branch/tag names
# fail the comparison). Export a clean tree for npm so Git metadata never enters
# the deploy image.
RUN test "${#INTERFACES_REF}" -eq 40 \
    && test -z "$(printf '%s' "$INTERFACES_REF" | tr -d '0-9a-f')" \
    && git init --quiet .fiducia-interfaces-source \
    && git -C .fiducia-interfaces-source remote add origin https://github.com/fiducia-cloud/fiducia-interfaces.git \
    && git -C .fiducia-interfaces-source fetch --quiet --depth=1 --no-tags origin "$INTERFACES_REF" \
    && git -C .fiducia-interfaces-source checkout --quiet --detach FETCH_HEAD \
    && test "$(git -C .fiducia-interfaces-source rev-parse HEAD)" = "$INTERFACES_REF" \
    && mkdir fiducia-interfaces \
    && git -C .fiducia-interfaces-source archive HEAD | tar -x -C fiducia-interfaces

WORKDIR /build/fiducia-edge
COPY package.json package-lock.json wrangler.toml ./
# Deterministic, lockfile-pinned install with the exact sibling contract above.
RUN npm ci
COPY src src
RUN npm run check

FROM node:24-slim
WORKDIR /build/fiducia-edge
COPY --from=build --chown=node:node /build/fiducia-interfaces /build/fiducia-interfaces
COPY --from=build --chown=node:node /build/fiducia-edge /build/fiducia-edge
# Drop root — wrangler needs no privileges and can write its runtime build output
# under the node-owned /build/fiducia-edge directory.
USER node
# The Worker runs on Cloudflare's edge, not inside this container, so there is no
# long-running server to expose. The production entrypoint publishes the Worker
# (needs CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID at run time) instead of
# shipping the insecure `wrangler dev --ip 0.0.0.0` dev server.
CMD ["npm", "run", "deploy"]
