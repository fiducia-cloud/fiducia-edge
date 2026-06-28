# syntax=docker/dockerfile:1
# Cloudflare Worker tooling image.
FROM node:24-slim
WORKDIR /app
COPY package.json wrangler.toml ./
COPY src src
RUN npm install && npm run check
EXPOSE 8787
CMD ["npx", "wrangler", "dev", "--ip", "0.0.0.0"]
