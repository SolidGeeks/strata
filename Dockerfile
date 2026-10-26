# ---- Stage 1: fetch three.js and the fonts, copy them into public/vendor ----
FROM node:22-alpine AS vendor
WORKDIR /build
COPY package.json package-lock.json ./
# npm ci installs exactly what package-lock.json pins, so a given commit always builds the same image
RUN npm ci --omit=dev --no-audit --no-fund
COPY scripts ./scripts
COPY public ./public
RUN node scripts/vendor.mjs

# ---- Stage 2: runtime (no npm dependencies needed) ----
FROM node:22-alpine
ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data \
    PUBLIC_DIR=/app/public
WORKDIR /app
COPY package.json package-lock.json ./
COPY server ./server
COPY scripts/users.mjs scripts/connector-sim.mjs scripts/pack-module.mjs ./scripts/
COPY --from=vendor /build/public ./public
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["node", "server/server.js"]
