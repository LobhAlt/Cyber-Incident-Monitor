# CIMI — Cyber Incident Monitor in India
# Single-stage image: no build step, no native modules.
FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/app/data

WORKDIR /app

# Install production dependencies first so the layer is cached across code changes.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.js ./
COPY src ./src
COPY public ./public

# Persistent state (users, lookup history, JWT secret) lives here — mount a volume.
RUN mkdir -p /app/data && chown -R node:node /app
USER node
VOLUME ["/app/data"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health >/dev/null || exit 1

CMD ["node", "server.js"]
