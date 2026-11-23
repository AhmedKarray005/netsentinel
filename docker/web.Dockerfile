# NetSentinel dashboard image: React build served by nginx, which also forwards /api to the API.
# Build from the repository root:  docker build -f docker/web.Dockerfile -t netsentinel-web .

# ---- stage 1: build the static files ----------------------------------------------------
FROM node:26-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- stage 2: nginx without root (listens on 8080, not 80) ------------------------------
# mainline, not stable: on 2026-11-23 stable-alpine still shipped nginx 1.30.6 with 6 fixable
# HIGH/CRITICAL CVEs (nginx comes from nginx.org's repo, so `apk upgrade` cannot fix it);
# mainline-alpine had 1.31.7. nginx.org recommends mainline for general use.
FROM nginxinc/nginx-unprivileged:mainline-alpine
# Apply Alpine security fixes released after the base image was published. Trivy found 20
# fixable HIGH/CRITICAL issues (nginx, musl, zlib, curl, ...) without this, on 2026-11-23.
USER root
RUN apk upgrade --no-cache
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
# The base image already runs as uid 101 ("nginx"); saying it here makes it explicit and
# keeps it true even if a later instruction switched to root.
USER 101
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
