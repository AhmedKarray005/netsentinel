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
FROM nginxinc/nginx-unprivileged:stable-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
