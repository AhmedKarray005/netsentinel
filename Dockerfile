# NetSentinel API image: FastAPI + analysis engine, SQLite database in the /data volume.
# Build:  docker build -t netsentinel-api .

# ---- stage 1: build a wheel (the packaged project) --------------------------------------
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# ---- stage 2: small runtime image, no build tools, no source tree -----------------------
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETSENTINEL_DB_PATH=/data/netsentinel.db \
    NETSENTINEL_UPLOAD_DIR=/data/uploads \
    NETSENTINEL_LOG_FORMAT=json \
    HOME=/tmp

# Run as an unprivileged user: a bug in packet parsing must not give root in the container.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin netsentinel \
    && mkdir /data && chown netsentinel:netsentinel /data

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
COPY config/rules.example.toml /app/config/rules.example.toml

USER netsentinel
VOLUME ["/data"]
EXPOSE 8000

# Docker marks the container "unhealthy" if /api/health (which queries the DB) stops answering.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"]

# 0.0.0.0 inside the container is required so Docker can forward the port; what is reachable
# from outside is decided by the `ports:` mapping in docker-compose.yml (127.0.0.1 only).
CMD ["netsentinel", "serve", "--host", "0.0.0.0", "--port", "8000"]
