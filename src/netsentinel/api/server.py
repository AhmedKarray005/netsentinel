"""Runtime wiring around the API: structured logs, one log line per request, request IDs.

`app.py` holds the routes; this module turns them into the server that `netsentinel serve`
and the Docker image run.
"""

import logging
import re
import time
import uuid

from fastapi import FastAPI, Request

from netsentinel.api.app import create_app
from netsentinel.api.settings import Settings
from netsentinel.detection import ConfigError
from netsentinel.logging_setup import setup_logging

log = logging.getLogger("netsentinel.http")

# A client may send its own X-Request-ID (e.g. a reverse proxy); accept only safe values so
# nobody can inject fake log content through that header.
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def add_request_logging(app: FastAPI) -> FastAPI:
    @app.middleware("http")
    async def log_request(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID.match(incoming) else uuid.uuid4().hex[:16]
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception(
                "request failed",
                extra={"request_id": request_id, "method": request.method,
                       "path": request.url.path},
            )  # fmt: skip
            raise
        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        response.headers["X-Request-ID"] = request_id
        # Health checks run every few seconds: log them only at DEBUG to keep logs readable.
        level = logging.DEBUG if request.url.path == "/api/health" else logging.INFO
        log.log(
            level,
            "%s %s %d %.1f ms", request.method, request.url.path, response.status_code,
            duration_ms,
            extra={"request_id": request_id, "method": request.method,
                   "path": request.url.path, "status": response.status_code,
                   "duration_ms": duration_ms},
        )  # fmt: skip
        return response

    return app


def build_app(settings: Settings | None = None) -> FastAPI:
    return add_request_logging(create_app(settings))


def create_server_app() -> FastAPI:
    """Factory used by `netsentinel serve` (uvicorn --factory) and the container."""
    try:
        setup_logging()
        settings = Settings.from_env()
        app = build_app(settings)
    except (ConfigError, ValueError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    logging.getLogger("netsentinel.api").info(
        "NetSentinel API ready",
        extra={"db_path": str(settings.db_path), "max_upload_mb": settings.max_upload_mb,
               "rules_file": str(settings.rules_file) if settings.rules_file else None},
    )  # fmt: skip
    return app
