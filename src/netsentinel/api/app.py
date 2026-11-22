"""NetSentinel REST API (FastAPI). Run it with `netsentinel serve`, docs at /docs."""

import ipaddress
import logging
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing
from dataclasses import asdict
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from netsentinel import __version__, storage
from netsentinel.analysis import run_analysis
from netsentinel.api import schemas
from netsentinel.api.settings import Settings
from netsentinel.api.uploads import clean_filename, save_upload
from netsentinel.detection import ConfigError, load_config
from netsentinel.detection.rules import FAILED_CONNECTIONS, PORT_SCAN, TRAFFIC_SPIKE
from netsentinel.parsing import PcapReadError

log = logging.getLogger("netsentinel.api")

Limit = Annotated[int, Query(ge=1, le=500, description="Page size")]
Offset = Annotated[int, Query(ge=0, description="Rows to skip")]
RuleId = Annotated[str | None, Query(pattern=r"^NS-\d{3}$")]


def _valid_ip(ip: str | None) -> str | None:
    """Reject anything that is not a real IPv4/IPv6 address (clear 422 instead of 0 results)."""
    if ip is None:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(422, f"Invalid IP address: {ip!r}") from None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    detection = load_config(settings.rules_file)  # fail at startup if the rules file is wrong
    with closing(storage.connect(settings.db_path)) as conn:
        storage.init_db(conn)

    app = FastAPI(
        title="NetSentinel API",
        version=__version__,
        description="Upload packet captures, get traffic statistics, flows and security alerts.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def reject_oversized_uploads(request: Request, call_next):
        # Refuse early, before the body is read, when the client announces a too-big upload.
        # (Uploads without Content-Length are still capped while saving, in save_upload.)
        length = request.headers.get("content-length", "")
        limit = settings.max_upload_bytes + 65536  # + room for the multipart envelope
        if request.method == "POST" and length.isdigit() and int(length) > limit:
            return JSONResponse({"detail": "Upload too large"}, status_code=413)
        return await call_next(request)

    def get_db() -> Iterator[sqlite3.Connection]:
        conn = storage.connect(settings.db_path)  # one connection per request
        try:
            yield conn
        finally:
            conn.close()

    Db = Annotated[sqlite3.Connection, Depends(get_db)]

    def require_analysis(conn: sqlite3.Connection, analysis_id: int) -> dict:
        analysis = storage.get_analysis(conn, analysis_id)
        if analysis is None:
            raise HTTPException(404, f"Analysis {analysis_id} not found")
        return analysis

    # -------------------------------------------------------------- health & rules
    @app.get("/api/health", tags=["system"])
    def health(conn: Db) -> dict:
        conn.execute("SELECT 1")  # proves the database answers
        return {"status": "ok", "version": __version__}

    @app.get("/api/rules", tags=["system"])
    def rules() -> list[schemas.RuleInfo]:
        pairs = [
            (PORT_SCAN, detection.port_scan),
            (TRAFFIC_SPIKE, detection.traffic_spike),
            (FAILED_CONNECTIONS, detection.failed_connections),
        ]
        return [
            schemas.RuleInfo(
                rule_id=rule.rule_id,
                name=rule.name,
                description=rule.description,
                mitre_attack=rule.mitre_attack,
                enabled=cfg.enabled,
                thresholds={k: v for k, v in asdict(cfg).items() if k != "enabled"},
            )
            for rule, cfg in pairs
        ]

    # -------------------------------------------------------------- analyses
    # Plain `def` (not async): FastAPI runs it in a worker thread, so a slow analysis does
    # not freeze the whole server.
    @app.post("/api/analyses", status_code=201, tags=["analyses"])
    def create_analysis(conn: Db, file: Annotated[UploadFile, File()]) -> schemas.AnalysisDetail:
        path, sha256, size = save_upload(file, settings.upload_dir, settings.max_upload_bytes)
        started = time.perf_counter()
        try:
            result = run_analysis(path, detection=detection)
        except PcapReadError as exc:
            log.warning("upload rejected: unreadable capture sha256=%s", sha256[:12])
            raise HTTPException(422, "The file could not be parsed as a capture") from exc
        finally:
            path.unlink(missing_ok=True)  # the raw capture is never kept
        analysis_id = storage.save_analysis(
            conn, filename=clean_filename(file.filename), sha256=sha256, size_bytes=size,
            result=result,
        )  # fmt: skip
        log.info(
            "analysis %d: %d packets, %d flows, %d alerts in %.2f s (sha256=%s)",
            analysis_id, result.summary.packet_count, len(result.flows), len(result.alerts),
            time.perf_counter() - started, sha256[:12],
        )  # fmt: skip
        return storage.get_analysis(conn, analysis_id)

    @app.get("/api/analyses", tags=["analyses"])
    def list_analyses(
        conn: Db, limit: Limit = 20, offset: Offset = 0
    ) -> schemas.Page[schemas.Analysis]:
        items, total = storage.list_analyses(conn, limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/analyses/{analysis_id}", tags=["analyses"])
    def get_analysis(conn: Db, analysis_id: int) -> schemas.AnalysisDetail:
        return require_analysis(conn, analysis_id)

    @app.delete("/api/analyses/{analysis_id}", status_code=204, tags=["analyses"])
    def delete_analysis(conn: Db, analysis_id: int) -> None:
        if not storage.delete_analysis(conn, analysis_id):
            raise HTTPException(404, f"Analysis {analysis_id} not found")

    # -------------------------------------------------------------- flows & alerts
    @app.get("/api/analyses/{analysis_id}/flows", tags=["flows"])
    def list_flows(
        conn: Db,
        analysis_id: int,
        protocol: schemas.Protocol | None = None,
        ip: str | None = None,
        port: Annotated[int | None, Query(ge=0, le=65535)] = None,
        tcp_state: schemas.TcpState | None = None,
        sort: schemas.FlowSort = "start",
        limit: Limit = 50,
        offset: Offset = 0,
    ) -> schemas.Page[schemas.Flow]:
        require_analysis(conn, analysis_id)
        items, total = storage.list_flows(
            conn, analysis_id, protocol=protocol, ip=_valid_ip(ip), port=port,
            tcp_state=tcp_state, sort=sort, limit=limit, offset=offset,
        )  # fmt: skip
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/alerts", tags=["alerts"])
    def list_alerts(
        conn: Db,
        analysis_id: int | None = None,
        severity: schemas.Severity | None = None,
        rule_id: RuleId = None,
        ip: str | None = None,
        limit: Limit = 50,
        offset: Offset = 0,
    ) -> schemas.Page[schemas.Alert]:
        if analysis_id is not None:
            require_analysis(conn, analysis_id)
        items, total = storage.list_alerts(
            conn, analysis_id=analysis_id, severity=severity, rule_id=rule_id,
            ip=_valid_ip(ip), limit=limit, offset=offset,
        )  # fmt: skip
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    return app


def create_app_from_env() -> FastAPI:
    """Factory used by `uvicorn --factory` and `netsentinel serve`."""
    try:
        return create_app()
    except ConfigError as exc:
        raise SystemExit(f"error: {exc}") from exc
