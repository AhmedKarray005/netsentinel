"""Structured logging: one JSON object per line, so log tools (Loki, ELK, `jq`) can filter fields.

Config from environment variables:
- NETSENTINEL_LOG_LEVEL  = DEBUG | INFO (default) | WARNING | ERROR
- NETSENTINEL_LOG_FORMAT = json (default) | text (easier to read in a terminal)
"""

import json
import logging
import os
import sys
from datetime import UTC, datetime

# Attributes every LogRecord has; anything else was passed with `extra={...}` and is a field.
_STANDARD = set(vars(logging.makeLogRecord({}))) | {"message", "asctime", "taskName"}
_STANDARD.add("color_message")  # uvicorn's ANSI-coloured copy of the message


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            # Same value under the name Google Cloud Logging reads, so Cloud Run logs get a real
            # severity (colours, "errors only" filter, log-based alerts). Other tools ignore it.
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging(level: str | None = None, fmt: str | None = None) -> None:
    """Configure the root logger once. Safe to call again (replaces our handler)."""
    level = (level or os.environ.get("NETSENTINEL_LOG_LEVEL", "INFO")).upper()
    fmt = (fmt or os.environ.get("NETSENTINEL_LOG_FORMAT", "json")).lower()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ValueError(f"NETSENTINEL_LOG_LEVEL must be DEBUG/INFO/WARNING/ERROR, got {level!r}")
    if fmt not in {"json", "text"}:
        raise ValueError(f"NETSENTINEL_LOG_FORMAT must be json or text, got {fmt!r}")

    handler = logging.StreamHandler(sys.stdout)  # containers collect stdout
    handler.set_name("netsentinel")
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))

    root = logging.getLogger()
    for old in [h for h in root.handlers if h.get_name() == "netsentinel"]:
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(level)
    # uvicorn's own access log duplicates our request log line: keep only ours.
    logging.getLogger("uvicorn.access").disabled = True
