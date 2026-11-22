"""Structured logging and request logging (Phase 7)."""

import json
import logging

import pytest
from fastapi.testclient import TestClient

from netsentinel.api.server import build_app
from netsentinel.api.settings import Settings
from netsentinel.logging_setup import JsonFormatter, setup_logging


def _record(msg: str, **extra) -> logging.LogRecord:
    record = logging.makeLogRecord({"name": "t", "levelname": "INFO", "msg": msg})
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_writes_one_object_with_extra_fields():
    line = JsonFormatter().format(_record("hello", request_id="abc", status=200))
    entry = json.loads(line)
    assert entry["message"] == "hello"
    assert entry["level"] == "INFO"
    assert entry["request_id"] == "abc"
    assert entry["status"] == 200
    assert entry["time"].endswith("+00:00")
    assert "\n" not in line


def test_setup_logging_rejects_bad_values():
    with pytest.raises(ValueError):
        setup_logging(level="LOUD")
    with pytest.raises(ValueError):
        setup_logging(fmt="xml")


def test_setup_logging_twice_keeps_one_handler():
    setup_logging(fmt="text")
    setup_logging(fmt="json")
    ours = [h for h in logging.getLogger().handlers if h.get_name() == "netsentinel"]
    assert len(ours) == 1


@pytest.fixture
def client(tmp_path):
    settings = Settings(db_path=tmp_path / "t.db", upload_dir=tmp_path / "up")
    with TestClient(build_app(settings)) as c:
        yield c


def test_each_request_gets_an_id_and_a_log_line(client, caplog):
    with caplog.at_level(logging.INFO, logger="netsentinel.http"):
        response = client.get("/api/rules")
    assert response.status_code == 200
    request_id = response.headers["X-Request-ID"]
    assert len(request_id) == 16
    [entry] = [r for r in caplog.records if r.name == "netsentinel.http"]
    assert entry.request_id == request_id
    assert entry.status == 200
    assert entry.path == "/api/rules"


def test_safe_incoming_request_id_is_kept_unsafe_one_replaced(client):
    assert (
        client.get("/api/rules", headers={"X-Request-ID": "proxy-42"}).headers["X-Request-ID"]
        == "proxy-42"
    )
    replaced = client.get("/api/rules", headers={"X-Request-ID": "x\ninjected log line"})
    assert replaced.headers["X-Request-ID"] != "x\ninjected log line"


def test_health_checks_are_not_logged_at_info(client, caplog):
    with caplog.at_level(logging.INFO, logger="netsentinel.http"):
        assert client.get("/api/health").status_code == 200
    assert not [r for r in caplog.records if r.name == "netsentinel.http"]
