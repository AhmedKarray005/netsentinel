"""API tests: FastAPI's TestClient calls the app in-process (no real server, no network)."""

import pytest
from fastapi.testclient import TestClient
from scapy.utils import wrpcap

from netsentinel.api.app import create_app
from netsentinel.api.settings import Settings
from netsentinel.scenarios import port_scan_connect, repeated_failed_connections


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "test.db", upload_dir=tmp_path / "uploads", max_upload_mb=1)


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))


@pytest.fixture(scope="module")
def scan_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("pcaps") / "scan.pcap"
    wrpcap(str(path), port_scan_connect())
    return path


@pytest.fixture(scope="module")
def retry_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("pcaps") / "retry.pcap"
    wrpcap(str(path), repeated_failed_connections())
    return path


def upload(client, path, name=None):
    with open(path, "rb") as fh:
        return client.post("/api/analyses", files={"file": (name or path.name, fh)})


# ---------------------------------------------------------------- happy path
def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_rules_lists_three_rules_with_thresholds(client):
    rules = client.get("/api/rules").json()
    assert [r["rule_id"] for r in rules] == ["NS-001", "NS-002", "NS-003"]
    assert rules[0]["thresholds"]["min_distinct_ports"] == 20


def test_upload_analyzes_and_stores(client, scan_pcap, settings):
    response = upload(client, scan_pcap)
    assert response.status_code == 201
    body = response.json()
    assert body["filename"] == "scan.pcap"
    # 198 refused ports x 2 packets (SYN, RST) + 2 open ports (22, 80) x 9 packets (session)
    assert body["packet_count"] == 414
    assert body["flow_count"] == 200
    assert body["alert_count"] == 1
    assert body["alerts_by_severity"] == {"high": 1}
    assert body["overview"]["summary"]["protocols"] == {"TCP": 414}
    assert len(body["sha256"]) == 64
    assert list(settings.upload_dir.iterdir()) == []  # temporary upload deleted


def test_list_and_get_analyses(client, scan_pcap, retry_pcap):
    first = upload(client, scan_pcap).json()["id"]
    second = upload(client, retry_pcap).json()["id"]
    page = client.get("/api/analyses").json()
    assert page["total"] == 2
    assert [a["id"] for a in page["items"]] == [second, first]  # newest first
    assert client.get(f"/api/analyses/{first}").json()["flow_count"] == 200


def test_flow_filters_sorting_and_pagination(client, scan_pcap):
    analysis_id = upload(client, scan_pcap).json()["id"]
    url = f"/api/analyses/{analysis_id}/flows"

    rejected = client.get(url, params={"tcp_state": "REJECTED", "limit": 10}).json()
    assert rejected["total"] == 198
    assert len(rejected["items"]) == 10

    second_page = client.get(url, params={"tcp_state": "REJECTED", "limit": 10, "offset": 10})
    assert second_page.json()["items"][0]["id"] != rejected["items"][0]["id"]

    port_22 = client.get(url, params={"port": 22}).json()["items"]
    assert [(f["server_port"], f["tcp_state"]) for f in port_22] == [(22, "CLOSED")]

    by_bytes = client.get(url, params={"sort": "bytes", "limit": 3}).json()["items"]
    assert by_bytes[0]["bytes_total"] >= by_bytes[1]["bytes_total"] >= by_bytes[2]["bytes_total"]
    assert by_bytes[0]["tcp_state"] == "CLOSED"  # open ports carried data


def test_flow_time_filter(client, scan_pcap):
    # Scenario: port i is probed at 1000 + i * 0.05 s, for ports 1..200 (i = 0..199).
    analysis_id = upload(client, scan_pcap).json()["id"]
    url = f"/api/analyses/{analysis_id}/flows"
    first_second = client.get(url, params={"until": 1000.999}).json()
    assert first_second["total"] == 20  # probes at 1000.00 ... 1000.95
    window = client.get(url, params={"since": 1005.0, "until": 1005.999}).json()
    assert window["total"] == 20
    # Port 22 (open) session runs 1001.05 -> ~1001.19: it is the only flow active in between.
    active = client.get(url, params={"since": 1001.12, "until": 1001.13}).json()["items"]
    assert [(f["server_port"], f["tcp_state"]) for f in active] == [(22, "CLOSED")]
    assert client.get(url, params={"since": 1010, "until": 1000}).status_code == 422


def test_alert_filters_across_analyses(client, scan_pcap, retry_pcap):
    scan_id = upload(client, scan_pcap).json()["id"]
    upload(client, retry_pcap)

    everything = client.get("/api/alerts").json()
    assert everything["total"] == 2
    assert {a["rule_id"] for a in everything["items"]} == {"NS-001", "NS-003"}

    high = client.get("/api/alerts", params={"severity": "high"}).json()["items"]
    assert [a["rule_id"] for a in high] == ["NS-001"]
    assert high[0]["evidence"]["distinct_ports"] == 200
    assert high[0]["mitre_attack"].startswith("T1046")

    only_scan = client.get("/api/alerts", params={"analysis_id": scan_id}).json()
    assert only_scan["total"] == 1
    by_rule = client.get("/api/alerts", params={"rule_id": "NS-003"}).json()["items"]
    assert by_rule[0]["dst_port"] == 5432


def test_delete_removes_flows_and_alerts(client, scan_pcap):
    analysis_id = upload(client, scan_pcap).json()["id"]
    assert client.delete(f"/api/analyses/{analysis_id}").status_code == 204
    assert client.get(f"/api/analyses/{analysis_id}").status_code == 404
    assert client.get("/api/alerts").json()["total"] == 0  # ON DELETE CASCADE
    assert client.delete(f"/api/analyses/{analysis_id}").status_code == 404


def test_connection_can_be_closed_from_another_thread(tmp_path):
    # Regression: under uvicorn, the get_db dependency opened the connection in one worker
    # thread and closed it in another -> sqlite3.ProgrammingError -> HTTP 500.
    import threading

    from netsentinel import storage

    conn = storage.connect(tmp_path / "t.db")
    errors = []

    def use_and_close():
        try:
            storage.init_db(conn)
            conn.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=use_and_close)
    worker.start()
    worker.join()
    assert errors == []


def test_data_survives_an_app_restart(settings, scan_pcap):
    upload(TestClient(create_app(settings)), scan_pcap)
    restarted = TestClient(create_app(settings))
    assert restarted.get("/api/analyses").json()["total"] == 1


# ---------------------------------------------------------------- untrusted input
def test_wrong_extension_is_refused(client, tmp_path):
    exe = tmp_path / "evil.exe"
    exe.write_bytes(b"MZ\x90\x00")
    assert upload(client, exe).status_code == 415


def test_fake_pcap_extension_is_refused(client, tmp_path, settings):
    fake = tmp_path / "notes.pcap"
    fake.write_text("this is text, not a capture")
    response = upload(client, fake)
    assert response.status_code == 422
    assert "signature" in response.json()["detail"]
    assert list(settings.upload_dir.iterdir()) == []


def test_truncated_capture_with_valid_signature_is_refused(client, scan_pcap, tmp_path):
    broken = tmp_path / "broken.pcap"
    broken.write_bytes(scan_pcap.read_bytes()[:10])  # magic number ok, header cut off
    assert upload(client, broken).status_code == 422


def test_too_large_upload_is_refused(client, tmp_path, settings):
    big = tmp_path / "big.pcap"
    big.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * (2 * 1024 * 1024))  # 2 MB > 1 MB limit
    assert upload(client, big).status_code == 413
    assert not settings.upload_dir.exists() or list(settings.upload_dir.iterdir()) == []


@pytest.mark.parametrize(
    "name", ["..\\..\\windows\\system32\\scan.pcap", "../../etc/scan.pcap", "C:\\x/y\\scan.pcap"]
)
def test_path_in_filename_is_neutralized(client, scan_pcap, name):
    body = upload(client, scan_pcap, name=name).json()
    assert body["filename"] == "scan.pcap"


@pytest.mark.parametrize(
    "params",
    [
        {"ip": "not-an-ip"},
        {"ip": "1.2.3.4' OR '1'='1"},  # SQL injection attempt
        {"port": 70000},
        {"tcp_state": "DROP TABLE flows"},
        {"sort": "id; DROP TABLE flows"},
        {"limit": 0},
        {"limit": 10000},
        {"offset": -1},
    ],
)
def test_invalid_flow_query_parameters_get_422(client, scan_pcap, params):
    analysis_id = upload(client, scan_pcap).json()["id"]
    response = client.get(f"/api/analyses/{analysis_id}/flows", params=params)
    assert response.status_code == 422
    # ...and the data is still there afterwards
    assert client.get(f"/api/analyses/{analysis_id}/flows").json()["total"] == 200


def test_invalid_alert_filters_get_422(client):
    assert client.get("/api/alerts", params={"severity": "critical"}).status_code == 422
    assert client.get("/api/alerts", params={"rule_id": "x"}).status_code == 422


def test_unknown_analysis_gives_404(client):
    assert client.get("/api/analyses/999").status_code == 404
    assert client.get("/api/analyses/999/flows").status_code == 404
    assert client.get("/api/alerts", params={"analysis_id": 999}).status_code == 404
