"""SQLite persistence for analyses, flows and alerts (Python's built-in sqlite3, no ORM).

Every value from the outside reaches SQL through `?` placeholders, never through string
formatting: that is what prevents SQL injection. Column names used for sorting come from a
fixed whitelist.
"""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netsentinel.analysis import AnalysisResult
from netsentinel.flows.stats import flow_report

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    filename      TEXT    NOT NULL,
    sha256        TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL,
    created_at    TEXT    NOT NULL,
    packet_count  INTEGER NOT NULL,
    flow_count    INTEGER NOT NULL,
    alert_count   INTEGER NOT NULL,
    start_time    REAL,
    end_time      REAL,
    overview_json TEXT    NOT NULL  -- summary + flow rankings, for the dashboard overview
);

CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    protocol    TEXT    NOT NULL,
    client_ip   TEXT    NOT NULL,
    client_port INTEGER,
    server_ip   TEXT    NOT NULL,
    server_port INTEGER,
    start_ts    REAL    NOT NULL,
    end_ts      REAL    NOT NULL,
    packets_fwd INTEGER NOT NULL,
    packets_bwd INTEGER NOT NULL,
    bytes_fwd   INTEGER NOT NULL,
    bytes_bwd   INTEGER NOT NULL,
    bytes_total INTEGER NOT NULL,
    tcp_state   TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_analysis ON flows(analysis_id, start_ts);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    rule_id         TEXT    NOT NULL,
    rule_name       TEXT    NOT NULL,
    mitre_attack    TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    start_ts        REAL    NOT NULL,
    end_ts          REAL    NOT NULL,
    src_ip          TEXT    NOT NULL,
    dst_ip          TEXT,
    dst_port        INTEGER,
    summary         TEXT    NOT NULL,
    thresholds_json TEXT    NOT NULL,
    evidence_json   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_analysis ON alerts(analysis_id, start_ts);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, start_ts);
"""

FLOW_SORTS = {  # the only ORDER BY values ever sent to SQL
    "start": "start_ts ASC",
    "bytes": "bytes_total DESC",
    "packets": "(packets_fwd + packets_bwd) DESC",
}


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row  # rows behave like dicts
    conn.execute("PRAGMA foreign_keys = ON")  # needed for ON DELETE CASCADE
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


# ------------------------------------------------------------------ write
def save_analysis(
    conn: sqlite3.Connection,
    *,
    filename: str,
    sha256: str,
    size_bytes: int,
    result: AnalysisResult,
    top: int = 10,
) -> int:
    """Store one analysis with all its flows and alerts in a single transaction."""
    s = result.summary
    overview = {"summary": s.to_dict(top=top), "flows": flow_report(result.flows, top=top)}
    with conn:  # commit at the end, or roll everything back on error
        cursor = conn.execute(
            """INSERT INTO analyses (filename, sha256, size_bytes, created_at, packet_count,
               flow_count, alert_count, start_time, end_time, overview_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                filename, sha256, size_bytes, datetime.now(UTC).isoformat(timespec="seconds"),
                s.packet_count, len(result.flows), len(result.alerts),
                s.first_timestamp, s.last_timestamp, json.dumps(overview),
            ),
        )  # fmt: skip
        analysis_id = cursor.lastrowid
        conn.executemany(
            """INSERT INTO flows (analysis_id, protocol, client_ip, client_port, server_ip,
               server_port, start_ts, end_ts, packets_fwd, packets_bwd, bytes_fwd, bytes_bwd,
               bytes_total, tcp_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    analysis_id, f.protocol, f.client_ip, f.client_port, f.server_ip,
                    f.server_port, f.start, f.end, f.packets_fwd, f.packets_bwd,
                    f.bytes_fwd, f.bytes_bwd, f.bytes, f.tcp_state,
                )
                for f in result.flows
            ],
        )  # fmt: skip
        conn.executemany(
            """INSERT INTO alerts (analysis_id, rule_id, rule_name, mitre_attack, severity,
               start_ts, end_ts, src_ip, dst_ip, dst_port, summary, thresholds_json, evidence_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    analysis_id, a.rule.rule_id, a.rule.name, a.rule.mitre_attack, a.severity,
                    a.start, a.end, a.src_ip, a.dst_ip, a.dst_port, a.summary,
                    json.dumps(a.thresholds), json.dumps(a.evidence),
                )
                for a in result.alerts
            ],
        )  # fmt: skip
    return analysis_id


def delete_analysis(conn: sqlite3.Connection, analysis_id: int) -> bool:
    with conn:
        cursor = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    return cursor.rowcount > 0


# ------------------------------------------------------------------ read
def get_analysis(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        return None
    analysis = _analysis_row(row)
    analysis["overview"] = json.loads(row["overview_json"])
    severities = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE analysis_id = ? GROUP BY severity",
        (analysis_id,),
    )
    analysis["alerts_by_severity"] = {r["severity"]: r["n"] for r in severities}
    return analysis


def list_analyses(conn: sqlite3.Connection, limit: int, offset: int):
    total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
    rows = conn.execute(
        "SELECT * FROM analyses ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    return [_analysis_row(r) for r in rows], total


def list_flows(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    protocol: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    tcp_state: str | None = None,
    sort: str = "start",
    limit: int = 50,
    offset: int = 0,
):
    where, params = ["analysis_id = ?"], [analysis_id]
    if protocol:
        where.append("protocol = ?")
        params.append(protocol)
    if ip:
        where.append("(client_ip = ? OR server_ip = ?)")
        params += [ip, ip]
    if port is not None:
        where.append("(client_port = ? OR server_port = ?)")
        params += [port, port]
    if tcp_state:
        where.append("tcp_state = ?")
        params.append(tcp_state)
    return _page(conn, "flows", where, params, FLOW_SORTS[sort], limit, offset, _flow_row)


def list_alerts(
    conn: sqlite3.Connection,
    *,
    analysis_id: int | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    ip: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    where, params = [], []
    if analysis_id is not None:
        where.append("analysis_id = ?")
        params.append(analysis_id)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    if ip:
        where.append("(src_ip = ? OR dst_ip = ?)")
        params += [ip, ip]
    return _page(conn, "alerts", where, params, "start_ts ASC, id ASC", limit, offset, _alert_row)


def _page(conn, table, where, params, order_by, limit, offset, convert):
    # `table`, `where` clauses and `order_by` are fixed strings from this module; only the
    # values in `params` come from the user, and they go through placeholders.
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM {table} {clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM {table} {clause} ORDER BY {order_by} LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return [convert(r) for r in rows], total


def _analysis_row(row: sqlite3.Row) -> dict[str, Any]:
    data = {k: row[k] for k in row.keys() if k != "overview_json"}
    start, end = row["start_time"], row["end_time"]
    data["duration_seconds"] = round(end - start, 6) if start is not None else 0.0
    return data


def _flow_row(row: sqlite3.Row) -> dict[str, Any]:
    data = _with_times(dict(row))
    data["duration_seconds"] = round(data["end"] - data["start"], 6)
    return data


def _with_times(data: dict[str, Any]) -> dict[str, Any]:
    """DB columns start_ts/end_ts ("end" is an SQL keyword) -> API fields start/end."""
    data["start"] = data.pop("start_ts")
    data["end"] = data.pop("end_ts")
    return data


def _alert_row(row: sqlite3.Row) -> dict[str, Any]:
    data = _with_times({k: row[k] for k in row.keys() if not k.endswith("_json")})
    data["thresholds"] = json.loads(row["thresholds_json"])
    data["evidence"] = json.loads(row["evidence_json"])
    data["start_iso"] = datetime.fromtimestamp(data["start"], tz=UTC).isoformat()
    return data
