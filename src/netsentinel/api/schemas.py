"""Response shapes. FastAPI uses them to validate output and to generate the /docs page."""

from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel

Severity = Literal["low", "medium", "high"]
Protocol = Literal["TCP", "UDP", "ICMP", "ICMPv6", "OTHER_IP"]
TcpState = Literal["ESTABLISHED", "CLOSED", "REJECTED", "NO_REPLY", "HALF_OPEN", "MIDSTREAM"]
FlowSort = Literal["start", "bytes", "packets"]


class Analysis(BaseModel):
    id: int
    filename: str
    sha256: str
    size_bytes: int
    created_at: str
    packet_count: int
    flow_count: int
    alert_count: int
    start_time: float | None
    end_time: float | None
    duration_seconds: float


class AnalysisDetail(Analysis):
    overview: dict[str, Any]  # packet summary + flow rankings (same as the CLI report)
    alerts_by_severity: dict[str, int]


class Flow(BaseModel):
    id: int
    analysis_id: int
    protocol: str
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    start: float
    end: float
    duration_seconds: float
    packets_fwd: int
    packets_bwd: int
    bytes_fwd: int
    bytes_bwd: int
    bytes_total: int
    tcp_state: str | None


class Alert(BaseModel):
    id: int
    analysis_id: int
    rule_id: str
    rule_name: str
    mitre_attack: str
    severity: Severity
    start: float
    end: float
    start_iso: str
    src_ip: str
    dst_ip: str | None
    dst_port: int | None
    summary: str
    thresholds: dict[str, Any]
    evidence: dict[str, Any]


T = TypeVar("T")


class Page(BaseModel, Generic[T]):  # noqa: UP046  (classic form, safest with Pydantic)
    items: list[T]
    total: int  # number of matching rows, for the pagination controls
    limit: int
    offset: int


class RuleInfo(BaseModel):
    rule_id: str
    name: str
    description: str
    mitre_attack: str
    enabled: bool
    thresholds: dict[str, Any]
