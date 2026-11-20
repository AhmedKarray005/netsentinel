"""Traffic statistics computed from a stream of PacketRecords, one packet at a time."""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netsentinel.parsing.models import PacketRecord


@dataclass
class TrafficSummary:
    """Accumulates statistics without keeping the packets in memory."""

    packet_count: int = 0
    total_bytes: int = 0
    min_length: int | None = None
    max_length: int | None = None
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    protocols: Counter = field(default_factory=Counter)
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    dst_ports: Counter = field(default_factory=Counter)  # keys like "TCP/443", "UDP/53"
    dns_queries: Counter = field(default_factory=Counter)

    def add(self, record: PacketRecord) -> None:
        self.packet_count += 1
        self.total_bytes += record.length
        if self.min_length is None or record.length < self.min_length:
            self.min_length = record.length
        if self.max_length is None or record.length > self.max_length:
            self.max_length = record.length
        # Captures are usually in time order, but not always: keep true min/max.
        if self.first_timestamp is None or record.timestamp < self.first_timestamp:
            self.first_timestamp = record.timestamp
        if self.last_timestamp is None or record.timestamp > self.last_timestamp:
            self.last_timestamp = record.timestamp

        self.protocols[record.protocol] += 1
        if record.src_ip:
            self.src_ips[record.src_ip] += 1
        if record.dst_ip:
            self.dst_ips[record.dst_ip] += 1
        if record.dst_port is not None:
            self.dst_ports[f"{record.protocol}/{record.dst_port}"] += 1
        if record.dns_query:
            self.dns_queries[record.dns_query] += 1

    @property
    def duration_seconds(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return self.last_timestamp - self.first_timestamp

    @property
    def mean_length(self) -> float:
        return self.total_bytes / self.packet_count if self.packet_count else 0.0

    def to_dict(self, top: int = 10) -> dict[str, Any]:
        """A JSON-friendly report. `top` limits the size of each ranking."""
        duration = self.duration_seconds
        return {
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "start_time": _iso(self.first_timestamp),
            "end_time": _iso(self.last_timestamp),
            "duration_seconds": round(duration, 6),
            "packets_per_second": round(self.packet_count / duration, 2) if duration else None,
            "packet_length": {
                "min": self.min_length,
                "max": self.max_length,
                "mean": round(self.mean_length, 1),
            },
            "protocols": dict(self.protocols.most_common()),
            "top_src_ips": dict(self.src_ips.most_common(top)),
            "top_dst_ips": dict(self.dst_ips.most_common(top)),
            "top_dst_ports": dict(self.dst_ports.most_common(top)),
            "top_dns_queries": dict(self.dns_queries.most_common(top)),
        }


def summarize(records: Iterable[PacketRecord]) -> TrafficSummary:
    summary = TrafficSummary()
    for record in records:
        summary.add(record)
    return summary


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
