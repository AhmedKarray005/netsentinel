"""Runs every enabled rule. Feed packets with add() while reading, then call run(flows)."""

from netsentinel.detection.config import DetectionConfig
from netsentinel.detection.models import Alert
from netsentinel.detection.rules import (
    PacketRateTracker,
    detect_failed_connections,
    detect_port_scans,
    detect_traffic_spikes,
)
from netsentinel.flows.models import Flow
from netsentinel.parsing.models import PacketRecord


class DetectionEngine:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._rates = PacketRateTracker(self.config.traffic_spike.bucket_seconds)

    def add(self, record: PacketRecord) -> None:
        if self.config.traffic_spike.enabled:
            self._rates.add(record)

    def run(self, flows: list[Flow]) -> list[Alert]:
        cfg = self.config
        alerts: list[Alert] = []
        if cfg.port_scan.enabled:
            alerts += detect_port_scans(flows, cfg.port_scan)
        if cfg.traffic_spike.enabled:
            alerts += detect_traffic_spikes(self._rates, flows, cfg.traffic_spike)
        if cfg.failed_connections.enabled:
            alerts += detect_failed_connections(flows, cfg.failed_connections)
        return sorted(alerts, key=lambda a: (a.start, a.rule.rule_id))
