"""One entry point for a full analysis: read the file once, feed every analyzer.

`run_analysis` returns the full result (every flow and alert) for storage by the API;
`analyze_file` turns it into the compact report printed by the CLI.
"""

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netsentinel.detection import Alert, DetectionConfig, DetectionEngine
from netsentinel.flows import Flow, FlowAggregator, flow_report
from netsentinel.parsing import read_pcap
from netsentinel.summary import TrafficSummary


@dataclass
class AnalysisResult:
    summary: TrafficSummary
    flows: list[Flow]
    alerts: list[Alert]

    def report(self, top: int = 10) -> dict[str, Any]:
        alerts = [alert.to_dict() for alert in self.alerts]
        return {
            "summary": self.summary.to_dict(top=top),
            "flows": flow_report(self.flows, top=top),
            "alerts": {
                "count": len(alerts),
                "by_rule": dict(Counter(a["rule_id"] for a in alerts)),
                "by_severity": dict(Counter(a["severity"] for a in alerts)),
                "items": alerts,
            },
        }


def run_analysis(
    path: str | Path,
    *,
    idle_timeout: float = 60.0,
    tcp_idle_timeout: float = 300.0,
    bucket_seconds: float = 1.0,
    detection: DetectionConfig | None = None,
) -> AnalysisResult:
    """Raises PcapReadError on a missing or invalid file."""
    summary = TrafficSummary(bucket_seconds=bucket_seconds)
    aggregator = FlowAggregator(idle_timeout=idle_timeout, tcp_idle_timeout=tcp_idle_timeout)
    engine = DetectionEngine(detection)
    for record in read_pcap(path):  # single pass over the file
        summary.add(record)
        aggregator.add(record)
        engine.add(record)
    flows = aggregator.finish()
    return AnalysisResult(summary=summary, flows=flows, alerts=engine.run(flows))


def analyze_file(path: str | Path, *, top: int = 10, **options: Any) -> dict[str, Any]:
    """Return {"summary", "flows", "alerts"} with rankings limited to `top`."""
    return run_analysis(path, **options).report(top=top)
