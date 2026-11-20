"""One entry point for a full analysis: read the file once, feed every analyzer.

The CLI uses it now; the API (Phase 5) will use the same function.
"""

from collections import Counter
from pathlib import Path
from typing import Any

from netsentinel.detection import DetectionConfig, DetectionEngine
from netsentinel.flows import FlowAggregator, flow_report
from netsentinel.parsing import read_pcap
from netsentinel.summary import TrafficSummary


def analyze_file(
    path: str | Path,
    *,
    top: int = 10,
    idle_timeout: float = 60.0,
    tcp_idle_timeout: float = 300.0,
    bucket_seconds: float = 1.0,
    detection: DetectionConfig | None = None,
) -> dict[str, Any]:
    """Return {"summary", "flows", "alerts"}. Raises PcapReadError on a bad file."""
    summary = TrafficSummary(bucket_seconds=bucket_seconds)
    aggregator = FlowAggregator(idle_timeout=idle_timeout, tcp_idle_timeout=tcp_idle_timeout)
    engine = DetectionEngine(detection)
    for record in read_pcap(path):  # single pass over the file
        summary.add(record)
        aggregator.add(record)
        engine.add(record)

    flows = aggregator.finish()
    alerts = [alert.to_dict() for alert in engine.run(flows)]
    return {
        "summary": summary.to_dict(top=top),
        "flows": flow_report(flows, top=top),
        "alerts": {
            "count": len(alerts),
            "by_rule": dict(Counter(a["rule_id"] for a in alerts)),
            "by_severity": dict(Counter(a["severity"] for a in alerts)),
            "items": alerts,
        },
    }
