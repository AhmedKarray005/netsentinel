"""Who talks to whom: rankings built from a list of flows."""

from collections import Counter
from typing import Any

from netsentinel.flows.models import Flow


def top_conversations(flows: list[Flow], top: int = 10) -> list[dict[str, Any]]:
    """Host pairs ranked by bytes exchanged (all protocols and ports together)."""
    pairs: dict[tuple[str, str], dict[str, int]] = {}
    for flow in flows:
        pair = tuple(sorted((flow.client_ip, flow.server_ip)))
        stats = pairs.setdefault(pair, {"flows": 0, "packets": 0, "bytes": 0})
        stats["flows"] += 1
        stats["packets"] += flow.packets
        stats["bytes"] += flow.bytes
    ranked = sorted(pairs.items(), key=lambda item: item[1]["bytes"], reverse=True)
    return [{"hosts": list(pair), **stats} for pair, stats in ranked[:top]]


def top_talkers(flows: list[Flow], top: int = 10) -> list[dict[str, Any]]:
    """Hosts ranked by total bytes sent + received."""
    sent: Counter = Counter()
    received: Counter = Counter()
    for flow in flows:
        sent[flow.client_ip] += flow.bytes_fwd
        received[flow.server_ip] += flow.bytes_fwd
        sent[flow.server_ip] += flow.bytes_bwd
        received[flow.client_ip] += flow.bytes_bwd
    total = sent + received
    return [
        {"host": host, "bytes_sent": sent[host], "bytes_received": received[host], "bytes": n}
        for host, n in total.most_common(top)
    ]


def flow_report(flows: list[Flow], top: int = 10) -> dict[str, Any]:
    by_bytes = sorted(flows, key=lambda f: f.bytes, reverse=True)
    return {
        "flow_count": len(flows),
        "by_protocol": dict(Counter(f.protocol for f in flows).most_common()),
        "tcp_states": dict(Counter(f.tcp_state for f in flows if f.tcp_state).most_common()),
        "top_flows_by_bytes": [f.to_dict() for f in by_bytes[:top]],
        "top_conversations": top_conversations(flows, top),
        "top_talkers": top_talkers(flows, top),
    }
