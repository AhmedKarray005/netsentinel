"""The three NetSentinel detection rules: each reads flows (or packet rates), returns alerts."""

from collections import Counter, defaultdict
from statistics import median

from netsentinel.detection.config import (
    FailedConnectionsConfig,
    PortScanConfig,
    TrafficSpikeConfig,
)
from netsentinel.detection.models import HIGH, LOW, MEDIUM, Alert, Rule
from netsentinel.detection.windows import find_episodes
from netsentinel.flows.models import HALF_OPEN, NO_REPLY, REJECTED, Flow
from netsentinel.parsing.models import PacketRecord

FAILED_STATES = {REJECTED, NO_REPLY, HALF_OPEN}
SAMPLE_SIZE = 25  # max items listed in evidence

PORT_SCAN = Rule(
    "NS-001",
    "Port scan indicator",
    "One source opened connections to many distinct ports of the same destination "
    "within a short time window.",
    "T1046 Network Service Discovery",
)
TRAFFIC_SPIKE = Rule(
    "NS-002",
    "Traffic spike (unsolicited packets)",
    "One source sent far more unsolicited packets (UDP, ICMP, TCP without ACK) in a short "
    "interval than both an absolute floor and its own usual rate in this capture.",
    "T1498 Network Denial of Service (possible)",
)
FAILED_CONNECTIONS = Rule(
    "NS-003",
    "Repeated failed connections",
    "One source repeatedly failed to open a TCP connection to the same destination port "
    "(rejected, unanswered or abandoned handshakes).",
    "T1110 Brute Force (possible) / misconfiguration",
)


# ---------------------------------------------------------------- NS-001 port scan
def detect_port_scans(flows: list[Flow], cfg: PortScanConfig) -> list[Alert]:
    by_pair: dict[tuple[str, str], list[Flow]] = defaultdict(list)
    for flow in flows:
        if flow.protocol in ("TCP", "UDP") and flow.server_port is not None:
            by_pair[(flow.client_ip, flow.server_ip)].append(flow)

    alerts = []
    for (src, dst), pair_flows in by_pair.items():
        events = [(f.start, (f.protocol, f.server_port)) for f in pair_flows]
        for episode in find_episodes(
            events, cfg.window_seconds, cfg.min_distinct_ports, distinct=True
        ):
            ports = sorted({value for _, value in episode.events}, key=lambda p: p[1])
            in_episode = [f for f in pair_flows if episode.start <= f.start <= episode.end]
            states = Counter(f.tcp_state for f in in_episode if f.tcp_state)
            failed = sum(n for state, n in states.items() if state in FAILED_STATES)
            severity = HIGH if len(ports) >= cfg.high_severity_ports else MEDIUM
            alerts.append(
                Alert(
                    rule=PORT_SCAN,
                    severity=severity,
                    start=episode.start,
                    end=episode.end,
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=None,
                    summary=(
                        f"{src} contacted {len(ports)} distinct ports on {dst} "
                        f"in {episode.end - episode.start:.1f} s ({failed} failed)"
                    ),
                    thresholds={
                        "window_seconds": cfg.window_seconds,
                        "min_distinct_ports": cfg.min_distinct_ports,
                    },
                    evidence={
                        "distinct_ports": len(ports),
                        "peak_distinct_ports_in_window": episode.peak,
                        "connection_attempts": len(in_episode),
                        "failed_attempts": failed,
                        "tcp_states": dict(states),
                        "ports_sample": [f"{proto}/{port}" for proto, port in ports[:SAMPLE_SIZE]],
                    },
                )
            )
    return alerts


# ---------------------------------------------------------------- NS-002 traffic spike
class PacketRateTracker:
    """Counts UNSOLICITED packets per source IP per time bucket while the file is being read.

    A packet is SOLICITED (not counted) when its receiver already sent a packet in the same
    conversation (same protocol, IPs and ports, reversed): a reply, a download the client
    asked for (TCP or QUIC/UDP), a ping reply. Without this, every fast download would look
    like a flood. TCP packets carrying ACK are also skipped (they belong to an accepted
    connection, even if the capture missed its start).
    Counted: floods, scans, replies nobody asked for (e.g. DNS reflection).
    Trade-off: floods over a conversation the victim started are not counted.
    """

    def __init__(self, bucket_seconds: float) -> None:
        self.bucket_seconds = bucket_seconds
        self.counts: dict[str, Counter] = defaultdict(Counter)
        self.first: float | None = None  # capture time range (all packets)
        self.last: float | None = None
        self._spoken: set[tuple] = set()  # conversations directions seen so far

    def add(self, record: PacketRecord) -> None:
        if not record.src_ip or record.protocol == "ARP":
            return
        ts = record.timestamp
        self.first = ts if self.first is None else min(self.first, ts)
        self.last = ts if self.last is None else max(self.last, ts)

        own = (record.protocol, record.src_ip, record.src_port, record.dst_ip, record.dst_port)
        reverse = (record.protocol, record.dst_ip, record.dst_port, record.src_ip, record.src_port)
        self._spoken.add(own)
        if reverse in self._spoken:
            return  # the receiver spoke first: this is a reply
        if record.protocol == "TCP" and record.tcp_flags and "A" in record.tcp_flags:
            return
        self.counts[record.src_ip][int(ts // self.bucket_seconds)] += 1


def detect_traffic_spikes(
    rates: PacketRateTracker, flows: list[Flow], cfg: TrafficSpikeConfig
) -> list[Alert]:
    if rates.first is None or rates.last is None:
        return []
    first_bucket = int(rates.first // cfg.bucket_seconds)
    last_bucket = int(rates.last // cfg.bucket_seconds)
    span = last_bucket - first_bucket + 1

    alerts = []
    for src, buckets in rates.counts.items():
        # Baseline = median packets per bucket over the WHOLE capture (silent buckets count as 0).
        # The median ignores short bursts, so the burst itself does not raise the baseline.
        # A capture that is too short (e.g. only the attack) has no "usual" rate: the burst
        # would be its own baseline. In that case only the absolute floor applies.
        silent = span - len(buckets)
        if span >= cfg.min_baseline_buckets:
            baseline = median(list(buckets.values()) + [0] * silent)
        else:
            baseline = 0
        limit = max(cfg.min_packets, cfg.baseline_multiplier * baseline)
        hot = sorted(b for b, n in buckets.items() if n >= limit)

        for run in _consecutive_runs(hot):
            start = run[0] * cfg.bucket_seconds
            end = (run[-1] + 1) * cfg.bucket_seconds
            peak = max(buckets[b] for b in run)
            total = sum(buckets[b] for b in run)
            targets = Counter()
            for flow in flows:
                if flow.client_ip == src and flow.start < end and flow.end >= start:
                    targets[flow.server_ip] += flow.packets_fwd
                elif flow.server_ip == src and flow.start < end and flow.end >= start:
                    targets[flow.client_ip] += flow.packets_bwd
            high = peak >= cfg.min_packets * cfg.high_severity_multiplier
            alerts.append(
                Alert(
                    rule=TRAFFIC_SPIKE,
                    severity=HIGH if high else MEDIUM,
                    start=start,
                    end=end,
                    src_ip=src,
                    dst_ip=targets.most_common(1)[0][0] if targets else None,
                    dst_port=None,
                    summary=(
                        f"{src} sent up to {peak} unsolicited packets per {cfg.bucket_seconds:g} s "
                        f"(usual: {baseline:g}) for {len(run)} interval(s)"
                    ),
                    thresholds={
                        "bucket_seconds": cfg.bucket_seconds,
                        "min_packets": cfg.min_packets,
                        "baseline_multiplier": cfg.baseline_multiplier,
                        "effective_limit": limit,
                    },
                    evidence={
                        "peak_packets_per_bucket": peak,
                        "baseline_packets_per_bucket": baseline,
                        "packets_during_spike": total,
                        "intervals": len(run),
                        "top_destinations": dict(targets.most_common(5)),
                    },
                )
            )
    return alerts


def _consecutive_runs(numbers: list[int]) -> list[list[int]]:
    runs: list[list[int]] = []
    for n in numbers:
        if runs and n == runs[-1][-1] + 1:
            runs[-1].append(n)
        else:
            runs.append([n])
    return runs


# ---------------------------------------------------------------- NS-003 failed connections
def detect_failed_connections(flows: list[Flow], cfg: FailedConnectionsConfig) -> list[Alert]:
    by_target: dict[tuple[str, str, int], list[Flow]] = defaultdict(list)
    for flow in flows:
        if flow.tcp_state in FAILED_STATES and flow.server_port is not None:
            by_target[(flow.client_ip, flow.server_ip, flow.server_port)].append(flow)

    alerts = []
    for (src, dst, port), failed_flows in by_target.items():
        events = [(f.start, i) for i, f in enumerate(failed_flows)]
        for episode in find_episodes(events, cfg.window_seconds, cfg.min_failed, distinct=False):
            attempts = [failed_flows[i] for _, i in episode.events]
            states = Counter(f.tcp_state for f in attempts)
            severity = MEDIUM if len(attempts) >= cfg.medium_severity_failed else LOW
            alerts.append(
                Alert(
                    rule=FAILED_CONNECTIONS,
                    severity=severity,
                    start=episode.start,
                    end=episode.end,
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=port,
                    summary=(
                        f"{src} failed {len(attempts)} TCP connections to {dst}:{port} "
                        f"in {episode.end - episode.start:.1f} s"
                    ),
                    thresholds={
                        "window_seconds": cfg.window_seconds,
                        "min_failed": cfg.min_failed,
                    },
                    evidence={
                        "failed_attempts": len(attempts),
                        "peak_attempts_in_window": episode.peak,
                        "tcp_states": dict(states),
                        "distinct_source_ports": len({f.client_port for f in attempts}),
                    },
                )
            )
    return alerts
