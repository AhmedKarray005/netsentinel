"""Detection tests: each rule must fire on its pattern (positive) and stay silent just below
its threshold or on normal traffic (negative)."""

import pytest

from netsentinel.detection import ConfigError, DetectionConfig, DetectionEngine, load_config
from netsentinel.detection.windows import find_episodes
from netsentinel.flows import FlowAggregator
from netsentinel.parsing import PacketRecord

A, T = "192.0.2.66", "198.51.100.20"  # attacker / source, target


def tcp(ts, src, sport, dst, dport, flags, length=60):
    return PacketRecord(ts, length, "TCP", src, dst, sport, dport, tcp_flags=flags)


def detect(records, config=None):
    engine = DetectionEngine(config)
    aggregator = FlowAggregator()
    for record in records:
        engine.add(record)
        aggregator.add(record)
    return engine.run(aggregator.finish())


def refused(ts, sport, port, src=A, dst=T):
    return [tcp(ts, src, sport, dst, port, "S"), tcp(ts + 0.001, dst, port, src, sport, "RA")]


# ---------------------------------------------------------------- sliding window
def test_window_counts_distinct_values_and_merges_overlaps():
    events = [(float(i), i) for i in range(30)]  # 30 distinct values, one per second
    (episode,) = find_episodes(events, window=10, threshold=5, distinct=True)
    assert (episode.start, episode.end) == (0.0, 29.0)  # one merged episode, not 26
    assert episode.peak == 11  # values at t, t-1 ... t-10 (window edges included)


def test_window_below_threshold_gives_nothing():
    events = [(i * 10.0, i) for i in range(30)]  # spread out: max 2 per 10 s window
    assert find_episodes(events, window=10, threshold=5, distinct=True) == []


def test_window_counts_repeats_when_not_distinct():
    events = [(float(i), "same") for i in range(6)]
    assert find_episodes(events, window=10, threshold=5, distinct=True) == []
    assert len(find_episodes(events, window=10, threshold=5, distinct=False)) == 1


# ---------------------------------------------------------------- NS-001 port scan
def test_port_scan_fires_at_threshold():
    records = [r for i in range(20) for r in refused(i * 0.1, 40000 + i, 1 + i)]
    (alert,) = detect(records)
    assert alert.rule.rule_id == "NS-001"
    assert (alert.src_ip, alert.dst_ip, alert.severity) == (A, T, "medium")
    assert alert.evidence["distinct_ports"] == 20
    assert alert.evidence["failed_attempts"] == 20


def test_port_scan_silent_below_threshold():
    records = [r for i in range(19) for r in refused(i * 0.1, 40000 + i, 1 + i)]
    assert detect(records) == []


def test_port_scan_high_severity_and_threshold_from_config():
    records = [r for i in range(100) for r in refused(i * 0.01, 40000 + i, 1 + i)]
    (alert,) = detect(records)
    assert alert.severity == "high"


def test_many_servers_on_same_port_is_not_a_port_scan():
    # Normal browsing: one client, 50 different servers, all port 443.
    records = [
        r
        for i in range(50)
        for r in [
            tcp(i, "192.0.2.10", 50000 + i, f"198.51.100.{i}", 443, "S"),
            tcp(i + 0.01, f"198.51.100.{i}", 443, "192.0.2.10", 50000 + i, "SA"),
            tcp(i + 0.02, "192.0.2.10", 50000 + i, f"198.51.100.{i}", 443, "A"),
        ]
    ]
    assert detect(records) == []


# ---------------------------------------------------------------- NS-002 traffic spike
def udp(ts, src=A, dst=T):
    return PacketRecord(ts, 100, "UDP", src, dst, 43000, 9)


def test_udp_burst_after_quiet_period_is_a_spike():
    quiet = [udp(float(i)) for i in range(30)]  # 1 packet/s for 30 s
    burst = [udp(30 + i / 2000) for i in range(2000)]  # 2000 packets in 1 s
    (alert,) = detect(quiet + burst)
    assert alert.rule.rule_id == "NS-002"
    assert alert.evidence["peak_packets_per_bucket"] == 2000
    assert alert.evidence["baseline_packets_per_bucket"] == 1
    assert alert.dst_ip == T


def test_burst_below_absolute_floor_is_not_a_spike():
    assert detect([udp(i / 999) for i in range(999)]) == []  # 999 < min_packets 1000


def test_steady_high_rate_is_its_own_baseline():
    # 1200 packets/s for 20 s: above the floor, but it IS this source's usual rate.
    records = [udp(s + i / 1200) for s in range(20) for i in range(1200)]
    assert detect(records) == []


def test_tcp_packets_with_ack_do_not_count_as_spike():
    download = [tcp(i / 3000, T, 443, "192.0.2.10", 50000, "A", 1500) for i in range(3000)]
    assert detect(download) == []


def test_udp_download_the_client_asked_for_is_not_a_spike():
    # QUIC (HTTP/3) runs over UDP 443: the client speaks first, the server then streams.
    # Real case found in lab/01_ping capture (2026-11-20).
    client, server = "192.0.2.10", "198.51.100.7"
    records = [PacketRecord(0.0, 1200, "UDP", client, server, 55000, 443)]
    records += [
        PacketRecord(i / 2000, 1300, "UDP", server, client, 443, 55000) for i in range(1, 3000)
    ]
    assert detect(records) == []


def test_replies_nobody_asked_for_are_a_spike():
    # DNS reflection: a victim receives thousands of DNS responses it never requested.
    victim, resolver = "192.0.2.10", "198.51.100.53"
    records = [PacketRecord(i / 2000, 512, "UDP", resolver, victim, 53, 40000) for i in range(3000)]
    (alert,) = detect(records)
    assert (alert.rule.rule_id, alert.src_ip, alert.dst_ip) == ("NS-002", resolver, victim)


def test_syn_flood_counts_as_spike_even_in_a_capture_of_only_the_attack():
    # 1 s capture: too short for a baseline, so the absolute floor alone decides.
    flood = [tcp(i / 3000, A, 1024 + i % 60000, T, 80, "S") for i in range(3000)]
    rules = {alert.rule.rule_id for alert in detect(flood)}
    # NS-003 also fires: 3000 unanswered SYNs to port 80 ARE repeated failed connections.
    assert rules == {"NS-002", "NS-003"}


# ---------------------------------------------------------------- NS-003 failed connections
def test_repeated_failures_to_one_port_fire():
    records = [r for i in range(10) for r in refused(i * 2.0, 51000 + i, 5432)]
    (alert,) = detect(records)
    assert alert.rule.rule_id == "NS-003"
    assert (alert.dst_ip, alert.dst_port, alert.severity) == (T, 5432, "low")
    assert alert.evidence["failed_attempts"] == 10


def test_failures_spread_over_time_do_not_fire():
    records = [r for i in range(10) for r in refused(i * 10.0, 51000 + i, 5432)]  # 90 s span
    assert detect(records) == []


def test_successful_connections_never_count_as_failures():
    records = []
    for i in range(20):
        t, sport = i * 1.0, 51000 + i
        records += [
            tcp(t, A, sport, T, 5432, "S"),
            tcp(t + 0.01, T, 5432, A, sport, "SA"),
            tcp(t + 0.02, A, sport, T, 5432, "A"),
        ]
    assert detect(records) == []


# ---------------------------------------------------------------- config
def test_config_file_overrides_and_disables(tmp_path):
    rules = tmp_path / "rules.toml"
    rules.write_text("[port_scan]\nmin_distinct_ports = 5\n[failed_connections]\nenabled = false\n")
    config = load_config(rules)
    assert config.port_scan.min_distinct_ports == 5
    assert config.port_scan.window_seconds == 60.0  # untouched default
    assert config.failed_connections.enabled is False
    records = [r for i in range(10) for r in refused(i * 2.0, 51000 + i, 1 + i)]
    assert [a.rule.rule_id for a in detect(records, config)] == ["NS-001"]


@pytest.mark.parametrize(
    "content, message",
    [
        ("[port_scan]\nmin_distinct_port = 5\n", "Unknown key"),
        ("[portscan]\n", "Unknown section"),
        ("[port_scan]\nmin_distinct_ports = 0\n", "greater than 0"),
        ("[port_scan]\nmin_distinct_ports = 2.5\n", "whole number"),
        ("[port_scan]\nenabled = 1\n", "true or false"),
        ("[port_scan\n", "Cannot read"),
    ],
)
def test_invalid_config_is_rejected(tmp_path, content, message):
    rules = tmp_path / "rules.toml"
    rules.write_text(content)
    with pytest.raises(ConfigError, match=message):
        load_config(rules)


def test_default_config_matches_example_file():
    from pathlib import Path

    example = Path(__file__).parents[1] / "config" / "rules.example.toml"
    assert load_config(example) == DetectionConfig()
