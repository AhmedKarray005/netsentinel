import pytest

from netsentinel.parsing import PacketRecord, read_pcap
from netsentinel.summary import TrafficSummary, summarize


def test_summary_of_sample_capture(sample_pcap):
    report = summarize(read_pcap(sample_pcap)).to_dict()
    assert report["packet_count"] == 8
    assert report["duration_seconds"] == pytest.approx(0.7)
    assert report["protocols"] == {"TCP": 2, "UDP": 2, "ICMP": 2, "ARP": 1, "ICMPv6": 1}
    # 10.0.0.1 sends: TCP SYN, DNS question, ping, ARP request = 4
    assert report["top_src_ips"]["10.0.0.1"] == 4
    assert report["top_dst_ports"] == {"TCP/80": 1, "TCP/40000": 1, "UDP/53": 1, "UDP/40001": 1}
    assert report["top_dns_queries"] == {"example.com": 1}


def test_lengths_and_out_of_order_timestamps():
    summary = TrafficSummary()
    for ts, length in [(10.0, 100), (5.0, 60), (12.0, 1500)]:
        summary.add(PacketRecord(ts, length, "OTHER"))
    report = summary.to_dict()
    assert report["packet_length"] == {"min": 60, "max": 1500, "mean": 553.3}
    assert report["duration_seconds"] == 7.0
    assert report["packets_per_second"] == pytest.approx(3 / 7, abs=0.01)


def test_empty_input():
    report = TrafficSummary().to_dict()
    assert report["packet_count"] == 0
    assert report["packets_per_second"] is None
    assert report["start_time"] is None


def test_top_limits_rankings():
    summary = TrafficSummary()
    for i in range(20):
        summary.add(PacketRecord(float(i), 60, "UDP", f"10.0.0.{i}", "10.0.0.250"))
    assert len(summary.to_dict(top=5)["top_src_ips"]) == 5
