from collections import Counter

import pytest

from netsentinel.parsing import PcapReadError, read_pcap


def test_reads_every_packet(sample_pcap):
    assert len(list(read_pcap(sample_pcap))) == 8


def test_protocol_classification(sample_pcap):
    protocols = Counter(r.protocol for r in read_pcap(sample_pcap))
    assert protocols == {"TCP": 2, "UDP": 2, "ICMP": 2, "ARP": 1, "ICMPv6": 1}


def test_tcp_fields(sample_pcap):
    syn, syn_ack = [r for r in read_pcap(sample_pcap) if r.protocol == "TCP"]
    assert (syn.src_ip, syn.dst_ip, syn.src_port, syn.dst_port) == (
        "10.0.0.1",
        "10.0.0.2",
        40000,
        80,
    )
    assert syn.tcp_flags == "S"
    assert syn_ack.tcp_flags == "SA"


def test_icmp_error_quoting_udp_is_not_counted_as_udp(sample_pcap):
    records = list(read_pcap(sample_pcap))
    ttl_exceeded = records[5]
    assert ttl_exceeded.protocol == "ICMP"
    assert ttl_exceeded.src_port is None


def test_dns_question_name_only_on_queries(sample_pcap):
    udp = [r for r in read_pcap(sample_pcap) if r.protocol == "UDP"]
    assert udp[0].dns_query == "example.com"  # question
    assert udp[1].dns_query is None  # answer


def test_arp_and_timestamps(sample_pcap):
    records = list(read_pcap(sample_pcap))
    arp = records[6]
    assert (arp.protocol, arp.src_ip, arp.dst_ip) == ("ARP", "10.0.0.1", "10.0.0.254")
    assert records[0].timestamp == pytest.approx(1000.0)
    assert records[7].timestamp == pytest.approx(1000.7)


def test_missing_file_raises(tmp_path):
    with pytest.raises(PcapReadError, match="not found"):
        list(read_pcap(tmp_path / "nope.pcap"))


def test_garbage_file_raises(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture file at all")
    with pytest.raises(PcapReadError, match="Not a valid"):
        list(read_pcap(bad))
