from netsentinel.analysis import analyze_file


def test_analyze_file_on_sample_capture(sample_pcap):
    report = analyze_file(sample_pcap)
    assert report["summary"]["packet_count"] == 8
    flows = report["flows"]
    # TCP SYN/SYN-ACK, DNS question/answer, ping + TTL-exceeded (same ICMP host pair), IPv6 ping.
    # ARP is not a flow.
    assert flows["flow_count"] == 4
    assert flows["by_protocol"] == {"TCP": 1, "UDP": 1, "ICMP": 1, "ICMPv6": 1}
    assert flows["tcp_states"] == {"HALF_OPEN": 1}


def test_timeline_buckets(sample_pcap):
    timeline = analyze_file(sample_pcap, bucket_seconds=0.5)["summary"]["timeline"]
    # packets at 1000.0 ... 1000.7 -> buckets 1000.0 (5 packets) and 1000.5 (3 packets)
    assert [b["packets"] for b in timeline["buckets"]] == [5, 3]
    assert timeline["peak"]["packets"] == 5
