"""Flow aggregation tests with hand-built records: every expected number is countable by hand."""

from netsentinel.flows import FlowAggregator, flow_key, top_conversations, top_talkers
from netsentinel.parsing import PacketRecord

C, S = "10.0.0.1", "10.0.0.2"  # client, server


def tcp(ts, src, sport, dst, dport, flags, length=60):
    return PacketRecord(ts, length, "TCP", src, dst, sport, dport, tcp_flags=flags)


def run(records, idle_timeout=60.0):
    aggregator = FlowAggregator(idle_timeout=idle_timeout)
    for record in records:
        aggregator.add(record)
    return aggregator.finish()


def full_connection(t0=0.0, port=50000):
    """Handshake, one request, one response, FIN from both sides, final ACK."""
    return [
        tcp(t0 + 0.0, C, port, S, 80, "S"),
        tcp(t0 + 0.1, S, 80, C, port, "SA"),
        tcp(t0 + 0.2, C, port, S, 80, "A"),
        tcp(t0 + 0.3, C, port, S, 80, "PA", length=200),  # request
        tcp(t0 + 0.4, S, 80, C, port, "PA", length=1500),  # response
        tcp(t0 + 0.5, C, port, S, 80, "FA"),
        tcp(t0 + 0.6, S, 80, C, port, "FA"),
        tcp(t0 + 0.7, C, port, S, 80, "A"),  # final ACK: must NOT open a new flow
    ]


def test_both_directions_share_one_key():
    a_to_b = tcp(0, C, 50000, S, 80, "S")
    b_to_a = tcp(0, S, 80, C, 50000, "SA")
    assert flow_key(a_to_b) == flow_key(b_to_a)


def test_full_connection_is_one_closed_flow_with_direction():
    (flow,) = run(full_connection())
    assert (flow.client_ip, flow.client_port, flow.server_ip, flow.server_port) == (C, 50000, S, 80)
    assert (flow.packets_fwd, flow.packets_bwd) == (5, 3)
    assert (flow.bytes_fwd, flow.bytes_bwd) == (60 * 4 + 200, 60 * 2 + 1500)
    assert round(flow.duration, 3) == 0.7
    assert flow.tcp_state == "CLOSED"


def test_open_connection_is_established():
    (flow,) = run(full_connection()[:5])
    assert flow.tcp_state == "ESTABLISHED"


def test_syn_answered_by_rst_is_rejected():
    (flow,) = run([tcp(0, C, 50000, S, 9999, "S"), tcp(0.001, S, 9999, C, 50000, "RA")])
    assert flow.tcp_state == "REJECTED"
    assert (flow.client_ip, flow.server_port) == (C, 9999)


def test_unanswered_syn_is_no_reply():
    (flow,) = run([tcp(0, C, 50000, S, 22, "S"), tcp(1, C, 50000, S, 22, "S")])
    assert flow.tcp_state == "NO_REPLY"
    assert flow.packets_fwd == 2  # a retransmitted SYN stays in the same flow


def test_missing_final_ack_is_half_open():
    (flow,) = run(full_connection()[:2])
    assert flow.tcp_state == "HALF_OPEN"


def test_capture_started_mid_connection():
    (flow,) = run([tcp(0, C, 50000, S, 443, "PA"), tcp(0.1, S, 443, C, 50000, "A")])
    assert flow.tcp_state == "MIDSTREAM"


def test_first_packet_syn_ack_makes_its_sender_the_server():
    (flow,) = run([tcp(0, S, 80, C, 50000, "SA"), tcp(0.1, C, 50000, S, 80, "A")])
    assert (flow.client_ip, flow.server_ip) == (C, S)


def test_port_reuse_after_close_starts_a_new_flow():
    flows = run(full_connection(t0=0.0) + full_connection(t0=5.0))
    assert [f.tcp_state for f in flows] == ["CLOSED", "CLOSED"]


def test_windows_syn_retry_after_rst_is_the_same_attempt():
    # Real pattern from lab/04_loopback_scan: SYN, RST, then the same SYN again 0.5 s later.
    records = [
        tcp(0.0, C, 51717, S, 9999, "S"),
        tcp(0.0001, S, 9999, C, 51717, "RA"),
        tcp(0.5, C, 51717, S, 9999, "S"),
        tcp(0.5001, S, 9999, C, 51717, "RA"),
    ]
    (flow,) = run(records)
    assert (flow.tcp_state, flow.packets_fwd) == ("REJECTED", 2)


def test_same_ports_reused_long_after_a_refusal_is_a_new_attempt():
    records = [
        tcp(0.0, C, 51717, S, 9999, "S"),
        tcp(0.0001, S, 9999, C, 51717, "RA"),
        tcp(10.0, C, 51717, S, 9999, "S"),
        tcp(10.0001, S, 9999, C, 51717, "RA"),
    ]
    assert len(run(records)) == 2


def test_idle_timeout_splits_flows():
    dns = [
        PacketRecord(0.0, 80, "UDP", C, "10.0.0.53", 40000, 53),
        PacketRecord(0.1, 120, "UDP", "10.0.0.53", C, 53, 40000),
        PacketRecord(100.0, 80, "UDP", C, "10.0.0.53", 40000, 53),  # 99.9 s later
    ]
    assert len(run(dns, idle_timeout=60)) == 2
    assert len(run(dns, idle_timeout=200)) == 1


def test_tcp_keepalive_gap_stays_in_one_flow():
    # 133 s of silence then a keep-alive: same connection with the TCP timeout (300 s)...
    records = full_connection()[:5] + [tcp(133.0, C, 50000, S, 80, "A")]
    (flow,) = run(records)
    assert flow.tcp_state == "ESTABLISHED"
    # ...but split if TCP used the short UDP-style timeout.
    aggregator = FlowAggregator(idle_timeout=60, tcp_idle_timeout=60)
    for record in records:
        aggregator.add(record)
    assert [f.tcp_state for f in aggregator.finish()] == ["ESTABLISHED", "MIDSTREAM"]


def test_ping_request_and_reply_are_one_icmp_flow_and_arp_is_ignored():
    records = [
        PacketRecord(0.0, 74, "ICMP", C, "10.0.0.254"),
        PacketRecord(0.003, 74, "ICMP", "10.0.0.254", C),
        PacketRecord(0.004, 42, "ARP", C, "10.0.0.254"),
    ]
    (flow,) = run(records)
    assert (flow.protocol, flow.packets_fwd, flow.packets_bwd, flow.tcp_state) == (
        "ICMP",
        1,
        1,
        None,
    )


def test_conversations_and_talkers():
    records = full_connection() + [
        PacketRecord(1.0, 100, "UDP", C, "10.0.0.53", 40000, 53),
        PacketRecord(1.1, 300, "UDP", "10.0.0.53", C, 53, 40000),
    ]
    flows = run(records)
    conversations = top_conversations(flows)
    assert conversations[0] == {"hosts": [C, S], "flows": 1, "packets": 8, "bytes": 2060}
    talkers = {t["host"]: t for t in top_talkers(flows)}
    assert talkers[C]["bytes"] == 2060 + 400  # in both conversations
    assert talkers[C]["bytes_sent"] == 440 + 100
    assert talkers[S]["bytes_received"] == 440
