"""Shared test fixtures: a tiny synthetic capture whose content we know exactly."""

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap


def build_packets():
    """8 hand-made packets, 0.1 s apart, covering every protocol the parser knows."""
    packets = [
        # TCP handshake start: SYN then SYN-ACK
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=40000, flags="SA"),
        # DNS question and answer (UDP port 53)
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.53")
        / UDP(sport=40001, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether()
        / IP(src="10.0.0.53", dst="10.0.0.1")
        / UDP(sport=53, dport=40001)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="1.2.3.4")),
        # Ping request
        Ether() / IP(src="10.0.0.1", dst="10.0.0.254") / ICMP(type=8),
        # Router error "TTL exceeded" that QUOTES a UDP header: must still count as ICMP
        Ether()
        / IP(src="10.0.0.254", dst="10.0.0.1")
        / ICMP(type=11)
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=33434, dport=33434),
        # ARP "who has 10.0.0.254?"
        Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.254"),
        # IPv6 ping
        Ether() / IPv6(src="fe80::1", dst="ff02::1") / ICMPv6EchoRequest(),
    ]
    for i, packet in enumerate(packets):
        packet.time = 1000.0 + i / 10
    return packets


@pytest.fixture
def sample_pcap(tmp_path):
    """Write the synthetic packets to a temporary .pcap file and return its path."""
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), build_packets())
    return path
