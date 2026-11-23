"""Labelled synthetic scenarios to measure detection quality (true/false positives/negatives).

Packets are crafted in memory with Scapy and written to PCAP files: nothing is sent on any
network. Addresses come from the documentation ranges reserved by RFC 5737
(192.0.2.0/24 and 198.51.100.0/24), which never exist on real networks.

(This module and `parsing` are the only places that import Scapy.)
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

CLIENT = "192.0.2.10"  # a normal workstation
ATTACKER = "192.0.2.66"
SERVER = "198.51.100.20"
DNS_SERVER = "198.51.100.53"


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    truth: list[str]  # rule IDs that SHOULD fire (what really happened)
    build: Callable[[], list[Packet]]


# ------------------------------------------------------------------ packet helpers
# Fixed, locally administered MACs: without them Scapy asks the real network (ARP) for the
# destination MAC, which needs raw sockets and fails in a locked-down container.
_MAC_A = "02:00:00:00:00:01"
_MAC_B = "02:00:00:00:00:02"


def _pkt(t: float, src: str, dst: str, layer4: Packet) -> Packet:
    packet = Ether(src=_MAC_A, dst=_MAC_B) / IP(src=src, dst=dst) / layer4
    packet.time = t
    return packet


def _tcp(t, src, sport, dst, dport, flags, payload: bytes = b"") -> Packet:
    layer = TCP(sport=sport, dport=dport, flags=flags)
    return _pkt(t, src, dst, layer / Raw(payload) if payload else layer)


def _session(t, client, cport, server, sport, request=200, responses=3) -> list[Packet]:
    """A complete, normal TCP connection: handshake, request, responses, FIN/FIN."""
    packets = [
        _tcp(t, client, cport, server, sport, "S"),
        _tcp(t + 0.01, server, sport, client, cport, "SA"),
        _tcp(t + 0.02, client, cport, server, sport, "A"),
        _tcp(t + 0.03, client, cport, server, sport, "PA", b"x" * request),
    ]
    for i in range(responses):
        packets.append(_tcp(t + 0.05 + i * 0.01, server, sport, client, cport, "PA", b"y" * 1400))
        packets.append(_tcp(t + 0.055 + i * 0.01, client, cport, server, sport, "A"))
    end = t + 0.1 + responses * 0.01
    packets += [
        _tcp(end, client, cport, server, sport, "FA"),
        _tcp(end + 0.01, server, sport, client, cport, "FA"),
        _tcp(end + 0.02, client, cport, server, sport, "A"),
    ]
    return packets


def _dns_query(t, client, cport, name) -> list[Packet]:
    query = DNS(rd=1, qd=DNSQR(qname=name))
    return [
        _pkt(t, client, DNS_SERVER, UDP(sport=cport, dport=53) / query),
        _pkt(t + 0.02, DNS_SERVER, client, UDP(sport=53, dport=cport) / DNS(qr=1, qd=query.qd)),
    ]


# ------------------------------------------------------------------ scenarios
def normal_browsing() -> list[Packet]:
    """A workstation: 40 HTTPS connections to 20 servers + DNS, over 80 s."""
    packets = []
    for i in range(40):
        t = 1000.0 + i * 2
        server = f"198.51.100.{100 + i % 20}"
        packets += _dns_query(t, CLIENT, 30000 + i, f"site{i % 20}.example")
        packets += _session(t + 0.1, CLIENT, 50000 + i, server, 443)
    return packets


def port_scan_connect() -> list[Packet]:
    """Connect scan of ports 1-200 in ~10 s. Ports 22 and 80 are open."""
    open_ports = {22, 80}
    packets = []
    for i, port in enumerate(range(1, 201)):
        t = 1000.0 + i * 0.05
        sport = 40000 + i
        if port in open_ports:
            packets += _session(t, ATTACKER, sport, SERVER, port, request=0, responses=1)
        else:
            packets.append(_tcp(t, ATTACKER, sport, SERVER, port, "S"))
            packets.append(_tcp(t + 0.001, SERVER, port, ATTACKER, sport, "RA"))
    return packets


def port_scan_syn() -> list[Packet]:
    """'Half-open' SYN scan of 100 ports: the scanner never completes handshakes."""
    packets = []
    for i, port in enumerate(range(1, 101)):
        t = 1000.0 + i * 0.02
        packets.append(_tcp(t, ATTACKER, 41000, SERVER, port, "S"))
        if port in (22, 80):
            packets.append(_tcp(t + 0.001, SERVER, port, ATTACKER, 41000, "SA"))
            packets.append(_tcp(t + 0.002, ATTACKER, 41000, SERVER, port, "R"))
        else:
            packets.append(_tcp(t + 0.001, SERVER, port, ATTACKER, 41000, "RA"))
    return packets


def slow_port_scan() -> list[Packet]:
    """A real scan of 30 ports, one every 5 s: never 20 ports inside one 60 s window.
    Expected to be MISSED by NS-001 with default thresholds (a known false negative)."""
    packets = []
    for i, port in enumerate(range(1000, 1030)):
        t = 1000.0 + i * 5
        packets.append(_tcp(t, ATTACKER, 42000 + i, SERVER, port, "S"))
        packets.append(_tcp(t + 0.001, SERVER, port, ATTACKER, 42000 + i, "RA"))
    return packets


def udp_flood() -> list[Packet]:
    """30 s of light traffic, then 5000 UDP packets in 1 s from one source."""
    packets = []
    for i in range(30):
        packets += _dns_query(1000.0 + i, CLIENT, 30000 + i, "intranet.example")
    for i in range(5000):
        packets.append(
            _pkt(1030.0 + i / 5000, ATTACKER, SERVER, UDP(sport=43000, dport=9) / Raw(b"z" * 64))
        )
    return packets


def bulk_download() -> list[Packet]:
    """A legitimate 5 s download at ~1500 packets/s after 20 s of quiet.
    Must NOT trigger NS-002 (TCP traffic with ACK flags belongs to an accepted session)."""
    packets = _dns_query(1000.0, CLIENT, 30000, "updates.example")
    packets += [
        _tcp(1020.0, CLIENT, 50000, SERVER, 443, "S"),
        _tcp(1020.01, SERVER, 443, CLIENT, 50000, "SA"),
        _tcp(1020.02, CLIENT, 50000, SERVER, 443, "A"),
    ]
    for i in range(7500):
        t = 1020.1 + i / 1500
        packets.append(_tcp(t, SERVER, 443, CLIENT, 50000, "A", b"d" * 1400))
        if i % 2 == 0:
            packets.append(_tcp(t + 0.0001, CLIENT, 50000, SERVER, 443, "A"))
    return packets


def repeated_failed_connections() -> list[Packet]:
    """An application retrying a closed database port 25 times, every 2 s."""
    packets = []
    for i in range(25):
        t = 1000.0 + i * 2
        packets.append(_tcp(t, CLIENT, 51000 + i, SERVER, 5432, "S"))
        packets.append(_tcp(t + 0.001, SERVER, 5432, CLIENT, 51000 + i, "RA"))
    return packets


SCENARIOS = [
    Scenario("normal_browsing", "40 HTTPS sessions + DNS", [], normal_browsing),
    Scenario("port_scan_connect", "connect scan, 200 ports", ["NS-001"], port_scan_connect),
    Scenario("port_scan_syn", "SYN (half-open) scan, 100 ports", ["NS-001"], port_scan_syn),
    Scenario("slow_port_scan", "30 ports, 1 every 5 s (evasion)", ["NS-001"], slow_port_scan),
    Scenario("udp_flood", "5000 UDP packets in 1 s", ["NS-002"], udp_flood),
    Scenario("bulk_download", "legit 5 s download, 1500 pkt/s", [], bulk_download),
    Scenario(
        "repeated_failed_connections",
        "25 refused connections to port 5432",
        ["NS-003"],
        repeated_failed_connections,
    ),
]


def write_scenarios(out_dir: str | Path) -> Path:
    """Write one PCAP per scenario plus manifest.json (the ground truth)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for scenario in SCENARIOS:
        wrpcap(str(out / f"{scenario.name}.pcap"), scenario.build())
        manifest.append(
            {"file": f"{scenario.name}.pcap", "description": scenario.description,
             "truth": scenario.truth}
        )  # fmt: skip
    path = out / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path
