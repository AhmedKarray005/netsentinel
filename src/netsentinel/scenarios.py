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
MONITOR = "192.0.2.30"  # a monitoring server (Nagios/Zabbix-like) run on purpose
SERVER = "198.51.100.20"
DNS_SERVER = "198.51.100.53"


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    # What really happened: (rule ID, source IP that rule should blame). An alert with the right
    # rule but the wrong source counts as a false positive AND a false negative.
    truth: list[tuple[str, str]]
    build: Callable[[], list[Packet]]
    # What we PREDICT the rules will do: "detected" / "no alert" (default from truth),
    # or a known limit written in advance: "missed" / "false alarm".
    expected: str | None = None


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


def port_scan_connect(start: float = 1000.0) -> list[Packet]:
    """Connect scan of ports 1-200 in ~10 s. Ports 22 and 80 are open."""
    open_ports = {22, 80}
    packets = []
    for i, port in enumerate(range(1, 201)):
        t = start + i * 0.05
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


# ---- Phase 8: harder cases, including ones the rules are EXPECTED to get wrong --------------
def scan_in_background_traffic() -> list[Packet]:
    """The normal_browsing workstation keeps working while another host scans 200 ports.
    Checks the alert blames the scanner, not the busy workstation."""
    packets = normal_browsing() + port_scan_connect(start=1030.0)
    return sorted(packets, key=lambda p: float(p.time))


def horizontal_scan() -> list[Packet]:
    """One port (445/SMB) probed on 60 hosts in 6 s: a real discovery scan, but NS-001 counts
    ports per destination, so it should be MISSED (known false negative)."""
    packets = []
    for i in range(60):
        t, host = 1000.0 + i * 0.1, f"198.51.100.{i + 1}"
        packets.append(_tcp(t, ATTACKER, 44000 + i, host, 445, "S"))
        packets.append(_tcp(t + 0.001, host, 445, ATTACKER, 44000 + i, "RA"))
    return packets


def distributed_flood() -> list[Packet]:
    """20 sources x 400 UDP packets/s for 3 s against one server (8000 packets/s in total).
    Each source stays under the 1000/s floor: expected to be MISSED (known false negative)."""
    packets = []
    for i in range(30):
        packets += _dns_query(1000.0 + i, CLIENT, 30000 + i, "intranet.example")
    for s in range(20):
        src = f"192.0.2.{100 + s}"
        for i in range(1200):
            t = 1030.0 + i / 400 + s * 0.0001
            packets.append(_pkt(t, src, SERVER, UDP(sport=45000 + s, dport=9) / Raw(b"z" * 64)))
    return sorted(packets, key=lambda p: float(p.time))


def syn_flood() -> list[Packet]:
    """3000 SYNs in 1 s to port 80, new source port each time, the server never answers.
    Both NS-002 (burst of unsolicited packets) and NS-003 (failed handshakes) are true."""
    return [_tcp(1000.0 + i / 3000, ATTACKER, 1024 + i, SERVER, 80, "S") for i in range(3000)]


def monitoring_checks() -> list[Packet]:
    """A monitoring server checks 25 services on one server every 60 s, each connection
    succeeds. Benign, but it looks like a scan: expected FALSE ALARM from NS-001."""
    ports = [21, 22, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433,
             1521, 3306, 3389, 5432, 5672, 6379, 8080, 8443, 9200]  # fmt: skip
    packets = []
    for round_ in range(3):
        for i, port in enumerate(ports):
            t = 1000.0 + round_ * 60 + i * 0.2
            packets += _session(t, MONITOR, 46000 + round_ * 100 + i, SERVER, port, 50, 1)
    return sorted(packets, key=lambda p: float(p.time))


def dns_heavy_client() -> list[Packet]:
    """A browser resolving 300 different names in 10 s (prefetching). Benign."""
    packets = []
    for i in range(300):
        packets += _dns_query(1000.0 + i / 30, CLIENT, 20000 + i, f"cdn{i}.example")
    return packets


def service_restart() -> list[Packet]:
    """A web server restarts: a client is refused 8 times (1 per s), then connects normally.
    Benign, and under the NS-003 threshold of 10 failures."""
    packets = []
    for i in range(8):
        t = 1000.0 + i
        packets.append(_tcp(t, CLIENT, 52000 + i, SERVER, 8080, "S"))
        packets.append(_tcp(t + 0.001, SERVER, 8080, CLIENT, 52000 + i, "RA"))
    for i in range(5):
        packets += _session(1009.0 + i, CLIENT, 52100 + i, SERVER, 8080)
    return packets


SCENARIOS = [
    Scenario("normal_browsing", "40 HTTPS sessions + DNS", [], normal_browsing),
    Scenario(
        "port_scan_connect", "connect scan, 200 ports", [("NS-001", ATTACKER)], port_scan_connect
    ),
    Scenario(
        "port_scan_syn", "SYN (half-open) scan, 100 ports", [("NS-001", ATTACKER)], port_scan_syn
    ),
    Scenario(
        "slow_port_scan",
        "30 ports, 1 every 5 s (evasion)",
        [("NS-001", ATTACKER)],
        slow_port_scan,
        "missed",
    ),  # fmt: skip
    Scenario("udp_flood", "5000 UDP packets in 1 s", [("NS-002", ATTACKER)], udp_flood),
    Scenario("bulk_download", "legit 5 s download, 1500 pkt/s", [], bulk_download),
    Scenario(
        "repeated_failed_connections",
        "25 refused connections to port 5432",
        [("NS-003", CLIENT)],
        repeated_failed_connections,
    ),  # fmt: skip
    Scenario(
        "scan_in_background_traffic",
        "200-port scan during normal browsing",
        [("NS-001", ATTACKER)],
        scan_in_background_traffic,
    ),  # fmt: skip
    Scenario(
        "horizontal_scan",
        "port 445 on 60 hosts in 6 s",
        [("NS-001", ATTACKER)],
        horizontal_scan,
        "missed",
    ),  # fmt: skip
    Scenario(
        "distributed_flood",
        "20 sources x 400 UDP pkt/s",
        [("NS-002", f"192.0.2.{100 + s}") for s in range(20)],
        distributed_flood,
        "missed",
    ),  # fmt: skip
    Scenario(
        "syn_flood",
        "3000 unanswered SYNs in 1 s to port 80",
        [("NS-002", ATTACKER), ("NS-003", ATTACKER)],
        syn_flood,
    ),  # fmt: skip
    Scenario(
        "monitoring_checks",
        "monitoring server checks 25 open ports / 60 s",
        [],
        monitoring_checks,
        "false alarm",
    ),  # fmt: skip
    Scenario("dns_heavy_client", "300 DNS lookups in 10 s", [], dns_heavy_client),
    Scenario("service_restart", "8 refused, then normal sessions", [], service_restart),
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
             "truth": [{"rule": rule, "src": src} for rule, src in scenario.truth],
             "expected": scenario.expected or ("detected" if scenario.truth else "no alert")}
        )  # fmt: skip
    path = out / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path
