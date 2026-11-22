"""Read a PCAP/PCAPNG file and turn each packet into a PacketRecord."""

from collections.abc import Iterator
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader

from netsentinel.parsing.models import PacketRecord

ICMPV6_NEXT_HEADER = 58


class PcapReadError(Exception):
    """The file is missing or is not a readable PCAP/PCAPNG capture."""


def _dns_query_name(udp: UDP) -> str | None:
    """Return the queried name if this UDP packet is a DNS question, else None."""
    dns = udp.payload
    if not isinstance(dns, DNS) or dns.qr != 0 or not dns.qd:
        return None
    question = dns.qd[0]
    name = question.qname.decode(errors="replace") if question.qname else ""
    return name.rstrip(".") or None


def to_record(packet) -> PacketRecord:
    """Convert one Scapy packet into a PacketRecord."""
    timestamp = float(packet.time)
    length = len(packet)

    # ARP has no IP layer: it is the "who has this IP?" question on the local network.
    if ARP in packet:
        arp = packet[ARP]
        return PacketRecord(timestamp, length, "ARP", src_ip=arp.psrc, dst_ip=arp.pdst)

    if IP in packet:
        ip = packet[IP]
    elif IPv6 in packet:
        ip = packet[IPv6]
    else:
        return PacketRecord(timestamp, length, "OTHER")

    # Classify by the layer DIRECTLY on top of IP. Using "TCP in packet" would be wrong:
    # ICMP error messages (e.g. traceroute's "TTL exceeded") quote the original TCP/UDP
    # header inside them, and would be miscounted as TCP/UDP.
    transport = ip.payload
    if isinstance(transport, TCP):
        return PacketRecord(
            timestamp, length, "TCP", ip.src, ip.dst,
            transport.sport, transport.dport, tcp_flags=str(transport.flags),
        )  # fmt: skip
    if isinstance(transport, UDP):
        return PacketRecord(
            timestamp, length, "UDP", ip.src, ip.dst,
            transport.sport, transport.dport, dns_query=_dns_query_name(transport),
        )  # fmt: skip
    if isinstance(transport, ICMP):
        return PacketRecord(timestamp, length, "ICMP", ip.src, ip.dst)
    if isinstance(ip, IPv6) and ip.nh == ICMPV6_NEXT_HEADER:
        return PacketRecord(timestamp, length, "ICMPv6", ip.src, ip.dst)
    return PacketRecord(timestamp, length, "OTHER_IP", ip.src, ip.dst)


def read_pcap(path: str | Path) -> Iterator[PacketRecord]:
    """Yield one PacketRecord per packet, reading the file progressively (streaming).

    Raises PcapReadError if the file does not exist or is not a valid capture.
    """
    path = Path(path)
    if not path.is_file():
        raise PcapReadError(f"File not found: {path}")
    # We open the file ourselves: if Scapy rejects it, it does not close a file it opened,
    # and on Windows an open file cannot be deleted (found by the API upload tests).
    with path.open("rb") as handle:
        try:
            reader = PcapReader(handle)
        except (Scapy_Exception, OSError, ValueError, EOFError) as exc:
            raise PcapReadError(f"Not a valid PCAP/PCAPNG file: {path} ({exc})") from exc
        with reader:
            for packet in reader:
                yield to_record(packet)
